//! sipnab audio playback plugin.
//!
//! This crate is built as a `cdylib` (`libsipnab_audio.so` on Linux,
//! `libsipnab_audio.dylib` on macOS). It is the *only* component that links
//! `rodio` → `cpal` → `alsa-sys` → `libasound`. The main `sipnab` binary
//! `dlopen`s it lazily (via `libloading`) the moment the user actually plays
//! audio, so the binary itself carries no load-time `NEEDED libasound.so.2`
//! ELF entry and starts fine on hosts without libasound installed.
//!
//! The exported C ABI is handle-based: the caller opens a player handle, feeds
//! it f32 PCM buffers, queries/stops playback, and finally closes the handle.
//! All entry points are null-safe and never unwind across the FFI boundary.

use std::io::Write;
use std::num::NonZero;
use std::os::raw::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};

use rodio::DeviceSinkBuilder;
use rodio::Player;
use rodio::buffer::SamplesBuffer;
use rodio::stream::MixerDeviceSink;

/// Opaque playback handle: a rodio output device + connected player.
struct AudioHandle {
    player: Player,
    _device_sink: MixerDeviceSink,
}

/// Open the default audio output device and create a player.
///
/// Returns an opaque boxed handle pointer, or null on failure (no device,
/// libasound errors, etc.). The device open is wrapped in [`StderrSilencer`]
/// so libasound's C-level error chatter does not corrupt the caller's TUI.
///
/// # Safety
/// The returned pointer must only be passed back to the other `sipnab_audio_*`
/// functions, and freed exactly once with [`sipnab_audio_close`].
#[unsafe(no_mangle)]
pub extern "C" fn sipnab_audio_open() -> *mut c_void {
    let result = catch_unwind(|| {
        let mut device_sink = {
            // libasound writes config/device errors straight to stderr,
            // which corrupts an alternate-screen TUI. Redirect stderr to
            // /dev/null for the duration of the device open.
            let _silencer = StderrSilencer::new();
            DeviceSinkBuilder::open_default_sink()
        }
        .ok()?;
        device_sink.log_on_drop(false);
        let player = Player::connect_new(device_sink.mixer());
        Some(Box::new(AudioHandle {
            player,
            _device_sink: device_sink,
        }))
    });

    match result {
        Ok(Some(handle)) => Box::into_raw(handle) as *mut c_void,
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Append `len` interleaved f32 PCM samples (copied) to the player.
///
/// Returns `0` on success and nonzero on error (null handle/pointer, invalid
/// sample rate or channel count, or a panic caught at the boundary).
///
/// # Safety
/// `handle` must be a live handle from [`sipnab_audio_open`]; `samples` must
/// point to at least `len` valid `f32` values (or be null with `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_audio_play(
    handle: *mut c_void,
    samples: *const f32,
    len: usize,
    sample_rate: u32,
    channels: u16,
) -> i32 {
    if handle.is_null() {
        return 1;
    }
    if samples.is_null() && len != 0 {
        return 2;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle is non-null and originates from sipnab_audio_open.
        let handle = unsafe { &*(handle as *const AudioHandle) };

        // Copy the caller's samples; never hold the caller's pointer.
        let pcm: Vec<f32> = if len == 0 {
            Vec::new()
        } else {
            // SAFETY: caller guarantees `samples` is valid for `len` f32s.
            unsafe { std::slice::from_raw_parts(samples, len) }.to_vec()
        };

        let channels = match NonZero::new(channels) {
            Some(c) => c,
            None => return 3,
        };
        let sample_rate = match NonZero::new(sample_rate) {
            Some(r) => r,
            None => return 4,
        };

        let source = SamplesBuffer::new(channels, sample_rate, pcm);
        handle.player.append(source);
        0
    }));

    result.unwrap_or(5)
}

/// Stop playback immediately. No-op if `handle` is null.
///
/// # Safety
/// `handle` must be a live handle from [`sipnab_audio_open`] or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_audio_stop(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle is non-null and originates from sipnab_audio_open.
        let handle = unsafe { &*(handle as *const AudioHandle) };
        handle.player.stop();
    }));
}

/// Return `1` if audio is currently playing, `0` otherwise (including null
/// handle / caught panic).
///
/// # Safety
/// `handle` must be a live handle from [`sipnab_audio_open`] or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_audio_is_playing(handle: *mut c_void) -> i32 {
    if handle.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle is non-null and originates from sipnab_audio_open.
        let handle = unsafe { &*(handle as *const AudioHandle) };
        i32::from(!handle.player.empty())
    }));
    result.unwrap_or(0)
}

/// Drop the player/device and free the handle. No-op if `handle` is null.
///
/// # Safety
/// `handle` must be a handle from [`sipnab_audio_open`] that has not already
/// been closed; after this call the pointer is dangling and must not be used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_audio_close(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle is non-null and originates from sipnab_audio_open and
        // has not been closed before, so reclaiming the Box is sound.
        drop(unsafe { Box::from_raw(handle as *mut AudioHandle) });
    }));
}

/// RAII guard that redirects stderr to `/dev/null` while alive.
///
/// Used during audio device initialization so that libasound's C-level error
/// output (e.g. ALSA config evaluation failures on Tegra/Jetson) does not
/// bleed through and corrupt the caller's alternate-screen TUI.
#[cfg(unix)]
struct StderrSilencer {
    saved_fd: libc::c_int,
}

#[cfg(unix)]
impl StderrSilencer {
    fn new() -> Option<Self> {
        let _ = std::io::stderr().flush();
        // SAFETY: all file descriptors are owned locally and only closed
        // on the exact paths that produced them.
        unsafe {
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
            if devnull < 0 {
                return None;
            }
            let saved_fd = libc::dup(libc::STDERR_FILENO);
            if saved_fd < 0 {
                libc::close(devnull);
                return None;
            }
            if libc::dup2(devnull, libc::STDERR_FILENO) < 0 {
                libc::close(saved_fd);
                libc::close(devnull);
                return None;
            }
            libc::close(devnull);
            Some(Self { saved_fd })
        }
    }
}

#[cfg(unix)]
impl Drop for StderrSilencer {
    fn drop(&mut self) {
        // SAFETY: saved_fd came from a successful dup() in new().
        unsafe {
            libc::dup2(self.saved_fd, libc::STDERR_FILENO);
            libc::close(self.saved_fd);
        }
    }
}

#[cfg(not(unix))]
struct StderrSilencer;

#[cfg(not(unix))]
impl StderrSilencer {
    fn new() -> Option<Self> {
        None
    }
}
