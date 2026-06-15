//! Real-time audio playback from RTP stream payload buffers.
//!
//! Decodes G.711 and Opus audio (pure Rust, no ALSA dependency) and resamples
//! to 48 kHz mono. The actual device output is delegated to the
//! `sipnab-audio` plugin (`libsipnab_audio.so` / `.dylib`), which is the only
//! component linking rodio/ALSA. The plugin is `dlopen`'d lazily on first
//! [`AudioPlayer::new`], so the main binary carries no load-time
//! `NEEDED libasound.so.2` ELF entry and starts fine without libasound.

use std::ffi::OsString;
use std::os::raw::c_void;
use std::path::PathBuf;

use anyhow::{Result, bail};
use libloading::{Library, Symbol};

use super::g711::{G711Codec, decode_frame};
use super::opus_decode::OpusStreamDecoder;
use super::stream::RtpStream;

// C ABI of the sipnab-audio plugin (see crates/sipnab-audio/src/lib.rs).
type OpenFn = unsafe extern "C" fn() -> *mut c_void;
type PlayFn = unsafe extern "C" fn(*mut c_void, *const f32, usize, u32, u16) -> i32;
type StopFn = unsafe extern "C" fn(*mut c_void);
type IsPlayingFn = unsafe extern "C" fn(*mut c_void) -> i32;
type CloseFn = unsafe extern "C" fn(*mut c_void);

/// Audio player backed by the lazily-loaded `sipnab-audio` plugin.
///
/// The public API is unchanged from the previous rodio-linked implementation
/// so TUI callers need no modification.
pub struct AudioPlayer {
    // Raw function pointers resolved from `_lib`. They are only valid while
    // `_lib` is alive, so `_lib` is kept (and dropped last via field order).
    play: PlayFn,
    stop: StopFn,
    is_playing: IsPlayingFn,
    close: CloseFn,
    handle: *mut c_void,
    // The loaded plugin library. MUST outlive the function pointers above and
    // the handle; it is dropped last (struct fields drop in declaration order,
    // so `_lib` is listed last here).
    _lib: Library,
}

impl AudioPlayer {
    /// Create a new audio player by `dlopen`-ing the `sipnab-audio` plugin and
    /// opening the default output device through it.
    ///
    /// Returns a clear `Err` (never panics) when the plugin or its libasound
    /// dependency is unavailable, so callers can fall back to WAV export.
    pub fn new() -> Result<Self> {
        let lib = load_plugin()?;

        // SAFETY: the plugin exports exactly these C-ABI symbols. We resolve
        // them up front and copy the raw fn pointers out so we don't hold
        // borrows of `lib`.
        let (open, play, stop, is_playing, close) = unsafe {
            let open: Symbol<OpenFn> = lib
                .get(b"sipnab_audio_open\0")
                .map_err(|e| anyhow::anyhow!("audio plugin missing sipnab_audio_open: {e}"))?;
            let play: Symbol<PlayFn> = lib
                .get(b"sipnab_audio_play\0")
                .map_err(|e| anyhow::anyhow!("audio plugin missing sipnab_audio_play: {e}"))?;
            let stop: Symbol<StopFn> = lib
                .get(b"sipnab_audio_stop\0")
                .map_err(|e| anyhow::anyhow!("audio plugin missing sipnab_audio_stop: {e}"))?;
            let is_playing: Symbol<IsPlayingFn> =
                lib.get(b"sipnab_audio_is_playing\0").map_err(|e| {
                    anyhow::anyhow!("audio plugin missing sipnab_audio_is_playing: {e}")
                })?;
            let close: Symbol<CloseFn> = lib
                .get(b"sipnab_audio_close\0")
                .map_err(|e| anyhow::anyhow!("audio plugin missing sipnab_audio_close: {e}"))?;
            (*open, *play, *stop, *is_playing, *close)
        };

        // SAFETY: `open` is a valid plugin symbol; it returns null on failure.
        let handle = unsafe { open() };
        if handle.is_null() {
            bail!(
                "No audio output device available. \
                 Use F2 to save the stream as a WAV file instead."
            );
        }

        Ok(Self {
            play,
            stop,
            is_playing,
            close,
            handle,
            _lib: lib,
        })
    }

    /// Play audio from an RTP stream's payload buffer.
    ///
    /// Supports G.711 (PCMU/PCMA) and Opus codecs. G.711 is decoded at
    /// 8 kHz and resampled to 48 kHz; Opus decodes natively at 48 kHz.
    pub fn play_stream(&self, stream: &RtpStream) -> Result<String> {
        if stream.payload_buffer.is_empty() {
            bail!("No audio payload captured");
        }

        let output_rate = 48000u32;
        let (pcm_48k, codec_label) = match stream.codec.as_deref() {
            Some("PCMU") => {
                let pcm = decode_g711_to_f32(G711Codec::Ulaw, stream);
                let resampled = resample_f32(&pcm, stream.clock_rate, output_rate);
                (resampled, "mu-law")
            }
            Some("PCMA") => {
                let pcm = decode_g711_to_f32(G711Codec::Alaw, stream);
                let resampled = resample_f32(&pcm, stream.clock_rate, output_rate);
                (resampled, "A-law")
            }
            Some(name) if name.eq_ignore_ascii_case("opus") => {
                let pcm = decode_opus_to_f32(stream)?;
                // Opus already at 48 kHz, no resampling needed
                (pcm, "Opus")
            }
            Some(other) => bail!("Unsupported codec for playback: {other}"),
            None => bail!("Unknown codec"),
        };

        let duration_secs = pcm_48k.len() as f64 / output_rate as f64;

        // SAFETY: `self.play` is a valid plugin symbol resolved in `new`;
        // `self.handle` is a live handle; the slice is valid for its length.
        let rc =
            unsafe { (self.play)(self.handle, pcm_48k.as_ptr(), pcm_48k.len(), output_rate, 1) };
        if rc != 0 {
            bail!("audio plugin playback failed (code {rc})");
        }

        Ok(format!(
            "Playing {:.1}s of {} audio ({} frames)",
            duration_secs,
            codec_label,
            stream.payload_buffer.len(),
        ))
    }

    /// Stop playback immediately.
    pub fn stop(&self) {
        // SAFETY: valid plugin symbol + live handle.
        unsafe { (self.stop)(self.handle) };
    }

    /// Check if audio is currently playing.
    pub fn is_playing(&self) -> bool {
        // SAFETY: valid plugin symbol + live handle.
        unsafe { (self.is_playing)(self.handle) != 0 }
    }
}

impl Drop for AudioPlayer {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: valid plugin symbol; `handle` was opened in `new` and is
            // closed exactly once here before `_lib` is dropped.
            unsafe { (self.close)(self.handle) };
            self.handle = std::ptr::null_mut();
        }
        // `_lib` drops after this (last field), unloading the plugin.
    }
}

/// Candidate filename for the plugin on this platform
/// (`libsipnab_audio.so` / `libsipnab_audio.dylib`).
fn plugin_filename() -> String {
    format!(
        "{}sipnab_audio{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    )
}

/// Build the ordered list of candidate plugin paths to try:
/// 1. `$SIPNAB_AUDIO_PLUGIN` (explicit path),
/// 2. next to the current executable (dev builds),
/// 3. `/usr/lib/sipnab/<soname>` (Debian install),
/// 4. the bare soname via the loader search path.
fn plugin_candidates() -> Vec<OsString> {
    let filename = plugin_filename();
    let mut candidates: Vec<OsString> = Vec::new();

    if let Some(explicit) = std::env::var_os("SIPNAB_AUDIO_PLUGIN") {
        candidates.push(explicit);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join(&filename).into_os_string());
    }
    candidates.push(
        PathBuf::from("/usr/lib/sipnab")
            .join(&filename)
            .into_os_string(),
    );
    candidates.push(OsString::from(&filename));
    candidates
}

/// Resolve and `dlopen` the audio plugin, trying [`plugin_candidates`] in
/// order and returning the first that loads.
fn load_plugin() -> Result<Library> {
    let candidates = plugin_candidates();

    let mut last_err = String::from("no candidate paths");
    for cand in &candidates {
        // SAFETY: loading a trusted plugin library; any initializers it runs
        // are our own code. Errors are non-fatal (we try the next candidate).
        match unsafe { Library::new(cand) } {
            Ok(lib) => return Ok(lib),
            Err(e) => last_err = format!("{}: {e}", cand.to_string_lossy()),
        }
    }

    bail!(
        "Audio playback unavailable — the sipnab audio plugin or libasound2 is \
         not installed (last error: {last_err}). Install libasound2 (Debian: \
         `apt install libasound2t64`) or use F2 to save the stream as a WAV \
         file instead."
    )
}

/// Decode G.711 frames to f32 PCM in [-1.0, 1.0] range.
fn decode_g711_to_f32(codec: G711Codec, stream: &RtpStream) -> Vec<f32> {
    let mut pcm = Vec::new();
    for (_ts, payload) in &stream.payload_buffer {
        let decoded = decode_frame(codec, payload);
        for sample in decoded {
            pcm.push(sample as f32 / 32768.0);
        }
    }
    pcm
}

/// Decode Opus frames to f32 PCM in [-1.0, 1.0] range at 48 kHz.
fn decode_opus_to_f32(stream: &RtpStream) -> Result<Vec<f32>> {
    let mut decoder = OpusStreamDecoder::new(48000, 1)?;
    let mut pcm = Vec::new();
    for (_ts, payload) in &stream.payload_buffer {
        match decoder.decode_frame(payload) {
            Ok(samples) => {
                for sample in samples {
                    pcm.push(sample as f32 / 32768.0);
                }
            }
            Err(e) => {
                tracing::debug!("Opus decode error (skipping frame): {e}");
            }
        }
    }
    Ok(pcm)
}

/// Resample f32 PCM using linear interpolation.
fn resample_f32(samples: &[f32], from_rate: u32, to_rate: u32) -> Vec<f32> {
    if from_rate == to_rate || samples.is_empty() {
        return samples.to_vec();
    }
    let ratio = to_rate as f64 / from_rate as f64;
    let output_len = (samples.len() as f64 * ratio) as usize;
    let mut out = Vec::with_capacity(output_len);
    for i in 0..output_len {
        let src_pos = i as f64 / ratio;
        let src_idx = src_pos as usize;
        let frac = (src_pos - src_idx as f64) as f32;
        let s0 = samples.get(src_idx).copied().unwrap_or(0.0);
        let s1 = samples.get(src_idx + 1).copied().unwrap_or(s0);
        out.push(s0 + (s1 - s0) * frac);
    }
    out
}

// Tests cover the device-free DSP helpers (decode + resample) and the plugin
// load/error paths. The rodio device path lives in the `sipnab-audio` plugin
// and is hardware-bound, so it stays uncovered by design.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// An RtpStream with the given payload type and no captured frames yet.
    fn stream(payload_type: u8) -> RtpStream {
        let key = StreamKey {
            ssrc: 0x1111_2222,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4002),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type,
            sequence: 0,
            timestamp: 0,
            ssrc: 0x1111_2222,
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, Utc::now())
    }

    #[test]
    fn resample_same_rate_and_empty_are_identity() {
        let s = vec![0.1, -0.2, 0.3];
        assert_eq!(resample_f32(&s, 8000, 8000), s);
        assert_eq!(resample_f32(&[], 8000, 16000), Vec::<f32>::new());
    }

    #[test]
    fn resample_upsample_and_downsample_lengths() {
        let s = vec![0.0f32; 100];
        // 8k -> 16k roughly doubles the sample count.
        assert_eq!(resample_f32(&s, 8000, 16000).len(), 200);
        // 48k -> 8k roughly divides by six.
        let s = vec![0.0f32; 60];
        assert_eq!(resample_f32(&s, 48000, 8000).len(), 10);
    }

    #[test]
    fn resample_linear_interpolation_values() {
        // Upsampling [0.0, 1.0] by 2x interpolates a midpoint near 0.5.
        let out = resample_f32(&[0.0, 1.0], 8000, 16000);
        assert_eq!(out.len(), 4);
        assert!((out[0] - 0.0).abs() < 1e-6);
        assert!((out[1] - 0.5).abs() < 1e-6, "midpoint should interpolate");
    }

    #[test]
    fn decode_g711_normalizes_to_unit_range() {
        let mut s = stream(0); // PCMU
        s.payload_buffer.push_back((0, vec![0xFFu8; 160]));
        s.payload_buffer.push_back((160, vec![0x00u8; 160]));

        let ulaw = decode_g711_to_f32(G711Codec::Ulaw, &s);
        // One f32 sample per input byte across both frames.
        assert_eq!(ulaw.len(), 320);
        assert!(ulaw.iter().all(|&v| (-1.0..=1.0).contains(&v)));

        // A-law decodes the same byte counts (values differ).
        let alaw = decode_g711_to_f32(G711Codec::Alaw, &stream_with_frame());
        assert_eq!(alaw.len(), 160);
    }

    fn stream_with_frame() -> RtpStream {
        let mut s = stream(8); // PCMA
        s.payload_buffer.push_back((0, vec![0x55u8; 160]));
        s
    }

    #[test]
    fn decode_g711_empty_stream_is_empty() {
        assert!(decode_g711_to_f32(G711Codec::Ulaw, &stream(0)).is_empty());
    }

    #[test]
    fn decode_opus_skips_undecodable_frames() {
        // Empty stream -> Ok(empty).
        let empty = decode_opus_to_f32(&stream(111)).expect("opus decode ok");
        assert!(empty.is_empty());

        // Garbage payloads: each frame fails to decode and is skipped, but the
        // function still returns Ok (the error-skip branch).
        let mut s = stream(111);
        s.payload_buffer
            .push_back((0, vec![0xDE, 0xAD, 0xBE, 0xEF]));
        s.payload_buffer.push_back((20, vec![0xFF; 8]));
        let pcm = decode_opus_to_f32(&s).expect("opus decode ok despite bad frames");
        // Undecodable frames produce no samples.
        assert!(pcm.is_empty());
    }

    #[test]
    fn plugin_filename_is_platform_appropriate() {
        let name = plugin_filename();
        assert!(name.contains("sipnab_audio"));
        // On Linux this is `libsipnab_audio.so`; on macOS `.dylib`.
        assert!(name.ends_with(std::env::consts::DLL_SUFFIX));
    }

    #[test]
    fn explicit_nonexistent_plugin_path_does_not_load() {
        // A non-existent explicit path must not dlopen successfully. We test
        // the candidate directly to stay independent of fallback paths.
        let bad = OsString::from("/nonexistent/path/to/libsipnab_audio.so");
        // SAFETY: loading a (missing) library; the call simply fails.
        let loaded = unsafe { Library::new(&bad) }.is_ok();
        assert!(!loaded, "a non-existent plugin path must not load");
    }

    #[test]
    fn new_with_missing_plugin_returns_err_not_panic() {
        // Pointing SIPNAB_AUDIO_PLUGIN at a non-existent path forces the
        // explicit-path candidate to fail. The remaining fallbacks are highly
        // unlikely to find a real plugin in the test environment, so this
        // exercises the graceful-fallback error path (no panic/abort).
        //
        // SAFETY: set_var/remove_var are unsafe in edition 2024; tests are
        // single-threaded here and we restore the previous value.
        let prev = std::env::var_os("SIPNAB_AUDIO_PLUGIN");
        unsafe {
            std::env::set_var(
                "SIPNAB_AUDIO_PLUGIN",
                "/nonexistent/path/to/libsipnab_audio.so",
            );
        }

        let result = AudioPlayer::new();

        unsafe {
            match prev {
                Some(v) => std::env::set_var("SIPNAB_AUDIO_PLUGIN", v),
                None => std::env::remove_var("SIPNAB_AUDIO_PLUGIN"),
            }
        }

        // The contract is: never panic/abort. The explicit bad path must fail
        // to load; if no other candidate finds a real plugin (the common test
        // case) we get the "Audio playback unavailable" load error. If a real
        // plugin *does* load via a fallback path but no audio device exists
        // (CI), `open()` returns null and we get "No audio output device
        // available". Both are clean `Err`s — what matters is that we did not
        // unwind. Any `Ok` would mean a real device opened, which is also a
        // non-panicking outcome.
        if let Err(e) = &result {
            let msg = e.to_string();
            assert!(!msg.is_empty(), "error message should be non-empty");
        }
    }
}
