// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real-time audio playback from RTP stream payload buffers.
//!
//! Decodes G.711 and Opus audio (pure Rust, no ALSA dependency) and resamples
//! to 48 kHz mono. The actual device output is delegated to the
//! `sipnab-audio` plugin (`libsipnab_audio.so` / `.dylib`), which is the only
//! component linking rodio/ALSA. The plugin is `dlopen`'d lazily on first
//! `AudioPlayer::new`, so the main binary carries no load-time
//! `NEEDED libasound.so.2` ELF entry and starts fine without libasound.

use std::ffi::OsString;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use libloading::{Library, Symbol};

use super::g711::{G711Codec, decode_frame};
use super::opus_decode::OpusStreamDecoder;
use super::stream::RtpStream;

// C ABI of the sipnab-audio plugin (see crates/sipnab-audio/src/lib.rs).

/// Opens the default output device and returns an opaque handle (null on
/// failure).
type OpenFn = unsafe extern "C" fn() -> *mut c_void;
/// Plays a slice of interleaved f32 samples: `(handle, ptr, len, sample_rate,
/// channels)`, returning 0 on success.
type PlayFn = unsafe extern "C" fn(*mut c_void, *const f32, usize, u32, u16) -> i32;
/// Stops playback on the given handle.
type StopFn = unsafe extern "C" fn(*mut c_void);
/// Returns non-zero while the given handle is still playing.
type IsPlayingFn = unsafe extern "C" fn(*mut c_void) -> i32;
/// Closes the given handle and releases the device.
type CloseFn = unsafe extern "C" fn(*mut c_void);

/// Audio player backed by the lazily-loaded `sipnab-audio` plugin.
///
/// The public API is unchanged from the previous rodio-linked implementation
/// so TUI callers need no modification.
///
/// # Thread-safety invariant
///
/// `AudioPlayer` is deliberately **neither `Send` nor `Sync`** and must stay
/// that way. `handle` is an opaque `*mut c_void` owning a live rodio/ALSA
/// output stream inside the plugin; nothing in the plugin's C ABI
/// (`sipnab_audio_{play,stop,is_playing,close}`) promises that handle is safe
/// to touch from another thread or from two threads at once, and rodio's
/// `OutputStream` is itself `!Send + !Sync`. Moving the player across threads
/// or sharing `&self` between them would therefore be unsound.
///
/// Today the raw `handle` pointer already removes the auto `Send`/`Sync` impls,
/// but that is fragile: wrapping `handle` in a `Send`/`Sync` type (an
/// `AtomicPtr`, a `usize`, a newtype with a hand-written `unsafe impl`) would
/// silently make the whole struct thread-shareable and reintroduce the
/// unsoundness. The `_not_send_sync: PhantomData<*const c_void>` field pins the
/// negative traits structurally so they survive such refactors, and the
/// `compile_fail` doctests below fail the build if either trait ever appears:
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<sipnab::rtp::playback::AudioPlayer>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<sipnab::rtp::playback::AudioPlayer>();
/// ```
pub struct AudioPlayer {
    // Raw function pointers resolved from `_lib`. They are only valid while
    // `_lib` is alive, so `_lib` is kept (and dropped last via field order).
    /// Resolved `sipnab_audio_play` symbol.
    play: PlayFn,
    /// Resolved `sipnab_audio_stop` symbol.
    stop: StopFn,
    /// Resolved `sipnab_audio_is_playing` symbol.
    is_playing: IsPlayingFn,
    /// Resolved `sipnab_audio_close` symbol.
    close: CloseFn,
    /// Opaque device handle returned by `sipnab_audio_open`.
    handle: *mut c_void,
    /// Pins `AudioPlayer: !Send + !Sync` structurally (see the type's
    /// thread-safety invariant), independent of how `handle` is later
    /// represented. `*const c_void` is itself `!Send + !Sync`, so this marker
    /// keeps the negative traits even if the raw `handle` pointer is replaced
    /// with a thread-shareable type.
    _not_send_sync: PhantomData<*const c_void>,
    // The loaded plugin library. MUST outlive the function pointers above and
    // the handle; it is dropped last (struct fields drop in declaration order,
    // so `_lib` is listed last here).
    /// The loaded plugin library, dropped last so the symbols above stay valid.
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
            _not_send_sync: PhantomData,
            _lib: lib,
        })
    }

    /// Play audio from an RTP stream's payload buffer.
    ///
    /// Supports G.711 (PCMU/PCMA) and Opus codecs. G.711 is decoded at
    /// 8 kHz and resampled to 48 kHz; Opus decodes natively at 48 kHz.
    pub fn play_stream(&self, stream: &RtpStream) -> Result<String> {
        if stream.payload_buffer.is_empty() {
            // The same explanation the exporter gives, from the same function.
            //
            // This line used to read "No audio payload captured" -- verbatim
            // the wording `nothing_to_decode` was written to replace, and which
            // its doc comment names as the defect: a reader takes it as a
            // statement about the CALL. Only one of the two functions that
            // decode `payload_buffer` was migrated, so pressing `P` in the TUI
            // still produced the sentence the exporter had stopped saying.
            bail!(crate::rtp::audio_export::nothing_to_decode(&[stream]));
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
    /// Closes the plugin device handle exactly once (side effect: releases the
    /// audio device), then lets `_lib` drop to unload the plugin.
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

/// Environment variable naming an alternate plugin to load.
///
/// A development aid, not a configuration knob: see [`env_override_candidate`]
/// for why it is tried last and what has to hold before it is honored at all.
const PLUGIN_OVERRIDE_ENV: &str = "SIPNAB_AUDIO_PLUGIN";

/// Trusted plugin locations, in the order they are tried:
/// 1. next to the current executable (dev builds and relocatable installs),
/// 2. `/usr/lib/sipnab/<soname>` (the Debian package's location),
/// 3. the bare soname, resolved through the dynamic loader's search path.
///
/// Writing to any of these already implies the ability to replace the sipnab
/// binary or the package that installed it, so loading from them confers no
/// authority an attacker did not already hold.
fn trusted_plugin_candidates() -> Vec<OsString> {
    let filename = plugin_filename();
    let mut candidates: Vec<OsString> = Vec::new();

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

/// Why a `$SIPNAB_AUDIO_PLUGIN` path was refused, phrased for the log line that
/// reports it.
///
/// The variants are per-platform because the checks are: only Unix can inspect
/// process credentials and file ownership, so everywhere else there is exactly
/// one answer and it is "no".
#[derive(Debug, PartialEq, Eq)]
enum OverrideRefusal {
    /// The process gained privileges at `execve`, so its environment came from
    /// across a trust boundary and cannot select native code.
    #[cfg(unix)]
    Elevated,
    /// The path could not be inspected (missing, or unreadable directory).
    #[cfg(unix)]
    Unreadable,
    /// The path is not a regular file.
    #[cfg(unix)]
    NotAFile,
    /// Owned by neither `root` nor the invoking user, carrying the owner's uid.
    #[cfg(unix)]
    ForeignOwner(u32),
    /// Writable by group or other, carrying the offending mode bits.
    #[cfg(unix)]
    SharedWritable(u32),
    /// Sits in a non-sticky directory writable by group or other, carrying that
    /// directory's mode.
    #[cfg(unix)]
    SwappableLocation(u32),
    /// This platform cannot check ownership or process credentials, so the
    /// override is never honored on it.
    #[cfg(not(unix))]
    Unsupported,
}

impl fmt::Display for OverrideRefusal {
    /// Renders the refusal as the reason half of a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Elevated => f.write_str(
                "sipnab is running with privileges it did not inherit (setuid, setgid \
                 or file capabilities such as cap_net_raw), so the environment is not \
                 trusted to name native code",
            ),
            #[cfg(unix)]
            Self::Unreadable => f.write_str("path cannot be read"),
            #[cfg(unix)]
            Self::NotAFile => f.write_str("path is not a regular file"),
            #[cfg(unix)]
            Self::ForeignOwner(uid) => {
                write!(f, "file is owned by uid {uid}, neither root nor this user")
            }
            #[cfg(unix)]
            Self::SharedWritable(mode) => {
                write!(f, "file is group- or world-writable (mode {mode:04o})")
            }
            #[cfg(unix)]
            Self::SwappableLocation(mode) => write!(
                f,
                "file sits in a group- or world-writable, non-sticky directory \
                 (mode {mode:04o}), where another user can substitute it"
            ),
            #[cfg(not(unix))]
            Self::Unsupported => f.write_str("this platform cannot verify who owns the file"),
        }
    }
}

/// True when this process gained privileges at `execve`: setuid, setgid, or
/// file capabilities such as the `cap_net_raw` that sipnab's own `--setup-caps`
/// installs.
///
/// This is the case the override gate exists for. A privileged sipnab inherits
/// the environment of an unprivileged invoker, so honoring an env-var plugin
/// path there would hand that invoker native code execution inside a process
/// holding TLS key material, bearer tokens and the capture handle.
#[cfg(unix)]
fn started_privileged() -> bool {
    // SAFETY: getuid/geteuid/getgid/getegid take no arguments, cannot fail, and
    // only read this process's own credentials.
    let ids_differ =
        unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() };

    // File capabilities leave uid == euid, so comparing ids alone misses the
    // setcap deployment entirely — which is precisely how sipnab is meant to be
    // installed for live capture. AT_SECURE is the kernel's own verdict and
    // covers setuid, setgid and file capabilities alike.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getauxval reads the auxiliary vector the kernel placed in this
        // process at exec. It takes a scalar, cannot fail, and returns 0 for an
        // absent entry.
        ids_differ || unsafe { libc::getauxval(libc::AT_SECURE) } != 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        ids_differ
    }
}

/// Decide whether the override may be honored for `path`.
///
/// "The environment is trusted" only holds while the file it names is trusted
/// too, so ownership and mode are checked as well as process credentials: a
/// world-writable plugin, or one in a directory another user can write, is
/// attacker-controlled no matter who set the variable.
///
/// The check is on the path as given. A symlink whose *intermediate* directories
/// are writable by others is not detected; catching that needs a resolve-and-lock
/// dance that `dlopen`'s own open would still race.
#[cfg(unix)]
fn vet_override(path: &Path) -> Result<(), OverrideRefusal> {
    use std::os::unix::fs::MetadataExt;

    if started_privileged() {
        return Err(OverrideRefusal::Elevated);
    }

    // Follows symlinks on purpose: what matters is who owns the file `dlopen`
    // will actually map.
    let meta = std::fs::metadata(path).map_err(|_| OverrideRefusal::Unreadable)?;
    if !meta.is_file() {
        return Err(OverrideRefusal::NotAFile);
    }
    // SAFETY: getuid takes no arguments, cannot fail, and only reads this
    // process's own real uid.
    let own_uid = unsafe { libc::getuid() };
    if meta.uid() != 0 && meta.uid() != own_uid {
        return Err(OverrideRefusal::ForeignOwner(meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(OverrideRefusal::SharedWritable(meta.mode() & 0o7777));
    }

    // A file nobody else can write is still swappable when its directory is
    // writable by others: rename over it and the mode above proves nothing. The
    // sticky bit is what makes a shared directory (`/tmp`) safe, because it
    // stops non-owners renaming or unlinking entries.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let dir = std::fs::metadata(parent).map_err(|_| OverrideRefusal::Unreadable)?;
        if dir.mode() & 0o022 != 0 && dir.mode() & 0o1000 == 0 {
            return Err(OverrideRefusal::SwappableLocation(dir.mode() & 0o7777));
        }
    }
    Ok(())
}

/// Non-Unix builds cannot read process credentials or file ownership, so the
/// override is refused outright rather than trusted blindly.
#[cfg(not(unix))]
fn vet_override(_path: &Path) -> Result<(), OverrideRefusal> {
    Err(OverrideRefusal::Unsupported)
}

/// The `$SIPNAB_AUDIO_PLUGIN` override, if it is set and passes vetting.
///
/// `dlopen` executes the library's initialisers immediately, as native
/// unsandboxed code in a process that holds TLS key material, bearer tokens and
/// the capture handle. This path is the only candidate an outside party can
/// influence, so it is deliberately tried **last**: a trusted plugin, when one
/// is installed, always wins and the variable cannot preempt it. It is honored
/// at all only for a genuinely unprivileged process pointing at a file that
/// nobody else can rewrite — and it says so loudly when it is used, because a
/// developer override that goes unnoticed in production is the same bug again.
fn env_override_candidate() -> Option<OsString> {
    let raw = std::env::var_os(PLUGIN_OVERRIDE_ENV)?;
    let path = PathBuf::from(&raw);
    match vet_override(&path) {
        Ok(()) => {
            tracing::warn!(
                "loading the audio plugin from ${PLUGIN_OVERRIDE_ENV} ({}) — a \
                 development override that runs unsandboxed native code inside \
                 sipnab; unset it outside development",
                path.display(),
            );
            Some(raw)
        }
        Err(reason) => {
            tracing::warn!(
                "ignoring ${PLUGIN_OVERRIDE_ENV} ({}): {reason}",
                path.display(),
            );
            None
        }
    }
}

/// Build the ordered list of candidate plugin paths: every trusted location
/// first, then the vetted development override, if any.
fn plugin_candidates() -> Vec<OsString> {
    let mut candidates = trusted_plugin_candidates();
    candidates.extend(env_override_candidate());
    candidates
}

/// Resolve and `dlopen` the audio plugin, trying `plugin_candidates` in
/// order and returning the first that loads.
fn load_plugin() -> Result<Library> {
    let candidates = plugin_candidates();

    let mut last_err = String::from("no candidate paths");
    for cand in &candidates {
        // SAFETY: `dlopen` runs the library's initialisers in this process, so
        // this is only sound for a library sipnab trusts. Every candidate here
        // is one: `trusted_plugin_candidates` yields sipnab's own build and
        // install locations, and the single externally-influenced path,
        // `$SIPNAB_AUDIO_PLUGIN`, is gated by `env_override_candidate` and
        // ordered behind them. Errors are non-fatal (we try the next candidate).
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
///
/// Thin wrapper over the shared [`resample_linear`](crate::rtp::audio_export::resample_linear)
/// core, which the i16 WAV-export path also uses; the f32 per-sample
/// arithmetic is unchanged.
fn resample_f32(samples: &[f32], from_rate: u32, to_rate: u32) -> Vec<f32> {
    crate::rtp::audio_export::resample_linear(samples, from_rate, to_rate)
}

// Tests cover the device-free DSP helpers (decode + resample) and the plugin
// load/error paths. The rodio device path lives in the `sipnab-audio` plugin
// and is hardware-bound, so it stays uncovered by design.
/// Unit tests for the device-free DSP helpers and plugin load/error paths.
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

    /// Resampling at an equal rate, or an empty input, is an identity operation.
    #[test]
    fn resample_same_rate_and_empty_are_identity() {
        let s = vec![0.1, -0.2, 0.3];
        assert_eq!(resample_f32(&s, 8000, 8000), s);
        assert_eq!(resample_f32(&[], 8000, 16000), Vec::<f32>::new());
    }

    /// Up- and down-sampling produce output lengths scaled by the rate ratio.
    #[test]
    fn resample_upsample_and_downsample_lengths() {
        let s = vec![0.0f32; 100];
        // 8k -> 16k roughly doubles the sample count.
        assert_eq!(resample_f32(&s, 8000, 16000).len(), 200);
        // 48k -> 8k roughly divides by six.
        let s = vec![0.0f32; 60];
        assert_eq!(resample_f32(&s, 48000, 8000).len(), 10);
    }

    /// 2x upsampling linearly interpolates a midpoint between two samples.
    #[test]
    fn resample_linear_interpolation_values() {
        // Upsampling [0.0, 1.0] by 2x interpolates a midpoint near 0.5.
        let out = resample_f32(&[0.0, 1.0], 8000, 16000);
        assert_eq!(out.len(), 4);
        assert!((out[0] - 0.0).abs() < 1e-6);
        assert!((out[1] - 0.5).abs() < 1e-6, "midpoint should interpolate");
    }

    /// G.711 decode yields one f32 sample per byte, all within [-1.0, 1.0].
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

    /// A PCMA stream carrying a single 160-byte A-law frame.
    fn stream_with_frame() -> RtpStream {
        let mut s = stream(8); // PCMA
        s.payload_buffer.push_back((0, vec![0x55u8; 160]));
        s
    }

    /// Decoding a stream with no captured frames yields empty PCM.
    #[test]
    fn decode_g711_empty_stream_is_empty() {
        assert!(decode_g711_to_f32(G711Codec::Ulaw, &stream(0)).is_empty());
    }

    /// Opus decode returns `Ok` for an empty stream and skips undecodable
    /// frames without erroring.
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

    /// The plugin filename carries the base name and the platform DLL suffix.
    #[test]
    fn plugin_filename_is_platform_appropriate() {
        let name = plugin_filename();
        assert!(name.contains("sipnab_audio"));
        // On Linux this is `libsipnab_audio.so`; on macOS `.dylib`.
        assert!(name.ends_with(std::env::consts::DLL_SUFFIX));
    }

    /// Sets `SIPNAB_AUDIO_PLUGIN` for the guard's lifetime and restores the
    /// previous value — or its absence — on drop.
    ///
    /// Pair every use with `#[serial_test::serial(sipnab_audio_plugin_env)]`:
    /// the environment is process-global and cargo runs these tests on threads.
    struct EnvGuard {
        /// The value to put back on drop, or `None` if the variable was unset.
        prev: Option<OsString>,
    }

    impl EnvGuard {
        /// Point `SIPNAB_AUDIO_PLUGIN` at `value`.
        fn set(value: &std::ffi::OsStr) -> Self {
            let prev = std::env::var_os(PLUGIN_OVERRIDE_ENV);
            // SAFETY: set_var is unsafe in edition 2024 because it races other
            // threads reading the environment; the serial attribute on every
            // caller is what makes this single-threaded with respect to it.
            unsafe { std::env::set_var(PLUGIN_OVERRIDE_ENV, value) };
            Self { prev }
        }
    }

    impl Drop for EnvGuard {
        /// Restores the variable to whatever it was before `set`.
        fn drop(&mut self) {
            // SAFETY: same as `set` — serialized against other env readers.
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(PLUGIN_OVERRIDE_ENV, v),
                    None => std::env::remove_var(PLUGIN_OVERRIDE_ENV),
                }
            }
        }
    }

    /// A scratch directory created with the given mode and removed on drop.
    struct ScratchDir {
        /// Absolute path of the directory.
        path: PathBuf,
    }

    impl ScratchDir {
        /// Create a uniquely named directory under the system temp dir.
        #[cfg(unix)]
        fn new(tag: &str, mode: u32) -> Self {
            use std::os::unix::fs::PermissionsExt;
            use std::sync::atomic::{AtomicU32, Ordering};

            // A counter, not a timestamp: two tests can start in the same
            // millisecond and must not collide on the directory name.
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "sipnab-playback-{}-{tag}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create scratch dir");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set scratch dir mode");
            Self { path }
        }

        /// Write a file into the directory with the given mode and return it.
        #[cfg(unix)]
        fn file(&self, name: &str, mode: u32) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;

            let file = self.path.join(name);
            std::fs::write(&file, b"not a real shared object").expect("write scratch file");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode))
                .expect("set scratch file mode");
            file
        }
    }

    impl Drop for ScratchDir {
        /// Removes the directory tree; failure to clean up is not a test failure.
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // A 0500 directory cannot be emptied, so restore write access
                // before removing it.
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// The trusted list is built without consulting the environment at all, so
    /// setting the variable cannot inject a path into it.
    #[test]
    #[serial_test::serial(sipnab_audio_plugin_env)]
    fn trusted_candidates_never_include_the_env_override() {
        let injected = OsString::from("/nonexistent/attacker/libsipnab_audio.so");
        let _env = EnvGuard::set(&injected);

        let trusted = trusted_plugin_candidates();
        assert!(
            !trusted.contains(&injected),
            "the env var must not reach the trusted candidate list: {trusted:?}"
        );
        assert!(
            !trusted.is_empty(),
            "there must always be at least the bare soname to try"
        );
    }

    /// A vetted override is appended after every trusted path, so an installed
    /// plugin always loads first and the variable cannot preempt it.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial(sipnab_audio_plugin_env)]
    fn env_override_is_ordered_behind_every_trusted_path() {
        if started_privileged() {
            // A privileged process refuses the override outright; that is the
            // subject of `vet_override_refuses_when_privileges_were_gained`.
            return;
        }
        let dir = ScratchDir::new("ordering", 0o700);
        let plugin = dir.file("libsipnab_audio.so", 0o644);
        let _env = EnvGuard::set(plugin.as_os_str());

        let trusted = trusted_plugin_candidates();
        let all = plugin_candidates();

        assert_eq!(
            all.len(),
            trusted.len() + 1,
            "the vetted override should add exactly one candidate"
        );
        assert_eq!(
            all.last().map(std::ffi::OsString::as_os_str),
            Some(plugin.as_os_str()),
            "the override must be the last candidate, never the first"
        );
        assert_eq!(
            &all[..trusted.len()],
            &trusted[..],
            "trusted order preserved"
        );
    }

    /// An override that fails vetting is dropped entirely: the candidate list
    /// is exactly the trusted one.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial(sipnab_audio_plugin_env)]
    fn rejected_override_leaves_only_trusted_candidates() {
        let dir = ScratchDir::new("rejected", 0o700);
        // World-writable: anyone on the box could rewrite it between the check
        // and the `dlopen`, so it is never a candidate.
        let plugin = dir.file("libsipnab_audio.so", 0o666);
        let _env = EnvGuard::set(plugin.as_os_str());

        assert_eq!(plugin_candidates(), trusted_plugin_candidates());
    }

    /// A file only its owner can write, in a directory only its owner can
    /// write, is the one shape the override accepts.
    #[cfg(unix)]
    #[test]
    fn vet_override_accepts_owner_only_file() {
        if started_privileged() {
            return;
        }
        let dir = ScratchDir::new("accept", 0o700);
        let plugin = dir.file("libsipnab_audio.so", 0o644);

        assert_eq!(vet_override(&plugin), Ok(()));
    }

    /// Group- or world-writable plugins are refused: their content is not
    /// pinned to their owner.
    #[cfg(unix)]
    #[test]
    fn vet_override_refuses_shared_writable_file() {
        if started_privileged() {
            return;
        }
        let dir = ScratchDir::new("mode", 0o700);

        assert_eq!(
            vet_override(&dir.file("world.so", 0o666)),
            Err(OverrideRefusal::SharedWritable(0o666))
        );
        assert_eq!(
            vet_override(&dir.file("group.so", 0o664)),
            Err(OverrideRefusal::SharedWritable(0o664))
        );
    }

    /// A private file in a world-writable, non-sticky directory is refused:
    /// another user can rename their own file over it.
    #[cfg(unix)]
    #[test]
    fn vet_override_refuses_swappable_location() {
        if started_privileged() {
            return;
        }
        let dir = ScratchDir::new("swappable", 0o777);
        let plugin = dir.file("libsipnab_audio.so", 0o644);

        assert_eq!(
            vet_override(&plugin),
            Err(OverrideRefusal::SwappableLocation(0o777))
        );
    }

    /// A sticky world-writable directory (the `/tmp` shape) is accepted: the
    /// sticky bit stops non-owners replacing entries.
    #[cfg(unix)]
    #[test]
    fn vet_override_accepts_sticky_shared_directory() {
        if started_privileged() {
            return;
        }
        let dir = ScratchDir::new("sticky", 0o1777);
        let plugin = dir.file("libsipnab_audio.so", 0o644);

        assert_eq!(vet_override(&plugin), Ok(()));
    }

    /// Missing paths and directories are refused rather than handed to `dlopen`.
    #[cfg(unix)]
    #[test]
    fn vet_override_refuses_missing_path_and_directory() {
        if started_privileged() {
            return;
        }
        let dir = ScratchDir::new("shape", 0o700);

        assert_eq!(
            vet_override(&dir.path.join("absent.so")),
            Err(OverrideRefusal::Unreadable)
        );
        assert_eq!(vet_override(&dir.path), Err(OverrideRefusal::NotAFile));
    }

    /// Every refusal renders a non-empty, distinct reason, since the log line is
    /// the only place a rejected override is ever visible.
    #[cfg(unix)]
    #[test]
    fn refusal_reasons_are_distinct_and_non_empty() {
        let all = [
            OverrideRefusal::Elevated,
            OverrideRefusal::Unreadable,
            OverrideRefusal::NotAFile,
            OverrideRefusal::ForeignOwner(1000),
            OverrideRefusal::SharedWritable(0o666),
            OverrideRefusal::SwappableLocation(0o777),
        ];
        let rendered: Vec<String> = all.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|r| !r.is_empty()));
        let unique: std::collections::BTreeSet<&String> = rendered.iter().collect();
        assert_eq!(unique.len(), rendered.len(), "reasons must not collide");
        assert!(
            rendered[3].contains("1000"),
            "the owning uid belongs in the message: {}",
            rendered[3]
        );
    }

    /// A non-existent explicit plugin path does not `dlopen` successfully.
    #[test]
    fn explicit_nonexistent_plugin_path_does_not_load() {
        // A non-existent explicit path must not dlopen successfully. We test
        // the candidate directly to stay independent of fallback paths.
        let bad = OsString::from("/nonexistent/path/to/libsipnab_audio.so");
        // SAFETY: loading a (missing) library; the call simply fails.
        let loaded = unsafe { Library::new(&bad) }.is_ok();
        assert!(!loaded, "a non-existent plugin path must not load");
    }

    /// A missing plugin makes `AudioPlayer::new` return an `Err`, never panic.
    #[test]
    #[serial_test::serial(sipnab_audio_plugin_env)]
    fn new_with_missing_plugin_returns_err_not_panic() {
        // A non-existent override is refused by vetting and dropped, so this
        // runs against the trusted candidates alone. None of them is likely to
        // find a real plugin in the test environment, which is what exercises
        // the graceful-fallback error path (no panic/abort).
        let _env = EnvGuard::set(std::ffi::OsStr::new(
            "/nonexistent/path/to/libsipnab_audio.so",
        ));

        let result = AudioPlayer::new();

        // The contract is: never panic/abort. If no candidate finds a real
        // plugin (the common test case) we get the "Audio playback unavailable"
        // load error. If a real plugin *does* load but no audio device exists
        // (CI), `open()` returns null and we get "No audio output device
        // available". Both are clean `Err`s — what matters is that we did not
        // unwind. Any `Ok` would mean a real device opened, which is also a
        // non-panicking outcome.
        if let Err(e) = &result {
            let msg = e.to_string();
            assert!(!msg.is_empty(), "error message should be non-empty");
        }
    }

    /// The load failure keeps telling the user how to fix it. The message is
    /// the entire remedy for the most common cause (no libasound2 installed),
    /// so it must survive changes to the candidate order.
    #[test]
    #[serial_test::serial(sipnab_audio_plugin_env)]
    fn load_failure_still_names_libasound_and_the_wav_fallback() {
        let _env = EnvGuard::set(std::ffi::OsStr::new(
            "/nonexistent/path/to/libsipnab_audio.so",
        ));

        // A real plugin next to the test binary would make this load succeed;
        // only the failure path carries the message under test.
        if let Err(e) = load_plugin() {
            let msg = e.to_string();
            assert!(msg.contains("libasound2"), "missing the remedy: {msg}");
            assert!(msg.contains("apt install"), "missing the command: {msg}");
            assert!(msg.contains("WAV"), "missing the fallback: {msg}");
        }
    }
}
