//! Real-time audio playback from RTP stream payload buffers.
//!
//! Decodes G.711 and Opus audio, resamples to the system output rate, and
//! plays through the default audio device via rodio. G.711 is resampled
//! from 8 kHz; Opus decodes natively at 48 kHz (no resampling needed).

use std::io::Write;
use std::num::NonZero;

use anyhow::{Result, bail};
use rodio::DeviceSinkBuilder;
use rodio::Player;
use rodio::buffer::SamplesBuffer;
use rodio::stream::MixerDeviceSink;

use super::g711::{G711Codec, decode_frame};
use super::opus_decode::OpusStreamDecoder;
use super::stream::RtpStream;

/// Audio player wrapping a rodio output device and player.
pub struct AudioPlayer {
    player: Player,
    _device_sink: MixerDeviceSink,
}

impl AudioPlayer {
    /// Create a new audio player using the default output device.
    pub fn new() -> Result<Self> {
        let mut device_sink = {
            // libasound writes config/device errors straight to stderr,
            // which corrupts the alternate-screen TUI. Redirect stderr
            // to /dev/null for the duration of the device open.
            let _silencer = StderrSilencer::new();
            DeviceSinkBuilder::open_default_sink()
        }
        .map_err(|e| {
            anyhow::anyhow!(
                "No audio output device available ({e}). \
                 Use F2 to save the stream as a WAV file instead."
            )
        })?;
        device_sink.log_on_drop(false);
        let player = Player::connect_new(device_sink.mixer());
        Ok(Self {
            player,
            _device_sink: device_sink,
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
        let channels = match NonZero::new(1u16) {
            Some(c) => c,
            None => bail!("invalid channel count"),
        };
        let sample_rate = match NonZero::new(output_rate) {
            Some(r) => r,
            None => bail!("invalid sample rate"),
        };
        let source = SamplesBuffer::new(channels, sample_rate, pcm_48k);
        self.player.append(source);

        Ok(format!(
            "Playing {:.1}s of {} audio ({} frames)",
            duration_secs,
            codec_label,
            stream.payload_buffer.len(),
        ))
    }

    /// Stop playback immediately.
    pub fn stop(&self) {
        self.player.stop();
    }

    /// Check if audio is currently playing.
    pub fn is_playing(&self) -> bool {
        !self.player.empty()
    }
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

/// RAII guard that redirects stderr to /dev/null while alive.
///
/// Used during audio device initialization so that libasound's C-level
/// error output (e.g. ALSA config evaluation failures on Tegra/Jetson)
/// does not bleed through and corrupt the TUI's alternate screen.
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
