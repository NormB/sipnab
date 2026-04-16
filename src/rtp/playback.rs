//! Real-time audio playback from RTP stream payload buffers.
//!
//! Decodes G.711 audio, resamples to the system output rate, and plays
//! through the default audio device via rodio. The resampler uses simple
//! linear interpolation which is perfectly adequate for 8 kHz voice preview.

use std::num::NonZero;

use anyhow::{Result, bail};
use rodio::DeviceSinkBuilder;
use rodio::Player;
use rodio::buffer::SamplesBuffer;
use rodio::stream::MixerDeviceSink;

use super::g711::{G711Codec, decode_frame};
use super::stream::RtpStream;

/// Audio player wrapping a rodio output device and player.
pub struct AudioPlayer {
    player: Player,
    _device_sink: MixerDeviceSink,
}

impl AudioPlayer {
    /// Create a new audio player using the default output device.
    pub fn new() -> Result<Self> {
        let mut device_sink = DeviceSinkBuilder::open_default_sink()
            .map_err(|e| anyhow::anyhow!("No audio output device: {e}"))?;
        device_sink.log_on_drop(false);
        let player = Player::connect_new(device_sink.mixer());
        Ok(Self {
            player,
            _device_sink: device_sink,
        })
    }

    /// Play audio from an RTP stream's payload buffer.
    pub fn play_stream(&self, stream: &RtpStream) -> Result<String> {
        let codec = match stream.codec.as_deref() {
            Some("PCMU") => G711Codec::Ulaw,
            Some("PCMA") => G711Codec::Alaw,
            Some(other) => bail!("Unsupported codec for playback: {other}"),
            None => bail!("Unknown codec"),
        };

        if stream.payload_buffer.is_empty() {
            bail!("No audio payload captured");
        }

        // Decode all G.711 frames to PCM f32
        let mut pcm_8k: Vec<f32> = Vec::new();
        for (_ts, payload) in &stream.payload_buffer {
            let decoded = decode_frame(codec, payload);
            for sample in decoded {
                pcm_8k.push(sample as f32 / 32768.0);
            }
        }

        // Resample 8 kHz -> 48 kHz using linear interpolation
        // (perfectly adequate for voice preview quality)
        let output_rate = 48000u32;
        let ratio = output_rate as f64 / stream.clock_rate as f64;
        let output_len = (pcm_8k.len() as f64 * ratio) as usize;
        let mut pcm_48k = Vec::with_capacity(output_len);
        for i in 0..output_len {
            let src_pos = i as f64 / ratio;
            let src_idx = src_pos as usize;
            let frac = (src_pos - src_idx as f64) as f32;
            let s0 = pcm_8k.get(src_idx).copied().unwrap_or(0.0);
            let s1 = pcm_8k.get(src_idx + 1).copied().unwrap_or(s0);
            pcm_48k.push(s0 + (s1 - s0) * frac);
        }

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
            match codec {
                G711Codec::Ulaw => "mu-law",
                G711Codec::Alaw => "A-law",
            },
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
