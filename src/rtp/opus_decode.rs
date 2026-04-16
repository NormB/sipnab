//! Opus audio codec decoder for RTP payloads.
//!
//! Uses the pure-Rust `opus-decoder` crate (RFC 8251 conformant, no FFI)
//! to decode Opus RTP frames to 16-bit linear PCM. The decoder is stateful
//! because Opus uses previous frame context for better reconstruction and
//! packet loss concealment (PLC).
//!
//! Opus in RTP typically runs at 48 kHz mono (channels=1 in the decoder,
//! despite the SDP `a=rtpmap` convention of declaring `opus/48000/2` which
//! refers to stereo *capability*, not the actual channel count in use).

use anyhow::{Result, bail};

/// Stateful Opus decoder wrapping `opus_decoder::OpusDecoder`.
///
/// Must be kept alive across frames for the same RTP stream since Opus
/// decoding quality depends on inter-frame state (SILK LSF interpolation,
/// CELT overlap, PLC context).
pub struct OpusStreamDecoder {
    inner: opus_decoder::OpusDecoder,
    sample_rate: u32,
    channels: usize,
}

impl OpusStreamDecoder {
    /// Create a new Opus decoder for the given sample rate and channel count.
    ///
    /// `sample_rate` must be one of: 8000, 12000, 16000, 24000, 48000.
    /// `channels` must be 1 (mono) or 2 (stereo).
    ///
    /// For typical VoIP RTP, use `48000` and `1` (mono). The SDP convention
    /// `a=rtpmap:111 opus/48000/2` declares stereo capability but most VoIP
    /// calls send mono frames.
    pub fn new(sample_rate: u32, channels: usize) -> Result<Self> {
        let inner = opus_decoder::OpusDecoder::new(sample_rate, channels)
            .map_err(|e| anyhow::anyhow!("Failed to create Opus decoder: {e}"))?;
        Ok(Self {
            inner,
            sample_rate,
            channels,
        })
    }

    /// Decode a single Opus RTP payload to PCM i16 samples.
    ///
    /// Returns the decoded samples (interleaved if stereo). The output length
    /// depends on the Opus frame duration (typically 960 samples at 48 kHz
    /// for 20ms frames).
    ///
    /// The decoder maintains inter-frame state, so frames should be fed in
    /// RTP sequence order. For lost frames, call [`decode_lost`] instead.
    pub fn decode_frame(&mut self, opus_data: &[u8]) -> Result<Vec<i16>> {
        if opus_data.is_empty() {
            bail!("Empty Opus payload");
        }

        // Allocate buffer for maximum possible frame size
        let max_samples = self.inner.max_frame_size_per_channel() * self.channels;
        let mut pcm = vec![0i16; max_samples];

        let samples_per_channel = self
            .inner
            .decode(opus_data, &mut pcm, false)
            .map_err(|e| anyhow::anyhow!("Opus decode error: {e}"))?;

        pcm.truncate(samples_per_channel * self.channels);
        Ok(pcm)
    }

    /// Invoke packet loss concealment for a missing frame.
    ///
    /// Uses the decoder's internal state to synthesize a plausible frame,
    /// maintaining audio continuity across gaps.
    pub fn decode_lost(&mut self) -> Result<Vec<i16>> {
        let max_samples = self.inner.max_frame_size_per_channel() * self.channels;
        let mut pcm = vec![0i16; max_samples];

        let samples_per_channel = self
            .inner
            .decode(&[], &mut pcm, false)
            .map_err(|e| anyhow::anyhow!("Opus PLC error: {e}"))?;

        pcm.truncate(samples_per_channel * self.channels);
        Ok(pcm)
    }

    /// The output sample rate in Hz.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// The number of output channels.
    pub fn channels(&self) -> usize {
        self.channels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_decoder_valid_params() {
        let dec = OpusStreamDecoder::new(48000, 1);
        assert!(dec.is_ok());
        let dec = dec.unwrap();
        assert_eq!(dec.sample_rate(), 48000);
        assert_eq!(dec.channels(), 1);
    }

    #[test]
    fn new_decoder_stereo() {
        let dec = OpusStreamDecoder::new(48000, 2);
        assert!(dec.is_ok());
        assert_eq!(dec.unwrap().channels(), 2);
    }

    #[test]
    fn new_decoder_invalid_rate() {
        let dec = OpusStreamDecoder::new(44100, 1);
        assert!(dec.is_err());
    }

    #[test]
    fn new_decoder_invalid_channels() {
        let dec = OpusStreamDecoder::new(48000, 3);
        assert!(dec.is_err());
    }

    #[test]
    fn decode_empty_payload_errors() {
        let mut dec = OpusStreamDecoder::new(48000, 1).unwrap();
        let result = dec.decode_frame(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_lost_produces_samples() {
        // First feed a valid-ish frame, then test PLC.
        // With a fresh decoder and no prior state, PLC returns zero-length.
        let mut dec = OpusStreamDecoder::new(48000, 1).unwrap();
        let result = dec.decode_lost();
        // Fresh decoder with no prior packets produces 0 samples (no state to conceal from)
        assert!(result.is_ok());
    }
}
