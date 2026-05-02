//! Audio export from RTP streams to WAV files.
//!
//! Decodes G.711 (PCMU/PCMA) and Opus RTP payload buffers into 16-bit
//! linear PCM and writes standard WAV files. Supports mono (single stream)
//! and stereo (two streams interleaved as left/right channels) export.
//!
//! G.711 streams export at 8 kHz; Opus streams export at 48 kHz. When
//! mixing G.711 and Opus in stereo mode, the G.711 channel is resampled
//! to 48 kHz to match.

use std::path::Path;

use anyhow::{Result, bail};

use super::g711::{G711Codec, decode_frame};
use super::opus_decode::OpusStreamDecoder;
use super::stream::RtpStream;
use super::wav::write_wav;

/// Export a single RTP stream to a mono WAV file.
///
/// Decodes all captured payloads in the stream's ring buffer to 16-bit
/// linear PCM and writes a mono WAV. G.711 streams export at 8 kHz;
/// Opus streams export at 48 kHz.
///
/// # Errors
///
/// Returns an error if:
/// - The stream codec is not PCMU, PCMA, or Opus
/// - No audio payloads have been captured
/// - The WAV file cannot be written
pub fn export_stream_to_wav(stream: &RtpStream, path: &Path) -> Result<String> {
    if stream.payload_buffer.is_empty() {
        bail!("No audio payload captured for this stream.");
    }

    let (pcm_samples, sample_rate, codec_label) = decode_stream_pcm(stream)?;
    let duration_secs = pcm_samples.len() as f64 / sample_rate as f64;
    write_wav(path, &pcm_samples, sample_rate, 1)?;

    Ok(format!(
        "Exported {:.1}s of {} audio ({} frames, {}/{}Hz) to {}",
        duration_secs,
        codec_label,
        stream.payload_buffer.len(),
        stream.codec.as_deref().unwrap_or("?"),
        sample_rate,
        path.display(),
    ))
}

/// Export multiple streams (dialog) to a WAV file.
///
/// - If exactly one exportable stream: creates a mono WAV.
/// - If two or more exportable streams: creates a stereo WAV with the first
///   stream as the left channel and the second as the right channel.
///
/// G.711 and Opus streams with captured payload data are considered
/// exportable. When mixing codecs at different sample rates (e.g., G.711
/// at 8 kHz and Opus at 48 kHz), the lower-rate channel is resampled up.
///
/// # Errors
///
/// Returns an error if no exportable streams are found.
pub fn export_dialog_to_wav(streams: &[&RtpStream], path: &Path) -> Result<String> {
    if streams.is_empty() {
        bail!("No RTP streams to export");
    }

    // Filter to streams with decodable audio payload data
    let exportable: Vec<&RtpStream> = streams
        .iter()
        .filter(|s| is_exportable_codec(s.codec.as_deref()) && !s.payload_buffer.is_empty())
        .copied()
        .collect();

    if exportable.is_empty() {
        bail!("No audio streams with captured data found");
    }

    if exportable.len() == 1 {
        return export_stream_to_wav(exportable[0], path);
    }

    // Stereo: decode both streams
    let (mut left_pcm, left_rate, _) = decode_stream_pcm(exportable[0])?;
    let (mut right_pcm, right_rate, _) = decode_stream_pcm(exportable[1])?;

    // Use the higher sample rate as the output rate; resample the lower one
    let output_rate = left_rate.max(right_rate);
    if left_rate < output_rate {
        left_pcm = resample_linear(&left_pcm, left_rate, output_rate);
    }
    if right_rate < output_rate {
        right_pcm = resample_linear(&right_pcm, right_rate, output_rate);
    }

    // Pad the shorter channel with silence so both are the same length
    let max_len = left_pcm.len().max(right_pcm.len());
    left_pcm.resize(max_len, 0);
    right_pcm.resize(max_len, 0);

    // Interleave: L0, R0, L1, R1, ...
    let mut interleaved: Vec<i16> = Vec::with_capacity(max_len * 2);
    for i in 0..max_len {
        interleaved.push(left_pcm[i]);
        interleaved.push(right_pcm[i]);
    }

    let duration_secs = max_len as f64 / output_rate as f64;
    write_wav(path, &interleaved, output_rate, 2)?;

    Ok(format!(
        "Exported {:.1}s stereo audio ({} + {} frames, {}Hz) to {}",
        duration_secs,
        exportable[0].payload_buffer.len(),
        exportable[1].payload_buffer.len(),
        output_rate,
        path.display(),
    ))
}

/// Check whether a codec name represents a decodable audio codec.
fn is_exportable_codec(codec: Option<&str>) -> bool {
    matches!(
        codec,
        Some("PCMU") | Some("PCMA") | Some("opus") | Some("OPUS") | Some("Opus")
    )
}

/// Check if a codec name is Opus (case-insensitive per SDP convention).
fn is_opus_codec(codec: &str) -> bool {
    codec.eq_ignore_ascii_case("opus")
}

/// Decode all captured payloads in a stream to PCM i16 samples.
///
/// Returns `(samples, sample_rate, codec_label)`.
fn decode_stream_pcm(stream: &RtpStream) -> Result<(Vec<i16>, u32, &'static str)> {
    let codec_name = stream.codec.as_deref();

    match codec_name {
        Some("PCMU") => {
            let mut pcm: Vec<i16> = Vec::new();
            for (_ts, payload) in &stream.payload_buffer {
                pcm.extend_from_slice(&decode_frame(G711Codec::Ulaw, payload));
            }
            Ok((pcm, stream.clock_rate, "mu-law"))
        }
        Some("PCMA") => {
            let mut pcm: Vec<i16> = Vec::new();
            for (_ts, payload) in &stream.payload_buffer {
                pcm.extend_from_slice(&decode_frame(G711Codec::Alaw, payload));
            }
            Ok((pcm, stream.clock_rate, "A-law"))
        }
        Some(name) if is_opus_codec(name) => {
            // Opus decodes at 48 kHz mono by default. SDP declares
            // opus/48000/2 but RTP frames are typically mono.
            let mut decoder = OpusStreamDecoder::new(48000, 1)?;
            let mut pcm: Vec<i16> = Vec::new();
            for (_ts, payload) in &stream.payload_buffer {
                match decoder.decode_frame(payload) {
                    Ok(samples) => pcm.extend_from_slice(&samples),
                    Err(e) => {
                        tracing::debug!("Opus decode error (skipping frame): {e}");
                    }
                }
            }
            Ok((pcm, 48000, "Opus"))
        }
        Some(other) => {
            bail!("Unsupported codec for WAV export: {other}. Supported: PCMU, PCMA, Opus.")
        }
        None => bail!("Unknown codec — cannot decode to WAV"),
    }
}

/// Resample PCM i16 samples using linear interpolation.
///
/// Adequate quality for voice audio upsampling (e.g., 8 kHz to 48 kHz).
fn resample_linear(samples: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    if from_rate == to_rate || samples.is_empty() {
        return samples.to_vec();
    }
    let ratio = to_rate as f64 / from_rate as f64;
    let output_len = (samples.len() as f64 * ratio) as usize;
    let mut out = Vec::with_capacity(output_len);
    for i in 0..output_len {
        let src_pos = i as f64 / ratio;
        let src_idx = src_pos as usize;
        let frac = src_pos - src_idx as f64;
        let s0 = samples.get(src_idx).copied().unwrap_or(0) as f64;
        let s1 = samples.get(src_idx + 1).copied().unwrap_or(s0 as i16) as f64;
        let interpolated = s0 + (s1 - s0) * frac;
        out.push(interpolated.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use chrono::DateTime;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_stream(codec: Option<&str>, payloads: Vec<(u32, Vec<u8>)>) -> RtpStream {
        let key = StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: if codec == Some("PCMA") { 8 } else { 0 },
            sequence: 1,
            timestamp: 0,
            ssrc: 0x12345678,
            payload_offset: 12,
        };
        let ts = DateTime::from_timestamp(1_700_000_000, 0).expect("valid");
        let mut stream = RtpStream::new(key, &hdr, ts);
        if let Some(c) = codec {
            stream.codec = Some(c.to_string());
        }
        stream.payload_buffer = VecDeque::from(payloads);
        stream
    }

    #[test]
    fn export_mono_pcmu() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wav");

        // 160 bytes of mu-law silence (0xFF)
        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let result = export_stream_to_wav(&stream, &path).unwrap();

        assert!(result.contains("mu-law"));
        assert!(result.contains("1 frames"));
        assert!(path.exists());
    }

    #[test]
    fn export_rejects_unsupported_codec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wav");

        let stream = make_stream(Some("G729"), vec![(0, vec![0; 10])]);
        let result = export_stream_to_wav(&stream, &path);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported codec")
        );
    }

    #[test]
    fn export_rejects_empty_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wav");

        let stream = make_stream(Some("PCMU"), vec![]);
        let result = export_stream_to_wav(&stream, &path);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No audio payload"));
    }

    #[test]
    fn export_dialog_mono_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dialog.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let result = export_dialog_to_wav(&[&stream], &path).unwrap();

        assert!(result.contains("mu-law"));
    }

    #[test]
    fn export_dialog_stereo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stereo.wav");

        let s1 = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let s2 = make_stream(Some("PCMA"), vec![(0, vec![0xD5; 160])]);
        let result = export_dialog_to_wav(&[&s1, &s2], &path).unwrap();

        assert!(result.contains("stereo"));
        assert!(path.exists());

        // Verify it's actually a stereo file
        let data = std::fs::read(&path).unwrap();
        let channels = u16::from_le_bytes(data[22..24].try_into().unwrap());
        assert_eq!(channels, 2);
    }

    #[test]
    fn export_dialog_filters_unsupported_codecs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.wav");

        let g711 = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let g729 = make_stream(Some("G729"), vec![(0, vec![0; 10])]);
        let result = export_dialog_to_wav(&[&g711, &g729], &path).unwrap();

        // Should fall back to mono since only one decodable stream
        assert!(result.contains("mu-law"));
    }

    #[test]
    fn export_dialog_empty_streams_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.wav");

        let result = export_dialog_to_wav(&[], &path);
        assert!(result.is_err());
    }
}
