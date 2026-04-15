//! Audio export from RTP streams to WAV files.
//!
//! Decodes G.711 (PCMU/PCMA) RTP payload buffers into 16-bit linear PCM
//! and writes standard WAV files. Supports mono (single stream) and stereo
//! (two streams interleaved as left/right channels) export.

use std::path::Path;

use anyhow::{Result, bail};

use super::g711::{G711Codec, decode_frame};
use super::stream::RtpStream;
use super::wav::write_wav;

/// Export a single RTP stream to a mono WAV file.
///
/// Decodes all captured G.711 payloads in the stream's ring buffer to
/// 16-bit linear PCM and writes a mono WAV at the stream's clock rate.
///
/// # Errors
///
/// Returns an error if:
/// - The stream codec is not PCMU or PCMA
/// - No audio payloads have been captured
/// - The WAV file cannot be written
pub fn export_stream_to_wav(stream: &RtpStream, path: &Path) -> Result<String> {
    let codec = match stream.codec.as_deref() {
        Some("PCMU") => G711Codec::Ulaw,
        Some("PCMA") => G711Codec::Alaw,
        Some(other) => bail!(
            "Unsupported codec for WAV export: {other}. Only PCMU and PCMA are supported."
        ),
        None => bail!("Unknown codec — cannot decode to WAV"),
    };

    if stream.payload_buffer.is_empty() {
        bail!("No audio payload captured for this stream. Audio capture requires G.711 codec streams.");
    }

    // Decode all frames to PCM
    let mut pcm_samples: Vec<i16> = Vec::new();
    for (_rtp_ts, payload) in &stream.payload_buffer {
        let decoded = decode_frame(codec, payload);
        pcm_samples.extend_from_slice(&decoded);
    }

    let duration_secs = pcm_samples.len() as f64 / stream.clock_rate as f64;
    write_wav(path, &pcm_samples, stream.clock_rate, 1)?;

    Ok(format!(
        "Exported {:.1}s of {} audio ({} frames, {}/{}Hz) to {}",
        duration_secs,
        codec_name(codec),
        stream.payload_buffer.len(),
        stream.codec.as_deref().unwrap_or("?"),
        stream.clock_rate,
        path.display(),
    ))
}

/// Export multiple streams (dialog) to a WAV file.
///
/// - If exactly one exportable stream: creates a mono WAV.
/// - If two or more exportable streams: creates a stereo WAV with the first
///   stream as the left channel and the second as the right channel.
///
/// Only G.711 streams with captured payload data are considered exportable.
///
/// # Errors
///
/// Returns an error if no exportable streams are found.
pub fn export_dialog_to_wav(streams: &[&RtpStream], path: &Path) -> Result<String> {
    if streams.is_empty() {
        bail!("No RTP streams to export");
    }

    // Filter to G.711 streams with payload data
    let exportable: Vec<&RtpStream> = streams
        .iter()
        .filter(|s| {
            matches!(s.codec.as_deref(), Some("PCMU") | Some("PCMA"))
                && !s.payload_buffer.is_empty()
        })
        .copied()
        .collect();

    if exportable.is_empty() {
        bail!("No G.711 streams with captured audio found");
    }

    if exportable.len() == 1 {
        return export_stream_to_wav(exportable[0], path);
    }

    // Stereo: decode both streams, interleave left/right
    let left = &exportable[0];
    let right = &exportable[1];

    let left_codec = match left.codec.as_deref() {
        Some("PCMU") => G711Codec::Ulaw,
        Some("PCMA") => G711Codec::Alaw,
        _ => unreachable!("filtered to G.711 above"),
    };
    let right_codec = match right.codec.as_deref() {
        Some("PCMU") => G711Codec::Ulaw,
        Some("PCMA") => G711Codec::Alaw,
        _ => unreachable!("filtered to G.711 above"),
    };

    let mut left_pcm: Vec<i16> = Vec::new();
    for (_ts, payload) in &left.payload_buffer {
        left_pcm.extend_from_slice(&decode_frame(left_codec, payload));
    }

    let mut right_pcm: Vec<i16> = Vec::new();
    for (_ts, payload) in &right.payload_buffer {
        right_pcm.extend_from_slice(&decode_frame(right_codec, payload));
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

    // Use the clock rate from the first stream (both should be 8000 for G.711)
    let sample_rate = left.clock_rate;
    let duration_secs = max_len as f64 / sample_rate as f64;
    write_wav(path, &interleaved, sample_rate, 2)?;

    Ok(format!(
        "Exported {:.1}s stereo audio ({} + {} frames) to {}",
        duration_secs,
        left.payload_buffer.len(),
        right.payload_buffer.len(),
        path.display(),
    ))
}

fn codec_name(codec: G711Codec) -> &'static str {
    match codec {
        G711Codec::Ulaw => "mu-law",
        G711Codec::Alaw => "A-law",
    }
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
        assert!(result.unwrap_err().to_string().contains("Unsupported codec"));
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
    fn export_dialog_filters_non_g711() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.wav");

        let g711 = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let g729 = make_stream(Some("G729"), vec![(0, vec![0; 10])]);
        let result = export_dialog_to_wav(&[&g711, &g729], &path).unwrap();

        // Should fall back to mono since only one G.711 stream
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
