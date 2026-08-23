// SPDX-License-Identifier: MIT OR Apache-2.0

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
        bail!("{}", nothing_to_decode(&[stream]));
    }

    let (pcm_samples, sample_rate, codec_label) = decode_stream_pcm(stream)?;
    let duration_secs = pcm_samples.len() as f64 / sample_rate as f64;
    write_wav(path, &pcm_samples, sample_rate, 1)?;

    Ok(format!(
        "Exported {:.1}s of {} audio ({} frames, {}/{}Hz) to {}{}",
        duration_secs,
        codec_label,
        stream.payload_buffer.len(),
        stream.codec.as_deref().unwrap_or("?"),
        sample_rate,
        path.display(),
        wrap_clause(stream.payload_frames_dropped),
    ))
}

/// A clause naming the ring wrap, or nothing when the buffer held everything.
///
/// Appended to every export summary. Without it the duration reads as a fact
/// about the CALL: a ten-minute call whose ring keeps the last 1500 frames
/// exports as "30.0s", byte-identical to a genuinely thirty-second call. The
/// number was never wrong about the FILE; it was silent about what the file
/// left out.
fn wrap_clause(dropped: u64) -> String {
    if dropped == 0 {
        return String::new();
    }
    format!(
        " — PARTIAL: the payload ring wrapped and dropped {dropped} earlier frame(s), \
         so this file holds the END of the stream, not all of it. Raise \
         [limits] max_audio_frames to keep more."
    )
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
        bail!("{}", nothing_to_decode(streams));
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
        "Exported {:.1}s stereo audio ({} + {} frames, {}Hz) to {}{}",
        duration_secs,
        exportable[0].payload_buffer.len(),
        exportable[1].payload_buffer.len(),
        output_rate,
        path.display(),
        // Summed across both channels: either ring wrapping makes the file
        // partial, and an operator reading one number wants the total.
        wrap_clause(exportable[0].payload_frames_dropped + exportable[1].payload_frames_dropped),
    ))
}

/// Explain a failed export in terms of what sipnab actually observed.
///
/// Both failures used to read "No audio streams with captured data found" /
/// "No audio payload captured for this stream", and a reader — an operator, or
/// an agent relaying to one — takes that as a statement about the CALL: it had
/// no audio. Two quite different situations produce it, and neither is that:
///
/// - **Nothing decodable.** Every stream carries a codec sipnab cannot turn
///   into PCM (G.729, video). Naming the codecs found is the whole answer.
/// - **Nothing retained.** The streams carry PCMU/PCMA/Opus and sipnab counted
///   their packets, but the payload was never copied into the ring buffer that
///   export decodes from. Retention is a per-run setting; when it is off, the
///   buffers are empty for every call in the capture regardless of what the
///   calls carried. Saying "no audio" there asserts something about the media
///   from evidence that says nothing about it.
///
/// So the message reports the measurement — packet count and codecs — and
/// names retention as the reason nothing is decodable, without claiming the
/// call was silent.
pub(crate) fn nothing_to_decode(streams: &[&RtpStream]) -> String {
    let decodable: Vec<&&RtpStream> = streams
        .iter()
        .filter(|s| is_exportable_codec(s.codec.as_deref()))
        .collect();

    if decodable.is_empty() {
        let mut found: Vec<&str> = streams
            .iter()
            .map(|s| s.codec.as_deref().unwrap_or("unidentified"))
            .collect();
        found.sort_unstable();
        found.dedup();
        return format!(
            "No stream on this call carries a codec that decodes to WAV (found: {}). \
             Supported: PCMU, PCMA, Opus.",
            found.join(", "),
        );
    }

    let packets: u64 = decodable.iter().map(|s| s.packet_count).sum();
    let mut codecs: Vec<&str> = decodable
        .iter()
        .filter_map(|s| s.codec.as_deref())
        .collect();
    codecs.sort_unstable();
    codecs.dedup();
    // What is REPORTED is the measurement. What is OFFERED is the likeliest
    // cause, named as a candidate rather than asserted.
    //
    // This used to state "Audio payload retention was off for this run" as
    // fact. It is inferred from an empty buffer and nothing else, and at least
    // three other things empty that buffer with retention ON: a `--snaplen`
    // that truncated the payload away, an RTP packet that genuinely carried
    // none, and -- until it was fixed -- a codec the buffering gate spelled
    // differently from the export gate. Telling an operator who DID pass
    // --retain-audio that they had not is a confident answer about the wrong
    // subject, which is the failure this whole message exists to avoid.
    format!(
        "No audio payload retained: sipnab measured {packets} RTP packet(s) of {} on {} \
         decodable {}, but kept none of their payload, so there is nothing to decode. \
         This is a statement about what this run kept, not a finding that the call was \
         silent. Most often audio payload retention was off — start the server with \
         --retain-audio to hold payload for export. With retention already on, the \
         other causes are a --snaplen that truncated the payload away before sipnab \
         saw it, or packets that carried no payload at all.",
        codecs.join("/"),
        decodable.len(),
        if decodable.len() == 1 {
            "stream"
        } else {
            "streams"
        },
    )
}

/// Check whether a codec name represents a decodable audio codec.
///
/// Opus is matched case-insensitively (SDP `a=rtpmap` casing is not
/// normalized), consistent with `is_opus_codec` and `decode_stream_pcm` —
/// otherwise a stream labeled e.g. `OpUs` would decode but be silently
/// filtered out of export. G.711 (`PCMU`/`PCMA`) is matched exactly, matching
/// what `decode_stream_pcm` accepts.
fn is_exportable_codec(codec: Option<&str>) -> bool {
    is_capturable_audio_codec(codec)
}

/// The one answer to "can sipnab turn this codec into audio".
///
/// Both sides of the pipeline ask it: [`crate::rtp::stream_store::StreamStore`]
/// at buffer time, deciding whether to keep a stream's payload at all, and the
/// exporter at decode time. They used to answer it separately, and disagreed:
/// the buffering side matched `"opus" | "OPUS" | "Opus"` exactly while this
/// side compared case-insensitively, as SDP requires. A stream labeled `OpUs`
/// -- legal, and what several stacks emit -- was therefore never buffered,
/// then classified as decodable, and the export blamed retention for an empty
/// buffer that the codec check had emptied.
///
/// One function rather than two that agree today, because the wrong answer
/// here is not a failed export: it is a CORRECT-LOOKING message about the
/// wrong subject.
#[must_use]
pub(crate) fn is_capturable_audio_codec(codec: Option<&str>) -> bool {
    matches!(codec, Some("PCMU") | Some("PCMA")) || codec.is_some_and(is_opus_codec)
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

/// A PCM sample type that a [`resample_linear`] pass can interpolate.
///
/// Factors the per-sample arithmetic out of the shared resampling loop so a
/// single implementation serves both the integer export path (`i16`, rounded
/// and clamped) and the floating-point playback path (`f32`). Each impl keeps
/// the exact numeric behavior its call site had before the two loops were
/// merged.
pub(crate) trait LinearResampleSample: Copy {
    /// The value substituted for samples read past the end of the input
    /// (out-of-range indices during interpolation).
    fn zero() -> Self;

    /// Linearly interpolate between neighbors `a` and `b` at fractional
    /// position `frac` in `[0, 1)`.
    fn lerp(a: Self, b: Self, frac: f64) -> Self;
}

impl LinearResampleSample for i16 {
    fn zero() -> Self {
        0
    }

    fn lerp(a: Self, b: Self, frac: f64) -> Self {
        // Interpolate in f64, then round and clamp back into i16 range.
        let a = a as f64;
        let b = b as f64;
        (a + (b - a) * frac)
            .round()
            .clamp(i16::MIN as f64, i16::MAX as f64) as i16
    }
}

impl LinearResampleSample for f32 {
    fn zero() -> Self {
        0.0
    }

    fn lerp(a: Self, b: Self, frac: f64) -> Self {
        // Interpolate in f32; the fractional position narrows to f32 first.
        let frac = frac as f32;
        a + (b - a) * frac
    }
}

/// Resample PCM samples using linear interpolation.
///
/// Adequate quality for voice audio upsampling (e.g., 8 kHz to 48 kHz).
/// Shared by the i16 WAV-export path and the f32 playback path via
/// [`LinearResampleSample`]; the per-sample arithmetic (rounding/clamping for
/// i16, plain f32 math for f32) lives in that trait so both paths keep their
/// original numeric behavior.
pub(crate) fn resample_linear<T: LinearResampleSample>(
    samples: &[T],
    from_rate: u32,
    to_rate: u32,
) -> Vec<T> {
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
        let s0 = samples.get(src_idx).copied().unwrap_or_else(T::zero);
        let s1 = samples.get(src_idx + 1).copied().unwrap_or(s0);
        out.push(T::lerp(s0, s1, frac));
    }
    out
}

/// Unit tests for mono and stereo WAV export from RTP streams.
#[cfg(test)]
mod tests {
    /// "The call was silent" and "this run did not keep it" must never read as
    /// the same sentence.
    ///
    /// This is the honesty requirement RE7 names, asserted rather than
    /// described. The two facts have different owners -- one is a fault in the
    /// traffic, the other a limit of this run -- and an operator who cannot
    /// tell them apart investigates the wrong thing.
    ///
    /// It has already gone wrong twice. `nothing_to_decode` was written to
    /// replace "No audio payload captured", and `playback.rs` kept saying it
    /// for months because only one of the two functions that decode
    /// `payload_buffer` was migrated. This test spans both.
    #[test]
    fn a_run_that_kept_nothing_never_reads_as_a_silent_call() {
        // Retention empty, codec decodable: a statement about the RUN.
        let kept_nothing = make_stream(Some("PCMU"), vec![]);
        let run_msg = nothing_to_decode(&[&kept_nothing]);

        // Nothing sipnab can decode: a statement about the TRAFFIC's codecs.
        let undecodable = make_stream(Some("G729"), vec![]);
        let codec_msg = nothing_to_decode(&[&undecodable]);

        assert_ne!(
            run_msg, codec_msg,
            "two different reasons produced one identical sentence"
        );

        // The run-limited message must DISCLAIM the reading it would otherwise
        // invite, and scope itself to the run.
        //
        // Asserted as presence of the disclaimer rather than absence of the
        // phrase: the first version of this test banned the substring "the
        // call was silent", which appears in "not a finding that the call was
        // silent" -- correct prose that the check rejected, because a
        // substring cannot tell a claim from its negation.
        assert!(
            run_msg.contains("not a finding that the call was silent"),
            "the retention message must disclaim the reading it invites:\n{run_msg}"
        );
        assert!(
            run_msg.contains("this run kept"),
            "the retention message must say it describes the run:\n{run_msg}"
        );
        // And must not assert a cause it cannot observe. It infers an empty
        // buffer, and --snaplen truncation empties it with retention ON.
        assert!(
            !run_msg.contains("retention was off for this run"),
            "the message asserts a cause it only inferred:\n{run_msg}"
        );

        // The codec message must name the codecs, which is the whole answer.
        assert!(
            codec_msg.contains("G729"),
            "the undecodable-codec message must name what it found:\n{codec_msg}"
        );
    }

    /// A wrapped ring must say so, or the duration reads as the call's length.
    #[test]
    fn a_wrapped_ring_is_named_in_the_summary() {
        assert_eq!(wrap_clause(0), "", "an intact buffer adds no clause");

        let wrapped = wrap_clause(4200);
        assert!(
            wrapped.contains("4200"),
            "the operator's next question is how much was lost:\n{wrapped}"
        );
        assert!(
            wrapped.contains("PARTIAL"),
            "a partial file must announce itself:\n{wrapped}"
        );
        assert!(
            wrapped.contains("END of the stream"),
            "which END was kept decides whether the file answers the question \
             being asked of it:\n{wrapped}"
        );
    }

    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use chrono::DateTime;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Build a stream with the given codec label and captured payload frames.
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

    /// A single PCMU stream exports to a mono mu-law WAV file.
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

    /// Exporting an unsupported codec (G729) returns an error.
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

    /// Exporting a stream with no captured payload returns an error.
    #[test]
    fn export_rejects_empty_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wav");

        let stream = make_stream(Some("PCMU"), vec![]);
        let result = export_stream_to_wav(&stream, &path);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No audio payload"));
    }

    /// A dialog with one exportable stream falls back to mono export.
    #[test]
    fn export_dialog_mono_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dialog.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let result = export_dialog_to_wav(&[&stream], &path).unwrap();

        assert!(result.contains("mu-law"));
    }

    /// Two exportable streams export to an interleaved stereo WAV.
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

    /// Unsupported-codec streams are filtered out before stereo/mono selection.
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

    /// `is_exportable_codec` must accept Opus case-insensitively, consistent
    /// with `is_opus_codec` and the decoder — a mixed-case `OpUs` label decodes
    /// but the exact-case filter used to drop it from export.
    #[test]
    fn is_exportable_codec_accepts_mixed_case_opus() {
        // Canonical spellings still exportable.
        assert!(is_exportable_codec(Some("opus")));
        assert!(is_exportable_codec(Some("OPUS")));
        assert!(is_exportable_codec(Some("Opus")));
        // The bug: mixed case decoded (is_opus_codec is case-insensitive) but
        // was filtered out of export. It must now be exportable, and the two
        // predicates must agree.
        assert!(is_exportable_codec(Some("OpUs")));
        assert_eq!(
            is_exportable_codec(Some("OpUs")),
            is_opus_codec("OpUs"),
            "export filter must agree with the opus detector"
        );
        // G.711 still accepted; unknown / none rejected.
        assert!(is_exportable_codec(Some("PCMU")));
        assert!(is_exportable_codec(Some("PCMA")));
        assert!(!is_exportable_codec(Some("G729")));
        assert!(!is_exportable_codec(None));
    }

    /// A mixed-case `OpUs` stream is not filtered out of dialog export: paired
    /// with a G.711 stream it participates in stereo selection rather than
    /// being silently dropped to a mono fallback.
    #[test]
    fn export_dialog_keeps_mixed_case_opus_stream() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed_case_opus.wav");

        // Opus payloads here are undecodable garbage (skipped frame-by-frame),
        // but the point is codec-name filtering, not audio content: the OpUs
        // stream must survive is_exportable_codec so stereo is selected.
        let g711 = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let opus = make_stream(Some("OpUs"), vec![(0, vec![0xFF; 8])]);
        let result = export_dialog_to_wav(&[&g711, &opus], &path).unwrap();

        assert!(
            result.contains("stereo"),
            "mixed-case Opus must count as exportable (stereo), got: {result}"
        );
        assert!(path.exists());
    }

    /// Exporting an empty stream list returns an error.
    #[test]
    fn export_dialog_empty_streams_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.wav");

        let result = export_dialog_to_wav(&[], &path);
        assert!(result.is_err());
    }

    /// A call whose media sipnab measured but whose payload it never retained
    /// must not be reported as a call with no audio.
    ///
    /// This is the state every MCP `export_audio` call meets: batch mode
    /// switches payload retention off, so the streams carry full packet
    /// counts, a decodable codec and an empty ring buffer. Reporting that as
    /// "no audio streams with captured data found" tells the reader the call
    /// was silent — a claim about the evidence that the evidence does not
    /// support, and one an agent will repeat to an operator. The error has to
    /// say what was observed and that the payload was not kept.
    #[test]
    fn export_dialog_unretained_payload_does_not_deny_the_media() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unretained.wav");

        // Two PCMU streams, thousands of packets measured, nothing retained.
        let mut a = make_stream(Some("PCMU"), vec![]);
        a.packet_count = 1200;
        let mut b = make_stream(Some("PCMU"), vec![]);
        b.packet_count = 1198;

        let err = export_dialog_to_wav(&[&a, &b], &path)
            .expect_err("nothing to decode, so the export must fail");
        let msg = err.to_string();

        assert!(
            msg.contains("2398") && msg.contains("PCMU"),
            "the error must say what sipnab DID observe: {msg}"
        );
        assert!(
            msg.contains("retain") || msg.contains("retention"),
            "the error must say the payload was not retained: {msg}"
        );
        assert!(
            !msg.contains("No audio streams with captured data"),
            "the old wording asserts the call had no audio: {msg}"
        );
        assert!(!path.exists(), "no file may be left behind: {msg}");
    }

    /// A call carrying only codecs sipnab cannot decode names them, rather
    /// than reporting the same "no captured data" as an unretained buffer —
    /// the two are different facts and lead to different next steps.
    #[test]
    fn export_dialog_undecodable_codecs_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g729.wav");

        let mut s = make_stream(Some("G729"), vec![(0, vec![0; 10])]);
        s.packet_count = 500;

        let err = export_dialog_to_wav(&[&s], &path).expect_err("G729 is not decodable");
        let msg = err.to_string();
        assert!(
            msg.contains("G729"),
            "the error must name the codec found: {msg}"
        );
        assert!(
            msg.contains("PCMU"),
            "the error must name what IS supported: {msg}"
        );
    }

    /// The single-stream export says the same thing: packets measured, payload
    /// not retained.
    #[test]
    fn export_stream_unretained_payload_does_not_deny_the_media() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.wav");

        let mut s = make_stream(Some("PCMA"), vec![]);
        s.packet_count = 4242;

        let err = export_stream_to_wav(&s, &path).expect_err("nothing to decode");
        let msg = err.to_string();
        assert!(
            msg.contains("4242") && msg.contains("PCMA"),
            "the error must say what was observed: {msg}"
        );
        assert!(
            msg.contains("retain") || msg.contains("retention"),
            "the error must say the payload was not retained: {msg}"
        );
    }
}
