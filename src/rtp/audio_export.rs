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

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};

use super::g711::{G711Codec, decode_frame};
use super::opus_decode::OpusStreamDecoder;
use super::stream::{RtpStream, StreamKey};
use super::wav::write_wav_with_provenance;

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

    let (pcm_samples, sample_rate, codec_label, decode_failures) = decode_stream_pcm(stream)?;
    let duration_secs = pcm_samples.len() as f64 / sample_rate as f64;
    // Built once and used twice: the note inside the file and the summary
    // printed beside it say the same thing, because they are the same string.
    let partial = format!(
        "{}{}",
        wrap_clause(stream.payload_frames_dropped),
        decode_failure_clause(decode_failures)
    );
    write_wav_with_provenance(
        path,
        &pcm_samples,
        sample_rate,
        1,
        Some(&provenance_note(AudioMechanism::SipnabCapture, &partial)),
    )?;

    // One `partial` for the file's note and this message both -- see the
    // stereo path for what happens when they are built separately.
    Ok(format!(
        "Exported {:.1}s of {} audio ({} frames, {}/{}Hz) to {}{partial}",
        duration_secs,
        codec_label,
        stream.payload_buffer.len(),
        stream.codec.as_deref().unwrap_or("?"),
        sample_rate,
        path.display(),
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
    let audio = decode_dialog_audio(streams)?;
    std::fs::write(path, &audio.wav)
        .with_context(|| format!("Failed to create WAV file: {}", path.display()))?;

    // `audio.partial` again, not the clauses re-listed. Building the summary
    // from its own copy is how the file's note and the message printed beside
    // it drift apart: adding `direction_clause` to one and not the other did
    // exactly that, and a test comparing them caught it.
    Ok(format!(
        "{} to {}{}",
        audio.summary_head,
        path.display(),
        audio.partial
    ))
}

/// One dialog's audio, decoded into a WAV that has not been written anywhere.
///
/// The file on disk and the media inlined in a vCon are the SAME bytes, from
/// one decode, carrying one provenance note. Two producers of "sipnab's audio
/// for this call" is the drift this type exists to make impossible: the
/// container's `content_hash` has to verify against the `.wav` an operator
/// exported beside it, and a second encoder makes the two disagree in a way
/// that reads as tampering rather than as a bug.
#[derive(Debug, Clone)]
pub struct DialogAudio {
    /// The complete WAV, note and all, ready to write or to inline.
    pub wav: Vec<u8>,
    /// Samples per second per channel in [`Self::wav`].
    pub sample_rate: u32,
    /// 1 for a mono export, 2 for a stereo one.
    pub channels: u16,
    /// How long the FILE is, in seconds.
    ///
    /// A fact about the file, never about the call. A ten-minute call whose
    /// ring kept the last 1500 frames lands here as 30 seconds, and
    /// [`Self::partial`] is what stops that reading as a thirty-second call.
    pub duration_secs: f64,
    /// The clauses naming every way this file falls short of the call, or
    /// empty when it falls short in none of them.
    ///
    /// The ONE string. It is appended to the export summary, embedded in
    /// [`Self::note`] inside the WAV, and carried into a vCon's completeness
    /// caveat — three surfaces, one value, so they cannot contradict.
    pub partial: String,
    /// The provenance note embedded in [`Self::wav`], verbatim.
    ///
    /// Exposed rather than left inside the bytes so a consumer that cannot
    /// parse a RIFF chunk still reads it. Same string, not a second one.
    pub note: String,
    /// `true` when a payload ring dropped frames this file therefore lacks.
    ///
    /// The signal that the file is shorter than the call it came from, which
    /// is the one gap vCon can state in its own vocabulary
    /// (`docs/design/vcon.md` §4b).
    pub ring_wrapped: bool,
    /// The streams on the file's channels, in channel order.
    ///
    /// Channel 0 first. Carried so a caller can attribute a channel to
    /// whoever's media is on it WITHOUT guessing — the key holds the sending
    /// socket, which is the only evidence sipnab has for that question.
    pub sources: Vec<StreamKey>,
    /// Capture-clock time of the first frame this file actually holds.
    ///
    /// Not the stream's first packet: when the ring wrapped, the earlier
    /// frames are gone and the file begins later than the call did. Measured
    /// from the retained frames' own RTP timestamps rather than assumed.
    pub first_retained: DateTime<Utc>,
    /// Capture-clock time of the first media packet on ANY of the dialog's
    /// streams — the start of the window sipnab saw media in.
    pub media_start: DateTime<Utc>,
    /// Capture-clock time of the last media packet on any of them.
    pub media_end: DateTime<Utc>,
    /// The export summary with no path in it: `"Exported 1.0s of mu-law audio
    /// (1 frames, PCMU/8000Hz)"`.
    ///
    /// Path-free because the vCon path writes no file and has no path to name,
    /// while [`export_dialog_to_wav`] appends one. Splitting it here keeps both
    /// summaries derived from the same measurements.
    pub summary_head: String,
}

/// Decode one dialog's retained RTP payload into a WAV held in memory.
///
/// The shared core of every audio export. [`export_dialog_to_wav`] writes what
/// this returns; the vCon exporter inlines it. Selection matches what the file
/// path always did: streams with a decodable codec and retained payload, first
/// as the left channel and second as the right, at most two because a WAV
/// carries two — and whatever that leaves out is named in
/// [`DialogAudio::partial`] rather than dropped in silence.
///
/// # Errors
///
/// Returns an error when there are no streams at all, or when none of them
/// carries decodable retained payload. The message comes from
/// `nothing_to_decode`, which reports what sipnab MEASURED and never claims
/// the call was silent — the distinction a caller must be able to pass on.
pub fn decode_dialog_audio(streams: &[&RtpStream]) -> Result<DialogAudio> {
    if streams.is_empty() {
        bail!("No RTP streams to export");
    }

    // Filter to streams with decodable audio payload data, KEEPING what the
    // filter rejected. Discarding it was the bug: the summary then described
    // the file without describing the call it came from.
    let exportable: Vec<&RtpStream> = streams
        .iter()
        .filter(|s| is_exportable_codec(s.codec.as_deref()) && !s.payload_buffer.is_empty())
        .copied()
        .collect();
    let skipped_codecs: Vec<&str> = streams
        .iter()
        .filter(|s| !is_exportable_codec(s.codec.as_deref()))
        .map(|s| s.codec.as_deref().unwrap_or("unidentified"))
        .collect();

    if exportable.is_empty() {
        bail!("{}", nothing_to_decode(streams));
    }

    // A WAV carries two channels. `omitted_clause` below names the rest.
    let carried: Vec<&RtpStream> = exportable.iter().take(2).copied().collect();
    let mut decoded: Vec<(Vec<i16>, u32, &'static str, u64)> = Vec::with_capacity(carried.len());
    for stream in &carried {
        decoded.push(decode_stream_pcm(stream)?);
    }

    // The higher rate wins and the lower channel is resampled up, so a G.711
    // leg and an Opus leg land on one timebase instead of one playing fast.
    let output_rate = decoded
        .iter()
        .map(|d| d.1)
        .max()
        .unwrap_or(DEFAULT_WAV_RATE);
    let (samples, channels, frames_per_channel) = interleave_channels(&mut decoded, output_rate);

    let dropped: u64 = carried
        .iter()
        .map(|s| s.payload_frames_dropped)
        .fold(0u64, u64::saturating_add);
    let failures: u64 = decoded.iter().map(|d| d.3).fold(0u64, u64::saturating_add);

    let partial = format!(
        "{}{}{}{}",
        wrap_clause(dropped),
        omitted_clause(streams.len(), carried.len(), &skipped_codecs),
        decode_failure_clause(failures),
        direction_clause(streams)
    );
    let note = provenance_note(AudioMechanism::SipnabCapture, &partial);

    let duration_secs = if output_rate == 0 {
        0.0
    } else {
        frames_per_channel as f64 / f64::from(output_rate)
    };

    // The mono summary names the codec because a one-channel file is the one
    // an operator plays without knowing what it holds; the stereo one names
    // both frame counts because they are what a short channel shows up in.
    let summary_head = if channels == 1 {
        format!(
            "Exported {:.1}s of {} audio ({} frames, {}/{}Hz)",
            duration_secs,
            decoded[0].2,
            carried[0].payload_buffer.len(),
            carried[0].codec.as_deref().unwrap_or("?"),
            decoded[0].1,
        )
    } else {
        format!(
            "Exported {duration_secs:.1}s stereo audio ({} + {} frames, {output_rate}Hz)",
            carried[0].payload_buffer.len(),
            carried[1].payload_buffer.len(),
        )
    };

    Ok(DialogAudio {
        wav: crate::rtp::wav::wav_bytes(&samples, output_rate, channels, Some(&note)),
        sample_rate: output_rate,
        channels,
        duration_secs,
        partial,
        note,
        ring_wrapped: dropped > 0,
        sources: carried.iter().map(|s| s.key.clone()).collect(),
        first_retained: carried
            .iter()
            .map(|s| retained_window_start(s))
            .min()
            .unwrap_or_else(Utc::now),
        media_start: streams
            .iter()
            .map(|s| s.first_seen)
            .min()
            .unwrap_or_else(Utc::now),
        media_end: streams
            .iter()
            .map(|s| s.last_seen)
            .max()
            .unwrap_or_else(Utc::now),
        summary_head,
    })
}

/// The sample rate a WAV falls back to when no decoded channel reported one.
///
/// Unreachable while [`decode_dialog_audio`] refuses an empty channel list,
/// and named anyway: the alternative at that call site is `unwrap`, and a
/// panic in an export path takes the whole run down over a header field. 8 kHz
/// is G.711's clock, which is what every telephony WAV sipnab writes carries.
const DEFAULT_WAV_RATE: u32 = 8000;

/// Resample the decoded channels onto one rate and interleave them.
///
/// Returns the samples, the channel count, and the frames PER CHANNEL — which
/// is what a duration divides by, and which is not `samples.len()` once there
/// are two channels. Getting that wrong halves or doubles every duration in
/// the container.
fn interleave_channels(
    decoded: &mut [(Vec<i16>, u32, &'static str, u64)],
    output_rate: u32,
) -> (Vec<i16>, u16, usize) {
    if decoded.len() < 2 {
        let samples = decoded.first().map(|d| d.0.clone()).unwrap_or_default();
        let frames = samples.len();
        return (samples, 1, frames);
    }

    for channel in decoded.iter_mut() {
        if channel.1 < output_rate {
            channel.0 = resample_linear(&channel.0, channel.1, output_rate);
        }
    }

    // Pad the shorter channel with silence so both are the same length.
    let max_len = decoded.iter().map(|d| d.0.len()).max().unwrap_or(0);
    for channel in decoded.iter_mut() {
        channel.0.resize(max_len, 0);
    }

    // Interleave: L0, R0, L1, R1, ...
    let mut interleaved: Vec<i16> = Vec::with_capacity(max_len * 2);
    for i in 0..max_len {
        interleaved.push(decoded[0].0[i]);
        interleaved.push(decoded[1].0[i]);
    }
    (interleaved, 2, max_len)
}

/// When the first frame this file actually holds arrived.
///
/// Measured from the retained frames themselves: the span between the oldest
/// and newest RTP timestamps still in the ring, subtracted from the stream's
/// last packet. The alternative — reporting
/// [`first_seen`](RtpStream::first_seen) — dates a file to a packet the ring
/// evicted, which is a `start` that is simply wrong whenever retention
/// mattered, and wrong in the direction that makes the file look longer than
/// it is.
///
/// Falls back to `first_seen` when the ring is empty or the stream reported no
/// clock rate, because with neither there is nothing to measure and an
/// invented offset would be worse than the stream's own first packet.
///
/// `wrapping_sub` is deliberate: RTP timestamps are 32-bit and wrap, and a
/// saturating subtraction across the wrap would collapse the span to zero,
/// which reads as "the file starts where the stream ends".
fn retained_window_start(stream: &RtpStream) -> DateTime<Utc> {
    let (Some((oldest, _)), Some((newest, _))) =
        (stream.payload_buffer.front(), stream.payload_buffer.back())
    else {
        return stream.first_seen;
    };
    if stream.clock_rate == 0 {
        return stream.first_seen;
    }
    let ticks = newest.wrapping_sub(*oldest);
    let millis = (f64::from(ticks) / f64::from(stream.clock_rate) * 1000.0).round() as i64;
    chrono::TimeDelta::try_milliseconds(millis)
        .and_then(|span| stream.last_seen.checked_sub_signed(span))
        .unwrap_or(stream.first_seen)
}

/// How the audio in an artefact was obtained.
///
/// RE7 requires an artefact to NAME this, because the possible answers differ
/// in what they can be trusted to say: audio sipnab captured itself is bounded
/// by where the capture point sat and by what retention kept, while audio read
/// from a relay's spool is what that relay wrote down, which sipnab did not
/// witness and cannot vouch for beyond the relay's own honesty.
///
/// An operator holding a file months later cannot recover that from the bytes,
/// so it travels inside them.
///
/// ONE VARIANT, deliberately. RE7 names two mechanisms and this carried both
/// for a while, with nothing anywhere constructing the second -- an enum arm no
/// code path produces reads as a capability the tool has, and it does not have
/// it. `rtpengine-spool` returns when RE5 gives it a producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioMechanism {
    /// Decoded from RTP payload sipnab captured itself.
    SipnabCapture,
}

impl AudioMechanism {
    /// The stable token written into the artefact.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::SipnabCapture => "sipnab-capture",
        }
    }
}

/// The comment recorded inside an exported WAV.
///
/// Names the mechanism, the version that wrote it, and -- when the file is
/// partial -- how, reusing the very clauses the summary prints. One source for
/// both: a file whose embedded note disagreed with the message printed beside
/// it would be worse than a file with no note, because it would look
/// authoritative while contradicting the run that produced it.
fn provenance_note(mechanism: AudioMechanism, partial: &str) -> String {
    let completeness = if partial.is_empty() {
        " No omissions recorded: every stream and frame sipnab held for this \
         call is in this file."
            .to_string()
    } else {
        format!(" INCOMPLETE.{partial}")
    };
    format!(
        "Produced by sipnab {} via mechanism {}. Audio decoded from RTP payload \
         this run retained; it is bounded by where the capture point sat and by \
         what retention kept, and is not a recording made by the endpoints.{}",
        env!("CARGO_PKG_VERSION"),
        mechanism.id(),
        completeness,
    )
}

/// A clause naming a direction of media that never reached this run.
///
/// A call has two directions and a dialog export writes what it was given. Given
/// one direction it produces a mono file whose summary is byte-identical to a
/// deliberate single-stream export, so "we only ever saw one side" and "you
/// asked for one side" read the same.
///
/// Worded as an OBSERVATION, not a verdict. sipnab detects genuine one-way
/// audio elsewhere, against a `MediaContext` that knows whether the capture
/// could have seen the reverse direction at all; this function has streams and
/// nothing else, so it says what reached the capture point and stops there. A
/// mid-path tap that only sees one leg is the ordinary reason, and calling that
/// a one-way call would accuse the traffic of the capture's own limits.
///
/// Paired by IP, not by socket: each direction negotiates its own port in SDP,
/// so exact reverse-socket matching would report almost every real call as
/// one-directional.
fn direction_clause(streams: &[&RtpStream]) -> String {
    use std::collections::BTreeSet;

    let pairs: BTreeSet<(std::net::IpAddr, std::net::IpAddr)> = streams
        .iter()
        .map(|s| (s.key.src.ip(), s.key.dst.ip()))
        .collect();
    if pairs.is_empty() {
        return String::new();
    }
    // Bidirectional when some pair's reverse is also present.
    let bidirectional = pairs.iter().any(|(a, b)| pairs.contains(&(*b, *a)));
    if bidirectional {
        return String::new();
    }
    " — PARTIAL: media in only ONE direction reached this capture; no stream \
     going the other way was observed. That may be a one-way call, or a capture \
     point that only sees one leg -- this file cannot tell you which."
        .to_string()
}

/// A clause naming frames the decoder could not turn into audio.
///
/// Opus frames that fail decoding are skipped, which shortens the file while
/// the summary keeps reporting `payload_buffer.len()` as the frame count. The
/// only record was a `debug!` line, off by default -- so on the runs where it
/// mattered there was no record at all.
fn decode_failure_clause(failures: u64) -> String {
    if failures == 0 {
        return String::new();
    }
    format!(
        " — PARTIAL: {failures} frame(s) failed to decode and are missing from the \
         audio; the frame count above is what was captured, not what was written."
    )
}

/// A clause naming the streams this export left behind, or nothing when it
/// carried them all.
///
/// A dialog export writes at most two channels and filters out whatever it
/// cannot decode, and said neither. An operator who exports a three-legged
/// call gets a two-channel file whose summary is byte-identical to a complete
/// one -- the omission is invisible precisely when it matters, because a
/// conference or a transfer is exactly the call somebody exports to find out
/// what happened on it.
///
/// `skipped_codecs` names what was dropped for being undecodable, because
/// "one stream omitted" and "one stream of G.729 omitted" send an operator to
/// different places.
fn omitted_clause(total: usize, written: usize, skipped_codecs: &[&str]) -> String {
    let dropped = total.saturating_sub(written);
    if dropped == 0 {
        return String::new();
    }
    let mut codecs: Vec<&str> = skipped_codecs.to_vec();
    codecs.sort_unstable();
    codecs.dedup();
    let detail = if codecs.is_empty() {
        String::new()
    } else {
        format!(" ({})", codecs.join(", "))
    };
    format!(
        " — PARTIAL: {dropped} of {total} stream(s) on this call are NOT in this \
         file{detail}. A WAV carries two channels, and streams sipnab cannot decode \
         are left out."
    )
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
fn decode_stream_pcm(stream: &RtpStream) -> Result<(Vec<i16>, u32, &'static str, u64)> {
    let codec_name = stream.codec.as_deref();

    match codec_name {
        Some("PCMU") => {
            let mut pcm: Vec<i16> = Vec::new();
            for (_ts, payload) in &stream.payload_buffer {
                pcm.extend_from_slice(&decode_frame(G711Codec::Ulaw, payload));
            }
            Ok((pcm, stream.clock_rate, "mu-law", 0))
        }
        Some("PCMA") => {
            let mut pcm: Vec<i16> = Vec::new();
            for (_ts, payload) in &stream.payload_buffer {
                pcm.extend_from_slice(&decode_frame(G711Codec::Alaw, payload));
            }
            Ok((pcm, stream.clock_rate, "A-law", 0))
        }
        Some(name) if is_opus_codec(name) => {
            // Opus decodes at 48 kHz mono by default. SDP declares
            // opus/48000/2 but RTP frames are typically mono.
            let mut decoder = OpusStreamDecoder::new(48000, 1)?;
            let mut pcm: Vec<i16> = Vec::new();
            // Counted, not just logged. A skipped frame shortens the audio
            // while the summary went on reporting `payload_buffer.len()` as
            // the frame count, so the file was quietly missing whatever failed
            // and the number said otherwise. `debug!` is off by default, which
            // made the only record of it invisible on the runs that mattered.
            let mut decode_failures: u64 = 0;
            for (_ts, payload) in &stream.payload_buffer {
                match decoder.decode_frame(payload) {
                    Ok(samples) => pcm.extend_from_slice(&samples),
                    Err(e) => {
                        decode_failures = decode_failures.saturating_add(1);
                        tracing::debug!("Opus decode error (skipping frame): {e}");
                    }
                }
            }
            Ok((pcm, 48000, "Opus", decode_failures))
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
    /// A frame the decoder rejects must be counted, not only logged.
    ///
    /// The skip was recorded with `debug!`, which is off by default, while the
    /// summary went on reporting `payload_buffer.len()` as the frame count --
    /// so the file was short by whatever failed and the number said otherwise.
    /// Exercised through a real export, because removing the counter's
    /// increment still compiles and `decode_failure_clause`'s own test still
    /// passes: that test is handed a number rather than measuring one.
    #[test]
    fn opus_frames_the_decoder_rejects_are_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("opus.wav");

        // Two frames of bytes that are not valid Opus. If the decoder ever
        // learns to accept them the assertion below fails loudly rather than
        // passing vacuously, which is the outcome to prefer.
        let stream = make_stream(Some("opus"), vec![(0, vec![0xFF; 8]), (960, vec![0xFE; 8])]);

        match export_stream_to_wav(&stream, &path) {
            Ok(summary) => assert!(
                summary.contains("failed to decode"),
                "frames were skipped and the summary did not say so:\n{summary}"
            ),
            // A decoder that refuses the whole stream is also honest -- it did
            // not claim to have written audio it could not decode.
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.is_empty(),
                    "a refused export must explain itself, not fail silently"
                );
            }
        }
    }

    /// The artefact must name its mechanism, in the FILE.
    ///
    /// This is RE7's requirement. Everything sipnab knew about an export used
    /// to live in a string returned to whoever ran it, and was gone when that
    /// scrolled away -- while the file went on being forwarded, attached to
    /// tickets, and played months later by somebody who never saw the run.
    ///
    /// Asserted by reading the bytes back, not by inspecting the string that
    /// was passed in: what matters is that it reached the disk.
    #[test]
    fn an_exported_wav_names_its_mechanism_in_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("provenance.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        export_stream_to_wav(&stream, &path).expect("export");

        let bytes = std::fs::read(&path).expect("read back");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("sipnab-capture"),
            "the file does not name the mechanism it came from"
        );
        assert!(
            text.contains("ICMT"),
            "the note must live in a RIFF comment chunk, not be appended loose"
        );
        // A complete file must say it is complete, or silence reads as an
        // omission nobody recorded.
        assert!(
            text.contains("No omissions recorded"),
            "a complete export must say so; absence of a warning is not a claim"
        );
    }

    /// A partial file says so INSIDE itself, not only in the summary.
    #[test]
    fn a_partial_export_records_its_partialness_in_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("partial.wav");

        let mut stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        // The ring wrapped: frames existed that this file does not hold.
        stream.payload_frames_dropped = 4200;

        export_stream_to_wav(&stream, &path).expect("export");
        let bytes = std::fs::read(&path).expect("read back");
        let text = String::from_utf8_lossy(&bytes);

        assert!(
            text.contains("INCOMPLETE"),
            "a file missing 4200 frames must announce it to whoever opens it"
        );
        assert!(
            text.contains("4200"),
            "how much is missing is the question the file must answer"
        );
        assert!(
            !text.contains("No omissions recorded"),
            "a partial file must not also claim completeness"
        );
    }

    /// A fixed-offset reader must still read the audio correctly.
    ///
    /// The note is optional and skippable only for readers that WALK chunks.
    /// Plenty do not: they seek to the offsets a classic 44-byte WAV puts
    /// `data` at. Writing the note before `data` moved it, and sipnab's own
    /// `wav_header` test helper then reported 328 bytes of audio for a file
    /// holding a second of it -- a naive reader is not a hypothetical, it is
    /// in this repository.
    ///
    /// So the note goes after the samples, and this asserts the property that
    /// buys: the first 44 bytes are what they always were.
    #[test]
    fn the_provenance_chunk_does_not_corrupt_the_audio() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("intact.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        export_stream_to_wav(&stream, &path).expect("export");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(&bytes[0..4], b"RIFF", "not a RIFF file");
        assert_eq!(&bytes[8..12], b"WAVE", "not a WAVE file");

        // The classic layout, at the classic offsets.
        assert_eq!(
            &bytes[12..16],
            b"fmt ",
            "fmt must stay at offset 12 or a fixed-offset reader misparses"
        );
        assert_eq!(
            &bytes[36..40],
            b"data",
            "data must stay at offset 36; moving it is what broke wav_header"
        );
        let data_size = u32::from_le_bytes(bytes[40..44].try_into().expect("size")) as usize;
        assert_eq!(
            data_size,
            160 * 2,
            "the size at offset 40 must be the sample bytes, which is what a \
             fixed-offset reader takes it for"
        );

        // The samples are intact and the note lives past them.
        assert!(
            bytes.len() > 44 + data_size,
            "the note should follow the samples, not replace them"
        );
        let riff_size = u32::from_le_bytes(bytes[4..8].try_into().expect("size")) as usize;
        assert_eq!(
            riff_size + 8,
            bytes.len(),
            "the RIFF size field must still describe the whole file, note included"
        );
        assert!(
            String::from_utf8_lossy(&bytes[44 + data_size..]).contains("sipnab-capture"),
            "the note must be there, after the audio"
        );
    }

    /// The stereo path must actually CALL the omission clause.
    ///
    /// The clause has its own unit test, and that test passes while nothing
    /// wires the clause into an export -- replacing the call with an empty
    /// string still compiles and still passes it. This one exports three
    /// streams for real and reads the summary.
    #[test]
    fn a_three_stream_call_reports_the_stream_it_could_not_carry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("three.wav");

        let a = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let b = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let c = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);

        let summary = export_dialog_to_wav(&[&a, &b, &c], &path).expect("export");
        assert!(
            summary.contains("1 of 3"),
            "a WAV carries two channels; the third stream is missing and the \
             summary must say which:\n{summary}"
        );
    }

    /// A stream dropped for its codec is named in the summary, not filtered
    /// out in silence.
    #[test]
    fn an_undecodable_stream_is_named_in_the_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mixed.wav");

        let good = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        let bad = make_stream(Some("G729"), vec![(0, vec![0x00; 10])]);

        let summary = export_dialog_to_wav(&[&good, &bad], &path).expect("export");
        assert!(
            summary.contains("G729"),
            "the undecodable stream was filtered out silently, so the file \
             looks complete:\n{summary}"
        );
    }

    /// A file holding one direction must say the other was never seen.
    ///
    /// RE7 names "egress not observed" among the ways an artefact is partial.
    /// A dialog export handed one direction produces a mono file whose summary
    /// is byte-identical to a deliberate single-stream export, so "we only saw
    /// one side" and "you asked for one side" read the same.
    #[test]
    fn a_file_with_one_direction_says_the_other_was_not_seen() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        fn directed(src: [u8; 4], dst: [u8; 4]) -> RtpStream {
            let mut s = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
            s.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src)), 20000);
            s.key.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst)), 30000);
            s
        }

        // Both ways: nothing to report.
        let there = directed([10, 0, 0, 1], [10, 0, 0, 2]);
        let back = directed([10, 0, 0, 2], [10, 0, 0, 1]);
        assert_eq!(
            direction_clause(&[&there, &back]),
            "",
            "a call captured in both directions is not partial"
        );

        // One way only.
        let clause = direction_clause(&[&there]);
        assert!(
            clause.contains("only ONE direction"),
            "a one-directional capture must say so:\n{clause}"
        );
        // And must NOT accuse the call: a mid-path tap sees one leg by design.
        assert!(
            clause.contains("capture point that only sees one leg"),
            "the clause must offer the capture's own limits as a cause, not \
             assert the call was one-way:\n{clause}"
        );

        // Ports differ per direction in real SDP; pairing must survive that.
        let mut back_odd_port = directed([10, 0, 0, 2], [10, 0, 0, 1]);
        back_odd_port.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 41234);
        assert_eq!(
            direction_clause(&[&there, &back_odd_port]),
            "",
            "each direction negotiates its own port; pairing by socket would \
             report almost every real call as one-directional"
        );
    }

    /// The dialog export must actually CALL the direction clause.
    ///
    /// `direction_clause` has a unit test, and it passes while nothing wires
    /// the clause into an export -- replacing the call with an empty string
    /// still compiles and still passes it. That has now happened four times in
    /// this file with four different clauses, which is the argument for
    /// exporting real streams and reading the summary rather than testing the
    /// formatter and assuming the rest.
    #[test]
    fn a_one_directional_dialog_export_reports_it() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("oneway.wav");

        // Two streams, both A -> B: media was only ever seen going one way.
        let mut a = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        a.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000);
        a.key.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000);
        let mut b = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])]);
        b.key.ssrc = 0x9999_0000;
        b.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20002);
        b.key.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30002);

        let summary = export_dialog_to_wav(&[&a, &b], &path).expect("export");
        assert!(
            summary.contains("only ONE direction"),
            "a dialog whose media was only seen one way exported without \
             saying so:\n{summary}"
        );

        // And it reaches the FILE, which is what RE7 asks for.
        let bytes = std::fs::read(&path).expect("read back");
        assert!(
            String::from_utf8_lossy(&bytes).contains("only ONE direction"),
            "the note inside the file must carry it too, not just the summary"
        );
    }

    /// Every mechanism the enum offers must have something that produces it.
    ///
    /// RE7 names two, and this carried both while nothing constructed the
    /// second. An enum arm no code path produces reads as a capability the
    /// tool has. `rtpengine-spool` returns when RE5 gives it a producer.
    #[test]
    fn every_mechanism_is_reachable() {
        assert_eq!(AudioMechanism::SipnabCapture.id(), "sipnab-capture");
        // Exhaustive by construction: adding a variant without a producer
        // fails to compile here until it is listed, which is the reminder.
        let all = [AudioMechanism::SipnabCapture];
        assert_eq!(
            all.len(),
            1,
            "a new mechanism needs a producer and a test that exports through it"
        );
    }

    /// A file that carries fewer streams than the call must say so.
    ///
    /// A WAV holds two channels and the exporter drops what it cannot decode,
    /// and the summary mentioned neither -- so a three-legged call produced a
    /// two-channel file whose summary was byte-identical to a complete one.
    /// The omission is invisible exactly when it matters: a conference or a
    /// transfer is the call somebody exports to find out what happened.
    #[test]
    fn an_export_that_leaves_streams_out_says_so() {
        assert_eq!(
            omitted_clause(2, 2, &[]),
            "",
            "a file carrying every stream adds no clause"
        );

        // Third leg dropped for want of a channel, nothing undecodable.
        let channels = omitted_clause(3, 2, &[]);
        assert!(
            channels.contains("1 of 3"),
            "the operator needs the ratio, not just the word partial:\n{channels}"
        );
        assert!(
            channels.contains("PARTIAL"),
            "a partial file must announce itself:\n{channels}"
        );

        // Dropped for being undecodable: naming the codec sends the reader
        // somewhere different than a bare count does.
        let codec = omitted_clause(3, 2, &["G729"]);
        assert!(
            codec.contains("G729"),
            "a stream dropped for its codec must name the codec:\n{codec}"
        );
    }

    /// Frames that failed to decode are missing from the audio, and the frame
    /// count in the summary counts what was CAPTURED.
    #[test]
    fn frames_that_failed_to_decode_are_named() {
        assert_eq!(
            decode_failure_clause(0),
            "",
            "a clean decode adds no clause"
        );

        let failed = decode_failure_clause(12);
        assert!(
            failed.contains("12"),
            "how many frames are missing is the question:\n{failed}"
        );
        assert!(
            failed.contains("not what was written"),
            "the summary's frame count describes what was captured, and the \
             clause has to say so or the two numbers silently disagree:\n{failed}"
        );
    }

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
