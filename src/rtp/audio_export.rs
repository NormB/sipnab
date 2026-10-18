// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Audio export from RTP streams to WAV files.
//!
//! Decodes G.711 (PCMU/PCMA) and Opus RTP payload buffers into 16-bit
//! linear PCM and writes standard WAV files. Supports mono (single stream)
//! and stereo (two streams interleaved as left/right channels) export.
//!
//! G.729 decodes too, in a build with the `g729` feature and on a host where
//! `sipnab g729 install` has installed its tables ([`crate::rtp::g729_tables`]).
//!
//! G.711 streams export at 8 kHz; Opus streams export at 48 kHz. When
//! mixing G.711 and Opus in stereo mode, the G.711 channel is resampled
//! to 48 kHz to match.

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};

use super::g711::{G711Codec, decode_frame};
use super::opus_decode::OpusStreamDecoder;
use super::stream::{RetainedFrame, RtpStream, StreamKey};
use super::wav::write_wav_with_provenance;
#[cfg(feature = "g729")]
use crate::rtp::g729_family::G7291Rates;
use crate::rtp::g729_family::{G729Variant, g729_variant};

/// Export a single RTP stream to a mono WAV file.
///
/// Decodes all captured payloads in the stream's ring buffer to 16-bit
/// linear PCM and writes a mono WAV. G.711 streams export at 8 kHz;
/// Opus streams export at 48 kHz.
///
/// # Errors
///
/// Returns an error if:
/// - The stream codec is not PCMU, PCMA, G.722 or Opus
/// - No audio payloads have been captured
/// - The WAV file cannot be written
pub fn export_stream_to_wav(stream: &RtpStream, path: &Path) -> Result<String> {
    if stream.payload_buffer.is_empty() {
        bail!("{}", nothing_to_decode(&[stream]));
    }

    let DecodedStream {
        pcm: pcm_samples,
        rate: sample_rate,
        label: codec_label,
        failures: decode_failures,
        timeline,
        codec_fill,
        caveat,
    } = decode_stream_pcm(stream, true)?;
    let duration_secs = pcm_samples.len() as f64 / sample_rate as f64;
    // Built once and used twice: the note inside the file and the summary
    // printed beside it say the same thing, because they are the same string.
    let partial = format!(
        "{}{}{}{}",
        caveat_clause(caveat.as_slice()),
        retention_clauses(&RetentionLoss::of(&[stream])),
        decode_failure_clause(decode_failures),
        timeline_clause(&TimelineTotals::of(
            &timeline,
            stream.clock_rate,
            codec_fill
        ))
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

/// The clauses saying what decoded audio is when it is not simply its codec's
/// audio (G.729.1 decoded to its core layer), each once, or nothing.
fn caveat_clause(caveats: &[String]) -> String {
    let mut once: Vec<&String> = Vec::new();
    for caveat in caveats {
        if !once.contains(&caveat) {
            once.push(caveat);
        }
    }
    once.iter().map(|c| format!(" — {c}.")).collect()
}

/// A clause naming the ring wrap, or nothing when the buffer held everything.
///
/// Only an explicit `[limits] max_audio_frames` makes a ring; unset, the
/// whole stream is kept. Appended to every export summary. Without it the
/// duration reads as a fact about the CALL: a ten-minute call whose ring
/// keeps the last 1500 frames exports as "30.0s", byte-identical to a
/// genuinely thirty-second call. The number was never wrong about the FILE;
/// it was silent about what the file left out.
fn wrap_clause(dropped: u64) -> String {
    if dropped == 0 {
        return String::new();
    }
    format!(
        " — PARTIAL: the payload ring wrapped and dropped {dropped} earlier frame(s), \
         so this file holds the END of the stream, not all of it. Raise or \
         remove [limits] max_audio_frames to keep more."
    )
}

/// Frames missing from the START of a file's streams, by why they are gone.
///
/// Each of the three removes the earliest frames, so a file with any of them
/// holds the end of its streams and not the call's beginning.
#[derive(Debug, Default, Clone, Copy)]
struct RetentionLoss {
    /// Dropped by an explicit `[limits] max_audio_frames` ring.
    dropped: u64,
    /// Released to stay inside the `[limits] max_audio_bytes` budget.
    released: u64,
    /// Released after the call's vCon container was written live.
    after_export: u64,
}

impl RetentionLoss {
    /// The losses summed over `streams`.
    fn of(streams: &[&RtpStream]) -> Self {
        streams.iter().fold(Self::default(), |acc, s| Self {
            dropped: acc.dropped.saturating_add(s.payload_frames_dropped),
            released: acc.released.saturating_add(s.payload_frames_released),
            after_export: acc
                .after_export
                .saturating_add(s.payload_frames_released_after_export),
        })
    }

    /// Whether any frame is missing from the start.
    fn any(self) -> bool {
        self.dropped > 0 || self.released > 0 || self.after_export > 0
    }
}

/// The clauses naming every frame missing from the start of a file, by
/// reason and count, or nothing when none is.
fn retention_clauses(loss: &RetentionLoss) -> String {
    let mut out = wrap_clause(loss.dropped);
    if loss.released > 0 {
        out.push_str(&format!(
            " — PARTIAL: the [limits] max_audio_bytes retention budget was reached and \
             released {} earlier frame(s), oldest stream first, so this file holds the \
             END of the stream, not all of it. Raise [limits] max_audio_bytes to keep more.",
            loss.released
        ));
    }
    if loss.after_export > 0 {
        out.push_str(&format!(
            " — PARTIAL: {} earlier frame(s) were released after this call's vCon \
             container was written, so this file holds only the audio that arrived \
             after that. The written container carries the audio released.",
            loss.after_export
        ));
    }
    out
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
    /// `[limits] max_audio_frames = 1500` ring kept its last 1500 frames
    /// lands here as 30 seconds, and
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
    /// `true` when frames are missing from the start of this file's streams:
    /// a payload ring dropped them, the retention budget released them, or
    /// they were released after the call's vCon container was written.
    ///
    /// The signal that the file is shorter than the call it came from, which
    /// is the one gap vCon can state in its own vocabulary
    /// (section 4b of `docs/design/vcon.md`,
    /// ["Media: a `recording` Dialog Object is not a recording"](https://github.com/NormB/sipnab/blob/main/docs/design/vcon.md#4b-media-a-recording-dialog-object-is-not-a-recording)).
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

    // A WAV carries two channels, and they must come from two SOURCES.
    //
    // Taking the first two exportable streams looks equivalent and is not. A
    // media relay sees each direction TWICE -- arriving and leaving -- so a
    // two-party call reaches here as four records carrying two SSRCs, and the
    // two records of one leg can both sort ahead of the other leg. The export
    // was then a stereo file whose channels were byte-identical: it claims a
    // conversation and carries one side of it, and nothing in the file says so.
    //
    // One stream per SSRC, in first-seen order. Where only one source is
    // present the result is mono, which is the honest answer -- duplicating a
    // single leg across two channels would read as a two-party recording.
    // Sources, not records. A relay hands over two records per source, so a
    // count of `streams.len()` reports two of four omitted on a call where both
    // parties were carried -- a caveat describing loss that did not happen,
    // which is as misleading as one that hides loss. Counted over EVERY stream,
    // including ones dropped for their codec, because the clause speaks about
    // the call rather than about what survived the filter.
    let distinct_sources = {
        let mut seen: Vec<u32> = Vec::new();
        for s in streams {
            if !seen.contains(&s.key.ssrc) {
                seen.push(s.key.ssrc);
            }
        }
        seen.len()
    };

    let mut seen_ssrc: Vec<u32> = Vec::with_capacity(2);
    let carried: Vec<&RtpStream> = exportable
        .iter()
        .filter(|s| {
            let ssrc = s.key.ssrc;
            if seen_ssrc.contains(&ssrc) {
                return false;
            }
            seen_ssrc.push(ssrc);
            true
        })
        .take(2)
        .copied()
        .collect();
    let mut decoded: Vec<(Vec<i16>, u32, &'static str, u64)> = Vec::with_capacity(carried.len());
    let mut placed = TimelineTotals::default();
    let mut caveats: Vec<String> = Vec::new();
    for stream in &carried {
        let d = decode_stream_pcm(stream, true)?;
        caveats.extend(d.caveat);
        placed.add(&TimelineTotals::of(
            &d.timeline,
            stream.clock_rate,
            d.codec_fill,
        ));
        decoded.push((d.pcm, d.rate, d.label, d.failures));
    }

    // The higher rate wins and the lower channel is resampled up, so a G.711
    // leg and an Opus leg land on one timebase instead of one playing fast.
    let output_rate = decoded
        .iter()
        .map(|d| d.1)
        .max()
        .unwrap_or(DEFAULT_WAV_RATE);
    // Each channel starts where its party started, so a party who began
    // talking later is preceded by silence rather than pulled to the front.
    let starts: Vec<DateTime<Utc>> = carried.iter().map(|s| aligned_start(s)).collect();
    let earliest = starts.iter().min().copied().unwrap_or_else(Utc::now);
    // Microseconds, not milliseconds: two directions captured 0.5 ms apart
    // are 4 samples apart at 8 kHz, and whole milliseconds would drop that.
    let lead_in_us: Vec<u64> = starts
        .iter()
        .map(|s| {
            (*s - earliest)
                .num_microseconds()
                .and_then(|us| u64::try_from(us).ok())
                .unwrap_or(0)
        })
        .collect();
    let (samples, channels, frames_per_channel) =
        interleave_channels(&mut decoded, output_rate, &lead_in_us);

    let loss = RetentionLoss::of(&carried);
    let failures: u64 = decoded.iter().map(|d| d.3).fold(0u64, u64::saturating_add);

    let partial = format!(
        "{}{}{}{}{}{}{}",
        caveat_clause(&caveats),
        retention_clauses(&loss),
        omitted_clause(distinct_sources, carried.len(), &skipped_codecs),
        not_decoded_clause(&skipped_codecs),
        decode_failure_clause(failures),
        timeline_clause(&placed),
        direction_clause(streams)
    ) + &undecrypted_clause(&carried);
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
        ring_wrapped: loss.any(),
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
    lead_in_us: &[u64],
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

    // Silence in front of a channel whose party started later, at the output
    // rate. Bounded by the capture's own span: see `aligned_start`.
    for (channel, us) in decoded.iter_mut().zip(lead_in_us) {
        let lead = usize::try_from(crate::rtp::timeline::ticks_to_samples(
            *us,
            1_000_000,
            output_rate,
        ))
        .unwrap_or(0);
        if lead > 0 {
            channel.0.splice(0..0, std::iter::repeat_n(0, lead));
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
    let (
        Some(RetainedFrame {
            timestamp: oldest, ..
        }),
        Some(RetainedFrame {
            timestamp: newest, ..
        }),
    ) = (stream.payload_buffer.front(), stream.payload_buffer.back())
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

/// When `stream`'s first retained sample was captured, for lining up the two
/// channels of a stereo file.
///
/// [`retained_window_start`] measures it from the RTP timestamp span, which
/// the sender controls: a span of a day would put the start a day before the
/// stream's first packet and fill the other channel with a day of silence.
/// It is clamped to the first packet's capture time, which the sender does
/// not control.
fn aligned_start(stream: &RtpStream) -> DateTime<Utc> {
    retained_window_start(stream).max(stream.first_seen)
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

/// What the carried streams' timelines did, summed across streams whose RTP
/// clocks may differ, in milliseconds.
#[derive(Debug, Default, Clone, Copy)]
struct TimelineTotals {
    /// Gaps filled with silence.
    gaps: u64,
    /// Their total length, in milliseconds.
    filled_ms: u64,
    /// Repeated packets dropped.
    duplicates: u64,
    /// Timestamp jumps left unfilled.
    jumps: u64,
    /// Gaps a codec's own decoder filled (G.729 concealment or comfort
    /// noise), and their length in milliseconds.
    codec_gaps: u64,
    /// Their total length, in milliseconds.
    codec_ms: u64,
    /// The codec whose decoder filled them.
    codec_label: Option<&'static str>,
}

impl TimelineTotals {
    /// One stream's report, its fill converted from its own clock.
    ///
    /// `codec_fill` names the codec when its own decoder filled the gaps
    /// (see [`FrameDecoder::fills_with_codec`]); otherwise they are silence.
    fn of(
        report: &crate::rtp::timeline::TimelineReport,
        clock_rate: u32,
        codec_fill: Option<&'static str>,
    ) -> Self {
        let ms = report.filled_ms(clock_rate);
        let mut t = Self {
            duplicates: report.duplicates,
            jumps: report.jumps,
            ..Self::default()
        };
        if codec_fill.is_some() {
            t.codec_gaps = report.gaps;
            t.codec_ms = ms;
            t.codec_label = codec_fill;
        } else {
            t.gaps = report.gaps;
            t.filled_ms = ms;
        }
        t
    }

    /// Add another stream's totals.
    fn add(&mut self, other: &Self) {
        self.gaps = self.gaps.saturating_add(other.gaps);
        self.filled_ms = self.filled_ms.saturating_add(other.filled_ms);
        self.duplicates = self.duplicates.saturating_add(other.duplicates);
        self.jumps = self.jumps.saturating_add(other.jumps);
        self.codec_gaps = self.codec_gaps.saturating_add(other.codec_gaps);
        self.codec_ms = self.codec_ms.saturating_add(other.codec_ms);
        self.codec_label = self.codec_label.or(other.codec_label);
    }
}

/// Clauses naming the time filled with silence, the repeated packets
/// dropped, and the timestamp jumps left unfilled, or nothing when the frames
/// lay end to end.
///
/// The file is longer than the frames it holds wherever silence was put in,
/// and the timestamps cannot say whether a packet was lost or the sender
/// paused, so the clause names both causes rather than guessing one.
fn timeline_clause(t: &TimelineTotals) -> String {
    let mut out = String::new();
    if t.gaps > 0 {
        let noun = if t.gaps == 1 { "gap" } else { "gaps" };
        out.push_str(&format!(
            " — {} ms in {} {noun} where the RTP timestamps show no audio arrived \
             (lost packets, or the sender pausing) is silence in this file.",
            t.filled_ms, t.gaps
        ));
    }
    if t.codec_gaps > 0 {
        let noun = if t.codec_gaps == 1 { "gap" } else { "gaps" };
        let codec = t.codec_label.unwrap_or("codec");
        out.push_str(&format!(
            " — {} ms in {} {noun} where the RTP timestamps show no audio arrived \
             holds the {codec} decoder's loss concealment or comfort noise in this file.",
            t.codec_ms, t.codec_gaps
        ));
    }
    if t.duplicates > 0 {
        let noun = if t.duplicates == 1 {
            "packet"
        } else {
            "packets"
        };
        out.push_str(&format!(
            " — {} duplicate {noun} (a repeated RTP timestamp) dropped.",
            t.duplicates
        ));
    }
    if t.jumps > 0 {
        let noun = if t.jumps == 1 { "jump" } else { "jumps" };
        out.push_str(&format!(
            " — {} RTP timestamp {noun} longer than the stream itself not filled; \
             the audio either side is joined.",
            t.jumps
        ));
    }
    out
}

/// A clause counting SRTP packets on the carried streams that were not
/// decrypted, or nothing when there were none.
///
/// Their payload was not kept, so the audio has a gap wherever they fell. A
/// stream reaches the export with some packets decrypted and some not when a
/// key authenticated only part of it.
fn undecrypted_clause(carried: &[&RtpStream]) -> String {
    let undecrypted: u64 = carried
        .iter()
        .map(|s| s.srtp_undecrypted_packets)
        .fold(0u64, u64::saturating_add);
    if undecrypted == 0 {
        return String::new();
    }
    format!(
        " — PARTIAL: {undecrypted} SRTP packet(s) were not decrypted and are missing from \
         the audio."
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
    let mut codecs: Vec<&str> = skipped_codecs.to_vec();
    codecs.sort_unstable();
    codecs.dedup();

    // A codec drop is an omission even when the COUNT shows none. The two were
    // one condition, so an undecodable stream sharing a source with a carried
    // one was filtered out in silence -- which is the exact failure the rest of
    // this doc comment says must not happen. It surfaced once omissions were
    // counted over sources rather than records, but the coupling was always
    // there and any call whose numbers happened to line up hit it.
    if dropped == 0 && codecs.is_empty() {
        return String::new();
    }

    let detail = if codecs.is_empty() {
        String::new()
    } else {
        format!(" ({})", codecs.join(", "))
    };
    if dropped == 0 {
        return format!(
            " — PARTIAL: stream(s) on this call are NOT in this file{detail}. \
             sipnab could not decode them."
        );
    }
    format!(
        " — PARTIAL: {dropped} of {total} stream(s) on this call are NOT in this \
         file{detail}. A WAV carries two channels, and streams sipnab cannot decode \
         are left out."
    )
}

/// Why a codec this build can decode in principle is not decoded by this run,
/// or `None`. Only G.729 has such a reason: its tables are installed per
/// host, and a build may leave the feature out.
fn not_decoded_reason(codec: Option<&str>) -> Option<String> {
    match codec {
        Some(c) if g729_variant(c).is_some() => {
            let why = crate::rtp::g729_tables::unavailable_reason();
            if let Some(why) = &why {
                crate::rtp::g729_tables::say_once_not_decoded(why);
            }
            why
        }
        _ => None,
    }
}

/// The reasons [`not_decoded_reason`] gives for `codecs`, each once, as
/// clauses: " — G.729 not decoded: ...; run sipnab g729 install."
fn not_decoded_clause(codecs: &[&str]) -> String {
    let mut reasons: Vec<String> = codecs
        .iter()
        .filter_map(|c| not_decoded_reason(Some(c)))
        .collect();
    reasons.sort_unstable();
    reasons.dedup();
    reasons.iter().map(|r| format!(" — {r}.")).collect()
}

/// The codecs a WAV export decodes in this build, for a refusal to list.
fn supported_codecs() -> &'static str {
    if cfg!(feature = "g729") {
        "PCMU, PCMA, G.722, Opus, G.729 and the G.729.1 core layer (with the G.729 tables \
         installed)"
    } else {
        "PCMU, PCMA, G.722, Opus"
    }
}

/// Explain a failed export in terms of what sipnab actually observed.
///
/// Both failures used to read "No audio streams with captured data found" /
/// "No audio payload captured for this stream", and a reader — an operator, or
/// an agent relaying to one — takes that as a statement about the CALL: it had
/// no audio. Two quite different situations produce it, and neither is that:
///
/// - **Nothing decodable.** Every stream carries a codec sipnab cannot turn
///   into PCM (GSM, video, or G.729 without its tables). Naming the codecs
///   found, and why G.729 was not decoded, is the whole answer.
/// - **Nothing retained.** The streams carry PCMU/PCMA/G.722/Opus and sipnab counted
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
             Supported: {}.{}",
            found.join(", "),
            supported_codecs(),
            not_decoded_clause(&found),
        );
    }

    // Audio that WAS retained and then released is not "retention was off".
    let loss = RetentionLoss::of(&decodable.iter().map(|s| **s).collect::<Vec<_>>());
    if loss.after_export > 0 || loss.released > 0 {
        let mut why = Vec::new();
        if loss.after_export > 0 {
            why.push(format!(
                "sipnab released {} frame(s) after this call's vCon container was written, \
                 which carries them",
                loss.after_export
            ));
        }
        if loss.released > 0 {
            why.push(format!(
                "the [limits] max_audio_bytes retention budget released {} frame(s) to \
                 make room for newer calls; raise it to keep more",
                loss.released
            ));
        }
        return format!(
            "No audio payload held now: this run retained the call's audio and then {}. \
             This is a statement about what this run holds, not a finding that the call \
             was silent.",
            why.join(", and ")
        );
    }

    // SRTP sipnab could not decrypt is a cause it measured, so it is stated
    // rather than left to the retention candidate below.
    let undecrypted: u64 = decodable.iter().map(|s| s.srtp_undecrypted_packets).sum();
    if undecrypted > 0 {
        return format!(
            "No audio payload held: {undecrypted} packet(s) on this call's SRTP stream(s) \
             were not decrypted, because sipnab held no key that authenticated them, so \
             their payload was ciphertext and was not kept. sipnab decrypts SRTP with SDES \
             keys from the SDP's a=crypto lines, with --srtp-keys, or, for DTLS-SRTP, with \
             --dtls-keylog."
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
/// what `decode_stream_pcm` accepts. G.729 is exportable only when this run
/// decodes it: the `g729` feature is built in and its tables load
/// ([`not_decoded_reason`]); otherwise the stream is omitted and the reason
/// named.
fn is_exportable_codec(codec: Option<&str>) -> bool {
    is_capturable_audio_codec(codec) && not_decoded_reason(codec).is_none()
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
///
/// G.729 is kept whenever the `g729` feature is built in, with or without its
/// tables. Tables installed during the run then decode what was already
/// retained, and an export without them names the missing tables rather than
/// an empty buffer. [`is_exportable_codec`] adds the tables check.
#[must_use]
pub(crate) fn is_capturable_audio_codec(codec: Option<&str>) -> bool {
    matches!(codec, Some("PCMU") | Some("PCMA"))
        || codec.is_some_and(|c| {
            is_opus_codec(c)
                || is_g722_codec(c)
                || (cfg!(feature = "g729") && g729_variant(c).is_some())
        })
}

/// Check if a codec name is G.722 (case-insensitive per SDP convention).
fn is_g722_codec(codec: &str) -> bool {
    codec.eq_ignore_ascii_case("G722")
}

/// Check if a codec name is Opus (case-insensitive per SDP convention).
fn is_opus_codec(codec: &str) -> bool {
    codec.eq_ignore_ascii_case("opus")
}

/// The decoded samples of one stream, for a caller that wants the audio rather
/// than a file.
///
/// The same decode the WAV export runs, exposed because
/// [`crate::rtp::amplitude`] measures what the samples DID and there is no
/// reason for a second decoder to exist beside this one.
///
/// # Arguments
///
/// * `stream` — the stream to decode. Its `payload_buffer` is empty unless the
///   run asked for `--retain-audio`.
///
/// # Returns
///
/// `(samples, sample_rate)`, or `None` when nothing was retained or the codec
/// has no decoder here. `None` means NOT DECODED and never "silence".
#[must_use]
pub fn stream_pcm(stream: &RtpStream) -> Option<(Vec<i16>, u32)> {
    if stream.payload_buffer.is_empty() {
        return None;
    }
    let DecodedStream { pcm, rate, .. } = decode_stream_pcm(stream, false).ok()?;
    if pcm.is_empty() {
        None
    } else {
        Some((pcm, rate))
    }
}

/// Decode all captured payloads in a stream to PCM i16 samples.
///
/// Returns `(samples, sample_rate, codec_label)`.
/// How long `stream` has lasted in capture time, in milliseconds: the
/// budget for the silence its timeline may put in (see
/// [`crate::rtp::timeline`]).
pub(crate) fn stream_wall_ms(stream: &RtpStream) -> u64 {
    u64::try_from((stream.last_seen - stream.first_seen).num_milliseconds()).unwrap_or(0)
}

/// One stream's retained audio, decoded.
pub(crate) struct DecodedStream {
    /// The samples.
    pub(crate) pcm: Vec<i16>,
    /// Their rate.
    pub(crate) rate: u32,
    /// The codec's name in a summary.
    pub(crate) label: &'static str,
    /// Frames the decoder refused.
    pub(crate) failures: u64,
    /// Where the frames were placed on the stream's RTP clock.
    pub(crate) timeline: crate::rtp::timeline::TimelineReport,
    /// The codec whose own decoder filled the gaps, or `None` for silence.
    pub(crate) codec_fill: Option<&'static str>,
    /// What the audio is when it is not simply the codec's audio (see
    /// [`FrameDecoder::caveat`]).
    pub(crate) caveat: Option<String>,
}

/// Decode `stream`'s retained frames in RTP timestamp order.
///
/// `fill` puts silence wherever the timestamps show time passed with no audio
/// received (see [`crate::rtp::timeline`]), which is what a file someone
/// listens to needs. Without it the gaps close up, which is what a
/// measurement of the sender's own samples needs: a lost packet is not dead
/// air. Both drop repeated packets and undo reordering.
fn decode_stream_pcm(stream: &RtpStream, fill: bool) -> Result<DecodedStream> {
    use crate::rtp::timeline::{
        Step, Timeline, samples_to_ticks, ticks_to_samples, timestamp_order,
    };
    let mut decoder = FrameDecoder::new(stream.codec.as_deref())?;
    let rate = decoder.rate(stream.clock_rate);
    let clock = stream.clock_rate;
    let mut timeline = Timeline::new(clock, stream_wall_ms(stream), fill);
    let stamps: Vec<u32> = stream.payload_buffer.iter().map(|f| f.timestamp).collect();
    let mut pcm: Vec<i16> = Vec::new();
    // Counted, not just logged. A skipped frame shortens the audio while the
    // summary went on reporting `payload_buffer.len()` as the frame count, so
    // the file was quietly missing whatever failed and the number said
    // otherwise. `debug!` is off by default, which made the only record of it
    // invisible on the runs that mattered.
    let mut decode_failures: u64 = 0;
    // The sequence number of the last frame that decoded: the packets
    // between it and the next frame that are missing were lost.
    let mut decoded_sequence: Option<u16> = None;
    for index in timestamp_order(&stamps) {
        let Some(RetainedFrame {
            timestamp: ts,
            sequence,
            payload,
        }) = stream.payload_buffer.get(index)
        else {
            continue;
        };
        let Step::Play { fill_ticks } = timeline.step(*ts) else {
            continue;
        };
        // Bounded by the timeline's budget, the stream's own wall-clock span,
        // so a hostile timestamp cannot size this allocation.
        let silence = usize::try_from(ticks_to_samples(fill_ticks, clock, rate)).unwrap_or(0);
        if silence > 0 {
            pcm.extend(decoder.fill(silence, missing_between(decoded_sequence, *sequence)));
        }
        match decoder.decode(payload) {
            Ok(samples) => {
                decoded_sequence = Some(*sequence);
                timeline.played(samples_to_ticks(samples.len() as u64, rate, clock));
                pcm.extend_from_slice(&samples);
            }
            Err(e) => {
                decode_failures = decode_failures.saturating_add(1);
                tracing::debug!("{} decode error (skipping frame): {e}", decoder.label());
            }
        }
    }
    Ok(DecodedStream {
        pcm,
        rate,
        label: decoder.label(),
        failures: decode_failures,
        timeline: timeline.report(),
        codec_fill: decoder.fills_with_codec().then(|| decoder.label()),
        caveat: decoder.caveat(),
    })
}

/// RTP sequence numbers missing between a frame with sequence `previous` and
/// the next one with sequence `next`, counted modulo 2^16 as the 16-bit
/// sequence number wraps ([RFC 3550 section 5.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1)); `None` when there is no previous
/// frame.
#[must_use]
pub fn missing_between(previous: Option<u16>, next: u16) -> Option<u16> {
    previous.map(|p| next.wrapping_sub(p).wrapping_sub(1))
}

/// One stream's decoder, frame by frame, carrying whatever state the codec
/// keeps from one frame to the next.
///
/// The one place a codec name becomes a decoder: the whole-call export and
/// the live audio route both decode through it, so they cannot come to
/// disagree about which codecs decode or at what rate.
pub enum FrameDecoder {
    /// G.711 mu-law (PCMU).
    Ulaw,
    /// G.711 A-law (PCMA).
    Alaw,
    /// G.722, which is adaptive: each frame continues the last one's state.
    G722(Box<crate::rtp::g722::Decoder>),
    /// Opus, decoded at 48 kHz mono.
    Opus(Box<OpusStreamDecoder>),
    /// G.729 Annex A with Annex B comfort noise, on the tables this run
    /// loaded (see [`crate::rtp::g729_tables`]).
    #[cfg(feature = "g729")]
    G729(Box<G729Stream>),
}

/// One G.729-family stream's decoder and whether the sender was talking when
/// the last frame arrived.
#[cfg(feature = "g729")]
pub struct G729Stream {
    /// The decoder, on the tables this run loaded.
    decoder: g729::Decoder<'static>,
    /// What the last payload ended with.
    last: G729Last,
    /// How many 10 ms frames this stream's speech packets carry: how much
    /// time one lost packet stands for.
    speech_packets: SpeechPacketSizes,
    /// G.729, or G.729.1 decoded to its core layer.
    variant: G729Variant,
    /// The G.729.1 bit rates of the frames decoded.
    rates: G7291Rates,
}

#[cfg(feature = "g729")]
impl G729Stream {
    /// One payload, decoded: [RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6) frames for G.729, the
    /// core layer of RFC 4749 frames for G.729.1.
    fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>> {
        let mut pcm = Vec::new();
        match self.variant {
            G729Variant::G729 => {
                self.last = g729_last_after(payload.len(), self.last);
                // A payload of 10n octets is n speech frames; one ending in
                // a SID is not the size of the stream's speech packets.
                if payload.len() >= 10 && payload.len().is_multiple_of(10) {
                    self.speech_packets.record(payload.len() / 10);
                }
                self.decoder
                    .decode_rtp(payload, &mut pcm)
                    .map_err(anyhow::Error::msg)?;
            }
            G729Variant::G7291 => {
                let split = g729::g7291::split_rtp(payload).map_err(anyhow::Error::msg)?;
                self.last = g7291_last_after(&split, self.last);
                // Each 20 ms frame is two 10 ms G.729 frames.
                if split.sid.is_none() && split.frame_count() > 0 {
                    self.speech_packets.record(2 * split.frame_count());
                }
                if let g729::g7291::FrameType::Speech(rate) = split.header.frame_type
                    && split.frame_count() > 0
                {
                    self.rates.record(rate);
                }
                self.decoder
                    .decode_g7291_rtp(payload, &mut pcm)
                    .map_err(anyhow::Error::msg)?;
            }
        }
        Ok(pcm)
    }
}

/// What a G.729.1 payload leaves the stream in, after `last`: a SID ends in
/// discontinuous transmission, frames alone end in speech, and a payload
/// with neither (FT 15, or no whole frame) changes nothing.
#[cfg(feature = "g729")]
pub(crate) fn g7291_last_after(payload: &g729::g7291::Payload<'_>, last: G729Last) -> G729Last {
    if payload.sid.is_some() {
        G729Last::Inactive
    } else if payload.frame_count() > 0 {
        G729Last::Active
    } else {
        last
    }
}

/// The sizes of a G.729 stream's speech packets (payloads of speech frames
/// alone, 10n octets), counted, so a lost packet is sized by the stream's
/// usual packet rather than by the one before it: speech that resumes on an
/// odd frame arrives as a one-frame packet in a stream of two-frame packets.
#[cfg(feature = "g729")]
#[derive(Debug, Clone, Default)]
pub(crate) struct SpeechPacketSizes {
    /// `counts[n - 1]`: packets of `n` frames; the last slot also counts
    /// every larger packet.
    counts: [u32; 16],
}

#[cfg(feature = "g729")]
impl SpeechPacketSizes {
    /// Count one speech packet of `frames` frames.
    pub(crate) fn record(&mut self, frames: usize) {
        if frames == 0 {
            return;
        }
        let slot = frames.min(self.counts.len()) - 1;
        self.counts[slot] = self.counts[slot].saturating_add(1);
    }

    /// The most frequent size, the larger on a tie, or 1 before any speech
    /// packet arrived.
    pub(crate) fn usual(&self) -> usize {
        let mut best = (0u32, 1usize);
        for (slot, &count) in self.counts.iter().enumerate() {
            if count > 0 && count >= best.0 {
                best = (count, slot + 1);
            }
        }
        best.1
    }
}

/// What the last G.729 payload ended with, which decides what a gap after
/// it means.
#[cfg(feature = "g729")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum G729Last {
    /// A speech frame (or nothing yet): the sender was talking.
    Active,
    /// A SID frame: the sender switched to discontinuous transmission.
    Inactive,
}

/// What a G.729 payload of `len` octets leaves the stream in, after `last`.
///
/// [RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6): a payload is zero or more 10-octet frames
/// followed by zero or one 2-octet SID frame, so a payload of 10n + 2
/// octets ends in a SID and one of 10n octets (n > 0) ends in speech.
#[cfg(feature = "g729")]
pub(crate) fn g729_last_after(len: usize, last: G729Last) -> G729Last {
    if len % 10 == 2 {
        G729Last::Inactive
    } else if len >= 10 {
        G729Last::Active
    } else {
        last
    }
}

/// The frame a whole gap in a G.729 stream stands for, after `last`, when
/// the RTP sequence numbers cannot say how much of it was lost (see
/// [`g729_gap_frames`]).
///
/// Annex B: a sender stops sending after a SID frame, so time with no
/// packet after a SID is untransmitted frames and the comfort noise carries
/// on (clause B.4.5). After speech a sender sends a SID before it stops, so
/// time with no packet after speech is taken as lost frames, which the
/// decoder conceals (clause 4.4).
#[cfg(feature = "g729")]
pub(crate) fn g729_gap_frame(last: G729Last) -> g729::Frame<'static> {
    match last {
        G729Last::Active => g729::Frame::Erased,
        G729Last::Inactive => g729::Frame::NoTx,
    }
}

/// How the 10 ms frames of one gap in a G.729 stream divide between lost
/// and untransmitted frames, in the order the decoder is given them.
#[cfg(feature = "g729")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct G729Gap {
    /// Erased frames right after the last received packet.
    pub(crate) erased_before: usize,
    /// Untransmitted frames.
    pub(crate) notx: usize,
    /// Erased frames right before the next received packet.
    pub(crate) erased_after: usize,
}

/// The frames a gap of `gap_frames` 10 ms frames in a G.729 stream stands
/// for, after a payload that left the stream in `last`.
///
/// The RTP timestamps say how long the gap is; the RTP sequence numbers say
/// how much of it was lost. A sender under discontinuous transmission (Annex
/// B) sends no packet for an untransmitted frame, so its sequence numbers
/// stay consecutive across a pause, and a sequence number missing from the
/// capture is a packet that was sent and lost.
///
/// - `missing_packets` is the count of sequence numbers missing between the
///   packet before the gap and the packet after it (see
///   [`missing_between`]). The lost frames are `missing_packets` times
///   `frames_per_packet` (at least 1), at most `gap_frames`, and are
///   erased frames. The rest of the gap is untransmitted frames.
/// - After speech, a gap longer than the lost packets fill holds a pause,
///   and an Annex B pause starts with a SID packet of one frame. So the last
///   packet lost was that SID: the lost frames are `missing_packets - 1`
///   speech packets' frames plus one.
/// - After speech ([`G729Last::Active`]) the lost frames come first, right
///   after the last packet received: a sender sends a SID frame before it
///   pauses, so the packet missing after speech is that SID or more speech.
/// - After a SID ([`G729Last::Inactive`]) the lost frames come last, right
///   before the next packet received: the sender sent nothing during the
///   pause, so the packet missing is the one that ended it.
/// - With no sequence number missing, the whole gap is untransmitted, after
///   speech as well as after a SID. After speech this is a sender that
///   paused and whose SID frame was not sent. Annex B clause B.4.5 decodes
///   an untransmitted frame after an active one as the start of a pause
///   whose first SID frame was lost: comfort noise at the level of the
///   speech before it. An erased frame after an active one is concealed as
///   speech (clause 4.4), which nothing lost here calls for.
/// - A count larger than the gap has frames is not a count of packets lost
///   in it (a sequence number repeated, reordered, or reset), and `None` is
///   no packet before the gap. For either, the count is unknown and the gap
///   is the frame [`g729_gap_frame`] chooses from `last` alone, for its
///   whole length.
#[cfg(feature = "g729")]
pub(crate) fn g729_gap_frames(
    last: G729Last,
    missing_packets: Option<u16>,
    frames_per_packet: usize,
    gap_frames: usize,
) -> G729Gap {
    let whole = |frame| match frame {
        g729::Frame::Erased => G729Gap {
            erased_before: gap_frames,
            notx: 0,
            erased_after: 0,
        },
        _ => G729Gap {
            erased_before: 0,
            notx: gap_frames,
            erased_after: 0,
        },
    };
    let Some(missing) = missing_packets
        .map(usize::from)
        .filter(|&missing| missing <= gap_frames)
    else {
        return whole(g729_gap_frame(last));
    };
    let per_packet = frames_per_packet.max(1);
    let filled = missing.saturating_mul(per_packet);
    // A gap the lost packets do not fill holds a pause, and an Annex B pause
    // starts with a SID packet of one frame: after speech, the last packet
    // lost was that SID, so it is one frame, not a speech packet's.
    let lost = if last == G729Last::Active && missing > 0 && filled < gap_frames {
        (missing - 1).saturating_mul(per_packet).saturating_add(1)
    } else {
        filled.min(gap_frames)
    };
    let notx = gap_frames - lost;
    match last {
        G729Last::Active => G729Gap {
            erased_before: lost,
            notx,
            erased_after: 0,
        },
        G729Last::Inactive => G729Gap {
            erased_before: 0,
            notx,
            erased_after: lost,
        },
    }
}

/// `samples` samples of `decoder`'s own output for time in which no payload
/// arrived: one frame per 10 ms (80 samples), in the order `gap` gives them.
/// A remainder short of a frame is zeros, so the length is exact.
#[cfg(feature = "g729")]
fn g729_fill(decoder: &mut g729::Decoder<'static>, gap: G729Gap, samples: usize) -> Vec<i16> {
    let mut out = Vec::with_capacity(samples);
    let mut pcm = [0i16; g729::FRAME_SAMPLES];
    let frames = std::iter::repeat_n(g729::Frame::Erased, gap.erased_before)
        .chain(std::iter::repeat_n(g729::Frame::NoTx, gap.notx))
        .chain(std::iter::repeat_n(g729::Frame::Erased, gap.erased_after));
    for frame in frames {
        decoder.decode(frame, &mut pcm);
        out.extend_from_slice(&pcm);
    }
    out.resize(samples, 0);
    out
}

/// The decoder for a stream of `variant` of the G.729 family, or why there is
/// none: the build has no `g729` feature, or the tables are not installed.
fn g729_decoder(variant: G729Variant) -> Result<FrameDecoder> {
    #[cfg(feature = "g729")]
    {
        let tables = crate::rtp::g729_tables::tables().map_err(|why| {
            crate::rtp::g729_tables::say_once_not_decoded(&why);
            anyhow::Error::msg(why)
        })?;
        Ok(FrameDecoder::G729(Box::new(G729Stream {
            decoder: g729::Decoder::new(tables),
            last: G729Last::Active,
            speech_packets: SpeechPacketSizes::default(),
            variant,
            rates: G7291Rates::default(),
        })))
    }
    #[cfg(not(feature = "g729"))]
    {
        let _ = variant;
        crate::rtp::g729_tables::say_once_not_decoded(crate::rtp::g729_tables::NOT_BUILT);
        bail!("{}", crate::rtp::g729_tables::NOT_BUILT)
    }
}

impl FrameDecoder {
    /// The decoder for a stream whose codec is `codec`.
    ///
    /// # Errors
    ///
    /// A codec with no decoder here, or none named, or an Opus decoder that
    /// would not start.
    pub fn new(codec: Option<&str>) -> Result<Self> {
        match codec {
            Some("PCMU") => Ok(Self::Ulaw),
            Some("PCMA") => Ok(Self::Alaw),
            Some(name) if is_g722_codec(name) => Ok(Self::G722(Box::default())),
            // Opus decodes at 48 kHz mono by default. SDP declares
            // opus/48000/2 but RTP frames are typically mono.
            Some(name) if is_opus_codec(name) => {
                Ok(Self::Opus(Box::new(OpusStreamDecoder::new(48000, 1)?)))
            }
            Some(other) => match g729_variant(other) {
                Some(variant) => g729_decoder(variant),
                None => bail!(
                    "Unsupported codec for WAV export: {other}. Supported: {}.",
                    supported_codecs()
                ),
            },
            None => bail!("Unknown codec — cannot decode to WAV"),
        }
    }

    /// The rate of the samples it decodes to, for a stream whose RTP clock
    /// runs at `clock_rate`.
    ///
    /// G.711's is the clock rate. G.722's is 16 kHz whatever the clock rate
    /// says: [RFC 3551 section 4.5.2](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.2) gives payload type 9 an 8 kHz RTP clock
    /// for historical reasons, and the samples are 16 kHz. Opus decodes at
    /// 48 kHz.
    #[must_use]
    pub fn rate(&self, clock_rate: u32) -> u32 {
        match self {
            Self::Ulaw | Self::Alaw => clock_rate,
            Self::G722(_) => 16000,
            Self::Opus(_) => 48000,
            #[cfg(feature = "g729")]
            Self::G729(_) => 8000,
        }
    }

    /// The codec's name in an export's summary.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ulaw => "mu-law",
            Self::Alaw => "A-law",
            Self::G722(_) => "G.722",
            Self::Opus(_) => "Opus",
            #[cfg(feature = "g729")]
            Self::G729(stream) => stream.variant.label(),
        }
    }

    /// What the decoded audio is, when it is not simply the codec's audio:
    /// for G.729.1, the core layer decoded as G.729, at the bit rates of the
    /// frames decoded so far (see [`crate::rtp::g729_family::g7291_caveat`]).
    #[must_use]
    pub fn caveat(&self) -> Option<String> {
        match self {
            #[cfg(feature = "g729")]
            Self::G729(stream) if stream.variant == G729Variant::G7291 => {
                Some(crate::rtp::g729_family::g7291_caveat(&stream.rates))
            }
            _ => None,
        }
    }

    /// One frame's payload, decoded.
    ///
    /// # Errors
    ///
    /// A frame the Opus decoder refused, or a G.729 payload that is neither
    /// 10n nor 10n + 2 octets; G.711 and G.722 decode any bytes.
    pub fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>> {
        match self {
            Self::Ulaw => Ok(decode_frame(G711Codec::Ulaw, payload)),
            Self::Alaw => Ok(decode_frame(G711Codec::Alaw, payload)),
            Self::G722(decoder) => Ok(decoder.decode(payload)),
            Self::Opus(decoder) => decoder.decode_frame(payload),
            #[cfg(feature = "g729")]
            Self::G729(stream) => stream.decode(payload),
        }
    }

    /// `samples` samples standing for time in which no frame arrived (see
    /// [`crate::rtp::timeline`]).
    ///
    /// `missing_packets` is the count of RTP sequence numbers missing between
    /// the last frame decoded and the next one (see [`missing_between`]), or
    /// `None` when no frame was decoded before the gap.
    ///
    /// Zeros for G.711, G.722 and Opus, which do not read `missing_packets`.
    /// For G.729, the decoder's own output for the missing frames, so its
    /// concealment and comfort noise run as the Recommendation intends: the
    /// frames of missing packets are erased frames and the rest of the gap
    /// is untransmitted frames, by the rule `g729_gap_frames` states.
    pub fn fill(&mut self, samples: usize, missing_packets: Option<u16>) -> Vec<i16> {
        self.fill_samples(samples, missing_packets)
    }

    /// Whether [`fill`](Self::fill) produces the codec's own output (G.729
    /// concealment or comfort noise) rather than silence.
    #[must_use]
    pub fn fills_with_codec(&self) -> bool {
        match self {
            #[cfg(feature = "g729")]
            Self::G729(_) => true,
            _ => false,
        }
    }

    /// The body of [`fill`](Self::fill).
    fn fill_samples(&mut self, samples: usize, missing_packets: Option<u16>) -> Vec<i16> {
        match self {
            #[cfg(feature = "g729")]
            Self::G729(stream) => {
                let gap = g729_gap_frames(
                    stream.last,
                    missing_packets,
                    stream.speech_packets.usual(),
                    samples / g729::FRAME_SAMPLES,
                );
                g729_fill(&mut stream.decoder, gap, samples)
            }
            _ => {
                // Silence whatever was lost: only G.729 tells a lost frame
                // from an untransmitted one.
                let _ = missing_packets;
                vec![0; samples]
            }
        }
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
    type TestError = Box<dyn std::error::Error>;
    /// A frame the decoder rejects must be counted, not only logged.
    ///
    /// The skip was recorded with `debug!`, which is off by default, while the
    /// summary went on reporting `payload_buffer.len()` as the frame count --
    /// so the file was short by whatever failed and the number said otherwise.
    /// Exercised through a real export, because removing the counter's
    /// increment still compiles and `decode_failure_clause`'s own test still
    /// passes: that test is handed a number rather than measuring one.
    #[test]
    fn opus_frames_the_decoder_rejects_are_counted() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("opus.wav");

        // Two frames of bytes that are not valid Opus. If the decoder ever
        // learns to accept them the assertion below fails loudly rather than
        // passing vacuously, which is the outcome to prefer.
        let stream = make_stream(Some("opus"), vec![(0, vec![0xFF; 8]), (960, vec![0xFE; 8])])?;

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
        Ok(())
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
    fn an_exported_wav_names_its_mechanism_in_the_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("provenance.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        export_stream_to_wav(&stream, &path).map_err(|e| format!("export: {e:?}"))?;

        let bytes = std::fs::read(&path).map_err(|e| format!("read back: {e:?}"))?;
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
        Ok(())
    }

    /// A partial file says so INSIDE itself, not only in the summary.
    #[test]
    fn a_partial_export_records_its_partialness_in_the_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("partial.wav");

        let mut stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        // The ring wrapped: frames existed that this file does not hold.
        stream.payload_frames_dropped = 4200;

        export_stream_to_wav(&stream, &path).map_err(|e| format!("export: {e:?}"))?;
        let bytes = std::fs::read(&path).map_err(|e| format!("read back: {e:?}"))?;
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
        Ok(())
    }

    /// Frames the retention budget released are named in the file, with the
    /// budget's key and the count, and mark the start of the call missing.
    #[test]
    fn a_budget_release_names_the_budget_and_the_count() -> Result<(), TestError> {
        let mut stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        stream.payload_frames_released = 1319;
        let audio = decode_dialog_audio(&[&stream]).map_err(|e| format!("decode: {e:?}"))?;
        assert!(
            audio.partial.contains(
                "PARTIAL: the [limits] max_audio_bytes retention budget was reached and \
                 released 1319 earlier frame(s)"
            ),
            "the reason and the count: {}",
            audio.partial
        );
        assert!(
            audio.note.contains("1319"),
            "the file's own note carries it"
        );
        assert!(
            audio.ring_wrapped,
            "released frames are the START of the stream, so the file is a fragment"
        );
        Ok(())
    }

    /// Frames released after the call's vCon was written are named too.
    #[test]
    fn a_release_after_export_is_named() -> Result<(), TestError> {
        let mut stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        stream.payload_frames_released_after_export = 3000;
        let audio = decode_dialog_audio(&[&stream]).map_err(|e| format!("decode: {e:?}"))?;
        assert!(
            audio.partial.contains(
                "PARTIAL: 3000 earlier frame(s) were released after this call's vCon \
                 container was written"
            ),
            "{}",
            audio.partial
        );
        assert!(audio.ring_wrapped);
        Ok(())
    }

    /// A stream whose audio was all released does not blame retention.
    ///
    /// An empty buffer reads as "retention was off" otherwise, which is false
    /// for a run that retained the call and then gave the memory back.
    #[test]
    fn nothing_to_decode_names_audio_that_was_released() -> Result<(), TestError> {
        let mut stream = make_stream(Some("PCMU"), Vec::new())?;
        stream.payload_frames_released_after_export = 3000;
        let message = nothing_to_decode(&[&stream]);
        assert!(
            message.contains("released 3000 frame(s) after this call's vCon container was written"),
            "{message}"
        );
        let mut budget = make_stream(Some("PCMU"), Vec::new())?;
        budget.payload_frames_released = 40;
        let message = nothing_to_decode(&[&budget]);
        assert!(
            message.contains("[limits] max_audio_bytes retention budget released 40 frame(s)"),
            "{message}"
        );
        Ok(())
    }

    /// An SRTP stream sipnab could not decrypt is named as the reason there
    /// is nothing to decode, with the packet count and the ways to supply a
    /// key, rather than blamed on retention or read as a silent call.
    #[test]
    fn nothing_to_decode_names_srtp_it_could_not_decrypt() -> Result<(), TestError> {
        let mut stream = make_stream(Some("PCMU"), Vec::new())?;
        stream.srtp = true;
        stream.srtp_undecrypted_packets = 250;
        let message = nothing_to_decode(&[&stream]);
        assert!(
            message.contains("250 packet(s)") && message.contains("SRTP"),
            "{message}"
        );
        for way in ["a=crypto", "--srtp-keys", "--dtls-keylog"] {
            assert!(message.contains(way), "names {way}: {message}");
        }
        assert!(
            !message.contains("retention"),
            "retention is not the cause: {message}"
        );
        Ok(())
    }

    /// Audio from a stream where only some SRTP packets were decrypted says
    /// the rest are missing; a stream with none undecrypted says nothing.
    #[test]
    fn a_partly_decrypted_stream_is_exported_as_partial() -> Result<(), TestError> {
        let mut stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        stream.srtp = true;
        stream.srtp_decrypted_packets = 1;
        stream.srtp_undecrypted_packets = 9;
        let audio = decode_dialog_audio(&[&stream]).map_err(|e| format!("decodes: {e:?}"))?;
        assert!(
            audio
                .partial
                .contains("PARTIAL: 9 SRTP packet(s) were not decrypted"),
            "{}",
            audio.partial
        );
        stream.srtp_undecrypted_packets = 0;
        let audio = decode_dialog_audio(&[&stream]).map_err(|e| format!("decodes: {e:?}"))?;
        assert!(!audio.partial.contains("SRTP"), "{}", audio.partial);
        Ok(())
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
    fn the_provenance_chunk_does_not_corrupt_the_audio() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("intact.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        export_stream_to_wav(&stream, &path).map_err(|e| format!("export: {e:?}"))?;

        let bytes = std::fs::read(&path).map_err(|e| format!("read back: {e:?}"))?;
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
        let data_size = u32::from_le_bytes(
            bytes[40..44]
                .try_into()
                .map_err(|e| format!("size: {e:?}"))?,
        ) as usize;
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
        let riff_size =
            u32::from_le_bytes(bytes[4..8].try_into().map_err(|e| format!("size: {e:?}"))?)
                as usize;
        assert_eq!(
            riff_size + 8,
            bytes.len(),
            "the RIFF size field must still describe the whole file, note included"
        );
        assert!(
            String::from_utf8_lossy(&bytes[44 + data_size..]).contains("sipnab-capture"),
            "the note must be there, after the audio"
        );
        Ok(())
    }

    /// The stereo path must actually CALL the omission clause.
    ///
    /// The clause has its own unit test, and that test passes while nothing
    /// wires the clause into an export -- replacing the call with an empty
    /// string still compiles and still passes it. This one exports three
    /// streams for real and reads the summary.
    #[test]
    fn a_three_stream_call_reports_the_stream_it_could_not_carry() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("three.wav");

        // Three distinct SOURCES. Sharing one SSRC made this a three-record
        // view of one source, which now exports mono and omits two -- the
        // summary would say "2 of 3" and the test would be measuring the
        // fixture rather than the two-channel limit it exists for.
        let a = make_stream_ssrc(Some("PCMU"), vec![(0, vec![0xFF; 160])], 0x0A0A_0A0A)?;
        let b = make_stream_ssrc(Some("PCMU"), vec![(0, vec![0xFF; 160])], 0x0B0B_0B0B)?;
        let c = make_stream_ssrc(Some("PCMU"), vec![(0, vec![0xFF; 160])], 0x0C0C_0C0C)?;

        let summary =
            export_dialog_to_wav(&[&a, &b, &c], &path).map_err(|e| format!("export: {e:?}"))?;
        assert!(
            summary.contains("1 of 3"),
            "a WAV carries two channels; the third stream is missing and the \
             summary must say which:\n{summary}"
        );
        Ok(())
    }

    /// A stream dropped for its codec is named in the summary, not filtered
    /// out in silence.
    #[test]
    fn an_undecodable_stream_is_named_in_the_summary() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("mixed.wav");

        let good = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        let bad = make_stream(Some("GSM"), vec![(0, vec![0x00; 10])])?;

        let summary =
            export_dialog_to_wav(&[&good, &bad], &path).map_err(|e| format!("export: {e:?}"))?;
        assert!(
            summary.contains("GSM"),
            "the undecodable stream was filtered out silently, so the file \
             looks complete:\n{summary}"
        );
        Ok(())
    }

    /// A file holding one direction must say the other was never seen.
    ///
    /// RE7 names "egress not observed" among the ways an artefact is partial.
    /// A dialog export handed one direction produces a mono file whose summary
    /// is byte-identical to a deliberate single-stream export, so "we only saw
    /// one side" and "you asked for one side" read the same.
    #[test]
    fn a_file_with_one_direction_says_the_other_was_not_seen() -> Result<(), TestError> {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        fn directed(src: [u8; 4], dst: [u8; 4]) -> Result<RtpStream, TestError> {
            let mut s = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
            s.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src)), 20000);
            s.key.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst)), 30000);
            Ok(s)
        }

        // Both ways: nothing to report.
        let there = directed([10, 0, 0, 1], [10, 0, 0, 2])?;
        let back = directed([10, 0, 0, 2], [10, 0, 0, 1])?;
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
        let mut back_odd_port = directed([10, 0, 0, 2], [10, 0, 0, 1])?;
        back_odd_port.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 41234);
        assert_eq!(
            direction_clause(&[&there, &back_odd_port]),
            "",
            "each direction negotiates its own port; pairing by socket would \
             report almost every real call as one-directional"
        );
        Ok(())
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
    fn a_one_directional_dialog_export_reports_it() -> Result<(), TestError> {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("oneway.wav");

        // Two streams, both A -> B: media was only ever seen going one way.
        let mut a = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        a.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000);
        a.key.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000);
        let mut b = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        b.key.ssrc = 0x9999_0000;
        b.key.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20002);
        b.key.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30002);

        let summary =
            export_dialog_to_wav(&[&a, &b], &path).map_err(|e| format!("export: {e:?}"))?;
        assert!(
            summary.contains("only ONE direction"),
            "a dialog whose media was only seen one way exported without \
             saying so:\n{summary}"
        );

        // And it reaches the FILE, which is what RE7 asks for.
        let bytes = std::fs::read(&path).map_err(|e| format!("read back: {e:?}"))?;
        assert!(
            String::from_utf8_lossy(&bytes).contains("only ONE direction"),
            "the note inside the file must carry it too, not just the summary"
        );
        Ok(())
    }

    /// Every mechanism the enum offers must have something that produces it.
    ///
    /// RE7 names two, and this carried both while nothing constructed the
    /// second. An enum arm no code path produces reads as a capability the
    /// tool has. `rtpengine-spool` returns when RE5 gives it a producer.
    #[test]
    fn every_mechanism_is_reachable() -> Result<(), TestError> {
        assert_eq!(AudioMechanism::SipnabCapture.id(), "sipnab-capture");
        // Exhaustive by construction: adding a variant without a producer
        // fails to compile here until it is listed, which is the reminder.
        let all = [AudioMechanism::SipnabCapture];
        assert_eq!(
            all.len(),
            1,
            "a new mechanism needs a producer and a test that exports through it"
        );
        Ok(())
    }

    /// A file that carries fewer streams than the call must say so.
    ///
    /// A WAV holds two channels and the exporter drops what it cannot decode,
    /// and the summary mentioned neither -- so a three-legged call produced a
    /// two-channel file whose summary was byte-identical to a complete one.
    /// The omission is invisible exactly when it matters: a conference or a
    /// transfer is the call somebody exports to find out what happened.
    #[test]
    fn an_export_that_leaves_streams_out_says_so() -> Result<(), TestError> {
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
        let codec = omitted_clause(3, 2, &["GSM"]);
        assert!(
            codec.contains("GSM"),
            "a stream dropped for its codec must name the codec:\n{codec}"
        );
        Ok(())
    }

    /// Frames that failed to decode are missing from the audio, and the frame
    /// count in the summary counts what was CAPTURED.
    #[test]
    fn frames_that_failed_to_decode_are_named() -> Result<(), TestError> {
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
        Ok(())
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
    fn a_run_that_kept_nothing_never_reads_as_a_silent_call() -> Result<(), TestError> {
        // Retention empty, codec decodable: a statement about the RUN.
        let kept_nothing = make_stream(Some("PCMU"), vec![])?;
        let run_msg = nothing_to_decode(&[&kept_nothing]);

        // Nothing sipnab can decode: a statement about the TRAFFIC's codecs.
        let undecodable = make_stream(Some("GSM"), vec![])?;
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
            codec_msg.contains("GSM"),
            "the undecodable-codec message must name what it found:\n{codec_msg}"
        );
        Ok(())
    }

    /// A wrapped ring must say so, or the duration reads as the call's length.
    #[test]
    fn a_wrapped_ring_is_named_in_the_summary() -> Result<(), TestError> {
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
        Ok(())
    }

    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use chrono::DateTime;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Build a stream with the given codec label and captured payload frames.
    fn make_stream(
        codec: Option<&str>,
        payloads: Vec<(u32, Vec<u8>)>,
    ) -> Result<RtpStream, TestError> {
        make_stream_ssrc(codec, payloads, 0x1234_5678)
    }

    /// A stream from a named source.
    ///
    /// `make_stream` hardcoded one SSRC, so every multi-stream test built two
    /// RECORDS OF ONE SOURCE and called it two parties. That is exactly the
    /// shape a relay produces -- each direction seen arriving and leaving --
    /// and it is why stereo export selecting "the first two" went unnoticed.
    fn make_stream_ssrc(
        codec: Option<&str>,
        payloads: Vec<(u32, Vec<u8>)>,
        ssrc: u32,
    ) -> Result<RtpStream, TestError> {
        let key = StreamKey {
            ssrc,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
            session: 0,
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
            ssrc,
            payload_offset: 12,
        };
        let ts = DateTime::from_timestamp(1_700_000_000, 0).ok_or("valid")?;
        let mut stream = RtpStream::new(key, &hdr, ts);
        if let Some(c) = codec {
            stream.codec = Some(c.to_string());
        }
        // Consecutive sequence numbers in the order given: these streams
        // lost nothing.
        stream.payload_buffer = payloads
            .into_iter()
            .zip(0u16..)
            .map(|((ts, payload), sequence)| RetainedFrame::new(ts, sequence, payload))
            .collect::<VecDeque<_>>();
        Ok(stream)
    }

    /// A single PCMU stream exports to a mono mu-law WAV file.
    #[test]
    fn export_mono_pcmu() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.wav");

        // 160 bytes of mu-law silence (0xFF)
        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        let result = export_stream_to_wav(&stream, &path)?;

        assert!(result.contains("mu-law"));
        assert!(result.contains("1 frames"));
        assert!(path.exists());
        Ok(())
    }

    /// Exporting an unsupported codec (GSM) returns an error.
    #[test]
    fn export_rejects_unsupported_codec() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.wav");

        let stream = make_stream(Some("GSM"), vec![(0, vec![0; 10])])?;
        let result = export_stream_to_wav(&stream, &path);

        assert!(result.is_err());
        assert!(
            result
                .err()
                .ok_or("expected an error, got Ok")?
                .to_string()
                .contains("Unsupported codec")
        );
        Ok(())
    }

    /// Exporting a stream with no captured payload returns an error.
    #[test]
    fn export_rejects_empty_buffer() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.wav");

        let stream = make_stream(Some("PCMU"), vec![])?;
        let result = export_stream_to_wav(&stream, &path);

        assert!(result.is_err());
        assert!(
            result
                .err()
                .ok_or("expected an error, got Ok")?
                .to_string()
                .contains("No audio payload")
        );
        Ok(())
    }

    /// A dialog with one exportable stream falls back to mono export.
    #[test]
    fn export_dialog_mono_fallback() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("dialog.wav");

        let stream = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        let result = export_dialog_to_wav(&[&stream], &path)?;

        assert!(result.contains("mu-law"));
        Ok(())
    }

    /// Two exportable streams export to an interleaved stereo WAV.
    #[test]
    fn export_dialog_stereo() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("stereo.wav");

        // Two SOURCES, not two records of one. This test passed with a single
        // SSRC used twice, which is the shape a relay emits and the reason
        // "first two exportable streams" looked correct for so long.
        let s1 = make_stream_ssrc(Some("PCMU"), vec![(0, vec![0xFF; 160])], 0x1111_1111)?;
        let s2 = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0x2222_2222)?;
        let result = export_dialog_to_wav(&[&s1, &s2], &path)?;

        assert!(result.contains("stereo"));
        assert!(path.exists());

        // Verify it's actually a stereo file
        let data = std::fs::read(&path)?;
        let channels = u16::from_le_bytes(data[22..24].try_into()?);
        assert_eq!(channels, 2);
        Ok(())
    }

    /// Two records of ONE source export mono, never fake stereo.
    ///
    /// A media relay sees each direction twice -- arriving and leaving -- so a
    /// two-party call yields four stream records carrying two SSRCs. Taking
    /// "the first two" therefore picks two copies of one leg, and the result
    /// is a stereo file whose channels are byte-identical: it claims a
    /// conversation and carries one side of it, which is worse than mono
    /// because a reader has no way to tell.
    #[test]
    fn two_records_of_one_source_export_mono_not_fake_stereo() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("dup.wav");

        // Same SSRC: the same audio seen twice at a relay.
        let ingress = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let egress = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        export_dialog_to_wav(&[&ingress, &egress], &path)?;

        let data = std::fs::read(&path)?;
        let channels = u16::from_le_bytes(data[22..24].try_into()?);
        assert_eq!(
            channels, 1,
            "one source must export mono; a stereo file here would carry the \
             same leg on both channels and read as a two-party recording"
        );
        Ok(())
    }

    /// Stereo selects two DISTINCT sources, not the first two records.
    ///
    /// The relay ordering that caused this: both records of one leg arrive
    /// before either record of the other. A selector that takes the first two
    /// picks the duplicate pair and never sees the second party at all.
    #[test]
    fn stereo_selects_two_distinct_sources_not_the_first_two() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pair.wav");

        let a_in = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let a_out = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let b_in = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xBBBB_BBBB)?;
        let b_out = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xBBBB_BBBB)?;

        let audio = decode_dialog_audio(&[&a_in, &a_out, &b_in, &b_out])?;
        assert_eq!(
            audio.channels, 2,
            "two distinct sources are present, so the export is stereo"
        );

        export_dialog_to_wav(&[&a_in, &a_out, &b_in, &b_out], &path)?;
        let data = std::fs::read(&path)?;
        // Find the `data` chunk. Reading from a fixed offset 44 is what the
        // first draft did, and these files carry a provenance note chunk
        // before the samples -- so it compared NOTE TEXT, found it varied, and
        // passed while the audio on both channels was identical.
        let tag = data
            .windows(4)
            .position(|w| w == b"data")
            .ok_or("a WAV has a data chunk")?;
        // The chunk's DECLARED size, not everything to EOF. These files carry
        // the provenance note in a chunk AFTER the samples, so a slice running
        // to the end compares note text as if it were audio -- it varies, the
        // test passes, and the two identical channels it exists to catch go
        // straight through.
        let size = u32::from_le_bytes(data[tag + 4..tag + 8].try_into()?) as usize;
        let start = tag + 8;
        let body = &data[start..start + size];
        let mut differs = false;
        for i in (0..body.len().saturating_sub(3)).step_by(4) {
            let l = i16::from_le_bytes([body[i], body[i + 1]]);
            let r = i16::from_le_bytes([body[i + 2], body[i + 3]]);
            if l != r {
                differs = true;
                break;
            }
        }
        assert!(
            differs,
            "the two channels are identical, so the same leg was selected \
             twice and the far end is absent from the recording"
        );
        Ok(())
    }

    /// A codec drop is named even when the COUNT shows nothing missing.
    ///
    /// The clause used to fire only when `total > written`, so an undecodable
    /// stream that shared a source with a carried one vanished in silence --
    /// the file then read as complete. `omitted_clause(1, 1, &["GSM"])` is the
    /// shape: nothing missing by the numbers, a whole codec dropped in fact.
    #[test]
    fn a_codec_drop_is_named_even_when_the_count_balances() -> Result<(), TestError> {
        let clause = omitted_clause(1, 1, &["GSM"]);
        assert!(
            !clause.is_empty(),
            "a stream dropped for its codec must be named even when the counts \
             agree, or the file reads as complete"
        );
        assert!(
            clause.contains("GSM"),
            "and the codec must be named: {clause}"
        );
        Ok(())
    }

    /// A clean export still says nothing.
    ///
    /// The other half: loosening the guard above must not make every complete
    /// file carry a PARTIAL caveat, which would train a reader to ignore it.
    #[test]
    fn a_complete_export_carries_no_partial_clause() -> Result<(), TestError> {
        assert!(
            omitted_clause(2, 2, &[]).is_empty(),
            "nothing was dropped and no codec was skipped, so there is no caveat"
        );
        Ok(())
    }

    /// The omitted count is of SOURCES, not of stream records.
    ///
    /// A relay hands the exporter two records per source. Counting records
    /// would tell an operator that four streams existed and two were dropped,
    /// when two sources existed and both were carried -- a caveat describing
    /// loss that did not happen is as misleading as one that hides loss.
    #[test]
    fn the_omitted_count_is_of_sources_not_records() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("relay.wav");

        let a_in = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let a_out = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let b_in = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xBBBB_BBBB)?;
        let b_out = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xBBBB_BBBB)?;

        let summary = export_dialog_to_wav(&[&a_in, &a_out, &b_in, &b_out], &path)
            .map_err(|e| format!("export: {e:?}"))?;
        assert!(
            !summary.contains(" of 4"),
            "both sources were carried, so nothing was omitted; a count over \
             the four RECORDS invents a loss that did not happen:\n{summary}"
        );
        Ok(())
    }

    /// Selection keeps the FIRST record of each source, in arrival order.
    ///
    /// Which record of a source is kept is not arbitrary at a relay: the two
    /// differ in their endpoints, and a caller reading `src`/`dst` off the
    /// carried stream to say where the audio came from gets a different answer
    /// depending on the choice. First-seen is the one the rest of the pipeline
    /// already assumes.
    #[test]
    fn selection_keeps_the_first_record_of_each_source() -> Result<(), TestError> {
        let first = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let second = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xAAAA_AAAA)?;
        let other = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x55; 160])], 0xBBBB_BBBB)?;

        let audio = decode_dialog_audio(&[&first, &second, &other])
            .map_err(|e| format!("decode: {e:?}"))?;
        assert_eq!(
            audio.channels, 2,
            "two sources are present regardless of how many records each has"
        );
        // The duplicate of source A must not displace source B.
        assert!(
            audio.summary_head.contains("stereo"),
            "the second source must reach a channel: {}",
            audio.summary_head
        );
        Ok(())
    }

    /// A source whose records are interleaved with another's still yields two
    /// channels.
    ///
    /// Relay ordering is not grouped: records arrive as they are seen, so a
    /// selector that stopped at the first duplicate, or that assumed records of
    /// one source are adjacent, would drop the second party on real traffic
    /// while passing every grouped fixture.
    #[test]
    fn interleaved_records_still_find_both_sources() -> Result<(), TestError> {
        let a1 = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let b1 = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xBBBB_BBBB)?;
        let a2 = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0xAAAA_AAAA)?;
        let b2 = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0xBBBB_BBBB)?;

        for order in [
            [&a1, &b1, &a2, &b2],
            [&b1, &a1, &b2, &a2],
            [&a1, &a2, &b1, &b2],
        ] {
            let audio = decode_dialog_audio(&order).map_err(|e| format!("decode: {e:?}"))?;
            assert_eq!(
                audio.channels, 2,
                "two sources are present in every ordering; this one lost one"
            );
        }
        Ok(())
    }

    /// Three sources still carry two and report the third.
    ///
    /// Guards the interaction between deduplication and the two-channel limit:
    /// deduplicating first and then truncating are different from truncating
    /// first, and only the first order can see a third source at all.
    #[test]
    fn three_sources_carry_two_and_name_the_third() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("three_src.wav");

        let a = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0x0101_0101)?;
        let a_dup = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0xD5; 160])], 0x0101_0101)?;
        let b = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x2A; 160])], 0x0202_0202)?;
        let c = make_stream_ssrc(Some("PCMA"), vec![(0, vec![0x55; 160])], 0x0303_0303)?;

        let summary = export_dialog_to_wav(&[&a, &a_dup, &b, &c], &path)
            .map_err(|e| format!("export: {e:?}"))?;
        assert!(
            summary.contains("1 of 3"),
            "three sources, two channels: exactly one source is omitted and \
             the summary must say so:\n{summary}"
        );
        Ok(())
    }

    /// Unsupported-codec streams are filtered out before stereo/mono selection.
    #[test]
    fn export_dialog_filters_unsupported_codecs() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("mixed.wav");

        let g711 = make_stream(Some("PCMU"), vec![(0, vec![0xFF; 160])])?;
        let gsm = make_stream(Some("GSM"), vec![(0, vec![0; 10])])?;
        let result = export_dialog_to_wav(&[&g711, &gsm], &path)?;

        // Should fall back to mono since only one decodable stream
        assert!(result.contains("mu-law"));
        Ok(())
    }

    /// A G.722 stream (static payload type 9) is retained and decodes to
    /// 16 kHz: the samples of the Recommendation, not of the 8 kHz RTP clock
    /// RFC 3551 gives the payload type. Its decode equals FFmpeg's sample for
    /// sample (see `tests/fixtures/g722/README.md`).
    #[test]
    fn a_g722_stream_decodes_to_16_khz() -> Result<(), TestError> {
        for name in ["G722", "g722"] {
            assert!(is_capturable_audio_codec(Some(name)), "{name}");
        }
        let encoded = std::fs::read("tests/fixtures/g722/tone440.g722")?;
        let expected: Vec<i16> = std::fs::read("tests/fixtures/g722/tone440.s16le")?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b))
            .collect();
        // 20 ms frames: 160 bytes of G.722, 160 ticks of its 8 kHz RTP clock.
        let frames: Vec<(u32, Vec<u8>)> = encoded
            .chunks(160)
            .enumerate()
            .map(|(i, f)| (u32::try_from(i).unwrap_or(0) * 160, f.to_vec()))
            .collect();
        let mut stream = make_stream(Some("G722"), frames)?;
        stream.clock_rate = 8000;
        let DecodedStream {
            pcm,
            rate,
            label,
            failures,
            ..
        } = decode_stream_pcm(&stream, true)?;
        assert_eq!(rate, 16000);
        assert_eq!(failures, 0);
        assert!(label.contains("G.722"), "{label}");
        assert_eq!(pcm, expected);
        let audio = decode_dialog_audio(&[&stream])?;
        assert!(
            (audio.duration_secs - 1.0).abs() < 0.001,
            "{}",
            audio.duration_secs
        );
        Ok(())
    }

    /// `is_exportable_codec` must accept Opus case-insensitively, consistent
    /// with `is_opus_codec` and the decoder — a mixed-case `OpUs` label decodes
    /// but the exact-case filter used to drop it from export.
    #[test]
    fn is_exportable_codec_accepts_mixed_case_opus() -> Result<(), TestError> {
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
        assert!(!is_exportable_codec(Some("GSM")));
        assert!(!is_exportable_codec(None));
        Ok(())
    }

    /// A mixed-case `OpUs` stream is not filtered out of dialog export: paired
    /// with a G.711 stream it participates in stereo selection rather than
    /// being silently dropped to a mono fallback.
    #[test]
    fn export_dialog_keeps_mixed_case_opus_stream() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("mixed_case_opus.wav");

        // Opus payloads here are undecodable garbage (skipped frame-by-frame),
        // but the point is codec-name filtering, not audio content: the OpUs
        // stream must survive is_exportable_codec so stereo is selected.
        let g711 = make_stream_ssrc(Some("PCMU"), vec![(0, vec![0xFF; 160])], 0x0D0D_0D0D)?;
        let opus = make_stream_ssrc(Some("OpUs"), vec![(0, vec![0xFF; 8])], 0x0E0E_0E0E)?;
        let result = export_dialog_to_wav(&[&g711, &opus], &path)?;

        assert!(
            result.contains("stereo"),
            "mixed-case Opus must count as exportable (stereo), got: {result}"
        );
        assert!(path.exists());
        Ok(())
    }

    /// Exporting an empty stream list returns an error.
    #[test]
    fn export_dialog_empty_streams_errors() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("empty.wav");

        let result = export_dialog_to_wav(&[], &path);
        assert!(result.is_err());
        Ok(())
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
    fn export_dialog_unretained_payload_does_not_deny_the_media() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("unretained.wav");

        // Two PCMU streams, thousands of packets measured, nothing retained.
        let mut a = make_stream(Some("PCMU"), vec![])?;
        a.packet_count = 1200;
        let mut b = make_stream(Some("PCMU"), vec![])?;
        b.packet_count = 1198;

        let err = export_dialog_to_wav(&[&a, &b], &path)
            .err()
            .ok_or("nothing to decode, so the export must fail")?;
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
        Ok(())
    }

    /// A call carrying only codecs sipnab cannot decode names them, rather
    /// than reporting the same "no captured data" as an unretained buffer —
    /// the two are different facts and lead to different next steps.
    #[test]
    fn export_dialog_undecodable_codecs_are_named() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("gsm.wav");

        let mut s = make_stream(Some("GSM"), vec![(0, vec![0; 10])])?;
        s.packet_count = 500;

        let err = export_dialog_to_wav(&[&s], &path)
            .err()
            .ok_or("GSM is not decodable")?;
        let msg = err.to_string();
        assert!(
            msg.contains("GSM"),
            "the error must name the codec found: {msg}"
        );
        assert!(
            msg.contains("PCMU"),
            "the error must name what IS supported: {msg}"
        );
        Ok(())
    }

    /// The single-stream export says the same thing: packets measured, payload
    /// not retained.
    #[test]
    fn export_stream_unretained_payload_does_not_deny_the_media() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("one.wav");

        let mut s = make_stream(Some("PCMA"), vec![])?;
        s.packet_count = 4242;

        let err = export_stream_to_wav(&s, &path)
            .err()
            .ok_or("nothing to decode")?;
        let msg = err.to_string();
        assert!(
            msg.contains("4242") && msg.contains("PCMA"),
            "the error must say what was observed: {msg}"
        );
        assert!(
            msg.contains("retain") || msg.contains("retention"),
            "the error must say the payload was not retained: {msg}"
        );
        Ok(())
    }

    /// PCMU frames of one byte value each, 160 bytes per 20 ms, on a stream
    /// that lasted `wall_ms` of capture time.
    fn pcmu_at(stamps: &[(u32, u8)], wall_ms: i64) -> Result<RtpStream, TestError> {
        let frames = stamps.iter().map(|&(ts, b)| (ts, vec![b; 160])).collect();
        let mut s = make_stream(Some("PCMU"), frames)?;
        s.clock_rate = 8000;
        s.last_seen = s.first_seen + chrono::Duration::milliseconds(wall_ms);
        Ok(s)
    }

    /// The sample a whole frame of `byte` decodes to.
    fn ulaw(byte: u8) -> i16 {
        decode_frame(G711Codec::Ulaw, &[byte])[0]
    }

    /// A lost packet is silence of its own length in the export, so the audio
    /// after it plays at the time it was spoken rather than 20 ms early.
    #[test]
    fn a_lost_packet_is_silence_of_its_length_in_the_export() -> Result<(), TestError> {
        let s = pcmu_at(&[(0, 0x00), (160, 0x00), (480, 0x00)], 60)?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(d.pcm.len(), 640, "four 20 ms slots, one of them silence");
        assert!(d.pcm[..320].iter().all(|&x| x == ulaw(0x00)));
        assert!(d.pcm[320..480].iter().all(|&x| x == 0), "the lost packet");
        assert!(d.pcm[480..].iter().all(|&x| x == ulaw(0x00)));
        assert_eq!((d.timeline.gaps, d.timeline.filled_ticks), (1, 160));
        let audio = decode_dialog_audio(&[&s])?;
        assert!(
            (audio.duration_secs - 0.08).abs() < 1e-9,
            "{}",
            audio.duration_secs
        );
        assert!(audio.partial.contains("20 ms"), "{}", audio.partial);
        Ok(())
    }

    /// Time a codec's own decoder filled (G.729 concealment or comfort noise)
    /// is named as that, not as silence: the file holds sound there.
    #[test]
    fn codec_filled_time_is_named_as_the_codec_s_output() {
        let totals = TimelineTotals {
            codec_gaps: 2,
            codec_ms: 40,
            codec_label: Some("G.729"),
            ..TimelineTotals::default()
        };
        let clause = timeline_clause(&totals);
        assert!(clause.contains("40 ms in 2 gaps"), "{clause}");
        assert!(
            clause.contains("the G.729 decoder's loss concealment or comfort noise"),
            "{clause}"
        );
        assert!(!clause.contains("silence"), "{clause}");
        let both = TimelineTotals {
            gaps: 1,
            filled_ms: 20,
            ..totals
        };
        let clause = timeline_clause(&both);
        assert!(
            clause.contains("20 ms in 1 gap") && clause.contains("is silence"),
            "{clause}"
        );
        assert!(clause.contains("40 ms in 2 gaps"), "{clause}");
    }

    /// The single-stream export says what it filled, in the summary and in
    /// the file's own note.
    #[test]
    fn the_stream_export_names_the_filled_time() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("gap.wav");
        let s = pcmu_at(&[(0, 0x00), (480, 0x00)], 60)?;
        let summary = export_stream_to_wav(&s, &path)?;
        assert!(summary.contains("Exported 0.1s"), "{summary}");
        assert!(summary.contains("40 ms in 1 gap"), "{summary}");
        let bytes = std::fs::read(&path)?;
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("40 ms in 1 gap"),
            "the note in the file says it too"
        );
        Ok(())
    }

    /// Reordered packets play in timestamp order and a duplicate plays once.
    #[test]
    fn reordered_and_duplicate_packets_play_once_in_order() -> Result<(), TestError> {
        let s = pcmu_at(&[(0, 0x00), (320, 0x20), (160, 0x10), (160, 0x30)], 60)?;
        let d = decode_stream_pcm(&s, true)?;
        let firsts: Vec<i16> = d.pcm.chunks(160).map(|c| c[0]).collect();
        assert_eq!(firsts, vec![ulaw(0x00), ulaw(0x10), ulaw(0x20)]);
        assert_eq!(d.timeline.duplicates, 1);
        assert_eq!(d.timeline.gaps, 0);
        let audio = decode_dialog_audio(&[&s])?;
        assert!(audio.partial.contains("1 duplicate"), "{}", audio.partial);
        Ok(())
    }

    /// A timestamp jump longer than the stream lasted is not filled: one
    /// packet must not be able to make the export allocate hours of silence.
    #[test]
    fn a_timestamp_jump_beyond_the_stream_is_joined_not_filled() -> Result<(), TestError> {
        let s = pcmu_at(&[(0, 0x00), (0x4000_0000, 0x00)], 40)?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(d.pcm.len(), 320);
        assert_eq!(d.timeline.jumps, 1);
        let audio = decode_dialog_audio(&[&s])?;
        assert!(
            audio.partial.contains("timestamp jump"),
            "{}",
            audio.partial
        );
        Ok(())
    }

    /// The amplitude measurement reads what the sender's samples did, so a
    /// lost packet must not become dead air there.
    #[test]
    fn the_amplitude_samples_close_gaps_instead_of_filling_them() -> Result<(), TestError> {
        let s = pcmu_at(&[(0, 0x00), (160, 0x00), (480, 0x00)], 60)?;
        let (pcm, _) = stream_pcm(&s).ok_or("decoded")?;
        assert_eq!(pcm.len(), 480);
        assert!(pcm.iter().all(|&x| x == ulaw(0x00)));
        Ok(())
    }

    /// G.722 runs an 8 kHz RTP clock under 16 kHz samples, so a lost 20 ms
    /// packet is 160 ticks and 320 samples of silence.
    #[test]
    fn a_lost_g722_packet_fills_at_the_decoder_rate() -> Result<(), TestError> {
        let encoded = std::fs::read("tests/fixtures/g722/tone440.g722")?;
        let frames: Vec<(u32, Vec<u8>)> = encoded
            .chunks(160)
            .take(3)
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(i, f)| (u32::try_from(i).unwrap_or(0) * 160, f.to_vec()))
            .collect();
        let mut s = make_stream(Some("G722"), frames)?;
        s.clock_rate = 8000;
        s.last_seen = s.first_seen + chrono::Duration::milliseconds(60);
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(d.pcm.len(), 960);
        assert!(d.pcm[320..640].iter().all(|&x| x == 0));
        Ok(())
    }

    /// A PCMU stream from `ssrc` whose frames of `byte` start `start_ms` into
    /// the capture and run back to back for `frames` frames.
    fn party(ssrc: u32, byte: u8, start_ms: i64, frames: u32) -> Result<RtpStream, TestError> {
        let payloads = (0..frames).map(|i| (i * 160, vec![byte; 160])).collect();
        let mut s = make_stream_ssrc(Some("PCMU"), payloads, ssrc)?;
        s.clock_rate = 8000;
        let t0 = s.first_seen;
        s.first_seen = t0 + chrono::Duration::milliseconds(start_ms);
        s.last_seen =
            s.first_seen + chrono::Duration::milliseconds(i64::from(frames.saturating_sub(1)) * 20);
        Ok(s)
    }

    /// One channel of an interleaved stereo buffer.
    fn channel(samples: &[i16], index: usize) -> Vec<i16> {
        samples.iter().skip(index).step_by(2).copied().collect()
    }

    /// The samples of a WAV the export wrote, past its header chunks.
    fn wav_samples(audio: &DialogAudio) -> Result<Vec<i16>, TestError> {
        let wav = &audio.wav;
        let at = wav
            .windows(4)
            .position(|w| w == b"data")
            .ok_or("a data chunk")?;
        let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into()?) as usize;
        Ok(wav[at + 8..at + 8 + len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b))
            .collect())
    }

    /// A party who starts talking 100 ms after the other starts 100 ms later
    /// in the stereo file, instead of at its first sample.
    #[test]
    fn a_party_who_starts_later_starts_later_in_the_stereo_file() -> Result<(), TestError> {
        let a = party(1, 0x00, 0, 6)?;
        let b = party(2, 0x10, 100, 4)?;
        let audio = decode_dialog_audio(&[&a, &b])?;
        assert_eq!(audio.channels, 2);
        let samples = wav_samples(&audio)?;
        let (left, right) = (channel(&samples, 0), channel(&samples, 1));
        assert_eq!(right.len(), 800 + 640, "100 ms of lead-in, then 4 frames");
        assert!(
            right[..800].iter().all(|&x| x == 0),
            "silence before B starts"
        );
        assert_eq!(right[800], ulaw(0x10));
        assert!(
            left[..960].iter().all(|&x| x == ulaw(0x00)),
            "A is not moved"
        );
        Ok(())
    }

    /// The lead-in follows the party, not the channel order.
    #[test]
    fn the_lead_in_goes_to_whichever_channel_starts_later() -> Result<(), TestError> {
        let a = party(1, 0x00, 0, 6)?;
        let b = party(2, 0x10, 100, 4)?;
        let audio = decode_dialog_audio(&[&b, &a])?;
        let samples = wav_samples(&audio)?;
        let first = channel(&samples, 0);
        assert!(first[..800].iter().all(|&x| x == 0));
        assert_eq!(first[800], ulaw(0x10));
        assert_eq!(channel(&samples, 1)[0], ulaw(0x00));
        Ok(())
    }

    /// A stream's start is never placed before its first packet arrived: an
    /// RTP timestamp span of a day must not become a day of lead-in silence.
    #[test]
    fn a_hostile_timestamp_span_cannot_move_a_start_before_the_first_packet()
    -> Result<(), TestError> {
        let a = party(1, 0x00, 0, 6)?;
        let mut b = party(2, 0x10, 100, 2)?;
        b.payload_buffer[1].timestamp = 0x4000_0000;
        let audio = decode_dialog_audio(&[&a, &b])?;
        let samples = wav_samples(&audio)?;
        let right = channel(&samples, 1);
        assert!(right.len() < 2_000, "{} samples per channel", right.len());
        assert!(right[..800].iter().all(|&x| x == 0));
        assert_eq!(right[800], ulaw(0x10));
        Ok(())
    }
}

/// G.729 through [`FrameDecoder`]: the decoder, its absence, and its
/// concealment of lost packets.
#[cfg(test)]
mod g729_tests {
    use super::*;

    /// A build without the feature names the reason it does not decode G.729.
    #[cfg(not(feature = "g729"))]
    #[test]
    fn without_the_feature_g729_names_the_build() {
        let err = FrameDecoder::new(Some("G729")).err().map(|e| e.to_string());
        assert_eq!(err.as_deref(), Some(crate::rtp::g729_tables::NOT_BUILT));
    }

    #[cfg(feature = "g729")]
    mod with_the_feature {
        use super::*;
        use crate::rtp::g729_tables::{NOT_INSTALLED, test_support};
        use crate::rtp::stream::{RtpStream, StreamKey};

        type TestError = Box<dyn std::error::Error>;

        /// Ten octets that decode as one active frame.
        const VOICE: [u8; 10] = [0x7a, 0x13, 0xc4, 0x58, 0x2e, 0x91, 0x6b, 0x0f, 0xd2, 0x37];
        /// A second, different active frame.
        const VOICE2: [u8; 10] = [0x35, 0xe8, 0x0b, 0x9c, 0x71, 0x4a, 0xd6, 0x23, 0x88, 0x5f];
        /// Two octets that decode as an Annex B SID frame.
        const SID: [u8; 2] = [0x4c, 0x90];

        /// A G.729 stream on the 8 kHz clock holding `payloads`, lasting
        /// `wall_ms` of capture time.
        fn g729_stream(payloads: Vec<RetainedFrame>, wall_ms: i64) -> Result<RtpStream, TestError> {
            let key = StreamKey {
                ssrc: 0x0729_0729,
                src: "10.0.0.1:20000".parse()?,
                dst: "10.0.0.2:30000".parse()?,
                session: 0,
            };
            let hdr = crate::rtp::parser::RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 18,
                sequence: 1,
                timestamp: 0,
                ssrc: 0x0729_0729,
                payload_offset: 12,
            };
            let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("a time")?;
            let mut s = RtpStream::new(key, &hdr, ts);
            s.codec = Some("G729".into());
            s.clock_rate = 8000;
            s.last_seen = s.first_seen + chrono::Duration::milliseconds(wall_ms);
            s.payload_buffer = payloads.into();
            Ok(s)
        }

        /// What the crate's own decoder produces for `frames`, from a fresh
        /// state.
        fn reference(tables: &g729::Tables, frames: &[g729::Frame<'_>]) -> Vec<i16> {
            let mut d = g729::Decoder::new(tables);
            let mut out = Vec::new();
            let mut pcm = [0i16; g729::FRAME_SAMPLES];
            for f in frames {
                d.decode(*f, &mut pcm);
                out.extend_from_slice(&pcm);
            }
            out
        }

        /// Without the tables, the decoder is refused with the reason and the
        /// command, so the stream takes the "omitted, no decoder" path.
        #[test]
        fn without_tables_the_refusal_names_the_install_command() {
            test_support::use_no_tables();
            for name in ["G729", "g729"] {
                let err = FrameDecoder::new(Some(name)).err().map(|e| e.to_string());
                assert_eq!(err.as_deref(), Some(NOT_INSTALLED), "{name}");
            }
        }

        /// With the tables, G.729 decodes at 8 kHz under its own label, 80
        /// samples per 10-octet frame and per trailing SID frame, and a
        /// payload of any other length is refused.
        #[test]
        fn g729_decodes_10n_and_10n_plus_2_octets() -> Result<(), TestError> {
            test_support::use_tables()?;
            let mut d = FrameDecoder::new(Some("g729"))?;
            assert_eq!(d.rate(8000), 8000);
            assert_eq!(d.label(), "G.729");
            assert_eq!(d.decode(&VOICE)?.len(), 80);
            assert_eq!(d.decode(&[VOICE, VOICE2].concat())?.len(), 160);
            assert_eq!(d.decode(&[&VOICE[..], &SID[..]].concat())?.len(), 160);
            assert!(d.decode(&VOICE[..7]).is_err());
            Ok(())
        }

        /// Fill for G.729 is the decoder's own output for erased frames:
        /// concealment after active speech, comfort noise after a SID frame.
        /// Not zeros.
        #[test]
        fn g729_fill_is_the_decoder_s_concealment() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let mut d = FrameDecoder::new(Some("G729"))?;
            d.decode(&[VOICE, VOICE2, VOICE].concat())?;
            // One packet of three frames missing, capped at the gap's two.
            let fill = d.fill(160, Some(1));
            let expected = reference(
                tables,
                &[
                    g729::Frame::Voice(&VOICE),
                    g729::Frame::Voice(&VOICE2),
                    g729::Frame::Voice(&VOICE),
                    g729::Frame::Erased,
                    g729::Frame::Erased,
                ],
            );
            assert_eq!(fill, expected[240..]);
            assert!(fill.iter().any(|&x| x != 0), "concealment is not silence");

            Ok(())
        }

        /// Under discontinuous transmission (Annex B) a sender stops after a
        /// SID frame, so the RTP gap that follows is untransmitted frames and
        /// the decoder's comfort noise carries on (clause B.4.5). Filled as
        /// erased frames, the decoder ran its lost-SID path instead, and the
        /// output left the reference decoder's from there.
        #[test]
        fn a_g729_gap_after_a_sid_frame_is_untransmitted() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            const GAP: usize = 200;
            let mut d = FrameDecoder::new(Some("G729"))?;
            d.decode(&[&VOICE[..], &SID[..]].concat())?;
            let fill = d.fill(GAP * 80, Some(0));
            let lead = [g729::Frame::Voice(&VOICE), g729::Frame::Sid(&SID)];
            let mut untransmitted = lead.to_vec();
            untransmitted.extend([g729::Frame::NoTx; GAP]);
            assert_eq!(fill, reference(tables, &untransmitted)[160..]);
            Ok(())
        }

        /// The rule itself, which the decoder's output alone cannot show
        /// while an erased and an untransmitted frame decode alike after a
        /// SID: speech then a gap is loss, a SID then a gap is untransmitted.
        #[test]
        fn the_g729_gap_rule_follows_the_last_frame_type() {
            use super::super::{G729Last, g729_gap_frame, g729_last_after};
            assert_eq!(g729_gap_frame(G729Last::Active), g729::Frame::Erased);
            assert_eq!(g729_gap_frame(G729Last::Inactive), g729::Frame::NoTx);
            // 10n octets end in speech, 10n + 2 in a SID, a bare SID is 2.
            assert_eq!(g729_last_after(10, G729Last::Inactive), G729Last::Active);
            assert_eq!(g729_last_after(20, G729Last::Inactive), G729Last::Active);
            assert_eq!(g729_last_after(12, G729Last::Active), G729Last::Inactive);
            assert_eq!(g729_last_after(2, G729Last::Active), G729Last::Inactive);
            // A payload that is neither keeps what the stream was in.
            assert_eq!(g729_last_after(0, G729Last::Inactive), G729Last::Inactive);
            assert_eq!(g729_last_after(7, G729Last::Active), G729Last::Active);
        }

        /// A gap after a voice frame whose packets are all missing from the
        /// sequence numbers is loss: erased frames for its whole length.
        #[test]
        fn a_g729_gap_of_missing_packets_after_a_voice_frame_is_erased() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let mut d = FrameDecoder::new(Some("G729"))?;
            d.decode(&VOICE)?;
            let fill = d.fill(3 * 80, Some(3));
            let mut frames = vec![g729::Frame::Voice(&VOICE)];
            frames.extend([g729::Frame::Erased; 3]);
            assert_eq!(fill, reference(tables, &frames)[80..]);
            Ok(())
        }

        /// The rule follows the last frame received, through every payload:
        /// voice after the SID makes the next gap loss again.
        #[test]
        fn voice_after_a_sid_makes_the_next_g729_gap_loss_again() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let mut d = FrameDecoder::new(Some("G729"))?;
            d.decode(&[&VOICE[..], &SID[..]].concat())?;
            d.fill(80, Some(0));
            d.decode(&VOICE2)?;
            let fill = d.fill(80, Some(1));
            let frames = [
                g729::Frame::Voice(&VOICE),
                g729::Frame::Sid(&SID),
                g729::Frame::NoTx,
                g729::Frame::Voice(&VOICE2),
                g729::Frame::Erased,
            ];
            assert_eq!(fill, reference(tables, &frames)[320..]);
            Ok(())
        }

        /// A gap that is not a whole number of frames is concealed for its
        /// whole frames and the rest is zeros, so the length is exact.
        #[test]
        fn g729_fill_keeps_the_exact_length() -> Result<(), TestError> {
            test_support::use_tables()?;
            let mut d = FrameDecoder::new(Some("G729"))?;
            d.decode(&VOICE)?;
            let fill = d.fill(100, Some(1));
            assert_eq!(fill.len(), 100);
            assert!(fill[80..].iter().all(|&x| x == 0));
            Ok(())
        }

        /// G.711 fills with zeros, as before.
        #[test]
        fn g711_fill_is_zeros() -> Result<(), TestError> {
            let mut d = FrameDecoder::new(Some("PCMU"))?;
            assert_eq!(d.fill(160, Some(2)), vec![0i16; 160]);
            Ok(())
        }

        /// A lost packet in a G.729 stream: the export is the right length
        /// and the lost packet's time holds the decoder's concealment.
        #[test]
        fn a_lost_g729_packet_is_concealed_by_the_decoder() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let s = g729_stream(
                vec![
                    RetainedFrame::new(0, 0, [VOICE, VOICE2].concat()),
                    RetainedFrame::new(160, 1, [VOICE2, VOICE].concat()),
                    // Sequence 2, 320..480, lost.
                    RetainedFrame::new(480, 3, [VOICE, VOICE2].concat()),
                ],
                80,
            )?;
            let d = decode_stream_pcm(&s, true)?;
            assert_eq!(d.pcm.len(), 640);
            assert_eq!((d.timeline.gaps, d.timeline.filled_ticks), (1, 160));
            let expected = reference(
                tables,
                &[
                    g729::Frame::Voice(&VOICE),
                    g729::Frame::Voice(&VOICE2),
                    g729::Frame::Voice(&VOICE2),
                    g729::Frame::Voice(&VOICE),
                    g729::Frame::Erased,
                    g729::Frame::Erased,
                    g729::Frame::Voice(&VOICE),
                    g729::Frame::Voice(&VOICE2),
                ],
            );
            assert_eq!(d.pcm, expected);
            assert!(d.pcm[320..480].iter().any(|&x| x != 0));
            Ok(())
        }

        /// A payload of a length G.729 cannot carry is one decode failure,
        /// and its time is concealed in front of the next frame.
        #[test]
        fn a_bad_length_is_one_failure_and_its_time_is_concealed() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let s = g729_stream(
                vec![
                    RetainedFrame::new(0, 0, VOICE.to_vec()),
                    RetainedFrame::new(80, 1, VOICE[..7].to_vec()),
                    RetainedFrame::new(160, 2, VOICE2.to_vec()),
                ],
                30,
            )?;
            let d = decode_stream_pcm(&s, true)?;
            assert_eq!(d.failures, 1);
            assert_eq!(d.pcm.len(), 240);
            let expected = reference(
                tables,
                &[
                    g729::Frame::Voice(&VOICE),
                    g729::Frame::Erased,
                    g729::Frame::Voice(&VOICE2),
                ],
            );
            assert_eq!(d.pcm, expected);
            Ok(())
        }

        /// The first sample where `got` and `want` differ, or where one ends
        /// before the other; `None` when they are equal.
        fn first_difference(got: &[i16], want: &[i16]) -> Option<usize> {
            got.iter()
                .zip(want)
                .position(|(a, b)| a != b)
                .or_else(|| (got.len() != want.len()).then(|| got.len().min(want.len())))
        }

        /// The frames a reference decode is given for `payload`: its speech
        /// frames, then its SID frame if it ends in one.
        fn frames_of(payload: &[u8]) -> Vec<g729::Frame<'_>> {
            let (speech, sid) = payload.split_at(payload.len() / 10 * 10);
            let mut frames: Vec<g729::Frame<'_>> = speech
                .as_chunks::<10>()
                .0
                .iter()
                .map(g729::Frame::Voice)
                .collect();
            if let Ok(sid) = <&[u8; 2]>::try_from(sid) {
                frames.push(g729::Frame::Sid(sid));
            }
            frames
        }

        /// A stream of two-frame packets that loses the SID frame after its
        /// speech, then pauses under discontinuous transmission, then talks
        /// again: five speech packets (sequence `first` to `first + 4`,
        /// timestamps 0 to 640), the packet `first + 5` lost, and three
        /// speech packets from timestamp 4000 on, with consecutive sequence
        /// numbers through the pause. The gap is 40 frames.
        fn lost_sid_then_a_pause(first: u16) -> Vec<RetainedFrame> {
            let speech = |n: u16| {
                if n.is_multiple_of(2) {
                    [VOICE, VOICE2].concat()
                } else {
                    [VOICE2, VOICE].concat()
                }
            };
            let mut packets: Vec<RetainedFrame> = (0..5u16)
                .map(|n| RetainedFrame::new(u32::from(n) * 160, first.wrapping_add(n), speech(n)))
                .collect();
            packets.extend((0..3u16).map(|n| {
                RetainedFrame::new(
                    4000 + u32::from(n) * 160,
                    first.wrapping_add(6 + n),
                    speech(n),
                )
            }));
            packets
        }

        /// The true frames of [`lost_sid_then_a_pause`]: the speech, the lost
        /// SID packet's one frame erased, 39 untransmitted frames, the speech.
        fn lost_sid_then_a_pause_reference(
            tables: &g729::Tables,
            packets: &[RetainedFrame],
        ) -> Vec<i16> {
            let mut frames: Vec<g729::Frame<'_>> = Vec::new();
            for (i, p) in packets.iter().enumerate() {
                if i == 5 {
                    frames.extend([g729::Frame::Erased; 1]);
                    frames.extend([g729::Frame::NoTx; 39]);
                }
                frames.extend(frames_of(&p.payload));
            }
            reference(tables, &frames)
        }

        /// A real G.729 call with discontinuous transmission: speech, the SID
        /// frame after it lost (one missing sequence number), a pause
        /// (timestamps jump, sequence numbers consecutive), speech. The
        /// export equals the decoder fed the true frame types: the lost
        /// packet's frames erased, the pause untransmitted. Filled from the
        /// last frame type alone, the whole pause was concealed as speech.
        #[test]
        fn a_lost_sid_before_a_pause_decodes_as_the_true_frames() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let packets = lost_sid_then_a_pause(0);
            let s = g729_stream(packets.clone(), 600)?;
            let d = decode_stream_pcm(&s, true)?;
            let expected = lost_sid_then_a_pause_reference(tables, &packets);
            assert_eq!(d.pcm.len(), expected.len());
            assert_eq!(first_difference(&d.pcm, &expected), None);
            Ok(())
        }

        /// A speech packet and the SID after it lost before a pause: two
        /// sequence numbers missing. The true frames are the speech packet's
        /// two frames and the SID's one frame erased, then the pause
        /// untransmitted: three erased frames, not four.
        #[test]
        fn a_lost_speech_packet_and_sid_before_a_pause_erase_three_frames() -> Result<(), TestError>
        {
            let tables = test_support::use_tables()?;
            let mut packets = lost_sid_then_a_pause(0);
            for p in packets.iter_mut().skip(5) {
                p.sequence = p.sequence.wrapping_add(1);
            }
            let s = g729_stream(packets.clone(), 600)?;
            let d = decode_stream_pcm(&s, true)?;
            let mut frames: Vec<g729::Frame<'_>> = Vec::new();
            for (i, p) in packets.iter().enumerate() {
                if i == 5 {
                    frames.extend([g729::Frame::Erased; 3]);
                    frames.extend([g729::Frame::NoTx; 37]);
                }
                frames.extend(frames_of(&p.payload));
            }
            let expected = reference(tables, &frames);
            assert_eq!(d.pcm.len(), expected.len());
            assert_eq!(first_difference(&d.pcm, &expected), None);
            Ok(())
        }

        /// A lost packet is the size of the stream's usual speech packet, not
        /// of the one just before it: speech that resumes on an odd frame
        /// arrives as a one-frame packet, and the two-frame packet lost after
        /// it is two lost frames, with no pause between.
        #[test]
        fn a_lost_packet_after_an_odd_speech_packet_is_the_usual_size() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let two = |n: u32| {
                RetainedFrame::new(
                    n * 160,
                    u16::try_from(n).unwrap_or(0),
                    [VOICE, VOICE2].concat(),
                )
            };
            let mut packets: Vec<RetainedFrame> = (0..4).map(two).collect();
            // One frame at 640, then the two-frame packet at 720 (sequence 5)
            // lost, then speech again at 880.
            packets.push(RetainedFrame::new(640, 4, VOICE.to_vec()));
            packets.push(RetainedFrame::new(880, 6, [VOICE2, VOICE].concat()));
            let s = g729_stream(packets.clone(), 120)?;
            let d = decode_stream_pcm(&s, true)?;
            let mut frames: Vec<g729::Frame<'_>> = Vec::new();
            for (i, p) in packets.iter().enumerate() {
                if i == 5 {
                    frames.extend([g729::Frame::Erased; 2]);
                }
                frames.extend(frames_of(&p.payload));
            }
            let expected = reference(tables, &frames);
            assert_eq!(d.pcm.len(), expected.len());
            assert_eq!(first_difference(&d.pcm, &expected), None);
            Ok(())
        }

        /// The same call with the lost packet's sequence number at 0, between
        /// 65535 and 1: the count of missing packets wraps as RTP's sequence
        /// numbers do, so it is still one.
        #[test]
        fn the_missing_count_wraps_at_65536() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let packets = lost_sid_then_a_pause(65531);
            assert_eq!(packets[4].sequence, 65535);
            assert_eq!(packets[5].sequence, 1);
            let s = g729_stream(packets.clone(), 600)?;
            let d = decode_stream_pcm(&s, true)?;
            let expected = lost_sid_then_a_pause_reference(tables, &packets);
            assert_eq!(first_difference(&d.pcm, &expected), None);
            Ok(())
        }

        /// Two packets lost inside speech, with no pause: the timestamps
        /// step over exactly the missing packets' time, so the whole gap is
        /// erased frames.
        #[test]
        fn packets_lost_inside_speech_are_all_erased() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let s = g729_stream(
                vec![
                    RetainedFrame::new(0, 0, [VOICE, VOICE2].concat()),
                    RetainedFrame::new(160, 1, [VOICE2, VOICE].concat()),
                    // Sequence 2 and 3, 320..640, lost.
                    RetainedFrame::new(640, 4, [VOICE, VOICE2].concat()),
                    RetainedFrame::new(800, 5, [VOICE2, VOICE].concat()),
                ],
                120,
            )?;
            let d = decode_stream_pcm(&s, true)?;
            let mut frames = frames_of(&s.payload_buffer[0].payload);
            frames.extend(frames_of(&s.payload_buffer[1].payload));
            frames.extend([g729::Frame::Erased; 4]);
            frames.extend(frames_of(&s.payload_buffer[2].payload));
            frames.extend(frames_of(&s.payload_buffer[3].payload));
            assert_eq!(first_difference(&d.pcm, &reference(tables, &frames)), None);
            Ok(())
        }

        /// A SID, a pause, and the packet that resumed speech lost: the
        /// pause is untransmitted, and the lost packet's frames are erased
        /// at its END, right before the next packet received.
        #[test]
        fn a_lost_packet_after_a_pause_is_erased_at_the_pause_s_end() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let s = g729_stream(
                vec![
                    RetainedFrame::new(0, 0, [VOICE, VOICE2].concat()),
                    RetainedFrame::new(160, 1, [&VOICE[..], &SID[..]].concat()),
                    // The pause; sequence 2, speech resuming at 1600, lost.
                    RetainedFrame::new(1760, 3, [VOICE2, VOICE].concat()),
                    RetainedFrame::new(1920, 4, [VOICE, VOICE2].concat()),
                ],
                280,
            )?;
            let d = decode_stream_pcm(&s, true)?;
            let mut frames = frames_of(&s.payload_buffer[0].payload);
            frames.extend(frames_of(&s.payload_buffer[1].payload));
            frames.extend([g729::Frame::NoTx; 16]);
            frames.extend([g729::Frame::Erased; 2]);
            frames.extend(frames_of(&s.payload_buffer[2].payload));
            frames.extend(frames_of(&s.payload_buffer[3].payload));
            assert_eq!(first_difference(&d.pcm, &reference(tables, &frames)), None);
            Ok(())
        }

        /// A gap after speech with no sequence number missing: the sender
        /// paused and sent no SID. The gap is untransmitted frames, which
        /// the decoder starts as comfort noise from the speech before it
        /// (clause B.4.5), not loss concealed as speech.
        #[test]
        fn a_gap_after_speech_with_nothing_missing_is_untransmitted() -> Result<(), TestError> {
            let tables = test_support::use_tables()?;
            let mut d = FrameDecoder::new(Some("G729"))?;
            d.decode(&VOICE)?;
            let fill = d.fill(3 * 80, Some(0));
            let mut frames = vec![g729::Frame::Voice(&VOICE)];
            frames.extend([g729::Frame::NoTx; 3]);
            assert_eq!(fill, reference(tables, &frames)[80..]);
            Ok(())
        }

        /// The rule itself, which the decoder's output alone cannot show
        /// where an erased and an untransmitted frame decode alike (after a
        /// SID): how many frames are lost, where they go, and when the count
        /// is unknown.
        #[test]
        fn the_g729_gap_rule_divides_lost_and_untransmitted_frames() {
            use super::super::{G729Gap, G729Last, g729_gap_frames};
            use G729Last::{Active, Inactive};
            let gap = |erased_before, notx, erased_after| G729Gap {
                erased_before,
                notx,
                erased_after,
            };
            // After speech, the lost frames come first. A gap longer than the
            // lost packets fill holds a pause, and an Annex B pause starts
            // with a one-frame SID packet: the last packet lost was that SID.
            assert_eq!(g729_gap_frames(Active, Some(1), 2, 102), gap(1, 101, 0));
            // A speech packet and the SID lost before a pause: 2 + 1 frames.
            assert_eq!(g729_gap_frames(Active, Some(2), 2, 100), gap(3, 97, 0));
            // A gap the lost packets fill exactly holds no pause: all erased.
            // docs/g729.md gives two calls where that is not the call's
            // layout and says sipnab decodes these frames for them:
            // two-frame packets, SID and first speech packet lost, four-frame
            // gap; and three-frame packets, the SID lost, three-frame gap.
            assert_eq!(g729_gap_frames(Active, Some(2), 2, 4), gap(4, 0, 0));
            assert_eq!(g729_gap_frames(Active, Some(1), 3, 3), gap(3, 0, 0));
            assert_eq!(g729_gap_frames(Active, Some(2), 1, 2), gap(2, 0, 0));
            // After a SID, the lost frames come last.
            assert_eq!(g729_gap_frames(Inactive, Some(1), 2, 50), gap(0, 48, 2));
            // Nothing missing: untransmitted, after speech or a SID.
            assert_eq!(g729_gap_frames(Active, Some(0), 2, 50), gap(0, 50, 0));
            assert_eq!(g729_gap_frames(Inactive, Some(0), 2, 50), gap(0, 50, 0));
            // The lost frames are capped at the gap's length.
            assert_eq!(g729_gap_frames(Active, Some(3), 2, 4), gap(4, 0, 0));
            assert_eq!(g729_gap_frames(Inactive, Some(3), 2, 4), gap(0, 0, 4));
            // A packet is at least one frame.
            assert_eq!(g729_gap_frames(Active, Some(2), 0, 5), gap(2, 3, 0));
            // More missing packets than the gap has frames, or no previous
            // frame: unknown, and the last frame type decides the gap.
            assert_eq!(g729_gap_frames(Active, Some(5), 1, 4), gap(4, 0, 0));
            assert_eq!(g729_gap_frames(Inactive, Some(5), 1, 4), gap(0, 4, 0));
            assert_eq!(g729_gap_frames(Active, None, 1, 4), gap(4, 0, 0));
            assert_eq!(g729_gap_frames(Inactive, None, 1, 4), gap(0, 4, 0));
        }

        /// The usual speech packet is the most frequent size, the larger on a
        /// tie, and one frame before any arrives.
        #[test]
        fn the_usual_speech_packet_is_the_most_frequent_size() {
            use super::super::SpeechPacketSizes;
            let mut sizes = SpeechPacketSizes::default();
            assert_eq!(sizes.usual(), 1);
            for n in [2, 2, 2, 1] {
                sizes.record(n);
            }
            assert_eq!(sizes.usual(), 2, "the latest is 1, the usual is 2");
            let mut tie = SpeechPacketSizes::default();
            tie.record(1);
            tie.record(3);
            assert_eq!(tie.usual(), 3);
            let mut large = SpeechPacketSizes::default();
            large.record(40);
            assert_eq!(large.usual(), 16, "larger packets share the last slot");
            sizes.record(0);
            assert_eq!(sizes.usual(), 2, "an empty payload is not a packet");
        }

        /// Missing sequence numbers are counted modulo 2^16.
        #[test]
        fn missing_sequence_numbers_wrap() {
            assert_eq!(missing_between(None, 5), None);
            assert_eq!(missing_between(Some(4), 5), Some(0));
            assert_eq!(missing_between(Some(4), 7), Some(2));
            assert_eq!(missing_between(Some(65535), 0), Some(0));
            assert_eq!(missing_between(Some(65534), 1), Some(2));
            // A repeated or earlier sequence number is a count no gap holds.
            assert_eq!(missing_between(Some(10), 10), Some(65535));
        }

        /// A dialog whose only stream is G.729 without tables is refused, and
        /// the refusal names the reason and the command.
        #[test]
        fn a_g729_dialog_without_tables_names_the_command() -> Result<(), TestError> {
            test_support::use_no_tables();
            let s = g729_stream(vec![RetainedFrame::new(0, 0, VOICE.to_vec())], 10)?;
            let err = decode_dialog_audio(&[&s])
                .err()
                .ok_or("nothing decodable")?
                .to_string();
            assert!(err.contains(NOT_INSTALLED), "{err}");
            Ok(())
        }

        /// A G.729 stream beside a decoded one, without tables, is named as
        /// omitted with the reason and the command.
        #[test]
        fn an_omitted_g729_stream_names_the_command() -> Result<(), TestError> {
            test_support::use_no_tables();
            let mut pcmu = g729_stream(vec![RetainedFrame::new(0, 0, vec![0xFF; 160])], 20)?;
            pcmu.codec = Some("PCMU".into());
            pcmu.key.ssrc = 1;
            let mut g = g729_stream(vec![RetainedFrame::new(0, 0, VOICE.to_vec())], 10)?;
            std::mem::swap(&mut g.key.src, &mut g.key.dst);
            let audio = decode_dialog_audio(&[&pcmu, &g])?;
            assert!(audio.partial.contains("G729"), "{}", audio.partial);
            assert!(audio.partial.contains(NOT_INSTALLED), "{}", audio.partial);
            Ok(())
        }

        /// G.729 is always retained in a `g729` build, and exportable only
        /// when the tables load.
        #[test]
        fn g729_is_retained_always_and_exported_with_tables() -> Result<(), TestError> {
            test_support::use_no_tables();
            assert!(is_capturable_audio_codec(Some("G729")));
            assert!(!is_exportable_codec(Some("G729")));
            test_support::use_tables()?;
            assert!(is_exportable_codec(Some("g729")));
            Ok(())
        }

        /// With tables, a G.729 dialog exports a WAV at 8 kHz.
        #[test]
        fn a_g729_dialog_with_tables_exports() -> Result<(), TestError> {
            test_support::use_tables()?;
            let s = g729_stream(vec![RetainedFrame::new(0, 0, [VOICE, VOICE2].concat())], 20)?;
            let audio = decode_dialog_audio(&[&s])?;
            assert_eq!((audio.sample_rate, audio.channels), (8000, 1));
            assert!(
                audio.summary_head.contains("G.729"),
                "{}",
                audio.summary_head
            );
            assert!((audio.duration_secs - 0.02).abs() < 1e-9);
            Ok(())
        }
    }
}

/// G.729.1 through [`FrameDecoder`]: its core layer on the 16 kHz RTP clock,
/// and the decoder's own concealment and comfort noise in the gaps.
#[cfg(all(test, feature = "g729"))]
mod g7291_tests {
    use super::*;
    use crate::rtp::g729_tables::test_support;
    use crate::rtp::stream::{RtpStream, StreamKey};

    type TestError = Box<dyn std::error::Error>;

    /// Ten octets that decode as one active G.729 frame.
    const VOICE: [u8; 10] = [0x7a, 0x13, 0xc4, 0x58, 0x2e, 0x91, 0x6b, 0x0f, 0xd2, 0x37];
    /// A second, different active frame.
    const VOICE2: [u8; 10] = [0x35, 0xe8, 0x0b, 0x9c, 0x71, 0x4a, 0xd6, 0x23, 0x88, 0x5f];
    /// A core SID: an Annex B SID frame.
    const SID: [u8; 2] = [0x4c, 0x90];

    /// One G.729.1 frame at frame type `ft` whose core is `VOICE` then
    /// `VOICE2`, the rest of the frame (the higher layers) 0xA5.
    fn frame(ft: u8) -> Vec<u8> {
        let octets = g729::g7291::Rate::from_ft(ft).map_or(20, g729::g7291::Rate::frame_octets);
        let mut f = [VOICE, VOICE2].concat();
        f.resize(octets, 0xa5);
        f
    }

    /// A payload: header `0xF0 | ft`, then `frames` frames at that rate.
    fn speech(ft: u8, frames: usize) -> Vec<u8> {
        let mut p = vec![0xf0 | ft];
        for _ in 0..frames {
            p.extend(frame(ft));
        }
        p
    }

    /// A payload holding a 3-octet SID alone (FT 14) whose core is `SID`.
    fn sid() -> Vec<u8> {
        vec![0xfe, SID[0], SID[1] | 1, 0x77]
    }

    /// A G.729.1 stream on the 16 kHz RTP clock holding `payloads`, lasting
    /// `wall_ms` of capture time.
    fn g7291_stream(payloads: Vec<RetainedFrame>, wall_ms: i64) -> Result<RtpStream, TestError> {
        let key = StreamKey {
            ssrc: 0x7291_7291,
            src: "10.0.0.1:20000".parse()?,
            dst: "10.0.0.2:30000".parse()?,
            session: 0,
        };
        let hdr = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 96,
            sequence: 1,
            timestamp: 0,
            ssrc: 0x7291_7291,
            payload_offset: 12,
        };
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("a time")?;
        let mut s = RtpStream::new(key, &hdr, ts);
        s.codec = Some("G7291".into());
        s.clock_rate = 16000;
        s.last_seen = s.first_seen + chrono::Duration::milliseconds(wall_ms);
        s.payload_buffer = payloads.into();
        Ok(s)
    }

    /// The 10 ms frames the crate's decoder is given, from a fresh state.
    enum Expect {
        /// One G.729.1 frame's core: `VOICE` then `VOICE2`.
        Core,
        /// The core SID then an untransmitted frame.
        Sid,
        /// `n` erased frames.
        Erased(usize),
        /// `n` untransmitted frames.
        NoTx(usize),
    }

    /// What the crate's decoder produces for `script`.
    fn reference(tables: &g729::Tables, script: &[Expect]) -> Vec<i16> {
        let mut frames: Vec<g729::Frame<'_>> = Vec::new();
        for step in script {
            match step {
                Expect::Core => {
                    frames.extend([g729::Frame::Voice(&VOICE), g729::Frame::Voice(&VOICE2)])
                }
                Expect::Sid => frames.extend([g729::Frame::Sid(&SID), g729::Frame::NoTx]),
                Expect::Erased(n) => frames.extend(std::iter::repeat_n(g729::Frame::Erased, *n)),
                Expect::NoTx(n) => frames.extend(std::iter::repeat_n(g729::Frame::NoTx, *n)),
            }
        }
        let mut d = g729::Decoder::new(tables);
        let mut out = Vec::new();
        let mut pcm = [0i16; g729::FRAME_SAMPLES];
        for f in frames {
            d.decode(f, &mut pcm);
            out.extend_from_slice(&pcm);
        }
        out
    }

    /// The rule itself: frames alone leave the stream talking, a SID (alone
    /// or after frames) leaves it paused, and a payload with neither leaves
    /// it as it was. After a SID an erased and an untransmitted frame decode
    /// alike, so the decoded audio alone cannot show this.
    #[test]
    fn the_g7291_gap_rule_follows_the_last_frame_type() -> Result<(), TestError> {
        let after = |payload: &[u8], last| -> Result<G729Last, TestError> {
            Ok(g7291_last_after(&g729::g7291::split_rtp(payload)?, last))
        };
        let mut speech_then_sid = speech(0, 1);
        speech_then_sid.extend_from_slice(&SID);
        for last in [G729Last::Active, G729Last::Inactive] {
            assert_eq!(after(&speech(0, 1), last)?, G729Last::Active);
            assert_eq!(after(&speech(11, 2), last)?, G729Last::Active);
            assert_eq!(after(&sid(), last)?, G729Last::Inactive);
            assert_eq!(after(&speech_then_sid, last)?, G729Last::Inactive);
            assert_eq!(after(&[0xff], last)?, last, "no data");
            assert_eq!(after(&[0xf0], last)?, last, "a header alone");
        }
        Ok(())
    }

    /// A lost packet stands for the stream's usual speech packet, counted
    /// from packets of frames alone: a packet ending in a SID is not a
    /// speech packet's size. Here one packet of three frames (six 10 ms
    /// frames) and one of a frame alone tie, the larger wins, and the two
    /// one-frame packets that end in a SID do not count.
    #[test]
    fn a_packet_ending_in_a_sid_does_not_size_a_lost_packet() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let mut d = FrameDecoder::new(Some("G7291"))?;
        let mut speech_then_sid = speech(0, 1);
        speech_then_sid.extend_from_slice(&SID);
        for payload in [
            speech(0, 3),
            speech_then_sid.clone(),
            speech_then_sid,
            speech(0, 1),
        ] {
            d.decode(&payload)?;
        }
        // One packet missing in 60 ms after speech: six erased frames.
        let fill = d.fill(480, Some(1));
        let whole = reference(
            tables,
            &[
                Expect::Core,
                Expect::Core,
                Expect::Core,
                Expect::Core,
                Expect::Sid,
                Expect::Core,
                Expect::Sid,
                Expect::Core,
                Expect::Erased(6),
            ],
        );
        assert_eq!(fill, whole[whole.len() - 480..]);
        Ok(())
    }

    /// Each caveat is said once, in the order first met, whatever number of
    /// streams carry it.
    #[test]
    fn each_caveat_is_said_once() {
        let a = "G.729.1: one".to_owned();
        let b = "G.729.1: two".to_owned();
        assert_eq!(caveat_clause(&[]), "");
        assert_eq!(
            caveat_clause(&[a.clone(), a.clone(), b.clone(), a]),
            " — G.729.1: one. — G.729.1: two."
        );
    }

    /// One frame a packet at 8 kbit/s: 320 ticks of the 16 kHz clock each,
    /// 160 samples at 8 kHz each, end to end with no gap.
    #[test]
    fn g7291_runs_on_the_16_khz_clock_and_decodes_to_8_khz() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let s = g7291_stream(
            (0..3u16)
                .map(|i| RetainedFrame::new(u32::from(i) * 320, i, speech(0, 1)))
                .collect(),
            60,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!((d.rate, d.label), (8000, "G.729.1 core layer"));
        assert_eq!((d.timeline.gaps, d.failures), (0, 0));
        assert_eq!(
            d.pcm,
            reference(tables, &[Expect::Core, Expect::Core, Expect::Core])
        );
        Ok(())
    }

    /// Two 32 kbit/s frames a packet advance the clock by 640 ticks, and
    /// only their cores are decoded.
    #[test]
    fn two_frames_a_packet_advance_640_ticks() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let s = g7291_stream(
            (0..3u16)
                .map(|i| RetainedFrame::new(u32::from(i) * 640, i, speech(11, 2)))
                .collect(),
            120,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(d.timeline.gaps, 0);
        let six = [
            Expect::Core,
            Expect::Core,
            Expect::Core,
            Expect::Core,
            Expect::Core,
            Expect::Core,
        ];
        assert_eq!(d.pcm, reference(tables, &six));
        Ok(())
    }

    /// A sequence number missing from the stream is a packet lost: its 20 ms
    /// are erased frames, which the decoder conceals.
    #[test]
    fn a_missing_sequence_number_is_a_lost_packet_concealed() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let s = g7291_stream(
            vec![
                RetainedFrame::new(0, 0, speech(3, 1)),
                RetainedFrame::new(320, 1, speech(3, 1)),
                // Sequence 2, timestamps 640 to 959, lost.
                RetainedFrame::new(960, 3, speech(3, 1)),
            ],
            80,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!((d.timeline.gaps, d.timeline.filled_ticks), (1, 320));
        assert_eq!(
            d.pcm,
            reference(
                tables,
                &[Expect::Core, Expect::Core, Expect::Erased(2), Expect::Core]
            )
        );
        Ok(())
    }

    /// After a SID the sender stops; a timestamp jump with consecutive
    /// sequence numbers is untransmitted frames, and the comfort noise the
    /// core SID started carries on.
    #[test]
    fn a_timestamp_jump_after_a_sid_is_untransmitted() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let s = g7291_stream(
            vec![
                RetainedFrame::new(0, 0, speech(0, 1)),
                RetainedFrame::new(320, 1, sid()),
                // Five 20 ms frames not sent: 640 to 2239.
                RetainedFrame::new(2240, 2, speech(0, 1)),
            ],
            160,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!((d.timeline.gaps, d.timeline.filled_ticks), (1, 1600));
        assert_eq!(
            d.pcm,
            reference(
                tables,
                &[Expect::Core, Expect::Sid, Expect::NoTx(10), Expect::Core]
            )
        );
        Ok(())
    }

    /// The 16-bit sequence number wraps from 65535 to 0 without a loss, and a
    /// packet missing across the wrap is one lost packet.
    #[test]
    fn the_sequence_number_wraps_at_65535() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let whole = g7291_stream(
            vec![
                RetainedFrame::new(0, 65534, speech(0, 1)),
                RetainedFrame::new(320, 65535, speech(0, 1)),
                RetainedFrame::new(640, 0, speech(0, 1)),
            ],
            60,
        )?;
        let d = decode_stream_pcm(&whole, true)?;
        assert_eq!(d.timeline.gaps, 0);
        assert_eq!(
            d.pcm,
            reference(tables, &[Expect::Core, Expect::Core, Expect::Core])
        );
        let lost = g7291_stream(
            vec![
                RetainedFrame::new(0, 65535, speech(0, 1)),
                // Sequence 0 lost.
                RetainedFrame::new(640, 1, speech(0, 1)),
            ],
            60,
        )?;
        let d = decode_stream_pcm(&lost, true)?;
        assert_eq!(
            d.pcm,
            reference(tables, &[Expect::Core, Expect::Erased(2), Expect::Core])
        );
        Ok(())
    }

    /// A packet lost in a pause after a SID is the one that ended the pause:
    /// its frames are erased right before the next packet, and the rest of
    /// the pause is untransmitted.
    #[test]
    fn a_packet_lost_next_to_a_sid_is_erased_before_the_next_packet() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let s = g7291_stream(
            vec![
                RetainedFrame::new(0, 0, speech(0, 1)),
                RetainedFrame::new(320, 1, sid()),
                // Sequence 2 lost; 640 to 1919 is four 20 ms frames.
                RetainedFrame::new(1920, 3, speech(0, 1)),
            ],
            160,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(
            d.pcm,
            reference(
                tables,
                &[
                    Expect::Core,
                    Expect::Sid,
                    Expect::NoTx(6),
                    Expect::Erased(2),
                    Expect::Core
                ]
            )
        );
        Ok(())
    }

    /// FT 15 (no data) decodes nothing and is no loss: the time it stands
    /// for is untransmitted frames, not erased ones.
    #[test]
    fn no_data_packets_count_as_no_loss() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let s = g7291_stream(
            vec![
                RetainedFrame::new(0, 0, speech(0, 1)),
                RetainedFrame::new(320, 1, vec![0xff]),
                RetainedFrame::new(640, 2, vec![0xff]),
                RetainedFrame::new(960, 3, speech(0, 1)),
            ],
            80,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(d.failures, 0);
        assert_eq!(
            d.pcm,
            reference(tables, &[Expect::Core, Expect::NoTx(4), Expect::Core])
        );
        Ok(())
    }

    /// FT 12 is reserved: the payload is ignored and counted as a frame that
    /// failed to decode, and its time is concealed as a lost packet.
    #[test]
    fn a_reserved_frame_type_is_one_failure_and_its_time_is_concealed() -> Result<(), TestError> {
        let tables = test_support::use_tables()?;
        let mut reserved = speech(0, 1);
        reserved[0] = 0xfc;
        let s = g7291_stream(
            vec![
                RetainedFrame::new(0, 0, speech(0, 1)),
                RetainedFrame::new(320, 1, reserved),
                RetainedFrame::new(640, 2, speech(0, 1)),
            ],
            60,
        )?;
        let d = decode_stream_pcm(&s, true)?;
        assert_eq!(d.failures, 1);
        assert_eq!(
            d.pcm,
            reference(tables, &[Expect::Core, Expect::Erased(2), Expect::Core])
        );
        Ok(())
    }
}
