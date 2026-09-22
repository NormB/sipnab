// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one-shot annotated copy: `--notes FILE --write-annotated OUT -I CAPTURE`.
//!
//! Writes a pcapng copy of the ORIGINAL frames of one capture, with each
//! operator note as a packet comment on the frame it names. The copy is what
//! goes to a carrier or a vendor, so three things hold or nothing is written:
//!
//! - **Every note is bound to its frame by digest.** A note names a frame as
//!   `<source>#<ordinal>@<digest>`. The frame at that ordinal is hashed as it
//!   is copied, and a digest that differs means the capture changed since the
//!   note was written (rotated, truncated, recompressed). The run then fails
//!   and writes no file: a note on the wrong frame is worse than no note,
//!   because it reads as a precise claim about bytes it was never about. A
//!   pointer with no digest (a live `eth0#12`, or one typed by hand) is
//!   refused for the same reason: nothing could prove where it lands.
//! - **Frames are counted the way [`crate::capture::resolve::resolve`]
//!   counts them**, through [`crate::capture::file::open_offline`], so an
//!   ordinal means the same frame here as in `--show-frame`.
//! - **The copy carries nothing the operator did not see.** Re-encoding
//!   through libpcap drops decryption secrets (DSBs), name resolution blocks
//!   and the input's own comments, and the section comment says so. A byte
//!   copy of the input's blocks, the way `--strip-secrets` works, would carry
//!   forward whatever the input held and count frames by a second rule.
//!
//! The output is written to a temporary file beside it and renamed into
//! place only when every frame is written, so a refusal leaves no file behind.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::TimeZone;

use super::pcapng::{EpbComment, section_sentence};
use super::{NoteText, Notes};
use crate::capture::packet::{FrameSource, frame_digest};

/// What a finished copy contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyReport {
    /// Frames written.
    pub frames: u64,
    /// Notes written, each as one packet comment.
    pub notes: usize,
}

/// Why no annotated copy was written.
///
/// Every variant names the frame pointer or path involved and never a note's
/// text.
#[derive(Debug)]
#[non_exhaustive]
pub enum CopyError {
    /// The output name says classic pcap, which has nowhere to put a comment.
    ClassicOutput(String),
    /// A note's pointer carries no digest.
    NoDigest(String),
    /// A note's pointer names text read out of a process, never a frame.
    NeverOnTheWire(String),
    /// A note's pointer names a different capture.
    OtherSource {
        /// The pointer.
        frame: String,
        /// The capture being copied, as the operator spelled it.
        input: String,
    },
    /// The capture could not be opened.
    Unreadable(String),
    /// The capture holds fewer frames than a note's ordinal.
    NoSuchFrame {
        /// The pointer.
        frame: String,
        /// How many frames the capture holds.
        frames_present: u64,
    },
    /// The frame at a note's ordinal is not the frame the note was written
    /// about.
    Changed(String),
    /// A frame's timestamp cannot be written without changing it.
    Timestamp(u64),
    /// Writing the copy failed.
    Write(String),
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClassicOutput(out) => write!(
                f,
                "'{out}' names a classic pcap, which has no field for a packet \
                 comment; name the output .pcapng"
            ),
            Self::NoDigest(frame) => write!(
                f,
                "the note on {frame} names no digest, so nothing can prove it \
                 lands on the frame it was written about; take the pointer from \
                 --json over the capture (it ends in @<digest>)"
            ),
            Self::NeverOnTheWire(frame) => write!(
                f,
                "the note on {frame} is about plaintext read out of a process, \
                 which was never a frame in any capture"
            ),
            Self::OtherSource { frame, input } => write!(
                f,
                "the note on {frame} names another capture, not '{input}'; \
                 annotate one capture per run"
            ),
            Self::Unreadable(cause) => write!(f, "cannot read the capture: {cause}"),
            Self::NoSuchFrame {
                frame,
                frames_present,
            } => write!(
                f,
                "the note on {frame} names a frame past the end: the capture \
                 holds {frames_present} frame(s). It may have been truncated \
                 since the note was written"
            ),
            Self::Changed(frame) => write!(
                f,
                "the frame at {frame} is not the frame the note was written \
                 about: its bytes no longer match the digest. The capture was \
                 rotated, truncated or rewritten since. Refusing to put the note \
                 on a frame it does not describe"
            ),
            Self::Timestamp(ordinal) => write!(
                f,
                "frame {ordinal} carries a timestamp the copy cannot represent, \
                 so copying it would change it"
            ),
            Self::Write(cause) => write!(f, "cannot write the copy: {cause}"),
        }
    }
}

impl std::error::Error for CopyError {}

/// Whether `output` is named as a classic pcap: `.pcap` or `.cap`.
fn is_classic_name(output: &Path) -> bool {
    output
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("cap"))
}

/// Whether a pointer's `source` names the capture at `input`.
///
/// The same path, the same file reached another way (compared canonically),
/// or the same file name: a capture moved to another directory, or named
/// relative to another working directory, is still the capture the note was
/// written on, and the digest check proves the bytes. A different file name
/// is a different capture.
fn names_this_capture(source: &str, input: &Path, input_label: &str) -> bool {
    // The label is the name frame pointers carry, including for a member of
    // an archive, whose `input` is only the file it was extracted to.
    if source == input_label {
        return true;
    }
    let named = Path::new(source);
    if named == input {
        return true;
    }
    if let (Ok(a), Ok(b)) = (named.canonicalize(), input.canonicalize())
        && a == b
    {
        return true;
    }
    // The same member of the same archive, spelled from a different place.
    if let (Some(a), Some(b)) = (
        crate::capture::archive::locate_member(source),
        crate::capture::archive::locate_member(input_label),
    ) {
        let rest = |label: &str, archive: &Path| {
            label
                .strip_prefix(&archive.display().to_string())
                .unwrap_or(label)
                .to_string()
        };
        let same_archive = matches!(
            (a.canonicalize(), b.canonicalize()),
            (Ok(x), Ok(y)) if x == y
        );
        return same_archive && rest(source, &a) == rest(input_label, &b);
    }
    matches!(
        (named.file_name(), Path::new(input_label).file_name()),
        (Some(a), Some(b)) if a == b
    )
}

/// One note, placed.
struct Placed<'a> {
    /// The pointer as written in the notes file.
    frame: String,
    /// The digest the frame must have.
    digest: u64,
    /// The note.
    note: &'a NoteText,
}

/// Every note, checked and grouped by ordinal.
///
/// # Errors
///
/// A [`CopyError`] naming the first note whose pointer cannot be honored.
fn place<'a>(
    notes: &'a Notes,
    input: &Path,
    input_label: &str,
) -> Result<BTreeMap<u64, Vec<Placed<'a>>>, CopyError> {
    let mut by_ordinal: BTreeMap<u64, Vec<Placed<'a>>> = BTreeMap::new();
    for (key, note) in notes.entries() {
        // Keys are the text form of a FrameRef, so this parses; a key that
        // somehow does not is a pointer nothing can be checked against.
        let pointer = crate::capture::resolve::parse_pointer(key)
            .map_err(|_| CopyError::NoDigest(key.to_string()))?;
        if matches!(pointer.source_kind(), FrameSource::Uprobe { .. }) {
            return Err(CopyError::NeverOnTheWire(key.to_string()));
        }
        let Some(digest) = pointer.origin.digest else {
            return Err(CopyError::NoDigest(key.to_string()));
        };
        if !names_this_capture(&pointer.source, input, input_label) {
            return Err(CopyError::OtherSource {
                frame: key.to_string(),
                input: input_label.to_string(),
            });
        }
        by_ordinal
            .entry(pointer.origin.ordinal)
            .or_default()
            .push(Placed {
                frame: key.to_string(),
                digest,
                note,
            });
    }
    Ok(by_ordinal)
}

/// The section comment of an annotated copy.
fn provenance(input_label: &str, notes: usize, from_password_archive: bool) -> String {
    format!(
        "Produced by sipnab {} by --write-annotated from '{input_label}'.\n\
         \n\
         Every frame in this file is copied byte for byte from that capture, \
         in its order, with its captured and original lengths. {}\n\
         \n\
         Each note was bound to its frame by the frame's digest, and sipnab \
         would have refused to write this file had any of those frames \
         differed.\n\
         \n\
         NOT CARRIED from the input: decryption secrets (DSBs), name \
         resolution blocks, the input's own packet and section comments, \
         interface options other than the link type, and timestamp precision \
         finer than a microsecond.",
        env!("CARGO_PKG_VERSION"),
        section_sentence(notes),
    ) + if from_password_archive {
        "\n\n\
         The capture was decrypted out of a password-protected archive to be \
         read, and this copy is NOT encrypted: protect it as you would the \
         unpacked archive."
    } else {
        ""
    }
}

/// Write an annotated pcapng copy of `input` to `output`.
///
/// # Arguments
///
/// * `input` — the capture to copy.
/// * `input_label` — how the operator spelled it; written into the section
///   comment and the interface name as given, never made absolute, because an
///   absolute path carries the account name into a file that leaves the box.
/// * `notes` — the notes to write; each must name a frame of `input` with a
///   digest.
/// * `output` — where the copy goes; replaced only if the copy succeeds.
///
/// # Errors
///
/// A [`CopyError`] when any note cannot be placed on the frame it names, the
/// input cannot be read, or the copy cannot be written. No file is left at
/// `output` in any of those cases.
///
/// # Side effects
///
/// Reads `input` (decompressing a gzip capture to a temporary file), writes a
/// temporary file beside `output`, and renames it over `output` on success.
pub fn write_annotated_copy(
    input: &Path,
    input_label: &str,
    notes: &Notes,
    output: &Path,
) -> Result<CopyReport, CopyError> {
    if is_classic_name(output) {
        return Err(CopyError::ClassicOutput(output.display().to_string()));
    }
    let by_ordinal = place(notes, input, input_label)?;

    let (mut cap, _gunzipped) = crate::capture::file::open_offline(input)
        .map_err(|e| CopyError::Unreadable(format!("{e:#}")))?;
    let link_type = cap.get_datalink().0;

    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let temp = tempfile::Builder::new()
        .prefix(".sipnab-tmp-")
        .tempfile_in(&dir)
        .map_err(|e| CopyError::Write(format!("{}: {e}", dir.display())))?;

    let mut writer = crate::capture::PcapWriter::with_provenance(
        temp.path(),
        link_type,
        None,
        None,
        true,
        // Raw: an annotated copy is for sending, and never carries secrets.
        crate::capture::PcapExportMode::Raw,
        Some(input_label),
        Some(provenance(
            input_label,
            notes.len(),
            crate::capture::archive::is_decrypted_member(input),
        )),
    )
    .map_err(|e| CopyError::Write(format!("{e:#}")))?;

    let mut ordinal: u64 = 0;
    let mut written_notes = 0usize;
    // The same loop `resolve` runs, so an ordinal names the same frame.
    while let Ok(pkt) = cap.next_packet() {
        let mut comments = Vec::new();
        if let Some(placed) = by_ordinal.get(&ordinal) {
            let digest = frame_digest(pkt.data);
            for p in placed {
                if p.digest != digest {
                    return Err(CopyError::Changed(p.frame.clone()));
                }
                comments.push(EpbComment::on_original_frame(p.note));
            }
        }
        let ts = pkt.header.ts;
        let timestamp = u32::try_from(ts.tv_usec)
            .ok()
            .filter(|us| *us < 1_000_000)
            .and_then(|us| chrono::Utc.timestamp_opt(ts.tv_sec, us * 1000).single())
            .ok_or(CopyError::Timestamp(ordinal))?;
        let packet = crate::capture::Packet::new(
            timestamp,
            pkt.data.to_vec(),
            pkt.header.caplen as usize,
            pkt.header.len as usize,
            Some(input_label.to_string()),
            link_type,
        );
        writer
            .write_annotated(&packet, &comments)
            .map_err(|e| CopyError::Write(format!("{e:#}")))?;
        written_notes += comments.len();
        ordinal += 1;
    }

    // A note past the last frame: the capture is shorter than when the note
    // was written.
    if let Some((_, placed)) = by_ordinal.range(ordinal..).next()
        && let Some(first) = placed.first()
    {
        return Err(CopyError::NoSuchFrame {
            frame: first.frame.clone(),
            frames_present: ordinal,
        });
    }

    writer
        .finish()
        .map_err(|e| CopyError::Write(format!("{e:#}")))?;
    drop(writer);
    temp.as_file()
        .sync_all()
        .map_err(|e| CopyError::Write(format!("{e}")))?;
    temp.persist(output)
        .map_err(|e| CopyError::Write(format!("{}: {}", output.display(), e.error)))?;
    Ok(CopyReport {
        frames: ordinal,
        notes: written_notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy of a member decrypted out of a password-protected archive says
    /// so in its section comment, naming no password; any other copy does
    /// not mention archives at all.
    #[test]
    fn the_section_comment_says_when_the_source_was_a_password_archive() {
        let from_archive = provenance("evidence.zip/a.pcap", 0, true);
        assert!(
            from_archive.contains("decrypted out of a password-protected archive"),
            "{from_archive}"
        );
        let plain = provenance("a.pcap", 0, false);
        assert!(!plain.contains("password"), "{plain}");
    }

    /// A capture read out of an archive is named by its label — the name its
    /// frame pointers carry — not by the file it was extracted to. A note made
    /// against `<archive>/<member>` must bind to that member.
    #[test]
    fn an_archive_member_is_named_by_its_label() {
        let extracted = Path::new("/tmp/sipnab-archive-XXXX/m00000.pcap");
        let label = "caps/session.tgz/set/call.pcap";
        assert!(names_this_capture(label, extracted, label));
        assert!(
            !names_this_capture("caps/session.tgz/set/other.pcap", extracted, label),
            "a different member of the same archive is a different capture"
        );
    }
}
