// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one door a note's text leaves by into a capture file.
//!
//! A pcapng Enhanced Packet Block may carry any number of `opt_comment`
//! options (option code 1, UTF-8; draft-ietf-opsawg-pcapng section 3.5), and
//! Wireshark shows each beside its frame. [`EpbComment`] is such a comment
//! with a note in it. Only this module builds one, and
//! [`crate::capture::PcapWriter::write_annotated`] is the only thing that
//! takes one, so an export path that does not import this module (MCP's
//! `export_capture` above all) has no way to put text into a packet comment.
//!
//! Every comment starts with [`NOTE_PREFIX`], so a reader can tell a note
//! from any other comment a later tool adds. No author is written: the file
//! leaves the box, and a name in it is personal data the operator did not
//! choose to send.

use std::borrow::Cow;

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;

use super::NoteText;
#[cfg(feature = "tui")]
use crate::capture::packet::FrameRef;

/// What every note comment starts with.
pub const NOTE_PREFIX: &str = "[operator note] ";

/// Longest comment the pcapng writer can store: `pcap-file` writes an
/// option's length as a `u16`, so anything longer wraps the field and
/// corrupts the block instead of failing.
const MAX_COMMENT_BYTES: usize = u16::MAX as usize;

/// A packet comment carrying one operator note.
///
/// Built only here, from a [`NoteText`]; there is no public constructor and
/// the field is private. The type is reachable, so the second block fails for
/// the privacy of the field and not for a path that does not exist:
///
/// ```
/// fn takes(_comments: &[sipnab::annotate::pcapng::EpbComment]) {}
/// takes(&[]);
/// ```
///
/// ```compile_fail
/// let _comment = sipnab::annotate::pcapng::EpbComment(String::from("[operator note] forged"));
/// ```
pub struct EpbComment(String);

/// A note's comment would not fit the 16-bit option length.
///
/// Reachable only through a frame pointer long enough to push a capped note
/// past 65,535 bytes, which is a pointer no capture sipnab reads can produce.
/// Refused rather than cut: a truncated note says something its author did
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommentTooLong {
    /// How long the comment would have been, in bytes.
    pub bytes: usize,
}

impl std::fmt::Display for CommentTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a packet comment of {} bytes does not fit the pcapng option \
             length ({MAX_COMMENT_BYTES} bytes)",
            self.bytes
        )
    }
}

impl std::error::Error for CommentTooLong {}

impl EpbComment {
    /// The comment for a note on a frame copied byte for byte from the
    /// capture it was written about: `[operator note] <text>`.
    #[must_use]
    pub(crate) fn on_original_frame(note: &NoteText) -> Self {
        // The note is capped at MAX_NOTE_BYTES, far below the option length,
        // so this cannot outgrow the field.
        Self(format!("{NOTE_PREFIX}{}", note.0))
    }

    /// The comment for a note on a REBUILT frame: the note, then the pointer
    /// to the frame it was written about.
    ///
    /// A rebuilt frame's bytes are not the original's, so the pointer is the
    /// only link back to the evidence. Wireshark shows it with the note, and
    /// `sipnab --show-frame` follows it.
    ///
    /// # Errors
    ///
    /// [`CommentTooLong`] when the pointer is long enough to push the comment
    /// past the option length.
    ///
    /// Built with the `tui` feature: the TUI's save dialog is the one exporter
    /// that writes rebuilt frames with notes.
    #[cfg(feature = "tui")]
    pub(crate) fn on_rebuilt_frame(
        note: &NoteText,
        original: &FrameRef,
    ) -> Result<Self, CommentTooLong> {
        let mut whole = original.clone();
        whole.bytes = None;
        let text = format!("{NOTE_PREFIX}{}\noriginal frame: {whole}", note.0);
        if text.len() > MAX_COMMENT_BYTES {
            return Err(CommentTooLong { bytes: text.len() });
        }
        Ok(Self(text))
    }

    /// The pcapng option the writer puts on the frame's Enhanced Packet
    /// Block. Crate-private: the writer is its only caller.
    pub(crate) fn option(&self) -> EnhancedPacketOption<'_> {
        EnhancedPacketOption::Comment(Cow::Borrowed(self.0.as_str()))
    }

    /// Length of the comment in bytes, as it will be written.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for EpbComment {
    /// The length and nothing else, like [`NoteText`]'s.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpbComment(<{} bytes, sealed>)", self.0.len())
    }
}

/// The sentence a file carrying notes puts in its section comment, so a
/// reader who opens capture file properties before any frame learns what
/// the packet comments are.
#[must_use]
pub fn section_sentence(notes: usize) -> String {
    format!(
        "{notes} packet comment(s) in this file are notes typed by a person, \
         each starting \"{}\". They are not sipnab analysis, and sipnab does \
         not read them back.",
        NOTE_PREFIX.trim_end()
    )
}

#[cfg(test)]
mod tests {
    //! The two comment shapes, the option-length guard, and the sealed Debug.

    use super::*;
    #[cfg(feature = "tui")]
    use crate::capture::resolve::parse_pointer;

    /// A validated note.
    fn note(text: &str) -> NoteText {
        NoteText::new(text).expect("a valid note")
    }

    /// A copied frame's comment is the prefix and the note, nothing else.
    #[test]
    fn a_note_on_an_original_frame_is_the_prefix_and_the_text() {
        let c = EpbComment::on_original_frame(&note("the 183 with new SDP"));
        let EnhancedPacketOption::Comment(text) = c.option() else {
            panic!("a note is written as opt_comment");
        };
        assert_eq!(text, "[operator note] the 183 with new SDP");
        assert_eq!(c.byte_len(), text.len());
    }

    /// A rebuilt frame's comment adds the pointer to the WHOLE original frame,
    /// the only link back to the evidence once the bytes are synthetic.
    #[cfg(feature = "tui")]
    #[test]
    fn a_note_on_a_rebuilt_frame_names_the_original_frame() {
        let original = parse_pointer("cap.pcap#3@00000000deadbeef+10-20").expect("pointer");
        let c = EpbComment::on_rebuilt_frame(&note("here"), &original).expect("fits");
        let EnhancedPacketOption::Comment(text) = c.option() else {
            panic!("a note is written as opt_comment");
        };
        assert_eq!(
            text,
            "[operator note] here\noriginal frame: cap.pcap#3@00000000deadbeef"
        );
    }

    /// A comment that would outgrow the 16-bit option length is refused, not
    /// cut: a cut note says something its author did not.
    #[cfg(feature = "tui")]
    #[test]
    fn a_comment_past_the_option_length_is_refused() {
        let long = format!("{}#0@00000000deadbeef", "d/".repeat(40_000));
        let original = parse_pointer(&long).expect("pointer");
        let err =
            EpbComment::on_rebuilt_frame(&note("n"), &original).expect_err("over 65,535 bytes");
        assert!(err.bytes > u16::MAX as usize, "{err}");

        // And one byte under the field is still written whole.
        let fits = format!(
            "{}#0",
            "d".repeat(u16::MAX as usize - "[operator note] n\noriginal frame: #0".len())
        );
        let c = EpbComment::on_rebuilt_frame(&note("n"), &parse_pointer(&fits).expect("pointer"))
            .expect("exactly at the limit fits");
        assert_eq!(c.byte_len(), u16::MAX as usize);
    }

    /// `{:?}` carries the length and not the text.
    #[test]
    fn debug_output_is_sealed() {
        let shown = format!("{:?}", EpbComment::on_original_frame(&note("sentinel")));
        assert!(!shown.contains("sentinel"), "{shown}");
    }

    /// The section sentence says how many comments are notes and that sipnab
    /// never reads them.
    #[test]
    fn the_section_sentence_counts_the_notes_and_disowns_them() {
        let s = section_sentence(3);
        assert!(s.starts_with("3 packet comment(s)"), "{s}");
        assert!(s.contains("not sipnab analysis"), "{s}");
        assert!(s.contains("does not read them back"), "{s}");
        assert!(s.contains("[operator note]"), "{s}");
    }
}
