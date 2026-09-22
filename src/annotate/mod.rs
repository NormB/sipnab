// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator notes: text a person types about a SIP message, written into a
//! pcapng file as a packet comment and never read back.
//!
//! # What this is for
//!
//! An operator reading a call in the TUI wants to hand the capture to a
//! carrier or a vendor with a remark on the frame that matters: "this 183 is
//! where the SDP changed". Wireshark shows a pcapng packet comment
//! (`opt_comment`, draft-ietf-opsawg-pcapng section 3.5) beside the frame, so
//! that is where the note goes. The person who opens the file needs nothing
//! but Wireshark.
//!
//! # Output, never input
//!
//! A note is a person's conclusion, and sipnab's analysis is built from what
//! was on the wire. The two must not meet, for the reason
//! `docs/design/deferred-and-declined.md` section 2 gives for agent-written
//! findings: a conclusion that comes back as evidence can be cited as though
//! the capture said it. So a note reaches exactly three places, all of them
//! outputs:
//!
//! - a pcapng packet comment in a file sipnab writes ([`pcapng::EpbComment`]);
//! - the TUI's own note pane, labeled as not being analysis (`tui` module);
//! - the notes file an operator saves to resume a session
//!   ([`Notes::save`]), written `0600`.
//!
//! sipnab never parses a packet comment. No packet, message, dialog or stream
//! has a field for one, and nothing in this module is reachable from the
//! analysis: `tests/annotate_import_gate_test.rs` fails the build of any
//! analysis, output or MCP module that names this one.
//!
//! # The text is sealed
//!
//! [`NoteText`] has a private inner string and no `Deref`, `as_str`,
//! `Display` or `Serialize`, so it cannot be put into a JSON projection, a
//! log line or a tool answer by accident: the only ways out are the three
//! above, each written in this module. Its `Debug` prints the length, never
//! the text.
//!
//! # What a note may not contain
//!
//! The file leaves the box, and the SIP it carries may have been decrypted
//! from TLS. A decryption key pasted into a note would travel in clear where
//! it had traveled encrypted, which is Invariant 5 in
//! `docs/internals/invariants.md` ("key material is toxic waste"). So a note
//! holding an SDES `inline:` key, a TLS key-log line or a digest `response=`
//! value is REFUSED, not warned about and not trimmed. So is a note over
//! [`MAX_NOTE_BYTES`], because the pcapng writer stores an option's length in
//! 16 bits and a longer comment would corrupt the file rather than fail.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;

use crate::capture::packet::FrameRef;

pub mod copy;
pub mod pcapng;

/// Longest note, in BYTES of UTF-8.
///
/// Bytes rather than characters because the limit that matters is the
/// pcapng option length, which `pcap-file` writes as a `u16`: a comment over
/// 65,535 bytes wraps the length field and corrupts every block after it.
/// 4,096 leaves room below that for the `[operator note] ` prefix and the
/// original-frame line the TUI export adds, and is still several paragraphs.
pub const MAX_NOTE_BYTES: usize = 4096;

/// Most notes one session or one notes file may hold.
///
/// A bound in the spirit of Invariant 4: a notes file is input the CLI reads,
/// and one of any size would otherwise be admitted whole. Past the bound a
/// note is refused and the refusal says so; nothing is evicted, because
/// dropping a note an operator wrote is worse than telling them it did not
/// fit.
pub const MAX_NOTES: usize = 10_000;

/// Longest line a notes file may carry, in bytes.
///
/// A note is at most [`MAX_NOTE_BYTES`], JSON escaping can triple that for
/// non-ASCII text written as `\u` escapes, and the frame pointer carries a
/// path. 64 KiB covers all of it; a longer line is not a notes file.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Why a note was refused.
///
/// Every variant explains itself without repeating the note: a refusal for a
/// key shape that echoed the key would put it on the screen, in a status
/// line and in a scrollback buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoteRefusal {
    /// Nothing but whitespace.
    Empty,
    /// Longer than [`MAX_NOTE_BYTES`].
    TooLong {
        /// How many bytes the note had.
        bytes: usize,
    },
    /// A control character other than newline or tab.
    ControlCharacter {
        /// Byte offset of the first one.
        offset: usize,
    },
    /// An SDES `inline:` key ([RFC 4568 section 6.1](https://www.rfc-editor.org/rfc/rfc4568#section-6.1)).
    SdesKey,
    /// A TLS key-log line (the NSS `SSLKEYLOGFILE` format).
    KeylogLine,
    /// A digest authentication `response=` value ([RFC 7616 section 3.4](https://www.rfc-editor.org/rfc/rfc7616#section-3.4)).
    DigestResponse,
}

impl std::fmt::Display for NoteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the note is empty"),
            Self::TooLong { bytes } => write!(
                f,
                "the note is {bytes} bytes; a note may be at most \
                 {MAX_NOTE_BYTES} bytes, and it is refused rather than cut"
            ),
            Self::ControlCharacter { offset } => write!(
                f,
                "the note has a control character at byte {offset}; only \
                 newline and tab are allowed, because the note is shown in \
                 terminals and in Wireshark"
            ),
            Self::SdesKey => write!(
                f,
                "the note holds an SDES `inline:` key. The file leaves this \
                 machine, and a media key must never travel in it"
            ),
            Self::KeylogLine => write!(
                f,
                "the note holds a TLS key-log line. The file leaves this \
                 machine, and a decryption secret must never travel in it"
            ),
            Self::DigestResponse => write!(
                f,
                "the note holds a digest `response=` value, which is a \
                 credential; sipnab deletes it from every redacted export and \
                 will not write it into a note"
            ),
        }
    }
}

impl std::error::Error for NoteRefusal {}

/// The text of one operator note, validated and sealed.
///
/// Built only by [`NoteText::new`], which refuses everything
/// [`NoteRefusal`] names. There is no way to read the text back as a string:
/// no `Deref`, no `as_str`, no `Display`, no `Serialize`. It leaves only
/// through the three outputs the module documentation lists.
///
/// The type is reachable, so the refusals below are about the missing
/// accessors rather than about a path that does not exist:
///
/// ```
/// let note = sipnab::annotate::NoteText::new("this 183 is where the SDP changed")?;
/// assert_eq!(note.byte_len(), 33);
/// # Ok::<(), sipnab::annotate::NoteRefusal>(())
/// ```
///
/// No `Deref` to `str`:
///
/// ```compile_fail
/// let note = sipnab::annotate::NoteText::new("sealed").expect("valid");
/// let _text: &str = &note;
/// ```
///
/// No `as_str`:
///
/// ```compile_fail
/// let note = sipnab::annotate::NoteText::new("sealed").expect("valid");
/// let _text = note.as_str();
/// ```
///
/// No `Display`, so no `to_string` and no `format!("{}")`:
///
/// ```compile_fail
/// let note = sipnab::annotate::NoteText::new("sealed").expect("valid");
/// let _text = note.to_string();
/// ```
///
/// No `Serialize`, so it cannot be put into any JSON projection:
///
/// ```compile_fail
/// let note = sipnab::annotate::NoteText::new("sealed").expect("valid");
/// let _json = serde_json::to_string(&note);
/// ```
///
/// And the field is private:
///
/// ```compile_fail
/// let note = sipnab::annotate::NoteText::new("sealed").expect("valid");
/// let _text: String = note.0;
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct NoteText(String);

impl NoteText {
    /// Validate `text` as a note.
    ///
    /// # Errors
    ///
    /// [`NoteRefusal`] when the text is empty, longer than
    /// [`MAX_NOTE_BYTES`], holds a control character other than newline or
    /// tab, or holds a key or credential shape. A refused note is never
    /// shortened or cleaned into an accepted one: the operator decides what
    /// the note says.
    pub fn new(text: &str) -> Result<Self, NoteRefusal> {
        if text.trim().is_empty() {
            return Err(NoteRefusal::Empty);
        }
        if text.len() > MAX_NOTE_BYTES {
            return Err(NoteRefusal::TooLong { bytes: text.len() });
        }
        if let Some((offset, _)) = text
            .char_indices()
            .find(|&(_, c)| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(NoteRefusal::ControlCharacter { offset });
        }
        if let Some(refusal) = secret_shape(text) {
            return Err(refusal);
        }
        Ok(Self(text.to_string()))
    }

    /// Length of the note in bytes of UTF-8.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for NoteText {
    /// The length and nothing else, so a `{:?}` in a log line or a test
    /// failure cannot carry the text anywhere.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoteText(<{} bytes, sealed>)", self.0.len())
    }
}

/// The NSS key-log labels (`SSLKEYLOGFILE`), which begin every line of a
/// TLS key log.
///
/// Matched as a whole whitespace-separated word, case-insensitively, and only
/// when a long run of hex follows it: the label alone is a word an operator
/// might write, and a long hex run alone is what a Call-ID often is.
const KEYLOG_LABELS: &[&str] = &[
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
    "ECH_SECRET",
    "RSA",
];

/// Shortest hex run after a key-log label that counts as key material: eight
/// bytes. A client random is 32 bytes and every secret is at least 32, so
/// this also catches a paste cut short.
const KEYLOG_MIN_HEX: usize = 16;

/// Shortest base64 run after `inline:` that counts as an SDES key. The
/// smallest RFC 4568 suite carries 30 bytes (40 base64 characters); 16 still
/// catches half of one.
const SDES_MIN_BASE64: usize = 16;

/// Shortest hex run after `response=` that counts as a digest response. An
/// MD5 response is 32 hex digits; eight catches a truncated paste and leaves
/// "response=401" alone.
const DIGEST_MIN_HEX: usize = 8;

/// Which key or credential shape `text` holds, if any.
///
/// Pure, so each shape is tested directly and in both directions. The three
/// shapes are the three things Invariant 5 and the vCon redactor already
/// treat as secret: SDES media keys, TLS secrets, and digest credentials.
fn secret_shape(text: &str) -> Option<NoteRefusal> {
    if has_sdes_key(text) {
        return Some(NoteRefusal::SdesKey);
    }
    if has_keylog_line(text) {
        return Some(NoteRefusal::KeylogLine);
    }
    if has_digest_response(text) {
        return Some(NoteRefusal::DigestResponse);
    }
    None
}

/// Whether `text` holds `inline:` followed by a base64 run long enough to be
/// an SDES key.
fn has_sdes_key(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.match_indices("inline:").any(|(at, m)| {
        let run = lower[at + m.len()..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            .count();
        run >= SDES_MIN_BASE64
    })
}

/// Whether `text` holds a key-log label followed by a long hex word.
///
/// Words are split across lines too, so a key-log line that wrapped when it
/// was pasted is still one line to this check.
fn has_keylog_line(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    words.windows(2).any(|pair| {
        KEYLOG_LABELS
            .iter()
            .any(|label| pair[0].eq_ignore_ascii_case(label))
            && pair[1].len() >= KEYLOG_MIN_HEX
            && pair[1].bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// Whether `text` holds `response=` (optionally spaced and quoted) followed
/// by a hex run long enough to be a digest response.
fn has_digest_response(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.match_indices("response").any(|(at, m)| {
        let rest = lower[at + m.len()..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            return false;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        rest.bytes().take_while(u8::is_ascii_hexdigit).count() >= DIGEST_MIN_HEX
    })
}

/// A note could not be added because the session already holds
/// [`MAX_NOTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotesFull;

impl std::fmt::Display for NotesFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this session already holds {MAX_NOTES} notes, the most one \
             notes file may carry"
        )
    }
}

impl std::error::Error for NotesFull {}

/// Why a notes file could not be read.
///
/// Every variant names a line number and a reason, never a note's text.
#[derive(Debug)]
#[non_exhaustive]
pub enum NotesFileError {
    /// The file could not be read.
    Io(std::io::Error),
    /// One line is not a note sipnab will accept.
    Line {
        /// 1-based line number.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
    /// More than [`MAX_NOTES`] notes.
    TooMany,
}

impl std::fmt::Display for NotesFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the notes file: {e}"),
            Self::Line { line, reason } => write!(f, "notes file line {line}: {reason}"),
            Self::TooMany => write!(
                f,
                "the notes file holds more than {MAX_NOTES} notes, the most \
                 sipnab reads from one"
            ),
        }
    }
}

impl std::error::Error for NotesFileError {}

/// One line of a notes file as written.
///
/// Borrows the sealed text; built only by [`Notes::save`], which is one of
/// the three ways a note leaves this module.
#[derive(serde::Serialize)]
struct LineOut<'a> {
    /// The frame pointer, `<source>#<ordinal>[@digest]`.
    frame: &'a str,
    /// The note text.
    note: &'a str,
}

/// One line of a notes file as read. Unknown fields are refused, so a file
/// written for a later format is not half-read.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LineIn {
    /// The frame pointer.
    frame: String,
    /// The note text, validated by [`NoteText::new`] before it is kept.
    note: String,
}

/// The operator's notes for one session, keyed by the frame each is about.
///
/// Held by the TUI's `App` and by the one-shot `--write-annotated` copy, and
/// by nothing else: no store, no dialog and no stream has a field for one.
#[derive(Debug, Default)]
pub struct Notes {
    /// Note per frame pointer, in its whole-frame text form. A `BTreeMap` so
    /// a saved file lists the notes in one stable order.
    by_frame: BTreeMap<String, NoteText>,
    /// Whether a note changed since the notes were last saved or loaded.
    unsaved: bool,
}

/// The key a frame's note is stored under: the pointer's text form for the
/// WHOLE frame. A note is about a message, so a byte range narrowing the
/// pointer is dropped rather than making the same frame two keys.
fn frame_key(frame: &FrameRef) -> String {
    let mut whole = frame.clone();
    whole.bytes = None;
    whole.to_string()
}

impl Notes {
    /// An empty set of notes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many notes are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_frame.len()
    }

    /// Whether no note is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_frame.is_empty()
    }

    /// The note on `frame`, if there is one.
    #[must_use]
    pub fn get(&self, frame: &FrameRef) -> Option<&NoteText> {
        self.by_frame.get(&frame_key(frame))
    }

    /// Put `note` on `frame`, replacing any note already there.
    ///
    /// # Errors
    ///
    /// [`NotesFull`] when `frame` has no note yet and [`MAX_NOTES`] are
    /// already held. Replacing an existing note is always allowed.
    pub fn set(&mut self, frame: &FrameRef, note: NoteText) -> Result<(), NotesFull> {
        let key = frame_key(frame);
        if !self.by_frame.contains_key(&key) && self.by_frame.len() >= MAX_NOTES {
            return Err(NotesFull);
        }
        self.by_frame.insert(key, note);
        self.unsaved = true;
        Ok(())
    }

    /// Remove the note on `frame`. Returns whether there was one.
    pub fn remove(&mut self, frame: &FrameRef) -> bool {
        let removed = self.by_frame.remove(&frame_key(frame)).is_some();
        self.unsaved |= removed;
        removed
    }

    /// Whether a note changed since the notes were last saved or loaded.
    #[must_use]
    pub fn is_unsaved(&self) -> bool {
        self.unsaved
    }

    /// The notes with their frame pointers, in key order. Private to this
    /// module: the text stays sealed outside it.
    fn entries(&self) -> impl Iterator<Item = (&str, &NoteText)> {
        self.by_frame.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Read a notes file: one JSON object per line, `{"frame": …, "note": …}`.
    ///
    /// # Errors
    ///
    /// [`NotesFileError`] when the file cannot be read, or when any line is
    /// not a note sipnab accepts. One bad line refuses the whole file: a
    /// notes file partly loaded would be saved back without the rest.
    pub fn load(path: &Path) -> Result<Self, NotesFileError> {
        let file = std::fs::File::open(path).map_err(NotesFileError::Io)?;
        let mut notes = Self::from_reader(std::io::BufReader::new(file))?;
        notes.unsaved = false;
        Ok(notes)
    }

    /// Parse notes-file text. See [`Notes::load`].
    ///
    /// # Errors
    ///
    /// As [`Notes::load`], without the file.
    pub fn from_jsonl(text: &str) -> Result<Self, NotesFileError> {
        Self::from_reader(text.as_bytes())
    }

    /// Read notes-file lines from `reader`, each bounded by
    /// [`MAX_LINE_BYTES`] and the whole by [`MAX_NOTES`].
    fn from_reader<R: BufRead>(mut reader: R) -> Result<Self, NotesFileError> {
        use std::io::Read;
        let mut notes = Self::new();
        let mut line_no = 0usize;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = (&mut reader)
                .take(MAX_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut buf)
                .map_err(NotesFileError::Io)?;
            if n == 0 {
                break;
            }
            line_no += 1;
            let line_err = |reason: String| NotesFileError::Line {
                line: line_no,
                reason,
            };
            if buf.len() > MAX_LINE_BYTES {
                return Err(line_err(format!(
                    "longer than {MAX_LINE_BYTES} bytes, which no note needs"
                )));
            }
            let text = std::str::from_utf8(&buf)
                .map_err(|_| line_err("not UTF-8".to_string()))?
                .trim();
            if text.is_empty() {
                continue;
            }
            let parsed: LineIn = serde_json::from_str(text).map_err(|e| {
                line_err(format!(
                    "not a notes line ({}); each line is one JSON object with \
                     exactly `frame` and `note`",
                    e.classify_label()
                ))
            })?;
            let pointer = crate::capture::resolve::parse_pointer(&parsed.frame).map_err(|_| {
                line_err(
                    "`frame` is not a frame pointer; the form is \
                     <source>#<ordinal>[@digest], as in capture.pcap#12"
                        .to_string(),
                )
            })?;
            if pointer.bytes.is_some() {
                return Err(line_err(
                    "`frame` narrows to a byte range; a note is about a whole \
                     frame, so drop the +start-end suffix"
                        .to_string(),
                ));
            }
            let note = NoteText::new(&parsed.note)
                .map_err(|refusal| line_err(format!("the note is refused: {refusal}")))?;
            if notes.get(&pointer).is_some() {
                return Err(line_err(
                    "a second note for a frame an earlier line already \
                     annotated; one frame, one note"
                        .to_string(),
                ));
            }
            notes
                .set(&pointer, note)
                .map_err(|_| NotesFileError::TooMany)?;
        }
        Ok(notes)
    }

    /// Write every note to `path` as a notes file, atomically and `0600`,
    /// and mark the notes saved.
    ///
    /// `0600` for the reason the TUI's action trail is: the file holds free
    /// text an operator typed about a call, which may name a subscriber.
    ///
    /// # Errors
    ///
    /// Any error creating, writing or renaming the file. The previous file,
    /// if any, is left untouched on error, and the notes stay unsaved.
    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        crate::capture::atomic::write_atomic(path, |w| {
            for (frame, note) in self.entries() {
                let line = serde_json::to_string(&LineOut {
                    frame,
                    note: &note.0,
                })
                .map_err(std::io::Error::other)?;
                w.write_all(line.as_bytes())?;
                w.write_all(b"\n")?;
            }
            Ok(())
        })?;
        self.unsaved = false;
        Ok(())
    }
}

/// A short, text-free label for a `serde_json` error: its category and
/// position, never the offending input.
trait ClassifyLabel {
    /// `"syntax error at column 12"` and the like.
    fn classify_label(&self) -> String;
}

impl ClassifyLabel for serde_json::Error {
    fn classify_label(&self) -> String {
        let kind = match self.classify() {
            serde_json::error::Category::Io => "read error",
            serde_json::error::Category::Syntax => "syntax error",
            serde_json::error::Category::Data => "wrong or missing field",
            serde_json::error::Category::Eof => "truncated",
        };
        format!("{kind} at column {}", self.column())
    }
}

#[cfg(test)]
mod tests {
    //! Every refusal [`NoteText::new`] makes, each beside the nearest text it
    //! must ACCEPT, so a validator that refuses everything fails as surely as one
    //! that refuses nothing. Then the notes set and its file.

    use super::*;
    use crate::capture::resolve::parse_pointer;

    /// A pointer with a digest, the form a replayed capture mints.
    fn frame(text: &str) -> FrameRef {
        parse_pointer(text).expect("a well-formed test pointer")
    }

    /// `NoteText::new(text)`, asserting it was accepted.
    fn accepted(text: &str) -> NoteText {
        match NoteText::new(text) {
            Ok(note) => note,
            Err(refusal) => panic!("an ordinary note was refused: {refusal}"),
        }
    }

    /// `NoteText::new(text)`, asserting it was refused, and the refusal.
    fn refused(text: &str) -> NoteRefusal {
        match NoteText::new(text) {
            Ok(note) => panic!("this note had to be refused and was accepted as {note:?}"),
            Err(refusal) => refusal,
        }
    }

    // ── Accepted ─────────────────────────────────────────────────────────────

    /// An ordinary note, with the two control characters a note may hold.
    #[test]
    fn an_ordinary_note_is_accepted_with_its_newlines_and_tabs() {
        let note = accepted("this 183 is where the SDP changed\n\tsee the a=sendonly");
        assert_eq!(note.byte_len(), 53);
    }

    // ── Empty ────────────────────────────────────────────────────────────────

    /// Whitespace is no note; one visible character is.
    #[test]
    fn an_empty_note_is_refused_and_one_character_is_not() {
        assert_eq!(refused(""), NoteRefusal::Empty);
        assert_eq!(refused(" \n\t "), NoteRefusal::Empty);
        accepted("x");
    }

    // ── Size ─────────────────────────────────────────────────────────────────

    /// Past the cap the note is refused, not clipped, and the cap is BYTES.
    ///
    /// Bytes because the pcapng option length is a `u16` of bytes. A cap counted
    /// in characters would admit 4,096 four-byte characters, 16 KiB.
    #[test]
    fn a_note_over_the_byte_cap_is_refused_whole() {
        accepted(&"a".repeat(MAX_NOTE_BYTES));
        assert_eq!(
            refused(&"a".repeat(MAX_NOTE_BYTES + 1)),
            NoteRefusal::TooLong {
                bytes: MAX_NOTE_BYTES + 1
            }
        );
        // 2,048 two-byte characters are exactly the cap; one more is over it,
        // though it is only 2,049 characters.
        accepted(&"é".repeat(MAX_NOTE_BYTES / 2));
        assert_eq!(
            refused(&"é".repeat(MAX_NOTE_BYTES / 2 + 1)),
            NoteRefusal::TooLong {
                bytes: MAX_NOTE_BYTES + 2
            }
        );
    }

    /// The cap sits well below the 16-bit option length it protects.
    #[test]
    fn the_byte_cap_leaves_room_below_the_option_length_field() {
        const _: () = assert!(MAX_NOTE_BYTES * 2 < u16::MAX as usize);
    }

    // ── Control characters ───────────────────────────────────────────────────

    /// A terminal escape, a carriage return, DEL and a C1 control are refused,
    /// and the refusal says where.
    ///
    /// A note is drawn in a terminal (the TUI pane) and in Wireshark. An escape
    /// sequence in one could clear the operator's screen or forge a line.
    #[test]
    fn control_characters_are_refused_but_newline_and_tab_are_not() {
        assert_eq!(
            refused("ok\u{1b}[2J"),
            NoteRefusal::ControlCharacter { offset: 2 }
        );
        assert_eq!(
            refused("line\r\nline"),
            NoteRefusal::ControlCharacter { offset: 4 }
        );
        assert_eq!(
            refused("\u{7f}"),
            NoteRefusal::ControlCharacter { offset: 0 }
        );
        assert_eq!(
            refused("é\u{9b}"),
            NoteRefusal::ControlCharacter { offset: 2 }
        );
        accepted("line\nline\tcolumn");
    }

    // ── Key and credential shapes ────────────────────────────────────────────

    /// The `a=crypto` line from the SDP parser's own test, whole or as the bare
    /// key, in either case.
    #[test]
    fn an_sdes_inline_key_is_refused() {
        for sample in [
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj",
            "key was inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:32",
            "INLINE:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1c",
        ] {
            assert_eq!(refused(sample), NoteRefusal::SdesKey);
        }
    }

    /// Talking ABOUT SDES is fine.
    #[test]
    fn a_note_about_sdes_keying_is_accepted() {
        accepted("the offer used inline: keying and the answer dropped it");
        accepted("a=crypto was present on the 183 but not the 200");
        accepted("inline:short");
    }

    /// A key-log line, whole, wrapped by the paste, or lowercased.
    #[test]
    fn a_tls_keylog_line_is_refused() {
        // Hex runs of a client random's and a traffic secret's lengths.
        let first_hex = "a".repeat(64);
        let second_hex = "b".repeat(96);
        for sample in [
            format!("CLIENT_RANDOM {first_hex} {second_hex}"),
            format!("see\nSERVER_TRAFFIC_SECRET_0\n{first_hex}\n{second_hex}"),
            format!("client_handshake_traffic_secret {first_hex} {second_hex}"),
        ] {
            assert_eq!(refused(&sample), NoteRefusal::KeylogLine);
        }
    }

    /// The label as a word, and a long hex run as a Call-ID, are both fine.
    #[test]
    fn a_note_naming_a_keylog_label_or_a_hex_call_id_is_accepted() {
        accepted("no CLIENT_RANDOM for this session in the key log");
        accepted("Call-ID 3c2a8f4e9b1d4c7a8e2f6b0d1a3c5e7f matches the B leg");
        accepted("RSA 1024 certificate on the SBC");
    }

    /// A digest response, quoted or bare, in an Authorization header or alone.
    #[test]
    fn a_digest_response_value_is_refused() {
        for sample in [
            "Authorization: Digest username=\"alice\", response=\"6629fae49393a05397450978507c4ef1\"",
            "response=deadbeef",
            "Response = \"0123456789abcdef\"",
        ] {
            assert_eq!(refused(sample), NoteRefusal::DigestResponse);
        }
    }

    /// The word "response", and a status code after `=`, are fine.
    #[test]
    fn a_note_about_a_response_is_accepted() {
        accepted("no response from the SBC for 32 s");
        accepted("the response=401 came before the retransmission");
        accepted("response= empty in the second REGISTER");
    }

    /// A refusal explains itself without repeating what it refused.
    ///
    /// The refusal is shown on the status line and may land in a log. One that
    /// quoted the key would put it exactly where the refusal exists to keep it
    /// out of.
    #[test]
    fn a_refusal_never_repeats_the_note() {
        let marker = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
        let refusal = refused(&format!("inline:{marker}"));
        let shown = format!("{refusal} {refusal:?}");
        assert!(
            !shown.contains(marker),
            "the refusal text carried the refused material"
        );
    }

    /// `{:?}` shows the length, never the text.
    #[test]
    fn debug_output_carries_the_length_and_not_the_text() {
        let note = accepted("the sentinel phrase");
        let shown = format!("{note:?}");
        assert!(!shown.contains("sentinel"), "{shown}");
        assert!(shown.contains("19 bytes"), "{shown}");
    }

    // ── The notes set ────────────────────────────────────────────────────────

    /// Set, replace, remove, and the unsaved flag that the quit prompt reads.
    #[test]
    fn notes_are_kept_per_frame_and_track_whether_they_are_saved() {
        let mut notes = Notes::new();
        let a = frame("cap.pcap#3@00000000deadbeef");
        let b = frame("cap.pcap#4@00000000feedface");
        assert!(!notes.is_unsaved(), "a fresh set has nothing to lose");

        notes.set(&a, accepted("first")).expect("room");
        assert!(notes.is_unsaved());
        assert_eq!(notes.get(&a), Some(&accepted("first")));
        assert_eq!(notes.get(&b), None);

        notes
            .set(&a, accepted("second"))
            .expect("replacing never needs room");
        assert_eq!(notes.len(), 1, "one frame, one note");
        assert_eq!(notes.get(&a), Some(&accepted("second")));

        assert!(notes.remove(&a));
        assert!(!notes.remove(&a), "nothing left to remove");
        assert!(notes.is_empty());
    }

    /// A pointer narrowed to a byte range is still the same frame's note.
    #[test]
    fn a_byte_range_does_not_make_a_second_note_for_the_same_frame() {
        let mut notes = Notes::new();
        notes
            .set(&frame("cap.pcap#3@00000000deadbeef"), accepted("whole"))
            .expect("room");
        assert_eq!(
            notes.get(&frame("cap.pcap#3@00000000deadbeef+10-20")),
            Some(&accepted("whole"))
        );
    }

    /// The cap refuses a NEW note, and says so, while an existing one can still
    /// be edited.
    #[test]
    fn the_note_count_is_bounded_and_the_bound_refuses() {
        let mut notes = Notes::new();
        for i in 0..MAX_NOTES {
            notes
                .set(&frame(&format!("cap.pcap#{i}")), accepted("n"))
                .expect("under the cap");
        }
        assert_eq!(
            notes.set(&frame(&format!("cap.pcap#{MAX_NOTES}")), accepted("n")),
            Err(NotesFull)
        );
        assert_eq!(notes.len(), MAX_NOTES, "nothing was evicted to make room");
        notes
            .set(&frame("cap.pcap#0"), accepted("edited"))
            .expect("an existing note is always editable");
    }

    // ── The notes file ───────────────────────────────────────────────────────

    /// Save, read back, compare; the file is `0600` and marks the set saved.
    #[test]
    fn a_saved_notes_file_reads_back_the_same_notes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.notes.jsonl");
        let a = frame("cap.pcap#3@00000000deadbeef");
        let b = frame("uprobe:opensips/12#7");
        let mut notes = Notes::new();
        notes
            .set(&a, accepted("where the SDP changed\n\"quoted\""))
            .expect("room");
        notes.set(&b, accepted("plaintext read")).expect("room");

        notes.save(&path).expect("save");
        assert!(!notes.is_unsaved(), "a save clears the unsaved flag");

        let back = Notes::load(&path).expect("load what was saved");
        assert_eq!(back.len(), 2);
        assert_eq!(back.get(&a), notes.get(&a));
        assert_eq!(back.get(&b), notes.get(&b));
        assert!(!back.is_unsaved(), "a loaded set matches its file");

        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text.lines().count(), 2, "one note per line: {text}");
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
            let keys: Vec<&str> = v
                .as_object()
                .expect("an object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, ["frame", "note"], "exactly the two fields");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the notes file holds free text about a call");
        }
    }

    /// Blank lines are skipped; a note written by hand with its pointer is read.
    #[test]
    fn a_hand_written_notes_file_is_read() {
        let notes = Notes::from_jsonl(
            "\n{\"frame\":\"a.pcap#0@00000000deadbeef\",\"note\":\"first\"}\n\n\
             {\"note\":\"second\",\"frame\":\"a.pcap#1\"}\n",
        )
        .expect("two notes");
        assert_eq!(notes.len(), 2);
        assert_eq!(notes.get(&frame("a.pcap#1")), Some(&accepted("second")));
    }

    /// `from_jsonl(text)`, asserting it was refused, and the refusal text.
    fn file_refused(text: &str) -> String {
        match Notes::from_jsonl(text) {
            Ok(notes) => panic!(
                "this notes file had to be refused; it read {} notes",
                notes.len()
            ),
            Err(e) => e.to_string(),
        }
    }

    /// Each way a line can be wrong names its line number and why.
    #[test]
    fn a_bad_notes_line_refuses_the_file_and_names_the_line() {
        let good = "{\"frame\":\"a.pcap#0\",\"note\":\"ok\"}\n";
        for (bad, why) in [
            ("not json", "not a notes line"),
            ("{\"frame\":\"a.pcap#1\"}", "not a notes line"),
            (
                "{\"frame\":\"a.pcap#1\",\"note\":\"x\",\"author\":\"n\"}",
                "not a notes line",
            ),
            (
                "{\"frame\":\"no pointer\",\"note\":\"x\"}",
                "not a frame pointer",
            ),
            ("{\"frame\":\"a.pcap#1+0-4\",\"note\":\"x\"}", "byte range"),
            ("{\"frame\":\"a.pcap#0\",\"note\":\"again\"}", "second note"),
            ("{\"frame\":\"a.pcap#1\",\"note\":\"\"}", "refused"),
        ] {
            let msg = file_refused(&format!("{good}{bad}\n"));
            assert!(msg.contains("line 2"), "must name line 2 for {bad}: {msg}");
            assert!(msg.contains(why), "must say `{why}` for {bad}: {msg}");
        }
    }

    /// A refused note in a file is refused for the same reasons, and the error
    /// does not quote it.
    #[test]
    fn a_notes_file_is_screened_like_a_typed_note() {
        let marker = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
        let msg = file_refused(&format!(
            "{{\"frame\":\"a.pcap#0\",\"note\":\"inline:{marker}\"}}\n"
        ));
        assert!(msg.contains("SDES"), "{msg}");
        assert!(
            !msg.contains(marker),
            "the error carried the refused material"
        );
    }

    /// A line longer than any note needs is refused before it is parsed.
    #[test]
    fn an_overlong_notes_line_is_refused() {
        let msg = file_refused(&format!(
            "{{\"frame\":\"a.pcap#0\",\"note\":\"{}\"}}\n",
            "a".repeat(MAX_LINE_BYTES)
        ));
        assert!(
            msg.contains("line 1") && msg.contains("longer than"),
            "{msg}"
        );
    }

    /// More notes than the cap refuses the file rather than keeping a prefix.
    #[test]
    fn a_notes_file_over_the_cap_is_refused() {
        let mut text = String::new();
        for i in 0..=MAX_NOTES {
            text.push_str(&format!("{{\"frame\":\"a.pcap#{i}\",\"note\":\"n\"}}\n"));
        }
        assert!(matches!(
            Notes::from_jsonl(&text),
            Err(NotesFileError::TooMany)
        ));
    }
}
