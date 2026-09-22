// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TUI's view of a note: the labeled pane it is shown in, and the
//! one-line editor it is typed into.
//!
//! Both live here rather than in `crate::tui` because both need the text, and
//! the text does not leave this module except through the outputs its parent
//! lists. The pane gets styled lines, never a `String`; the editor holds what
//! the operator is typing and hands back a [`NoteText`] only after
//! [`NoteText::new`] accepted it.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::{NoteRefusal, NoteText};

/// The title of the pane a note is shown in.
///
/// A note sits on screen beside sipnab's own analysis. The title says, every
/// time it is drawn, which of the two this is.
pub const PANE_TITLE: &str = " operator note — not sipnab analysis ";

/// The glyph the call-flow ladder draws on a row that carries a note.
pub const MARKER: &str = "✎";

/// The lines of the note pane: the note, one line per line of the note.
///
/// Styled lines rather than a string, so the text reaches the screen and
/// nowhere else.
#[must_use]
pub fn note_lines(note: &NoteText, style: Style) -> Vec<Line<'static>> {
    note.0
        .split('\n')
        .map(|line| Line::from(Span::styled(line.replace('\t', "    "), style)))
        .collect()
}

/// A one-line editor for a note.
///
/// Holds the text being typed. It becomes a note only through
/// [`NoteEditor::commit`], which runs every refusal [`NoteText::new`] makes.
#[derive(Default)]
pub struct NoteEditor {
    /// What the operator has typed.
    buf: String,
    /// Cursor position, a byte offset on a character boundary.
    cursor: usize,
}

impl NoteEditor {
    /// An editor holding `existing`, or empty for a new note. A note typed in
    /// the TUI is one line; an existing note's newlines are kept, and the
    /// editor shows them as `↵`.
    #[must_use]
    pub fn new(existing: Option<&NoteText>) -> Self {
        let buf = existing.map(|n| n.0.clone()).unwrap_or_default();
        let cursor = buf.len();
        Self { buf, cursor }
    }

    /// Insert `c` at the cursor.
    pub fn insert(&mut self, c: char) {
        self.buf.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Delete the character before the cursor.
    pub fn backspace(&mut self) {
        if let Some((at, _)) = self.buf[..self.cursor].char_indices().next_back() {
            self.buf.remove(at);
            self.cursor = at;
        }
    }

    /// Delete the character at the cursor.
    pub fn delete(&mut self) {
        if self.cursor < self.buf.len() {
            self.buf.remove(self.cursor);
        }
    }

    /// Move the cursor one character left.
    pub fn left(&mut self) {
        if let Some((at, _)) = self.buf[..self.cursor].char_indices().next_back() {
            self.cursor = at;
        }
    }

    /// Move the cursor one character right.
    pub fn right(&mut self) {
        if let Some(c) = self.buf[self.cursor..].chars().next() {
            self.cursor += c.len_utf8();
        }
    }

    /// Move the cursor to the start.
    pub fn home(&mut self) {
        self.cursor = 0;
    }

    /// Move the cursor to the end.
    pub fn end(&mut self) {
        self.cursor = self.buf.len();
    }

    /// The editor line as drawn: the text with the cursor as a reversed cell.
    #[must_use]
    pub fn line(&self, style: Style) -> Line<'static> {
        let shown = |s: &str| s.replace('\n', "↵").replace('\t', " ");
        let (before, rest) = self.buf.split_at(self.cursor);
        let mut chars = rest.chars();
        let at = chars
            .next()
            .map_or_else(|| " ".to_string(), |c| shown(&c.to_string()));
        Line::from(vec![
            Span::styled(shown(before), style),
            Span::styled(at, style.add_modifier(Modifier::REVERSED)),
            Span::styled(shown(chars.as_str()), style),
        ])
    }

    /// Finish editing.
    ///
    /// # Returns
    ///
    /// `Ok(Some(note))` for a note to keep, `Ok(None)` when the text is empty
    /// (which removes the note, the way clearing a field does).
    ///
    /// # Errors
    ///
    /// Every [`NoteRefusal`] except [`NoteRefusal::Empty`]: the editor stays
    /// open with the text as typed, so the operator can fix it.
    pub fn commit(&self) -> Result<Option<NoteText>, NoteRefusal> {
        match NoteText::new(&self.buf) {
            Ok(note) => Ok(Some(note)),
            Err(NoteRefusal::Empty) => Ok(None),
            Err(refusal) => Err(refusal),
        }
    }
}

impl std::fmt::Debug for NoteEditor {
    /// The length and the cursor, never the text being typed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NoteEditor(<{} bytes, sealed>, cursor {})",
            self.buf.len(),
            self.cursor
        )
    }
}

#[cfg(test)]
mod tests {
    //! The editor's keys and its commit, and the pane's lines.

    use super::*;

    /// Text of a line, for assertions.
    fn text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    /// Typing, moving and deleting edit on character boundaries.
    #[test]
    fn the_editor_edits_on_character_boundaries() {
        let mut e = NoteEditor::new(None);
        for c in "héllo".chars() {
            e.insert(c);
        }
        e.left();
        e.left();
        e.backspace(); // the first 'l', the character before the cursor
        e.insert('X');
        e.home();
        e.delete();
        e.end();
        e.insert('!');
        assert_eq!(text(&e.line(Style::default())), "éXlo! ");
    }

    /// An empty commit removes; a refused one says why; a good one keeps.
    #[test]
    fn commit_keeps_removes_or_refuses() {
        let mut e = NoteEditor::new(None);
        assert_eq!(e.commit(), Ok(None), "empty removes the note");
        for c in "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1c".chars() {
            e.insert(c);
        }
        assert_eq!(e.commit(), Err(NoteRefusal::SdesKey));
        let mut ok = NoteEditor::new(None);
        for c in "fine".chars() {
            ok.insert(c);
        }
        assert_eq!(ok.commit(), Ok(Some(NoteText::new("fine").expect("valid"))));
    }

    /// An existing note opens with its text and the cursor at the end.
    #[test]
    fn an_existing_note_opens_for_amending() {
        let note = NoteText::new("first\nsecond").expect("valid");
        let mut e = NoteEditor::new(Some(&note));
        e.insert('!');
        assert_eq!(text(&e.line(Style::default())), "first↵second! ");
    }

    /// The pane shows one line per line of the note.
    #[test]
    fn the_pane_shows_every_line_of_the_note() {
        let note = NoteText::new("one\n\ttwo").expect("valid");
        let lines = note_lines(&note, Style::default());
        let texts: Vec<String> = lines.iter().map(text).collect();
        assert_eq!(texts, ["one", "    two"]);
    }
}
