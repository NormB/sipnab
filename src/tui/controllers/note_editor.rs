// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator notes: the `C` key, the one-line editor it opens, and the question
//! a capture swap asks while notes are not saved.
//!
//! A note is output, never input (Invariant 13 in
//! `docs/internals/invariants.md`). This module only moves it between the
//! editor and `App::notes`; the text itself stays inside
//! [`crate::annotate`], which is the one place that can read it.

use crate::tui::*;

/// `C` on a message: open the editor for that message's note.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `call_id` / `index` - the message, as the dialog store holds it.
///
/// # Side effects
/// Opens [`Popup::NoteEditor`] holding the message's existing note, if any.
/// A message read from no frame gets a status line instead: there is nowhere
/// to save its note and nothing a comment could point back at.
pub(in crate::tui) fn open_note_editor(app: &mut App, call_id: &str, index: usize) {
    let frame = {
        let store = app.dialog_store.read();
        store
            .get(call_id)
            .and_then(|d| d.messages.get(index))
            .and_then(|m| m.frame.clone())
    };
    let Some(frame) = frame else {
        app.set_status_error(
            "This message was read from no frame, so a note on it could not be saved or \
             written into a capture",
        );
        return;
    };
    let editor = crate::annotate::tui::NoteEditor::new(app.notes.get(&frame));
    app.note_editor = Some(NoteEditorState { frame, editor });
    app.active_popup = Some(Popup::NoteEditor);
}

/// Keys while the note editor is open.
///
/// # Side effects
/// Characters and the cursor keys edit. Enter keeps the note (or removes it,
/// when the text is empty) and records the edit on the action trail by frame,
/// never by text; a refused note leaves the editor open and says why. Esc
/// closes the editor and changes nothing.
pub(in crate::tui) fn handle_note_editor_key(app: &mut App, key: KeyEvent) {
    let Some(state) = app.note_editor.as_mut() else {
        app.active_popup = None;
        return;
    };
    match key.code {
        KeyCode::Esc => {
            app.note_editor = None;
            app.active_popup = None;
        }
        KeyCode::Enter => match state.editor.commit() {
            Ok(Some(note)) => {
                let frame = state.frame.clone();
                match app.notes.set(&frame, note) {
                    Ok(()) => {
                        app.note_editor = None;
                        app.active_popup = None;
                        app.status_error = Some(
                            "Note kept. F2 then NOTES saves the notes; PCAP-NG writes them \
                             into the capture"
                                .to_string(),
                        );
                        app.record_action("note_set", &frame.to_string(), "", "ok", "");
                    }
                    Err(full) => app.set_status_error(format!("Note not kept: {full}")),
                }
            }
            Ok(None) => {
                let frame = state.frame.clone();
                app.note_editor = None;
                app.active_popup = None;
                if app.notes.remove(&frame) {
                    app.status_error = Some("Note removed".to_string());
                    app.record_action("note_removed", &frame.to_string(), "", "ok", "");
                }
            }
            Err(refusal) => {
                app.set_status_error(format!("Note refused: {refusal}"));
            }
        },
        KeyCode::Backspace => state.editor.backspace(),
        KeyCode::Delete => state.editor.delete(),
        KeyCode::Left => state.editor.left(),
        KeyCode::Right => state.editor.right(),
        KeyCode::Home => state.editor.home(),
        KeyCode::End => state.editor.end(),
        KeyCode::Char(c) => state.editor.insert(c),
        _ => {}
    }
}

/// Keys while [`Popup::UnsavedNotes`] asks whether to open another capture.
///
/// # Side effects
/// `y`/Enter drops the notes and opens the capture the swap asked for; `n`,
/// Esc and `q` keep the session as it was. Any other key leaves the question
/// standing, as the quit confirmation does.
pub(in crate::tui) fn handle_unsaved_notes_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
            app.active_popup = None;
            if let Some(swap) = app.pending_swap.take() {
                begin_pcap_load_confirmed(app, &swap.path, swap.filter.as_deref());
            }
        }
        KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc => {
            app.active_popup = None;
            app.pending_swap = None;
            app.status_error = Some("Capture not changed; your notes are still here".to_string());
        }
        _ => {}
    }
}
