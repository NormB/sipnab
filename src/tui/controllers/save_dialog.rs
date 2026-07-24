// SPDX-License-Identifier: MIT OR Apache-2.0

//! The save dialog popup: opening and key handling.

use crate::tui::*;

/// Open the save popup, pre-populating path and counts.
///
/// From a stream view, defaults to WAV export; otherwise defaults to PCAP.
///
/// # Arguments
/// * `app` - the application state to mutate.
///
/// # Side effects
/// Sets `app.save.format` from the current view, seeds `app.save.path`
/// with a timestamped `/tmp/sipnab_*.<ext>` default (cursor at the end),
/// caches the dialog/selected/message counts for display (briefly holding
/// the dialog-store read lock), and sets `app.active_popup` to the save
/// dialog.
pub(in crate::tui) fn open_save_popup(app: &mut App) {
    app.save.format = match app.current_view {
        View::StreamList | View::StreamDetail(_) => SaveFormat::Wav,
        _ => SaveFormat::default(),
    };

    let now = chrono::Local::now();
    let ext = app.save.format.extension();
    app.save.path = format!("/tmp/sipnab_{}.{ext}", now.format("%Y%m%d_%H%M%S"));
    app.save.cursor = app.save.path.len();

    // Cache counts for display
    let store = app.dialog_store.read();
    app.save.dialog_count = store.len();
    app.save.selected_count = app.call_list.selected_rows_count();
    app.save.message_count = store.iter().map(|d| d.messages.len()).sum();
    drop(store);

    app.active_popup = Some(Popup::SaveDialog);
}

/// Handle keys in the save dialog popup.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (this popup has no keymap
///   bindings): Esc cancels, Enter saves, Tab/BackTab/Up/Down cycle the
///   format, and the rest edit the path field.
///
/// # Side effects
/// Esc closes the popup. Enter queues `app.pending_save` (the write runs
/// on the next event-loop tick so the "Saving…" status paints first),
/// sets the status line, and closes the popup. The format-cycling keys
/// change `app.save.format` and rewrite the path's extension when it
/// still matches the previous format. The editing keys mutate
/// `app.save.path` and `app.save.cursor` on char boundaries.
pub(in crate::tui) fn handle_save_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            // Reject a blank path at the dialog: an empty (or whitespace-
            // only) path can only fail once the deferred write runs, so
            // catch it here and keep the popup open for the user to fix.
            if app.save.path.trim().is_empty() {
                app.status_error = Some("Save path is empty".to_string());
                return;
            }
            // Defer the write one event-loop tick (App::run_pending_save):
            // large exports can block for a while, and running them on the
            // keypress froze the UI with no feedback. This way the
            // "Saving…" status paints first.
            app.pending_save = Some(PendingSave {
                format: app.save.format,
                path: app.save.path.clone(),
            });
            app.status_error = Some(format!("Saving {}…", app.save.path));
            app.active_popup = None;
        }
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Down | KeyCode::Up => {
            // Cycle save format and update file extension
            let old_ext = app.save.format.extension();
            app.save.format = if key.code == KeyCode::BackTab || key.code == KeyCode::Up {
                app.save.format.prev()
            } else {
                app.save.format.next()
            };
            let new_ext = app.save.format.extension();
            // Replace the FULL old extension — it can span several dots
            // (e.g. "rtp.json"); replacing only the text after the last
            // dot left a stale ".rtp" behind on every lap through the
            // list. A user-edited path that no longer ends in the old
            // extension is left alone.
            let base = app
                .save
                .path
                .strip_suffix(old_ext)
                .and_then(|p| p.strip_suffix('.'))
                .map(str::to_string);
            if let Some(base) = base {
                app.save.path = format!("{base}.{new_ext}");
                app.save.cursor = app.save.path.len();
            }
        }
        KeyCode::Backspace => {
            if app.save.cursor > 0 {
                // Find the previous char boundary
                let prev = app.save.path[..app.save.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.save.path.remove(prev);
                app.save.cursor = prev;
            }
        }
        KeyCode::Delete => {
            // Forward-delete: drop the whole char at the cursor (kept on a
            // char boundary) and leave the cursor in place — the same gap the
            // filter dialog already filled.
            if app.save.cursor < app.save.path.len() {
                app.save.path.remove(app.save.cursor);
            }
        }
        KeyCode::Left => {
            if app.save.cursor > 0 {
                app.save.cursor = app.save.path[..app.save.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.save.cursor < app.save.path.len() {
                app.save.cursor = app.save.path[app.save.cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.save.cursor + i)
                    .unwrap_or(app.save.path.len());
            }
        }
        KeyCode::Home => {
            app.save.cursor = 0;
        }
        KeyCode::End => {
            app.save.cursor = app.save.path.len();
        }
        KeyCode::Char(c) => {
            app.save.path.insert(app.save.cursor, c);
            app.save.cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Unit tests for the save dialog's deferred-write behavior.
#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    /// Build an unmodified `KeyEvent` for `code`.
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Enter must not perform the (possibly long) write on the keypress:
    /// large exports froze the UI with no feedback. The write is deferred
    /// one event-loop tick so the "Saving…" status paints first.
    #[test]
    fn enter_defers_the_write_and_paints_saving_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let mut app = crate::tui::controllers::test_support::app_with_dialogs();
        app.save.format = SaveFormat::Txt;
        app.save.path = path.to_string_lossy().into_owned();
        app.active_popup = Some(Popup::SaveDialog);

        handle_save_popup_key(&mut app, key(KeyCode::Enter));

        assert!(app.active_popup.is_none(), "popup closes immediately");
        assert!(!path.exists(), "the write must NOT run on the keypress");
        assert!(
            app.pending_save.is_some(),
            "write deferred to the next tick"
        );
        assert!(
            app.status_error.as_deref().unwrap_or("").contains("Saving"),
            "got: {:?}",
            app.status_error
        );

        app.run_pending_save();

        assert!(path.exists(), "deferred write ran");
        assert!(app.pending_save.is_none());
        assert!(
            app.status_error.as_deref().unwrap_or("").contains("Saved"),
            "got: {:?}",
            app.status_error
        );
    }

    /// Delete removes the char AT the cursor (cursor stays put) and is a
    /// no-op at end-of-line — the same forward-delete the filter dialog had
    /// but the save dialog was missing.
    #[test]
    fn delete_removes_char_at_cursor() {
        let mut app = crate::tui::controllers::test_support::app_with_dialogs();
        app.active_popup = Some(Popup::SaveDialog);
        app.save.path = "/tmp/x".to_string();
        app.save.cursor = 0;

        handle_save_popup_key(&mut app, key(KeyCode::Delete));
        assert_eq!(app.save.path, "tmp/x");
        assert_eq!(app.save.cursor, 0);

        app.save.cursor = app.save.path.len();
        handle_save_popup_key(&mut app, key(KeyCode::Delete));
        assert_eq!(app.save.path, "tmp/x", "Delete at EOL is a no-op");
    }

    /// Enter on an empty or whitespace-only path must be rejected at the
    /// dialog — with a status message and the popup left open to fix it —
    /// rather than queuing a `PendingSave` whose write is guaranteed to
    /// fail on the next tick.
    #[test]
    fn enter_with_blank_path_is_rejected_without_queuing() {
        for blank in ["", "   ", "\t "] {
            let mut app = crate::tui::controllers::test_support::app_with_dialogs();
            app.save.format = SaveFormat::Txt;
            app.save.path = blank.to_string();
            app.active_popup = Some(Popup::SaveDialog);

            handle_save_popup_key(&mut app, key(KeyCode::Enter));

            assert!(
                app.pending_save.is_none(),
                "blank path {blank:?} must not queue a save"
            );
            assert_eq!(
                app.active_popup,
                Some(Popup::SaveDialog),
                "dialog stays open so the blank path {blank:?} can be corrected"
            );
            assert!(
                app.status_error
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("path"),
                "expected a path-rejection status for {blank:?}, got: {:?}",
                app.status_error
            );
        }
    }
}
