// SPDX-License-Identifier: MIT OR Apache-2.0

//! The quit-confirmation popup.
//!
//! Reported as [issue #283](https://github.com/NormB/sipnab/issues/283) by
//! WangKLi: `Esc` ended the session outright, and `Esc` is the key a terminal
//! user presses reflexively to back out of things. In every other view here it
//! means "go back" — in the call list it meant "go away", and a capture that
//! has been running for an hour does not survive the difference.
//!
//! `Ctrl-C` keeps quitting immediately. It is the one gesture nobody presses by
//! accident, and a TUI that cannot be closed without answering a question is
//! its own kind of trap — scripts and stuck terminals need a way out that does
//! not depend on the popup rendering correctly.

use crate::tui::*;

/// Ask before quitting, rather than quitting.
///
/// Every view's `Quit` action routes here. Seven of them used to set
/// `should_quit` themselves, which is seven places to remember when the answer
/// to "should this really exit?" changes.
///
/// # Side effects
/// Opens [`Popup::QuitConfirm`]. Does NOT set `should_quit` — nothing quits
/// until the popup is answered.
pub(in crate::tui) fn request_quit(app: &mut App) {
    app.active_popup = Some(Popup::QuitConfirm);
}

/// Handle keys while the quit confirmation is open.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly.
///
/// # Side effects
/// `y`/`Y`/Enter quits. `n`/`N`/`Esc`/`q` closes the popup and returns to
/// whatever view was underneath. Every other key is ignored rather than
/// treated as a cancel: a stray keypress against an open dialog must not
/// dismiss the question the dialog is asking.
pub(in crate::tui) fn handle_quit_confirm_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
            app.active_popup = None;
            app.should_quit = true;
        }
        KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc => {
            app.active_popup = None;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Esc opens the question instead of ending the session.
    ///
    /// The defect issue #283 reports: one reflexive keypress ended a capture
    /// that had been running for an hour.
    #[test]
    fn esc_asks_rather_than_quitting() {
        let mut app = App::with_processed_messages(Vec::new());
        crate::tui::controllers::handle_key_event(&mut app, key(KeyCode::Esc));
        assert!(
            !app.should_quit,
            "Esc must not end the session on its own any more"
        );
        assert_eq!(
            app.active_popup,
            Some(Popup::QuitConfirm),
            "it opens the confirmation instead"
        );
    }

    /// The configured quit key asks too.
    #[test]
    fn the_quit_key_asks_rather_than_quitting() {
        let mut app = App::with_processed_messages(Vec::new());
        let q = app.keymap.quit;
        crate::tui::controllers::handle_key_event(&mut app, key(q));
        assert!(!app.should_quit);
        assert_eq!(app.active_popup, Some(Popup::QuitConfirm));
    }

    /// Answering yes quits, and closes the popup on the way out.
    #[test]
    fn y_quits() {
        for answer in [KeyCode::Char('y'), KeyCode::Char('Y'), KeyCode::Enter] {
            let mut app = App::with_processed_messages(Vec::new());
            request_quit(&mut app);
            handle_quit_confirm_key(&mut app, key(answer));
            assert!(app.should_quit, "{answer:?} must quit");
            assert_eq!(
                app.active_popup, None,
                "{answer:?} leaves no popup behind for the next frame to draw"
            );
        }
    }

    /// Answering no returns to the session with nothing lost.
    #[test]
    fn n_and_esc_cancel() {
        for answer in [
            KeyCode::Char('n'),
            KeyCode::Char('N'),
            KeyCode::Esc,
            KeyCode::Char('q'),
        ] {
            let mut app = App::with_processed_messages(Vec::new());
            request_quit(&mut app);
            handle_quit_confirm_key(&mut app, key(answer));
            assert!(!app.should_quit, "{answer:?} must not quit");
            assert_eq!(app.active_popup, None, "{answer:?} closes the popup");
        }
    }

    /// A key that is neither yes nor no leaves the question standing.
    ///
    /// Treating any keypress as a cancel would make the dialog vanish under a
    /// typist's hands; treating one as a yes would be worse.
    #[test]
    fn an_unrelated_key_neither_quits_nor_dismisses() {
        for stray in [
            KeyCode::Char('x'),
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Tab,
            KeyCode::Char('k'),
        ] {
            let mut app = App::with_processed_messages(Vec::new());
            request_quit(&mut app);
            handle_quit_confirm_key(&mut app, key(stray));
            assert!(!app.should_quit, "{stray:?} must not quit");
            assert_eq!(
                app.active_popup,
                Some(Popup::QuitConfirm),
                "{stray:?} must leave the question standing"
            );
        }
    }

    /// Ctrl-C still ends the session outright.
    ///
    /// The issue asks for this explicitly, and it is the escape hatch that
    /// keeps the popup from being a trap: a terminal that cannot be closed
    /// without answering a question is worse than the accident being fixed.
    #[test]
    fn ctrl_c_still_quits_immediately() {
        let mut app = App::with_processed_messages(Vec::new());
        crate::tui::controllers::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );
        assert!(app.should_quit, "Ctrl-C is the unconditional exit");
        assert_eq!(
            app.active_popup, None,
            "and it does not stop to ask on the way"
        );
    }

    /// Ctrl-C works while the confirmation itself is open.
    ///
    /// The popup handler runs before the view handlers, so a Ctrl-C that had
    /// to pass through it would be swallowed by the `_ => {}` arm — and the
    /// one guaranteed way out would be gone exactly when a user is looking
    /// for it.
    #[test]
    fn ctrl_c_escapes_the_confirmation_itself() {
        let mut app = App::with_processed_messages(Vec::new());
        request_quit(&mut app);
        crate::tui::controllers::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );
        assert!(
            app.should_quit,
            "Ctrl-C must not be swallowed by the open dialog"
        );
    }
}
