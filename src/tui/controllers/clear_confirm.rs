// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The confirmation before a clear that cannot be undone.
//!
//! `F5`/`Ctrl+L` (clear calls) and `i`/`I` (clear the dialogs that do not, or
//! do, match the view filter) discard dialogs and their RTP streams. From a
//! file that costs nothing: `O` reads the file again. From a live capture the
//! packets are gone, and one keypress did it. So a clear asks first only
//! during a live capture, and only when it would discard something.

use crate::tui::controllers::call_list::{clear_calls, clear_matching, clear_non_matching};
use crate::tui::{App, ClearKind, KeyCode, KeyEvent, Popup};

/// Whether a clear of `held` dialogs must ask first: only when the data came
/// from a live capture, which cannot be read again, and there is any. Pure.
pub(in crate::tui) fn clear_needs_confirmation(live: bool, held: usize) -> bool {
    live && held > 0
}

/// What a clear of `kind` would discard, as the popup says it. Pure.
///
/// # Arguments
/// * `kind` - which clear was asked for.
/// * `dialogs` - dialogs the store holds.
/// * `streams` - RTP streams the store holds.
/// * `checked` - dialogs checked with Space; a clear of calls removes only
///   those when there are any.
pub(in crate::tui) fn clear_summary(
    kind: ClearKind,
    dialogs: usize,
    streams: usize,
    checked: usize,
) -> String {
    use crate::tui::count_noun;
    match kind {
        ClearKind::Calls if checked > 0 => format!(
            "Discard the {} and their RTP streams?",
            count_noun(checked, "checked dialog", "checked dialogs")
        ),
        ClearKind::Calls => format!(
            "Discard {} {} and {}?",
            if dialogs == 1 { "the" } else { "all" },
            count_noun(dialogs, "dialog", "dialogs"),
            count_noun(streams, "RTP stream", "RTP streams")
        ),
        ClearKind::NonMatching => {
            format!("Discard every dialog the view filter does not match, of {dialogs} held?")
        }
        ClearKind::Matching => {
            format!("Discard every dialog the view filter matches, of {dialogs} held?")
        }
    }
}

/// Run the clear `kind` names, at once.
fn run_clear(app: &mut App, kind: ClearKind) {
    match kind {
        ClearKind::Calls => clear_calls(app),
        ClearKind::NonMatching => clear_non_matching(app),
        ClearKind::Matching => clear_matching(app),
    }
}

/// Clear, or ask first when the clear cannot be undone.
///
/// # Side effects
/// From a file, or with nothing to discard, runs the clear at once, as
/// before. During a live capture opens [`Popup::ClearConfirm`] and clears
/// nothing until it is answered. `i`/`I` with no view filter do nothing, as
/// before, and do not ask.
pub(in crate::tui) fn request_clear(app: &mut App, kind: ClearKind) {
    // `i`/`I` without a view filter clear nothing; asking would be a
    // question about nothing.
    let clears_nothing = kind != ClearKind::Calls && app.active_filter.is_none();
    // The same test the status line uses to say "Live capture".
    let live = app.capture_mode.starts_with("Online");
    let held = app.dialog_store.read().len();
    if !clears_nothing && clear_needs_confirmation(live, held) {
        app.active_popup = Some(Popup::ClearConfirm(kind));
    } else {
        run_clear(app, kind);
    }
}

/// Handle keys while the clear confirmation is open.
///
/// # Side effects
/// `y`/`Y` runs the clear. `n`/`N`/`q`/`Esc` and Enter close the popup and
/// discard nothing: No is the default, so Enter is No. Every other key is
/// ignored, so a stray keypress does not answer the question.
pub(in crate::tui) fn handle_clear_confirm_key(app: &mut App, key: KeyEvent) {
    let Some(Popup::ClearConfirm(kind)) = app.active_popup else {
        return;
    };
    match key.code {
        KeyCode::Char('y' | 'Y') => {
            app.active_popup = None;
            run_clear(app, kind);
        }
        KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc | KeyCode::Enter => {
            app.active_popup = None;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::handle_key_event;
    use crate::tui::render::test_support::{TestError, app_with_dialog};
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// An app holding one dialog, from a live capture or from a file.
    fn app_holding_a_call(live: bool) -> Result<App, TestError> {
        let mut app = app_with_dialog()?;
        app.set_capture_mode(if live {
            "Online (eth0)".to_string()
        } else {
            "Offline (call.pcap)".to_string()
        });
        Ok(app)
    }

    fn held(app: &App) -> usize {
        app.dialog_store.read().len()
    }

    /// Failure: F5 during a live capture discards nothing; it asks.
    #[test]
    fn f5_during_a_live_capture_asks_and_discards_nothing() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(&mut app, key(KeyCode::F(5)));
        assert_eq!(held(&app), 1, "nothing is discarded before the answer");
        assert_eq!(
            app.active_popup,
            Some(Popup::ClearConfirm(ClearKind::Calls)),
            "the question is open"
        );
        Ok(())
    }

    /// Failure: Ctrl+L during a live capture asks as F5 does.
    #[test]
    fn ctrl_l_during_a_live_capture_asks() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL),
        );
        assert_eq!(held(&app), 1, "nothing is discarded before the answer");
        assert_eq!(
            app.active_popup,
            Some(Popup::ClearConfirm(ClearKind::Calls)),
            "the question is open"
        );
        Ok(())
    }

    /// Success: F5 on a file clears at once, as before. The file can be
    /// read again.
    #[test]
    fn f5_on_a_file_clears_at_once() -> Result<(), TestError> {
        let mut app = app_holding_a_call(false)?;
        handle_key_event(&mut app, key(KeyCode::F(5)));
        assert_eq!(held(&app), 0, "cleared");
        assert_eq!(app.active_popup, None, "no question");
        Ok(())
    }

    /// Success: `y` answers the question and the clear runs.
    #[test]
    fn y_discards() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(&mut app, key(KeyCode::F(5)));
        handle_key_event(&mut app, key(KeyCode::Char('y')));
        assert_eq!(held(&app), 0, "cleared");
        assert_eq!(app.active_popup, None, "the question is closed");
        Ok(())
    }

    /// Failure: Enter is the default answer, No. It closes the question and
    /// discards nothing.
    #[test]
    fn enter_is_no() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(&mut app, key(KeyCode::F(5)));
        handle_key_event(&mut app, key(KeyCode::Enter));
        assert_eq!(held(&app), 1, "nothing is discarded");
        assert_eq!(app.active_popup, None, "the question is closed");
        Ok(())
    }

    /// Failure: `n` and Esc each close the question and discard nothing.
    #[test]
    fn n_and_esc_keep_the_calls() -> Result<(), TestError> {
        for code in [KeyCode::Char('n'), KeyCode::Char('N'), KeyCode::Esc] {
            let mut app = app_holding_a_call(true)?;
            handle_key_event(&mut app, key(KeyCode::F(5)));
            handle_key_event(&mut app, key(code));
            assert_eq!(held(&app), 1, "{code:?} discards nothing");
            assert_eq!(app.active_popup, None, "{code:?} closes the question");
        }
        Ok(())
    }

    /// Edge: a key that is not an answer leaves the question open and
    /// discards nothing.
    #[test]
    fn a_stray_key_does_not_answer() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(&mut app, key(KeyCode::F(5)));
        handle_key_event(&mut app, key(KeyCode::Char('x')));
        assert_eq!(held(&app), 1, "nothing is discarded");
        assert_eq!(
            app.active_popup,
            Some(Popup::ClearConfirm(ClearKind::Calls)),
            "still asking"
        );
        Ok(())
    }

    /// Edge: a second F5 while the question is open is not a Yes.
    #[test]
    fn a_second_f5_is_not_an_answer() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(&mut app, key(KeyCode::F(5)));
        handle_key_event(&mut app, key(KeyCode::F(5)));
        assert_eq!(held(&app), 1, "nothing is discarded");
        Ok(())
    }

    /// Edge: with nothing held there is nothing to lose, so a live capture
    /// does not ask either.
    #[test]
    fn an_empty_live_capture_does_not_ask() {
        let mut app = App::with_processed_messages(Vec::new());
        app.set_capture_mode("Online (eth0)".to_string());
        handle_key_event(&mut app, key(KeyCode::F(5)));
        assert_eq!(app.active_popup, None, "no question over nothing");
    }

    /// Edge: `i` with no view filter does nothing, as before, and does not
    /// ask.
    #[test]
    fn i_without_a_view_filter_does_not_ask() -> Result<(), TestError> {
        let mut app = app_holding_a_call(true)?;
        handle_key_event(&mut app, key(KeyCode::Char('i')));
        assert_eq!(app.active_popup, None, "no question");
        assert_eq!(held(&app), 1, "nothing is discarded");
        Ok(())
    }

    /// Success: the rule is the capture's source and whether it holds
    /// anything, nothing else.
    #[test]
    fn only_a_live_capture_that_holds_something_asks() {
        assert!(clear_needs_confirmation(true, 1), "live, one dialog");
        assert!(!clear_needs_confirmation(false, 1), "a file");
        assert!(!clear_needs_confirmation(true, 0), "live, nothing held");
        assert!(!clear_needs_confirmation(false, 0), "a file, nothing held");
    }

    /// Success: the question names everything a clear of calls discards,
    /// with the counts.
    #[test]
    fn the_summary_counts_the_dialogs_and_streams() {
        assert_eq!(
            clear_summary(ClearKind::Calls, 12, 3, 0),
            "Discard all 12 dialogs and 3 RTP streams?",
            "everything held"
        );
    }

    /// Edge: one of each reads in the singular.
    #[test]
    fn the_summary_reads_in_the_singular() {
        assert_eq!(
            clear_summary(ClearKind::Calls, 1, 1, 0),
            "Discard the 1 dialog and 1 RTP stream?",
            "one of each"
        );
    }

    /// Edge: with dialogs checked, a clear of calls removes only those, and
    /// the question says so.
    #[test]
    fn the_summary_names_the_checked_dialogs() {
        assert_eq!(
            clear_summary(ClearKind::Calls, 12, 3, 2),
            "Discard the 2 checked dialogs and their RTP streams?",
            "only the checked ones"
        );
    }

    /// Success: `i` and `I` are named by what they keep and discard.
    #[test]
    fn the_summary_names_the_filter_clears() {
        assert_eq!(
            clear_summary(ClearKind::NonMatching, 12, 3, 0),
            "Discard every dialog the view filter does not match, of 12 held?",
            "i"
        );
        assert_eq!(
            clear_summary(ClearKind::Matching, 12, 3, 0),
            "Discard every dialog the view filter matches, of 12 held?",
            "I"
        );
    }
}
