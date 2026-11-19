// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `Y` in the call list: copy the filter in force as a `sipnab … --filter
//! '…'` command line, and show it.

use std::sync::Arc;

use crate::tui::{App, KeyCode, KeyEvent, Popup, StatusMessage};

/// Copy the filter in force as a command line and show it in a popup.
///
/// The text goes to the clipboard the way every TUI copy does
/// ([`crate::tui::clipboard::spawn_clipboard_copy`]: OSC 52, then the
/// platform helper, on a worker thread), and the status line reports the
/// outcome. The popup shows the same text every time: an OSC 52 write is not
/// acknowledged, so the TUI cannot tell whether a clipboard took it.
///
/// # Side effects
/// With a filter in force: opens [`Popup::CommandLine`] and starts the copy.
/// Without one, or for text no shell word can carry: sets the status line
/// error and opens nothing.
pub(in crate::tui) fn copy_filter_command(app: &mut App) {
    copy_filter_command_with(app, crate::tui::clipboard::copy_to_clipboard);
}

/// [`copy_filter_command`] with the copy passed in; tests pass one that never
/// reaches a clipboard.
fn copy_filter_command_with(app: &mut App, copy: fn(&str) -> StatusMessage) {
    use crate::tui::filter_command::{command_source, filter_command, filter_text};
    let filter = filter_text(
        app.active_filter.as_ref(),
        app.active_time_after,
        app.active_time_before,
    );
    let command = command_source(app.rescan_path.as_deref(), &app.capture_source)
        .and_then(|source| filter_command(&source, filter.as_deref()));
    match command {
        Ok(command) => {
            crate::tui::clipboard::spawn_copy_worker(
                command.clone(),
                Arc::clone(&app.async_messages),
                copy,
            );
            app.status_error =
                Some("Copying the filter command line to the clipboard\u{2026}".to_owned());
            app.active_popup = Some(Popup::CommandLine(command));
        }
        Err(why) => app.set_status_error(why),
    }
}

/// Keys while [`Popup::CommandLine`] shows the copied command: `Esc`, `Enter`
/// and `q` close it; every other key is ignored.
pub(in crate::tui) fn handle_command_line_key(app: &mut App, key: KeyEvent) {
    if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
        app.active_popup = None;
    }
}

/// Tests of `Y` through the controller: the popup, the copy, the source
/// words, and that the copied command reproduces the call list.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::filter_dialog::expression_tests::{
        apply_typed, big_table, fixture_app, fixture_messages, ids, key, screen, shown,
    };
    use crate::tui::filter_command::sh_parse::sh_words;
    use crate::tui::{EXPRESSION_FIELD_IDX, TuiOptions};

    type TestError = Box<dyn std::error::Error>;

    /// The texts the fake copy was handed, for the tests that check them.
    static COPIED: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

    /// A copy that records the text and reports success, never touching a
    /// clipboard.
    fn fake_copy(text: &str) -> StatusMessage {
        COPIED.lock().push(text.to_owned());
        StatusMessage::info(format!("Copied {} bytes (test)", text.len()))
    }

    /// A copy that reports what `copy_outcome` reports with no mechanism.
    fn failing_copy(_: &str) -> StatusMessage {
        StatusMessage::error("Clipboard error: OSC 52 write failed and no pbcopy/xclip helper.")
    }

    /// The outcome the copy worker pushed, waiting at most ten seconds.
    fn outcome(app: &App) -> Result<StatusMessage, TestError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(m) = app.async_messages.lock().pop() {
                return Ok(m);
            }
            if std::time::Instant::now() >= deadline {
                return Err("the copy worker never reported".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The command the popup shows, if it is open.
    fn shown_command(app: &App) -> Option<String> {
        match &app.active_popup {
            Some(Popup::CommandLine(text)) => Some(text.clone()),
            _ => None,
        }
    }

    /// The fixture with `text` applied from the Expression field, the popup
    /// closed, on the call list.
    fn filtered(text: &str) -> Result<App, TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, text);
        if let Some(e) = &app.filter_dialog.error {
            return Err(format!("{text:?} was refused: {e}").into());
        }
        Ok(app)
    }

    /// `Y` with a filter in force opens the popup with the command.
    #[test]
    fn y_shows_the_command_for_the_filter_in_force() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        app.capture_source = vec!["-I".into(), "/cases/a.pcap".into()];
        copy_filter_command_with(&mut app, fake_copy);
        assert_eq!(
            shown_command(&app).as_deref(),
            Some("sipnab -I /cases/a.pcap --filter 'msg_count > 5'"),
            "the popup shows the command"
        );
        Ok(())
    }

    /// The text copied is the text shown.
    #[test]
    fn the_copied_text_is_the_shown_text() -> Result<(), TestError> {
        let mut app = filtered("payload =~ 'X-Foo' AND msg_count > 5")?;
        copy_filter_command_with(&mut app, fake_copy);
        let shown_text = shown_command(&app).ok_or("no popup")?;
        let reported = outcome(&app)?;
        assert!(
            !reported.is_error,
            "the fake copy succeeds: {}",
            reported.text
        );
        assert!(
            COPIED.lock().contains(&shown_text),
            "the copy was handed the shown text {shown_text:?}"
        );
        Ok(())
    }

    /// The status line says a copy is under way until the worker reports.
    #[test]
    fn the_status_line_says_the_copy_is_under_way() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        copy_filter_command_with(&mut app, fake_copy);
        assert_eq!(
            app.status_error.as_deref(),
            Some("Copying the filter command line to the clipboard\u{2026}"),
            "the copy is said at once"
        );
        Ok(())
    }

    /// With no clipboard, the worker reports the error and the command stays
    /// on screen to be read or selected.
    #[test]
    fn with_no_clipboard_the_command_stays_shown() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        copy_filter_command_with(&mut app, failing_copy);
        let reported = outcome(&app)?;
        assert!(
            reported.is_error,
            "the failure is reported: {}",
            reported.text
        );
        assert!(
            shown_command(&app).is_some_and(|c| c.contains("--filter 'msg_count > 5'")),
            "the command is still shown"
        );
        Ok(())
    }

    /// No filter in force: nothing opens and the status line says why.
    #[test]
    fn y_without_a_filter_opens_nothing() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.active_popup = None;
        copy_filter_command_with(&mut app, fake_copy);
        assert_eq!(shown_command(&app), None, "no popup");
        let status = app.status_error.clone().unwrap_or_default();
        assert!(status.contains("No view filter"), "says why: {status:?}");
        Ok(())
    }

    /// A cleared filter is no filter: `Y` after `F9` opens nothing.
    #[test]
    fn y_after_a_clear_opens_nothing() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        app.clear_active_filter();
        copy_filter_command_with(&mut app, fake_copy);
        assert_eq!(shown_command(&app), None, "nothing in force");
        Ok(())
    }

    /// A capture path that is not UTF-8 is refused on the status line.
    #[test]
    fn a_path_that_is_not_utf8_is_refused() -> Result<(), TestError> {
        use std::os::unix::ffi::OsStrExt as _;
        let mut app = filtered("msg_count > 5")?;
        app.rescan_path = Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/cases/\xff.pcap",
        )));
        copy_filter_command_with(&mut app, fake_copy);
        assert_eq!(shown_command(&app), None, "no popup");
        let status = app.status_error.clone().unwrap_or_default();
        assert!(status.contains("not valid UTF-8"), "says why: {status:?}");
        Ok(())
    }

    /// The one file read now names the source, over the start's words.
    #[test]
    fn the_file_read_now_names_the_source() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        app.capture_source = vec!["-d".into(), "eth0".into()];
        app.rescan_path = Some(std::path::PathBuf::from("/cases/opened.pcap"));
        copy_filter_command_with(&mut app, fake_copy);
        let command = shown_command(&app).ok_or("no popup")?;
        assert!(
            command.starts_with("sipnab -I /cases/opened.pcap --filter "),
            "{command}"
        );
        Ok(())
    }

    /// The `Y` key in the call list is the copy.
    #[test]
    fn the_y_key_in_the_call_list_is_the_copy() -> Result<(), TestError> {
        let km = crate::tui::Keymap::default();
        assert_eq!(
            crate::tui::controllers::call_list_action(&km, key(KeyCode::Char('Y'))),
            Some(crate::tui::controllers::CallListAction::CopyFilterCommand),
            "Y maps to the copy"
        );
        Ok(())
    }

    /// `Esc`, `Enter` and `q` close the popup; another key leaves it open.
    #[test]
    fn the_popup_closes_on_esc_enter_and_q_only() -> Result<(), TestError> {
        for closer in [KeyCode::Esc, KeyCode::Enter, KeyCode::Char('q')] {
            let mut app = filtered("msg_count > 5")?;
            copy_filter_command_with(&mut app, fake_copy);
            handle_command_line_key(&mut app, key(KeyCode::Char('x')));
            assert!(shown_command(&app).is_some(), "x leaves it open");
            handle_command_line_key(&mut app, key(closer));
            assert_eq!(app.active_popup, None, "{closer:?} closes it");
        }
        Ok(())
    }

    /// Over the call list, the popup shows the command and the closing key.
    #[test]
    fn the_popup_is_drawn_over_the_call_list() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        copy_filter_command_with(&mut app, fake_copy);
        let text = screen(&mut app, 80, 24)?;
        assert!(
            text.contains("sipnab --filter 'msg_count > 5'"),
            "the command is on screen:\n{text}"
        );
        assert!(text.contains("Command line"), "the popup's title:\n{text}");
        Ok(())
    }

    /// The copied command, started again, shows the same call list: every F7
    /// field, a named filter, the Expression and the time window together.
    #[test]
    fn the_copied_command_reproduces_the_call_list() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.named_filters = big_table()?;
        app.filter_dialog.sip_from = "alice".into();
        app.filter_dialog.payload = "X-Foo".into();
        app.filter_dialog.named = "big".into();
        app.filter_dialog.time_after = "2020-01-01T00:00:00Z".into();
        apply_typed(&mut app, "NOT payload =~ 'OPTIONS' OR msg_count == 2");
        assert_eq!(app.filter_dialog.error, None, "the dialog applied");
        let before = shown(&mut app);
        assert_eq!(before, ids(&["foo-big"]), "the fixture narrows to one call");
        copy_filter_command_with(&mut app, fake_copy);
        let command = shown_command(&app).ok_or("no popup")?;
        let words = sh_words(&command)?;
        let at = words
            .iter()
            .position(|w| w == "--filter")
            .ok_or("no --filter word")?;
        let filter = words.get(at + 1).ok_or("no filter after --filter")?;
        let fixture = App::with_processed_messages(fixture_messages()?);
        let mut again = TuiOptions {
            filter_expression: Some(filter.clone()),
            ..TuiOptions::default()
        }
        .into_app(
            Arc::clone(&fixture.dialog_store),
            Arc::clone(&fixture.stream_store),
        );
        assert_eq!(again.filter_dialog.error, None, "the copied filter applies");
        assert_eq!(
            shown(&mut again),
            before,
            "the same call list from {filter:?}"
        );
        Ok(())
    }

    /// Calls-only (`-c`) is part of the copied filter: the methods it leaves
    /// out stay out.
    #[test]
    fn calls_only_is_part_of_the_copied_filter() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        crate::tui::controllers::start_calls_only(&mut app);
        let before = shown(&mut app);
        assert!(
            !before.contains(&"foo-opts".to_owned()),
            "OPTIONS left out: {before:?}"
        );
        copy_filter_command_with(&mut app, fake_copy);
        let command = shown_command(&app).ok_or("no popup")?;
        assert!(
            command.contains("INVITE"),
            "the method filter is copied: {command}"
        );
        Ok(())
    }

    /// A refused Expression does not change what `Y` copies: the filter in
    /// force is copied, not the text in the field.
    #[test]
    fn a_refused_expression_is_not_copied() -> Result<(), TestError> {
        let mut app = filtered("msg_count > 5")?;
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        apply_typed(&mut app, "msg_count = 5");
        assert!(app.filter_dialog.error.is_some(), "refused");
        app.active_popup = None;
        copy_filter_command_with(&mut app, fake_copy);
        let command = shown_command(&app).ok_or("no popup")?;
        assert!(command.ends_with("--filter 'msg_count > 5'"), "{command}");
        Ok(())
    }
}
