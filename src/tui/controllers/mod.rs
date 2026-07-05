//! Keyboard and mouse event handling for every view and popup — the
//! controller layer of the TUI. Per-view/per-popup handlers live in the
//! submodules; this module owns the top-level dispatchers plus the small
//! view handlers (help, statistics, settings) and shared selection helpers.

use super::*;

mod call_flow;
mod call_list;
mod file_open;
mod filter_dialog;
mod name_dialog;
mod save_dialog;
mod stream;

pub(in crate::tui) use call_flow::*;
pub(in crate::tui) use call_list::*;
// Re-exported at `tui` scope so keybinding_drift_test can probe the
// key→action mapping table directly (same exposure as Keymap/HELP_TEXT).
pub use call_list::{CallListAction, call_list_action};
pub(in crate::tui) use file_open::*;
pub(in crate::tui) use filter_dialog::*;
pub(in crate::tui) use name_dialog::*;
pub(in crate::tui) use save_dialog::*;
pub(in crate::tui) use stream::*;

/// Dispatch a key event to the handler for the current view.
pub(in crate::tui) fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Global shortcuts (Ctrl-C always quits)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    // Popup input takes priority over everything else
    if app.active_popup.is_some() {
        handle_popup_key(app, key);
        return;
    }

    // Search mode input
    if app.search_active {
        handle_search_input(app, key);
        return;
    }

    // Global fallback keys ('v'/'V' version, 'n' name-mode cycle) apply in
    // every view — but a key the user explicitly rebound in the keymap wins,
    // so a rebind can never be shadowed by these built-ins.
    let km = &app.keymap;
    let keymap_bound = [
        km.quit,
        km.help,
        km.save,
        km.search,
        km.filter,
        km.settings,
        km.pause,
        km.autoscroll,
        km.extended_flow,
        km.clear_calls,
        km.column_selector,
    ]
    .contains(&key.code);
    if !keymap_bound {
        if matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V')) {
            app.status_error = Some(format!("sipnab {}", crate::cli::build_version()));
            return;
        }
        // Cycle name-resolution mode (Off / Static / DNS).
        if key.code == KeyCode::Char('n') {
            app.name_mode = app.name_mode.next();
            app.status_error = Some(app.name_mode.label().to_string());
            return;
        }
    }

    match &app.current_view {
        View::CallList => handle_call_list_key(app, key),
        View::StreamList => handle_stream_list_key(app, key),
        View::StreamDetail(_) => handle_stream_detail_key(app, key),
        View::CallFlow(_) => handle_call_flow_key(app, key),
        View::RawMessage { .. } => handle_raw_message_key(app, key),
        View::MessageDiff { .. } => handle_message_diff_key(app, key),
        View::CombinedDetail { .. } => handle_combined_detail_key(app, key),
        View::Help => handle_help_key(app, key),
        View::Statistics => handle_statistics_key(app, key),
    }
}

/// Handle search input mode.
pub(in crate::tui) fn handle_search_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.search_active = false;
            app.search_query.clear();
        }
        KeyCode::Enter => {
            app.search_active = false;
            // search_query remains for highlighting
        }
        KeyCode::Backspace => {
            app.search_query.pop();
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
        }
        _ => {}
    }
}

/// Handle keys in the help view.
pub(in crate::tui) fn handle_help_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == KeyCode::Esc || k == app.keymap.help || k == app.keymap.quit => {
            app.current_view = View::CallList;
            app.help_scroll = 0; // start at the top next time
        }
        // The help can exceed the screen; allow scrolling. render() clamps the
        // offset to the content height, so over-scrolling self-corrects.
        KeyCode::Down | KeyCode::Char('j') => app.help_scroll = app.help_scroll.saturating_add(1),
        KeyCode::Up | KeyCode::Char('k') => app.help_scroll = app.help_scroll.saturating_sub(1),
        KeyCode::PageDown => app.help_scroll = app.help_scroll.saturating_add(10),
        KeyCode::PageUp => app.help_scroll = app.help_scroll.saturating_sub(10),
        KeyCode::Home => app.help_scroll = 0,
        KeyCode::End => app.help_scroll = u16::MAX, // clamped to content in render
        _ => {}
    }
}

/// Handle keys for any active popup dialog.
pub(in crate::tui) fn handle_popup_key(app: &mut App, key: KeyEvent) {
    let popup = match &app.active_popup {
        Some(p) => p.clone(),
        None => return,
    };

    match popup {
        Popup::SaveDialog => handle_save_popup_key(app, key),
        Popup::FilterDialog => handle_filter_popup_key(app, key),
        Popup::SettingsDialog => handle_settings_popup_key(app, key),
        Popup::FileOpenDialog => handle_file_open_popup_key(app, key),
        Popup::NameAddress => handle_name_popup_key(app, key),
    }
}

/// Handle keys in the settings popup.
pub(in crate::tui) fn handle_settings_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.settings_dialog.focused_item > 0 {
                app.settings_dialog.focused_item -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.settings_dialog.focused_item + 1 < SETTINGS_ITEM_COUNT {
                app.settings_dialog.focused_item += 1;
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => match app.settings_dialog.focused_item {
            0 => app.color_mode = app.color_mode.next(),
            1 => app.timestamp_mode = app.timestamp_mode.next(),
            2 => app.call_list.autoscroll = !app.call_list.autoscroll,
            3 => app.flow.raw_preview = !app.flow.raw_preview,
            4 => app.sdp_display_mode = app.sdp_display_mode.next(),
            5 => app.syntax_highlight = !app.syntax_highlight,
            _ => {}
        },
        _ => {}
    }
}

/// Handle keys in the statistics view.
pub(in crate::tui) fn handle_statistics_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == KeyCode::Esc || k == app.keymap.quit || k == KeyCode::Char('s') => {
            app.current_view = View::CallList;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.stats_scroll = app.stats_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.stats_scroll = app.stats_scroll.saturating_add(1);
        }
        KeyCode::PageUp => app.stats_scroll = app.stats_scroll.saturating_sub(20),
        KeyCode::PageDown => app.stats_scroll = app.stats_scroll.saturating_add(20),
        KeyCode::Home => app.stats_scroll = 0,
        // Clamped to the content height by the render pass.
        KeyCode::End => app.stats_scroll = u16::MAX,
        _ => {}
    }
}

/// Handle a mouse event (wheel scrolling) against the current view.
///
/// Wheel steps: one row in the list/ladder views (selection follows, like
/// Up/Down), three rows in the free-scrolling text views.
pub(in crate::tui) fn handle_mouse_event(app: &mut App, kind: crossterm::event::MouseEventKind) {
    use crossterm::event::MouseEventKind as MK;
    let down = match kind {
        MK::ScrollDown => true,
        MK::ScrollUp => false,
        _ => return,
    };
    // Popups own the input; wheel is ignored while one is open.
    if app.active_popup.is_some() {
        return;
    }
    match &app.current_view {
        View::CallList => {
            if down {
                let count = filtered_dialog_count(app);
                app.call_list.move_down(count);
            } else {
                app.call_list.move_up();
            }
        }
        View::StreamList => {
            if down {
                let ss = app.stream_store.read();
                let ds = app.dialog_store.try_read();
                let count = crate::tui::stream_list::displayed_streams(
                    ss.iter(),
                    ds.as_deref(),
                    app.active_filter.as_ref(),
                    &app.search_query,
                )
                .len();
                drop(ss);
                app.stream_list.move_down(count);
            } else {
                app.stream_list.move_up();
            }
        }
        View::CallFlow(_) => {
            if down {
                let count = app.flow.cached_msg_count;
                if count > 0 && app.flow.selected < count - 1 {
                    app.flow.selected += 1;
                    app.flow.detail_scroll = 0;
                }
            } else if app.flow.selected > 0 {
                app.flow.selected -= 1;
                app.flow.detail_scroll = 0;
            }
        }
        View::RawMessage { .. } | View::CombinedDetail { .. } => {
            app.raw_msg_scroll = if down {
                app.raw_msg_scroll.saturating_add(3)
            } else {
                app.raw_msg_scroll.saturating_sub(3)
            };
        }
        View::MessageDiff { .. } => {
            app.diff_scroll = if down {
                app.diff_scroll.saturating_add(3)
            } else {
                app.diff_scroll.saturating_sub(3)
            };
        }
        View::StreamDetail(_) => {
            app.stream_detail_scroll = if down {
                app.stream_detail_scroll.saturating_add(3)
            } else {
                app.stream_detail_scroll.saturating_sub(3)
            };
        }
        View::Help => {
            app.help_scroll = if down {
                app.help_scroll.saturating_add(3)
            } else {
                app.help_scroll.saturating_sub(3)
            };
        }
        View::Statistics => {
            app.stats_scroll = if down {
                app.stats_scroll.saturating_add(3)
            } else {
                app.stats_scroll.saturating_sub(3)
            };
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Get the Call-ID of the currently selected dialog in the call list.
///
/// Resolves against the DISPLAYED list — filter + search + sort, the same
/// `displayed_dialogs` the renderer draws — so the selection always opens
/// exactly the row the user sees highlighted.
pub(in crate::tui) fn get_selected_call_id(app: &App) -> Option<String> {
    let store = app.dialog_store.read();
    let dialogs = crate::tui::call_list::displayed_dialogs(
        &store,
        app.active_filter.as_ref(),
        &app.search_query,
        app.call_list.sort_column(),
        app.call_list.sort_ascending(),
    );
    let idx = app.call_list.selected();
    dialogs.get(idx).map(|d| d.call_id.clone())
}

/// Count dialogs visible after applying the active filter.
pub(in crate::tui) fn filtered_dialog_count(app: &App) -> usize {
    let store = app.dialog_store.read();
    // Count exactly the rows the renderer displays (filter + search), so
    // navigation clamps to what is on screen.
    crate::tui::call_list::displayed_dialogs(
        &store,
        app.active_filter.as_ref(),
        &app.search_query,
        app.call_list.sort_column(),
        app.call_list.sort_ascending(),
    )
    .len()
}

// ── Tests ───────────────────────────────────────────────────────────

/// Construction helpers shared by the controller unit tests
/// (mirroring `tests/tui_state_test.rs`).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    pub(crate) fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    pub(crate) fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    pub(crate) fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    pub(crate) fn raw_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg
    }

    pub(crate) fn make_invite(
        call_id: &str,
        from: &str,
        to: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = raw_sip(
            &format!("INVITE sip:{to}@example.com SIP/2.0"),
            &[
                &format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1"),
                &format!("To: \"{to}\" <sip:{to}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            addr_a(),
            addr_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse INVITE")
    }

    pub(crate) fn make_ok(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = raw_sip(
            "SIP/2.0 200 OK",
            &[
                "From: \"a\" <sip:a@example.com>;tag=t1",
                "To: \"b\" <sip:b@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            addr_b(),
            addr_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 200")
    }

    pub(crate) fn app_with_dialogs() -> App {
        let t0 = base_ts();
        App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", t0),
            make_ok("call-1@test", t0 + TimeDelta::seconds(1)),
            make_invite("call-2@test", "1003", "1004", t0 + TimeDelta::seconds(5)),
            make_ok("call-2@test", t0 + TimeDelta::seconds(6)),
            make_invite("call-3@test", "1005", "1006", t0 + TimeDelta::seconds(10)),
            make_ok("call-3@test", t0 + TimeDelta::seconds(11)),
        ])
    }

    pub(crate) fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    pub(crate) fn key_mod(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }

    pub(crate) fn open_call_flow(app: &mut App) {
        handle_call_list_key(app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    #[test]
    fn key_event_ctrl_c_quits() {
        let mut app = App::new_test();
        handle_key_event(&mut app, key_mod(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
    }

    #[test]
    fn key_event_routes_to_popup_first() {
        let mut app = app_with_dialogs();
        app.active_popup = Some(Popup::SaveDialog);
        // Esc inside save popup closes it (handled by popup handler, not view)
        handle_key_event(&mut app, key(KeyCode::Esc));
        assert_eq!(app.active_popup, None);
    }

    #[test]
    fn key_event_routes_to_search_when_active() {
        let mut app = App::new_test();
        app.search_active = true;
        handle_key_event(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.search_query, "z");
        assert!(app.search_active);
    }

    #[test]
    fn key_event_dispatches_by_view() {
        let mut app = App::new_test();
        handle_key_event(&mut app, key(KeyCode::Tab));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn key_event_n_cycles_name_mode() {
        let mut app = App::new_test();
        assert_eq!(app.name_mode(), crate::names::NameMode::Off);
        handle_key_event(&mut app, key(KeyCode::Char('n')));
        assert_eq!(app.name_mode(), crate::names::NameMode::Names);
        handle_key_event(&mut app, key(KeyCode::Char('n')));
        assert_eq!(app.name_mode(), crate::names::NameMode::Dns);
        handle_key_event(&mut app, key(KeyCode::Char('n')));
        assert_eq!(app.name_mode(), crate::names::NameMode::Off);
    }

    #[test]
    fn key_event_v_shows_version_globally() {
        let mut app = App::new_test();
        handle_key_event(&mut app, key(KeyCode::Char('v')));
        let status = app.status_error.clone().expect("version status set");
        assert!(status.starts_with("sipnab"), "got: {status}");
        assert!(status.contains(env!("CARGO_PKG_VERSION")), "got: {status}");
        // Showing the version must not change the current view.
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn key_event_shift_v_shows_version_in_any_view() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_key_event(&mut app, key(KeyCode::Char('V')));
        let status = app.status_error.clone().expect("version status set");
        assert!(status.contains(env!("CARGO_PKG_VERSION")), "got: {status}");
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn key_event_v_typed_into_search_not_version() {
        let mut app = App::new_test();
        app.search_active = true;
        handle_key_event(&mut app, key(KeyCode::Char('v')));
        // Search input takes priority — 'v' is a search character, not a command.
        assert_eq!(app.search_query, "v");
        assert!(app.status_error.is_none());
    }

    // ── handle_search_input ──────────────────────────────────────────

    #[test]
    fn search_input_char_and_backspace() {
        let mut app = App::new_test();
        app.search_active = true;
        handle_search_input(&mut app, key(KeyCode::Char('a')));
        handle_search_input(&mut app, key(KeyCode::Char('b')));
        assert_eq!(app.search_query, "ab");
        handle_search_input(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.search_query, "a");
    }

    #[test]
    fn search_input_esc_clears() {
        let mut app = App::new_test();
        app.search_active = true;
        app.search_query = "foo".to_string();
        handle_search_input(&mut app, key(KeyCode::Esc));
        assert!(!app.search_active);
        assert_eq!(app.search_query, "");
    }

    #[test]
    fn search_input_enter_commits() {
        let mut app = App::new_test();
        app.search_active = true;
        app.search_query = "bar".to_string();
        handle_search_input(&mut app, key(KeyCode::Enter));
        assert!(!app.search_active);
        assert_eq!(app.search_query, "bar"); // retained
    }

    #[test]
    fn search_input_unhandled_key_noop() {
        let mut app = App::new_test();
        app.search_active = true;
        handle_search_input(&mut app, key(KeyCode::F(4)));
        assert_eq!(app.search_query, "");
        assert!(app.search_active);
    }

    // ── small views: help / statistics / settings ────────────────────

    #[test]
    fn help_key_closes() {
        let mut app = App::new_test();
        app.current_view = View::Help;
        handle_help_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::CallList);

        app.current_view = View::Help;
        handle_help_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn help_key_unhandled_noop() {
        let mut app = App::new_test();
        app.current_view = View::Help;
        handle_help_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.current_view, View::Help);
    }

    #[test]
    fn statistics_key_closes() {
        let mut app = App::new_test();
        app.current_view = View::Statistics;
        handle_statistics_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::CallList);

        app.current_view = View::Statistics;
        handle_statistics_key(&mut app, key(KeyCode::Char('s')));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn statistics_key_unhandled_noop() {
        let mut app = App::new_test();
        app.current_view = View::Statistics;
        handle_statistics_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.current_view, View::Statistics);
    }

    // ── handle_settings_popup_key ────────────────────────────────────

    #[test]
    fn settings_popup_nav_and_toggle() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::SettingsDialog);
        app.settings_dialog.focused_item = 0;
        handle_settings_popup_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.settings_dialog.focused_item, 1);
        handle_settings_popup_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.settings_dialog.focused_item, 0);

        // Item 0 = color mode cycle
        let cm = app.color_mode;
        handle_settings_popup_key(&mut app, key(KeyCode::Enter));
        assert_ne!(app.color_mode, cm);
    }

    #[test]
    fn settings_popup_esc_closes() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::SettingsDialog);
        handle_settings_popup_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.active_popup, None);
    }

    // ── helpers ──────────────────────────────────────────────────────

    #[test]
    fn filtered_dialog_count_no_filter() {
        let app = app_with_dialogs();
        assert_eq!(filtered_dialog_count(&app), 3);
    }

    #[test]
    fn get_selected_call_id_returns_first() {
        let app = app_with_dialogs();
        assert!(get_selected_call_id(&app).is_some());
    }
}
