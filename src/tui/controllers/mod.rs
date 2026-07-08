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
pub use call_flow::{
    CallFlowAction, CombinedDetailAction, MessageDiffAction, RawMessageAction, call_flow_action,
    combined_detail_action, message_diff_action, raw_message_action,
};
pub use call_list::{CallListAction, call_list_action};
pub(in crate::tui) use file_open::*;
pub(in crate::tui) use filter_dialog::*;
pub(in crate::tui) use name_dialog::*;
pub(in crate::tui) use save_dialog::*;
pub(in crate::tui) use stream::*;
pub use stream::{StreamDetailAction, StreamListAction, stream_detail_action, stream_list_action};

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

    dispatch_view_key(app, key);
}

/// Route a key to the handler of the current view.
fn dispatch_view_key(app: &mut App, key: KeyEvent) {
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
///
/// The query narrows the list live, so the keys that move the highlight
/// (and, in the call list, star rows) pass through to the current view —
/// the user can walk the narrowed rows, select them, and Enter acts on
/// the selection in one press. Space stays a query character everywhere
/// except the call list (message-content search legitimately contains
/// spaces, and the stream list has no row starring for it to trigger).
pub(in crate::tui) fn handle_search_input(app: &mut App, key: KeyEvent) {
    let pass_through = matches!(
        key.code,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End
    ) || (key.code == KeyCode::Char(' ') && app.current_view == View::CallList);
    if pass_through {
        dispatch_view_key(app, key);
        return;
    }
    match key.code {
        KeyCode::Esc => {
            app.search_active = false;
            app.search_query.clear();
        }
        KeyCode::Enter => {
            app.search_active = false;
            // search_query remains for highlighting
            // In the list views one Enter both commits the query and opens
            // the flow/detail of the selection — a press that only closed
            // the prompt read as a dead key.
            if matches!(app.current_view, View::CallList | View::StreamList) {
                dispatch_view_key(app, key);
            }
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

/// Everything the help view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpAction {
    Close,
    ScrollDown,
    ScrollUp,
    PageDown,
    PageUp,
    ScrollTop,
    ScrollBottom,
}

/// Pure key→action mapping for the help view (keymap-aware).
pub fn help_action(km: &Keymap, key: KeyEvent) -> Option<HelpAction> {
    use HelpAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.help || k == km.quit => Close,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::PageDown => PageDown,
        KeyCode::PageUp => PageUp,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the help view: map, then execute.
pub(in crate::tui) fn handle_help_key(app: &mut App, key: KeyEvent) {
    let Some(action) = help_action(&app.keymap, key) else {
        return;
    };
    // The help can exceed the screen; allow scrolling. render() clamps the
    // offset to the content height, so over-scrolling self-corrects.
    match action {
        HelpAction::Close => {
            app.current_view = View::CallList;
            app.help_scroll = 0; // start at the top next time
        }
        HelpAction::ScrollDown => app.help_scroll = app.help_scroll.saturating_add(1),
        HelpAction::ScrollUp => app.help_scroll = app.help_scroll.saturating_sub(1),
        HelpAction::PageDown => app.help_scroll = app.help_scroll.saturating_add(10),
        HelpAction::PageUp => app.help_scroll = app.help_scroll.saturating_sub(10),
        HelpAction::ScrollTop => app.help_scroll = 0,
        HelpAction::ScrollBottom => app.help_scroll = u16::MAX, // clamped to content in render
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

/// Everything the statistics view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatisticsAction {
    Close,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ScrollTop,
    ScrollBottom,
}

/// Pure key→action mapping for the statistics view (keymap-aware).
pub fn statistics_action(km: &Keymap, key: KeyEvent) -> Option<StatisticsAction> {
    use StatisticsAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('s') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the statistics view: map, then execute.
pub(in crate::tui) fn handle_statistics_key(app: &mut App, key: KeyEvent) {
    let Some(action) = statistics_action(&app.keymap, key) else {
        return;
    };
    match action {
        StatisticsAction::Close => {
            app.current_view = View::CallList;
        }
        StatisticsAction::ScrollUp => {
            app.stats_scroll = app.stats_scroll.saturating_sub(1);
        }
        StatisticsAction::ScrollDown => {
            app.stats_scroll = app.stats_scroll.saturating_add(1);
        }
        StatisticsAction::PageUp => app.stats_scroll = app.stats_scroll.saturating_sub(20),
        StatisticsAction::PageDown => app.stats_scroll = app.stats_scroll.saturating_add(20),
        StatisticsAction::ScrollTop => app.stats_scroll = 0,
        // Clamped to the content height by the render pass.
        StatisticsAction::ScrollBottom => app.stats_scroll = u16::MAX,
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

/// Checkbox-selected ([*]) dialogs that are currently displayed, in
/// display order. Checkmarks are keyed by Call-ID and survive re-filtering,
/// so this intersects them with what is actually on screen — an action on
/// "the selected rows" must match the asterisks the user sees.
pub(in crate::tui) fn checked_displayed_call_ids(app: &App) -> Vec<String> {
    if app.call_list.selected_rows_count() == 0 {
        return Vec::new();
    }
    let store = app.dialog_store.read();
    crate::tui::call_list::displayed_dialogs(
        &store,
        app.active_filter.as_ref(),
        &app.search_query,
        app.call_list.sort_column(),
        app.call_list.sort_ascending(),
    )
    .iter()
    .filter(|d| app.call_list.selected_rows().contains(d.call_id.as_str()))
    .map(|d| d.call_id.clone())
    .collect()
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

    /// Method-generic request builder (OPTIONS, REGISTER, ...) for tests
    /// that need mixed-method dialog populations.
    pub(crate) fn make_request(
        method: &str,
        call_id: &str,
        from: &str,
        to: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = raw_sip(
            &format!("{method} sip:{to}@example.com SIP/2.0"),
            &[
                &format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1"),
                &format!("To: \"{to}\" <sip:{to}@example.com>"),
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {method}"),
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
        .expect("parse request")
    }

    /// Response builder with an arbitrary status line (e.g. "180 Ringing")
    /// for the initial INVITE transaction of `call_id`.
    pub(crate) fn make_response(
        status: &str,
        call_id: &str,
        cseq_method: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = raw_sip(
            &format!("SIP/2.0 {status}"),
            &[
                "From: \"a\" <sip:a@example.com>;tag=t1",
                "To: \"b\" <sip:b@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {cseq_method}"),
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
        .expect("parse response")
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
    fn help_action_honors_remapped_quit_and_help() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            help: KeyCode::Char('?'),
            ..Default::default()
        };
        assert_eq!(
            help_action(&km, key(KeyCode::Char('x'))),
            Some(HelpAction::Close)
        );
        assert_eq!(
            help_action(&km, key(KeyCode::Char('?'))),
            Some(HelpAction::Close)
        );
        assert_eq!(help_action(&km, key(KeyCode::Char('q'))), None);
        assert_eq!(help_action(&km, key(KeyCode::Esc)), Some(HelpAction::Close));
    }

    #[test]
    fn statistics_action_honors_remapped_quit() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            statistics_action(&km, key(KeyCode::Char('x'))),
            Some(StatisticsAction::Close)
        );
        assert_eq!(
            statistics_action(&km, key(KeyCode::Char('s'))),
            Some(StatisticsAction::Close)
        );
        assert_eq!(statistics_action(&km, key(KeyCode::Char('q'))), None);
    }

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

    /// Three dialogs of which exactly two match the query "5595" — the
    /// user's report: typing /5595 narrowed the list to two INVITE rows
    /// but the rows could neither be arrowed between nor starred.
    fn app_with_5595_dialogs() -> App {
        use chrono::TimeDelta;
        let t0 = base_ts();
        App::with_processed_messages(vec![
            make_invite("inv-5595-a@test", "alice", "bob", t0),
            make_invite(
                "inv-5595-b@test",
                "carol",
                "dave",
                t0 + TimeDelta::seconds(1),
            ),
            make_invite(
                "unrelated@test",
                "erin",
                "frank",
                t0 + TimeDelta::seconds(2),
            ),
        ])
    }

    #[test]
    fn search_input_arrows_navigate_narrowed_list() {
        let mut app = app_with_5595_dialogs();
        app.search_active = true;
        app.search_query = "5595".to_string();
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-a@test")
        );

        handle_key_event(&mut app, key(KeyCode::Down));
        assert!(
            app.search_active,
            "navigation must not leave the search prompt"
        );
        assert_eq!(
            app.search_query, "5595",
            "navigation must not edit the query"
        );
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-b@test")
        );

        // Clamped at the bottom of the two-row narrowed list.
        handle_key_event(&mut app, key(KeyCode::Down));
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-b@test")
        );

        handle_key_event(&mut app, key(KeyCode::Up));
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-a@test")
        );

        // Clamped at the top.
        handle_key_event(&mut app, key(KeyCode::Up));
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-a@test")
        );
    }

    #[test]
    fn search_input_home_end_jump_in_narrowed_list() {
        let mut app = app_with_5595_dialogs();
        app.search_active = true;
        app.search_query = "5595".to_string();

        handle_key_event(&mut app, key(KeyCode::End));
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-b@test")
        );
        handle_key_event(&mut app, key(KeyCode::Home));
        assert_eq!(
            get_selected_call_id(&app).as_deref(),
            Some("inv-5595-a@test")
        );
        assert_eq!(app.search_query, "5595");
        assert!(app.search_active);
    }

    #[test]
    fn search_input_space_stars_highlighted_row() {
        let mut app = app_with_5595_dialogs();
        app.search_active = true;
        app.search_query = "5595".to_string();

        handle_key_event(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(app.search_query, "5595", "space selects; it is not typed");
        assert!(app.call_list.selected_rows().contains("inv-5595-a@test"));

        handle_key_event(&mut app, key(KeyCode::Down));
        handle_key_event(&mut app, key(KeyCode::Char(' ')));
        assert!(app.call_list.selected_rows().contains("inv-5595-b@test"));

        // ONE Enter commits the search and immediately opens the merged
        // flow of both starred rows — a first press that only silently
        // closed the prompt read as a failure to the user.
        handle_key_event(&mut app, key(KeyCode::Enter));
        assert!(!app.search_active);
        assert!(matches!(app.current_view, View::CallFlow(_)));
        assert_eq!(app.flow.merged_calls.len(), 2);
    }

    /// Enter during search with nothing starred opens the highlighted
    /// row's flow directly (same single-press semantics as normal mode),
    /// and the committed query survives for highlighting.
    #[test]
    fn search_input_enter_opens_highlighted_row_flow() {
        let mut app = app_with_5595_dialogs();
        app.search_active = true;
        app.search_query = "5595".to_string();
        handle_key_event(&mut app, key(KeyCode::Down));
        handle_key_event(&mut app, key(KeyCode::Enter));
        assert!(!app.search_active);
        assert_eq!(
            app.current_view,
            View::CallFlow("inv-5595-b@test".to_string())
        );
        assert_eq!(app.search_query, "5595", "query kept for highlighting");
    }

    /// Enter during stream-list search commits the query and hands Enter
    /// to the stream list; with nothing to open it must not panic or get
    /// stuck in search mode.
    #[test]
    fn search_input_enter_in_stream_list_commits_and_delegates() {
        let mut app = app_with_5595_dialogs();
        app.current_view = View::StreamList;
        app.search_active = true;
        app.search_query = "pcmu".to_string();
        handle_key_event(&mut app, key(KeyCode::Enter));
        assert!(!app.search_active);
        assert_eq!(app.search_query, "pcmu");
    }

    #[test]
    fn search_input_space_on_empty_narrowed_list_is_noop() {
        let mut app = app_with_5595_dialogs();
        app.search_active = true;
        app.search_query = "zzz-matches-nothing".to_string();
        handle_key_event(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(app.search_query, "zzz-matches-nothing");
        assert_eq!(app.call_list.selected_rows_count(), 0);
        handle_key_event(&mut app, key(KeyCode::Down));
        handle_key_event(&mut app, key(KeyCode::End));
        assert!(app.search_active, "no panic, still searching");
    }

    #[test]
    fn search_input_space_still_types_in_call_flow_search() {
        let mut app = app_with_5595_dialogs();
        app.current_view = View::CallFlow("inv-5595-a@test".to_string());
        app.search_active = true;
        app.search_query = "180".to_string();
        handle_key_event(&mut app, key(KeyCode::Char(' ')));
        // Message-content search legitimately contains spaces — only the
        // list views repurpose Space for row selection.
        assert_eq!(app.search_query, "180 ");
    }

    #[test]
    fn search_input_space_types_in_stream_list() {
        // The stream list has no row starring, so Space must stay a query
        // character there — stealing it would make it a dead key.
        let mut app = app_with_5595_dialogs();
        app.current_view = View::StreamList;
        app.search_active = true;
        app.search_query = "pcmu".to_string();
        handle_key_event(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(app.search_query, "pcmu ");
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
