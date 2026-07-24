// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyboard and mouse event handling for every view and popup — the
//! controller layer of the TUI. Per-view/per-popup handlers live in the
//! submodules; this module owns the top-level dispatchers plus the small
//! view handlers (help, statistics, settings) and shared selection helpers.

use super::*;

mod call_flow;
mod call_list;
mod dashboard;
mod file_open;
mod filter_dialog;
mod name_dialog;
mod save_dialog;
mod stream;
mod timeline;

// Re-exported at `tui` scope so keybinding_drift_test can probe the
// key→action mapping table directly (same exposure as Keymap/HELP_TEXT).
#[cfg(test)]
use crate::tui::clipboard::spawn_clipboard_copy;
pub use call_flow::{
    CallFlowAction, CombinedDetailAction, MessageDiffAction, RawMessageAction, call_flow_action,
    combined_detail_action, message_diff_action, raw_message_action,
};
pub(in crate::tui) use call_flow::{
    handle_call_flow_key, handle_combined_detail_key, handle_message_diff_key,
    handle_raw_message_key,
};
pub(in crate::tui) use call_list::handle_call_list_key;
pub use call_list::{CallListAction, call_list_action};
pub use dashboard::{DashboardAction, dashboard_action};
pub(in crate::tui) use file_open::*;
pub(in crate::tui) use filter_dialog::*;
pub(in crate::tui) use name_dialog::*;
pub(in crate::tui) use save_dialog::*;
#[cfg(test)]
pub(in crate::tui) use stream::get_selected_stream_key;
pub use stream::{StreamDetailAction, StreamListAction, stream_detail_action, stream_list_action};
pub(in crate::tui) use stream::{handle_stream_detail_key, handle_stream_list_key};
pub use timeline::{TimelineAction, timeline_action};

/// Dispatch a key event to the handler for the current view.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the raw key event from the terminal.
///
/// # Side effects
/// Priority order: Ctrl-C sets `should_quit`; an open popup receives the
/// key via `handle_popup_key`; active search input goes to
/// `handle_search_input`. The global fallbacks then apply for keys not
/// claimed by the keymap: `v`/`V` show the version on the status line,
/// `n` cycles the name-resolution mode (except during raw-view match
/// navigation), and `?` re-dispatches as the configured help key. All
/// remaining keys route to the current view's handler.
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

    // Global fallback keys ('v'/'V' version, 'n' name-mode cycle, '?' help,
    // F12 mouse-capture toggle) apply in every view — but a key the user
    // explicitly rebound in the keymap wins, so a rebind can never be
    // shadowed by these built-ins.
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
        // Cycle name-resolution mode (Off / Static / DNS) — except in the
        // raw-message pager with an active search, where n/N are match
        // navigation (vim/less convention) and belong to the view.
        if key.code == KeyCode::Char('n') {
            let match_navigating =
                matches!(app.current_view, View::RawMessage { .. }) && !app.search_query.is_empty();
            if !match_navigating {
                app.name_mode = app.name_mode.next();
                app.status_error = Some(app.name_mode.label().to_string());
                return;
            }
        }
        // '?' opens help from any view — the near-universal TUI reflex —
        // by re-dispatching as the configured help key.
        if key.code == KeyCode::Char('?') {
            let help = KeyEvent::new(app.keymap.help, KeyModifiers::NONE);
            dispatch_view_key(app, help);
            return;
        }
        // F12 toggles mouse capture so the terminal's native drag-to-select
        // (and copy) works while it is off. The event loop reconciles the
        // terminal state with the flag after the input drain.
        if key.code == KeyCode::F(12) {
            toggle_mouse_capture(app);
            return;
        }
    }

    dispatch_view_key(app, key);
}

/// F12 — toggle terminal mouse capture.
///
/// With capture ON (the default) the TUI receives wheel/click events but
/// the terminal's native drag-to-select cannot work; OFF restores native
/// selection (for copy) at the cost of wheel scrolling. Only the state
/// flag flips here — the event loop executes the crossterm
/// `Enable`/`DisableMouseCapture` commands when it sees the flag change,
/// keeping this handler free of terminal I/O (and unit-testable).
///
/// # Side effects
/// Flips `app.mouse_capture_enabled` and announces the new state on the
/// status line; while OFF the status line also shows a persistent
/// reminder (see `render_status_line3`).
fn toggle_mouse_capture(app: &mut App) {
    app.mouse_capture_enabled = !app.mouse_capture_enabled;
    app.status_error = Some(if app.mouse_capture_enabled {
        "Mouse capture ON — wheel scrolling restored".to_string()
    } else {
        "Mouse capture OFF — drag selects text, F12 to re-enable".to_string()
    });
}

/// Route a key to the handler of the current view.
///
/// # Side effects
/// Whatever the per-view handler does; this function only dispatches on
/// `app.current_view`.
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
        View::QualityDashboard => dashboard::handle_dashboard_key(app, key),
        View::CallTimeline(_) => timeline::handle_timeline_key(app, key),
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
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (search input has no keymap
///   bindings).
///
/// # Side effects
/// Esc leaves search mode and clears `app.search_query`; Enter leaves
/// search mode, keeps the query for highlighting, and in the list views
/// re-dispatches Enter to open the selection; Backspace/characters edit
/// the query; the pass-through navigation keys go to the current view's
/// handler.
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
    /// Esc, the help key, or the quit key — close help and return to the
    /// call list (resetting the scroll for next time).
    Close,
    /// Scroll the help text down one line.
    ScrollDown,
    /// Scroll the help text up one line.
    ScrollUp,
    /// Scroll the help text down ten lines.
    PageDown,
    /// Scroll the help text up ten lines.
    PageUp,
    /// Jump to the top of the help text.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the help view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable help/quit keys are honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `HelpAction`, or `None` when the key is not bound in this
/// view.
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
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `help_action`.
///
/// # Side effects
/// Scroll actions move `app.help_scroll`; `Close` returns to the call
/// list and resets the scroll. Unbound keys are ignored.
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
///
/// # Side effects
/// Routes the key to the handler of `app.active_popup` (save, filter,
/// settings, file-open, or name-address); a no-op when no popup is open.
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
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (no keymap bindings).
///
/// # Side effects
/// Esc closes the popup. Up/Down (or k/j) move `focused_item` within
/// `SETTINGS_ITEM_COUNT`. Enter/Space activates the focused item: color
/// mode, timestamp mode, call-list autoscroll, raw preview, SDP display
/// mode, or syntax highlighting (in that order).
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
    /// Esc, the quit key, or `s` — close statistics and return to the
    /// call list.
    Close,
    /// Scroll the statistics text up one line.
    ScrollUp,
    /// Scroll the statistics text down one line.
    ScrollDown,
    /// Scroll the statistics text up 20 lines.
    PageUp,
    /// Scroll the statistics text down 20 lines.
    PageDown,
    /// Jump to the top of the statistics text.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the statistics view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `StatisticsAction`, or `None` when the key is not bound in
/// this view.
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
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `statistics_action`.
///
/// # Side effects
/// Scroll actions move `app.stats_scroll`; `Close` returns to the call
/// list. Unbound keys are ignored.
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
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `kind` - the mouse event kind; only ScrollUp/ScrollDown are handled.
///
/// # Side effects
/// Ignored while a popup is open. Otherwise moves the current view's
/// selection (call list — briefly taking the dialog-store read lock to
/// size the displayed count — dashboard, stream list, and call flow off
/// their per-tick caches) or its scroll offset
/// (raw/diff/stream-detail/help/statistics views). The timeline is a
/// static single-screen view with nothing to scroll or select, so the
/// wheel is intentionally a no-op there.
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
        View::QualityDashboard => {
            let rows = app.dashboard_snapshot.as_ref().map_or(0, |s| s.rows.len());
            if down {
                if rows > 0 {
                    app.dashboard_selected = (app.dashboard_selected + 1).min(rows - 1);
                }
            } else {
                app.dashboard_selected = app.dashboard_selected.saturating_sub(1);
            }
        }
        View::StreamList => {
            if down {
                // Navigate over the per-tick sync_caches-derived rows, the
                // same cache the keyboard path uses — the wheel must never
                // re-filter the store on every scroll event.
                let count = app.stream_displayed.keys.len();
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
        // The timeline is a fixed single screen (no scroll, no selection),
        // so its wheel arm is intentionally empty.
        View::CallTimeline(_) => {}
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Get the Call-ID of the currently selected dialog in the call list.
///
/// Resolves against the DISPLAYED list — filter + search + sort, the same
/// `displayed_dialogs` the renderer draws — so the selection always opens
/// exactly the row the user sees highlighted.
///
/// # Returns
/// The highlighted row's Call-ID, or `None` when the displayed list is
/// empty or the selection is out of range. Briefly holds the
/// dialog-store read lock.
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

/// Checkbox-selected (`[*]`) dialogs that are currently displayed, in
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

/// Count dialogs visible after applying the active filter and search
/// query — exactly the rows the renderer displays, so navigation clamps
/// to what is on screen. Briefly holds the dialog-store read lock.
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

    /// Fixture "caller" endpoint address (10.0.0.1).
    pub(crate) fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    /// Fixture "callee" endpoint address (10.0.0.2).
    pub(crate) fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    /// Fixed base timestamp all fixture messages are offset from.
    pub(crate) fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Assemble a raw SIP message (CRLF line endings, empty body) from a
    /// first line and header lines.
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

    /// Parsed INVITE from `from` to `to` for `call_id` at `ts`, sent
    /// A→B over UDP 5060.
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

    /// Parsed 200 OK answering `call_id`'s INVITE at `ts`, sent B→A.
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

    /// App pre-populated with three answered dialogs (call-1..call-3).
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

    /// Build an unmodified `KeyEvent` for `code`.
    pub(crate) fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Build a `KeyEvent` for `code` with the modifiers `m`.
    pub(crate) fn key_mod(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }

    /// Press Enter in the call list and assert the flow view opened.
    pub(crate) fn open_call_flow(app: &mut App) {
        handle_call_list_key(app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }
}

/// Unit tests for the top-level dispatchers, search input, and the small
/// views (help, statistics, settings).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// Rebound quit/help keys map to `Close` in the help view; the old
    /// quit key unbinds and Esc always closes.
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

    /// A rebound quit key maps to `Close` in statistics; `s` still closes
    /// and the old quit key unbinds.
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

    /// Ctrl-C quits from anywhere.
    #[test]
    fn key_event_ctrl_c_quits() {
        let mut app = App::new_test();
        handle_key_event(&mut app, key_mod(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
    }

    /// Field report: cycling formats mutated the path into
    /// `/tmp/x.rtp.rtp.rtp...` — the two-segment `rtp.json` extension
    /// defeated the replace-after-last-dot logic, leaving a stale `.rtp`
    /// behind on every lap. The path must track the format exactly, in
    /// both directions, for any number of laps.
    #[test]
    fn save_popup_extension_tracks_format_without_accumulating() {
        let mut app = app_with_dialogs();
        app.active_popup = Some(Popup::SaveDialog);
        app.save.format = SaveFormat::Pcap;
        app.set_save_path("/tmp/x.pcap");
        for _ in 0..2 {
            for _ in 0..11 {
                handle_save_popup_key(&mut app, key(KeyCode::Tab));
                let ext = app.save.format.extension();
                assert_eq!(
                    app.save.path,
                    format!("/tmp/x.{ext}"),
                    "after Tab to {:?}",
                    app.save.format
                );
            }
        }
        for _ in 0..11 {
            handle_save_popup_key(&mut app, key(KeyCode::Up));
            let ext = app.save.format.extension();
            assert_eq!(
                app.save.path,
                format!("/tmp/x.{ext}"),
                "after Up to {:?}",
                app.save.format
            );
        }
        // A user-edited path (extension no longer matches the format)
        // must be left alone.
        app.save.format = SaveFormat::Pcap;
        app.set_save_path("/tmp/custom.bin");
        handle_save_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.save.path, "/tmp/custom.bin");
    }

    /// With a popup open, keys go to the popup handler before the view.
    #[test]
    fn key_event_routes_to_popup_first() {
        let mut app = app_with_dialogs();
        app.active_popup = Some(Popup::SaveDialog);
        // Esc inside save popup closes it (handled by popup handler, not view)
        handle_key_event(&mut app, key(KeyCode::Esc));
        assert_eq!(app.active_popup, None);
    }

    /// With search active, characters extend the query instead of acting
    /// as view commands.
    #[test]
    fn key_event_routes_to_search_when_active() {
        let mut app = App::new_test();
        app.search_active = true;
        handle_key_event(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.search_query, "z");
        assert!(app.search_active);
    }

    /// Keys reach the current view's handler (Tab switches to streams).
    #[test]
    fn key_event_dispatches_by_view() {
        let mut app = App::new_test();
        handle_key_event(&mut app, key(KeyCode::Tab));
        assert_eq!(app.current_view, View::StreamList);
    }

    /// The global `n` fallback cycles the name-resolution mode
    /// Off → Names → DNS → Off.
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

    /// The global `v` fallback shows the version on the status line
    /// without changing the view.
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

    /// `V` shows the version from any view, view unchanged.
    #[test]
    fn key_event_shift_v_shows_version_in_any_view() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_key_event(&mut app, key(KeyCode::Char('V')));
        let status = app.status_error.clone().expect("version status set");
        assert!(status.contains(env!("CARGO_PKG_VERSION")), "got: {status}");
        assert_eq!(app.current_view, View::StreamList);
    }

    /// While searching, `v` is a query character, not the version command.
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

    /// Characters append to the query and Backspace removes the last one.
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

    /// Esc leaves search mode and clears the query.
    #[test]
    fn search_input_esc_clears() {
        let mut app = App::new_test();
        app.search_active = true;
        app.search_query = "foo".to_string();
        handle_search_input(&mut app, key(KeyCode::Esc));
        assert!(!app.search_active);
        assert_eq!(app.search_query, "");
    }

    /// Enter leaves search mode but retains the query for highlighting.
    #[test]
    fn search_input_enter_commits() {
        let mut app = App::new_test();
        app.search_active = true;
        app.search_query = "bar".to_string();
        handle_search_input(&mut app, key(KeyCode::Enter));
        assert!(!app.search_active);
        assert_eq!(app.search_query, "bar"); // retained
    }

    /// An unhandled key neither edits the query nor leaves search mode.
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

    /// Arrow keys walk the narrowed list (clamping at both ends) without
    /// leaving search mode or editing the query.
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

    /// Home/End jump within the narrowed list while search stays active.
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

    /// In the call list, Space stars the highlighted narrowed row and one
    /// Enter commits the query and opens the merged flow of both stars.
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

    /// Space and navigation on an empty narrowed list are safe no-ops.
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

    /// In the call-flow search, Space stays a query character.
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

    /// In the stream-list search, Space stays a query character (no row
    /// starring exists there).
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

    /// Esc and the help key both close the help view.
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

    /// An unbound key leaves the help view open.
    #[test]
    fn help_key_unhandled_noop() {
        let mut app = App::new_test();
        app.current_view = View::Help;
        handle_help_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.current_view, View::Help);
    }

    /// Esc and `s` both close the statistics view.
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

    /// An unbound key leaves the statistics view open.
    #[test]
    fn statistics_key_unhandled_noop() {
        let mut app = App::new_test();
        app.current_view = View::Statistics;
        handle_statistics_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.current_view, View::Statistics);
    }

    // ── handle_settings_popup_key ────────────────────────────────────

    /// Up/Down move the settings focus and Enter activates the focused
    /// item (item 0 cycles the color mode).
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

    /// Esc closes the settings popup.
    #[test]
    fn settings_popup_esc_closes() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::SettingsDialog);
        handle_settings_popup_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.active_popup, None);
    }

    // ── helpers ──────────────────────────────────────────────────────

    /// Without a filter, the displayed count equals the store size.
    #[test]
    fn filtered_dialog_count_no_filter() {
        let app = app_with_dialogs();
        assert_eq!(filtered_dialog_count(&app), 3);
    }

    /// With dialogs present, the initial selection resolves to a Call-ID.
    #[test]
    fn get_selected_call_id_returns_first() {
        let app = app_with_dialogs();
        assert!(get_selected_call_id(&app).is_some());
    }
}

/// Tests for the async-worker feedback channel (status-line drain and the
/// detached clipboard copy).
#[cfg(test)]
mod async_feedback_tests {
    use super::*;

    /// Detached workers (clipboard export) report via `async_messages`;
    /// the event-loop tick drains them into the status line.
    #[test]
    fn drain_async_messages_moves_worker_results_into_status() {
        let mut app = App::new_test();
        app.async_messages.lock().push("Copied!".to_string());
        app.drain_async_messages();
        assert_eq!(app.status_error.as_deref(), Some("Copied!"));
        assert!(app.async_messages.lock().is_empty());
    }

    /// The clipboard copy must not run on the UI thread: a wedged xclip
    /// used to hang the whole TUI on `child.wait()`. The spawn returns
    /// immediately and the worker reports (success or error) eventually.
    #[test]
    fn clipboard_copy_runs_detached_and_reports_eventually() {
        let app = App::new_test();
        let started = std::time::Instant::now();
        spawn_clipboard_copy(
            "graph TD;".to_string(),
            std::sync::Arc::clone(&app.async_messages),
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "spawning the copy must not block"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.async_messages.lock().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "clipboard worker never reported"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// Tests for the global F12 mouse-capture toggle and its rebind
/// precedence.
#[cfg(test)]
mod mouse_capture_toggle_tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    /// F12 flips the mouse-capture flag and announces both directions on
    /// the status line (the event loop reconciles the terminal state).
    #[test]
    fn f12_toggles_mouse_capture_flag_and_status() {
        let mut app = App::new_test();
        assert!(app.mouse_capture_enabled, "capture must start enabled");
        handle_key_event(&mut app, KeyEvent::new(KeyCode::F(12), KeyModifiers::NONE));
        assert!(!app.mouse_capture_enabled);
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or_default()
                .contains("Mouse capture OFF"),
            "got status {:?}",
            app.status_error
        );
        handle_key_event(&mut app, KeyEvent::new(KeyCode::F(12), KeyModifiers::NONE));
        assert!(app.mouse_capture_enabled);
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or_default()
                .contains("Mouse capture ON"),
            "got status {:?}",
            app.status_error
        );
    }

    /// The toggle is global: it works outside the call list too.
    #[test]
    fn f12_toggles_from_other_views() {
        for view in [
            View::StreamList,
            View::RawMessage {
                call_id: "x".to_string(),
                message_index: 0,
            },
            View::Help,
        ] {
            let mut app = App::new_test();
            app.current_view = view;
            handle_key_event(&mut app, KeyEvent::new(KeyCode::F(12), KeyModifiers::NONE));
            assert!(
                !app.mouse_capture_enabled,
                "F12 must toggle in {:?}",
                app.current_view
            );
        }
    }

    /// An F12 the user rebound in the keymap keeps its rebound meaning —
    /// same precedence rule as the other global fallbacks.
    #[test]
    fn rebound_f12_wins_over_mouse_toggle() {
        let mut app = App::new_test();
        app.keymap.save = KeyCode::F(12);
        handle_key_event(&mut app, KeyEvent::new(KeyCode::F(12), KeyModifiers::NONE));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
        assert!(
            app.mouse_capture_enabled,
            "rebound F12 must not also toggle mouse capture"
        );
    }
}

/// Tests for the global '?' help fallback and its rebind precedence.
#[cfg(test)]
mod question_mark_help_tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    /// A novice reflexively presses '?' for help; it must open the help
    /// view from anywhere (unless the user rebound '?' to something else).
    #[test]
    fn question_mark_opens_help_from_call_list_and_stream_list() {
        let mut app = App::new_test();
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(
            matches!(app.current_view, View::Help),
            "? must open help, got {:?}",
            app.current_view
        );

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(matches!(app.current_view, View::Help));
    }

    /// A '?' rebound by the user must keep its rebound meaning.
    #[test]
    fn rebound_question_mark_wins_over_help_fallback() {
        let mut app = App::new_test();
        app.keymap.search = KeyCode::Char('?');
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(
            app.search_active,
            "rebound '?' must trigger search, not help"
        );
        assert!(!matches!(app.current_view, View::Help));
    }
}

/// Tests for n/N search-match navigation in the raw-message pager and its
/// interplay with the global name-mode cycle.
#[cfg(test)]
mod search_match_nav_tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// App on the RawMessage view of call-1's first message.
    fn raw_view_app() -> App {
        let mut app = app_with_dialogs();
        app.current_view = View::RawMessage {
            call_id: "call-1@test".to_string(),
            message_index: 0,
        };
        app
    }

    /// vim/less muscle memory: with an active search in the raw-message
    /// pager, n/N jump between matches (and wrap) instead of only
    /// highlighting. The INVITE fixture matches on the request line and the
    /// CSeq line.
    #[test]
    fn n_and_shift_n_jump_between_matches_in_raw_view() {
        let mut app = raw_view_app();
        app.search_query = "invite".to_string();

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        let first = app.raw_msg_scroll;
        assert!(first > 0, "first match is below the info line");
        assert_eq!(
            app.name_mode,
            crate::names::NameMode::Off,
            "n must NOT cycle name mode while match-navigating"
        );

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        let second = app.raw_msg_scroll;
        assert!(second > first, "advances to the next match");

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert_eq!(app.raw_msg_scroll, first, "wraps to the first match");

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('N'), KeyModifiers::NONE),
        );
        assert_eq!(app.raw_msg_scroll, second, "N wraps backward");
    }

    /// Without an active query, n keeps its global name-mode meaning even
    /// in the raw view.
    #[test]
    fn n_still_cycles_name_mode_without_a_query() {
        let mut app = raw_view_app();
        assert_eq!(app.name_mode, crate::names::NameMode::Off);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert_ne!(
            app.name_mode,
            crate::names::NameMode::Off,
            "no query ⇒ n cycles name mode"
        );
    }

    /// In non-pager views (call list), n cycles name mode even while a
    /// search query narrows the list.
    #[test]
    fn n_cycles_name_mode_in_call_list_even_with_query() {
        let mut app = app_with_dialogs();
        app.search_query = "invite".to_string();
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert_ne!(app.name_mode, crate::names::NameMode::Off);
    }
}
