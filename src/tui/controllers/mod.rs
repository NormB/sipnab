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
pub(crate) mod loss_map;
mod name_dialog;
mod quit_confirm;
mod save_dialog;
mod stream;
mod timeline;

// Re-exported at `tui` scope so keybinding_drift_test can probe the
// key→action mapping table directly (same exposure as Keymap/HELP_TEXT).
#[cfg(test)]
use crate::tui::clipboard::spawn_copy_worker;
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
pub use loss_map::{LossMapAction, loss_map_action};
pub(in crate::tui) use name_dialog::*;
pub(in crate::tui) use quit_confirm::*;
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

    // The BPF-filter popup is a text input: it takes every key (the same way
    // search does above), so typing an expression that contains `v`, `n`, `q`
    // or `?` reaches the editor instead of the global fallback keys below.
    if app.current_view == View::BpfFilter {
        handle_bpf_filter_key(app, key);
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
        // by re-dispatching as the configured help key. EXCEPT in the
        // relay-statistics view, where '?' asks the relay which statistics it
        // knows (C3): that view owns the key, the same way the raw-message
        // pager owns `n` above.
        if key.code == KeyCode::Char('?') && !matches!(app.current_view, View::RelayStats { .. }) {
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
        View::Talkers => handle_talkers_key(app, key),
        View::CarrierMetrics => handle_carrier_metrics_key(app, key),
        View::CompareDialogs { .. } => handle_compare_dialogs_key(app, key),
        View::EndpointRollup { .. } => handle_endpoint_rollup_key(app, key),
        View::CaptureHealth => handle_capture_health_key(app, key),
        View::HepSenders => handle_hep_senders_key(app, key),
        View::CallVolume => handle_call_volume_key(app, key),
        View::SdpTimeline { .. } => handle_sdp_timeline_key(app, key),
        View::Conformance { .. } => handle_conformance_key(app, key),
        View::TfpsObserve { .. } => handle_tfps_observe_key(app, key),
        View::SecurityFindings => handle_security_key(app, key),
        View::RelayStats { .. } => handle_relay_stats_key(app, key),
        View::BpfFilter => handle_bpf_filter_key(app, key),
        View::QualityDashboard => dashboard::handle_dashboard_key(app, key),
        View::CallTimeline(_) => timeline::handle_timeline_key(app, key),
        View::StreamLossMap(_) => loss_map::handle_loss_map_key(app, key),
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

/// Handle keys for the BPF-filter editor popup.
///
/// The popup is a text input (routed all keys in `handle_key_event`, like
/// search): printable characters and Backspace edit the appended expression,
/// `Tab` flips the AND/OR mode, and `Enter` validates the composed effective
/// filter (compile-only for now — a later increment re-applies it to the
/// running capture). `Esc` cancels, discarding the typed expression. The arrow
/// and page keys scroll the preview, which can be taller than the popup — the
/// generated default runs to well over a thousand columns; `End` sets a
/// sentinel the render pass clamps to the true bottom.
pub(in crate::tui) fn handle_bpf_filter_key(app: &mut App, key: KeyEvent) {
    use crossterm::event::KeyCode;
    match key.code {
        KeyCode::Esc => {
            app.current_view = View::CallList;
            app.bpf_editor = crate::tui::bpf_editor::BpfEditor::new(); // discard the edit
            app.bpf_scroll = 0; // start at the top next time
        }
        KeyCode::Enter => {
            // Validate the composed effective filter first, so a typo is caught
            // here rather than at the capture thread or the re-scan. Three ways
            // to apply, in order: a live capture re-applies to the running
            // kernel filter; a single offline file re-scans from disk under the
            // new filter; anything else (multi-file input, no input) reports the
            // check only.
            let composed = app.bpf_editor.compose(&app.bpf_filter);
            match crate::capture::bpf_filter::validate_filter(&composed) {
                Ok(()) => {
                    if app.can_reapply_filter() {
                        app.request_filter_reapply(composed);
                        app.status_error = Some("applying filter…".to_string());
                    } else if let Some(path) = app.rescan_path.clone() {
                        // Re-read the file under the composed filter. begin_pcap_load
                        // resets the stores and view and paints a "Re-scanning…"
                        // status; only when it actually started (a load was not
                        // already in flight, the file still exists) do we promote
                        // the composed filter and consume the edit.
                        let path_str = path.to_string_lossy().into_owned();
                        file_open::begin_pcap_load(app, &path_str, Some(&composed));
                        if app.pcap_load.is_some() {
                            app.set_bpf_filter(composed, false);
                            app.bpf_editor = crate::tui::bpf_editor::BpfEditor::new();
                        }
                    } else {
                        app.status_error = Some(format!("filter OK (compiles): {composed}"));
                    }
                }
                Err(msg) => app.status_error = Some(format!("filter rejected: {msg}")),
            }
        }
        KeyCode::Tab => app.bpf_editor.toggle_mode(),
        KeyCode::Backspace => app.bpf_editor.backspace(),
        KeyCode::Char(c) => app.bpf_editor.insert(c),
        // Scroll the preview. `End` sets a sentinel the render clamps to the
        // true bottom, since only the render knows the wrapped height.
        KeyCode::Down => app.bpf_scroll = app.bpf_scroll.saturating_add(1),
        KeyCode::Up => app.bpf_scroll = app.bpf_scroll.saturating_sub(1),
        KeyCode::PageDown => app.bpf_scroll = app.bpf_scroll.saturating_add(10),
        KeyCode::PageUp => app.bpf_scroll = app.bpf_scroll.saturating_sub(10),
        KeyCode::Home => app.bpf_scroll = 0,
        KeyCode::End => app.bpf_scroll = u16::MAX,
        _ => {}
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
        Popup::QuitConfirm => handle_quit_confirm_key(app, key),
    }
}

/// The rows of the settings popup, in top-to-bottom render order.
///
/// This enum is the controller's single source of truth for which toggle
/// each row activates. The renderer (`render_settings_popup`) lists the
/// same items in the same order, and `ALL` is length-checked against
/// `SETTINGS_ITEM_COUNT` at compile time — so a reorder that desyncs the
/// controller from the row count fails to build instead of silently
/// activating the wrong toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tui) enum SettingsItem {
    /// Row 0 — cycle the message color mode.
    ColorMode,
    /// Row 1 — cycle the timestamp display mode.
    TimestampMode,
    /// Row 2 — toggle call-list autoscroll.
    Autoscroll,
    /// Row 3 — toggle the call-flow raw preview.
    RawPreview,
    /// Row 4 — cycle the SDP display mode.
    SdpDisplay,
    /// Row 5 — toggle syntax highlighting.
    SyntaxHighlight,
}

impl SettingsItem {
    /// Every settings row in render order; the array index is the row's
    /// `focused_item`. The fixed length ties the enum to
    /// `SETTINGS_ITEM_COUNT` so the two can never drift apart.
    pub(in crate::tui) const ALL: [SettingsItem; SETTINGS_ITEM_COUNT] = [
        SettingsItem::ColorMode,
        SettingsItem::TimestampMode,
        SettingsItem::Autoscroll,
        SettingsItem::RawPreview,
        SettingsItem::SdpDisplay,
        SettingsItem::SyntaxHighlight,
    ];

    /// The settings row currently focused at `index`, or `None` when the
    /// index is out of range.
    pub(in crate::tui) fn from_index(index: usize) -> Option<SettingsItem> {
        Self::ALL.get(index).copied()
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
/// mode, or syntax highlighting (in that order) — resolved through
/// `SettingsItem` so the row→toggle mapping stays named.
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
        KeyCode::Enter | KeyCode::Char(' ') => {
            match SettingsItem::from_index(app.settings_dialog.focused_item) {
                Some(SettingsItem::ColorMode) => app.color_mode = app.color_mode.next(),
                Some(SettingsItem::TimestampMode) => app.timestamp_mode = app.timestamp_mode.next(),
                Some(SettingsItem::Autoscroll) => {
                    app.call_list.autoscroll = !app.call_list.autoscroll
                }
                Some(SettingsItem::RawPreview) => app.flow.raw_preview = !app.flow.raw_preview,
                Some(SettingsItem::SdpDisplay) => {
                    app.sdp_display_mode = app.sdp_display_mode.next()
                }
                Some(SettingsItem::SyntaxHighlight) => app.syntax_highlight = !app.syntax_highlight,
                None => {}
            }
        }
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

/// Everything the talkers view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TalkersAction {
    /// Esc, the quit key, or `g` — close talkers and return to the call list.
    Close,
    /// Scroll the ranking up one line.
    ScrollUp,
    /// Scroll the ranking down one line.
    ScrollDown,
    /// Scroll the ranking up 20 lines.
    PageUp,
    /// Scroll the ranking down 20 lines.
    PageDown,
    /// Jump to the top of the ranking.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the talkers view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `TalkersAction`, or `None` when the key is not bound in this view.
pub fn talkers_action(km: &Keymap, key: KeyEvent) -> Option<TalkersAction> {
    use TalkersAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('g') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the talkers view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `talkers_action`.
///
/// # Side effects
/// Scroll actions move `app.talkers_scroll`; `Close` returns to the call list.
/// Unbound keys are ignored.
pub(in crate::tui) fn handle_talkers_key(app: &mut App, key: KeyEvent) {
    let Some(action) = talkers_action(&app.keymap, key) else {
        return;
    };
    match action {
        TalkersAction::Close => {
            app.current_view = View::CallList;
        }
        TalkersAction::ScrollUp => {
            app.talkers_scroll = app.talkers_scroll.saturating_sub(1);
        }
        TalkersAction::ScrollDown => {
            app.talkers_scroll = app.talkers_scroll.saturating_add(1);
        }
        TalkersAction::PageUp => app.talkers_scroll = app.talkers_scroll.saturating_sub(20),
        TalkersAction::PageDown => app.talkers_scroll = app.talkers_scroll.saturating_add(20),
        TalkersAction::ScrollTop => app.talkers_scroll = 0,
        // Clamped to the content height by the render pass.
        TalkersAction::ScrollBottom => app.talkers_scroll = u16::MAX,
    }
}

/// Everything the carrier-metrics view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierMetricsAction {
    /// Esc, the quit key, or `m` — close the view and return to the call list.
    Close,
    /// Scroll the table up one line.
    ScrollUp,
    /// Scroll the table down one line.
    ScrollDown,
    /// Scroll the table up 20 lines.
    PageUp,
    /// Scroll the table down 20 lines.
    PageDown,
    /// Jump to the top of the table.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the carrier-metrics view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `CarrierMetricsAction`, or `None` when the key is not bound here.
pub fn carrier_metrics_action(km: &Keymap, key: KeyEvent) -> Option<CarrierMetricsAction> {
    use CarrierMetricsAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('m') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the carrier-metrics view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `carrier_metrics_action`.
///
/// # Side effects
/// Scroll actions move `app.carrier_metrics_scroll`; `Close` returns to the
/// call list. Unbound keys are ignored.
pub(in crate::tui) fn handle_carrier_metrics_key(app: &mut App, key: KeyEvent) {
    let Some(action) = carrier_metrics_action(&app.keymap, key) else {
        return;
    };
    match action {
        CarrierMetricsAction::Close => {
            app.current_view = View::CallList;
        }
        CarrierMetricsAction::ScrollUp => {
            app.carrier_metrics_scroll = app.carrier_metrics_scroll.saturating_sub(1);
        }
        CarrierMetricsAction::ScrollDown => {
            app.carrier_metrics_scroll = app.carrier_metrics_scroll.saturating_add(1);
        }
        CarrierMetricsAction::PageUp => {
            app.carrier_metrics_scroll = app.carrier_metrics_scroll.saturating_sub(20);
        }
        CarrierMetricsAction::PageDown => {
            app.carrier_metrics_scroll = app.carrier_metrics_scroll.saturating_add(20);
        }
        CarrierMetricsAction::ScrollTop => app.carrier_metrics_scroll = 0,
        // Clamped to the content height by the render pass.
        CarrierMetricsAction::ScrollBottom => app.carrier_metrics_scroll = u16::MAX,
    }
}

/// Everything the two-call comparison view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareDialogsAction {
    /// Esc, the quit key, or `c` — close the comparison and return to the list.
    Close,
    /// Scroll the comparison up one line.
    ScrollUp,
    /// Scroll the comparison down one line.
    ScrollDown,
    /// Scroll the comparison up 20 lines.
    PageUp,
    /// Scroll the comparison down 20 lines.
    PageDown,
    /// Jump to the top of the comparison.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the two-call comparison view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `CompareDialogsAction`, or `None` when the key is not bound here.
pub fn compare_dialogs_action(km: &Keymap, key: KeyEvent) -> Option<CompareDialogsAction> {
    use CompareDialogsAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('c') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the two-call comparison view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `compare_dialogs_action`.
///
/// # Side effects
/// Scroll actions move `app.compare_scroll`; `Close` returns to the call list.
/// Unbound keys are ignored.
pub(in crate::tui) fn handle_compare_dialogs_key(app: &mut App, key: KeyEvent) {
    let Some(action) = compare_dialogs_action(&app.keymap, key) else {
        return;
    };
    match action {
        CompareDialogsAction::Close => {
            app.current_view = View::CallList;
        }
        CompareDialogsAction::ScrollUp => {
            app.compare_scroll = app.compare_scroll.saturating_sub(1);
        }
        CompareDialogsAction::ScrollDown => {
            app.compare_scroll = app.compare_scroll.saturating_add(1);
        }
        CompareDialogsAction::PageUp => app.compare_scroll = app.compare_scroll.saturating_sub(20),
        CompareDialogsAction::PageDown => {
            app.compare_scroll = app.compare_scroll.saturating_add(20)
        }
        CompareDialogsAction::ScrollTop => app.compare_scroll = 0,
        // Clamped to the content height by the render pass.
        CompareDialogsAction::ScrollBottom => app.compare_scroll = u16::MAX,
    }
}

/// Everything the per-endpoint rollup view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRollupAction {
    /// Esc, the quit key, or `e` — close the rollup and return to the list.
    Close,
    /// Scroll the rollup up one line.
    ScrollUp,
    /// Scroll the rollup down one line.
    ScrollDown,
    /// Scroll the rollup up 20 lines.
    PageUp,
    /// Scroll the rollup down 20 lines.
    PageDown,
    /// Jump to the top of the rollup.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the per-endpoint rollup view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `EndpointRollupAction`, or `None` when the key is not bound here.
pub fn endpoint_rollup_action(km: &Keymap, key: KeyEvent) -> Option<EndpointRollupAction> {
    use EndpointRollupAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('e') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the per-endpoint rollup view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `endpoint_rollup_action`.
///
/// # Side effects
/// Scroll actions move `app.endpoint_scroll`; `Close` returns to the call list.
/// Unbound keys are ignored.
pub(in crate::tui) fn handle_endpoint_rollup_key(app: &mut App, key: KeyEvent) {
    let Some(action) = endpoint_rollup_action(&app.keymap, key) else {
        return;
    };
    match action {
        EndpointRollupAction::Close => {
            app.current_view = View::CallList;
        }
        EndpointRollupAction::ScrollUp => {
            app.endpoint_scroll = app.endpoint_scroll.saturating_sub(1);
        }
        EndpointRollupAction::ScrollDown => {
            app.endpoint_scroll = app.endpoint_scroll.saturating_add(1);
        }
        EndpointRollupAction::PageUp => {
            app.endpoint_scroll = app.endpoint_scroll.saturating_sub(20)
        }
        EndpointRollupAction::PageDown => {
            app.endpoint_scroll = app.endpoint_scroll.saturating_add(20);
        }
        EndpointRollupAction::ScrollTop => app.endpoint_scroll = 0,
        // Clamped to the content height by the render pass.
        EndpointRollupAction::ScrollBottom => app.endpoint_scroll = u16::MAX,
    }
}

/// Everything the capture-health view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureHealthAction {
    /// Esc, the quit key, or `h` — close the panel and return to the list.
    Close,
    /// Scroll the panel up one line.
    ScrollUp,
    /// Scroll the panel down one line.
    ScrollDown,
    /// Scroll the panel up 20 lines.
    PageUp,
    /// Scroll the panel down 20 lines.
    PageDown,
    /// Jump to the top of the panel.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
    /// `s` — open the HEP senders view.
    OpenHepSenders,
}

/// Pure key→action mapping for the capture-health view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `CaptureHealthAction`, or `None` when the key is not bound here.
pub fn capture_health_action(km: &Keymap, key: KeyEvent) -> Option<CaptureHealthAction> {
    use CaptureHealthAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('h') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        KeyCode::Char('s') => OpenHepSenders,
        _ => return None,
    })
}

/// Handle keys in the capture-health view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `capture_health_action`.
///
/// # Side effects
/// Scroll actions move `app.capture_health_scroll`; `Close` returns to the call
/// list. Unbound keys are ignored.
pub(in crate::tui) fn handle_capture_health_key(app: &mut App, key: KeyEvent) {
    let Some(action) = capture_health_action(&app.keymap, key) else {
        return;
    };
    match action {
        CaptureHealthAction::Close => {
            app.current_view = View::CallList;
        }
        CaptureHealthAction::ScrollUp => {
            app.capture_health_scroll = app.capture_health_scroll.saturating_sub(1);
        }
        CaptureHealthAction::ScrollDown => {
            app.capture_health_scroll = app.capture_health_scroll.saturating_add(1);
        }
        CaptureHealthAction::PageUp => {
            app.capture_health_scroll = app.capture_health_scroll.saturating_sub(20);
        }
        CaptureHealthAction::PageDown => {
            app.capture_health_scroll = app.capture_health_scroll.saturating_add(20);
        }
        CaptureHealthAction::ScrollTop => app.capture_health_scroll = 0,
        // Clamped to the content height by the render pass.
        CaptureHealthAction::ScrollBottom => app.capture_health_scroll = u16::MAX,
        CaptureHealthAction::OpenHepSenders => {
            app.hep_senders_scroll = 0;
            app.current_view = View::HepSenders;
        }
    }
}

/// Everything the HEP senders view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HepSendersAction {
    /// Esc, the quit key, or `s` — back to the capture-health panel it was
    /// opened from.
    Close,
    /// Scroll up one line.
    ScrollUp,
    /// Scroll down one line.
    ScrollDown,
    /// Scroll up 20 lines.
    PageUp,
    /// Scroll down 20 lines.
    PageDown,
    /// Jump to the top.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the HEP senders view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `HepSendersAction`, or `None` when the key is not bound here.
pub fn hep_senders_action(km: &Keymap, key: KeyEvent) -> Option<HepSendersAction> {
    use HepSendersAction::*;
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

/// Handle keys in the HEP senders view: map, then execute.
///
/// # Side effects
/// Scroll actions move `app.hep_senders_scroll`; `Close` returns to the
/// capture-health panel the view was opened from. Unbound keys are ignored.
pub(in crate::tui) fn handle_hep_senders_key(app: &mut App, key: KeyEvent) {
    let Some(action) = hep_senders_action(&app.keymap, key) else {
        return;
    };
    match action {
        HepSendersAction::Close => app.current_view = View::CaptureHealth,
        HepSendersAction::ScrollUp => {
            app.hep_senders_scroll = app.hep_senders_scroll.saturating_sub(1);
        }
        HepSendersAction::ScrollDown => {
            app.hep_senders_scroll = app.hep_senders_scroll.saturating_add(1);
        }
        HepSendersAction::PageUp => {
            app.hep_senders_scroll = app.hep_senders_scroll.saturating_sub(20);
        }
        HepSendersAction::PageDown => {
            app.hep_senders_scroll = app.hep_senders_scroll.saturating_add(20);
        }
        HepSendersAction::ScrollTop => app.hep_senders_scroll = 0,
        // Clamped to the content height by the render pass.
        HepSendersAction::ScrollBottom => app.hep_senders_scroll = u16::MAX,
    }
}

/// Everything the call-volume histogram view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallVolumeAction {
    /// Esc, the quit key, or `b` — close the histogram and return to the list.
    Close,
    /// Scroll the histogram up one line.
    ScrollUp,
    /// Scroll the histogram down one line.
    ScrollDown,
    /// Scroll the histogram up 20 lines.
    PageUp,
    /// Scroll the histogram down 20 lines.
    PageDown,
    /// Jump to the top of the histogram.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the call-volume histogram view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `CallVolumeAction`, or `None` when the key is not bound here.
pub fn call_volume_action(km: &Keymap, key: KeyEvent) -> Option<CallVolumeAction> {
    use CallVolumeAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('b') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the call-volume histogram view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `call_volume_action`.
///
/// # Side effects
/// Scroll actions move `app.call_volume_scroll`; `Close` returns to the call
/// list. Unbound keys are ignored.
pub(in crate::tui) fn handle_call_volume_key(app: &mut App, key: KeyEvent) {
    let Some(action) = call_volume_action(&app.keymap, key) else {
        return;
    };
    match action {
        CallVolumeAction::Close => {
            app.current_view = View::CallList;
        }
        CallVolumeAction::ScrollUp => {
            app.call_volume_scroll = app.call_volume_scroll.saturating_sub(1);
        }
        CallVolumeAction::ScrollDown => {
            app.call_volume_scroll = app.call_volume_scroll.saturating_add(1);
        }
        CallVolumeAction::PageUp => {
            app.call_volume_scroll = app.call_volume_scroll.saturating_sub(20);
        }
        CallVolumeAction::PageDown => {
            app.call_volume_scroll = app.call_volume_scroll.saturating_add(20);
        }
        CallVolumeAction::ScrollTop => app.call_volume_scroll = 0,
        // Clamped to the content height by the render pass.
        CallVolumeAction::ScrollBottom => app.call_volume_scroll = u16::MAX,
    }
}

/// Everything the SDP offer/answer timeline view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpTimelineAction {
    /// Esc, the quit key, or `o` — close the timeline and return to the list.
    Close,
    /// Scroll the timeline up one line.
    ScrollUp,
    /// Scroll the timeline down one line.
    ScrollDown,
    /// Scroll the timeline up 20 lines.
    PageUp,
    /// Scroll the timeline down 20 lines.
    PageDown,
    /// Jump to the top of the timeline.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the SDP offer/answer timeline view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `SdpTimelineAction`, or `None` when the key is not bound here.
pub fn sdp_timeline_action(km: &Keymap, key: KeyEvent) -> Option<SdpTimelineAction> {
    use SdpTimelineAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('o') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the SDP offer/answer timeline view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `sdp_timeline_action`.
///
/// # Side effects
/// Scroll actions move `app.sdp_timeline_scroll`; `Close` returns to the call
/// list. Unbound keys are ignored.
pub(in crate::tui) fn handle_sdp_timeline_key(app: &mut App, key: KeyEvent) {
    let Some(action) = sdp_timeline_action(&app.keymap, key) else {
        return;
    };
    match action {
        SdpTimelineAction::Close => {
            app.current_view = View::CallList;
        }
        SdpTimelineAction::ScrollUp => {
            app.sdp_timeline_scroll = app.sdp_timeline_scroll.saturating_sub(1);
        }
        SdpTimelineAction::ScrollDown => {
            app.sdp_timeline_scroll = app.sdp_timeline_scroll.saturating_add(1);
        }
        SdpTimelineAction::PageUp => {
            app.sdp_timeline_scroll = app.sdp_timeline_scroll.saturating_sub(20);
        }
        SdpTimelineAction::PageDown => {
            app.sdp_timeline_scroll = app.sdp_timeline_scroll.saturating_add(20);
        }
        SdpTimelineAction::ScrollTop => app.sdp_timeline_scroll = 0,
        // Clamped to the content height by the render pass.
        SdpTimelineAction::ScrollBottom => app.sdp_timeline_scroll = u16::MAX,
    }
}

/// Everything the RFC-conformance view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceAction {
    /// Esc, the quit key, or `f` — close the panel and return to the list.
    Close,
    /// Scroll the findings up one line.
    ScrollUp,
    /// Scroll the findings down one line.
    ScrollDown,
    /// Scroll the findings up 20 lines.
    PageUp,
    /// Scroll the findings down 20 lines.
    PageDown,
    /// Jump to the top of the findings.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the RFC-conformance view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `ConformanceAction`, or `None` when the key is not bound here.
pub fn conformance_action(km: &Keymap, key: KeyEvent) -> Option<ConformanceAction> {
    use ConformanceAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('f') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the RFC-conformance view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `conformance_action`.
///
/// # Side effects
/// Scroll actions move `app.conformance_scroll`; `Close` returns to the call
/// list. Unbound keys are ignored.
pub(in crate::tui) fn handle_conformance_key(app: &mut App, key: KeyEvent) {
    let Some(action) = conformance_action(&app.keymap, key) else {
        return;
    };
    match action {
        ConformanceAction::Close => {
            app.current_view = View::CallList;
        }
        ConformanceAction::ScrollUp => {
            app.conformance_scroll = app.conformance_scroll.saturating_sub(1);
        }
        ConformanceAction::ScrollDown => {
            app.conformance_scroll = app.conformance_scroll.saturating_add(1);
        }
        ConformanceAction::PageUp => {
            app.conformance_scroll = app.conformance_scroll.saturating_sub(20);
        }
        ConformanceAction::PageDown => {
            app.conformance_scroll = app.conformance_scroll.saturating_add(20);
        }
        ConformanceAction::ScrollTop => app.conformance_scroll = 0,
        // Clamped to the content height by the render pass.
        ConformanceAction::ScrollBottom => app.conformance_scroll = u16::MAX,
    }
}

/// Everything the TFPS-observe view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TfpsObserveAction {
    /// Esc, the quit key, or `x` — close the view and return to the call list.
    Close,
    /// `b` — show the banned sources.
    ShowBanned,
    /// `d` — show the per-source drop counters.
    ShowDropped,
    /// Scroll the list up one line.
    ScrollUp,
    /// Scroll the list down one line.
    ScrollDown,
    /// Scroll the list up 20 lines.
    PageUp,
    /// Scroll the list down 20 lines.
    PageDown,
    /// Jump to the top of the list.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the TFPS-observe view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `TfpsObserveAction`, or `None` when the key is not bound here.
pub fn tfps_observe_action(km: &Keymap, key: KeyEvent) -> Option<TfpsObserveAction> {
    use TfpsObserveAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('x') => Close,
        KeyCode::Char('b') => ShowBanned,
        KeyCode::Char('d') => ShowDropped,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Switch the TFPS-observe view to `mode` and reset its scroll (the new facet is
/// a different length). A no-op from any other view.
fn set_tfps_mode(app: &mut App, mode: crate::tui::tfps_observe::TfpsMode) {
    if matches!(app.current_view, View::TfpsObserve { .. }) {
        app.current_view = View::TfpsObserve { mode };
        app.tfps_scroll = 0;
    }
}

/// Handle keys in the TFPS-observe view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `tfps_observe_action`.
///
/// # Side effects
/// Scroll actions move `app.tfps_scroll`; `ShowBanned`/`ShowDropped` switch the
/// facet (and reset the scroll, prompting a fresh ask); `Close` returns to the
/// call list. Unbound keys are ignored.
pub(in crate::tui) fn handle_tfps_observe_key(app: &mut App, key: KeyEvent) {
    use crate::tui::tfps_observe::TfpsMode;
    let Some(action) = tfps_observe_action(&app.keymap, key) else {
        return;
    };
    match action {
        TfpsObserveAction::Close => {
            app.current_view = View::CallList;
        }
        TfpsObserveAction::ShowBanned => set_tfps_mode(app, TfpsMode::Banned),
        TfpsObserveAction::ShowDropped => set_tfps_mode(app, TfpsMode::Dropped),
        TfpsObserveAction::ScrollUp => {
            app.tfps_scroll = app.tfps_scroll.saturating_sub(1);
        }
        TfpsObserveAction::ScrollDown => {
            app.tfps_scroll = app.tfps_scroll.saturating_add(1);
        }
        TfpsObserveAction::PageUp => app.tfps_scroll = app.tfps_scroll.saturating_sub(20),
        TfpsObserveAction::PageDown => app.tfps_scroll = app.tfps_scroll.saturating_add(20),
        TfpsObserveAction::ScrollTop => app.tfps_scroll = 0,
        // Clamped to the content height by the render pass.
        TfpsObserveAction::ScrollBottom => app.tfps_scroll = u16::MAX,
    }
}

/// Everything the security-findings view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFindingsAction {
    /// Esc, the quit key, or `a` — close the view and return to the call list.
    Close,
    /// Scroll the findings up one line.
    ScrollUp,
    /// Scroll the findings down one line.
    ScrollDown,
    /// Scroll the findings up 20 lines.
    PageUp,
    /// Scroll the findings down 20 lines.
    PageDown,
    /// Jump to the top of the findings.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
}

/// Pure key→action mapping for the security-findings view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `SecurityFindingsAction`, or `None` when the key is not bound here.
pub fn security_findings_action(km: &Keymap, key: KeyEvent) -> Option<SecurityFindingsAction> {
    use SecurityFindingsAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('a') => Close,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Handle keys in the security-findings view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `security_findings_action`.
///
/// # Side effects
/// Scroll actions move `app.security_scroll`; `Close` returns to the call list.
/// Unbound keys are ignored.
pub(in crate::tui) fn handle_security_key(app: &mut App, key: KeyEvent) {
    let Some(action) = security_findings_action(&app.keymap, key) else {
        return;
    };
    match action {
        SecurityFindingsAction::Close => {
            app.current_view = View::CallList;
        }
        SecurityFindingsAction::ScrollUp => {
            app.security_scroll = app.security_scroll.saturating_sub(1);
        }
        SecurityFindingsAction::ScrollDown => {
            app.security_scroll = app.security_scroll.saturating_add(1);
        }
        SecurityFindingsAction::PageUp => {
            app.security_scroll = app.security_scroll.saturating_sub(20)
        }
        SecurityFindingsAction::PageDown => {
            app.security_scroll = app.security_scroll.saturating_add(20);
        }
        SecurityFindingsAction::ScrollTop => app.security_scroll = 0,
        // Clamped to the content height by the render pass.
        SecurityFindingsAction::ScrollBottom => app.security_scroll = u16::MAX,
    }
}

/// Everything the relay-statistics view can do for a single key press (ST8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatsAction {
    /// Esc, the quit key, or `S` — close and return to the call list.
    Close,
    /// Scroll the text up one line.
    ScrollUp,
    /// Scroll the text down one line.
    ScrollDown,
    /// Scroll up 20 lines.
    PageUp,
    /// Scroll down 20 lines.
    PageDown,
    /// Jump to the top.
    ScrollTop,
    /// Jump to the bottom (the render pass clamps to the content height).
    ScrollBottom,
    /// `?` — show the names the relay knows (C3); pressed again, return to the
    /// counters.
    ToggleNames,
    /// `K` — compare the relay's per-call count against this capture's (C4);
    /// pressed again, return to the counters. Only meaningful when the view is
    /// scoped to a call.
    ToggleCompare,
    /// `H` — show the Call-IDs the relay is holding right now (ST8 holdings);
    /// pressed again, return to the counters.
    ToggleHoldings,
}

/// Pure key→action mapping for the relay-statistics view (keymap-aware).
///
/// `?` maps to [`RelayStatsAction::ToggleNames`] here, but reaches this view
/// only because [`handle_key_event`] special-cases it: `?` is otherwise the
/// global help key. `S` closes, pairing with the `S` that opened the view.
///
/// # Returns
/// The mapped action, or `None` when the key is not bound in this view.
pub fn relay_stats_action(km: &Keymap, key: KeyEvent) -> Option<RelayStatsAction> {
    use RelayStatsAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('S') => Close,
        KeyCode::Char('?') => ToggleNames,
        KeyCode::Char('K') => ToggleCompare,
        KeyCode::Char('H') => ToggleHoldings,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        _ => return None,
    })
}

/// Move the relay-stats view to `target`, or back to counters if it is already
/// there (the toggle `?` and `K` share). `Compare` is refused when the view has
/// no call to compare, so a global view's `K` is a no-op rather than a mode it
/// cannot answer. Resets the scroll, because the new answer is a different
/// length.
fn toggle_relay_stats_mode(app: &mut App, target: RelayStatsMode) {
    let View::RelayStats { call_id, mode } = &app.current_view else {
        return;
    };
    if target == RelayStatsMode::Compare && call_id.is_none() {
        return;
    }
    let next = if *mode == target {
        RelayStatsMode::Counters
    } else {
        target
    };
    let call_id = call_id.clone();
    app.current_view = View::RelayStats {
        call_id,
        mode: next,
    };
    app.relay_stats_scroll = 0;
}

/// Handle keys in the relay-statistics view: map, then execute.
///
/// # Side effects
/// Scroll actions move `app.relay_stats_scroll`; `ToggleNames`/`ToggleCompare`
/// change the view's mode (and reset the scroll); `Close` returns to the call
/// list. Unbound keys are ignored.
pub(in crate::tui) fn handle_relay_stats_key(app: &mut App, key: KeyEvent) {
    let Some(action) = relay_stats_action(&app.keymap, key) else {
        return;
    };
    match action {
        RelayStatsAction::Close => app.current_view = View::CallList,
        RelayStatsAction::ScrollUp => {
            app.relay_stats_scroll = app.relay_stats_scroll.saturating_sub(1);
        }
        RelayStatsAction::ScrollDown => {
            app.relay_stats_scroll = app.relay_stats_scroll.saturating_add(1);
        }
        RelayStatsAction::PageUp => {
            app.relay_stats_scroll = app.relay_stats_scroll.saturating_sub(20);
        }
        RelayStatsAction::PageDown => {
            app.relay_stats_scroll = app.relay_stats_scroll.saturating_add(20);
        }
        RelayStatsAction::ScrollTop => app.relay_stats_scroll = 0,
        RelayStatsAction::ScrollBottom => app.relay_stats_scroll = u16::MAX,
        RelayStatsAction::ToggleNames => toggle_relay_stats_mode(app, RelayStatsMode::Names),
        RelayStatsAction::ToggleCompare => toggle_relay_stats_mode(app, RelayStatsMode::Compare),
        RelayStatsAction::ToggleHoldings => toggle_relay_stats_mode(app, RelayStatsMode::Holdings),
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
            // One wheel step = one row, exactly like Down/Up. Rather than
            // re-implement the row clamp (which the renderer's centering
            // window and the keyboard handler already own), replay the wheel
            // as the equivalent nav key so the clamp lives in one place.
            let code = if down { KeyCode::Down } else { KeyCode::Up };
            dashboard::handle_dashboard_key(app, KeyEvent::new(code, KeyModifiers::NONE));
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
        View::Talkers => {
            app.talkers_scroll = if down {
                app.talkers_scroll.saturating_add(3)
            } else {
                app.talkers_scroll.saturating_sub(3)
            };
        }
        View::CarrierMetrics => {
            app.carrier_metrics_scroll = if down {
                app.carrier_metrics_scroll.saturating_add(3)
            } else {
                app.carrier_metrics_scroll.saturating_sub(3)
            };
        }
        View::CompareDialogs { .. } => {
            app.compare_scroll = if down {
                app.compare_scroll.saturating_add(3)
            } else {
                app.compare_scroll.saturating_sub(3)
            };
        }
        View::EndpointRollup { .. } => {
            app.endpoint_scroll = if down {
                app.endpoint_scroll.saturating_add(3)
            } else {
                app.endpoint_scroll.saturating_sub(3)
            };
        }
        View::CaptureHealth => {
            app.capture_health_scroll = if down {
                app.capture_health_scroll.saturating_add(3)
            } else {
                app.capture_health_scroll.saturating_sub(3)
            };
        }
        View::HepSenders => {
            app.hep_senders_scroll = if down {
                app.hep_senders_scroll.saturating_add(3)
            } else {
                app.hep_senders_scroll.saturating_sub(3)
            };
        }
        View::TfpsObserve { .. } => {
            app.tfps_scroll = if down {
                app.tfps_scroll.saturating_add(3)
            } else {
                app.tfps_scroll.saturating_sub(3)
            };
        }
        View::SecurityFindings => {
            app.security_scroll = if down {
                app.security_scroll.saturating_add(3)
            } else {
                app.security_scroll.saturating_sub(3)
            };
        }
        View::CallVolume => {
            app.call_volume_scroll = if down {
                app.call_volume_scroll.saturating_add(3)
            } else {
                app.call_volume_scroll.saturating_sub(3)
            };
        }
        View::SdpTimeline { .. } => {
            app.sdp_timeline_scroll = if down {
                app.sdp_timeline_scroll.saturating_add(3)
            } else {
                app.sdp_timeline_scroll.saturating_sub(3)
            };
        }
        View::Conformance { .. } => {
            app.conformance_scroll = if down {
                app.conformance_scroll.saturating_add(3)
            } else {
                app.conformance_scroll.saturating_sub(3)
            };
        }
        View::RelayStats { .. } => {
            app.relay_stats_scroll = if down {
                app.relay_stats_scroll.saturating_add(3)
            } else {
                app.relay_stats_scroll.saturating_sub(3)
            };
        }
        // The full-BPF popup is read-only and its content wraps to a single
        // screen for any real filter, so its wheel arm is intentionally empty
        // (v1). The editor increment adds scrolling.
        View::BpfFilter => {}
        // The timeline is a fixed single screen (no scroll, no selection),
        // so its wheel arm is intentionally empty. Deleting it is a compile
        // error, but FOLDING it into a neighbor is not, and that was the
        // silent regression: `timeline_wheel_moves_no_selection_and_no_scroll_offset`
        // holds the emptiness by requiring every selection and every scroll
        // offset in the app to be unmoved after a wheel burst here.
        View::CallTimeline(_) => {}
        // The loss map is likewise a fixed single screen (density strip +
        // header + legend), so its wheel arm is intentionally empty too.
        View::StreamLossMap(_) => {}
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
        app.active_time_after,
        app.active_time_before,
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
        app.active_time_after,
        app.active_time_before,
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
        app.active_time_after,
        app.active_time_before,
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

    /// The popup is a text input now: Esc closes it, and printable keys that
    /// used to close or scroll it (`B`, `q`, `j`, `k`) type instead.
    #[test]
    fn bpf_filter_esc_closes_but_letters_type() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        for c in ['B', 'q', 'j', 'k'] {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
            assert_eq!(
                app.current_view,
                View::BpfFilter,
                "'{c}' types into the filter, it does not close the popup"
            );
        }
        assert_eq!(app.bpf_editor.input(), "Bqjk", "the letters were typed");
        handle_bpf_filter_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::CallList, "Esc closes the popup");
    }

    /// Characters append to the expression; Backspace deletes the last one.
    #[test]
    fn bpf_filter_typing_edits_the_expression() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        for c in "host".chars() {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
        }
        assert_eq!(app.bpf_editor.input(), "host");
        handle_bpf_filter_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.bpf_editor.input(), "hos");
    }

    /// Tab flips the append mode between AND (narrow) and OR (widen).
    #[test]
    fn bpf_filter_tab_toggles_and_or() {
        use crate::tui::bpf_editor::AppendMode;
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        assert_eq!(app.bpf_editor.mode(), AppendMode::And, "starts narrowing");
        handle_bpf_filter_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.bpf_editor.mode(), AppendMode::Or, "Tab widens");
        handle_bpf_filter_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.bpf_editor.mode(), AppendMode::And, "Tab narrows again");
    }

    /// Arrows/PgUp/PgDn scroll the preview and saturate at the top; letters do
    /// not scroll any more (they type — see the test above).
    #[test]
    fn bpf_filter_arrows_scroll_the_preview() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        handle_bpf_filter_key(&mut app, key(KeyCode::Down));
        handle_bpf_filter_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.bpf_scroll, 2, "Down advances one line each");
        handle_bpf_filter_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.bpf_scroll, 1, "Up retreats one line");
        handle_bpf_filter_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.bpf_scroll, 11, "PageDown jumps ten lines");
        handle_bpf_filter_key(&mut app, key(KeyCode::PageUp));
        handle_bpf_filter_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.bpf_scroll, 0, "PageUp retreats ten and saturates");
    }

    /// Home returns to the top; End sets the bottom sentinel (render clamps it).
    #[test]
    fn bpf_filter_home_and_end() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        handle_bpf_filter_key(&mut app, key(KeyCode::PageDown));
        handle_bpf_filter_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.bpf_scroll, 0, "Home returns to the top");
        handle_bpf_filter_key(&mut app, key(KeyCode::End));
        assert_eq!(
            app.bpf_scroll,
            u16::MAX,
            "End sets the bottom sentinel; render clamps it to the content"
        );
    }

    /// Esc discards the typed expression and resets the scroll, so the next
    /// open starts clean at the top.
    #[test]
    fn bpf_filter_esc_discards_input_and_resets_scroll() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        app.bpf_scroll = 7;
        for c in "host 192.0.2.5".chars() {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_bpf_filter_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::CallList, "Esc closes");
        assert_eq!(app.bpf_scroll, 0, "Esc resets the scroll");
        assert_eq!(
            app.bpf_editor.input(),
            "",
            "Esc discards the typed expression"
        );
    }

    /// Enter validates the composed effective filter and reports the outcome on
    /// the status line — success for a good expression, the compiler's message
    /// for a broken one — without changing the view.
    #[test]
    fn bpf_filter_enter_validates_and_reports() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        app.bpf_filter = "udp port 5060".to_string();
        for c in "host 192.0.2.5".chars() {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_bpf_filter_key(&mut app, key(KeyCode::Enter));
        let msg = app.status_error.clone().expect("Enter sets a status");
        assert!(
            msg.contains("OK") && msg.contains("host 192.0.2.5"),
            "reports success with the composed filter: {msg}"
        );
        assert_eq!(app.current_view, View::BpfFilter, "Enter does not close");

        for c in " and and".chars() {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_bpf_filter_key(&mut app, key(KeyCode::Enter));
        let msg = app.status_error.clone().expect("Enter sets a status");
        assert!(msg.contains("rejected"), "reports the rejection: {msg}");
    }

    /// On a live capture (a reconfigure control wired), Enter requests the
    /// re-apply and reports progress; the confirmed outcome promotes the
    /// composed append to the effective filter.
    #[test]
    fn bpf_filter_enter_applies_on_a_live_capture() {
        use crate::capture::reconfigure::{FilterApplyOutcome, FilterControl};
        let mut app = App::new_test();
        let control = std::sync::Arc::new(FilterControl::new());
        let (otx, orx) = crossbeam_channel::unbounded();
        app.set_reconfigure(Some(std::sync::Arc::clone(&control)), Some(orx));
        app.current_view = View::BpfFilter;
        app.set_bpf_filter("udp port 5060".to_string(), false);
        for c in "host 192.0.2.5".chars() {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_bpf_filter_key(&mut app, key(KeyCode::Enter));
        assert!(
            app.status_error.as_deref().unwrap().contains("applying"),
            "Enter reports the apply is in flight: {:?}",
            app.status_error
        );
        // The capture loop confirms generation 1.
        otx.send(FilterApplyOutcome::Applied { generation: 1 })
            .unwrap();
        app.drain_filter_outcomes();
        assert_eq!(
            app.bpf_filter, "(udp port 5060) and (host 192.0.2.5)",
            "the composed append is now the effective filter"
        );
    }

    /// On an offline single-file session, Enter re-scans the file under the
    /// composed filter: a load starts, the composed filter becomes effective,
    /// and the editor is consumed.
    #[test]
    fn bpf_filter_enter_rescans_an_offline_file() {
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sip_call.pcap");
        let mut app = App::new_test();
        app.rescan_path = Some(fixture);
        app.current_view = View::BpfFilter;
        app.set_bpf_filter("udp port 5060".to_string(), false);
        for c in "host 192.0.2.5".chars() {
            handle_bpf_filter_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_bpf_filter_key(&mut app, key(KeyCode::Enter));

        assert!(app.pcap_load.is_some(), "the re-scan load started");
        assert_eq!(
            app.bpf_filter, "(udp port 5060) and (host 192.0.2.5)",
            "the composed filter is now the file's effective filter"
        );
        assert_eq!(app.bpf_editor.input(), "", "the edit is consumed");
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or_default()
                .contains("Re-scanning"),
            "status: {:?}",
            app.status_error
        );

        // Drain the worker so its thread finishes before the test returns.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.pcap_load.is_some() && std::time::Instant::now() < deadline {
            file_open::poll_pcap_load(&mut app);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
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

    /// `SettingsItem::ALL` is the render-ordered source of truth: its length
    /// equals `SETTINGS_ITEM_COUNT` (compile-time), `from_index` maps each row
    /// to the matching variant, and out-of-range indexes are `None`.
    #[test]
    fn settings_item_index_mapping_matches_render_order() {
        assert_eq!(SettingsItem::ALL.len(), SETTINGS_ITEM_COUNT);
        assert_eq!(SettingsItem::from_index(0), Some(SettingsItem::ColorMode));
        assert_eq!(
            SettingsItem::from_index(1),
            Some(SettingsItem::TimestampMode)
        );
        assert_eq!(SettingsItem::from_index(2), Some(SettingsItem::Autoscroll));
        assert_eq!(SettingsItem::from_index(3), Some(SettingsItem::RawPreview));
        assert_eq!(SettingsItem::from_index(4), Some(SettingsItem::SdpDisplay));
        assert_eq!(
            SettingsItem::from_index(5),
            Some(SettingsItem::SyntaxHighlight)
        );
        assert_eq!(SettingsItem::from_index(SETTINGS_ITEM_COUNT), None);
    }

    /// Each settings row activates exactly its named toggle (via
    /// `SettingsItem`), row for row.
    #[test]
    fn settings_popup_each_row_toggles_its_named_item() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::SettingsDialog);

        // Row 2 = call-list autoscroll.
        app.settings_dialog.focused_item = 2;
        let before = app.call_list.autoscroll;
        handle_settings_popup_key(&mut app, key(KeyCode::Enter));
        assert_ne!(app.call_list.autoscroll, before, "row 2 toggles autoscroll");

        // Row 3 = call-flow raw preview.
        app.settings_dialog.focused_item = 3;
        let before = app.flow.raw_preview;
        handle_settings_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert_ne!(app.flow.raw_preview, before, "row 3 toggles raw preview");

        // Row 5 = syntax highlighting.
        app.settings_dialog.focused_item = 5;
        let before = app.syntax_highlight;
        handle_settings_popup_key(&mut app, key(KeyCode::Enter));
        assert_ne!(
            app.syntax_highlight, before,
            "row 5 toggles syntax highlight"
        );
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

    /// Released by the test below once it has checked the copy is still
    /// running; the copy waits on it.
    static COPY_GATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// A stand-in for the real copy that blocks until [`COPY_GATE`] opens (or
    /// gives up after 10 s), so it never touches the system clipboard: the
    /// real copy writes OSC 52 to the developer's terminal and runs xclip.
    fn gated_copy(text: &str) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !COPY_GATE.load(std::sync::atomic::Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                return "the gate never opened".to_string();
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        format!("copied {text}")
    }

    /// The clipboard copy must not run on the UI thread: a wedged xclip
    /// used to hang the whole TUI on `child.wait()`. The spawn returns
    /// while the copy is still blocked, and the worker reports once it
    /// finishes.
    #[test]
    fn clipboard_copy_runs_detached_and_reports_eventually() {
        let app = App::new_test();
        spawn_copy_worker(
            "graph TD;".to_string(),
            std::sync::Arc::clone(&app.async_messages),
            gated_copy,
        );
        // Had the copy run on this thread, the spawn would have returned
        // only after the gate timed out, with its report already queued.
        assert!(
            app.async_messages.lock().is_empty(),
            "the spawn returned while the copy was still blocked"
        );
        COPY_GATE.store(true, std::sync::atomic::Ordering::SeqCst);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.async_messages.lock().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "clipboard worker never reported"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            *app.async_messages.lock(),
            vec!["copied graph TD;".to_string()]
        );
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

/// Tests for the scroll-only panel views (statistics, talkers, carrier
/// metrics, comparison, endpoint rollup, capture health, call volume, SDP
/// timeline, conformance, TFPS observe, security findings, relay stats), the
/// mode toggles two of them carry, popup routing, and the mouse wheel — each
/// driven through `handle_key_event` / `handle_mouse_event`, the entry points
/// the event loop calls.
#[cfg(test)]
mod panel_view_tests {
    use super::*;
    use crate::tui::controllers::test_support::*;
    use crossterm::event::MouseEventKind;

    /// One scroll-only panel: the view, the letter that closes it besides Esc
    /// and the quit key, and the scroll offset its keys move.
    struct Panel {
        view: View,
        close: char,
        scroll: fn(&App) -> u16,
    }

    /// Every panel whose handler is the map-then-scroll shape: seven scroll
    /// actions and a close.
    fn panels() -> Vec<Panel> {
        use crate::tui::tfps_observe::TfpsMode;
        vec![
            Panel {
                view: View::Statistics,
                close: 's',
                scroll: |a| a.stats_scroll,
            },
            Panel {
                view: View::Talkers,
                close: 'g',
                scroll: |a| a.talkers_scroll,
            },
            Panel {
                view: View::CarrierMetrics,
                close: 'm',
                scroll: |a| a.carrier_metrics_scroll,
            },
            Panel {
                view: View::CompareDialogs {
                    a: "call-1@test".to_string(),
                    b: "call-2@test".to_string(),
                },
                close: 'c',
                scroll: |a| a.compare_scroll,
            },
            Panel {
                view: View::EndpointRollup {
                    ip: "10.0.0.1".to_string(),
                },
                close: 'e',
                scroll: |a| a.endpoint_scroll,
            },
            Panel {
                view: View::CaptureHealth,
                close: 'h',
                scroll: |a| a.capture_health_scroll,
            },
            Panel {
                view: View::CallVolume,
                close: 'b',
                scroll: |a| a.call_volume_scroll,
            },
            Panel {
                view: View::SdpTimeline {
                    call_id: "call-1@test".to_string(),
                },
                close: 'o',
                scroll: |a| a.sdp_timeline_scroll,
            },
            Panel {
                view: View::Conformance {
                    call_id: "call-1@test".to_string(),
                },
                close: 'f',
                scroll: |a| a.conformance_scroll,
            },
            Panel {
                view: View::TfpsObserve {
                    mode: TfpsMode::Banned,
                },
                close: 'x',
                scroll: |a| a.tfps_scroll,
            },
            Panel {
                view: View::SecurityFindings,
                close: 'a',
                scroll: |a| a.security_scroll,
            },
            Panel {
                view: View::RelayStats {
                    call_id: None,
                    mode: RelayStatsMode::Counters,
                },
                close: 'S',
                scroll: |a| a.relay_stats_scroll,
            },
        ]
    }

    /// Press `code` through the top-level dispatcher.
    fn press(app: &mut App, code: KeyCode) {
        handle_key_event(app, key(code));
    }

    /// In every panel: Down/`j` and Up/`k` move one line, PgDn/PgUp move
    /// twenty, the top saturates at zero, End parks on the bottom sentinel
    /// the render pass clamps, Home returns to the top — and none of it
    /// leaves the view.
    #[test]
    fn every_panel_scrolls_by_line_and_by_page_and_saturates_at_the_top() {
        for p in panels() {
            let mut app = App::new_test();
            app.current_view = p.view.clone();
            let steps: [(KeyCode, u16); 12] = [
                (KeyCode::Down, 1),
                (KeyCode::Char('j'), 2),
                (KeyCode::Up, 1),
                (KeyCode::Char('k'), 0),
                (KeyCode::Up, 0),
                (KeyCode::PageDown, 20),
                (KeyCode::Down, 21),
                (KeyCode::PageUp, 1),
                (KeyCode::PageUp, 0),
                (KeyCode::End, u16::MAX),
                (KeyCode::Down, u16::MAX),
                (KeyCode::Home, 0),
            ];
            for (code, want) in steps {
                press(&mut app, code);
                assert_eq!((p.scroll)(&app), want, "{:?} after {code:?}", p.view);
                assert_eq!(app.current_view, p.view, "{code:?} must not leave the view");
            }
        }
    }

    /// Every panel closes back to the call list on Esc, on the quit key, and
    /// on its own letter; a key the panel does not bind changes nothing.
    #[test]
    fn every_panel_closes_on_esc_quit_and_its_own_letter_and_ignores_the_rest() {
        for p in panels() {
            let quit = App::new_test().keymap.quit;
            for code in [KeyCode::Esc, quit, KeyCode::Char(p.close)] {
                let mut app = App::new_test();
                app.current_view = p.view.clone();
                press(&mut app, code);
                assert_eq!(
                    app.current_view,
                    View::CallList,
                    "{code:?} must close {:?}",
                    p.view
                );
            }
            let mut app = App::new_test();
            app.current_view = p.view.clone();
            press(&mut app, KeyCode::Char('z'));
            press(&mut app, KeyCode::F(6));
            assert_eq!(app.current_view, p.view, "an unbound key keeps the view");
            assert_eq!((p.scroll)(&app), 0, "an unbound key does not scroll");
        }
    }

    /// Help scrolls one line on Down/`j` and Up/`k` and TEN on PgDn/PgUp (not
    /// the twenty the other panels use), saturates at the top, and End/Home
    /// jump to the ends. Closing resets the offset so the next open starts at
    /// the top.
    #[test]
    fn help_scrolls_ten_per_page_and_closing_resets_the_offset() {
        let mut app = App::new_test();
        app.current_view = View::Help;
        let steps: [(KeyCode, u16); 9] = [
            (KeyCode::Down, 1),
            (KeyCode::Char('j'), 2),
            (KeyCode::Char('k'), 1),
            (KeyCode::PageDown, 11),
            (KeyCode::Up, 10),
            (KeyCode::PageUp, 0),
            (KeyCode::PageUp, 0),
            (KeyCode::End, u16::MAX),
            (KeyCode::Home, 0),
        ];
        for (code, want) in steps {
            handle_help_key(&mut app, key(code));
            assert_eq!(app.help_scroll, want, "after {code:?}");
            assert_eq!(app.current_view, View::Help);
        }
        app.help_scroll = 7;
        handle_help_key(&mut app, key(KeyCode::Char('q')));
        assert_eq!(app.current_view, View::CallList, "quit key closes help");
        assert_eq!(app.help_scroll, 0, "closing resets the scroll");
    }

    /// Relay stats, global scope: `?` shows the names and `?` again returns
    /// to the counters; `H` does the same for holdings; each switch resets
    /// the scroll. `K` is refused — a global view has no call to compare —
    /// and leaves both the mode and the scroll alone.
    #[test]
    fn relay_stats_toggles_names_and_holdings_and_refuses_compare_without_a_call() {
        let mut app = App::new_test();
        app.current_view = View::RelayStats {
            call_id: None,
            mode: RelayStatsMode::Counters,
        };
        let mode = |app: &App| match &app.current_view {
            View::RelayStats { mode, .. } => *mode,
            other => panic!("left the relay-stats view: {other:?}"),
        };

        app.relay_stats_scroll = 5;
        // '?' reaches the view (it is the global help key everywhere else).
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(mode(&app), RelayStatsMode::Names);
        assert_eq!(app.relay_stats_scroll, 0, "a new answer starts at the top");
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(mode(&app), RelayStatsMode::Counters, "? again returns");

        app.relay_stats_scroll = 4;
        press(&mut app, KeyCode::Char('K'));
        assert_eq!(
            mode(&app),
            RelayStatsMode::Counters,
            "K is refused without a call"
        );
        assert_eq!(app.relay_stats_scroll, 4, "a refused K does not reset");

        press(&mut app, KeyCode::Char('H'));
        assert_eq!(mode(&app), RelayStatsMode::Holdings);
        assert_eq!(app.relay_stats_scroll, 0);
        press(&mut app, KeyCode::Char('H'));
        assert_eq!(mode(&app), RelayStatsMode::Counters, "H again returns");
    }

    /// Relay stats scoped to a call: `K` compares and keeps the call; a
    /// different toggle from Compare goes straight to ITS mode rather than
    /// back to the counters; the same toggle twice returns to the counters.
    #[test]
    fn relay_stats_compare_keeps_the_call_and_toggles_switch_directly() {
        let mut app = App::new_test();
        app.current_view = View::RelayStats {
            call_id: Some("call-1@test".to_string()),
            mode: RelayStatsMode::Counters,
        };
        press(&mut app, KeyCode::Char('K'));
        assert_eq!(
            app.current_view,
            View::RelayStats {
                call_id: Some("call-1@test".to_string()),
                mode: RelayStatsMode::Compare,
            }
        );
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(
            app.current_view,
            View::RelayStats {
                call_id: Some("call-1@test".to_string()),
                mode: RelayStatsMode::Names,
            },
            "Compare → Names directly"
        );
        press(&mut app, KeyCode::Char('K'));
        press(&mut app, KeyCode::Char('K'));
        assert_eq!(
            app.current_view,
            View::RelayStats {
                call_id: Some("call-1@test".to_string()),
                mode: RelayStatsMode::Counters,
            },
            "K twice returns to the counters"
        );
    }

    /// The relay-stats toggle is a no-op from any other view (the guard that
    /// lets it read the view's call and mode).
    #[test]
    fn relay_stats_toggle_outside_the_view_changes_nothing() {
        let mut app = App::new_test();
        app.relay_stats_scroll = 3;
        toggle_relay_stats_mode(&mut app, RelayStatsMode::Names);
        assert_eq!(app.current_view, View::CallList);
        assert_eq!(app.relay_stats_scroll, 3);
    }

    /// TFPS observe: `d` switches to the drop counters and `b` back to the
    /// bans, each resetting the scroll; the mode setter is a no-op from any
    /// other view.
    #[test]
    fn tfps_observe_switches_facets_and_resets_the_scroll() {
        use crate::tui::tfps_observe::TfpsMode;
        let mut app = App::new_test();
        app.current_view = View::TfpsObserve {
            mode: TfpsMode::Banned,
        };
        app.tfps_scroll = 9;
        press(&mut app, KeyCode::Char('d'));
        assert_eq!(
            app.current_view,
            View::TfpsObserve {
                mode: TfpsMode::Dropped
            }
        );
        assert_eq!(app.tfps_scroll, 0, "a new facet starts at the top");
        app.tfps_scroll = 2;
        press(&mut app, KeyCode::Char('b'));
        assert_eq!(
            app.current_view,
            View::TfpsObserve {
                mode: TfpsMode::Banned
            }
        );
        assert_eq!(app.tfps_scroll, 0);

        let mut elsewhere = App::new_test();
        elsewhere.tfps_scroll = 4;
        set_tfps_mode(&mut elsewhere, TfpsMode::Dropped);
        assert_eq!(elsewhere.current_view, View::CallList);
        assert_eq!(elsewhere.tfps_scroll, 4);
    }

    /// Settings rows 1 and 4 cycle the timestamp and SDP display modes;
    /// focus stops at both ends of the list (arrows and `j`/`k` alike); an
    /// out-of-range focus activates nothing; an unbound key does nothing.
    #[test]
    fn settings_rows_cycle_their_modes_and_focus_stops_at_both_ends() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::SettingsDialog);

        app.settings_dialog.focused_item = 1;
        let ts = app.timestamp_mode;
        handle_settings_popup_key(&mut app, key(KeyCode::Enter));
        assert_ne!(app.timestamp_mode, ts, "row 1 cycles the timestamp mode");

        app.settings_dialog.focused_item = 4;
        let sdp = app.sdp_display_mode;
        handle_settings_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert_ne!(app.sdp_display_mode, sdp, "row 4 cycles the SDP display");

        app.settings_dialog.focused_item = 0;
        handle_settings_popup_key(&mut app, key(KeyCode::Char('k')));
        assert_eq!(app.settings_dialog.focused_item, 0, "stops at the top");
        for _ in 0..SETTINGS_ITEM_COUNT + 2 {
            handle_settings_popup_key(&mut app, key(KeyCode::Char('j')));
        }
        assert_eq!(
            app.settings_dialog.focused_item,
            SETTINGS_ITEM_COUNT - 1,
            "stops at the last row"
        );

        app.settings_dialog.focused_item = SETTINGS_ITEM_COUNT;
        let before = (
            app.color_mode,
            app.timestamp_mode,
            app.call_list.autoscroll,
            app.flow.raw_preview,
            app.sdp_display_mode,
            app.syntax_highlight,
        );
        handle_settings_popup_key(&mut app, key(KeyCode::Enter));
        let after = (
            app.color_mode,
            app.timestamp_mode,
            app.call_list.autoscroll,
            app.flow.raw_preview,
            app.sdp_display_mode,
            app.syntax_highlight,
        );
        assert_eq!(before, after, "no row is focused, so nothing toggles");
        assert_eq!(app.active_popup, Some(Popup::SettingsDialog));

        app.settings_dialog.focused_item = 2;
        handle_settings_popup_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.settings_dialog.focused_item, 2, "unbound key: no move");
        assert_eq!(app.active_popup, Some(Popup::SettingsDialog), "nor a close");
    }

    /// Each open popup receives the key — shown by an effect only ITS handler
    /// has: a filter-field character, a settings focus move, a file-browser
    /// filter character, a name-dialog cursor move, and a confirmed quit.
    #[test]
    fn each_popup_receives_the_key_through_the_dispatcher() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::FilterDialog);
        press(&mut app, KeyCode::Char('z'));
        assert_eq!(app.filter_dialog.text_field(0), "z", "filter dialog typed");

        let mut app = App::new_test();
        app.active_popup = Some(Popup::SettingsDialog);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.settings_dialog.focused_item, 1, "settings focus moved");

        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new_test();
        app.file_open.dir = dir.path().to_path_buf();
        app.active_popup = Some(Popup::FileOpenDialog);
        press(&mut app, KeyCode::Char('z'));
        assert_eq!(app.file_open.filter, "z", "file browser filter typed");

        let mut app = App::new_test();
        app.active_popup = Some(Popup::NameAddress);
        app.name_dialog.cursor = 3;
        press(&mut app, KeyCode::Home);
        assert_eq!(app.name_dialog.cursor, 0, "name dialog cursor moved");

        let mut app = App::new_test();
        app.active_popup = Some(Popup::QuitConfirm);
        press(&mut app, KeyCode::Char('y'));
        assert!(app.should_quit, "quit confirmation answered");
    }

    /// With no popup open the popup router does nothing, even for a key a
    /// popup would act on.
    #[test]
    fn popup_router_without_a_popup_is_a_no_op() {
        let mut app = App::new_test();
        handle_popup_key(&mut app, key(KeyCode::Char('y')));
        assert!(!app.should_quit);
        assert_eq!(app.active_popup, None);
        assert_eq!(app.current_view, View::CallList);
    }

    /// The BPF-filter editor takes the global fallback keys as text: `v`
    /// types a `v` rather than showing the version, `n` does not cycle the
    /// name mode. The view router reaches the editor too, and an unbound key
    /// there changes nothing.
    #[test]
    fn bpf_filter_editor_takes_the_global_fallback_keys_as_text() {
        let mut app = App::new_test();
        app.current_view = View::BpfFilter;
        press(&mut app, KeyCode::Char('v'));
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.bpf_editor.input(), "vn");
        assert!(app.status_error.is_none(), "no version shown");
        assert_eq!(app.name_mode, crate::names::NameMode::Off);

        dispatch_view_key(&mut app, key(KeyCode::Char('x')));
        assert_eq!(
            app.bpf_editor.input(),
            "vnx",
            "the router reaches the editor"
        );

        press(&mut app, KeyCode::F(6));
        assert_eq!(app.bpf_editor.input(), "vnx");
        assert_eq!(app.bpf_scroll, 0);
        assert_eq!(app.current_view, View::BpfFilter);
    }

    /// One view with a free-scrolling offset the wheel moves three lines at a
    /// time.
    struct WheelView {
        view: View,
        offset: Box<dyn Fn(&App) -> usize>,
    }

    /// Every free-scrolling view, the panels plus the pagers.
    fn wheel_views() -> Vec<WheelView> {
        let mut v: Vec<WheelView> = panels()
            .into_iter()
            .map(|p| {
                let scroll = p.scroll;
                WheelView {
                    view: p.view,
                    offset: Box::new(move |a| usize::from(scroll(a))),
                }
            })
            .collect();
        v.push(WheelView {
            view: View::Help,
            offset: Box::new(|a| usize::from(a.help_scroll)),
        });
        v.push(WheelView {
            view: View::RawMessage {
                call_id: "call-1@test".to_string(),
                message_index: 0,
            },
            offset: Box::new(|a| usize::from(a.raw_msg_scroll)),
        });
        v.push(WheelView {
            view: View::CombinedDetail {
                call_id: "call-1@test".to_string(),
                indices: vec![0, 1],
                scope: "test",
            },
            offset: Box::new(|a| usize::from(a.raw_msg_scroll)),
        });
        v.push(WheelView {
            view: View::MessageDiff {
                call_id: "call-1@test".to_string(),
                msg1_idx: 0,
                msg2_idx: 1,
            },
            offset: Box::new(|a| usize::from(a.diff_scroll)),
        });
        v.push(WheelView {
            view: View::StreamDetail(stream_key(1)),
            offset: Box::new(|a| a.stream_detail_scroll),
        });
        v
    }

    /// A stream key distinguished by its SSRC.
    fn stream_key(ssrc: u32) -> crate::rtp::stream::StreamKey {
        crate::rtp::stream::StreamKey {
            ssrc,
            src: std::net::SocketAddr::new(addr_a(), 20000),
            dst: std::net::SocketAddr::new(addr_b(), 30000),
        }
    }

    /// In every free-scrolling view one wheel step is three lines, down and
    /// up, saturating at the top — and the view does not change.
    #[test]
    fn the_wheel_scrolls_every_free_scrolling_view_three_lines_a_step() {
        for w in wheel_views() {
            let mut app = App::new_test();
            app.current_view = w.view.clone();
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            assert_eq!((w.offset)(&app), 6, "{:?} two steps down", w.view);
            handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
            assert_eq!((w.offset)(&app), 3, "{:?} one step up", w.view);
            handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
            handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
            assert_eq!((w.offset)(&app), 0, "{:?} saturates at the top", w.view);
            assert_eq!(app.current_view, w.view);
        }
    }

    /// The wheel is ignored while a popup is open, and a mouse event that is
    /// not a wheel step (a move, a click) scrolls nothing.
    #[test]
    fn the_wheel_is_ignored_under_a_popup_and_non_wheel_events_do_nothing() {
        let mut app = App::new_test();
        app.current_view = View::Help;
        app.active_popup = Some(Popup::SettingsDialog);
        handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
        assert_eq!(app.help_scroll, 0, "popups own the input");

        app.active_popup = None;
        handle_mouse_event(&mut app, MouseEventKind::Moved);
        handle_mouse_event(
            &mut app,
            MouseEventKind::Down(crossterm::event::MouseButton::Left),
        );
        assert_eq!(app.help_scroll, 0, "only wheel steps scroll");
    }

    /// In the list views the wheel moves the SELECTION one row, clamped to
    /// the displayed rows: the call list (sized off the store), the stream
    /// list (sized off its per-tick cache), and the quality dashboard (via
    /// its own Up/Down so the clamp lives in one place).
    #[test]
    fn the_wheel_moves_the_selection_one_row_in_the_list_views() {
        let mut app = app_with_dialogs();
        for want in [1, 2, 2] {
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            assert_eq!(app.call_list.selected(), want, "call list down");
        }
        handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
        assert_eq!(app.call_list.selected(), 1, "call list up");

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
        assert_eq!(app.stream_list.selected(), 0, "no rows, no movement");
        app.stream_displayed.keys = vec![stream_key(1), stream_key(2)];
        for want in [1, 1] {
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            assert_eq!(app.stream_list.selected(), want, "stream list down");
        }
        handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
        assert_eq!(app.stream_list.selected(), 0, "stream list up");

        let mut app = App::new_test();
        app.current_view = View::QualityDashboard;
        let row = |ssrc| crate::tui::dashboard::StreamHealth {
            key: stream_key(ssrc),
            call_id: None,
            codec: None,
            mos: 4.0,
            jitter_ms: 0.0,
            loss_pct: 0.0,
            packets: 1,
            active: true,
            trend: Vec::new(),
        };
        app.dashboard_snapshot = Some(crate::tui::dashboard::DashboardSnapshot {
            rows: vec![row(1), row(2)],
            ..Default::default()
        });
        for want in [1, 1] {
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            assert_eq!(app.dashboard_selected, want, "dashboard down");
        }
        handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
        assert_eq!(app.dashboard_selected, 0, "dashboard up");
        assert_eq!(app.current_view, View::QualityDashboard);
    }

    /// In the call flow the wheel moves the selected message one arrow,
    /// clamped to the cached message count, and every move resets the detail
    /// pane's scroll; with no messages it does nothing.
    #[test]
    fn the_wheel_steps_the_call_flow_selection_and_resets_the_detail_scroll() {
        let mut app = App::new_test();
        app.current_view = View::CallFlow("call-1@test".to_string());
        handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
        assert_eq!(app.flow.selected, 0, "no messages, no movement");

        app.flow.cached_msg_count = 3;
        app.flow.detail_scroll = 5;
        handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
        assert_eq!(app.flow.selected, 1);
        assert_eq!(app.flow.detail_scroll, 0, "a new message starts at the top");

        handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
        app.flow.detail_scroll = 5;
        handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
        assert_eq!(app.flow.selected, 2, "clamped to the last message");
        assert_eq!(app.flow.detail_scroll, 5, "no move, no reset");

        handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
        assert_eq!(app.flow.selected, 1);
        assert_eq!(app.flow.detail_scroll, 0);
        handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
        app.flow.detail_scroll = 5;
        handle_mouse_event(&mut app, MouseEventKind::ScrollUp);
        assert_eq!(app.flow.selected, 0, "saturates at the first message");
        assert_eq!(app.flow.detail_scroll, 5, "no move, no reset");
    }

    /// The single-screen views — the BPF editor and the loss map — have
    /// nothing to scroll, so the wheel leaves them exactly as they were.
    #[test]
    fn the_wheel_does_nothing_in_the_single_screen_views() {
        for view in [View::BpfFilter, View::StreamLossMap(stream_key(1))] {
            let mut app = App::new_test();
            app.current_view = view.clone();
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            handle_mouse_event(&mut app, MouseEventKind::ScrollDown);
            assert_eq!(app.current_view, view);
            assert_eq!(app.bpf_scroll, 0, "{view:?}");
            assert_eq!(app.stream_detail_scroll, 0, "{view:?}");
            assert_eq!(app.raw_msg_scroll, 0, "{view:?}");
        }
    }

    /// Esc in the loss map reaches the loss-map handler through the
    /// dispatcher and returns to that stream's detail view.
    #[test]
    fn esc_in_the_loss_map_returns_to_the_stream_detail() {
        let mut app = App::new_test();
        app.current_view = View::StreamLossMap(stream_key(7));
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.current_view, View::StreamDetail(stream_key(7)));
    }
}
