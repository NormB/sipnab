// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key handling for the call list view, its column selector and the
//! clear-calls actions.

use crate::tui::*;

/// Everything the call-list view can do in response to a single key press.
///
/// Produced by `call_list_action` (the pure key→action mapping) and
/// consumed by the `handle_call_list_key` executor, so the binding table
/// is testable without touching any `App` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallListAction {
    /// The configured quit key or Esc — exit the application.
    Quit,
    /// Move the row selection up one row (saturating at the top).
    MoveUp,
    /// Move the row selection down one row (clamped to the displayed count).
    MoveDown,
    /// Jump the row selection to the first row.
    MoveTop,
    /// Jump the row selection to the last displayed row.
    MoveBottom,
    /// Move the row selection up one page.
    PageUp,
    /// Move the row selection down one page (clamped to the displayed count).
    PageDown,
    /// Enter — open the call flow: a merged flow of all checked rows when
    /// two or more are checked, otherwise the cursor row's flow.
    OpenFlow,
    /// Tab — switch to the RTP stream list view.
    SwitchToStreamList,
    /// Space — toggle the checkbox (`[*]`) selection of the cursor row.
    ToggleSelection,
    /// The configured search key or F3 — enter search-input mode (the
    /// existing query is kept for refining).
    Search,
    /// The configured clear key or Ctrl-L — clear the checked dialogs, or
    /// every dialog when none are checked.
    ClearCalls,
    /// F6 or `r` — open the raw view of the selected dialog's first message.
    OpenRaw,
    /// `t` — cycle the timestamp display mode.
    CycleTimestampMode,
    /// `u` — cycle the From/To column display (user / host:port / both).
    CycleFromToMode,
    /// The configured column-selector key — open the column selector popup.
    OpenColumnSelector,
    /// `<` — sort by the previous column.
    SortPrevColumn,
    /// `>` — sort by the next column.
    SortNextColumn,
    /// `Z` — reverse the sort direction.
    ReverseSort,
    /// The configured autoscroll key — toggle follow-newest autoscroll.
    ToggleAutoscroll,
    /// The configured pause key — toggle capture pause (shared flag with
    /// the capture thread).
    TogglePause,
    /// `i` — clear dialogs that do NOT match the active filter.
    ClearNonMatching,
    /// `I` — clear dialogs that DO match the active filter.
    ClearMatching,
    /// The configured help key — open the help view.
    Help,
    /// The configured save key — open the save dialog.
    OpenSaveDialog,
    /// The configured extended-flow key — open the selected call's flow
    /// with multi-leg correlation on.
    OpenExtendedFlow,
    /// The configured filter key — open the filter dialog popup.
    OpenFilterDialog,
    /// The configured settings key — open the settings popup.
    OpenSettings,
    /// F9 — drop the active filter, the filter dialog state, and the
    /// persisted search query.
    ClearFilter,
    /// `O` — open the file-open dialog.
    OpenFileDialog,
    /// `N` — open the Name Address popup for the selected dialog's
    /// endpoints (source focused first).
    NameEndpoints,
    /// `s` — open the statistics view.
    OpenStatistics,
    /// `D` — open the quality dashboard, remembering the call list as the
    /// return view.
    OpenDashboard,
    /// `T` — open the call timeline of the selected dialog.
    OpenTimeline,
}

/// Pure key→action mapping for the call list view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; every rebindable key is honored.
/// * `key` - the key event; the code is matched against the bindings and
///   the CONTROL modifier distinguishes Ctrl-L (clear calls).
///
/// # Returns
/// `None` for keys the view ignores. The arm order is the old
/// handler's match order verbatim — it defines the precedence between a
/// user rebind (keymap guard) and the built-in literals, so a rebind
/// behaves exactly as it always did.
pub fn call_list_action(km: &Keymap, key: KeyEvent) -> Option<CallListAction> {
    use CallListAction::*;
    // Ctrl-L (clear calls, same as F5)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
        return Some(ClearCalls);
    }
    Some(match key.code {
        k if k == km.quit || k == KeyCode::Esc => Quit,
        KeyCode::Up | KeyCode::Char('k') => MoveUp,
        KeyCode::Down | KeyCode::Char('j') => MoveDown,
        KeyCode::Home => MoveTop,
        KeyCode::End => MoveBottom,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Enter => OpenFlow,
        KeyCode::Tab => SwitchToStreamList,
        KeyCode::Char(' ') => ToggleSelection,
        k if k == km.search => Search,
        k if k == km.clear_calls => ClearCalls,
        KeyCode::F(6) | KeyCode::Char('r') => OpenRaw,
        KeyCode::Char('t') => CycleTimestampMode,
        KeyCode::Char('u') => CycleFromToMode,
        k if k == km.column_selector => OpenColumnSelector,
        KeyCode::Char('<') => SortPrevColumn,
        KeyCode::Char('>') => SortNextColumn,
        KeyCode::Char('Z') => ReverseSort,
        k if k == km.autoscroll => ToggleAutoscroll,
        k if k == km.pause => TogglePause,
        KeyCode::Char('i') => ClearNonMatching,
        KeyCode::Char('I') => ClearMatching,
        k if k == km.help => Help,
        k if k == km.save => OpenSaveDialog,
        KeyCode::F(3) => Search, // F3 — same as '/', keeps the query for refining
        k if k == km.extended_flow => OpenExtendedFlow,
        k if k == km.filter => OpenFilterDialog,
        k if k == km.settings => OpenSettings,
        KeyCode::F(9) => ClearFilter,
        KeyCode::Char('O') => OpenFileDialog,
        KeyCode::Char('N') => NameEndpoints,
        KeyCode::Char('s') => OpenStatistics,
        KeyCode::Char('D') => OpenDashboard,
        // 't' (lowercase) is the timestamp-mode cycle; the timeline opens
        // on Shift+T so both keep a call-list binding.
        KeyCode::Char('T') => OpenTimeline,
        _ => return None,
    })
}

/// Handle keys in the call list view: route to the column selector while
/// it is open, otherwise map the key to a `CallListAction` and execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `call_list_action`.
///
/// # Side effects
/// Delegates to `handle_column_selector_key` or
/// `execute_call_list_action`; unbound keys are ignored.
pub(in crate::tui) fn handle_call_list_key(app: &mut App, key: KeyEvent) {
    // Column selector popup captures keys when open
    if app.call_list.column_selector_open {
        handle_column_selector_key(app, key);
        return;
    }
    if let Some(action) = call_list_action(&app.keymap, key) {
        execute_call_list_action(app, action);
    }
}

/// Apply one `CallListAction` to the application state.
///
/// # Side effects
/// Mutates the state named by each variant (see `CallListAction`):
/// navigation moves `app.call_list` over the displayed row count, the
/// open/switch variants change `app.current_view` or `app.active_popup`
/// (flow openers also reset the call-flow view state, and `OpenRaw`
/// records the call list as the return view), the display-mode cycles
/// update their mode plus the status line, `TogglePause` also stores the
/// shared `paused_flag` for the capture thread, and the clear variants
/// remove dialogs from the stores under write locks.
fn execute_call_list_action(app: &mut App, action: CallListAction) {
    let dialog_count = filtered_dialog_count(app);
    match action {
        CallListAction::Quit => app.should_quit = true,
        CallListAction::MoveUp => app.call_list.move_up(),
        CallListAction::MoveDown => app.call_list.move_down(dialog_count),
        CallListAction::MoveTop => app.call_list.move_to_top(),
        CallListAction::MoveBottom => app.call_list.move_to_bottom(dialog_count),
        CallListAction::PageUp => app.call_list.page_up(),
        CallListAction::PageDown => app.call_list.page_down(dialog_count),
        CallListAction::OpenFlow => {
            // Two or more checked (`[*]`) rows: one flow merging ALL of them.
            // Otherwise the classic single-dialog flow of the cursor row.
            let checked = checked_displayed_call_ids(app);
            if checked.len() >= 2 {
                let anchor = checked[0].clone();
                app.reset_call_flow_view_state();
                app.flow.merged_calls = checked;
                app.current_view = View::CallFlow(anchor);
            } else if let Some(call_id) = get_selected_call_id(app) {
                app.reset_call_flow_view_state();
                app.current_view = View::CallFlow(call_id);
            }
        }
        CallListAction::SwitchToStreamList => {
            app.current_view = View::StreamList;
        }
        CallListAction::ToggleSelection => {
            if let Some(cid) = get_selected_call_id(app) {
                app.call_list.toggle_selection(&cid);
            }
        }
        CallListAction::Search => {
            // Keep the existing query so it can be refined.
            app.search_active = true;
        }
        CallListAction::ClearCalls => clear_calls(app),
        CallListAction::OpenRaw => {
            // Raw view for the selected dialog's first message
            if let Some(call_id) = get_selected_call_id(app) {
                app.raw_msg_scroll = 0;
                app.raw_msg_return_view = Some(View::CallList);
                app.current_view = View::RawMessage {
                    call_id,
                    message_index: 0,
                };
            }
        }
        CallListAction::CycleTimestampMode => {
            app.timestamp_mode = app.timestamp_mode.next();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        CallListAction::CycleFromToMode => {
            // Cycle From/To column display (user / host:port / both)
            app.from_to_mode = app.from_to_mode.next();
            app.status_error = Some(app.from_to_mode.label().to_string());
        }
        CallListAction::OpenColumnSelector => {
            app.call_list.column_selector_open = true;
            app.call_list.column_selector_cursor = 0;
        }
        CallListAction::SortPrevColumn => app.call_list.sort_prev_column(),
        CallListAction::SortNextColumn => app.call_list.sort_next_column(),
        CallListAction::ReverseSort => app.call_list.reverse_sort(),
        CallListAction::ToggleAutoscroll => {
            app.call_list.autoscroll = !app.call_list.autoscroll;
        }
        CallListAction::TogglePause => {
            app.paused = !app.paused;
            app.paused_flag.store(app.paused, AtomicOrdering::Relaxed);
        }
        CallListAction::ClearNonMatching => clear_non_matching(app),
        CallListAction::ClearMatching => clear_matching(app),
        CallListAction::Help => app.current_view = View::Help,
        CallListAction::OpenSaveDialog => open_save_popup(app),
        CallListAction::OpenExtendedFlow => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.flow.extended = true;
                app.reset_call_flow_view_state();
                app.current_view = View::CallFlow(call_id);
            }
        }
        CallListAction::OpenFilterDialog => {
            // Always open the filter dialog (state is preserved)
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.filter_dialog.error = None;
            app.active_popup = Some(Popup::FilterDialog);
        }
        CallListAction::OpenSettings => {
            app.settings_dialog.focused_item = 0;
            app.active_popup = Some(Popup::SettingsDialog);
        }
        CallListAction::ClearFilter => {
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_dialog.clear();
            // The persisted search query narrows the list exactly like the
            // filter does; "clear filter" must drop every narrowing input
            // or the list stays mysteriously incomplete.
            app.search_query.clear();
            app.status_error = None;
        }
        CallListAction::OpenFileDialog => open_file_dialog(app),
        CallListAction::NameEndpoints => {
            // Name the selected dialog's endpoints (source focused; Tab -> dest).
            if let Some((src, dst)) = get_selected_dialog_endpoints(app) {
                open_name_dialog_for(app, vec![src, dst], 0);
            }
        }
        CallListAction::OpenStatistics => {
            app.stats_scroll = 0;
            app.current_view = View::Statistics;
        }
        CallListAction::OpenDashboard => {
            app.dashboard_selected = 0;
            app.dashboard_return_view = Some(View::CallList);
            app.current_view = View::QualityDashboard;
        }
        CallListAction::OpenTimeline => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.current_view = View::CallTimeline(call_id);
            }
        }
    }
}

/// Handle keys when the column selector popup is open.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (no keymap bindings).
///
/// # Side effects
/// Up/Down (or k/j) move the selector cursor, Space toggles the cursor
/// column's visibility, `s` persists the layout via `save_columns`, and
/// Enter/Esc close the selector. Other keys are ignored.
pub(in crate::tui) fn handle_column_selector_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.call_list.column_selector_up(),
        KeyCode::Down | KeyCode::Char('j') => app.call_list.column_selector_down(),
        KeyCode::Char(' ') => app.call_list.toggle_column_visibility(),
        KeyCode::Char('s') => save_columns(app),
        KeyCode::Enter | KeyCode::Esc => {
            app.call_list.column_selector_open = false;
        }
        _ => {}
    }
}

/// Persist the current column layout to `[display] visible_columns` in the
/// user's sipnabrc, then close the selector. Reports the outcome on the status
/// line. A no-op (with an error message) when no config path is available.
///
/// # Side effects
/// Closes the column selector, writes the config file at
/// `app.column_config_path`, and sets `app.status_error` to the result.
pub(in crate::tui) fn save_columns(app: &mut App) {
    app.call_list.column_selector_open = false;
    let cols = app.call_list.visible_column_names();
    let Some(path) = app.column_config_path.clone() else {
        app.status_error = Some("Cannot save columns: no config path".to_string());
        return;
    };
    match crate::config::write_display_columns_file(&path, &cols) {
        Ok(()) => app.status_error = Some(format!("Saved columns to {}", path.display())),
        Err(e) => app.status_error = Some(format!("Save columns failed: {e}")),
    }
}

/// Clear calls from the dialog and stream stores.
///
/// If any rows are multi-selected, only those dialogs are removed.
/// Otherwise all dialogs are cleared.
///
/// # Side effects
/// Removes dialogs (and, on a full clear, streams) under store write
/// locks, drops the checkbox selections, moves the cursor to the top on
/// a full clear, and reports the cleared count on the status line.
pub(in crate::tui) fn clear_calls(app: &mut App) {
    let selected_ids: Vec<String> = app.call_list.selected_rows().iter().cloned().collect();

    if selected_ids.is_empty() {
        // Clear everything
        let count = {
            let mut ds = app.dialog_store.write();
            let n = ds.len();
            ds.clear();
            n
        };
        app.stream_store.write().clear();
        app.call_list.clear_selections();
        app.call_list.move_to_top();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    } else {
        // Checkmarks are Call-ID keyed: remove exactly the checked calls,
        // keeping only the ones that still exist (for an honest count).
        let call_ids_to_remove: Vec<String> = {
            let store = app.dialog_store.read();
            selected_ids
                .into_iter()
                .filter(|cid| store.get(cid).is_some())
                .collect()
        };

        let count = call_ids_to_remove.len();
        {
            // O(n+m) membership: a Vec::contains inside retain is O(n·m).
            let remove: std::collections::HashSet<&str> =
                call_ids_to_remove.iter().map(String::as_str).collect();
            let mut ds = app.dialog_store.write();
            ds.retain(|d| !remove.contains(d.call_id.as_str()));
        }
        app.call_list.clear_selections();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    }
}

/// Clear calls that do NOT match the current filter (keep matching ones).
///
/// # Side effects
/// A no-op without an active filter. Otherwise removes the non-matching
/// dialogs under a store write lock, drops the checkbox selections,
/// moves the cursor to the top, and reports the removed count on the
/// status line.
pub(in crate::tui) fn clear_non_matching(app: &mut App) {
    let filter = match &app.active_filter {
        Some(f) => f.clone(),
        None => return, // no filter active, do nothing
    };

    let removed = {
        // Judge each dialog against its real RTP streams so stream-criteria
        // filters (rtp.codec/mos/jitter/loss) classify correctly; the empty
        // slice made a stream-matching dialog look non-matching and deleted
        // it. Lock order is dialog-then-stream, matching the rest of the app.
        let mut ds = app.dialog_store.write();
        let ss = app.stream_store.read();
        let before = ds.len();
        ds.retain(|d| {
            let streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(&d.call_id).collect();
            filter.matches_dialog(d, &streams)
        });
        before - ds.len()
    };
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} non-matching dialogs", removed));
}

/// Clear calls that DO match the current filter (keep non-matching ones).
///
/// # Side effects
/// A no-op without an active filter. Otherwise removes the matching
/// dialogs under a store write lock, drops the checkbox selections,
/// moves the cursor to the top, and reports the removed count on the
/// status line.
pub(in crate::tui) fn clear_matching(app: &mut App) {
    let filter = match &app.active_filter {
        Some(f) => f.clone(),
        None => return, // no filter active, do nothing
    };

    let removed = {
        // Judge each dialog against its real RTP streams (see
        // clear_non_matching): the empty slice made a stream-matching dialog
        // look non-matching, so it wrongly survived a "clear matching".
        let mut ds = app.dialog_store.write();
        let ss = app.stream_store.read();
        let before = ds.len();
        ds.retain(|d| {
            let streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(&d.call_id).collect();
            !filter.matches_dialog(d, &streams)
        });
        before - ds.len()
    };
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} matching dialogs", removed));
}

/// Unit tests for the call-list key handling, column selector, and the
/// clear-calls variants.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// A filter with stream criteria must judge dialogs using their real RTP
    /// streams: `clear_non_matching` must not delete a dialog that matches
    /// only via its stream. The old `&[]` shortcut evaluated `rtp.codec` with
    /// no streams, so the dialog was misclassified as non-matching and wiped.
    #[test]
    fn clear_non_matching_uses_dialog_streams_not_empty_slice() {
        use crate::capture::parse::{ParsedPacket, TransportProto};
        let t0 = base_ts();
        let mut app = App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", t0),
            make_ok("call-1@test", t0 + chrono::TimeDelta::seconds(1)),
        ]);

        // Inject a PCMU (PT 0) RTP stream and associate it with call-1.
        let mut data = vec![
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];
        data.extend_from_slice(&[0xAA; 160]);
        let rtp = crate::rtp::parser::parse_rtp_header(&data).unwrap();
        let parsed = ParsedPacket {
            timestamp: t0,
            src_addr: addr_a(),
            dst_addr: addr_b(),
            src_port: 20000,
            dst_port: 30000,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from(data),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        };
        {
            let mut ss = app.stream_store.write();
            ss.process_rtp(&parsed, &rtp, t0);
            ss.link_to_dialog(addr_b(), 30000, "call-1@test");
        }

        // Filter that matches ONLY via the stream's codec.
        app.active_filter =
            Some(crate::sip::dsl::FilterExpr::parse("rtp.codec == 'PCMU'").unwrap());

        clear_non_matching(&mut app);

        assert_eq!(
            app.dialog_store.read().len(),
            1,
            "a dialog matching only via its RTP stream must survive clear_non_matching"
        );
    }

    /// Saving columns with no config path closes the selector and reports
    /// an error instead of writing anywhere.
    #[test]
    fn save_columns_without_config_path_reports_error() {
        // Default test App has no column_config_path → save is a safe no-op
        // that surfaces an error rather than writing anywhere.
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        handle_call_list_key(&mut app, key(KeyCode::Char('s')));
        assert!(!app.call_list.column_selector_open, "selector should close");
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or("")
                .contains("no config path"),
            "got: {:?}",
            app.status_error
        );
    }

    /// `s` in the selector persists the visible layout; the written
    /// config reloads with the hidden column absent.
    #[test]
    fn save_columns_writes_visible_layout_to_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/sipnab.toml");
        let mut app = App::new_test();
        app.set_column_config_path(Some(path.clone()));

        // Hide the first column ("#") via the selector, then save with `s`.
        app.call_list.column_selector_open = true;
        app.call_list.column_selector_cursor = 0;
        handle_call_list_key(&mut app, key(KeyCode::Char(' '))); // toggle "#" off
        handle_call_list_key(&mut app, key(KeyCode::Char('s'))); // save

        assert!(!app.call_list.column_selector_open);
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or("")
                .contains("Saved columns")
        );

        // The written config reloads with "#" hidden and the other 10 present.
        let cfg = crate::config::Config::load(Some(path.to_str().unwrap()), false)
            .unwrap()
            .config;
        let cols = cfg
            .display
            .visible_columns
            .expect("visible_columns written");
        assert_eq!(cols.len(), 10);
        assert!(
            !cols.iter().any(|c| c == "#"),
            "hidden column must be absent"
        );
        assert!(cols.iter().any(|c| c == "Method"));
    }

    /// `u` cycles the From/To display through all four modes and back,
    /// announcing each on the status line.
    #[test]
    fn call_list_u_cycles_from_to_mode() {
        let mut app = App::new_test();
        assert_eq!(app.from_to_mode(), crate::tui::FromToMode::Default);
        handle_call_list_key(&mut app, key(KeyCode::Char('u')));
        assert_eq!(app.from_to_mode(), crate::tui::FromToMode::HostPort);
        // Status line reflects the new mode.
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or("")
                .contains("From/To")
        );
        // Cycles through all four back to Default.
        handle_call_list_key(&mut app, key(KeyCode::Char('u')));
        handle_call_list_key(&mut app, key(KeyCode::Char('u')));
        handle_call_list_key(&mut app, key(KeyCode::Char('u')));
        assert_eq!(app.from_to_mode(), crate::tui::FromToMode::Default);
    }

    /// The key→action mapping is pure and keymap-aware: rebinding quit to
    /// 'x' must map 'x' (and no longer 'q') without touching any App state.
    #[test]
    fn call_list_action_honors_remapped_quit_key() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            call_list_action(&km, key(KeyCode::Char('x'))),
            Some(CallListAction::Quit)
        );
        assert_eq!(
            call_list_action(&km, key(KeyCode::Char('q'))),
            None,
            "the old quit key must be unbound after a rebind"
        );
        // Esc quits regardless of the keymap.
        assert_eq!(
            call_list_action(&km, key(KeyCode::Esc)),
            Some(CallListAction::Quit)
        );
    }

    /// A rebind can never be shadowed by a built-in literal: the keymap
    /// arms keep their original precedence order relative to the literals.
    #[test]
    fn call_list_action_literal_precedes_later_keymap_arm() {
        // 't' is the (earlier) timestamp-cycle literal; rebinding save to
        // 't' must lose to it, exactly as the old match-arm order did.
        let km = Keymap {
            save: KeyCode::Char('t'),
            ..Default::default()
        };
        assert_eq!(
            call_list_action(&km, key(KeyCode::Char('t'))),
            Some(CallListAction::CycleTimestampMode)
        );
    }

    /// `N` opens the Name Address popup with the source endpoint focused.
    #[test]
    fn call_list_shift_n_opens_name_dialog_for_source() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Char('N')));
        assert_eq!(app.active_popup, Some(Popup::NameAddress));
        // The source endpoint is focused first (Tab switches to the dest).
        assert_eq!(app.name_dialog.active_ip(), "10.0.0.1");
    }

    /// Down/j and Up/k move the row selection one row at a time.
    #[test]
    fn call_list_down_up_navigation() {
        let mut app = app_with_dialogs();
        assert_eq!(app.call_list.selected(), 0);
        handle_call_list_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.call_list.selected(), 1);
        handle_call_list_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(app.call_list.selected(), 2);
        handle_call_list_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.call_list.selected(), 1);
        handle_call_list_key(&mut app, key(KeyCode::Char('k')));
        assert_eq!(app.call_list.selected(), 0);
    }

    /// Home/End jump the selection to the first/last row.
    #[test]
    fn call_list_home_end() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::End));
        assert_eq!(app.call_list.selected(), 2);
        handle_call_list_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.call_list.selected(), 0);
    }

    /// PageDown/PageUp page the selection, clamping at both ends.
    #[test]
    fn call_list_page_down_up() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::PageDown));
        // clamps to last (idx 2)
        assert_eq!(app.call_list.selected(), 2);
        handle_call_list_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.call_list.selected(), 0);
    }

    /// Enter opens the call flow of the highlighted row.
    #[test]
    fn call_list_enter_opens_flow() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    /// Enter on an empty list is a no-op (no view change, no panic).
    #[test]
    fn call_list_enter_empty_noop() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.current_view, View::CallList);
    }

    /// Tab switches to the stream list view.
    #[test]
    fn call_list_tab_to_stream_list() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.current_view, View::StreamList);
    }

    /// Space checks the highlighted row ([*] multi-selection).
    #[test]
    fn call_list_space_toggles_selection() {
        let mut app = app_with_dialogs();
        assert_eq!(app.call_list.selected_rows_count(), 0);
        handle_call_list_key(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(app.call_list.selected_rows_count(), 1);
    }

    /// Esc from the top-level call list quits the app.
    #[test]
    fn call_list_esc_quits() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Esc));
        assert!(app.should_quit);
    }

    /// Ctrl-L clears every dialog (alias for the clear-calls key).
    #[test]
    fn call_list_ctrl_l_clears() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key_mod(KeyCode::Char('l'), KeyModifiers::CONTROL));
        assert_eq!(app.dialog_store.read().len(), 0);
    }

    /// F6 opens the raw view of the selected dialog's first message.
    #[test]
    fn call_list_f6_opens_raw() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::F(6)));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
    }

    /// `r` opens the raw view (alias for F6).
    #[test]
    fn call_list_r_opens_raw() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Char('r')));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
    }

    /// `t` cycles the timestamp mode and announces it on the status line.
    #[test]
    fn call_list_t_cycles_timestamp() {
        let mut app = App::new_test();
        let before = app.timestamp_mode;
        handle_call_list_key(&mut app, key(KeyCode::Char('t')));
        assert_ne!(app.timestamp_mode, before);
        assert!(app.status_error.is_some());
    }

    /// `<`/`>` move the sort column and `Z` reverses the direction.
    #[test]
    fn call_list_sort_prev_next_reverse() {
        let mut app = App::new_test();
        let start = app.call_list.sort_column();
        handle_call_list_key(&mut app, key(KeyCode::Char('>')));
        assert_ne!(app.call_list.sort_column(), start);
        handle_call_list_key(&mut app, key(KeyCode::Char('<')));
        assert_eq!(app.call_list.sort_column(), start);
        let asc = app.call_list.sort_ascending();
        handle_call_list_key(&mut app, key(KeyCode::Char('Z')));
        assert_ne!(app.call_list.sort_ascending(), asc);
    }

    /// The autoscroll key toggles follow-newest autoscroll.
    #[test]
    fn call_list_a_toggles_autoscroll() {
        let mut app = App::new_test();
        let before = app.call_list.autoscroll;
        handle_call_list_key(&mut app, key(KeyCode::Char('A')));
        assert_ne!(app.call_list.autoscroll, before);
    }

    /// The pause key toggles capture pause.
    #[test]
    fn call_list_p_toggles_pause() {
        let mut app = App::new_test();
        assert!(!app.paused);
        handle_call_list_key(&mut app, key(KeyCode::Char('p')));
        assert!(app.paused);
    }

    /// F1/F2/F7/F8 open help, save, filter, and settings respectively.
    #[test]
    fn call_list_help_save_filter_settings() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));

        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(7)));
        assert_eq!(app.active_popup, Some(Popup::FilterDialog));

        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(8)));
        assert_eq!(app.active_popup, Some(Popup::SettingsDialog));
    }

    /// Both `/` and F3 enter search-input mode.
    #[test]
    fn call_list_search_via_slash_and_f3() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('/')));
        assert!(app.search_active);

        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(3)));
        assert!(app.search_active);
    }

    /// F10 opens the column selector popup.
    #[test]
    fn call_list_f10_opens_column_selector() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(10)));
        assert!(app.call_list.column_selector_open);
    }

    /// F9 drops the active filter and its display text.
    #[test]
    fn call_list_f9_clears_filter() {
        let mut app = app_with_dialogs();
        app.active_filter_text = "x".to_string();
        handle_call_list_key(&mut app, key(KeyCode::F(9)));
        assert!(app.active_filter.is_none());
        assert!(app.active_filter_text.is_empty());
    }

    /// F9 also drops the persisted search query — the documented
    /// "clear active filter **and** persisted search" behavior, and the
    /// reference the call-flow F9 is aligned to (both views bind F9 to the
    /// same "clear every narrowing input" action).
    #[test]
    fn call_list_f9_clears_persisted_search() {
        let mut app = app_with_dialogs();
        app.search_query = "5595".to_string();
        handle_call_list_key(&mut app, key(KeyCode::F(9)));
        assert!(
            app.search_query.is_empty(),
            "F9 must clear the persisted search query"
        );
    }

    /// `s` opens the statistics view.
    #[test]
    fn call_list_s_opens_statistics() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('s')));
        assert_eq!(app.current_view, View::Statistics);
    }

    /// `T` opens the selected call's timeline; Esc returns to the list.
    #[test]
    fn timeline_opens_from_call_list_and_returns_on_close() {
        // Needs a selected call: the timeline opens for the highlighted row.
        let mut app = app_with_dialogs();
        app.handle_key(KeyCode::Char('T'));
        assert!(matches!(app.current_view, View::CallTimeline(_)));
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.current_view, View::CallList);
    }

    /// The extended-flow key opens the flow with multi-leg mode on.
    #[test]
    fn call_list_extended_flow_key() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::F(4)));
        assert!(app.flow.extended);
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    /// `O` opens the file-open dialog.
    #[test]
    fn call_list_capital_o_opens_file_dialog() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('O')));
        assert_eq!(app.active_popup, Some(Popup::FileOpenDialog));
    }

    /// An unbound key changes nothing.
    #[test]
    fn call_list_unhandled_key_noop() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('Q')));
        assert_eq!(app.current_view, View::CallList);
        assert!(!app.should_quit);
    }

    /// While the column selector is open it captures the keys (Esc closes
    /// it instead of quitting).
    #[test]
    fn call_list_routes_to_column_selector_when_open() {
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        handle_call_list_key(&mut app, key(KeyCode::Esc));
        assert!(!app.call_list.column_selector_open);
    }

    // ── handle_column_selector_key ───────────────────────────────────

    /// Up/Down move the selector cursor and Space toggles visibility.
    #[test]
    fn column_selector_nav_and_toggle() {
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        app.call_list.column_selector_cursor = 0;
        handle_column_selector_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.call_list.column_selector_cursor, 1);
        handle_column_selector_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.call_list.column_selector_cursor, 0);

        let vis = app.call_list.visible_columns[0];
        handle_column_selector_key(&mut app, key(KeyCode::Char(' ')));
        assert_ne!(app.call_list.visible_columns[0], vis);
    }

    /// Both Enter and Esc close the column selector.
    #[test]
    fn column_selector_enter_and_esc_close() {
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        handle_column_selector_key(&mut app, key(KeyCode::Enter));
        assert!(!app.call_list.column_selector_open);

        app.call_list.column_selector_open = true;
        handle_column_selector_key(&mut app, key(KeyCode::Esc));
        assert!(!app.call_list.column_selector_open);
    }

    /// An unbound key leaves the selector open and unchanged.
    #[test]
    fn column_selector_unhandled_noop() {
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        handle_column_selector_key(&mut app, key(KeyCode::Char('z')));
        assert!(app.call_list.column_selector_open);
    }
}
