//! Key handling for the call list view, its column selector and the
//! clear-calls actions.

use crate::tui::*;

/// Everything the call-list view can do in response to a single key press.
///
/// Produced by [`call_list_action`] (the pure key→action mapping) and
/// consumed by the `handle_call_list_key` executor, so the binding table
/// is testable without touching any `App` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallListAction {
    Quit,
    MoveUp,
    MoveDown,
    MoveTop,
    MoveBottom,
    PageUp,
    PageDown,
    OpenFlow,
    SwitchToStreamList,
    ToggleSelection,
    Search,
    ClearCalls,
    OpenRaw,
    CycleTimestampMode,
    CycleFromToMode,
    OpenColumnSelector,
    SortPrevColumn,
    SortNextColumn,
    ReverseSort,
    ToggleAutoscroll,
    TogglePause,
    ClearNonMatching,
    ClearMatching,
    Help,
    OpenSaveDialog,
    OpenExtendedFlow,
    OpenFilterDialog,
    OpenSettings,
    ClearFilter,
    OpenFileDialog,
    NameEndpoints,
    OpenStatistics,
}

/// Pure key→action mapping for the call list view (keymap-aware).
///
/// Returns `None` for keys the view ignores. The arm order is the old
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
        _ => return None,
    })
}

/// Handle keys in the call list view: route to the column selector while
/// it is open, otherwise map the key to a [`CallListAction`] and execute.
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

/// Apply one [`CallListAction`] to the application state.
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
            // Two or more checked ([*]) rows: one flow merging ALL of them.
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
    }
}

/// Handle keys when the column selector popup is open.
pub(in crate::tui) fn handle_column_selector_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.call_list.column_selector_up(),
        KeyCode::Down | KeyCode::Char('j') => app.call_list.column_selector_down(),
        KeyCode::Char(' ') => app.call_list.toggle_column_visibility(),
        KeyCode::Enter | KeyCode::Esc => {
            app.call_list.column_selector_open = false;
        }
        _ => {}
    }
}

/// Clear calls from the dialog and stream stores.
///
/// If any rows are multi-selected, only those dialogs are removed.
/// Otherwise all dialogs are cleared.
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
            let mut ds = app.dialog_store.write();
            ds.retain(|d| !call_ids_to_remove.contains(&d.call_id));
        }
        app.call_list.clear_selections();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    }
}

/// Clear calls that do NOT match the current filter (keep matching ones).
pub(in crate::tui) fn clear_non_matching(app: &mut App) {
    let filter = match &app.active_filter {
        Some(f) => f.clone(),
        None => return, // no filter active, do nothing
    };

    let removed = {
        let mut ds = app.dialog_store.write();
        let before = ds.len();
        ds.retain(|d| filter.matches_dialog(d, &[]));
        before - ds.len()
    };
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} non-matching dialogs", removed));
}

/// Clear calls that DO match the current filter (keep non-matching ones).
pub(in crate::tui) fn clear_matching(app: &mut App) {
    let filter = match &app.active_filter {
        Some(f) => f.clone(),
        None => return, // no filter active, do nothing
    };

    let removed = {
        let mut ds = app.dialog_store.write();
        let before = ds.len();
        ds.retain(|d| !filter.matches_dialog(d, &[]));
        before - ds.len()
    };
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} matching dialogs", removed));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

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

    #[test]
    fn call_list_shift_n_opens_name_dialog_for_source() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Char('N')));
        assert_eq!(app.active_popup, Some(Popup::NameAddress));
        // The source endpoint is focused first (Tab switches to the dest).
        assert_eq!(app.name_dialog.active_ip(), "10.0.0.1");
    }

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

    #[test]
    fn call_list_home_end() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::End));
        assert_eq!(app.call_list.selected(), 2);
        handle_call_list_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.call_list.selected(), 0);
    }

    #[test]
    fn call_list_page_down_up() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::PageDown));
        // clamps to last (idx 2)
        assert_eq!(app.call_list.selected(), 2);
        handle_call_list_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.call_list.selected(), 0);
    }

    #[test]
    fn call_list_enter_opens_flow() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    #[test]
    fn call_list_enter_empty_noop() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn call_list_tab_to_stream_list() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn call_list_space_toggles_selection() {
        let mut app = app_with_dialogs();
        assert_eq!(app.call_list.selected_rows_count(), 0);
        handle_call_list_key(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(app.call_list.selected_rows_count(), 1);
    }

    #[test]
    fn call_list_esc_quits() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Esc));
        assert!(app.should_quit);
    }

    #[test]
    fn call_list_ctrl_l_clears() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key_mod(KeyCode::Char('l'), KeyModifiers::CONTROL));
        assert_eq!(app.dialog_store.read().len(), 0);
    }

    #[test]
    fn call_list_f6_opens_raw() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::F(6)));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
    }

    #[test]
    fn call_list_r_opens_raw() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Char('r')));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
    }

    #[test]
    fn call_list_t_cycles_timestamp() {
        let mut app = App::new_test();
        let before = app.timestamp_mode;
        handle_call_list_key(&mut app, key(KeyCode::Char('t')));
        assert_ne!(app.timestamp_mode, before);
        assert!(app.status_error.is_some());
    }

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

    #[test]
    fn call_list_a_toggles_autoscroll() {
        let mut app = App::new_test();
        let before = app.call_list.autoscroll;
        handle_call_list_key(&mut app, key(KeyCode::Char('A')));
        assert_ne!(app.call_list.autoscroll, before);
    }

    #[test]
    fn call_list_p_toggles_pause() {
        let mut app = App::new_test();
        assert!(!app.paused);
        handle_call_list_key(&mut app, key(KeyCode::Char('p')));
        assert!(app.paused);
    }

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

    #[test]
    fn call_list_search_via_slash_and_f3() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('/')));
        assert!(app.search_active);

        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(3)));
        assert!(app.search_active);
    }

    #[test]
    fn call_list_f10_opens_column_selector() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::F(10)));
        assert!(app.call_list.column_selector_open);
    }

    #[test]
    fn call_list_f9_clears_filter() {
        let mut app = app_with_dialogs();
        app.active_filter_text = "x".to_string();
        handle_call_list_key(&mut app, key(KeyCode::F(9)));
        assert!(app.active_filter.is_none());
        assert!(app.active_filter_text.is_empty());
    }

    #[test]
    fn call_list_s_opens_statistics() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('s')));
        assert_eq!(app.current_view, View::Statistics);
    }

    #[test]
    fn call_list_extended_flow_key() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::F(4)));
        assert!(app.flow.extended);
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    #[test]
    fn call_list_capital_o_opens_file_dialog() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('O')));
        assert_eq!(app.active_popup, Some(Popup::FileOpenDialog));
    }

    #[test]
    fn call_list_unhandled_key_noop() {
        let mut app = App::new_test();
        handle_call_list_key(&mut app, key(KeyCode::Char('Q')));
        assert_eq!(app.current_view, View::CallList);
        assert!(!app.should_quit);
    }

    #[test]
    fn call_list_routes_to_column_selector_when_open() {
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        handle_call_list_key(&mut app, key(KeyCode::Esc));
        assert!(!app.call_list.column_selector_open);
    }

    // ── handle_column_selector_key ───────────────────────────────────

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

    #[test]
    fn column_selector_unhandled_noop() {
        let mut app = App::new_test();
        app.call_list.column_selector_open = true;
        handle_column_selector_key(&mut app, key(KeyCode::Char('z')));
        assert!(app.call_list.column_selector_open);
    }
}
