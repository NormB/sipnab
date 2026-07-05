//! Key handling for the call list view, its column selector and the
//! clear-calls actions.

use crate::tui::*;

/// Handle keys in the call list view.
pub(in crate::tui) fn handle_call_list_key(app: &mut App, key: KeyEvent) {
    // Column selector popup captures keys when open
    if app.call_list.column_selector_open {
        handle_column_selector_key(app, key);
        return;
    }

    let dialog_count = filtered_dialog_count(app);

    // Check for Ctrl-L (clear calls, same as F5)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
        clear_calls(app);
        return;
    }

    match key.code {
        k if k == app.keymap.quit || k == KeyCode::Esc => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.call_list.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.call_list.move_down(dialog_count),
        KeyCode::Home => app.call_list.move_to_top(),
        KeyCode::End => app.call_list.move_to_bottom(dialog_count),
        KeyCode::PageUp => app.call_list.page_up(),
        KeyCode::PageDown => app.call_list.page_down(dialog_count),
        KeyCode::Enter => {
            // Open call flow for selected dialog
            if let Some(call_id) = get_selected_call_id(app) {
                app.reset_call_flow_view_state();
                app.current_view = View::CallFlow(call_id);
            }
        }
        KeyCode::Tab => {
            app.current_view = View::StreamList;
        }
        KeyCode::Char(' ') => {
            if let Some(cid) = get_selected_call_id(app) {
                app.call_list.toggle_selection(&cid);
            }
        }
        k if k == app.keymap.search => {
            // Keep the existing query so it can be refined.
            app.search_active = true;
        }
        // F5 — Clear calls
        k if k == app.keymap.clear_calls => {
            clear_calls(app);
        }
        // F6 / r — Raw view for selected dialog's first message
        KeyCode::F(6) | KeyCode::Char('r') => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.raw_msg_scroll = 0;
                app.raw_msg_return_view = Some(View::CallList);
                app.current_view = View::RawMessage {
                    call_id,
                    message_index: 0,
                };
            }
        }
        // t — Cycle timestamp display mode
        KeyCode::Char('t') => {
            app.timestamp_mode = app.timestamp_mode.next();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        // u — Cycle From/To column display (user / host:port / both)
        KeyCode::Char('u') => {
            app.from_to_mode = app.from_to_mode.next();
            app.status_error = Some(app.from_to_mode.label().to_string());
        }
        // F10 — Column selector popup
        k if k == app.keymap.column_selector => {
            app.call_list.column_selector_open = true;
            app.call_list.column_selector_cursor = 0;
        }
        // < — Sort by previous column
        KeyCode::Char('<') => {
            app.call_list.sort_prev_column();
        }
        // > — Sort by next column
        KeyCode::Char('>') => {
            app.call_list.sort_next_column();
        }
        // Z — Reverse sort direction
        KeyCode::Char('Z') => {
            app.call_list.reverse_sort();
        }
        // A — Toggle autoscroll
        k if k == app.keymap.autoscroll => {
            app.call_list.autoscroll = !app.call_list.autoscroll;
        }
        // p — Pause/resume capture processing
        k if k == app.keymap.pause => {
            app.paused = !app.paused;
            app.paused_flag.store(app.paused, AtomicOrdering::Relaxed);
        }
        // i — Clear calls that DON'T match the current filter
        KeyCode::Char('i') => {
            clear_non_matching(app);
        }
        // I — Clear calls that DO match the current filter
        KeyCode::Char('I') => {
            clear_matching(app);
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        KeyCode::F(3) => {
            // F3 Search — same as '/' search; keeps the query for refining.
            app.search_active = true;
        }
        k if k == app.keymap.extended_flow => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.extended_flow = true;
                app.reset_call_flow_view_state();
                app.current_view = View::CallFlow(call_id);
            }
        }
        k if k == app.keymap.filter => {
            // Always open the filter dialog (state is preserved)
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        k if k == app.keymap.settings => {
            app.settings_dialog.focused_item = 0;
            app.active_popup = Some(Popup::SettingsDialog);
        }
        KeyCode::F(9) => {
            // F9 Clear Filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_dialog.clear();
            app.status_error = None;
        }
        // O — Open pcap file
        KeyCode::Char('O') => {
            open_file_dialog(app);
        }
        // N — Name the selected dialog's endpoints (source focused; Tab → dest).
        KeyCode::Char('N') => {
            if let Some((src, dst)) = get_selected_dialog_endpoints(app) {
                open_name_dialog_for(app, vec![src, dst], 0);
            }
        }
        KeyCode::Char('s') => {
            app.stats_scroll = 0;
            app.current_view = View::Statistics;
        }
        _ => {}
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
        assert!(app.extended_flow);
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
