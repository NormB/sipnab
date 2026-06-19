//! Keyboard event handling for every view and popup, plus the file
//! dialog and pcap-loading actions they trigger.

use super::*;

// ── Key handling ────────────────────────────────────────────────────

/// Dispatch a key event to the handler for the current view.
pub(super) fn handle_key_event(app: &mut App, key: KeyEvent) {
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

    // Global: show the version (with git commit) in the status line. Works in
    // any view; search and popups are handled above, so typing 'v' there is
    // unaffected.
    if matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V')) {
        app.status_error = Some(format!("sipnab {}", crate::cli::build_version()));
        return;
    }

    // Global: cycle name-resolution mode (Off / Static / DNS). Refresh the call
    // flow cache so resolved participant labels update on the next render.
    if key.code == KeyCode::Char('n') {
        app.name_mode = app.name_mode.next();
        app.call_flow_cache.clear();
        app.status_error = Some(app.name_mode.label().to_string());
        return;
    }

    match &app.current_view {
        View::CallList => handle_call_list_key(app, key),
        View::StreamList => handle_stream_list_key(app, key),
        View::StreamDetail(_) => handle_stream_detail_key(app, key),
        View::CallFlow(_) => handle_call_flow_key(app, key),
        View::RawMessage { .. } => handle_raw_message_key(app, key),
        View::MessageDiff { .. } => handle_message_diff_key(app, key),
        View::Help => handle_help_key(app, key),
        View::Statistics => handle_statistics_key(app, key),
    }
}

/// Handle search input mode.
pub(super) fn handle_search_input(app: &mut App, key: KeyEvent) {
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

/// Handle keys in the call list view.
pub(super) fn handle_call_list_key(app: &mut App, key: KeyEvent) {
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
                app.call_flow_scroll = 0;
                app.selected_msg_index = 0;
                app.detail_scroll = 0;
                app.current_view = View::CallFlow(call_id);
            }
        }
        KeyCode::Tab => {
            app.current_view = View::StreamList;
        }
        KeyCode::Char(' ') => {
            app.call_list.toggle_selection();
        }
        k if k == app.keymap.search => {
            app.search_active = true;
            app.search_query.clear();
        }
        // F5 — Clear calls
        k if k == app.keymap.clear_calls => {
            clear_calls(app);
        }
        // F6 / r — Raw view for selected dialog's first message
        KeyCode::F(6) | KeyCode::Char('r') => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.raw_msg_scroll = 0;
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
            // F3 Search — same as '/' search
            app.search_active = true;
            app.search_query.clear();
        }
        k if k == app.keymap.extended_flow => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.extended_flow = true;
                app.call_flow_scroll = 0;
                app.selected_msg_index = 0;
                app.detail_scroll = 0;
                app.call_flow_cache.clear();
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
        // N — Name the selected dialog's source address
        KeyCode::Char('N') => {
            if let Some(ip) = get_selected_dialog_src(app) {
                open_name_dialog(app, ip);
            }
        }
        KeyCode::Char('s') => app.current_view = View::Statistics,
        _ => {}
    }
}

/// Handle keys when the column selector popup is open.
pub(super) fn handle_column_selector_key(app: &mut App, key: KeyEvent) {
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
pub(super) fn clear_calls(app: &mut App) {
    let selected_rows: Vec<usize> = app.call_list.selected_rows().iter().copied().collect();

    if selected_rows.is_empty() {
        // Clear everything
        let count = {
            let mut ds = app.dialog_store.write();
            let n = ds.len();
            ds.clear();
            n
        };
        app.stream_store.write().clear();
        app.call_flow_cache.clear();
        app.call_list.clear_selections();
        app.call_list.move_to_top();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    } else {
        // Clear only selected rows: collect the Call-IDs to remove
        let call_ids_to_remove: Vec<String> = {
            let store = app.dialog_store.read();
            // Map selected row indices to dialogs through the same displayed
            // (filter + search + sort) ordering the user sees on screen.
            let dialogs = call_list::displayed_dialogs(
                &store,
                app.active_filter.as_ref(),
                &app.search_query,
                app.call_list.sort_column(),
                app.call_list.sort_ascending(),
            );
            selected_rows
                .iter()
                .filter_map(|&idx| dialogs.get(idx).map(|d| d.call_id.clone()))
                .collect()
        };

        let count = call_ids_to_remove.len();
        {
            let mut ds = app.dialog_store.write();
            ds.retain(|d| !call_ids_to_remove.contains(&d.call_id));
        }
        // Invalidate call flow cache for removed dialogs
        for cid in &call_ids_to_remove {
            app.call_flow_cache.remove(cid);
        }
        app.call_list.clear_selections();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    }
}

/// Clear calls that do NOT match the current filter (keep matching ones).
pub(super) fn clear_non_matching(app: &mut App) {
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
    app.call_flow_cache.clear();
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} non-matching dialogs", removed));
}

/// Clear calls that DO match the current filter (keep non-matching ones).
pub(super) fn clear_matching(app: &mut App) {
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
    app.call_flow_cache.clear();
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} matching dialogs", removed));
}

/// Handle keys in the stream list view.
pub(super) fn handle_stream_list_key(app: &mut App, key: KeyEvent) {
    let stream_count = app.stream_store.read().len();

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.stream_list.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.stream_list.move_down(stream_count),
        KeyCode::Home => app.stream_list.move_to_top(),
        KeyCode::End => app.stream_list.move_to_bottom(stream_count),
        KeyCode::Tab => {
            app.current_view = View::CallList;
        }
        k if k == app.keymap.search => {
            app.search_active = true;
            app.search_query.clear();
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        k if k == app.keymap.filter => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        KeyCode::Enter => {
            if let Some(key) = get_selected_stream_key(app) {
                app.stream_detail_scroll = 0;
                app.stream_detail_return_view = Some(View::StreamList);
                app.current_view = View::StreamDetail(key);
            }
        }
        // N — Name the selected stream's source address
        KeyCode::Char('N') => {
            if let Some(key) = get_selected_stream_key(app) {
                open_name_dialog(app, key.src.ip());
            }
        }
        KeyCode::Esc => app.current_view = View::CallList,
        _ => {}
    }
}

/// Handle keys in the RTP stream detail view.
pub(super) fn handle_stream_detail_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.stream_detail_scroll += 1;
        }
        KeyCode::PageUp => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.stream_detail_scroll += 20;
        }
        KeyCode::Home => app.stream_detail_scroll = 0,
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        KeyCode::Esc => {
            app.current_view = match app.stream_detail_return_view.take() {
                Some(v) => v,
                None => View::StreamList,
            };
        }
        #[cfg(feature = "audio")]
        KeyCode::Char('P') => {
            handle_stream_detail_play(app);
        }
        _ => {}
    }
}

/// Handle Shift+P audio playback toggle in stream detail view.
#[cfg(feature = "audio")]
pub(super) fn handle_stream_detail_play(app: &mut App) {
    // Don't re-attempt init if it already failed — retrying would
    // re-trigger libasound's stderr spam each keypress.
    if let Some(msg) = app.audio_init_error.as_deref() {
        app.status_error = Some(msg.to_string());
        return;
    }

    // Initialize player lazily on first use
    if app.audio_player.is_none() {
        match crate::rtp::playback::AudioPlayer::new() {
            Ok(player) => app.audio_player = Some(player),
            Err(e) => {
                let msg = format!("Audio init failed: {e}");
                app.status_error = Some(msg.clone());
                app.audio_init_error = Some(msg);
                return;
            }
        }
    }

    if let Some(player) = &app.audio_player {
        if player.is_playing() {
            player.stop();
            app.status_error = Some("Playback stopped".to_string());
        } else if let View::StreamDetail(ref key) = app.current_view {
            let store = app.stream_store.read();
            if let Some(stream) = store.get(key) {
                match player.play_stream(stream) {
                    Ok(msg) => app.status_error = Some(msg),
                    Err(e) => app.status_error = Some(format!("Playback error: {e}")),
                }
            }
        }
    }
}

/// Get the StreamKey for the currently selected row in the stream list.
pub(super) fn get_selected_stream_key(app: &App) -> Option<crate::rtp::stream::StreamKey> {
    let store = app.stream_store.read();
    let streams: Vec<_> = store.iter().collect();
    let idx = app.stream_list.selected();
    streams.get(idx).map(|s| s.key.clone())
}

/// Handle keys in the call flow view.
pub(super) fn handle_call_flow_key(app: &mut App, key: KeyEvent) {
    // Use the rendered (folded) message count. For extended flow, this includes
    // correlated legs. Fall back to raw dialog count if render hasn't run yet.
    let raw_count = if let View::CallFlow(ref call_id) = app.current_view {
        if app.extended_flow {
            // Extended: sum messages from main dialog + all correlated
            app.dialog_store
                .try_read()
                .map(|s| {
                    let base = s.get(call_id).map(|d| d.messages.len()).unwrap_or(0);
                    let correlated: usize = s
                        .find_correlated(call_id)
                        .iter()
                        .map(|d| d.messages.len())
                        .sum();
                    base + correlated
                })
                .unwrap_or(0)
        } else {
            app.dialog_store
                .try_read()
                .and_then(|s| s.get(call_id).map(|d| d.messages.len()))
                .unwrap_or(0)
        }
    } else {
        0
    };
    // Use cached rendered count if available, but never less than raw count
    // (folding reduces count, but raw count is the safe upper bound for navigation)
    let msg_count = if app.cached_flow_msg_count > 0 {
        app.cached_flow_msg_count.max(raw_count)
    } else {
        raw_count
    };

    // Clamp selected_msg_index to valid range
    if msg_count > 0 && app.selected_msg_index >= msg_count {
        app.selected_msg_index = msg_count - 1;
    }

    // In the split view, Tab moves focus between the ladder (left) and detail
    // (right) panes; the directional keys below then act on the focused pane.
    let detail_focused = app.raw_preview && app.call_flow_detail_focused;

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Tab | KeyCode::BackTab => {
            // Only meaningful when the detail pane is visible.
            if app.raw_preview {
                app.call_flow_detail_focused = !app.call_flow_detail_focused;
            }
        }
        KeyCode::Up | KeyCode::Char('k') if detail_focused => {
            app.detail_scroll = app.detail_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if detail_focused => {
            app.detail_scroll = app.detail_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_msg_index > 0 {
                app.selected_msg_index -= 1;
                app.detail_scroll = 0;
            }
            // Auto-scroll ladder to keep selection visible
            if app.selected_msg_index < app.call_flow_scroll {
                app.call_flow_scroll = app.selected_msg_index;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if msg_count > 0 && app.selected_msg_index < msg_count - 1 {
                app.selected_msg_index += 1;
                app.detail_scroll = 0;
            }
            // Auto-scroll ladder to keep selection visible
            // (each message takes ~1 row in the ladder, header takes 2 rows)
            let visible_rows = app.call_flow_scroll + 20; // approximate
            if app.selected_msg_index >= visible_rows {
                app.call_flow_scroll = app.selected_msg_index.saturating_sub(10);
            }
        }
        KeyCode::PageUp if detail_focused => {
            app.detail_scroll = app.detail_scroll.saturating_sub(20);
        }
        KeyCode::PageDown if detail_focused => {
            app.detail_scroll = app.detail_scroll.saturating_add(20);
        }
        KeyCode::Home if detail_focused => {
            app.detail_scroll = 0;
        }
        KeyCode::PageUp => {
            app.selected_msg_index = app.selected_msg_index.saturating_sub(20);
            app.call_flow_scroll = app.call_flow_scroll.saturating_sub(20);
            app.detail_scroll = 0;
        }
        KeyCode::PageDown => {
            let max = if msg_count > 0 { msg_count - 1 } else { 0 };
            app.selected_msg_index = (app.selected_msg_index + 20).min(max);
            app.call_flow_scroll += 20;
            app.detail_scroll = 0;
        }
        KeyCode::Home => {
            app.selected_msg_index = 0;
            app.call_flow_scroll = 0;
            app.detail_scroll = 0;
        }
        KeyCode::End => {
            if msg_count > 0 {
                app.selected_msg_index = msg_count - 1;
                app.call_flow_scroll = msg_count.saturating_sub(1);
            }
            app.detail_scroll = 0;
        }
        KeyCode::Enter => {
            if let View::CallFlow(ref call_id) = app.current_view
                && app.selected_msg_index < msg_count
            {
                // Check if this message is an RTP bar entry — if so, drill
                // down to stream detail. Otherwise show raw SIP message.
                let is_rtp = app.cached_rtp_bar_indices.contains(&app.selected_msg_index);
                if is_rtp {
                    let cid = call_id.clone();
                    // Find a stream linked to this dialog, or any stream
                    let stream_key = {
                        let store = app.stream_store.read();
                        store
                            .iter()
                            .find(|s| s.associated_dialog.as_deref() == Some(&cid))
                            .or_else(|| store.iter().next())
                            .map(|s| s.key.clone())
                    };
                    if let Some(key) = stream_key {
                        app.stream_detail_scroll = 0;
                        app.stream_detail_return_view = Some(app.current_view.clone());
                        app.current_view = View::StreamDetail(key);
                    } else {
                        app.status_error = Some("No RTP streams found".to_string());
                    }
                } else {
                    // Open full-screen raw message view for the selected message
                    let cid = call_id.clone();
                    app.raw_msg_scroll = 0;
                    app.current_view = View::RawMessage {
                        call_id: cid,
                        message_index: app.selected_msg_index,
                    };
                }
            }
        }
        KeyCode::Char(' ') => {
            // Select message for diff comparison
            if let View::CallFlow(ref call_id) = app.current_view
                && app.selected_msg_index < msg_count
            {
                if let Some(first) = app.diff_selected_msg {
                    if first != app.selected_msg_index {
                        // Second selection — open diff view
                        let cid = call_id.clone();
                        let msg2 = app.selected_msg_index;
                        app.diff_selected_msg = None;
                        app.current_view = View::MessageDiff {
                            call_id: cid,
                            msg1_idx: first,
                            msg2_idx: msg2,
                        };
                    }
                } else {
                    // First selection
                    app.diff_selected_msg = Some(app.selected_msg_index);
                    app.status_error = Some(format!(
                        "Selected: message {} (press Space on another to diff)",
                        app.selected_msg_index + 1
                    ));
                }
            }
        }
        KeyCode::Char('r') => {
            // Jump to RTP Streams view
            app.current_view = View::StreamList;
        }
        // N — Name the selected message's source address
        KeyCode::Char('N') => {
            if let View::CallFlow(ref call_id) = app.current_view {
                let sel = app.selected_msg_index;
                let ip = app.dialog_store.try_read().and_then(|s| {
                    s.get(call_id).map(|d| {
                        d.messages
                            .get(sel)
                            .map(|m| m.src_addr)
                            .unwrap_or(d.src_addr)
                    })
                });
                if let Some(ip) = ip {
                    open_name_dialog(app, ip);
                }
            }
        }
        KeyCode::Char('d') => {
            // Toggle SDP display mode
            app.sdp_display_mode = app.sdp_display_mode.next();
            app.call_flow_cache.clear();
            app.status_error = Some(app.sdp_display_mode.label().to_string());
        }
        KeyCode::Char('t') => {
            // Toggle timestamp display
            app.timestamp_mode = app.timestamp_mode.next();
            app.call_flow_cache.clear();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        KeyCode::Char('c') => {
            // Cycle color mode
            app.color_mode = app.color_mode.next();
            app.call_flow_cache.clear();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        KeyCode::Char('R') => {
            // Toggle raw preview split
            app.raw_preview = !app.raw_preview;
            if !app.raw_preview {
                // No detail pane to focus once the split is hidden.
                app.call_flow_detail_focused = false;
            }
            app.status_error = Some(if app.raw_preview {
                "Raw preview: ON".to_string()
            } else {
                "Raw preview: OFF".to_string()
            });
        }
        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('0') | KeyCode::Left => {
            // Increase detail panel size (Left = push split leftward = detail wider)
            if app.raw_preview && app.raw_preview_pct < 80 {
                app.raw_preview_pct = (app.raw_preview_pct + 5).min(80);
                app.status_error = Some(format!("Detail panel: {}%", app.raw_preview_pct));
            }
        }
        KeyCode::Char('-') | KeyCode::Char('9') | KeyCode::Right => {
            // Decrease detail panel size (Right = push split rightward = ladder wider)
            if app.raw_preview && app.raw_preview_pct > 10 {
                app.raw_preview_pct = app.raw_preview_pct.saturating_sub(5).max(10);
                app.status_error = Some(format!("Detail panel: {}%", app.raw_preview_pct));
            }
        }
        KeyCode::Char('[') => {
            // Scroll detail panel up
            app.detail_scroll = app.detail_scroll.saturating_sub(1);
        }
        KeyCode::Char(']') => {
            // Scroll detail panel down
            app.detail_scroll = app.detail_scroll.saturating_add(1);
        }
        k if k == app.keymap.extended_flow || k == KeyCode::Char('x') => {
            // Toggle extended (multi-leg) flow
            app.extended_flow = !app.extended_flow;
            app.call_flow_cache.clear();
            app.status_error = Some(if app.extended_flow {
                "Extended flow: ON (multi-leg)".to_string()
            } else {
                "Extended flow: OFF".to_string()
            });
        }
        KeyCode::F(6) => {
            // Toggle RTP display in flow
            app.show_rtp_in_flow = !app.show_rtp_in_flow;
            app.call_flow_cache.clear();
            app.status_error = Some(if app.show_rtp_in_flow {
                "RTP in flow: ON".to_string()
            } else {
                "RTP in flow: OFF".to_string()
            });
        }
        KeyCode::Char('m') => {
            app.mark_index = Some(app.selected_msg_index);
            app.status_error = Some("Mark set".to_string());
        }
        KeyCode::Char('M') => {
            app.mark_index = None;
            app.status_error = Some("Mark cleared".to_string());
        }
        KeyCode::Char('e') => {
            let idx = app.selected_msg_index;
            if app.fold_expanded.contains(&idx) {
                app.fold_expanded.remove(&idx);
            } else {
                app.fold_expanded.insert(idx);
            }
            app.call_flow_cache.clear();
        }
        KeyCode::Char('E') => {
            // Export Mermaid sequence diagram to clipboard
            if let View::CallFlow(ref call_id) = app.current_view
                && let Some(store) = app.dialog_store.try_read()
            {
                let prepared = store.get(call_id).and_then(|d| {
                    if d.messages.is_empty() {
                        return None;
                    }
                    let ft = d.messages[0].timestamp;
                    let pdd = d.timing.pdd_ms();
                    let flow_opts = call_flow::FlowDisplayOptions {
                        sdp_mode: app.sdp_display_mode,
                        ts_mode: app.timestamp_mode,
                        color_mode: app.color_mode,
                        show_rtp: app.show_rtp_in_flow,
                        selected_msg: None,
                        theme: &app.theme,
                        resolver: app.resolver.as_ref(),
                        name_mode: app.name_mode,
                    };
                    let (participants, msgs) = call_flow::prepare_messages(
                        &d.messages,
                        ft,
                        pdd,
                        &flow_opts,
                        &app.fold_expanded,
                    );
                    Some((participants, msgs))
                });
                if let Some((ref participants, ref msgs)) = prepared {
                    let mermaid = call_flow::export::export_mermaid(participants, msgs);
                    let cmd = if cfg!(target_os = "macos") {
                        "pbcopy"
                    } else {
                        "xclip"
                    };
                    let args: Vec<&str> = if cfg!(target_os = "macos") {
                        vec![]
                    } else {
                        vec!["-selection", "clipboard"]
                    };
                    let result = std::process::Command::new(cmd)
                        .args(&args)
                        .stdin(std::process::Stdio::piped())
                        .spawn()
                        .and_then(|mut child| {
                            use std::io::Write;
                            if let Some(ref mut stdin) = child.stdin {
                                stdin.write_all(mermaid.as_bytes())?;
                            }
                            child.wait()
                        });
                    match result {
                        Ok(_) => {
                            app.status_error =
                                Some("Mermaid diagram copied to clipboard".to_string());
                        }
                        Err(e) => {
                            app.status_error = Some(format!("Clipboard: {e}"));
                        }
                    }
                } else {
                    app.status_error = Some("No messages to export".to_string());
                }
            }
        }
        KeyCode::Esc => {
            app.diff_selected_msg = None;
            app.current_view = View::CallList;
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        k if k == app.keymap.clear_calls => {
            // F5 also starts compare mode (same as first Space press)
            app.diff_selected_msg = None;
            app.status_error =
                Some("Compare: press Space on first message, then Space on second".to_string());
        }
        k if k == app.keymap.filter => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        KeyCode::F(9) => {
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_dialog.clear();
            app.status_error = None;
        }
        _ => {}
    }
}

/// Handle keys in the raw message view.
pub(super) fn handle_raw_message_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(20);
        }
        KeyCode::Home => app.raw_msg_scroll = 0,
        k if k == app.keymap.search => {
            app.search_active = true;
            app.search_query.clear();
        }
        KeyCode::Char('s') => {
            // Toggle syntax highlighting
            app.syntax_highlight = !app.syntax_highlight;
            app.status_error = Some(if app.syntax_highlight {
                "Syntax highlighting: ON".to_string()
            } else {
                "Syntax highlighting: OFF".to_string()
            });
        }
        KeyCode::Char('c') => {
            // Cycle color mode
            app.color_mode = app.color_mode.next();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        KeyCode::Esc => {
            if let View::RawMessage { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        _ => {}
    }
}

/// Handle keys in the message diff view.
pub(super) fn handle_message_diff_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Esc => {
            if let View::MessageDiff { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        KeyCode::F(1) => app.current_view = View::Help,
        _ => {}
    }
}

/// Handle keys in the help view.
pub(super) fn handle_help_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == KeyCode::Esc || k == app.keymap.help || k == app.keymap.quit => {
            app.current_view = View::CallList;
        }
        _ => {}
    }
}

/// Open the save popup, pre-populating path and counts.
///
/// From a stream view, defaults to WAV export; otherwise defaults to PCAP.
pub(super) fn open_save_popup(app: &mut App) {
    app.save_format = match app.current_view {
        View::StreamList | View::StreamDetail(_) => SaveFormat::Wav,
        _ => SaveFormat::default(),
    };

    let now = chrono::Local::now();
    let ext = app.save_format.extension();
    app.save_path = format!("/tmp/sipnab_{}.{ext}", now.format("%Y%m%d_%H%M%S"));
    app.save_cursor = app.save_path.len();

    // Cache counts for display
    let store = app.dialog_store.read();
    app.save_dialog_count = store.len();
    app.save_selected_count = app.call_list.selected_rows_count();
    app.save_message_count = store.iter().map(|d| d.messages.len()).sum();
    drop(store);

    app.active_popup = Some(Popup::SaveDialog);
}

/// Handle keys for any active popup dialog.
pub(super) fn handle_popup_key(app: &mut App, key: KeyEvent) {
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

/// Handle keys in the save dialog popup.
pub(super) fn handle_save_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            let path = app.save_path.clone();
            let msg = match app.save_format {
                SaveFormat::Pcap => save_to_pcap_path(app, &path, false),
                SaveFormat::PcapNg => save_to_pcap_path(app, &path, true),
                SaveFormat::Txt => save_to_txt_path(app, &path),
                SaveFormat::Json => save_to_json_path(app, &path),
                SaveFormat::Ndjson => save_to_ndjson_path(app, &path),
                SaveFormat::Csv => save_to_csv_path(app, &path),
                SaveFormat::Html => save_to_mermaid_path(app, &path),
                SaveFormat::Markdown => save_to_markdown_path(app, &path),
                SaveFormat::Wav => save_to_wav_path(app, &path),
                SaveFormat::SippXml => save_to_sipp_path(app, &path),
                SaveFormat::RtpJson => save_to_rtp_json_path(app, &path),
            };
            app.status_error = Some(msg);
            app.active_popup = None;
        }
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Down | KeyCode::Up => {
            // Cycle save format and update file extension
            let old_ext = app.save_format.extension();
            app.save_format = if key.code == KeyCode::BackTab || key.code == KeyCode::Up {
                app.save_format.prev()
            } else {
                app.save_format.next()
            };
            let new_ext = app.save_format.extension();
            // Update the file extension in the path
            if let Some(dot_pos) = app.save_path.rfind('.') {
                let after_dot = &app.save_path[dot_pos + 1..];
                if after_dot == old_ext {
                    app.save_path.truncate(dot_pos + 1);
                    app.save_path.push_str(new_ext);
                    app.save_cursor = app.save_path.len();
                }
            }
        }
        KeyCode::Backspace => {
            if app.save_cursor > 0 {
                // Find the previous char boundary
                let prev = app.save_path[..app.save_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.save_path.remove(prev);
                app.save_cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.save_cursor > 0 {
                app.save_cursor = app.save_path[..app.save_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.save_cursor < app.save_path.len() {
                app.save_cursor = app.save_path[app.save_cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.save_cursor + i)
                    .unwrap_or(app.save_path.len());
            }
        }
        KeyCode::Home => {
            app.save_cursor = 0;
        }
        KeyCode::End => {
            app.save_cursor = app.save_path.len();
        }
        KeyCode::Char(c) => {
            app.save_path.insert(app.save_cursor, c);
            app.save_cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Open the file-open dialog, seeding it with a directory listing rooted at
/// the last-browsed directory (or the current working directory on first use).
pub(super) fn open_file_dialog(app: &mut App) {
    if !app.open_dir.is_dir() {
        app.open_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    }
    app.open_filter.clear();
    app.open_manual_mode = false;
    app.open_path.clear();
    app.open_cursor = 0;
    refresh_file_entries(app);
    app.active_popup = Some(Popup::FileOpenDialog);
}

/// Extensions recognised as pcap/pcapng files by the file browser.
pub(super) const PCAP_EXTENSIONS: &[&str] = &["pcap", "pcapng", "cap"];

/// True if `name` is a capture file the browser should list: a bare
/// pcap/pcapng/cap file, or a gzip-compressed one (`*.pcap.gz`, `*.cap.gz`…).
///
/// [`crate::capture::file::open_offline`] transparently decompresses gzip
/// captures (it sniffs the `1f 8b` magic), so hiding `*.gz` here would let the
/// browser refuse files the loader can actually open. Case-insensitive.
pub(super) fn is_browsable_capture(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Peel an optional `.gz` so `foo.pcap.gz` is judged by its `.pcap` stem.
    let stem = lower.strip_suffix(".gz").unwrap_or(lower.as_str());
    std::path::Path::new(stem)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| PCAP_EXTENSIONS.iter().any(|p| p == &e))
        .unwrap_or(false)
}

/// Rebuild [`App::open_entries`] from the current [`App::open_dir`], applying
/// [`App::open_filter`] and sorting dirs-first / alphabetical.
pub(super) fn refresh_file_entries(app: &mut App) {
    let mut entries: Vec<FileEntry> = Vec::new();

    if let Some(parent) = app.open_dir.parent() {
        entries.push(FileEntry {
            name: "..".to_string(),
            path: parent.to_path_buf(),
            is_dir: true,
        });
    }

    match std::fs::read_dir(&app.open_dir) {
        Err(e) => {
            // Surface the failure instead of showing a blank list. The most
            // common cause is running under sudo: the capture process drops
            // privileges to an unprivileged user that can't read the (0700)
            // home directory.
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                " — the capture process dropped privileges to an unprivileged \
                 user; run sipnab without sudo to browse your own files"
            } else {
                ""
            };
            app.open_error = Some(format!(
                "Cannot read {}: {}{}",
                app.open_dir.display(),
                e,
                hint
            ));
        }
        Ok(read_dir) => {
            app.open_error = None;
            let filter_lc = app.open_filter.to_lowercase();
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && !filter_lc.starts_with('.') {
                    continue;
                }
                let is_dir = match entry.file_type() {
                    // `file_type()` does not follow symlinks, so a symlinked
                    // directory reports `is_dir() == false`. Resolve via
                    // `metadata()` (which does follow) so directory symlinks
                    // still appear in the browser. Broken or unreadable links
                    // fall through as non-directories.
                    Ok(ft) if ft.is_symlink() => std::fs::metadata(entry.path())
                        .map(|m| m.is_dir())
                        .unwrap_or(false),
                    Ok(ft) => ft.is_dir(),
                    Err(_) => false,
                };

                if !is_dir && !is_browsable_capture(&name) {
                    continue;
                }

                if !filter_lc.is_empty() && !name.to_lowercase().contains(&filter_lc) {
                    continue;
                }

                entries.push(FileEntry {
                    name,
                    path: entry.path(),
                    is_dir,
                });
            }
        }
    }

    entries.sort_by(|a, b| match (a.name.as_str(), b.name.as_str()) {
        ("..", _) => std::cmp::Ordering::Less,
        (_, "..") => std::cmp::Ordering::Greater,
        _ => match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        },
    });

    app.open_entries = entries;
    if app.open_selected >= app.open_entries.len() {
        app.open_selected = app.open_entries.len().saturating_sub(1);
    }
}

/// Handle keys in the file-open dialog popup.
pub(super) fn handle_file_open_popup_key(app: &mut App, key: KeyEvent) {
    if app.open_manual_mode {
        handle_file_open_manual_key(app, key);
        return;
    }

    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Tab => {
            app.open_manual_mode = true;
            if app.open_path.is_empty() {
                app.open_path = app.open_dir.to_string_lossy().into_owned();
                if !app.open_path.ends_with(std::path::MAIN_SEPARATOR) {
                    app.open_path.push(std::path::MAIN_SEPARATOR);
                }
            }
            app.open_cursor = app.open_path.len();
        }
        KeyCode::Up => {
            if app.open_selected > 0 {
                app.open_selected -= 1;
            }
        }
        KeyCode::Down => {
            if app.open_selected + 1 < app.open_entries.len() {
                app.open_selected += 1;
            }
        }
        KeyCode::PageUp => {
            app.open_selected = app.open_selected.saturating_sub(10);
        }
        KeyCode::PageDown => {
            app.open_selected =
                (app.open_selected + 10).min(app.open_entries.len().saturating_sub(1));
        }
        KeyCode::Home => app.open_selected = 0,
        KeyCode::End => {
            app.open_selected = app.open_entries.len().saturating_sub(1);
        }
        KeyCode::Enter => {
            let entry = match app.open_entries.get(app.open_selected).cloned() {
                Some(e) => e,
                None => return,
            };
            if entry.is_dir {
                app.open_dir = entry.path;
                app.open_filter.clear();
                app.open_selected = 0;
                refresh_file_entries(app);
            } else {
                let path = entry.path.to_string_lossy().into_owned();
                let msg = load_pcap_file(app, &path);
                app.status_error = Some(msg);
                app.active_popup = None;
            }
        }
        KeyCode::Backspace => {
            if !app.open_filter.is_empty() {
                app.open_filter.pop();
                app.open_selected = 0;
                refresh_file_entries(app);
            } else if let Some(parent) = app.open_dir.parent() {
                app.open_dir = parent.to_path_buf();
                app.open_selected = 0;
                refresh_file_entries(app);
            }
        }
        KeyCode::Char(c) => {
            app.open_filter.push(c);
            app.open_selected = 0;
            refresh_file_entries(app);
        }
        _ => {}
    }
}

/// Manual-path edit mode within the file-open dialog.
/// Tab toggles back to browser mode; Enter loads the typed path.
pub(super) fn handle_file_open_manual_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Tab => {
            app.open_manual_mode = false;
        }
        KeyCode::Enter => {
            let path = expand_tilde(&app.open_path);
            if path.is_empty() {
                app.status_error = Some("No file path specified".to_string());
                app.active_popup = None;
                return;
            }
            let msg = load_pcap_file(app, &path);
            app.status_error = Some(msg);
            app.active_popup = None;
        }
        KeyCode::Backspace => {
            if app.open_cursor > 0 {
                let prev = app.open_path[..app.open_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.open_path.remove(prev);
                app.open_cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.open_cursor > 0 {
                app.open_cursor = app.open_path[..app.open_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.open_cursor < app.open_path.len() {
                app.open_cursor = app.open_path[app.open_cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.open_cursor + i)
                    .unwrap_or(app.open_path.len());
            }
        }
        KeyCode::Home => {
            app.open_cursor = 0;
        }
        KeyCode::End => {
            app.open_cursor = app.open_path.len();
        }
        KeyCode::Char(c) => {
            app.open_path.insert(app.open_cursor, c);
            app.open_cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Expand a leading `~` to the user's home directory.
pub(super) fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~')
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}{rest}");
    }
    path.to_string()
}

/// Load a pcap file into the application, replacing all existing data.
///
/// Parses each packet through etherparse, then routes it through SIP, RTP,
/// and RTCP detection — mirroring the online-capture pipeline so that
/// RTP-only pcaps populate the stream store for playback and WAV export.
pub(super) fn load_pcap_file(app: &mut App, path_str: &str) -> String {
    use crate::capture::parse::TransportProto;

    let path = std::path::Path::new(path_str);
    if !path.exists() {
        return format!("File not found: {path_str}");
    }

    // Transparently handles gzip-compressed captures (libpcap cannot). The
    // guard owns any decompressed temp file and must outlive the read loop
    // below, so keep it bound for the rest of the function.
    let (mut cap, _gz_guard) = match crate::capture::file::open_offline(path) {
        Ok(opened) => opened,
        Err(e) => return format!("Failed to open: {e:#}"),
    };

    // Clear existing data
    {
        let mut ds = app.dialog_store.write();
        ds.clear();
    }
    {
        let mut ss = app.stream_store.write();
        ss.clear();
    }

    // Reset TUI state (preserve column visibility preferences)
    let saved_columns = app.call_list.visible_columns;
    app.call_list = CallListState::new();
    app.call_list.visible_columns = saved_columns;
    app.stream_list = StreamListState::new();
    app.active_filter = None;
    app.active_filter_text.clear();
    app.call_flow_cache.clear();
    app.selected_msg_index = 0;
    app.call_flow_scroll = 0;
    app.cached_flow_msg_count = 0;
    app.cached_rtp_bar_indices.clear();
    app.fold_expanded.clear();
    app.mark_index = None;
    app.current_view = View::CallList;

    let mut packet_count = 0u64;
    let mut sip_count = 0u64;
    let mut rtp_count = 0u64;
    let mut rtcp_count = 0u64;
    let mut rtp_heuristic = crate::rtp::heuristic::RtpHeuristic::new();
    let link_type = cap.get_datalink().0;

    while let Ok(pkt) = cap.next_packet() {
        packet_count += 1;

        let ts = chrono::DateTime::from_timestamp(
            pkt.header.ts.tv_sec,
            (pkt.header.ts.tv_usec as u32) * 1000,
        )
        .unwrap_or_else(chrono::Utc::now);

        let capture_pkt = crate::capture::Packet::new(
            ts,
            pkt.data.to_vec(),
            pkt.header.caplen as usize,
            pkt.header.len as usize,
            None,
            link_type,
        );

        let Ok(parsed) = crate::capture::parse::parse_packet(&capture_pkt) else {
            continue;
        };
        if parsed.payload.is_empty() {
            continue;
        }

        // SIP: parse the message, ingest it into the dialog store, and link
        // any SDP media endpoints so matching RTP streams join the dialog.
        if crate::sip::is_sip_message(&parsed.payload) {
            if let Ok(sip_msg) = crate::sip::parser::parse_sip(
                &parsed.payload,
                parsed.timestamp,
                parsed.src_addr,
                parsed.dst_addr,
                parsed.src_port,
                parsed.dst_port,
                parsed.transport,
            ) {
                let sdp_links: Vec<(std::net::IpAddr, u16, String, crate::sip::sdp::SdpMedia)> =
                    if let Some(sdp) = sip_msg.sdp()
                        && let Some(call_id) = sip_msg.call_id()
                    {
                        sdp.media
                            .iter()
                            .filter_map(|media| {
                                crate::sip::sdp::effective_address(media, &sdp)
                                    .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                                    .map(|ip| (ip, media.port, call_id.to_string(), media.clone()))
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                app.dialog_store.write().process_message(sip_msg);
                sip_count += 1;

                if !sdp_links.is_empty() {
                    let mut ss = app.stream_store.write();
                    for (ip, port, call_id, media) in &sdp_links {
                        ss.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                    }
                }
            }
            continue;
        }

        // RTP/RTCP detection — only UDP, and only after SIP was ruled out.
        if parsed.transport != TransportProto::Udp {
            continue;
        }

        if is_rtcp_offline(&parsed.payload, parsed.dst_port) {
            let rtcp_packets = crate::rtp::rtcp::parse_rtcp(&parsed.payload);
            if !rtcp_packets.is_empty() {
                app.stream_store.write().process_rtcp(&rtcp_packets);
                rtcp_count += rtcp_packets.len() as u64;
            }
            continue;
        }

        if crate::rtp::is_rtp_packet(&parsed.payload)
            && let Ok(rtp_hdr) = crate::rtp::parser::parse_rtp_header(&parsed.payload)
        {
            app.stream_store
                .write()
                .process_rtp(&parsed, &rtp_hdr, parsed.timestamp);
            rtp_count += 1;
            continue;
        }

        if let Some(rtp_hdr) = rtp_heuristic.check(&parsed) {
            app.stream_store
                .write()
                .process_rtp(&parsed, &rtp_hdr, parsed.timestamp);
            rtp_count += 1;
        }
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path_str);
    app.set_capture_mode(format!("Offline ({filename})"));
    app.mark_data_updated();

    // Read pcapng metadata blocks that the libpcap reader ignores: load embedded
    // Name Resolution Block names into the resolver, and surface any embedded
    // Decryption Secrets Block so the operator is alerted the file carries keys.
    let mut names_loaded = 0;
    let mut secrets_present = 0;
    if let Ok(meta) = crate::capture::pcapng_meta::read_pcapng_metadata(path) {
        if !meta.names.is_empty() {
            names_loaded = app.resolver.load_file_names(meta.names);
            if names_loaded > 0 && app.name_mode == crate::names::NameMode::Off {
                app.name_mode = crate::names::NameMode::Names;
            }
        }
        secrets_present = meta.tls_secrets.len();
    }

    // If the pcap had no SIP but did have RTP streams, jump straight to the
    // stream list so playback / WAV export are immediately reachable.
    let stream_count = app.stream_store.read().len();
    if sip_count == 0 && stream_count > 0 {
        app.current_view = View::StreamList;
    }

    let rtcp_suffix = if rtcp_count > 0 {
        format!(", {rtcp_count} RTCP")
    } else {
        String::new()
    };
    let names_suffix = if names_loaded > 0 {
        format!(", {names_loaded} name(s)")
    } else {
        String::new()
    };
    let secrets_suffix = if secrets_present > 0 {
        format!(" \u{26a0} file contains {secrets_present} embedded decryption secret(s)")
    } else {
        String::new()
    };
    format!(
        "Loaded {sip_count} SIP, {rtp_count} RTP{rtcp_suffix}{names_suffix} from {packet_count} packets across {stream_count} stream(s) ({filename}){secrets_suffix}"
    )
}

/// Offline RTCP heuristic — matches the online-capture check in `main.rs`:
/// odd dst port, version=2, and payload type in the 200-204 range.
pub(super) fn is_rtcp_offline(data: &[u8], dst_port: u16) -> bool {
    if data.len() < 8 {
        return false;
    }
    if dst_port.is_multiple_of(2) {
        return false;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return false;
    }
    let pt = data[1];
    (200..=204).contains(&pt)
}

/// Apply the filter dialog state: build a DSL expression, parse it, and set the active filter.
pub(super) fn apply_filter_dialog(app: &mut App) {
    // No SIP methods selected => show nothing. This is the explicit "mute
    // everything" state (distinct from all-checked, which shows everything).
    if !app.filter_dialog.any_method_checked() {
        app.active_filter = Some(FilterExpr::never());
        app.active_filter_text = "(no methods selected)".to_string();
        app.status_error = None;
        app.active_popup = None;
        return;
    }
    match app.filter_dialog.build_filter_expression() {
        Some(expr_text) => match FilterExpr::parse(&expr_text) {
            Ok(expr) => {
                app.active_filter = Some(expr);
                app.active_filter_text = expr_text;
                app.status_error = None;
            }
            Err(e) => {
                app.status_error = Some(format!("Filter error: {e}"));
            }
        },
        None => {
            // All fields empty — clear any active filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
        }
    }
    app.active_popup = None;
}

/// Handle keys in the filter dialog popup.
pub(super) fn handle_filter_popup_key(app: &mut App, key: KeyEvent) {
    let is_shift = key.modifiers.contains(KeyModifiers::SHIFT);

    match key.code {
        KeyCode::Esc => {
            // Cancel without applying
            app.active_popup = None;
        }
        KeyCode::Enter => {
            if app.filter_dialog.focused_field == CANCEL_BUTTON_IDX {
                // Cancel button
                app.active_popup = None;
            } else {
                // Apply filter (from Filter button or any other field)
                apply_filter_dialog(app);
            }
        }
        KeyCode::Tab => {
            if is_shift {
                app.filter_dialog.focus_prev();
            } else {
                app.filter_dialog.focus_next();
            }
        }
        KeyCode::BackTab => {
            app.filter_dialog.focus_prev();
        }
        KeyCode::Down => {
            if app.filter_dialog.is_checkbox_focused() {
                app.filter_dialog.checkbox_down();
            } else {
                app.filter_dialog.focus_next();
            }
        }
        KeyCode::Up => {
            if app.filter_dialog.is_checkbox_focused() {
                app.filter_dialog.checkbox_up();
            } else {
                app.filter_dialog.focus_prev();
            }
        }
        KeyCode::Right if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.checkbox_right();
        }
        KeyCode::Left if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.checkbox_left();
        }
        KeyCode::F(9) => {
            // F9 clears all fields and the active filter, closes popup
            app.filter_dialog.clear();
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
            app.active_popup = None;
        }
        KeyCode::Char(' ') if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.toggle_checkbox();
        }
        KeyCode::Char(' ') if app.filter_dialog.focused_field == FILTER_BUTTON_IDX => {
            apply_filter_dialog(app);
        }
        KeyCode::Char(' ') if app.filter_dialog.focused_field == CANCEL_BUTTON_IDX => {
            app.active_popup = None;
        }
        // Text editing (only when a text field is focused)
        KeyCode::Backspace if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if cursor > 0
                && let Some(field) = app.filter_dialog.text_field_mut(idx)
            {
                field.remove(cursor - 1);
                app.filter_dialog.cursor_pos -= 1;
            }
        }
        KeyCode::Delete if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if let Some(field) = app.filter_dialog.text_field_mut(idx)
                && cursor < field.len()
            {
                field.remove(cursor);
            }
        }
        KeyCode::Left if app.filter_dialog.is_text_field_focused() => {
            app.filter_dialog.cursor_pos = app.filter_dialog.cursor_pos.saturating_sub(1);
        }
        KeyCode::Right if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let len = app.filter_dialog.text_field(idx).len();
            if app.filter_dialog.cursor_pos < len {
                app.filter_dialog.cursor_pos += 1;
            }
        }
        KeyCode::Home if app.filter_dialog.is_text_field_focused() => {
            app.filter_dialog.cursor_pos = 0;
        }
        KeyCode::End if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            app.filter_dialog.cursor_pos = app.filter_dialog.text_field(idx).len();
        }
        KeyCode::Char(c) if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if let Some(field) = app.filter_dialog.text_field_mut(idx) {
                field.insert(cursor, c);
                app.filter_dialog.cursor_pos += 1;
            }
        }
        _ => {}
    }
}

/// Handle keys in the settings popup.
pub(super) fn handle_settings_popup_key(app: &mut App, key: KeyEvent) {
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
            match app.settings_dialog.focused_item {
                0 => app.color_mode = app.color_mode.next(),
                1 => app.timestamp_mode = app.timestamp_mode.next(),
                2 => app.call_list.autoscroll = !app.call_list.autoscroll,
                3 => app.raw_preview = !app.raw_preview,
                4 => app.sdp_display_mode = app.sdp_display_mode.next(),
                5 => app.syntax_highlight = !app.syntax_highlight,
                _ => {}
            }
            app.call_flow_cache.clear();
        }
        _ => {}
    }
}

/// Handle keys in the statistics view.
pub(super) fn handle_statistics_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == KeyCode::Esc || k == app.keymap.quit || k == KeyCode::Char('s') => {
            app.current_view = View::CallList;
        }
        _ => {}
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Get the Call-ID of the currently selected dialog in the call list,
/// respecting the active filter.
pub(super) fn get_selected_call_id(app: &App) -> Option<String> {
    let store = app.dialog_store.read();
    let dialogs: Vec<_> = if let Some(ref filter) = app.active_filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .collect()
    } else {
        store.iter().collect()
    };
    let idx = app.call_list.selected();
    dialogs.get(idx).map(|d| d.call_id.clone())
}

/// Source IP of the selected call-list dialog (for the Name Address popup).
pub(super) fn get_selected_dialog_src(app: &App) -> Option<std::net::IpAddr> {
    let store = app.dialog_store.read();
    let dialogs: Vec<_> = if let Some(ref filter) = app.active_filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .collect()
    } else {
        store.iter().collect()
    };
    dialogs.get(app.call_list.selected()).map(|d| d.src_addr)
}

/// Open the "Name Address" popup pre-filled with `ip` and its existing name.
pub(super) fn open_name_dialog(app: &mut App, ip: std::net::IpAddr) {
    let existing = app
        .resolver
        .manual_entries()
        .into_iter()
        .find(|(i, _)| *i == ip)
        .map(|(_, n)| n)
        .unwrap_or_default();
    app.name_dialog.cursor = existing.len();
    app.name_dialog.name = existing;
    app.name_dialog.ip = ip.to_string();
    app.active_popup = Some(Popup::NameAddress);
}

/// Handle keys in the "Name Address" popup (single editable name field).
pub(super) fn handle_name_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            apply_name_dialog(app);
            app.active_popup = None;
        }
        KeyCode::Backspace => {
            if app.name_dialog.cursor > 0 {
                let prev = app.name_dialog.name[..app.name_dialog.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.name_dialog.name.remove(prev);
                app.name_dialog.cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.name_dialog.cursor > 0 {
                app.name_dialog.cursor = app.name_dialog.name[..app.name_dialog.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.name_dialog.cursor < app.name_dialog.name.len() {
                app.name_dialog.cursor = app.name_dialog.name[app.name_dialog.cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.name_dialog.cursor + i)
                    .unwrap_or(app.name_dialog.name.len());
            }
        }
        KeyCode::Home => app.name_dialog.cursor = 0,
        KeyCode::End => app.name_dialog.cursor = app.name_dialog.name.len(),
        KeyCode::Char(c) => {
            app.name_dialog.name.insert(app.name_dialog.cursor, c);
            app.name_dialog.cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Apply the Name Address popup: set or clear the manual mapping, persist it,
/// and turn name resolution on so the change is visible immediately.
fn apply_name_dialog(app: &mut App) {
    let Ok(ip) = app.name_dialog.ip.parse::<std::net::IpAddr>() else {
        return;
    };
    let name = app.name_dialog.name.trim().to_string();
    if name.is_empty() {
        app.resolver.remove_manual(&ip);
        app.status_error = Some(format!("Cleared name for {ip}"));
    } else if !crate::names::is_valid_name(&name) {
        app.status_error =
            Some("Invalid name (control characters or too long); not saved".to_string());
        return;
    } else {
        app.resolver.set_manual(ip, name.clone());
        app.status_error = Some(format!("{ip} \u{2192} {name}"));
        if app.name_mode == crate::names::NameMode::Off {
            app.name_mode = crate::names::NameMode::Names;
        }
    }
    app.call_flow_cache.clear();
    if let Some(path) = app.names_save_path.clone()
        && let Err(e) = app.resolver.save_manual_file(&path)
    {
        app.status_error = Some(format!("Named, but couldn't save {}: {e}", path.display()));
    }
    // Opt-in: also persist the full manual table into the user's sipnabrc,
    // preserving comments and other sections.
    if let Some(path) = app.names_config_path.clone() {
        let entries: Vec<(String, String)> = app
            .resolver
            .manual_entries()
            .into_iter()
            .map(|(ip, n)| (ip.to_string(), n))
            .collect();
        if let Err(e) = crate::config::write_manual_mappings_file(&path, &entries) {
            app.status_error = Some(format!(
                "Named, but couldn't update {}: {e}",
                path.display()
            ));
        }
    }
}

/// Count dialogs visible after applying the active filter.
pub(super) fn filtered_dialog_count(app: &App) -> usize {
    let store = app.dialog_store.read();
    if let Some(ref filter) = app.active_filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .count()
    } else {
        store.len()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    // ── Construction helpers (mirroring tests/tui_state_test.rs) ──────

    fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn raw_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
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

    fn make_invite(call_id: &str, from: &str, to: &str, ts: DateTime<Utc>) -> SipMessage {
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

    fn make_ok(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
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

    #[test]
    fn is_browsable_capture_matrix() {
        // Plain captures, any case.
        assert!(is_browsable_capture("a.pcap"));
        assert!(is_browsable_capture("a.pcapng"));
        assert!(is_browsable_capture("a.cap"));
        assert!(is_browsable_capture("A.PCAP"));
        assert!(is_browsable_capture("UPPER.PcApNg"));
        // Dotted/UUID stems keep working (extension is the final component).
        assert!(is_browsable_capture("9bbc-71.62.x.pcap"));
        // Gzip-compressed captures — loadable, so listable.
        assert!(is_browsable_capture("a.pcap.gz"));
        assert!(is_browsable_capture("a.cap.GZ"));
        assert!(is_browsable_capture("a.pcapng.gz"));
        // Non-captures and traps.
        assert!(!is_browsable_capture("notes.txt"));
        assert!(!is_browsable_capture("archive.gz")); // bare .gz isn't a capture
        assert!(!is_browsable_capture("notes.txt.gz"));
        assert!(!is_browsable_capture("pcap")); // no extension
        assert!(!is_browsable_capture(""));
        assert!(!is_browsable_capture(".pcap")); // dotfile, extension-less stem
    }

    #[test]
    fn refresh_file_entries_repro() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("9bbc7162-978d-4456-b81c-496ccb2b1200.pcap"), b"x").unwrap();
        std::fs::write(p.join("plain.pcap"), b"x").unwrap();
        std::fs::write(p.join("ng.pcapng"), b"x").unwrap();
        std::fs::write(p.join("legacy.cap"), b"x").unwrap();
        std::fs::write(p.join("gz.pcap.gz"), b"x").unwrap();
        std::fs::write(p.join("upper.PCAP"), b"x").unwrap();
        std::fs::write(p.join("notes.txt"), b"x").unwrap();
        std::fs::create_dir(p.join("subdir")).unwrap();

        let mut app = App::new_test();
        app.set_open_dir_for_test(p.to_path_buf());
        refresh_file_entries(&mut app);

        let names: Vec<&str> = app.open_entries.iter().map(|e| e.name.as_str()).collect();
        // Diagnostic: surface exactly what the browser would show.
        assert!(names.contains(&"plain.pcap"), "listed: {names:?}");
        assert!(names.contains(&"ng.pcapng"), "listed: {names:?}");
        assert!(names.contains(&"legacy.cap"), "listed: {names:?}");
        assert!(names.contains(&"upper.PCAP"), "listed: {names:?}");
        assert!(names.contains(&"subdir"), "listed: {names:?}");
        assert!(!names.contains(&"notes.txt"), "listed: {names:?}");
        // Gzipped captures are loadable but currently filtered out by the browser.
        assert!(names.contains(&"gz.pcap.gz"), "listed: {names:?}");
        // A readable directory produces no error.
        assert!(app.open_error.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn refresh_file_entries_reports_unreadable_dir() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses directory permissions, so this scenario (the sudo /
        // privilege-drop case) only reproduces for an unprivileged user.
        if crate::privilege::is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("a.pcap"), b"x").unwrap();
        // Strip all permissions so read_dir fails with PermissionDenied.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let mut app = App::new_test();
        app.set_open_dir_for_test(locked.clone());
        refresh_file_entries(&mut app);
        let err = app.open_error.clone();

        // Restore perms so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));

        let err = err.expect("unreadable dir should set open_error");
        assert!(err.contains("Cannot read"), "got: {err}");
        assert!(
            err.contains("without sudo"),
            "missing privilege-drop hint: {err}"
        );
    }

    #[test]
    fn refresh_file_entries_clears_stale_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.pcap"), b"x").unwrap();
        let mut app = App::new_test();
        app.open_error = Some("stale".to_string());
        app.set_open_dir_for_test(dir.path().to_path_buf());
        refresh_file_entries(&mut app);
        assert!(
            app.open_error.is_none(),
            "readable dir must clear the error"
        );
        assert!(app.open_entries.iter().any(|e| e.name == "a.pcap"));
    }

    fn app_with_dialogs() -> App {
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

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn key_mod(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }

    fn open_call_flow(app: &mut App) {
        handle_call_list_key(app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

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

    // ── handle_key_event: dispatch & global ──────────────────────────

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
    fn call_list_shift_n_opens_name_dialog_for_source() {
        let mut app = app_with_dialogs();
        handle_call_list_key(&mut app, key(KeyCode::Char('N')));
        assert_eq!(app.active_popup, Some(Popup::NameAddress));
        // Pre-filled with the selected dialog's source IP.
        assert_eq!(app.name_dialog.ip, "10.0.0.1");
    }

    #[test]
    fn name_dialog_sets_mapping_and_enables_resolution() {
        let mut app = app_with_dialogs();
        open_name_dialog(&mut app, addr_a());
        for c in "sbc-edge".chars() {
            handle_name_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_name_popup_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.active_popup, None);
        // Naming an address turns resolution on so the change is visible.
        assert_eq!(app.name_mode(), crate::names::NameMode::Names);
        assert_eq!(
            app.resolver()
                .label_ip(addr_a(), crate::names::NameMode::Names),
            "sbc-edge"
        );
    }

    #[test]
    fn name_dialog_empty_clears_mapping() {
        let mut app = app_with_dialogs();
        app.resolver().set_manual(addr_a(), "old".into());
        open_name_dialog(&mut app, addr_a());
        for _ in 0.."old".len() {
            handle_name_popup_key(&mut app, key(KeyCode::Backspace));
        }
        handle_name_popup_key(&mut app, key(KeyCode::Enter));
        assert_eq!(
            app.resolver()
                .label_ip(addr_a(), crate::names::NameMode::Names),
            "10.0.0.1"
        );
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

    // ── handle_call_list_key ─────────────────────────────────────────

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

    // ── handle_stream_list_key ───────────────────────────────────────

    #[test]
    fn stream_list_tab_back_to_call_list() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn stream_list_esc_to_call_list() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn stream_list_quit_help_search_filter_save() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Char('/')));
        assert!(app.search_active);

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::F(7)));
        assert_eq!(app.active_popup, Some(Popup::FilterDialog));

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
    }

    #[test]
    fn stream_list_nav_noop_when_empty() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Down));
        handle_stream_list_key(&mut app, key(KeyCode::Up));
        handle_stream_list_key(&mut app, key(KeyCode::Home));
        handle_stream_list_key(&mut app, key(KeyCode::End));
        // Enter with no streams: stays in stream list
        handle_stream_list_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.current_view, View::StreamList);
    }

    // ── handle_stream_detail_key ─────────────────────────────────────

    fn app_in_stream_detail() -> App {
        let mut app = App::new_test();
        let k = crate::rtp::stream::StreamKey {
            ssrc: 1,
            src: std::net::SocketAddr::new(addr_a(), 20000),
            dst: std::net::SocketAddr::new(addr_b(), 30000),
        };
        app.stream_detail_return_view = Some(View::StreamList);
        app.current_view = View::StreamDetail(k);
        app
    }

    #[test]
    fn stream_detail_scroll() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.stream_detail_scroll, 1);
        handle_stream_detail_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(app.stream_detail_scroll, 2);
        handle_stream_detail_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.stream_detail_scroll, 1);
        handle_stream_detail_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.stream_detail_scroll, 21);
        handle_stream_detail_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.stream_detail_scroll, 1);
        handle_stream_detail_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.stream_detail_scroll, 0);
    }

    #[test]
    fn stream_detail_up_saturates() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.stream_detail_scroll, 0);
    }

    #[test]
    fn stream_detail_esc_returns() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn stream_detail_esc_default_stream_list() {
        let mut app = app_in_stream_detail();
        app.stream_detail_return_view = None;
        handle_stream_detail_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn stream_detail_quit_help_save() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
    }

    // ── handle_call_flow_key ─────────────────────────────────────────

    #[test]
    fn call_flow_down_up() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        assert_eq!(app.selected_msg_index, 0);
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.selected_msg_index, 1);
        handle_call_flow_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.selected_msg_index, 0);
    }

    #[test]
    fn call_flow_home_end() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::End));
        assert_eq!(app.selected_msg_index, 1); // 2 msgs
        handle_call_flow_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.selected_msg_index, 0);
    }

    #[test]
    fn call_flow_page_up_down() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.selected_msg_index, 1);
        handle_call_flow_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.selected_msg_index, 0);
    }

    #[test]
    fn call_flow_tab_toggles_pane_focus() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        assert!(app.raw_preview, "split is on by default");
        assert!(!app.call_flow_detail_focused, "ladder focused initially");
        handle_call_flow_key(&mut app, key(KeyCode::Tab));
        assert!(app.call_flow_detail_focused, "Tab focuses detail pane");
        handle_call_flow_key(&mut app, key(KeyCode::Tab));
        assert!(!app.call_flow_detail_focused, "Tab toggles back to ladder");
    }

    #[test]
    fn call_flow_tab_noop_without_split() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        app.raw_preview = false;
        handle_call_flow_key(&mut app, key(KeyCode::Tab));
        assert!(!app.call_flow_detail_focused, "no detail pane to focus");
    }

    #[test]
    fn call_flow_detail_focus_scrolls_detail_not_selection() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Tab)); // focus detail
        let sel = app.selected_msg_index;
        assert_eq!(app.detail_scroll, 0);
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.detail_scroll, 1, "Down scrolls the detail pane");
        assert_eq!(
            app.selected_msg_index, sel,
            "selection unchanged while detail focused"
        );
        handle_call_flow_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.detail_scroll, 0, "Up scrolls the detail pane back");
    }

    #[test]
    fn call_flow_ladder_focus_moves_selection() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        // Default focus is the ladder: Down advances the selected message.
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.selected_msg_index, 1);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn call_flow_toggle_split_off_clears_focus() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Tab)); // focus detail
        assert!(app.call_flow_detail_focused);
        handle_call_flow_key(&mut app, key(KeyCode::Char('R'))); // hide split
        assert!(!app.raw_preview);
        assert!(
            !app.call_flow_detail_focused,
            "focus reset when split is hidden"
        );
    }

    #[test]
    fn call_flow_enter_opens_raw() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
    }

    #[test]
    fn call_flow_space_diff_select() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        assert_eq!(app.diff_selected_msg, Some(0));
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        assert!(matches!(app.current_view, View::MessageDiff { .. }));
    }

    #[test]
    fn call_flow_r_jumps_to_stream_list() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('r')));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn call_flow_display_toggles() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        let sdp = app.sdp_display_mode;
        handle_call_flow_key(&mut app, key(KeyCode::Char('d')));
        assert_ne!(app.sdp_display_mode, sdp);

        let cm = app.color_mode;
        handle_call_flow_key(&mut app, key(KeyCode::Char('c')));
        assert_ne!(app.color_mode, cm);

        let rp = app.raw_preview;
        handle_call_flow_key(&mut app, key(KeyCode::Char('R')));
        assert_ne!(app.raw_preview, rp);
    }

    #[test]
    fn call_flow_panel_resize() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        app.raw_preview = true;
        let pct = app.raw_preview_pct;
        handle_call_flow_key(&mut app, key(KeyCode::Char('+')));
        assert_eq!(app.raw_preview_pct, pct + 5);
        handle_call_flow_key(&mut app, key(KeyCode::Char('-')));
        assert_eq!(app.raw_preview_pct, pct);
    }

    #[test]
    fn call_flow_detail_scroll_brackets() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(']')));
        assert_eq!(app.detail_scroll, 1);
        handle_call_flow_key(&mut app, key(KeyCode::Char('[')));
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn call_flow_extended_and_rtp_toggle() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('x')));
        assert!(app.extended_flow);
        let rtp = app.show_rtp_in_flow;
        handle_call_flow_key(&mut app, key(KeyCode::F(6)));
        assert_ne!(app.show_rtp_in_flow, rtp);
    }

    #[test]
    fn call_flow_mark_set_clear() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('m')));
        assert_eq!(app.mark_index, Some(0));
        handle_call_flow_key(&mut app, key(KeyCode::Char('M')));
        assert_eq!(app.mark_index, None);
    }

    #[test]
    fn call_flow_fold_expand_toggle() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('e')));
        assert!(app.fold_expanded.contains(&0));
        handle_call_flow_key(&mut app, key(KeyCode::Char('e')));
        assert!(!app.fold_expanded.contains(&0));
    }

    #[test]
    fn call_flow_esc_clears_diff_and_returns() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        handle_call_flow_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.diff_selected_msg, None);
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn call_flow_quit_help_save() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
    }

    #[test]
    fn call_flow_f5_resets_compare_and_f9_clears_filter() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        assert!(app.diff_selected_msg.is_some());
        handle_call_flow_key(&mut app, key(KeyCode::F(5)));
        assert_eq!(app.diff_selected_msg, None);

        app.active_filter_text = "x".to_string();
        handle_call_flow_key(&mut app, key(KeyCode::F(9)));
        assert!(app.active_filter.is_none());
    }

    #[test]
    fn call_flow_unhandled_noop() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('Q')));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    // ── handle_raw_message_key ───────────────────────────────────────

    fn app_in_raw_message() -> App {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
        app
    }

    #[test]
    fn raw_message_scroll() {
        let mut app = app_in_raw_message();
        handle_raw_message_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.raw_msg_scroll, 1);
        handle_raw_message_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(app.raw_msg_scroll, 2);
        handle_raw_message_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.raw_msg_scroll, 1);
        handle_raw_message_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.raw_msg_scroll, 21);
        handle_raw_message_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.raw_msg_scroll, 1);
        handle_raw_message_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.raw_msg_scroll, 0);
    }

    #[test]
    fn raw_message_esc_returns_to_flow() {
        let mut app = app_in_raw_message();
        handle_raw_message_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    #[test]
    fn raw_message_toggles_and_search() {
        let mut app = app_in_raw_message();
        let sh = app.syntax_highlight;
        handle_raw_message_key(&mut app, key(KeyCode::Char('s')));
        assert_ne!(app.syntax_highlight, sh);

        let cm = app.color_mode;
        handle_raw_message_key(&mut app, key(KeyCode::Char('c')));
        assert_ne!(app.color_mode, cm);

        handle_raw_message_key(&mut app, key(KeyCode::Char('/')));
        assert!(app.search_active);
    }

    #[test]
    fn raw_message_quit_help_save() {
        let mut app = app_in_raw_message();
        handle_raw_message_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        let mut app = app_in_raw_message();
        handle_raw_message_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = app_in_raw_message();
        handle_raw_message_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
    }

    #[test]
    fn raw_message_unhandled_noop() {
        let mut app = app_in_raw_message();
        handle_raw_message_key(&mut app, key(KeyCode::Char('Z')));
        assert!(matches!(app.current_view, View::RawMessage { .. }));
    }

    // ── handle_message_diff_key ──────────────────────────────────────

    fn app_in_message_diff() -> App {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        assert!(matches!(app.current_view, View::MessageDiff { .. }));
        app
    }

    #[test]
    fn message_diff_q_quits() {
        let mut app = app_in_message_diff();
        handle_message_diff_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn message_diff_esc_returns_to_flow() {
        let mut app = app_in_message_diff();
        handle_message_diff_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    #[test]
    fn message_diff_f1_help() {
        let mut app = app_in_message_diff();
        handle_message_diff_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);
    }

    #[test]
    fn message_diff_unhandled_noop() {
        let mut app = app_in_message_diff();
        handle_message_diff_key(&mut app, key(KeyCode::Char('z')));
        assert!(matches!(app.current_view, View::MessageDiff { .. }));
    }

    // ── handle_help_key / handle_statistics_key ──────────────────────

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

    #[test]
    fn is_rtcp_offline_checks() {
        // even port -> false
        assert!(!is_rtcp_offline(&[0x80, 200, 0, 0, 0, 0, 0, 0], 5000));
        // odd port, version 2, pt 200 -> true
        assert!(is_rtcp_offline(&[0x80, 200, 0, 0, 0, 0, 0, 0], 5001));
        // too short -> false
        assert!(!is_rtcp_offline(&[0x80, 200], 5001));
        // wrong version -> false
        assert!(!is_rtcp_offline(&[0x00, 200, 0, 0, 0, 0, 0, 0], 5001));
        // pt out of range -> false
        assert!(!is_rtcp_offline(&[0x80, 100, 0, 0, 0, 0, 0, 0], 5001));
    }

    #[test]
    fn expand_tilde_expands_home() {
        // SAFETY: test-only env mutation
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        assert_eq!(expand_tilde("~/foo"), "/home/testuser/foo");
        assert_eq!(expand_tilde("/abs/path"), "/abs/path");
    }

    #[test]
    fn load_pcap_file_missing_returns_error() {
        let mut app = App::new_test();
        let msg = load_pcap_file(&mut app, "/nonexistent/path/file.pcap");
        assert!(msg.contains("File not found"), "got: {msg}");
    }

    #[test]
    fn load_pcap_file_reads_embedded_nrb_names() {
        use crate::capture::{PcapExportMode, PcapWriter};
        use std::net::IpAddr;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("named.pcapng");
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        {
            let mut w =
                PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw).unwrap();
            w.write_name_resolution_block(&[(ip, vec!["sbc-edge".to_string()])])
                .unwrap();
            w.finish().unwrap();
        }
        let mut app = App::new_test();
        load_pcap_file(&mut app, path.to_str().unwrap());
        // The embedded NRB name is now resolvable (libpcap ignores the block;
        // our metadata pass loads it).
        assert_eq!(
            app.resolver()
                .name(ip, crate::names::NameMode::Names)
                .as_deref(),
            Some("sbc-edge")
        );
    }

    #[test]
    fn load_pcap_file_alerts_on_embedded_secrets() {
        use crate::capture::{PcapExportMode, PcapWriter};
        let dir = tempfile::tempdir().unwrap();
        let keylog = dir.path().join("keys.txt");
        std::fs::write(&keylog, b"CLIENT_RANDOM aabbccdd 00112233\n").unwrap();
        // Filename deliberately free of "secret" so the assertion can't pass
        // trivially on the path.
        let path = dir.path().join("withkeys.pcapng");
        {
            let mut w = PcapWriter::with_format(
                &path,
                1,
                None,
                None,
                true,
                PcapExportMode::EncryptedWithDsb,
            )
            .unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();
            w.finish().unwrap();
        }
        let mut app = App::new_test();
        let msg = load_pcap_file(&mut app, path.to_str().unwrap());
        assert!(
            msg.to_lowercase().contains("decryption secret"),
            "status should warn about embedded secrets: {msg}"
        );
    }
}
