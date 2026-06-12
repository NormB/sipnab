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
            let dialogs: Vec<_> = if let Some(ref filter) = app.active_filter {
                store
                    .iter()
                    .filter(|d| filter.matches_dialog(d, &[]))
                    .collect()
            } else {
                store.iter().collect()
            };
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

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
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

    if let Ok(read_dir) = std::fs::read_dir(&app.open_dir) {
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

            if !is_dir {
                let ext_ok = std::path::Path::new(&name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| PCAP_EXTENSIONS.iter().any(|p| p.eq_ignore_ascii_case(e)))
                    .unwrap_or(false);
                if !ext_ok {
                    continue;
                }
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

    let mut cap = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => return format!("Failed to open: {e}"),
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
    format!(
        "Loaded {sip_count} SIP, {rtp_count} RTP{rtcp_suffix} from {packet_count} packets across {stream_count} stream(s) ({filename})"
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
