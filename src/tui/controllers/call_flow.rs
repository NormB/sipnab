//! Key handling for the call flow ladder and its message-level views
//! (raw message, message diff, combined detail).

use crate::tui::*;

/// Map the call-flow selection (a *displayed* row position) back to the index
/// into the dialog's full message list. Two projections apply in order:
/// folds hide rows (visible row -> raw index, via the render-time cache),
/// and the transaction filter renders a subset of the dialog (filtered
/// index -> original index).
fn flow_selected_original_index(app: &App, call_id: &str) -> usize {
    let sel = app.flow.selected;
    // Visible row -> index into the (possibly filtered) message slice the
    // ladder rendered. Falls back to the row position before the first render.
    let raw = app
        .flow
        .cached_raw_indices
        .get(sel)
        .copied()
        .flatten()
        .unwrap_or(sel);
    let Some(key) = app.flow.transaction_filter.as_ref() else {
        return raw;
    };
    let Some(store) = app.dialog_store.try_read() else {
        return raw;
    };
    let Some(d) = store.get(call_id) else {
        return raw;
    };
    d.messages
        .iter()
        .enumerate()
        .filter(|(_, m)| crate::tui::call_flow::transaction_key(m).as_ref() == Some(key))
        .map(|(i, _)| i)
        .nth(raw)
        .unwrap_or(raw)
}

/// Resolve the selected visible row to `(dialog Call-ID, message index
/// within that dialog)`. Merged/extended ladders interleave several
/// dialogs and carry per-row provenance in the ladder's index map; a
/// single-dialog ladder (empty map) keeps the classic anchor-dialog path.
fn flow_selected_message(app: &App, anchor_call_id: &str) -> (String, usize) {
    if !app.flow.ladder.index_map.is_empty() {
        let sel = app.flow.selected;
        let raw = app
            .flow
            .cached_raw_indices
            .get(sel)
            .copied()
            .flatten()
            .unwrap_or(sel);
        if let Some((cid, idx)) = app.flow.ladder.index_map.get(raw) {
            return (cid.clone(), *idx);
        }
    }
    (
        anchor_call_id.to_string(),
        flow_selected_original_index(app, anchor_call_id),
    )
}

/// Everything the call flow view can do in response to a single key
/// press. Navigation variants are focus-independent — the executor routes
/// them to the detail pane or the ladder selection based on
/// `flow.detail_focused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallFlowAction {
    Quit,
    ToggleDetailFocus,
    NavUp,
    NavDown,
    NavPageUp,
    NavPageDown,
    NavHome,
    NavEnd,
    Activate,
    DiffSelect,
    ToggleRtpInFlow,
    JumpToStreams,
    NameParticipants,
    CombinedDetailTransaction,
    CombinedDetailDialog,
    ToggleTransactionFilter,
    CycleSdpMode,
    CycleTimestampMode,
    CycleColorMode,
    CycleHeaderForm,
    ToggleSplit,
    GrowDetail,
    ShrinkDetail,
    DetailScrollUp,
    DetailScrollDown,
    ToggleExtended,
    SetMark,
    ClearMark,
    ToggleFold,
    ExportMermaid,
    Close,
    Help,
    OpenSaveDialog,
    ResetCompare,
    OpenFilterDialog,
    ClearFilter,
}

/// Pure key→action mapping for the call flow view (keymap-aware); arm
/// order mirrors the old handler so rebind precedence is unchanged.
pub fn call_flow_action(km: &Keymap, key: KeyEvent) -> Option<CallFlowAction> {
    use CallFlowAction::*;
    Some(match key.code {
        k if k == km.quit => Quit,
        KeyCode::Tab | KeyCode::BackTab => ToggleDetailFocus,
        KeyCode::Up | KeyCode::Char('k') => NavUp,
        KeyCode::Down | KeyCode::Char('j') => NavDown,
        KeyCode::PageUp => NavPageUp,
        KeyCode::PageDown => NavPageDown,
        KeyCode::Home => NavHome,
        KeyCode::End => NavEnd,
        KeyCode::Enter => Activate,
        KeyCode::Char(' ') => DiffSelect,
        // Ctrl+R — alias for F6. F-keys aren't sendable by every headless
        // front-end (e.g. the VHS hero recorder), so this keeps the toggle
        // reachable. (Bare `r` keeps its meaning.)
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => ToggleRtpInFlow,
        KeyCode::Char('r') => JumpToStreams,
        KeyCode::Char('N') => NameParticipants,
        KeyCode::Char('a') => CombinedDetailTransaction,
        KeyCode::Char('A') => CombinedDetailDialog,
        KeyCode::Char('f') => ToggleTransactionFilter,
        KeyCode::Char('d') => CycleSdpMode,
        KeyCode::Char('t') => CycleTimestampMode,
        KeyCode::Char('c') => CycleColorMode,
        KeyCode::Char('h') => CycleHeaderForm,
        KeyCode::Char('R') => ToggleSplit,
        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('0') | KeyCode::Left => GrowDetail,
        KeyCode::Char('-') | KeyCode::Char('9') | KeyCode::Right => ShrinkDetail,
        KeyCode::Char('[') => DetailScrollUp,
        KeyCode::Char(']') => DetailScrollDown,
        k if k == km.extended_flow || k == KeyCode::Char('x') => ToggleExtended,
        KeyCode::F(6) => ToggleRtpInFlow,
        KeyCode::Char('m') => SetMark,
        KeyCode::Char('M') => ClearMark,
        KeyCode::Char('e') => ToggleFold,
        KeyCode::Char('E') => ExportMermaid,
        KeyCode::Esc => Close,
        k if k == km.help => Help,
        k if k == km.save => OpenSaveDialog,
        // F5 also starts compare mode (same as first Space press).
        k if k == km.clear_calls => ResetCompare,
        k if k == km.filter => OpenFilterDialog,
        KeyCode::F(9) => ClearFilter,
        _ => return None,
    })
}

/// Handle keys in the call flow view: map, then execute.
pub(in crate::tui) fn handle_call_flow_key(app: &mut App, key: KeyEvent) {
    if let Some(action) = call_flow_action(&app.keymap, key) {
        execute_call_flow_action(app, action);
    }
}

/// Apply one [`CallFlowAction`] to the application state.
fn execute_call_flow_action(app: &mut App, action: CallFlowAction) {
    let msg_count = flow_visible_msg_count(app);

    // Clamp selected message index to valid range
    if msg_count > 0 && app.flow.selected >= msg_count {
        app.flow.selected = msg_count - 1;
    }

    // In the split view, Tab moves focus between the ladder (left) and detail
    // (right) panes; the navigation actions below then act on the focused pane.
    let detail_focused = app.flow.raw_preview && app.flow.detail_focused;

    match action {
        CallFlowAction::Quit => app.should_quit = true,
        CallFlowAction::ToggleDetailFocus => {
            // Only meaningful when the detail pane is visible.
            if app.flow.raw_preview {
                app.flow.detail_focused = !app.flow.detail_focused;
            }
        }
        CallFlowAction::NavUp if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_sub(1);
        }
        CallFlowAction::NavDown if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_add(1);
        }
        CallFlowAction::NavUp => {
            // Selection only; the render pass follows and clamps the scroll
            // using the real viewport geometry.
            if app.flow.selected > 0 {
                app.flow.selected -= 1;
                app.flow.detail_scroll = 0;
            }
        }
        CallFlowAction::NavDown => {
            if msg_count > 0 && app.flow.selected < msg_count - 1 {
                app.flow.selected += 1;
                app.flow.detail_scroll = 0;
            }
        }
        CallFlowAction::NavPageUp if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_sub(20);
        }
        CallFlowAction::NavPageDown if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_add(20);
        }
        CallFlowAction::NavHome if detail_focused => {
            app.flow.detail_scroll = 0;
        }
        CallFlowAction::NavPageUp => {
            app.flow.selected = app.flow.selected.saturating_sub(20);
            app.flow.detail_scroll = 0;
        }
        CallFlowAction::NavPageDown => {
            let max = if msg_count > 0 { msg_count - 1 } else { 0 };
            app.flow.selected = (app.flow.selected + 20).min(max);
            app.flow.detail_scroll = 0;
        }
        CallFlowAction::NavHome => {
            app.flow.selected = 0;
            app.flow.scroll = 0;
            app.flow.detail_scroll = 0;
        }
        CallFlowAction::NavEnd => {
            if msg_count > 0 {
                app.flow.selected = msg_count - 1;
            }
            app.flow.detail_scroll = 0;
        }
        CallFlowAction::Activate => activate_selected(app, msg_count),
        CallFlowAction::DiffSelect => diff_select(app, msg_count),
        CallFlowAction::ToggleRtpInFlow => {
            app.flow.show_rtp = !app.flow.show_rtp;
            app.status_error = Some(if app.flow.show_rtp {
                "RTP in flow: ON".to_string()
            } else {
                "RTP in flow: OFF".to_string()
            });
        }
        CallFlowAction::JumpToStreams => {
            app.current_view = View::StreamList;
        }
        CallFlowAction::NameParticipants => name_participants(app),
        CallFlowAction::CombinedDetailTransaction => open_combined_detail(app, false),
        CallFlowAction::CombinedDetailDialog => open_combined_detail(app, true),
        CallFlowAction::ToggleTransactionFilter => toggle_transaction_filter(app),
        CallFlowAction::CycleSdpMode => {
            app.sdp_display_mode = app.sdp_display_mode.next();
            app.status_error = Some(app.sdp_display_mode.label().to_string());
        }
        CallFlowAction::CycleTimestampMode => {
            app.timestamp_mode = app.timestamp_mode.next();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        CallFlowAction::CycleColorMode => {
            app.color_mode = app.color_mode.next();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        CallFlowAction::CycleHeaderForm => cycle_header_form(app),
        CallFlowAction::ToggleSplit => {
            app.flow.raw_preview = !app.flow.raw_preview;
            if !app.flow.raw_preview {
                // No detail pane to focus once the split is hidden.
                app.flow.detail_focused = false;
            }
            app.status_error = Some(if app.flow.raw_preview {
                "Raw preview: ON".to_string()
            } else {
                "Raw preview: OFF".to_string()
            });
        }
        CallFlowAction::GrowDetail => {
            // Increase detail panel size (Left = push split leftward = detail wider)
            if app.flow.raw_preview {
                if app.flow.raw_preview_pct < 80 {
                    app.flow.raw_preview_pct = (app.flow.raw_preview_pct + 5).min(80);
                    app.status_error = Some(format!("Detail panel: {}%", app.flow.raw_preview_pct));
                }
            } else {
                // Not a silent no-op: say why nothing resized.
                app.status_error = Some("Split view is off — press R to enable it".to_string());
            }
        }
        CallFlowAction::ShrinkDetail => {
            // Decrease detail panel size (Right = push split rightward = ladder wider)
            if app.flow.raw_preview {
                if app.flow.raw_preview_pct > 10 {
                    app.flow.raw_preview_pct = app.flow.raw_preview_pct.saturating_sub(5).max(10);
                    app.status_error = Some(format!("Detail panel: {}%", app.flow.raw_preview_pct));
                }
            } else {
                app.status_error = Some("Split view is off — press R to enable it".to_string());
            }
        }
        CallFlowAction::DetailScrollUp => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_sub(1);
        }
        CallFlowAction::DetailScrollDown => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_add(1);
        }
        CallFlowAction::ToggleExtended => {
            app.flow.extended = !app.flow.extended;
            app.status_error = Some(if app.flow.extended {
                "Extended flow: ON (multi-leg)".to_string()
            } else {
                "Extended flow: OFF".to_string()
            });
        }
        CallFlowAction::SetMark => {
            app.flow.mark_index = Some(app.flow.selected);
            app.status_error = Some("Mark set".to_string());
        }
        CallFlowAction::ClearMark => {
            app.flow.mark_index = None;
            app.status_error = Some("Mark cleared".to_string());
        }
        CallFlowAction::ToggleFold => {
            // Toggle fold expansion. Folds are keyed by the RAW index of the
            // fold-header message (stable across display modes), so map the
            // visible selection first.
            let idx = app
                .flow
                .cached_raw_indices
                .get(app.flow.selected)
                .copied()
                .flatten()
                .unwrap_or(app.flow.selected);
            if app.flow.fold_expanded.contains(&idx) {
                app.flow.fold_expanded.remove(&idx);
            } else {
                app.flow.fold_expanded.insert(idx);
            }
        }
        CallFlowAction::ExportMermaid => export_mermaid_to_clipboard(app),
        CallFlowAction::Close => {
            app.flow.diff_selected = None;
            app.current_view = View::CallList;
        }
        CallFlowAction::Help => app.current_view = View::Help,
        CallFlowAction::OpenSaveDialog => open_save_popup(app),
        CallFlowAction::ResetCompare => {
            app.flow.diff_selected = None;
            app.status_error =
                Some("Compare: press Space on first message, then Space on second".to_string());
        }
        CallFlowAction::OpenFilterDialog => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.filter_dialog.error = None;
            app.active_popup = Some(Popup::FilterDialog);
        }
        CallFlowAction::ClearFilter => {
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_dialog.clear();
            app.status_error = None;
        }
    }
}

/// Count of navigable (visible) ladder rows: the rendered (post-fold)
/// count once a render has produced it, falling back to the raw message
/// count before the first render. Extended flow sums correlated legs; a
/// transaction filter restricts to the anchored transaction's messages.
fn flow_visible_msg_count(app: &App) -> usize {
    let raw_count = if let View::CallFlow(ref call_id) = app.current_view {
        if !app.flow.merged_calls.is_empty() {
            // Merged multi-selection: sum every checked dialog's messages.
            app.dialog_store
                .try_read()
                .map(|s| {
                    app.flow
                        .merged_calls
                        .iter()
                        .filter_map(|c| s.get(c))
                        .map(|d| d.messages.len())
                        .sum()
                })
                .unwrap_or(0)
        } else if app.flow.extended {
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
                .and_then(|s| {
                    s.get(call_id)
                        .map(|d| match app.flow.transaction_filter.as_ref() {
                            // Filtered: only the active transaction's messages are
                            // reachable, so navigation must clamp to that subset.
                            Some(key) => d
                                .messages
                                .iter()
                                .filter(|m| {
                                    crate::tui::call_flow::transaction_key(m).as_ref() == Some(key)
                                })
                                .count(),
                            None => d.messages.len(),
                        })
                })
                .unwrap_or(0)
        }
    } else {
        0
    };
    // Navigation moves over VISIBLE rows: use the rendered (post-fold) count
    // once a render has produced it; fall back to the raw message count only
    // before the first render. Taking max() with the raw count would let the
    // selection walk past the last visible row whenever folds hide messages.
    if app.flow.cached_msg_count > 0 {
        app.flow.cached_msg_count
    } else {
        raw_count
    }
}

/// Enter on the selected row: drill into stream detail for an RTP bar,
/// otherwise open the full-screen raw view of the selected message.
fn activate_selected(app: &mut App, msg_count: usize) {
    if let View::CallFlow(ref call_id) = app.current_view
        && app.flow.selected < msg_count
    {
        let is_rtp = app.flow.cached_rtp_bar_indices.contains(&app.flow.selected);
        if is_rtp {
            let cid = call_id.clone();
            // Find a stream linked to this dialog, or any stream
            let stream_key = {
                let store = app.stream_store.read();
                store
                    .streams_for(&cid)
                    .next()
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
            // Open full-screen raw message view for the selected message —
            // in a merged/extended flow, of the row's OWN dialog.
            let (cid, message_index) = flow_selected_message(app, call_id);
            app.raw_msg_scroll = 0;
            app.raw_msg_return_view = Some(app.current_view.clone());
            app.current_view = View::RawMessage {
                call_id: cid,
                message_index,
            };
        }
    }
}

/// Space: select a message for diff comparison; the second selection
/// opens the diff view.
fn diff_select(app: &mut App, msg_count: usize) {
    if let View::CallFlow(ref call_id) = app.current_view
        && app.flow.selected < msg_count
    {
        let (cur_cid, cur) = flow_selected_message(app, call_id);
        if let Some((first_cid, first)) = app.flow.diff_selected.clone() {
            if (first_cid.as_str(), first) != (cur_cid.as_str(), cur) {
                // Second selection — open diff view. The diff view renders
                // two messages of ONE dialog; in a merged flow both rows
                // must therefore come from the same dialog.
                if first_cid != cur_cid {
                    app.flow.diff_selected = None;
                    app.status_error = Some("Diff across dialogs is not supported".to_string());
                    return;
                }
                app.flow.diff_selected = None;
                app.diff_scroll = 0;
                app.current_view = View::MessageDiff {
                    call_id: cur_cid,
                    msg1_idx: first,
                    msg2_idx: cur,
                };
            }
        } else {
            // First selection
            app.flow.diff_selected = Some((cur_cid, cur));
            app.status_error = Some(format!(
                "Selected: message {} (press Space on another to diff)",
                cur + 1
            ));
        }
    }
}

/// N — Name any participant. Offers every endpoint in the flow; the
/// selected message's source is focused first. Tab switches columns.
fn name_participants(app: &mut App) {
    if let View::CallFlow(ref call_id) = app.current_view {
        let (row_cid, sel) = flow_selected_message(app, call_id);
        let gathered = app.dialog_store.try_read().and_then(|s| {
            s.get(&row_cid).map(|d| {
                let sel_ip = d
                    .messages
                    .get(sel)
                    .map(|m| m.src_addr)
                    .unwrap_or(d.src_addr);
                let mut ips: Vec<std::net::IpAddr> = Vec::new();
                for m in &d.messages {
                    for ip in [m.src_addr, m.dst_addr] {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                if ips.is_empty() {
                    ips.push(d.src_addr);
                }
                let active = ips.iter().position(|i| *i == sel_ip).unwrap_or(0);
                (ips, active)
            })
        });
        if let Some((ips, active)) = gathered {
            open_name_dialog_for(app, ips, active);
        }
    }
}

/// a/A — combined detail of the selected message's transaction (`whole`
/// false) or the whole dialog (`whole` true). Both stack every message's
/// full text into one scrollable view.
fn open_combined_detail(app: &mut App, whole: bool) {
    if let View::CallFlow(ref call_id) = app.current_view {
        // Scope to the selected row's OWN dialog (merged flows interleave).
        let (cid, sel) = flow_selected_message(app, call_id);
        let indices = app.dialog_store.try_read().and_then(|s| {
            s.get(&cid).map(|d| {
                if whole {
                    (0..d.messages.len()).collect::<Vec<_>>()
                } else {
                    crate::tui::call_flow::transaction_indices(&d.messages, sel)
                }
            })
        });
        if let Some(indices) = indices
            && !indices.is_empty()
        {
            app.raw_msg_scroll = 0;
            app.current_view = View::CombinedDetail {
                call_id: cid,
                indices,
                scope: if whole { "Dialog" } else { "Transaction" },
            };
        }
    }
}

/// f — toggle the ladder filter between "this transaction only" and the
/// whole dialog, keeping the same message selected across the switch.
fn toggle_transaction_filter(app: &mut App) {
    if let View::CallFlow(ref call_id) = app.current_view {
        if app.flow.transaction_filter.is_some() {
            let orig = flow_selected_original_index(app, call_id);
            app.flow.transaction_filter = None;
            app.flow.selected = orig;
            app.flow.scroll = 0;
            app.status_error = Some("Filter off: whole dialog".to_string());
        } else {
            let orig = app.flow.selected;
            let info = app.dialog_store.try_read().and_then(|s| {
                s.get(call_id).and_then(|d| {
                    let key = d
                        .messages
                        .get(orig)
                        .and_then(crate::tui::call_flow::transaction_key)?;
                    let pos = d
                        .messages
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| {
                            crate::tui::call_flow::transaction_key(m).as_ref() == Some(&key)
                        })
                        .position(|(i, _)| i == orig)
                        .unwrap_or(0);
                    Some((key, pos))
                })
            });
            if let Some((key, pos)) = info {
                app.status_error = Some(format!("Filter: transaction {} {}", key.0, key.1));
                app.flow.transaction_filter = Some(key);
                app.flow.selected = pos;
                app.flow.scroll = 0;
            }
        }
    }
}

/// E — export the flow as a Mermaid sequence diagram to the clipboard.
fn export_mermaid_to_clipboard(app: &mut App) {
    if let View::CallFlow(ref call_id) = app.current_view
        && let Some(store) = app.dialog_store.try_read()
    {
        let prepared = store.get(call_id).and_then(|d| {
            if d.messages.is_empty() {
                return None;
            }
            let ft = d.messages[0].timestamp;
            let pdd = d.timing.pdd_ms();
            let rtp_segs = app.rtp_codec_segments(call_id);
            let flow_opts = call_flow::FlowDisplayOptions {
                sdp_mode: app.sdp_display_mode,
                ts_mode: app.timestamp_mode,
                color_mode: app.color_mode,
                show_rtp: app.flow.show_rtp,
                selected_msg: None,
                theme: &app.theme,
                resolver: app.resolver.as_ref(),
                name_mode: app.name_mode,
                rtp_segments: &rtp_segs,
            };
            let (participants, msgs) = call_flow::prepare_messages(
                &d.messages,
                ft,
                pdd,
                &flow_opts,
                &app.flow.fold_expanded,
            );
            Some((participants, msgs))
        });
        if let Some((ref participants, ref msgs)) = prepared {
            let mermaid = call_flow::export::export_mermaid(participants, msgs);
            // Copy on a detached worker: a wedged clipboard helper used to
            // hang the whole TUI on child.wait(). The worker's result lands
            // in the status line via the async_messages drain.
            spawn_clipboard_copy(mermaid, Arc::clone(&app.async_messages));
            app.status_error = Some("Copying Mermaid diagram to clipboard…".to_string());
        } else {
            app.status_error = Some("No messages to export".to_string());
        }
    }
}

/// Copy `text` to the system clipboard on a detached worker thread, pushing
/// the outcome message into `messages` (drained into the status line by the
/// event-loop tick). Never blocks the caller.
pub(in crate::tui) fn spawn_clipboard_copy(
    text: String,
    messages: Arc<parking_lot::Mutex<Vec<String>>>,
) {
    let worker_messages = Arc::clone(&messages);
    let spawned = std::thread::Builder::new()
        .name("clipboard".to_string())
        .spawn(move || {
            let msg = clipboard_copy_bounded(&text);
            worker_messages.lock().push(msg);
        });
    if let Err(e) = spawned {
        messages.lock().push(format!("Clipboard: {e}"));
    }
}

/// Run the platform clipboard helper (pbcopy/xclip) with a bounded wait so
/// a wedged helper is killed instead of leaking. Worker-thread only.
fn clipboard_copy_bounded(text: &str) -> String {
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
    let mut child = match std::process::Command::new(cmd)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return format!("Clipboard: {e}"),
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        if let Err(e) = stdin.write_all(text.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return format!("Clipboard: {e}");
        }
        // Dropping stdin closes the pipe so the helper sees EOF and exits.
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                return "Mermaid diagram copied to clipboard".to_string();
            }
            Ok(Some(status)) => return format!("Clipboard helper exited with {status}"),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return format!("Clipboard: {cmd} did not finish within 5s (killed)");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return format!("Clipboard: {e}"),
        }
    }
}

/// Scroll the raw message view to the next/previous search-match line,
/// wrapping at the ends. Uses the same display text the renderer builds so
/// the jump target and the highlight always agree.
fn jump_raw_search_match(app: &mut App, forward: bool) {
    if app.search_query.is_empty() {
        app.status_error = Some("No search active — press / to search".to_string());
        return;
    }
    let View::RawMessage {
        ref call_id,
        message_index,
    } = app.current_view
    else {
        return;
    };
    let matches = {
        let Some(store) = app.dialog_store.try_read() else {
            return;
        };
        let Some(msg) = store
            .get(call_id)
            .and_then(|d| d.messages.get(message_index))
        else {
            return;
        };
        let (info, raw_text) = crate::tui::msg_raw::raw_display_text(msg, app.header_form);
        crate::tui::msg_raw::search_match_lines(&info, &raw_text, &app.search_query)
    };
    if matches.is_empty() {
        app.status_error = Some(format!("No matches for '{}'", app.search_query));
        return;
    }
    let cur = app.raw_msg_scroll;
    let pos = if forward {
        matches.iter().position(|&m| m > cur).unwrap_or(0) // wrap to the first match
    } else {
        matches
            .iter()
            .rposition(|&m| m < cur)
            .unwrap_or(matches.len() - 1) // wrap to the last match
    };
    app.raw_msg_scroll = matches[pos];
    app.status_error = Some(format!(
        "Match {}/{} for '{}'",
        pos + 1,
        matches.len(),
        app.search_query
    ));
}

/// Everything the raw message view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMessageAction {
    Quit,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ScrollTop,
    ScrollBottom,
    Search,
    /// Jump to the next search-match line (vim/less `n`).
    NextMatch,
    /// Jump to the previous search-match line (vim/less `N`).
    PrevMatch,
    ToggleSyntaxHighlight,
    CycleColorMode,
    CycleHeaderForm,
    Back,
    Help,
    OpenSaveDialog,
}

/// Pure key→action mapping for the raw message view (keymap-aware).
pub fn raw_message_action(km: &Keymap, key: KeyEvent) -> Option<RawMessageAction> {
    use RawMessageAction::*;
    Some(match key.code {
        k if k == km.quit => Quit,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        k if k == km.search => Search,
        // vim/less match navigation. 'n' only reaches this mapper while a
        // search query is active (see the global fallback in
        // handle_key_event); 'N' is view-local.
        KeyCode::Char('n') => NextMatch,
        KeyCode::Char('N') => PrevMatch,
        KeyCode::Char('s') => ToggleSyntaxHighlight,
        KeyCode::Char('c') => CycleColorMode,
        KeyCode::Char('h') => CycleHeaderForm,
        KeyCode::Esc => Back,
        k if k == km.help => Help,
        k if k == km.save => OpenSaveDialog,
        _ => return None,
    })
}

/// Handle keys in the raw message view: map, then execute.
pub(in crate::tui) fn handle_raw_message_key(app: &mut App, key: KeyEvent) {
    if let Some(action) = raw_message_action(&app.keymap, key) {
        execute_raw_message_action(app, action);
    }
}

/// Apply one [`RawMessageAction`] to the application state.
fn execute_raw_message_action(app: &mut App, action: RawMessageAction) {
    match action {
        RawMessageAction::Quit => app.should_quit = true,
        RawMessageAction::ScrollUp => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(1);
        }
        RawMessageAction::ScrollDown => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(1);
        }
        RawMessageAction::PageUp => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(20);
        }
        RawMessageAction::PageDown => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(20);
        }
        RawMessageAction::ScrollTop => app.raw_msg_scroll = 0,
        // Clamped to the content height by the render pass.
        RawMessageAction::ScrollBottom => app.raw_msg_scroll = u16::MAX,
        RawMessageAction::Search => {
            // Keep the existing query so it can be refined.
            app.search_active = true;
        }
        RawMessageAction::NextMatch => jump_raw_search_match(app, true),
        RawMessageAction::PrevMatch => jump_raw_search_match(app, false),
        RawMessageAction::ToggleSyntaxHighlight => {
            app.syntax_highlight = !app.syntax_highlight;
            app.status_error = Some(if app.syntax_highlight {
                "Syntax highlighting: ON".to_string()
            } else {
                "Syntax highlighting: OFF".to_string()
            });
        }
        RawMessageAction::CycleColorMode => {
            app.color_mode = app.color_mode.next();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        RawMessageAction::CycleHeaderForm => cycle_header_form(app),
        RawMessageAction::Back => {
            if let View::RawMessage { ref call_id, .. } = app.current_view {
                // Return to wherever the raw view was opened from.
                let fallback = View::CallFlow(call_id.clone());
                app.current_view = app.raw_msg_return_view.take().unwrap_or(fallback);
            }
        }
        RawMessageAction::Help => app.current_view = View::Help,
        RawMessageAction::OpenSaveDialog => open_save_popup(app),
    }
}

/// Cycle the header-name display form (as captured → expanded → compact),
/// shared by every view that shows full message text.
fn cycle_header_form(app: &mut App) {
    app.header_form = app.header_form.next();
    app.status_error = Some(app.header_form.label().to_string());
}

/// Everything the message diff view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDiffAction {
    Quit,
    Help,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ScrollTop,
    ScrollBottom,
    CycleHeaderForm,
    Back,
}

/// Pure key→action mapping for the message diff view (keymap-aware).
pub fn message_diff_action(km: &Keymap, key: KeyEvent) -> Option<MessageDiffAction> {
    use MessageDiffAction::*;
    Some(match key.code {
        k if k == km.quit => Quit,
        k if k == km.help => Help,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        KeyCode::Char('h') => CycleHeaderForm,
        KeyCode::Esc => Back,
        _ => return None,
    })
}

/// Handle keys in the message diff view: map, then execute.
pub(in crate::tui) fn handle_message_diff_key(app: &mut App, key: KeyEvent) {
    if let Some(action) = message_diff_action(&app.keymap, key) {
        execute_message_diff_action(app, action);
    }
}

/// Apply one [`MessageDiffAction`] to the application state.
fn execute_message_diff_action(app: &mut App, action: MessageDiffAction) {
    match action {
        MessageDiffAction::Quit => app.should_quit = true,
        MessageDiffAction::Help => app.current_view = View::Help,
        MessageDiffAction::ScrollUp => {
            app.diff_scroll = app.diff_scroll.saturating_sub(1);
        }
        MessageDiffAction::ScrollDown => {
            app.diff_scroll = app.diff_scroll.saturating_add(1);
        }
        MessageDiffAction::PageUp => app.diff_scroll = app.diff_scroll.saturating_sub(20),
        MessageDiffAction::PageDown => app.diff_scroll = app.diff_scroll.saturating_add(20),
        MessageDiffAction::ScrollTop => app.diff_scroll = 0,
        // Clamped to the content height by the render pass.
        MessageDiffAction::ScrollBottom => app.diff_scroll = u16::MAX,
        MessageDiffAction::CycleHeaderForm => cycle_header_form(app),
        MessageDiffAction::Back => {
            // INVARIANT: the diff view is only reachable from the call flow
            // of its own call_id, so returning there is always correct. If
            // another opener is ever added, track a return view like
            // raw_msg_return_view instead of hardcoding CallFlow.
            if let View::MessageDiff { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
    }
}

/// Everything the combined transaction/dialog detail view can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CombinedDetailAction {
    Quit,
    Help,
    Back,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ScrollTop,
    ScrollBottom,
    CycleHeaderForm,
}

/// Pure key→action mapping for the combined detail view (keymap-aware).
pub fn combined_detail_action(km: &Keymap, key: KeyEvent) -> Option<CombinedDetailAction> {
    use CombinedDetailAction::*;
    Some(match key.code {
        k if k == km.quit => Quit,
        k if k == km.help => Help,
        KeyCode::Esc => Back,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::PageDown => PageDown,
        KeyCode::PageUp => PageUp,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        KeyCode::Char('h') => CycleHeaderForm,
        _ => return None,
    })
}

/// Handle keys in the combined transaction/dialog detail view.
pub(in crate::tui) fn handle_combined_detail_key(app: &mut App, key: KeyEvent) {
    if let Some(action) = combined_detail_action(&app.keymap, key) {
        execute_combined_detail_action(app, action);
    }
}

/// Apply one [`CombinedDetailAction`] to the application state.
fn execute_combined_detail_action(app: &mut App, action: CombinedDetailAction) {
    match action {
        CombinedDetailAction::Quit => app.should_quit = true,
        CombinedDetailAction::Help => app.current_view = View::Help,
        CombinedDetailAction::Back => {
            // INVARIANT: combined detail is only reachable from the call
            // flow of its own call_id (see MessageDiffAction::Back).
            if let View::CombinedDetail { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        CombinedDetailAction::ScrollDown => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(1);
        }
        CombinedDetailAction::ScrollUp => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(1);
        }
        CombinedDetailAction::PageDown => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(20)
        }
        CombinedDetailAction::PageUp => app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(20),
        CombinedDetailAction::ScrollTop => app.raw_msg_scroll = 0,
        // Clamped to the content height by the render pass.
        CombinedDetailAction::ScrollBottom => app.raw_msg_scroll = u16::MAX,
        CombinedDetailAction::CycleHeaderForm => cycle_header_form(app),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use crate::tui::controllers::test_support::*;
    use chrono::{DateTime, TimeDelta, Utc};

    /// The mapping is pure over (Keymap, KeyEvent): a rebound quit key
    /// maps, the old one unbinds, and Ctrl+R maps differently from bare r.
    #[test]
    fn call_flow_action_honors_remap_and_modifiers() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            call_flow_action(&km, key(KeyCode::Char('x'))),
            Some(CallFlowAction::Quit)
        );
        assert_eq!(call_flow_action(&km, key(KeyCode::Char('q'))), None);
        assert_eq!(
            call_flow_action(&km, key_mod(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            Some(CallFlowAction::ToggleRtpInFlow)
        );
        assert_eq!(
            call_flow_action(&km, key(KeyCode::Char('r'))),
            Some(CallFlowAction::JumpToStreams)
        );
        // Navigation maps focus-independently; the executor routes by pane.
        assert_eq!(
            call_flow_action(&km, key(KeyCode::Up)),
            Some(CallFlowAction::NavUp)
        );
    }

    #[test]
    fn raw_message_action_honors_remapped_quit() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            raw_message_action(&km, key(KeyCode::Char('x'))),
            Some(RawMessageAction::Quit)
        );
        assert_eq!(raw_message_action(&km, key(KeyCode::Char('q'))), None);
    }

    #[test]
    fn message_diff_and_combined_detail_actions_map() {
        let km = Keymap::default();
        assert_eq!(
            message_diff_action(&km, key(KeyCode::Esc)),
            Some(MessageDiffAction::Back)
        );
        assert_eq!(message_diff_action(&km, key(KeyCode::Char('z'))), None);
        assert_eq!(
            combined_detail_action(&km, key(KeyCode::PageDown)),
            Some(CombinedDetailAction::PageDown)
        );
    }

    #[test]
    fn call_flow_down_up() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        assert_eq!(app.flow.selected, 0);
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.flow.selected, 1);
        handle_call_flow_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.flow.selected, 0);
    }

    #[test]
    fn call_flow_home_end() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::End));
        assert_eq!(app.flow.selected, 1); // 2 msgs
        handle_call_flow_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.flow.selected, 0);
    }

    #[test]
    fn call_flow_page_up_down() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.flow.selected, 1);
        handle_call_flow_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.flow.selected, 0);
    }

    #[test]
    fn call_flow_tab_toggles_pane_focus() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        assert!(app.flow.raw_preview, "split is on by default");
        assert!(!app.flow.detail_focused, "ladder focused initially");
        handle_call_flow_key(&mut app, key(KeyCode::Tab));
        assert!(app.flow.detail_focused, "Tab focuses detail pane");
        handle_call_flow_key(&mut app, key(KeyCode::Tab));
        assert!(!app.flow.detail_focused, "Tab toggles back to ladder");
    }

    #[test]
    fn call_flow_tab_noop_without_split() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        app.flow.raw_preview = false;
        handle_call_flow_key(&mut app, key(KeyCode::Tab));
        assert!(!app.flow.detail_focused, "no detail pane to focus");
    }

    #[test]
    fn call_flow_detail_focus_scrolls_detail_not_selection() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Tab)); // focus detail
        let sel = app.flow.selected;
        assert_eq!(app.flow.detail_scroll, 0);
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.flow.detail_scroll, 1, "Down scrolls the detail pane");
        assert_eq!(
            app.flow.selected, sel,
            "selection unchanged while detail focused"
        );
        handle_call_flow_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.flow.detail_scroll, 0, "Up scrolls the detail pane back");
    }

    #[test]
    fn call_flow_ladder_focus_moves_selection() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        // Default focus is the ladder: Down advances the selected message.
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.flow.selected, 1);
        assert_eq!(app.flow.detail_scroll, 0);
    }

    #[test]
    fn call_flow_toggle_split_off_clears_focus() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Tab)); // focus detail
        assert!(app.flow.detail_focused);
        handle_call_flow_key(&mut app, key(KeyCode::Char('R'))); // hide split
        assert!(!app.flow.raw_preview);
        assert!(!app.flow.detail_focused, "focus reset when split is hidden");
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
        assert_eq!(
            app.flow.diff_selected.as_ref().map(|&(_, idx)| idx),
            Some(0)
        );
        handle_call_flow_key(&mut app, key(KeyCode::Down));
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        assert!(matches!(app.current_view, View::MessageDiff { .. }));
    }

    // R5a: `f` filters the ladder to the selected message's transaction and
    // re-projects the selection; raw/diff/name still resolve original indices.
    #[test]
    fn call_flow_f_filters_to_transaction_and_maps_back() {
        let t0 = base_ts();
        let mk = |start: &str, cseq: &str, ts: DateTime<Utc>| -> SipMessage {
            let raw = raw_sip(
                start,
                &[
                    "From: \"a\" <sip:a@x>;tag=t1",
                    "To: \"b\" <sip:b@x>",
                    "Call-ID: call-f@test",
                    cseq,
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
            .expect("parse")
        };
        let mut app = App::with_processed_messages(vec![
            mk("INVITE sip:b@x SIP/2.0", "CSeq: 1 INVITE", t0),
            mk(
                "SIP/2.0 200 OK",
                "CSeq: 1 INVITE",
                t0 + TimeDelta::seconds(1),
            ),
            mk(
                "BYE sip:b@x SIP/2.0",
                "CSeq: 2 BYE",
                t0 + TimeDelta::seconds(2),
            ),
            mk("SIP/2.0 200 OK", "CSeq: 2 BYE", t0 + TimeDelta::seconds(3)),
        ]);
        app.current_view = View::CallFlow("call-f@test".to_string());
        app.flow.selected = 2; // the BYE (original index 2)

        // Toggle on → filter to the BYE transaction, selection re-projected to 0.
        handle_call_flow_key(&mut app, key(KeyCode::Char('f')));
        assert_eq!(
            app.flow
                .transaction_filter
                .as_ref()
                .map(|(n, m)| (*n, m.as_str())),
            Some((2, "BYE"))
        );
        assert_eq!(app.flow.selected, 0);

        // Enter opens the raw view of the ORIGINAL message (BYE = index 2).
        handle_call_flow_key(&mut app, key(KeyCode::Enter));
        match &app.current_view {
            View::RawMessage { message_index, .. } => assert_eq!(*message_index, 2),
            v => panic!("expected RawMessage at original index 2, got {v:?}"),
        }

        // Back to the (still filtered) ladder, then toggle off → selection
        // restored to the original index in the full dialog.
        app.current_view = View::CallFlow("call-f@test".to_string());
        handle_call_flow_key(&mut app, key(KeyCode::Char('f')));
        assert!(app.flow.transaction_filter.is_none());
        assert_eq!(app.flow.selected, 2);
    }

    // R4: `a` opens the selected message's transaction; `A` the whole dialog.
    #[test]
    fn call_flow_a_opens_transaction_combined_detail() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('a')));
        match &app.current_view {
            View::CombinedDetail { indices, scope, .. } => {
                assert_eq!(*scope, "Transaction");
                assert!(!indices.is_empty());
            }
            v => panic!("expected CombinedDetail, got {v:?}"),
        }
        // Esc returns to the ladder.
        handle_combined_detail_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.current_view, View::CallFlow(_)));
    }

    #[test]
    fn call_flow_shift_a_opens_dialog_combined_detail() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('A')));
        match &app.current_view {
            View::CombinedDetail { indices, scope, .. } => {
                assert_eq!(*scope, "Dialog");
                assert_eq!(indices.len(), 2, "INVITE + 200 OK");
            }
            v => panic!("expected CombinedDetail, got {v:?}"),
        }
    }

    #[test]
    fn combined_detail_scrolls_and_pages() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('A')));
        assert_eq!(app.raw_msg_scroll, 0);
        handle_combined_detail_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.raw_msg_scroll, 1);
        handle_combined_detail_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.raw_msg_scroll, 21);
        handle_combined_detail_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.raw_msg_scroll, 0);
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

        let rp = app.flow.raw_preview;
        handle_call_flow_key(&mut app, key(KeyCode::Char('R')));
        assert_ne!(app.flow.raw_preview, rp);
    }

    #[test]
    fn call_flow_panel_resize() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        app.flow.raw_preview = true;
        let pct = app.flow.raw_preview_pct;
        handle_call_flow_key(&mut app, key(KeyCode::Char('+')));
        assert_eq!(app.flow.raw_preview_pct, pct + 5);
        handle_call_flow_key(&mut app, key(KeyCode::Char('-')));
        assert_eq!(app.flow.raw_preview_pct, pct);
    }

    #[test]
    fn call_flow_detail_scroll_brackets() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(']')));
        assert_eq!(app.flow.detail_scroll, 1);
        handle_call_flow_key(&mut app, key(KeyCode::Char('[')));
        assert_eq!(app.flow.detail_scroll, 0);
    }

    #[test]
    fn call_flow_extended_and_rtp_toggle() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('x')));
        assert!(app.flow.extended);
        let rtp = app.flow.show_rtp;
        handle_call_flow_key(&mut app, key(KeyCode::F(6)));
        assert_ne!(app.flow.show_rtp, rtp);
    }

    #[test]
    fn call_flow_rtp_toggle_ctrl_r_alias() {
        // Ctrl+R is an alias for F6 (toggle RTP-in-flow). F-keys can't be
        // driven by some headless front-ends (e.g. the VHS hero recorder), so a
        // Ctrl-modified alias keeps the toggle reachable. Both keys flip the
        // same flag.
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        assert!(!app.flow.show_rtp, "RTP-in-flow defaults off");
        handle_call_flow_key(&mut app, key_mod(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(app.flow.show_rtp, "Ctrl+R turns RTP-in-flow on");
        handle_call_flow_key(&mut app, key_mod(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(!app.flow.show_rtp, "Ctrl+R toggles RTP-in-flow back off");
        // And it stays consistent with the F6 path.
        handle_call_flow_key(&mut app, key(KeyCode::F(6)));
        assert!(app.flow.show_rtp, "F6 still toggles the same flag");
    }

    #[test]
    fn call_flow_plain_r_still_jumps_to_rtp_streams() {
        // The bare `r` (no modifier) must keep its existing meaning: jump to the
        // RTP Streams view — the Ctrl+R alias must not shadow it.
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('r')));
        assert!(matches!(app.current_view, View::StreamList));
        assert!(!app.flow.show_rtp, "plain r does not toggle RTP-in-flow");
    }

    #[test]
    fn call_flow_mark_set_clear() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('m')));
        assert_eq!(app.flow.mark_index, Some(0));
        handle_call_flow_key(&mut app, key(KeyCode::Char('M')));
        assert_eq!(app.flow.mark_index, None);
    }

    #[test]
    fn call_flow_fold_expand_toggle() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char('e')));
        assert!(app.flow.fold_expanded.contains(&0));
        handle_call_flow_key(&mut app, key(KeyCode::Char('e')));
        assert!(!app.flow.fold_expanded.contains(&0));
    }

    #[test]
    fn call_flow_esc_clears_diff_and_returns() {
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, key(KeyCode::Char(' ')));
        handle_call_flow_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.flow.diff_selected, None);
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
        assert!(app.flow.diff_selected.is_some());
        handle_call_flow_key(&mut app, key(KeyCode::F(5)));
        assert_eq!(app.flow.diff_selected, None);

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

    /// The `h` key cycles the header-name display form (as captured →
    /// expanded → compact) in every view that shows full message text.
    #[test]
    fn header_form_key_cycles_in_message_text_views() {
        use crate::tui::header_form::HeaderFormMode;
        let km = Keymap::default();
        let h = key(KeyCode::Char('h'));
        assert_eq!(
            raw_message_action(&km, h),
            Some(RawMessageAction::CycleHeaderForm)
        );
        assert_eq!(
            call_flow_action(&km, h),
            Some(CallFlowAction::CycleHeaderForm)
        );
        assert_eq!(
            combined_detail_action(&km, h),
            Some(CombinedDetailAction::CycleHeaderForm)
        );
        assert_eq!(
            message_diff_action(&km, h),
            Some(MessageDiffAction::CycleHeaderForm)
        );

        let mut app = app_in_raw_message();
        assert_eq!(app.header_form, HeaderFormMode::AsCaptured);
        handle_raw_message_key(&mut app, h);
        assert_eq!(app.header_form, HeaderFormMode::Expanded);
        assert_eq!(app.status_error.as_deref(), Some("Headers: expanded"));
        handle_raw_message_key(&mut app, h);
        assert_eq!(app.header_form, HeaderFormMode::Compact);
        handle_raw_message_key(&mut app, h);
        assert_eq!(app.header_form, HeaderFormMode::AsCaptured);

        // And from the call flow view (detail pane shows message text).
        let mut app = app_with_dialogs();
        open_call_flow(&mut app);
        handle_call_flow_key(&mut app, h);
        assert_eq!(app.header_form, HeaderFormMode::Expanded);
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
        // End jumps to the bottom (the render pass clamps the offset to
        // the content height, like the help view).
        handle_raw_message_key(&mut app, key(KeyCode::End));
        assert_eq!(app.raw_msg_scroll, u16::MAX);
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
}
