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

/// Handle keys in the call flow view.
pub(in crate::tui) fn handle_call_flow_key(app: &mut App, key: KeyEvent) {
    // Use the rendered (folded) message count. For extended flow, this includes
    // correlated legs. Fall back to raw dialog count if render hasn't run yet.
    let raw_count = if let View::CallFlow(ref call_id) = app.current_view {
        if app.flow.extended {
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
    let msg_count = if app.flow.cached_msg_count > 0 {
        app.flow.cached_msg_count
    } else {
        raw_count
    };

    // Clamp selected_msg_index to valid range
    if msg_count > 0 && app.flow.selected >= msg_count {
        app.flow.selected = msg_count - 1;
    }

    // In the split view, Tab moves focus between the ladder (left) and detail
    // (right) panes; the directional keys below then act on the focused pane.
    let detail_focused = app.flow.raw_preview && app.flow.detail_focused;

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Tab | KeyCode::BackTab => {
            // Only meaningful when the detail pane is visible.
            if app.flow.raw_preview {
                app.flow.detail_focused = !app.flow.detail_focused;
            }
        }
        KeyCode::Up | KeyCode::Char('k') if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            // Selection only; the render pass follows and clamps the scroll
            // using the real viewport geometry.
            if app.flow.selected > 0 {
                app.flow.selected -= 1;
                app.flow.detail_scroll = 0;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if msg_count > 0 && app.flow.selected < msg_count - 1 {
                app.flow.selected += 1;
                app.flow.detail_scroll = 0;
            }
        }
        KeyCode::PageUp if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_sub(20);
        }
        KeyCode::PageDown if detail_focused => {
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_add(20);
        }
        KeyCode::Home if detail_focused => {
            app.flow.detail_scroll = 0;
        }
        KeyCode::PageUp => {
            app.flow.selected = app.flow.selected.saturating_sub(20);
            app.flow.detail_scroll = 0;
        }
        KeyCode::PageDown => {
            let max = if msg_count > 0 { msg_count - 1 } else { 0 };
            app.flow.selected = (app.flow.selected + 20).min(max);
            app.flow.detail_scroll = 0;
        }
        KeyCode::Home => {
            app.flow.selected = 0;
            app.flow.scroll = 0;
            app.flow.detail_scroll = 0;
        }
        KeyCode::End => {
            if msg_count > 0 {
                app.flow.selected = msg_count - 1;
            }
            app.flow.detail_scroll = 0;
        }
        KeyCode::Enter => {
            if let View::CallFlow(ref call_id) = app.current_view
                && app.flow.selected < msg_count
            {
                // Check if this message is an RTP bar entry — if so, drill
                // down to stream detail. Otherwise show raw SIP message.
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
                    // Open full-screen raw message view for the selected message
                    let cid = call_id.clone();
                    let message_index = flow_selected_original_index(app, &cid);
                    app.raw_msg_scroll = 0;
                    app.raw_msg_return_view = Some(app.current_view.clone());
                    app.current_view = View::RawMessage {
                        call_id: cid,
                        message_index,
                    };
                }
            }
        }
        KeyCode::Char(' ') => {
            // Select message for diff comparison
            if let View::CallFlow(ref call_id) = app.current_view
                && app.flow.selected < msg_count
            {
                let cur = flow_selected_original_index(app, call_id);
                if let Some(first) = app.flow.diff_selected {
                    if first != cur {
                        // Second selection — open diff view
                        let cid = call_id.clone();
                        app.flow.diff_selected = None;
                        app.diff_scroll = 0;
                        app.current_view = View::MessageDiff {
                            call_id: cid,
                            msg1_idx: first,
                            msg2_idx: cur,
                        };
                    }
                } else {
                    // First selection
                    app.flow.diff_selected = Some(cur);
                    app.status_error = Some(format!(
                        "Selected: message {} (press Space on another to diff)",
                        cur + 1
                    ));
                }
            }
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Ctrl+R — alias for F6: toggle RTP display in flow. F-keys aren't
            // sendable by every headless front-end (e.g. the VHS hero recorder),
            // so this keeps the toggle reachable. (Bare `r` keeps its meaning.)
            app.flow.show_rtp = !app.flow.show_rtp;
            app.status_error = Some(if app.flow.show_rtp {
                "RTP in flow: ON".to_string()
            } else {
                "RTP in flow: OFF".to_string()
            });
        }
        KeyCode::Char('r') => {
            // Jump to RTP Streams view
            app.current_view = View::StreamList;
        }
        // N — Name any participant. Offers every endpoint in the flow; the
        // selected message's source is focused first. Tab switches columns.
        KeyCode::Char('N') => {
            if let View::CallFlow(ref call_id) = app.current_view {
                let sel = flow_selected_original_index(app, call_id);
                let gathered = app.dialog_store.try_read().and_then(|s| {
                    s.get(call_id).map(|d| {
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
        // a — combined detail of the selected message's transaction;
        // A — combined detail of the whole dialog. Both stack every message's
        // full text into one scrollable view.
        KeyCode::Char('a') | KeyCode::Char('A') => {
            if let View::CallFlow(ref call_id) = app.current_view {
                let sel = flow_selected_original_index(app, call_id);
                let whole = key.code == KeyCode::Char('A');
                let indices = app.dialog_store.try_read().and_then(|s| {
                    s.get(call_id).map(|d| {
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
                    let cid = call_id.clone();
                    app.raw_msg_scroll = 0;
                    app.current_view = View::CombinedDetail {
                        call_id: cid,
                        indices,
                        scope: if whole { "Dialog" } else { "Transaction" },
                    };
                }
            }
        }
        // f — toggle the ladder filter between "this transaction only" and the
        // whole dialog, keeping the same message selected across the switch.
        KeyCode::Char('f') => {
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
        KeyCode::Char('d') => {
            // Toggle SDP display mode
            app.sdp_display_mode = app.sdp_display_mode.next();
            app.status_error = Some(app.sdp_display_mode.label().to_string());
        }
        KeyCode::Char('t') => {
            // Toggle timestamp display
            app.timestamp_mode = app.timestamp_mode.next();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        KeyCode::Char('c') => {
            // Cycle color mode
            app.color_mode = app.color_mode.next();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        KeyCode::Char('R') => {
            // Toggle raw preview split
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
        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('0') | KeyCode::Left => {
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
        KeyCode::Char('-') | KeyCode::Char('9') | KeyCode::Right => {
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
        KeyCode::Char('[') => {
            // Scroll detail panel up
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_sub(1);
        }
        KeyCode::Char(']') => {
            // Scroll detail panel down
            app.flow.detail_scroll = app.flow.detail_scroll.saturating_add(1);
        }
        k if k == app.keymap.extended_flow || k == KeyCode::Char('x') => {
            // Toggle extended (multi-leg) flow
            app.flow.extended = !app.flow.extended;
            app.status_error = Some(if app.flow.extended {
                "Extended flow: ON (multi-leg)".to_string()
            } else {
                "Extended flow: OFF".to_string()
            });
        }
        KeyCode::F(6) => {
            // Toggle RTP display in flow
            app.flow.show_rtp = !app.flow.show_rtp;
            app.status_error = Some(if app.flow.show_rtp {
                "RTP in flow: ON".to_string()
            } else {
                "RTP in flow: OFF".to_string()
            });
        }
        KeyCode::Char('m') => {
            app.flow.mark_index = Some(app.flow.selected);
            app.status_error = Some("Mark set".to_string());
        }
        KeyCode::Char('M') => {
            app.flow.mark_index = None;
            app.status_error = Some("Mark cleared".to_string());
        }
        KeyCode::Char('e') => {
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
            app.flow.diff_selected = None;
            app.current_view = View::CallList;
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        k if k == app.keymap.clear_calls => {
            // F5 also starts compare mode (same as first Space press)
            app.flow.diff_selected = None;
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
pub(in crate::tui) fn handle_raw_message_key(app: &mut App, key: KeyEvent) {
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
            // Keep the existing query so it can be refined.
            app.search_active = true;
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
                // Return to wherever the raw view was opened from.
                let fallback = View::CallFlow(call_id.clone());
                app.current_view = app.raw_msg_return_view.take().unwrap_or(fallback);
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
pub(in crate::tui) fn handle_message_diff_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        k if k == app.keymap.help => app.current_view = View::Help,
        KeyCode::Up | KeyCode::Char('k') => {
            app.diff_scroll = app.diff_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.diff_scroll = app.diff_scroll.saturating_add(1);
        }
        KeyCode::PageUp => app.diff_scroll = app.diff_scroll.saturating_sub(20),
        KeyCode::PageDown => app.diff_scroll = app.diff_scroll.saturating_add(20),
        KeyCode::Home => app.diff_scroll = 0,
        // Clamped to the content height by the render pass.
        KeyCode::End => app.diff_scroll = u16::MAX,
        KeyCode::Esc => {
            if let View::MessageDiff { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        _ => {}
    }
}

/// Handle keys in the combined transaction/dialog detail view.
pub(in crate::tui) fn handle_combined_detail_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        k if k == app.keymap.help => app.current_view = View::Help,
        KeyCode::Esc => {
            if let View::CombinedDetail { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(1);
        }
        KeyCode::PageDown => app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(20),
        KeyCode::PageUp => app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(20),
        KeyCode::Home => app.raw_msg_scroll = 0,
        KeyCode::End => app.raw_msg_scroll = u16::MAX, // clamped to content in render
        _ => {}
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
        assert_eq!(app.flow.diff_selected, Some(0));
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
}
