//! All TUI rendering: main view dispatch, status lines, f-key bar,
//! and popup rendering.

use super::*;

// ── Rendering ───────────────────────────────────────────────────────

/// Render the entire application frame based on the current view.
///
/// Uses `try_read()` for the shared stores so the TUI never blocks waiting
/// for the processing thread to release a write lock. When the lock is
/// contended, the previous frame's cached counts are shown in the status
/// bar, and the main view simply skips its render (the terminal retains
/// the last-drawn content).
pub(super) fn render_app(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();

    // Layout: 3 status lines at top (sngrep-style), main content, F-key bar at bottom
    let [
        status1_area,
        status2_area,
        status3_area,
        main_area,
        fkey_area,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // Update cached counts when the lock is available (non-blocking)
    if let Some(store) = app.dialog_store.try_read() {
        app.cached_dialog_count = store.len();
        app.cached_displayed_count = {
            let mut count = if let Some(ref filter) = app.active_filter {
                store
                    .iter()
                    .filter(|d| filter.matches_dialog(d, &[]))
                    .count()
            } else {
                store.len()
            };
            // Apply text search filter to the count
            if !app.search_query.is_empty() {
                let q = app.search_query.to_ascii_lowercase();
                count = store
                    .iter()
                    .filter(|d| {
                        if let Some(ref filter) = app.active_filter
                            && !filter.matches_dialog(d, &[])
                        {
                            return false;
                        }
                        d.call_id.to_ascii_lowercase().contains(&q)
                            || d.method.as_str().to_ascii_lowercase().contains(&q)
                            || d.from_user
                                .as_deref()
                                .unwrap_or("")
                                .to_ascii_lowercase()
                                .contains(&q)
                            || d.to_user
                                .as_deref()
                                .unwrap_or("")
                                .to_ascii_lowercase()
                                .contains(&q)
                            || d.src_addr.to_string().contains(&q)
                            || d.dst_addr.to_string().contains(&q)
                            || call_list::state_display_str(d.state())
                                .to_ascii_lowercase()
                                .contains(&q)
                            || d.messages.iter().any(|msg| {
                                String::from_utf8_lossy(&msg.raw)
                                    .to_ascii_lowercase()
                                    .contains(&q)
                            })
                    })
                    .count();
            }
            count
        };
    }

    // Status lines at top (sngrep-style) — use cached counts
    render_status_line1(frame, status1_area, app);
    render_status_line2(frame, status2_area, app);
    render_status_line3(frame, status3_area, app);

    // Render the current view using try_read() to avoid blocking.
    // If the lock is contended, skip the render — the terminal retains
    // the previous frame's content, so the user sees no flicker.
    match &app.current_view.clone() {
        View::CallList => {
            if let Some(store) = app.dialog_store.try_read() {
                call_list::render_call_list(
                    frame,
                    main_area,
                    &mut app.call_list,
                    &store,
                    &call_list::CallListDisplay {
                        filter: app.active_filter.as_ref(),
                        search_query: &app.search_query,
                        timestamp_mode: app.timestamp_mode,
                        theme: &app.theme,
                        resolver: app.resolver.as_ref(),
                        name_mode: app.name_mode,
                    },
                );
            }
        }
        View::StreamList => {
            if let Some(store) = app.stream_store.try_read() {
                stream_list::render_stream_list(
                    frame,
                    main_area,
                    &mut app.stream_list,
                    &store,
                    &app.theme,
                    app.resolver.as_ref(),
                    app.name_mode,
                );
            }
        }
        View::StreamDetail(key) => {
            if let Some(store) = app.stream_store.try_read() {
                stream_detail::render_stream_detail(
                    frame,
                    main_area,
                    key,
                    &store,
                    app.stream_detail_scroll,
                    &app.theme,
                    app.resolver.as_ref(),
                    app.name_mode,
                );
            }
        }
        View::CallFlow(call_id) => {
            if let Some(store) = app.dialog_store.try_read() {
                let cid = call_id.clone();
                let scroll = app.call_flow_scroll;
                let sel = app.selected_msg_index;

                // Horizontal split: ladder on left, raw detail on right (sngrep style)
                let (ladder_area, detail_area) = if app.raw_preview {
                    let pct = app.raw_preview_pct;
                    let [left, right] = Layout::horizontal([
                        Constraint::Percentage(100 - pct),
                        Constraint::Percentage(pct),
                    ])
                    .areas(main_area);
                    (left, Some(right))
                } else {
                    (main_area, None)
                };

                // Gather messages for the direct-paint renderer.
                // For extended flow, merge correlated dialog messages.
                let prepared = if app.extended_flow {
                    // Extended: merge all correlated legs
                    let dialog = store.get(&cid);
                    if let Some(d) = dialog {
                        let mut all: Vec<&crate::sip::SipMessage> = d.messages.iter().collect();
                        let correlated = store.find_correlated(&cid);
                        for leg in &correlated {
                            all.extend(leg.messages.iter());
                        }
                        all.sort_by_key(|m| m.timestamp);
                        let owned: Vec<crate::sip::SipMessage> = all.into_iter().cloned().collect();
                        if owned.is_empty() {
                            None
                        } else {
                            let ft = owned[0].timestamp;
                            let flow_opts = call_flow::FlowDisplayOptions {
                                sdp_mode: app.sdp_display_mode,
                                ts_mode: app.timestamp_mode,
                                color_mode: app.color_mode,
                                show_rtp: false,
                                selected_msg: Some(sel),
                                theme: &app.theme,
                                resolver: app.resolver.as_ref(),
                                name_mode: app.name_mode,
                            };
                            let (participants, msgs) = call_flow::prepare_messages(
                                &owned,
                                ft,
                                None,
                                &flow_opts,
                                &app.fold_expanded,
                            );
                            Some((participants, msgs))
                        }
                    } else {
                        None
                    }
                } else {
                    let dialog = store.get(&cid);
                    if let Some(d) = dialog {
                        if d.messages.is_empty() {
                            None
                        } else {
                            let ft = d.messages[0].timestamp;
                            let pdd = d.timing.pdd_ms();
                            let flow_opts = call_flow::FlowDisplayOptions {
                                sdp_mode: app.sdp_display_mode,
                                ts_mode: app.timestamp_mode,
                                color_mode: app.color_mode,
                                show_rtp: app.show_rtp_in_flow,
                                selected_msg: Some(sel),
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
                        }
                    } else {
                        None
                    }
                };

                // Update cached rendered message count (excluding spacers)
                // and track which indices carry an RTP bar for Enter drill-down
                if let Some((_, ref msgs)) = prepared {
                    app.cached_flow_msg_count = msgs.iter().filter(|m| !m.is_spacer).count();
                    // Build RTP bar indices in terms of non-spacer message index
                    // (matching selected_msg_index which skips spacers)
                    app.cached_rtp_bar_indices = msgs
                        .iter()
                        .filter(|m| !m.is_spacer)
                        .enumerate()
                        .filter(|(_, m)| m.is_rtp_bar)
                        .map(|(i, _)| i)
                        .collect();
                }

                // Render ladder using direct buffer painting
                call_flow::render_call_flow_direct_or_empty(
                    frame,
                    ladder_area,
                    prepared.as_ref(),
                    &call_flow::render::FlowNavigation {
                        scroll_offset: scroll,
                        mark_index: app.mark_index,
                        selected_index: sel,
                    },
                    &app.theme,
                );

                // Ladder scrollbar when the flow is taller than the pane.
                if let Some((_, ref msgs)) = prepared {
                    let total_rows = call_flow::ladder_total_rows(msgs);
                    call_flow::render_ladder_scrollbar(
                        frame,
                        ladder_area,
                        total_rows,
                        scroll,
                        &app.theme,
                    );
                }

                // Render message detail panel (right side) if split is active
                if let Some(detail_area) = detail_area {
                    let total_lines = call_flow::render_message_detail(
                        frame,
                        detail_area,
                        &store,
                        &cid,
                        sel,
                        app.detail_scroll,
                        app.call_flow_detail_focused,
                        &app.theme,
                    );
                    // Keep the stored scroll offset within the message length so
                    // End / repeated Down never strand the view past the content.
                    let viewport = detail_area.height.saturating_sub(2);
                    let max_scroll = (total_lines as u16).saturating_sub(viewport);
                    if app.detail_scroll > max_scroll {
                        app.detail_scroll = max_scroll;
                    }
                }
            }
        }
        View::RawMessage {
            call_id,
            message_index,
        } => {
            if let Some(store) = app.dialog_store.try_read() {
                msg_raw::render_raw_message(
                    frame,
                    main_area,
                    &store,
                    &msg_raw::RawMessageView {
                        call_id,
                        message_index: *message_index,
                        scroll_offset: app.raw_msg_scroll,
                        search_query: &app.search_query,
                        theme: &app.theme,
                    },
                );
            }
        }
        View::MessageDiff {
            call_id,
            msg1_idx,
            msg2_idx,
        } => {
            if let Some(store) = app.dialog_store.try_read() {
                render_message_diff(
                    frame, main_area, &store, call_id, *msg1_idx, *msg2_idx, &app.theme,
                );
            }
        }
        View::Help => {
            help::render_help(frame, main_area, &app.theme);
        }
        View::Statistics => {
            render_statistics(frame, main_area, app);
        }
    }

    // F-key bar (sngrep-style, context-sensitive) at bottom
    render_fkey_bar(
        frame,
        fkey_area,
        &app.current_view,
        &app.active_popup,
        &app.theme,
    );

    // Render popup overlay on top of everything (if active)
    if let Some(popup) = &app.active_popup.clone() {
        match popup {
            Popup::SaveDialog => {
                render_save_popup(frame, area, app);
            }
            Popup::FilterDialog => {
                render_filter_popup(frame, area, &app.filter_dialog, &app.theme);
            }
            Popup::SettingsDialog => {
                render_settings_popup(frame, area, app);
            }
            Popup::FileOpenDialog => {
                render_file_open_popup(frame, area, app);
            }
            Popup::NameAddress => {
                render_name_popup(frame, area, app);
            }
        }
    }

    // Render column selector popup (not a Popup variant — it's call_list internal state)
    if app.call_list.column_selector_open {
        call_list::render_column_selector(frame, area, &app.call_list, &app.theme);
    }
}

/// Render status line 1 (sngrep-style): `Current Mode: Online (any)    Dialogs: N (N displayed)`
pub(super) fn render_status_line1(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let total_count = app.cached_dialog_count;
    let displayed_count = app.cached_displayed_count;

    // Determine if online (live capture) or offline (pcap file)
    let is_online = app.capture_mode.starts_with("Online");
    let mode_style = if is_online {
        Style::default().fg(app.theme.good)
    } else {
        Style::default().fg(app.theme.bad)
    };

    // Build status indicators for paused/autoscroll
    let mut indicators = String::new();
    if app.paused {
        indicators.push_str("  PAUSED");
    }
    if app.call_list.autoscroll {
        indicators.push_str("  [A]");
    }

    let content = format!(
        " Current Mode: {}    Dialogs: {} ({} displayed){}",
        app.capture_mode, total_count, displayed_count, indicators
    );
    let padded = format!("{:<width$}", content, width = area.width as usize);

    // Build spans with styling for the mode portion
    let mode_start = " Current Mode: ".len();
    let mode_end = mode_start + app.capture_mode.len();

    // Find indicator positions for coloring
    let paused_start = if app.paused {
        padded.find("PAUSED")
    } else {
        None
    };

    let mut spans = vec![
        Span::raw(&padded[..mode_start]),
        Span::styled(padded[mode_start..mode_end].to_string(), mode_style),
    ];

    if let Some(ps) = paused_start {
        spans.push(Span::raw(padded[mode_end..ps].to_string()));
        spans.push(Span::styled(
            "PAUSED".to_string(),
            Style::default()
                .fg(app.theme.bad)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(padded[ps + 6..].to_string()));
    } else {
        spans.push(Span::raw(padded[mode_end..].to_string()));
    };

    let line1 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line1, area);
}

/// Render status line 2 (sngrep-style): `Match Expression: <expr>    BPF Filter: <bpf>`
pub(super) fn render_status_line2(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let yellow = Style::default().fg(app.theme.selected);

    // Build styled spans with trailing padding for solid background
    let prefix1 = " Match Expression: ";
    let filter_text = &app.active_filter_text;
    let mid = "    BPF Filter: ";
    let bpf_text = &app.bpf_filter;
    let styled_len = prefix1.len() + filter_text.len() + mid.len() + bpf_text.len();
    let trailing_pad = if styled_len < area.width as usize {
        " ".repeat(area.width as usize - styled_len)
    } else {
        String::new()
    };

    let spans = vec![
        Span::raw(prefix1),
        Span::styled(filter_text.clone(), yellow),
        Span::raw(mid),
        Span::styled(bpf_text.clone(), yellow),
        Span::raw(trailing_pad),
    ];

    let line2 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line2, area);
}

/// Render status line 3 (sngrep-style): `Display Filter: <filter>` or search/error overlay.
pub(super) fn render_status_line3(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let w = area.width as usize;

    let spans = if app.search_active {
        let content = format!(" /{}", app.search_query);
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(app.theme.selected),
        )]
    } else if let Some(ref err) = app.status_error {
        let content = format!(" {}", err);
        // Use bright foreground + bold for high contrast on the dark status bar.
        // Actual errors (containing "error" or "fail") get the bad/red color.
        let is_error =
            err.to_ascii_lowercase().contains("error") || err.to_ascii_lowercase().contains("fail");
        let fg = if is_error {
            app.theme.bad
        } else {
            app.theme.foreground
        };
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(fg).add_modifier(Modifier::BOLD),
        )]
    } else if let View::CallFlow(_) = app.current_view {
        // In call flow: show current display modes so user knows what t/d/c do
        let cyan = Style::default().fg(app.theme.header);
        // Show focused pane (Tab to switch) only when the split is visible.
        let focus = if app.raw_preview {
            if app.call_flow_detail_focused {
                " | Focus: Detail (Tab)"
            } else {
                " | Focus: Ladder (Tab)"
            }
        } else {
            ""
        };
        let content = format!(
            " {} | {} | {} | Split: {}%{}",
            app.timestamp_mode.label(),
            app.sdp_display_mode.label(),
            app.color_mode.label(),
            if app.raw_preview {
                app.raw_preview_pct
            } else {
                0
            },
            focus,
        );
        let trailing = " ".repeat(w.saturating_sub(content.len()));
        vec![Span::styled(content, cyan), Span::raw(trailing)]
    } else {
        let yellow = Style::default().fg(app.theme.selected);
        let prefix = " Display Filter: ";
        let filter_text = &app.active_filter_text;
        let trailing = if prefix.len() + filter_text.len() < w {
            " ".repeat(w - prefix.len() - filter_text.len())
        } else {
            String::new()
        };
        vec![
            Span::raw(prefix),
            Span::styled(filter_text.clone(), yellow),
            Span::raw(trailing),
        ]
    };

    let line3 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line3, area);
}

/// Build the f-key bar item list for the current view/popup at the
/// given terminal width. Items near the end are lower priority and
/// dropped first on narrow terminals. Extracted from the renderer so
/// the visible key hints are unit-testable.
pub(super) fn fkey_bar_items(
    view: &View,
    popup: &Option<Popup>,
    width: u16,
) -> Vec<(&'static str, &'static str)> {
    if let Some(p) = popup {
        match p {
            Popup::SaveDialog => vec![("Enter", "Save"), ("Tab", "Format"), ("Esc", "Cancel")],
            Popup::FilterDialog => {
                vec![
                    ("Tab", "Next"),
                    ("Space", "Toggle"),
                    ("Enter", "Apply"),
                    ("Esc", "Cancel"),
                    ("F9", "Clear"),
                ]
            }
            Popup::SettingsDialog => {
                vec![
                    ("Up/Down", "Navigate"),
                    ("Enter", "Toggle"),
                    ("Esc", "Close"),
                ]
            }
            Popup::FileOpenDialog => vec![
                ("Enter", "Open/Cd"),
                ("\u{21E7}\u{21E9}", "Nav"),
                ("Backspace", "Up"),
                ("Tab", "Type path"),
                ("Esc", "Cancel"),
            ],
            Popup::NameAddress => vec![("Enter", "Save"), ("Esc", "Cancel")],
        }
    } else {
        match view {
            View::CallList => {
                if width < 80 {
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Show"),
                        ("Tab", "Streams"),
                        ("F2", "Save"),
                        ("F7", "Filter"),
                    ]
                } else if width < 100 {
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Show"),
                        ("Tab", "Streams"),
                        ("F2", "Save"),
                        ("F3", "Search"),
                        ("F6", "Raw"),
                        ("F7", "Filter"),
                        ("F9", "Addrs"),
                    ]
                } else {
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Show"),
                        ("Tab", "Streams"),
                        ("O", "Open"),
                        ("F2", "Save"),
                        ("F3", "Search"),
                        ("F4", "Extended"),
                        ("F5", "Clear"),
                        ("F6", "Raw"),
                        ("F7", "Filter"),
                        ("F9", "Addrs"),
                        ("F10", "Columns"),
                    ]
                }
            }
            View::CallFlow(_) => {
                if width < 80 {
                    vec![
                        ("Esc", "Back"),
                        ("\u{2191}\u{2193}", "Nav"),
                        ("Enter", "Raw"),
                    ]
                } else if width < 120 {
                    vec![
                        ("Esc", "Back"),
                        ("\u{2191}\u{2193}", "Nav"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Split"),
                    ]
                } else {
                    vec![
                        ("Esc", "Back"),
                        ("\u{2191}\u{2193}", "Nav"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Split"),
                        ("9/0", "Resize"),
                        ("F4", "Extend"),
                        ("r", "Streams"),
                        ("F6", "RTP"),
                    ]
                }
            }
            View::RawMessage { .. } => {
                if width < 80 {
                    vec![("Esc", "Back"), ("s", "Highlight"), ("F2", "Save")]
                } else {
                    vec![
                        ("Esc", "Back"),
                        ("s", "Highlight"),
                        ("c", "Color"),
                        ("/", "Search"),
                        ("F2", "Save"),
                    ]
                }
            }
            View::MessageDiff { .. } => vec![("Esc", "Back")],
            View::StreamList => vec![
                ("Esc", "Back"),
                ("Enter", "Detail"),
                ("Tab", "Calls"),
                ("F2", "Save WAV"),
                ("F7", "Filter"),
            ],
            View::StreamDetail(_) => {
                #[cfg(feature = "audio")]
                {
                    vec![
                        ("Esc", "Back"),
                        ("j/k", "Scroll"),
                        ("PgUp/Dn", "Page"),
                        ("P", "Play"),
                        ("F2", "Save WAV"),
                    ]
                }
                #[cfg(not(feature = "audio"))]
                {
                    vec![
                        ("Esc", "Back"),
                        ("j/k", "Scroll"),
                        ("PgUp/Dn", "Page"),
                        ("F2", "Save WAV"),
                    ]
                }
            }
            _ => vec![("Esc", "Back")],
        }
    }
}

/// Render the sngrep-style F-key bar at the bottom of the screen.
///
/// Format: `Esc Quit  Enter Show  F2 Save  ...`
/// Key names in bold white, labels in default. Full-width dark background.
/// The bar is context-sensitive based on the current view. On narrow
/// terminals, lower-priority items are dropped to avoid truncation.
pub(super) fn render_fkey_bar(
    frame: &mut ratatui::Frame,
    area: Rect,
    view: &View,
    popup: &Option<Popup>,
    theme: &Theme,
) {
    let key_style = Style::default()
        .fg(theme.foreground)
        .add_modifier(Modifier::BOLD);
    let label_style = Style::default().fg(theme.foreground);

    let width = area.width;

    // Full item sets per view; items near the end are lower priority.
    // Popup-specific bars take precedence.
    let items = fkey_bar_items(view, popup, width);

    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label)) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(format!("{key} "), key_style));
        spans.push(Span::styled((*label).to_string(), label_style));
    }

    // Pad to full width for solid background
    let content_len: usize = spans.iter().map(|s| s.content.len()).sum();
    if content_len < width as usize {
        spans.push(Span::raw(" ".repeat(width as usize - content_len)));
    }

    let bar = Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.status_bg));
    frame.render_widget(bar, area);
}

// ── Popup rendering ────────────────────────────────────────────────

/// Compute a centered popup rectangle within the given area.
pub(super) fn centered_popup(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

/// Render the save dialog as a centered popup overlay.
pub(super) fn render_save_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 72.min(area.width.saturating_sub(4));
    let popup_area = centered_popup(area, popup_width, 20);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Save Capture ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build vertical format list grouped by category.
    let all_formats = [
        SaveFormat::Pcap,
        SaveFormat::PcapNg, // Packet Capture
        SaveFormat::Txt,
        SaveFormat::SippXml, // SIP-Specific
        SaveFormat::Json,
        SaveFormat::Ndjson,
        SaveFormat::Csv, // Structured
        SaveFormat::Html,
        SaveFormat::Markdown, // Reporting
        SaveFormat::Wav,
        SaveFormat::RtpJson, // RTP/Media
    ];
    let mut fmt_lines: Vec<Line<'_>> = Vec::new();
    let mut last_cat = "";
    for fmt in &all_formats {
        let cat = fmt.category();
        if cat != last_cat {
            // Category header
            if !last_cat.is_empty() {
                fmt_lines.push(Line::from("")); // spacer between categories
            }
            fmt_lines.push(Line::from(Span::styled(
                format!("  {cat}"),
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            )));
            last_cat = cat;
        }
        let is_selected = *fmt == app.save_format;
        let marker = if is_selected { "\u{25B8} " } else { "  " }; // ▸ or space
        let label_style = if is_selected {
            Style::default()
                .fg(app.theme.foreground)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.muted)
        };
        let desc_style = if is_selected {
            Style::default().fg(app.theme.foreground)
        } else {
            Style::default().fg(app.theme.muted)
        };
        fmt_lines.push(Line::from(vec![
            Span::styled(format!("    {marker}"), label_style),
            Span::styled(format!("{:<7}", fmt.label()), label_style),
            Span::styled(format!(" {}", fmt.description()), desc_style),
        ]));
    }

    let info_line = format!(
        "  Dialogs: {} ({} selected) \u{00B7} Messages: {}",
        app.save_dialog_count, app.save_selected_count, app.save_message_count
    );

    // Build the path display with a visible cursor (reverse video at cursor position)
    let path = &app.save_path;
    let cursor = app.save_cursor.min(path.len());
    let mut path_spans: Vec<Span<'_>> = vec![Span::styled(
        "  Save to: ",
        Style::default().fg(app.theme.header),
    )];
    if path.is_empty() {
        path_spans.push(Span::styled(
            " ",
            Style::default().bg(Color::White).fg(Color::Black),
        ));
    } else {
        // Text before cursor
        if cursor > 0 {
            path_spans.push(Span::styled(
                path[..cursor].to_string(),
                Style::default()
                    .fg(app.theme.foreground)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        // Cursor character (reverse video)
        if cursor < path.len() {
            path_spans.push(Span::styled(
                path[cursor..cursor + 1].to_string(),
                Style::default().bg(Color::White).fg(Color::Black),
            ));
            // Text after cursor
            if cursor + 1 < path.len() {
                path_spans.push(Span::styled(
                    path[cursor + 1..].to_string(),
                    Style::default()
                        .fg(app.theme.foreground)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        } else {
            // Cursor at end — show block cursor
            path_spans.push(Span::styled(
                " ",
                Style::default().bg(Color::White).fg(Color::Black),
            ));
        }
    }

    let mut lines: Vec<Line<'_>> = vec![Line::from(""), Line::from(path_spans), Line::from("")];
    lines.extend(fmt_lines);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        info_line,
        Style::default().fg(app.theme.muted),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "  [Enter]",
            Style::default()
                .fg(app.theme.good)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Save  "),
        Span::styled(
            "[Tab/\u{21E7}Tab]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Format  "),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(app.theme.warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Cancel"),
    ]));

    // Ensure we don't exceed the inner area height
    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// Render the file-open dialog as a centered popup overlay.
///
/// Two modes: a directory browser (default) that lists subdirectories and
/// pcap/pcapng/cap files, or a manual-path text input (toggled with Tab).
/// Render the "Name Address" popup: an IP (read-only) and an editable name.
pub(super) fn render_name_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 8.min(area.height.saturating_sub(2));
    let popup_area = centered_popup(area, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Name Address ")
        .style(Style::default().bg(app.theme.background));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let mut lines: Vec<Line<'_>> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("  IP:   ", Style::default().fg(app.theme.muted)),
        Span::styled(
            app.name_dialog.ip.clone(),
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    // Name field with a visible cursor block at the edit position.
    let name = &app.name_dialog.name;
    let cursor = app.name_dialog.cursor.min(name.len());
    let (before, after) = name.split_at(cursor);
    let mut field: Vec<Span<'_>> = vec![
        Span::styled("  Name: ", Style::default().fg(app.theme.muted)),
        Span::raw(before.to_string()),
    ];
    let mut rest = after.chars();
    match rest.next() {
        Some(c) => {
            field.push(Span::styled(
                c.to_string(),
                Style::default().bg(app.theme.selected).fg(Color::Black),
            ));
            field.push(Span::raw(rest.as_str().to_string()));
        }
        None => field.push(Span::styled(" ", Style::default().bg(app.theme.selected))),
    }
    lines.push(Line::from(field));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter save · empty name clears · Esc cancel",
        Style::default().fg(app.theme.muted),
    )));

    frame.render_widget(Paragraph::new(lines), inner);
}

pub(super) fn render_file_open_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 80.min(area.width.saturating_sub(4));
    let popup_height = 22.min(area.height.saturating_sub(2));
    let popup_area = centered_popup(area, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Open PCAP File ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    if app.open_manual_mode {
        render_file_open_manual(frame, inner, app);
    } else {
        render_file_open_browser(frame, inner, app);
    }
}

/// Word-wrap `text` to `width` columns (best-effort, on whitespace). Used for
/// the file-browser error message, since the dialog Paragraph does not wrap.
fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if cur.is_empty() {
            cur.push_str(word);
        } else if cur.chars().count() + 1 + word.chars().count() <= width {
            cur.push(' ');
            cur.push_str(word);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Render the directory-browser variant of the Open dialog.
pub(super) fn render_file_open_browser(frame: &mut ratatui::Frame, inner: Rect, app: &App) {
    let header = format!("  Dir: {}", app.open_dir.display());
    let filter_label = if app.open_filter.is_empty() {
        "  (type to filter — Backspace: up dir  Tab: type path)".to_string()
    } else {
        format!("  Filter: {}", app.open_filter)
    };

    let mut lines: Vec<Line<'_>> = Vec::with_capacity(inner.height as usize);
    lines.push(Line::from(Span::styled(
        header,
        Style::default()
            .fg(app.theme.header)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        filter_label,
        Style::default().fg(app.theme.muted),
    )));
    lines.push(Line::from(""));

    // If the directory couldn't be read, show why (e.g. privileges dropped to
    // 'nobody' under sudo) instead of a blank list.
    if let Some(err) = &app.open_error {
        let wrap_width = (inner.width as usize).saturating_sub(4).max(10);
        for chunk in wrap_to_width(err, wrap_width) {
            lines.push(Line::from(Span::styled(
                format!("  {chunk}"),
                Style::default()
                    .fg(app.theme.bad)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(Line::from(""));
    }

    let list_rows = (inner.height as usize).saturating_sub(5);
    if app.open_entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no matching pcap files)",
            Style::default().fg(app.theme.muted),
        )));
    } else {
        let scroll_offset = app
            .open_selected
            .saturating_sub(list_rows.saturating_sub(1));
        for (idx, entry) in app
            .open_entries
            .iter()
            .enumerate()
            .skip(scroll_offset)
            .take(list_rows)
        {
            let selected = idx == app.open_selected;
            let prefix = if entry.is_dir { "  [DIR] " } else { "        " };
            let style = if selected {
                Style::default()
                    .bg(app.theme.selected)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD)
            } else if entry.is_dir {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.foreground)
            };
            let pad_to = (inner.width as usize).saturating_sub(prefix.len());
            let display = format!("{:<width$}", entry.name, width = pad_to);
            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(display, style),
            ]));
        }
    }

    // Pad so the footer sits at the bottom
    while lines.len() + 1 < inner.height as usize {
        lines.push(Line::from(""));
    }

    lines.push(Line::from(vec![
        Span::styled(
            "  [Enter]",
            Style::default()
                .fg(app.theme.good)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Open/Cd  "),
        Span::styled(
            "[\u{21E7}\u{21E9}]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Nav  "),
        Span::styled(
            "[Backspace]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Up  "),
        Span::styled(
            "[Tab]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Path  "),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(app.theme.warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Cancel"),
    ]));

    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// Render the manual path-input variant of the Open dialog.
pub(super) fn render_file_open_manual(frame: &mut ratatui::Frame, inner: Rect, app: &App) {
    let path = &app.open_path;
    let cursor = app.open_cursor.min(path.len());
    let mut path_spans: Vec<Span<'_>> = vec![Span::styled(
        "  Path: ",
        Style::default().fg(app.theme.header),
    )];
    if path.is_empty() {
        path_spans.push(Span::styled(
            " ",
            Style::default().bg(Color::White).fg(Color::Black),
        ));
    } else {
        if cursor > 0 {
            path_spans.push(Span::styled(
                path[..cursor].to_string(),
                Style::default()
                    .fg(app.theme.foreground)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        if cursor < path.len() {
            path_spans.push(Span::styled(
                path[cursor..cursor + 1].to_string(),
                Style::default().bg(Color::White).fg(Color::Black),
            ));
            if cursor + 1 < path.len() {
                path_spans.push(Span::styled(
                    path[cursor + 1..].to_string(),
                    Style::default()
                        .fg(app.theme.foreground)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        } else {
            path_spans.push(Span::styled(
                " ",
                Style::default().bg(Color::White).fg(Color::Black),
            ));
        }
    }

    let lines: Vec<Line<'_>> = vec![
        Line::from(""),
        Line::from(path_spans),
        Line::from(""),
        Line::from(Span::styled(
            "  Supports .pcap, .pcapng, .cap files (~ expands to $HOME)",
            Style::default().fg(app.theme.muted),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Enter]",
                Style::default()
                    .fg(app.theme.good)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Open  "),
            Span::styled(
                "[Tab]",
                Style::default()
                    .fg(app.theme.header)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Browse  "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(app.theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Cancel"),
        ]),
    ];

    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// State for a single filter text input field.
pub(super) struct FilterTextField<'a> {
    label: &'a str,
    value: &'a str,
    field_width: u16,
    focused: bool,
    cursor_pos: usize,
}

/// Render a text input field with cursor for the filter dialog.
///
/// Paints: `label [content_with_cursor_________________]`
/// The field content is rendered with a block cursor at `cursor_pos` when focused.
pub(super) fn render_filter_text_field(
    buf: &mut ratatui::buffer::Buffer,
    x: u16,
    y: u16,
    field: &FilterTextField<'_>,
    theme: &Theme,
) {
    let label = field.label;
    let value = field.value;
    let field_width = field.field_width;
    let focused = field.focused;
    let cursor_pos = field.cursor_pos;
    let label_style = Style::default().fg(theme.header);
    let bracket_style = if focused {
        Style::default().fg(theme.foreground)
    } else {
        Style::default().fg(theme.muted)
    };

    // Paint label
    let label_area = Rect::new(x, y, label.len() as u16, 1);
    buf.set_string(label_area.x, label_area.y, label, label_style);

    // Paint opening bracket
    let field_x = x + label.len() as u16;
    buf.set_string(field_x, y, "[", bracket_style);

    // Paint field content with cursor
    let content_x = field_x + 1;
    let inner_width = (field_width - 2) as usize; // subtract brackets
    let cursor = cursor_pos.min(value.len());

    if focused {
        // Before cursor
        let before = &value[..cursor.min(inner_width)];
        buf.set_string(
            content_x,
            y,
            before,
            Style::default()
                .fg(theme.foreground)
                .add_modifier(Modifier::BOLD),
        );
        // Cursor character (reverse video)
        let cursor_char = if cursor < value.len() {
            &value[cursor..cursor + 1]
        } else {
            " "
        };
        buf.set_string(
            content_x + cursor as u16,
            y,
            cursor_char,
            Style::default().bg(Color::White).fg(Color::Black),
        );
        // After cursor
        if cursor + 1 < value.len() {
            let after_end = value.len().min(inner_width);
            let after = &value[cursor + 1..after_end];
            buf.set_string(
                content_x + cursor as u16 + 1,
                y,
                after,
                Style::default()
                    .fg(theme.foreground)
                    .add_modifier(Modifier::BOLD),
            );
        }
        // Fill remaining with spaces
        let filled = value.len().max(cursor + 1).min(inner_width);
        if filled < inner_width {
            let pad = " ".repeat(inner_width - filled);
            buf.set_string(content_x + filled as u16, y, &pad, Style::default());
        }
    } else {
        // Not focused: just show value dimmed
        let display = if value.len() > inner_width {
            &value[..inner_width]
        } else {
            value
        };
        buf.set_string(content_x, y, display, Style::default().fg(theme.foreground));
        // Fill remaining
        if display.len() < inner_width {
            let pad = " ".repeat(inner_width - display.len());
            buf.set_string(content_x + display.len() as u16, y, &pad, Style::default());
        }
    }

    // Closing bracket
    buf.set_string(field_x + field_width - 1, y, "]", bracket_style);
}

/// Render the filter dialog as a centered popup overlay (sngrep-style).
///
/// Layout:
/// ```text
/// +- Filter -----------------------------------------+
/// |                                                    |
/// |  SIP From:    [                             ]      |
/// |  SIP To:      [                             ]      |
/// |  Source:      [                             ]      |
/// |  Destination: [                             ]      |
/// |  Payload:     [                             ]      |
/// |  ──────────────────────────────────────────────    |
/// |  REGISTER [*]          OPTIONS  [ ]                |
/// |  INVITE   [*]          PUBLISH  [ ]                |
/// |  SUBSCRIBE[ ]          MESSAGE  [ ]                |
/// |  NOTIFY   [ ]          REFER    [ ]                |
/// |  INFO     [ ]          UPDATE   [ ]                |
/// |                                                    |
/// |     [ Filter ]              [ Cancel ]             |
/// |                                                    |
/// +----------------------------------------------------+
/// ```
pub(super) fn render_filter_popup(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &FilterDialogState,
    theme: &Theme,
) {
    let popup_width: u16 = 56;
    let popup_height: u16 = 19;
    let popup_area = centered_popup(area, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter ")
        .style(Style::default().bg(theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let buf = frame.buffer_mut();
    let ix = inner.x;
    let iy = inner.y;
    let iw = inner.width;

    // ── Text input fields ──────────────────────────────────────────
    let labels = [
        "  SIP From:    ",
        "  SIP To:      ",
        "  Source:      ",
        "  Destination: ",
        "  Payload:     ",
    ];
    let field_width = iw.saturating_sub(labels[0].len() as u16 + 2); // +2 for margin

    for (i, label) in labels.iter().enumerate() {
        let focused = state.focused_field == i;
        let cursor = if focused { state.cursor_pos } else { 0 };
        render_filter_text_field(
            buf,
            ix,
            iy + 1 + i as u16,
            &FilterTextField {
                label,
                value: state.text_field(i),
                field_width,
                focused,
                cursor_pos: cursor,
            },
            theme,
        );
    }

    // ── Separator line ─────────────────────────────────────────────
    let sep_y = iy + 1 + labels.len() as u16;
    let sep = "\u{2500}".repeat((iw - 4) as usize);
    buf.set_string(ix + 2, sep_y, &sep, Style::default().fg(theme.muted));

    // ── Method checkboxes (two columns, 5 rows) ───────────────────
    let cb_y = sep_y + 1;
    let col1_x = ix + 2;
    let col2_x = ix + (iw / 2) + 1;

    for row in 0..5u16 {
        let left_idx = (row * 2) as usize;
        let right_idx = left_idx + 1;

        // Left column
        if left_idx < FILTER_METHODS.len() {
            let method = FILTER_METHODS[left_idx];
            let checked = state.methods[left_idx];
            let focused = state.focused_field == FILTER_TEXT_FIELD_COUNT + left_idx;
            let marker = if checked { "[*]" } else { "[ ]" };
            let name = format!("{:<10}", method);
            let style = if focused {
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.foreground)
            };
            buf.set_string(col1_x, cb_y + row, &name, style);
            buf.set_string(col1_x + 10, cb_y + row, marker, style);
        }

        // Right column
        if right_idx < FILTER_METHODS.len() {
            let method = FILTER_METHODS[right_idx];
            let checked = state.methods[right_idx];
            let focused = state.focused_field == FILTER_TEXT_FIELD_COUNT + right_idx;
            let marker = if checked { "[*]" } else { "[ ]" };
            let name = format!("{:<10}", method);
            let style = if focused {
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.foreground)
            };
            buf.set_string(col2_x, cb_y + row, &name, style);
            buf.set_string(col2_x + 10, cb_y + row, marker, style);
        }
    }

    // ── Buttons ────────────────────────────────────────────────────
    let btn_y = cb_y + 6;
    let filter_focused = state.focused_field == FILTER_BUTTON_IDX;
    let cancel_focused = state.focused_field == CANCEL_BUTTON_IDX;

    let filter_style = if filter_focused {
        Style::default().fg(theme.good).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };
    let cancel_style = if cancel_focused {
        Style::default()
            .fg(theme.warning)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };

    let btn_col1 = ix + 5;
    let btn_col2 = ix + iw / 2 + 5;
    buf.set_string(btn_col1, btn_y, "[ Filter ]", filter_style);
    buf.set_string(btn_col2, btn_y, "[ Cancel ]", cancel_style);
}

/// Render the settings popup as a centered overlay.
pub(super) fn render_settings_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width: u16 = 50;
    let popup_height: u16 = 12;
    let popup_area = centered_popup(area, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Settings ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let buf = frame.buffer_mut();
    let ix = inner.x;
    let iy = inner.y;

    let labels = [
        "Color Mode:",
        "Timestamp Mode:",
        "Autoscroll:",
        "Raw Preview:",
        "SDP Display:",
        "Syntax Highlight:",
    ];

    let values = [
        match app.color_mode {
            ColorMode::Method => "Method",
            ColorMode::CallId => "CallId",
            ColorMode::CSeq => "CSeq",
        },
        match app.timestamp_mode {
            TimestampMode::Absolute => "Absolute",
            TimestampMode::DeltaPrev => "DeltaPrev",
            TimestampMode::DeltaFirst => "DeltaFirst",
            TimestampMode::Scaled => "Scaled",
        },
        if app.call_list.autoscroll {
            "ON"
        } else {
            "OFF"
        },
        if app.raw_preview { "ON" } else { "OFF" },
        match app.sdp_display_mode {
            SdpDisplayMode::None => "None",
            SdpDisplayMode::Summary => "Summary",
            SdpDisplayMode::Full => "Full",
        },
        if app.syntax_highlight { "ON" } else { "OFF" },
    ];

    for (i, (label, value)) in labels.iter().zip(values.iter()).enumerate() {
        let focused = app.settings_dialog.focused_item == i;
        let style = if focused {
            Style::default()
                .fg(app.theme.selected)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.foreground)
        };
        let value_style = if focused {
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.good)
        };

        let row_y = iy + 1 + i as u16;
        buf.set_string(ix + 2, row_y, format!("{:<18}", label), style);
        buf.set_string(ix + 20, row_y, format!("[{}]", value), value_style);
    }
}

/// Render the statistics summary view with real data from stores.
pub(super) fn render_statistics(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &App,
) {
    use crate::sip::dialog::DialogState;
    use std::collections::HashMap;

    // Use try_read() to avoid blocking the TUI render loop
    let ds = match app.dialog_store.try_read() {
        Some(guard) => guard,
        None => return,
    };
    let ss = match app.stream_store.try_read() {
        Some(guard) => guard,
        None => return,
    };

    let dialog_count = ds.len();
    let active_count = ds.active_count();
    let stream_count = ss.len();
    let orphaned = ss.orphaned_count();

    // Per-state counts
    let mut state_counts: HashMap<&str, usize> = HashMap::new();
    let mut method_counts: HashMap<&str, usize> = HashMap::new();
    let mut total_messages: usize = 0;

    for dialog in ds.iter() {
        let state_name = match dialog.state() {
            DialogState::Trying => "Trying",
            DialogState::Ringing => "Ringing",
            DialogState::InCall => "InCall",
            DialogState::Completed => "Completed",
            DialogState::Cancelled => "Cancelled",
            DialogState::Failed => "Failed",
            DialogState::Registered => "Registered",
            DialogState::Expired => "Expired",
            DialogState::Pending => "Pending",
            DialogState::Active => "Active",
            DialogState::Terminated => "Terminated",
            DialogState::Transferring => "Transferring",
        };
        *state_counts.entry(state_name).or_insert(0) += 1;
        *method_counts.entry(dialog.method.as_str()).or_insert(0) += 1;
        total_messages += dialog.messages.len();
    }

    // Sort methods by count descending, then alphabetically
    let mut methods: Vec<(&&str, &usize)> = method_counts.iter().collect();
    methods.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut text = format!(
        "sipnab Statistics\n\n\
         Dialogs:           {dialog_count}\n\
         Active Calls:      {active_count}\n\
         Total Messages:    {total_messages}\n\
         RTP Streams:       {stream_count}\n\
         Orphaned Streams:  {orphaned}\n"
    );

    // State breakdown
    if !state_counts.is_empty() {
        text.push_str("\nDialog States:\n");
        let mut states: Vec<(&&str, &usize)> = state_counts.iter().collect();
        states.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (state, count) in states {
            text.push_str(&format!("  {:<16} {count}\n", state));
        }
    }

    // Method distribution
    if !methods.is_empty() {
        text.push_str("\nMethod Distribution:\n");
        for (method, count) in methods {
            text.push_str(&format!("  {:<16} {count}\n", method));
        }
    }

    text.push_str("\nPress Esc to return.");

    let block = Block::default().borders(Borders::ALL).title(" Statistics ");

    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(app.theme.foreground));

    frame.render_widget(paragraph, area);
}

/// Render a side-by-side diff of two SIP messages.
pub(super) fn render_message_diff(
    frame: &mut ratatui::Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    msg1_idx: usize,
    msg2_idx: usize,
    theme: &Theme,
) {
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.").style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return;
        }
    };

    let msg1 = dialog.messages.get(msg1_idx);
    let msg2 = dialog.messages.get(msg2_idx);

    let (Some(msg1), Some(msg2)) = (msg1, msg2) else {
        let para = Paragraph::new("Message not found.").style(Style::default().fg(theme.bad));
        frame.render_widget(para, area);
        return;
    };

    let raw1 = String::from_utf8_lossy(&msg1.raw);
    let raw2 = String::from_utf8_lossy(&msg2.raw);

    let lines1: Vec<&str> = raw1.lines().collect();
    let lines2: Vec<&str> = raw2.lines().collect();
    let max_lines = lines1.len().max(lines2.len());

    // Split area into two halves
    let half_width = area.width / 2;
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Length(half_width), Constraint::Fill(1)]).areas(area);

    let mut left_lines: Vec<Line<'static>> = Vec::new();
    let mut right_lines: Vec<Line<'static>> = Vec::new();

    // Header lines
    left_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg1_idx + 1),
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));
    right_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg2_idx + 1),
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));

    let diff_style = Style::default()
        .fg(theme.warning)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default();

    for i in 0..max_lines {
        let l1 = lines1.get(i).copied().unwrap_or("");
        let l2 = lines2.get(i).copied().unwrap_or("");

        let is_diff = l1 != l2;
        let style = if is_diff { diff_style } else { normal_style };

        left_lines.push(Line::from(Span::styled(l1.to_string(), style)));
        right_lines.push(Line::from(Span::styled(l2.to_string(), style)));
    }

    let left_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Message {} ", msg1_idx + 1));
    let right_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Message {} ", msg2_idx + 1));

    let left_para = Paragraph::new(left_lines)
        .block(left_block)
        .wrap(Wrap { trim: false });
    let right_para = Paragraph::new(right_lines)
        .block(right_block)
        .wrap(Wrap { trim: false });

    frame.render_widget(left_para, left_area);
    frame.render_widget(right_para, right_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::net::{IpAddr, Ipv4Addr};

    // ── Helpers ────────────────────────────────────────────────────

    fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
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
        let raw = build_sip(
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

    fn make_response(call_id: &str, status: u16, reason: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: \"Bob\" <sip:1002@example.com>;tag=t2",
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
        .expect("parse response")
    }

    fn make_bye(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "BYE sip:1002@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: \"Bob\" <sip:1002@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 2 BYE",
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
        .expect("parse BYE")
    }

    /// App with one populated, completed dialog (INVITE/180/200/BYE).
    fn app_with_dialog() -> App {
        let t0 = base_ts();
        App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", t0),
            make_response("call-1@test", 180, "Ringing", t0 + TimeDelta::seconds(1)),
            make_response("call-1@test", 200, "OK", t0 + TimeDelta::seconds(2)),
            make_bye("call-1@test", t0 + TimeDelta::seconds(62)),
        ])
    }

    /// Render `app` at the given size and return the buffer as a string.
    fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|frame| render_app(frame, app)).unwrap();
        let buf = terminal.backend().buffer();
        let area = buf.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            out.push('\n');
        }
        out
    }

    // ── render_app dispatch across views & widths ──────────────────

    #[test]
    fn render_app_call_list_empty_and_populated() {
        let mut empty = App::new_test();
        let out = render_to_string(&mut empty, 80, 24);
        assert!(out.contains("Current Mode"));
        assert!(out.contains("Dialogs:"));

        let mut app = app_with_dialog();
        let out = render_to_string(&mut app, 80, 24);
        // The dialog count should reflect one dialog.
        assert!(out.contains("Dialogs: 1"));
    }

    #[test]
    fn render_app_call_list_narrow_and_wide() {
        let mut app = app_with_dialog();
        let narrow = render_to_string(&mut app, 60, 12);
        assert!(narrow.contains("Esc"));
        let wide = render_to_string(&mut app, 130, 40);
        // Wide call list f-key bar advertises the Open hotkey.
        assert!(wide.contains("Open"));
    }

    #[test]
    fn render_app_stream_list_view() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        let out = render_to_string(&mut app, 100, 24);
        // Stream-list f-key bar advertises Calls (Tab to switch back).
        assert!(out.contains("Calls"));
    }

    #[test]
    fn render_app_call_flow_view_split_and_nosplit() {
        let mut app = app_with_dialog();
        app.current_view = View::CallFlow("call-1@test".to_string());
        // Default raw_preview = true → split layout; renders detail panel.
        let split = render_to_string(&mut app, 120, 30);
        assert!(split.contains("Back"));
        // status line 3 shows the call-flow mode hints
        assert!(split.contains("Time:") || split.contains("SDP:"));

        // No split.
        app.raw_preview = false;
        let nosplit = render_to_string(&mut app, 120, 30);
        assert!(nosplit.contains("Back"));
    }

    #[test]
    fn render_app_call_flow_extended_flow() {
        let mut app = app_with_dialog();
        app.current_view = View::CallFlow("call-1@test".to_string());
        app.extended_flow = true;
        let out = render_to_string(&mut app, 120, 30);
        assert!(out.contains("Back"));
    }

    #[test]
    fn render_app_raw_message_view() {
        let mut app = app_with_dialog();
        app.current_view = View::RawMessage {
            call_id: "call-1@test".to_string(),
            message_index: 0,
        };
        let out = render_to_string(&mut app, 90, 30);
        // Raw message f-key bar advertises Highlight.
        assert!(out.contains("Highlight"));
    }

    #[test]
    fn render_app_message_diff_view() {
        let mut app = app_with_dialog();
        app.current_view = View::MessageDiff {
            call_id: "call-1@test".to_string(),
            msg1_idx: 0,
            msg2_idx: 1,
        };
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Message 1"));
        assert!(out.contains("Message 2"));
    }

    #[test]
    fn render_app_help_and_statistics_views() {
        let mut app = app_with_dialog();
        app.current_view = View::Help;
        let help = render_to_string(&mut app, 80, 30);
        assert!(!help.is_empty());

        app.current_view = View::Statistics;
        let stats = render_to_string(&mut app, 80, 30);
        assert!(stats.contains("Statistics"));
        assert!(stats.contains("Dialogs:"));
    }

    // ── Status line variants ───────────────────────────────────────

    #[test]
    fn render_app_status_line1_paused_and_autoscroll() {
        let mut app = app_with_dialog();
        app.paused = true;
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("PAUSED"));
        // autoscroll indicator [A] (default autoscroll on for call list)
        assert!(out.contains("[A]"));
    }

    #[test]
    fn render_app_status_line1_offline_mode() {
        let mut app = app_with_dialog();
        app.capture_mode = "Offline (capture.pcap)".to_string();
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("Offline"));
    }

    #[test]
    fn render_app_status_line3_search_active() {
        let mut app = app_with_dialog();
        app.search_active = true;
        app.search_query = "invite".to_string();
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("/invite"));
    }

    #[test]
    fn render_app_status_line3_error_message() {
        let mut app = app_with_dialog();
        app.status_error = Some("save failed: disk full".to_string());
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("save failed"));
    }

    #[test]
    fn render_app_status_line3_info_message() {
        let mut app = app_with_dialog();
        // No "error"/"fail" → uses foreground color path.
        app.status_error = Some("saved 3 dialogs".to_string());
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("saved 3 dialogs"));
    }

    #[test]
    fn render_app_status_line2_filter_and_bpf() {
        let mut app = app_with_dialog();
        app.active_filter_text = "method == 'INVITE'".to_string();
        app.bpf_filter = "udp port 5060".to_string();
        let out = render_to_string(&mut app, 120, 24);
        assert!(out.contains("Match Expression"));
        assert!(out.contains("udp port 5060"));
    }

    // ── Popups via render_app overlay ──────────────────────────────

    #[test]
    fn render_app_save_popup_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::SaveDialog);
        app.set_save_path("/tmp/out.pcap");
        let out = render_to_string(&mut app, 90, 30);
        assert!(out.contains("Save Capture"));
        assert!(out.contains("/tmp/out.pcap"));
    }

    #[test]
    fn render_app_file_open_browser_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::FileOpenDialog);
        app.open_manual_mode = false;
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Open PCAP File"));
        assert!(out.contains("Dir:"));
    }

    #[test]
    fn render_app_file_open_manual_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::FileOpenDialog);
        app.open_manual_mode = true;
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Open PCAP File"));
        assert!(out.contains("Path:"));
    }

    #[test]
    fn render_app_settings_popup_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::SettingsDialog);
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Settings"));
        assert!(out.contains("Color Mode"));
    }

    #[test]
    fn render_app_filter_popup_overlay() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::FilterDialog);
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Filter"));
        assert!(out.contains("SIP From"));
    }

    // ── Direct popup function tests ────────────────────────────────

    #[test]
    fn render_save_popup_empty_path_shows_cursor() {
        let mut app = App::new_test();
        app.save_path.clear();
        app.save_cursor = 0;
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_save_popup(frame, area, &app);
            })
            .unwrap();
        // Should not panic with empty path; popup title present.
        let buf = terminal.backend().buffer();
        let mut found = false;
        for y in 0..buf.area.height {
            let mut row = String::new();
            for x in 0..buf.area.width {
                row.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            if row.contains("Save Capture") {
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn render_save_popup_cursor_mid_string() {
        let mut app = App::new_test();
        app.save_path = "abcdef".to_string();
        app.save_cursor = 3; // cursor in the middle
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_save_popup(frame, area, &app);
            })
            .unwrap();
        // Renders without panic; reaches the mid-string cursor branch.
    }

    #[test]
    fn render_file_open_browser_empty_and_populated() {
        // Empty entries → "(no matching pcap files)" path.
        let mut app = App::new_test();
        app.open_entries.clear();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_browser(frame, inner, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("no matching pcap files"));
    }

    #[test]
    fn render_file_open_browser_with_filter() {
        let mut app = App::new_test();
        app.open_filter = "abc".to_string();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_browser(frame, inner, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("Filter: abc"));
    }

    #[test]
    fn render_file_open_manual_empty_and_with_path() {
        // Empty path branch.
        let mut app = App::new_test();
        app.open_path.clear();
        app.open_cursor = 0;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_manual(frame, inner, &app);
            })
            .unwrap();

        // Cursor mid-path branch.
        app.open_path = "/tmp/a.pcap".to_string();
        app.open_cursor = 4;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_manual(frame, inner, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("Path:"));
    }

    // ── render_status_line2/3 direct (non-call-flow branch) ────────

    #[test]
    fn render_status_line3_display_filter_default() {
        let mut app = App::new_test();
        app.active_filter_text = "from.user =~ '1001'".to_string();
        let mut terminal = Terminal::new(TestBackend::new(80, 4)).unwrap();
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 80, 1);
                render_status_line3(frame, area, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut row = String::new();
        for x in 0..buf.area.width {
            row.push_str(buf.cell((x, 0)).unwrap().symbol());
        }
        assert!(row.contains("Display Filter"));
    }

    #[test]
    fn render_status_line3_call_flow_branch() {
        let mut app = app_with_dialog();
        app.current_view = View::CallFlow("call-1@test".to_string());
        app.raw_preview = true;
        let mut terminal = Terminal::new(TestBackend::new(100, 4)).unwrap();
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 100, 1);
                render_status_line3(frame, area, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut row = String::new();
        for x in 0..buf.area.width {
            row.push_str(buf.cell((x, 0)).unwrap().symbol());
        }
        assert!(row.contains("Split:"));
    }

    // ── render_fkey_bar across views ───────────────────────────────

    #[test]
    fn render_fkey_bar_views() {
        let theme = Theme::default();
        for view in [
            View::CallList,
            View::StreamList,
            View::CallFlow("x".to_string()),
            View::RawMessage {
                call_id: "x".to_string(),
                message_index: 0,
            },
            View::MessageDiff {
                call_id: "x".to_string(),
                msg1_idx: 0,
                msg2_idx: 1,
            },
            View::Help,
        ] {
            let mut terminal = Terminal::new(TestBackend::new(120, 3)).unwrap();
            terminal
                .draw(|frame| {
                    let area = Rect::new(0, 0, 120, 1);
                    render_fkey_bar(frame, area, &view, &None, &theme);
                })
                .unwrap();
            let buf = terminal.backend().buffer();
            let mut row = String::new();
            for x in 0..buf.area.width {
                row.push_str(buf.cell((x, 0)).unwrap().symbol());
            }
            assert!(
                row.contains("Esc"),
                "view {view:?} bar missing Esc: {row:?}"
            );
        }
    }

    #[test]
    fn render_fkey_bar_popup_overrides_view() {
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(120, 3)).unwrap();
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 120, 1);
                render_fkey_bar(
                    frame,
                    area,
                    &View::CallList,
                    &Some(Popup::SaveDialog),
                    &theme,
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut row = String::new();
        for x in 0..buf.area.width {
            row.push_str(buf.cell((x, 0)).unwrap().symbol());
        }
        assert!(row.contains("Format"));
    }

    // ── render_filter_text_field direct ────────────────────────────

    #[test]
    fn render_filter_text_field_focused_and_unfocused() {
        let theme = Theme::default();

        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "From: ",
            value: "alice",
            field_width: 20,
            focused: true,
            cursor_pos: 2,
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
        let mut row = String::new();
        for x in 0..buf.area.width {
            row.push_str(buf.cell((x, 0)).unwrap().symbol());
        }
        assert!(row.contains("From:"));
        assert!(row.contains("alice"));

        // Unfocused branch with value longer than the field (truncation).
        let mut buf2 = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field2 = FilterTextField {
            label: "To: ",
            value: "averylongvaluethatexceedsthefieldwidth",
            field_width: 12,
            focused: false,
            cursor_pos: 0,
        };
        render_filter_text_field(&mut buf2, 0, 0, &field2, &theme);
        let mut row2 = String::new();
        for x in 0..buf2.area.width {
            row2.push_str(buf2.cell((x, 0)).unwrap().symbol());
        }
        assert!(row2.contains("To:"));
    }

    #[test]
    fn render_filter_text_field_cursor_at_end() {
        let theme = Theme::default();
        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "F: ",
            value: "ab",
            field_width: 20,
            focused: true,
            cursor_pos: 2, // at end == value.len()
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
        // Renders block cursor at end without panic.
    }

    // ── centered_popup geometry ────────────────────────────────────

    #[test]
    fn centered_popup_clamps_to_area() {
        let area = Rect::new(0, 0, 40, 20);
        let r = centered_popup(area, 100, 100);
        assert_eq!(r.width, 40);
        assert_eq!(r.height, 20);
        let r2 = centered_popup(area, 20, 10);
        assert_eq!(r2.width, 20);
        assert_eq!(r2.height, 10);
        assert_eq!(r2.x, 10);
        assert_eq!(r2.y, 5);
    }

    // ── message diff edge cases ────────────────────────────────────

    #[test]
    fn render_message_diff_dialog_not_found() {
        let app = App::new_test();
        let store = app.dialog_store.read();
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_message_diff(frame, area, &store, "missing", 0, 1, &theme);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
        }
        assert!(text.contains("Dialog not found"));
    }

    #[test]
    fn render_message_diff_message_index_out_of_range() {
        let app = app_with_dialog();
        let store = app.dialog_store.read();
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                // msg index way past the end.
                render_message_diff(frame, area, &store, "call-1@test", 0, 999, &theme);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
        }
        assert!(text.contains("Message not found"));
    }
}
