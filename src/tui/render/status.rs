// SPDX-License-Identifier: MIT OR Apache-2.0

//! The three sngrep-style status lines and the context-sensitive
//! F-key bar.

use crate::tui::*;

/// Render status line 1 (sngrep-style): `Current Mode: Online (any)    Dialogs: N (N displayed)`
///
/// The mode is colored good/bad for online/offline; a bold `PAUSED`
/// indicator and the `[A]` autoscroll marker are appended when active.
/// Counts come from the cached values on `App` (no store access).
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - The one-row status line 1 area at the top of the screen.
/// * `app` - Application state (capture mode, cached counts, flags, theme).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_status_line1(frame: &mut ratatui::Frame, area: Rect, app: &App) {
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
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - The one-row status line 2 area.
/// * `app` - Application state (active filter text, BPF filter, theme).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_status_line2(frame: &mut ratatui::Frame, area: Rect, app: &App) {
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
///
/// Priority order: an active search input (`/query`) wins; then a status
/// message (error-colored when it contains "error"/"fail", info otherwise);
/// then, in the call-flow view, the display-mode hints (time/SDP/color
/// modes, split percentage, focused pane); otherwise the display filter
/// plus any persisted search query.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - The one-row status line 3 area.
/// * `app` - Application state (search, status message, view, modes, theme).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_status_line3(frame: &mut ratatui::Frame, area: Rect, app: &App) {
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
        let focus = if app.flow.raw_preview {
            if app.flow.detail_focused {
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
            if app.flow.raw_preview {
                app.flow.raw_preview_pct
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
        // A search query persisted with Enter keeps narrowing the list, so
        // it must stay visible here — an invisible query makes the match
        // expression look broken ("148 dialogs, 4 displayed").
        let search_text = if app.search_query.is_empty() {
            String::new()
        } else {
            format!("    Search: /{} (F9 clears)", app.search_query)
        };
        let used = prefix.len() + filter_text.len() + search_text.len();
        let trailing = if used < w {
            " ".repeat(w - used)
        } else {
            String::new()
        };
        vec![
            Span::raw(prefix),
            Span::styled(filter_text.clone(), yellow),
            Span::styled(search_text, yellow),
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
///
/// # Arguments
/// * `view` - Current view; selects the view-specific item set.
/// * `popup` - Active popup, if any; a popup's bar takes precedence.
/// * `width` - Terminal width; narrower widths select shorter sets.
///
/// # Returns
/// `(key, label)` pairs in display order. Pure.
pub(in crate::tui) fn fkey_bar_items(
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
            Popup::NameAddress => vec![("Tab", "Endpoint"), ("Enter", "Save"), ("Esc", "Cancel")],
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
                        ("a/A", "Txn/Dlg"),
                        ("f", "Filter"),
                        ("F4", "Extend"),
                        ("r", "Streams"),
                        ("F6", "RTP"),
                    ]
                }
            }
            View::CombinedDetail { .. } => {
                vec![
                    ("Esc", "Back"),
                    ("\u{2191}\u{2193}", "Scroll"),
                    ("PgUp/Dn", "Page"),
                ]
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
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - The one-row bar area at the bottom of the screen.
/// * `view` - Current view (selects the item set via `fkey_bar_items`).
/// * `popup` - Active popup, if any; its bar takes precedence.
/// * `theme` - Color theme for key/label styling.
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_fkey_bar(
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

/// Unit tests for the status lines and the context-sensitive f-key bar.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::render::test_support::*;

    /// Outside call flow, status line 3 shows the display filter.
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

    /// In the call-flow view, status line 3 shows the mode hints
    /// including the split percentage.
    #[test]
    fn render_status_line3_call_flow_branch() {
        let mut app = app_with_dialog();
        app.current_view = View::CallFlow("call-1@test".to_string());
        app.flow.raw_preview = true;
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

    /// Every view's f-key bar includes the Esc hint.
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

    /// An active popup's bar (save dialog) replaces the view's bar.
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
}
