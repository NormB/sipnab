// SPDX-License-Identifier: MIT OR Apache-2.0

//! The three sngrep-style status lines and the context-sensitive
//! F-key bar.

use crate::tui::*;
use unicode_width::UnicodeWidthStr;

/// Fixed leading label of status line 1.
const L1_PREFIX: &str = " Current Mode: ";
/// Paused indicator appended to status line 1 (leading spacer included).
const L1_PAUSED: &str = "  PAUSED";
/// Autoscroll indicator appended to status line 1 (leading spacer included).
const L1_AUTOSCROLL: &str = "  [A]";
/// Fixed leading label of status line 2.
const L2_PREFIX: &str = " Match Expression: ";
/// Fixed separator label between the match expression and the BPF filter.
const L2_MID: &str = "    BPF Filter: ";

/// Rendered column span of `s`.
///
/// Thin wrapper over `unicode-width` so status-line fill and offset math is
/// measured by the columns a terminal actually paints, not by UTF-8 byte
/// length. The two diverge for non-ASCII text — an accented or CJK pcap
/// filename shown as the capture-mode label, or multibyte filter text — and
/// byte length would then mis-size the trailing fill.
fn display_cols(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Display columns consumed by status line 1 for the given capture-mode
/// label, counts segment and active indicators. Drives the trailing fill so
/// the status background stays solid regardless of the label's script.
fn line1_used_cols(mode: &str, counts: &str, paused: bool, autoscroll: bool) -> usize {
    display_cols(L1_PREFIX)
        + display_cols(mode)
        + display_cols(counts)
        + if paused { display_cols(L1_PAUSED) } else { 0 }
        + if autoscroll {
            display_cols(L1_AUTOSCROLL)
        } else {
            0
        }
}

/// Display columns consumed by status line 2's fixed labels plus the
/// variable match-expression and BPF texts. Drives the trailing fill.
fn line2_used_cols(filter_text: &str, bpf_text: &str) -> usize {
    display_cols(L2_PREFIX)
        + display_cols(filter_text)
        + display_cols(L2_MID)
        + display_cols(bpf_text)
}

/// Fit `bpf` into `cols` rendered columns, marking any cut with `…`.
///
/// The BPF slot is the one field on this row that is routinely wider than the
/// terminal. An operator's own expression is short, but the filter a live
/// capture runs by default is generated: one portrange arm plus an
/// encapsulation arm per link-header/tunnel-depth offset, which is well over a
/// thousand columns. Ratatui would clip that at the right edge and the result
/// reads as a complete expression that happens to end there — a filter that
/// says it does less than it does, which is the same lie as the blank slot in
/// a different shape. The ellipsis says "there is more", and the full text is
/// on the startup log line the operator can scroll back to or paste.
///
/// # Arguments
/// * `bpf` — the effective filter text.
/// * `cols` — rendered columns left on the row after the labels and the match
///   expression.
///
/// # Returns
/// The filter unchanged when it fits; otherwise its leading columns plus `…`,
/// never wider than `cols`. Zero columns yields the empty string — there is
/// nowhere to draw, and a marker would push the row wider than the area.
fn fit_bpf_to_cols(bpf: &str, cols: usize) -> String {
    if display_cols(bpf) <= cols {
        return bpf.to_string();
    }
    if cols == 0 {
        return String::new();
    }
    // One column is reserved for the marker, so the cut is always visible.
    let budget = cols - 1;
    let mut out = String::new();
    let mut used = 0usize;
    for ch in bpf.chars() {
        let w = display_cols(ch.encode_utf8(&mut [0u8; 4]));
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

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

    let counts = format!("    Dialogs: {total_count} ({displayed_count} displayed)");

    // Assemble the line from discrete spans so the styled capture-mode
    // segment is placed by rendered width. The previous approach sliced a
    // char-count-padded string with byte offsets and located `PAUSED` with
    // `str::find`, mixing byte and char indexing — brittle for a non-ASCII
    // capture-mode label (an offline pcap with an accented/CJK filename).
    let mut spans = vec![
        Span::raw(L1_PREFIX),
        Span::styled(app.capture_mode.clone(), mode_style),
        Span::raw(counts.clone()),
    ];
    if app.paused {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            "PAUSED",
            Style::default()
                .fg(app.theme.bad)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if app.call_list.autoscroll {
        spans.push(Span::raw(L1_AUTOSCROLL));
    }

    // Fill the remaining columns so the status background stays solid.
    let used = line1_used_cols(
        &app.capture_mode,
        &counts,
        app.paused,
        app.call_list.autoscroll,
    );
    spans.push(Span::raw(
        " ".repeat((area.width as usize).saturating_sub(used)),
    ));

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

    // Build styled spans with trailing padding for solid background. The
    // fill is sized by display width (via `line2_used_cols`): filter/BPF
    // text can be multibyte or wide, and byte length would over-count and
    // under-fill the row.
    let filter_text = &app.active_filter_text;
    // `app.bpf_filter` is the expression this session's capture was compiled
    // with, so on a live capture it is populated even when the operator typed
    // nothing — an empty slot here means no filter was compiled, not that
    // none was asked for. It can be far wider than the row (see
    // `fit_bpf_to_cols`), so what gets drawn is the fitted text and the fill
    // is measured from that.
    let bpf_text = fit_bpf_to_cols(
        &app.bpf_filter,
        (area.width as usize).saturating_sub(line2_used_cols(filter_text, "")),
    );
    let used = line2_used_cols(filter_text, &bpf_text);
    let trailing_pad = " ".repeat((area.width as usize).saturating_sub(used));

    let spans = vec![
        Span::raw(L2_PREFIX),
        Span::styled(filter_text.clone(), yellow),
        Span::raw(L2_MID),
        Span::styled(bpf_text, yellow),
        Span::raw(trailing_pad),
    ];

    let line2 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line2, area);
}

/// Render status line 3 (sngrep-style): `Display Filter: <filter>` or search/error overlay.
///
/// Priority order: an active search input (`/query`) wins; then a status
/// message (error-colored when it contains "error"/"fail", info otherwise);
/// then the persistent mouse-capture-off reminder (F12 toggle); then, in
/// the call-flow view, the display-mode hints (time/SDP/color modes,
/// split percentage, focused pane); otherwise the display filter plus any
/// persisted search query.
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
    } else if !app.mouse_capture_enabled {
        // Persistent reminder while native drag-to-select is active:
        // wheel scrolling is off until F12 re-enables capture, and the
        // user must be able to rediscover the way back at any time.
        let content = " Mouse capture OFF — drag selects text, F12 to re-enable";
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(app.theme.selected),
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

    /// The fill accounting for status line 2 measures the filter and BPF
    /// text by rendered columns, not UTF-8 bytes. `"日本語"` is 9 bytes but
    /// 6 columns; a byte-based count over-sizes the used width and would
    /// under-fill the row.
    #[test]
    fn line2_used_cols_is_display_width_not_bytes() {
        assert_eq!(display_cols("日本語"), 6);
        assert_eq!("日本語".len(), 9); // pins the byte/column divergence
        // 19 (prefix) + 6 (filter cols) + 16 (mid) + 3 (bpf) = 44.
        assert_eq!(
            line2_used_cols("日本語", "udp"),
            L2_PREFIX.len() + 6 + L2_MID.len() + 3
        );
    }

    /// A filter that fits the row is left exactly as the capture compiled
    /// it. The operator pastes this text into `tcpdump`, so a marker on a
    /// complete expression would send them after traffic that is not missing.
    #[test]
    fn a_filter_that_fits_the_row_is_left_verbatim() {
        assert_eq!(fit_bpf_to_cols("udp port 5060", 40), "udp port 5060");
        // Exactly filling the row is still a whole expression.
        assert_eq!(fit_bpf_to_cols("udp port 5060", 13), "udp port 5060");
        assert_eq!(fit_bpf_to_cols("", 0), "");
    }

    /// A filter wider than the row is cut with a visible marker rather than
    /// clipped at the screen edge. The generated live filter is far wider
    /// than any terminal, and an expression that appears to end where the
    /// screen ends understates what the kernel is dropping.
    #[test]
    fn a_filter_wider_than_the_row_is_cut_with_a_visible_marker() {
        let long = "portrange 5060-5061 or ((ether proto 0x8100) and (udp))";
        let fitted = fit_bpf_to_cols(long, 20);
        assert_eq!(display_cols(&fitted), 20, "cut text overruns the row");
        assert!(fitted.ends_with('…'), "no cut marker: {fitted:?}");
        let head = fitted.trim_end_matches('…');
        assert!(long.starts_with(head), "cut text is not a prefix: {head:?}");
    }

    /// The cut counts rendered columns, so a wide grapheme cannot push the
    /// text one column past the row it was measured into.
    #[test]
    fn the_cut_counts_columns_so_a_wide_character_cannot_overrun_the_row() {
        let fitted = fit_bpf_to_cols("日本語です", 5);
        assert!(
            display_cols(&fitted) <= 5,
            "wide text overran the row: {fitted:?}"
        );
        assert!(fitted.ends_with('…'), "no cut marker: {fitted:?}");
    }

    /// With one column left there is still room to say a filter exists.
    /// Blank is reserved for "no filter was compiled", so it must not be the
    /// rendering of a filter that had nowhere to go.
    #[test]
    fn a_single_free_column_still_marks_that_a_filter_is_in_force() {
        assert_eq!(fit_bpf_to_cols("udp port 5060", 1), "…");
    }

    /// The fill accounting for status line 1 measures the capture-mode
    /// label (which for offline captures is a filename that may be
    /// non-ASCII) by rendered columns, not bytes.
    #[test]
    fn line1_used_cols_is_display_width_not_bytes() {
        let mode = "Offline (日本語.pcap)"; // 9 + 6 + 6 = 21 columns, 24 bytes
        let counts = "    Dialogs: 0 (0 displayed)"; // ASCII: bytes == columns
        assert_eq!(display_cols(mode), 21);
        assert_eq!(mode.len(), 24); // pins the byte/column divergence
        assert_eq!(
            line1_used_cols(mode, counts, false, false),
            L1_PREFIX.len() + 21 + counts.len()
        );
        // Active indicators add their own rendered width.
        assert_eq!(
            line1_used_cols(mode, counts, true, true),
            L1_PREFIX.len() + 21 + counts.len() + L1_PAUSED.len() + L1_AUTOSCROLL.len()
        );
    }

    /// A non-ASCII offline filename renders intact and the styled
    /// capture-mode span lands on the mode text (offline "bad" color at the
    /// first mode column), proving the styled segment is not shifted by
    /// byte/char index skew.
    #[test]
    fn render_status_line1_non_ascii_filename_alignment() {
        let mut app = App::new_test();
        app.set_capture_mode("Offline (café.pcap)".to_string());
        let w = 80u16;
        let mut terminal = Terminal::new(TestBackend::new(w, 4)).unwrap();
        terminal
            .draw(|frame| render_status_line1(frame, Rect::new(0, 0, w, 1), &app))
            .unwrap();
        let buf = terminal.backend().buffer();
        let row: String = (0..w)
            .map(|x| buf.cell((x, 0)).unwrap().symbol().to_string())
            .collect();
        assert!(row.contains("café.pcap"), "filename missing: {row:?}");
        let mode_col = L1_PREFIX.len() as u16;
        let cell = buf.cell((mode_col, 0)).unwrap();
        assert_eq!(cell.symbol(), "O", "mode span misaligned: {row:?}");
        assert_eq!(cell.fg, app.theme.bad, "mode span not styled");
    }

    /// A wide-character (CJK) match expression renders intact under status
    /// line 2 without truncation or panic.
    #[test]
    fn render_status_line2_wide_char_filter() {
        let mut app = App::new_test();
        app.active_filter_text = "日本語".to_string();
        app.bpf_filter = "udp".to_string();
        let w = 80u16;
        let mut terminal = Terminal::new(TestBackend::new(w, 4)).unwrap();
        terminal
            .draw(|frame| render_status_line2(frame, Rect::new(0, 0, w, 1), &app))
            .unwrap();
        let buf = terminal.backend().buffer();
        let row: String = (0..w)
            .map(|x| buf.cell((x, 0)).unwrap().symbol().to_string())
            .collect();
        // Reading per cell interleaves the wide-grapheme skip cells, so
        // assert each ideograph is present rather than the joined string.
        assert!(
            ['日', '本', '語'].iter().all(|c| row.contains(*c)),
            "wide filter text missing: {row:?}"
        );
        assert!(row.contains("BPF Filter:"), "bpf label missing: {row:?}");
    }

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

    /// While mouse capture is toggled off (F12), status line 3 shows the
    /// persistent re-enable reminder instead of the display filter.
    #[test]
    fn render_status_line3_mouse_capture_off_reminder() {
        let mut app = App::new_test();
        app.mouse_capture_enabled = false;
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
        assert!(
            row.contains("Mouse capture OFF") && row.contains("F12"),
            "missing persistent reminder: {row:?}"
        );
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
}
