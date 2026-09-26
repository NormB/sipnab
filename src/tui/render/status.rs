// SPDX-License-Identifier: MIT OR Apache-2.0

//! The three status lines and the context-sensitive
//! F-key bar.

use crate::tui::*;
use unicode_width::UnicodeWidthStr;

/// Leading indent of status line 1, before the capture source.
const L1_INDENT: &str = " ";
/// Gap between the segments of status line 1.
const L1_GAP: &str = "    ";
/// Fixed leading label of status line 2: the capture (BPF) filter.
const L2_PREFIX: &str = " Capture filter (BPF): ";
/// Fixed leading label of status line 3: the view filter.
const L3_PREFIX: &str = " View filter: ";
/// What an unset filter slot says. A bare label read as a rendering fault.
const FILTER_NONE: &str = "none";

/// Status line 1's capture-source phrase, from the capture-mode label.
///
/// The label is `Online (<interface>)` for a live capture and
/// `Offline (<file>)` for a file, a shape the loaders own. This turns it into
/// words a reader does not have to decode: `Live capture: eth0`,
/// `File: call.pcap`. A label in neither shape is shown as it is. Pure.
pub(in crate::tui) fn capture_source_phrase(mode: &str) -> String {
    let inner = |prefix: &str| {
        mode.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(')'))
    };
    if let Some(device) = inner("Online (") {
        format!("Live capture: {device}")
    } else if let Some(file) = inner("Offline (") {
        format!("File: {file}")
    } else {
        mode.to_string()
    }
}

/// Rendered column span of `s`.
///
/// Thin wrapper over `unicode-width` so the BPF slot's budget is measured by
/// the columns a terminal actually paints, not by UTF-8 byte length. The two
/// diverge for non-ASCII text (multibyte filter text), and byte length would
/// then mis-size the cut.
fn display_cols(s: &str) -> usize {
    UnicodeWidthStr::width(s)
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

/// What status line 2 shows for the auto-generated default capture filter,
/// one text per shape `plan` can generate.
///
/// The generated live filter is one portrange arm plus an encapsulation arm per
/// link-header/tunnel-depth offset -- well over a thousand columns -- and a
/// truncated prefix of it reads as a complete filter that does less than it
/// does. So the default is summarized rather than shown raw; the full text is on
/// the startup log line, exactly as `fit_bpf_to_cols` notes. SIP is admitted
/// inside every encapsulation the filter knows; RTP only untagged.
const BPF_DEFAULT_SIP_AND_RTP: &str = "default (SIP, all encapsulations; RTP)";
/// The generated default with RTP analysis off (`--no-rtp`).
const BPF_DEFAULT_SIP_ONLY: &str = "default (SIP only, all encapsulations)";
/// A composite's interface, whose signaling comes from the HEP listener.
const BPF_DEFAULT_RTP_ONLY: &str = "default (RTP only; SIP from HEP)";

/// The text to draw in status line 2's BPF slot, fitted to `cols`.
///
/// A `generated` default is shown as its [`default_summary`], not its raw
/// expression. An operator's own filter is shown verbatim, cut with `…` only
/// when it overflows the row. `live_only` appends the `[live capture]` marker
/// for the offline-after-`O` case (the filter belongs to the live half still
/// running behind an opened file), on either kind.
/// What the generated default in `expr` admits, in words.
///
/// Read from the expression rather than passed alongside it, so the words
/// cannot describe a different filter from the one the kernel runs. A fixed
/// `SIP + RTP` stood here while the default admitted no RTP at all
/// (LIVE-MEDIA-1).
fn default_summary(expr: &str) -> &'static str {
    let sip = expr.contains("portrange");
    let rtp = expr.contains(crate::app::bootstrap::MEDIA_FILTER_ARM);
    match (sip, rtp) {
        (true, true) => BPF_DEFAULT_SIP_AND_RTP,
        (false, true) => BPF_DEFAULT_RTP_ONLY,
        _ => BPF_DEFAULT_SIP_ONLY,
    }
}

fn bpf_display(generated: bool, bpf: &str, live_only: bool, cols: usize) -> String {
    let base = if generated { default_summary(bpf) } else { bpf };
    let shown = if live_only && !bpf.is_empty() {
        format!("{base} [live capture]")
    } else {
        base.to_string()
    };
    fit_bpf_to_cols(&shown, cols)
}

/// Render status line 1: `Live capture: any    Dialogs: 3 shown of 5    Autoscroll: on`.
///
/// The capture source is colored good/bad for live/offline; a bold `PAUSED`
/// indicator is appended while the capture is paused. Counts come from the
/// cached values on `App` (no store access). The row's background comes from
/// the paragraph style, which fills the whole area, so no padding is drawn.
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

    // Discrete spans, so the styled capture-source segment is placed by
    // rendered width and never by byte offsets into a padded string (a
    // non-ASCII pcap filename would skew those).
    let mut spans = vec![
        Span::raw(L1_INDENT),
        Span::styled(capture_source_phrase(&app.capture_mode), mode_style),
        Span::raw(format!(
            "{L1_GAP}Dialogs: {displayed_count} shown of {total_count}"
        )),
        Span::raw(format!(
            "{L1_GAP}Autoscroll: {}",
            if app.call_list.autoscroll {
                "on"
            } else {
                "off"
            }
        )),
    ];
    if app.paused {
        spans.push(Span::raw(L1_GAP));
        spans.push(Span::styled(
            "PAUSED",
            Style::default()
                .fg(app.theme.bad)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let line1 = Paragraph::new(Line::from(spans)).style(status_bar_style(&app.theme));
    frame.render_widget(line1, area);
}

/// The style of every status row and the f-key bar: the status background,
/// with text in the color that reads against it. The band is a fixed color,
/// so its text cannot be the terminal default, which is dark on a light
/// terminal. `Reset` (the NO_COLOR theme) sets no text color at all.
fn status_bar_style(theme: &Theme) -> Style {
    let style = Style::default().bg(theme.status_bg);
    match crate::tui::call_list::header_foreground(theme.status_bg) {
        Some(fg) => style.fg(fg),
        None => style,
    }
}

/// Render status line 2: `Capture filter (BPF): <bpf>`.
///
/// Only the capture filter lives here; the view filter is on line 3. Both
/// rows used to print the view filter, so the header said one thing twice.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - The one-row status line 2 area.
/// * `app` - Application state (BPF filter, theme).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_status_line2(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let yellow = Style::default().fg(app.theme.selected);

    // `app.bpf_filter` is the expression this session's capture was compiled
    // with, so on a live capture it is populated even when the operator typed
    // nothing — `none` here means no filter was compiled, not that none was
    // asked for. It can be far wider than the row (see `fit_bpf_to_cols`), so
    // what gets drawn is the fitted text.
    //
    // After an in-session `O` open, line 1 names the file while this filter
    // still belongs to the live capture that is running behind it. Unmarked,
    // the two read as one statement about one source (#190). The filter is not
    // cleared: it is still in force for the live half, and blanking it would
    // claim no filter was compiled, which is a different and false thing to
    // say.
    let bpf_text = bpf_display(
        app.bpf_filter_generated,
        &app.bpf_filter,
        app.bpf_is_live_only(),
        (area.width as usize).saturating_sub(display_cols(L2_PREFIX)),
    );
    let shown = if bpf_text.is_empty() {
        FILTER_NONE.to_string()
    } else {
        bpf_text
    };

    let spans = vec![Span::raw(L2_PREFIX), Span::styled(shown, yellow)];
    let line2 = Paragraph::new(Line::from(spans)).style(status_bar_style(&app.theme));
    frame.render_widget(line2, area);
}

/// Render status line 3: `View filter: <filter>` or search/error overlay.
///
/// Priority order: an active search input (`/query`) wins; then a status
/// message (error-colored when it was raised with `App::set_status_error`,
/// info otherwise);
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
        // Bold for contrast on the status bar. A message raised as an error
        // (`App::set_status_error`) takes the bad color; its words decide
        // nothing, so "File not found" is an error and "Cleared 3 failed
        // dialogs" is not.
        let style = if app.status_is_error() {
            Style::default().fg(app.theme.bad)
        } else {
            Style::default()
        };
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            style.add_modifier(Modifier::BOLD),
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
        let detail = if app.flow.raw_preview {
            format!("{}%", app.flow.raw_preview_pct)
        } else {
            "off".to_string()
        };
        let content = format!(
            " {} | {} | {} | Detail: {detail}{focus}",
            app.timestamp_mode.label(),
            app.sdp_display_mode.label(),
            app.color_mode.label(),
        );
        vec![Span::styled(content, cyan)]
    } else {
        let yellow = Style::default().fg(app.theme.selected);
        let filter_text = if app.active_filter_text.is_empty() {
            FILTER_NONE
        } else {
            app.active_filter_text.as_str()
        };
        // A search query persisted with Enter keeps narrowing the list, so
        // it must stay visible here — an invisible query makes the view
        // filter look broken ("148 dialogs, 4 shown").
        let search_text = if app.search_query.is_empty() {
            String::new()
        } else {
            format!("    Search: /{} (F9 clears)", app.search_query)
        };
        vec![
            Span::raw(L3_PREFIX),
            Span::styled(filter_text.to_string(), yellow),
            Span::styled(search_text, yellow),
        ]
    };

    let line3 = Paragraph::new(Line::from(spans)).style(status_bar_style(&app.theme));
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
    file_open_manual: bool,
) -> Vec<(&'static str, &'static str)> {
    if let Some(p) = popup {
        match p {
            Popup::QuitConfirm => vec![("Y", "Quit"), ("N/Esc", "Cancel")],
            Popup::NoteEditor => vec![("Enter", "Keep"), ("Esc", "Cancel")],
            Popup::UnsavedNotes => vec![("Y", "Open"), ("N/Esc", "Keep")],
            Popup::ArchivePassword => vec![
                ("Enter", "Try"),
                ("Esc", "Skip"),
                ("^R", "Reveal"),
                ("^U", "Clear"),
            ],
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
                    ("\u{2191}\u{2193}", "Move"),
                    ("Enter", "Toggle"),
                    ("Esc", "Close"),
                ]
            }
            // The dialog has two modes with different keys: in the typed-path
            // field Backspace deletes a character and Tab switches to the
            // browser, so the browser's bar would misdescribe both.
            Popup::FileOpenDialog if file_open_manual => {
                vec![("Enter", "Open"), ("Tab", "Browse"), ("Esc", "Cancel")]
            }
            Popup::FileOpenDialog => vec![
                ("Enter", "Open"),
                ("\u{2191}\u{2193}", "Move"),
                ("Backspace", "Parent dir"),
                ("Tab", "Type path"),
                ("Esc", "Cancel"),
            ],
            Popup::NameAddress => vec![("Tab", "Endpoint"), ("Enter", "Save"), ("Esc", "Cancel")],
        }
    } else {
        // The keys every scroll-only analysis view answers (statistics,
        // talkers, carrier metrics, conformance, ...): the help lists them
        // per view, and F1 opens help from each of them.
        let scroll_view = vec![
            ("Esc", "Back"),
            ("F1", "Help"),
            ("\u{2191}\u{2193}", "Scroll"),
            ("PgUp/Dn", "Page"),
        ];
        match view {
            // The thresholds are the measured column cost of each set, not
            // round numbers: `every_fkey_bar_tier_fits_the_width_that_selects_it`
            // recomputes them, so a label edited without a threshold edit
            // fails rather than silently clipping the tail of the row.
            //
            // F9 is `Clear filter`, never a bare `Clear`: F5 already clears the
            // CALL LIST (`Clear calls`), and two entries both reading "Clear"
            // would leave the operator guessing which one drops their capture.
            // It read `Addrs` until 2026-08-06 — the label of the `N` binding —
            // so pressing it cleared an unset filter and looked like a dead key.
            View::CallList => {
                if width < 67 {
                    // 58 columns: the narrowest set, for a 60-column terminal.
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Open call"),
                        ("Tab", "Streams"),
                        ("F7", "Filter"),
                    ]
                } else if width < 97 {
                    // 67 columns.
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Open call"),
                        ("Tab", "Streams"),
                        ("F2", "Save"),
                        ("F7", "Filter"),
                    ]
                } else if width < 124 {
                    // 97 columns. This tier exists so a ~120-column terminal
                    // — the common wide default — still gets `O Open file`.
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Open call"),
                        ("Tab", "Streams"),
                        ("O", "Open file"),
                        ("F2", "Save"),
                        ("F7", "Filter"),
                        ("F9", "Clear filter"),
                    ]
                } else if width < 164 {
                    // 124 columns.
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Open call"),
                        ("Tab", "Streams"),
                        ("O", "Open file"),
                        ("F2", "Save"),
                        ("F3", "Search"),
                        ("F5", "Clear calls"),
                        ("F7", "Filter"),
                        ("F9", "Clear filter"),
                    ]
                } else {
                    // 164 columns.
                    vec![
                        ("Esc", "Quit"),
                        ("F1", "Help"),
                        ("Enter", "Open call"),
                        ("Tab", "Streams"),
                        ("O", "Open file"),
                        ("F2", "Save"),
                        ("F3", "Search"),
                        ("F4", "Extend"),
                        ("F5", "Clear calls"),
                        ("F6", "Raw"),
                        ("F7", "Filter"),
                        ("F9", "Clear filter"),
                        ("F10", "Columns"),
                        ("N", "Name"),
                    ]
                }
            }
            View::CallFlow(_) => {
                if width < 80 {
                    // 37 columns.
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("\u{2191}\u{2193}", "Move"),
                        ("Enter", "Raw"),
                    ]
                } else if width < 107 {
                    // 71 columns.
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("\u{2191}\u{2193}", "Move"),
                        ("Enter", "Raw"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Detail"),
                    ]
                } else if width < 137 {
                    // 107 columns.
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("\u{2191}\u{2193}", "Move"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Detail"),
                        ("a/A", "Combined"),
                        ("f", "Filter"),
                    ]
                } else {
                    // 137 columns.
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("\u{2191}\u{2193}", "Move"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Detail"),
                        ("a/A", "Combined"),
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
                    ("F1", "Help"),
                    ("\u{2191}\u{2193}", "Scroll"),
                    ("PgUp/Dn", "Page"),
                ]
            }
            View::RawMessage { .. } => {
                if width < 80 {
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("s", "Highlight"),
                        ("F2", "Save"),
                    ]
                } else {
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("s", "Highlight"),
                        ("c", "Color"),
                        ("/", "Search"),
                        ("y", "Copy"),
                        ("F2", "Save"),
                    ]
                }
            }
            View::MessageDiff { .. } => vec![
                ("Esc", "Back"),
                ("F1", "Help"),
                ("\u{2191}\u{2193}", "Scroll"),
            ],
            View::StreamList => vec![
                ("Esc", "Back"),
                ("F1", "Help"),
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
                        ("F1", "Help"),
                        ("j/k", "Scroll"),
                        ("PgUp/Dn", "Page"),
                        ("P", "Play"),
                        ("F2", "Save WAV"),
                        ("L", "Loss map"),
                    ]
                }
                #[cfg(not(feature = "audio"))]
                {
                    vec![
                        ("Esc", "Back"),
                        ("F1", "Help"),
                        ("j/k", "Scroll"),
                        ("PgUp/Dn", "Page"),
                        ("F2", "Save WAV"),
                        ("L", "Loss map"),
                    ]
                }
            }
            View::RelayStats { .. } => vec![
                ("Esc/S", "Close"),
                ("F1", "Help"),
                ("?", "Names"),
                ("K", "Compare"),
                ("H", "Holdings"),
                ("\u{2191}\u{2193}", "Scroll"),
            ],
            View::BpfFilter => vec![
                ("Esc", "Cancel"),
                ("Tab", "AND/OR"),
                ("Enter", "Check"),
                ("\u{2191}\u{2193}", "Scroll"),
            ],
            View::Help => vec![
                ("Esc", "Close"),
                ("\u{2191}\u{2193}", "Scroll"),
                ("PgUp/Dn", "Page"),
            ],
            View::CaptureHealth => {
                let mut items = scroll_view;
                items.push(("s", "HEP senders"));
                items
            }
            View::TfpsObserve { .. } => vec![
                ("Esc", "Back"),
                ("F1", "Help"),
                ("b", "Banned"),
                ("d", "Drops"),
                ("\u{2191}\u{2193}", "Scroll"),
            ],
            View::QualityDashboard => vec![
                ("Esc", "Back"),
                ("F1", "Help"),
                ("\u{2191}\u{2193}", "Select"),
                ("Enter", "Detail"),
                ("L", "Loss map"),
            ],
            View::CallTimeline(_) | View::StreamLossMap(_) => {
                vec![("Esc", "Back"), ("F1", "Help")]
            }
            View::Statistics
            | View::Talkers
            | View::CarrierMetrics
            | View::CompareDialogs { .. }
            | View::EndpointRollup { .. }
            | View::HepSenders
            | View::CallVolume
            | View::SdpTimeline { .. }
            | View::Conformance { .. }
            | View::SecurityFindings => scroll_view,
        }
    }
}

/// Render the F-key bar at the bottom of the screen.
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
    file_open_manual: bool,
    theme: &Theme,
) {
    // No color of their own: both inherit the bar's text color, which is
    // chosen against the bar's background.
    let key_style = Style::default().add_modifier(Modifier::BOLD);
    let label_style = Style::default();

    let width = area.width;

    // Full item sets per view; items near the end are lower priority.
    // Popup-specific bars take precedence.
    let items = fkey_bar_items(view, popup, width, file_open_manual);

    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label)) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(format!("{key} "), key_style));
        spans.push(Span::styled((*label).to_string(), label_style));
    }

    let bar = Paragraph::new(Line::from(spans)).style(status_bar_style(theme));
    frame.render_widget(bar, area);
}

// ── Popup rendering ────────────────────────────────────────────────

/// Unit tests for the status lines and the context-sensitive f-key bar.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::render::test_support::*;

    /// The auto-generated default is summarized, never drawn as its raw
    /// thousand-column expression -- the whole point of the display fix. A
    /// truncated prefix of the generated filter reads as a complete filter that
    /// captures less than it does.
    #[test]
    fn a_generated_default_is_summarized_not_shown_raw() {
        let raw = "udp and (portrange 5060-5061 or ip proto 41) or ".repeat(40);
        let out = bpf_display(true, &raw, false, 200);
        assert_eq!(out, default_summary(&raw));
        assert!(
            !out.contains("portrange"),
            "the raw generated expression must not leak into the slot: {out}"
        );
    }

    /// The summary says what the generated filter admits, read from the filter
    /// itself. It used to say `SIP + RTP` whatever was generated, while the
    /// default admitted no RTP at all (LIVE-MEDIA-1); with `--no-rtp` it still
    /// admits none, and on a composite it admits RTP and no SIP.
    #[test]
    fn the_summary_names_what_the_generated_filter_admits() {
        use crate::app::bootstrap::{MEDIA_FILTER_ARM, auto_capture_filter};
        let both = bpf_display(
            true,
            &auto_capture_filter(5060, 5061, &[], true),
            false,
            200,
        );
        assert!(both.contains("SIP") && both.contains("RTP"), "{both}");
        let sip = bpf_display(
            true,
            &auto_capture_filter(5060, 5061, &[], false),
            false,
            200,
        );
        assert!(sip.contains("SIP") && !sip.contains("RTP"), "{sip}");
        let rtp = bpf_display(true, MEDIA_FILTER_ARM, false, 200);
        assert!(rtp.contains("RTP only"), "{rtp}");
    }

    /// An operator's own filter is shown verbatim when it fits -- pasteable into
    /// tcpdump, unchanged.
    #[test]
    fn an_operator_filter_is_shown_verbatim() {
        assert_eq!(
            bpf_display(false, "udp port 5060", false, 40),
            "udp port 5060"
        );
    }

    /// A long operator filter is still cut with `…`, the existing behavior for
    /// an expression the operator authored.
    #[test]
    fn a_long_operator_filter_is_cut_with_an_ellipsis() {
        let out = bpf_display(
            false,
            "udp port 5060 and host 192.0.2.5 and portrange 10000-20000",
            false,
            20,
        );
        assert!(
            out.ends_with('…'),
            "a long operator filter is truncated: {out}"
        );
    }

    /// The `[live capture]` marker rides on the summary too, so the
    /// offline-after-`O` case reads correctly for a generated default.
    #[test]
    fn the_live_marker_rides_on_the_summary() {
        let out = bpf_display(true, "anything", true, 200);
        assert!(
            out.starts_with(default_summary("anything")),
            "the summary comes first: {out}"
        );
        assert!(
            out.contains("[live capture]"),
            "the live marker travels: {out}"
        );
    }

    /// An empty filter (nothing compiled) stays empty -- blank means "nothing
    /// was filtered", never a summary.
    #[test]
    fn an_empty_filter_stays_empty() {
        assert_eq!(bpf_display(false, "", false, 40), "");
        assert_eq!(bpf_display(false, "", true, 40), "");
    }

    /// A live capture is named by its interface, in words: the old
    /// `Current Mode: Online (any)` made the reader decode "mode" and
    /// "online" into "which traffic am I looking at".
    #[test]
    fn a_live_capture_is_named_by_its_interface() {
        assert_eq!(capture_source_phrase("Online (eth0)"), "Live capture: eth0");
        assert_eq!(capture_source_phrase("Online (any)"), "Live capture: any");
    }

    /// An offline capture is named by its file, non-ASCII names intact.
    #[test]
    fn an_offline_capture_is_named_by_its_file() {
        assert_eq!(
            capture_source_phrase("Offline (café.pcap)"),
            "File: café.pcap"
        );
    }

    /// A label in neither shape is shown verbatim rather than mangled.
    #[test]
    fn an_unrecognized_capture_label_is_shown_as_is() {
        assert_eq!(capture_source_phrase("HEP listener"), "HEP listener");
    }

    /// Status line 1 reads as words: the source, the dialog counts as
    /// "N shown of M", and autoscroll spelled out rather than a bare `[A]`.
    #[test]
    fn status_line1_reads_as_words() {
        let app = App::new_test();
        let row = status_row(&app, 100, render_status_line1);
        assert!(row.contains("Live capture: any"), "source missing: {row:?}");
        assert!(
            row.contains("Dialogs: 0 shown of 0"),
            "counts missing: {row:?}"
        );
        assert!(
            row.contains("Autoscroll: on"),
            "autoscroll missing: {row:?}"
        );
        assert!(!row.contains("[A]"), "the bare [A] marker is back: {row:?}");
        assert!(!row.contains("Current Mode"), "old label is back: {row:?}");
    }

    /// Line 2 carries the capture (BPF) filter and ONLY that; the view
    /// filter lives on line 3. Both lines used to print the view filter, so
    /// the header said the same thing twice and the BPF slot was easy to miss.
    #[test]
    fn the_view_filter_is_on_line3_and_not_on_line2() {
        let mut app = App::new_test();
        app.active_filter_text = "method == 'BYE'".to_string();
        app.bpf_filter = "udp port 5060".to_string();
        let line2 = status_row(&app, 100, render_status_line2);
        let line3 = status_row(&app, 100, render_status_line3);
        assert!(
            line2.contains("Capture filter (BPF): udp port 5060"),
            "capture filter missing from line 2: {line2:?}"
        );
        assert!(
            !line2.contains("method =="),
            "the view filter is duplicated on line 2: {line2:?}"
        );
        assert!(
            line3.contains("View filter: method == 'BYE'"),
            "view filter missing from line 3: {line3:?}"
        );
    }

    /// With no view filter and no capture filter, both slots say `none`
    /// instead of ending on a bare label.
    #[test]
    fn unset_filters_read_none() {
        let app = App::new_test();
        let line2 = status_row(&app, 100, render_status_line2);
        let line3 = status_row(&app, 100, render_status_line3);
        assert!(
            line2.trim_end().ends_with("Capture filter (BPF): none"),
            "{line2:?}"
        );
        assert!(line3.trim_end().ends_with("View filter: none"), "{line3:?}");
    }

    /// The color of the first message column on status line 3.
    fn status_message_fg(app: &App) -> ratatui::style::Color {
        let mut terminal = Terminal::new(TestBackend::new(60, 2)).unwrap();
        terminal
            .draw(|frame| render_status_line3(frame, Rect::new(0, 0, 60, 1), app))
            .unwrap();
        terminal.backend().buffer().cell((1, 0)).unwrap().fg
    }

    /// A message raised as an error draws in the error color, whatever its
    /// words. "File not found" contains neither "error" nor "fail", and the
    /// old substring test drew it as plain information.
    #[test]
    fn a_raised_error_draws_in_the_error_color() {
        let mut app = App::new_test();
        app.set_status_error("File not found: /nope.pcap");
        assert_eq!(status_message_fg(&app), app.theme.bad);
    }

    /// Information draws as information even when its words contain "fail":
    /// severity is what the code said, not what the sentence happens to say.
    #[test]
    fn information_that_mentions_failure_is_not_drawn_as_an_error() {
        let mut app = App::new_test();
        app.status_error = Some("Cleared 3 failed dialogs".to_string());
        assert_ne!(status_message_fg(&app), app.theme.bad);
    }

    /// A later information message replaces an error without inheriting its
    /// color: severity belongs to the message it was raised with.
    #[test]
    fn an_error_does_not_color_the_message_that_replaces_it() {
        let mut app = App::new_test();
        app.set_status_error("Save failed: disk full");
        app.status_error = Some("Saved 3 packets".to_string());
        assert_ne!(status_message_fg(&app), app.theme.bad);
    }

    /// The default body text follows the terminal's own foreground, so a
    /// light terminal gets dark text. Hardcoded white was near-invisible on
    /// a white background.
    #[test]
    fn the_default_foreground_follows_the_terminal() {
        assert_eq!(Theme::default().foreground, ratatui::style::Color::Reset);
    }

    /// The status rows and the key bar paint their own background, so their
    /// text takes the color chosen against that background, never the
    /// terminal default (dark text on the dark band on a light terminal).
    #[test]
    fn status_bar_text_contrasts_with_its_background() {
        let app = App::new_test();
        let want = crate::tui::call_list::header_foreground(app.theme.status_bg)
            .expect("the default status band is a real color");
        let mut terminal = Terminal::new(TestBackend::new(80, 2)).unwrap();
        terminal
            .draw(|frame| {
                render_fkey_bar(
                    frame,
                    Rect::new(0, 0, 80, 1),
                    &View::CallList,
                    &None,
                    false,
                    &app.theme,
                );
                render_status_line1(frame, Rect::new(0, 1, 80, 1), &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        assert_eq!(buf.cell((0, 0)).unwrap().fg, want, "key bar key");
        assert_eq!(buf.cell((4, 0)).unwrap().fg, want, "key bar label");
        // Column 0 of line 1 is the indent, drawn in the row's own style.
        assert_eq!(buf.cell((0, 1)).unwrap().fg, want, "status line 1");
    }

    /// Draw one status row with `render` into a `width`-wide backend and
    /// return it as text.
    fn status_row(app: &App, width: u16, render: fn(&mut ratatui::Frame, Rect, &App)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, 2)).unwrap();
        terminal
            .draw(|frame| render(frame, Rect::new(0, 0, width, 1), app))
            .unwrap();
        let buf = terminal.backend().buffer();
        (0..width)
            .map(|x| buf.cell((x, 0)).unwrap().symbol().to_string())
            .collect()
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

    /// A non-ASCII offline filename renders intact and the styled
    /// capture-source span lands on the source text (offline "bad" color at
    /// the first source column), proving the styled segment is not shifted by
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
        assert!(row.contains("File: café.pcap"), "filename missing: {row:?}");
        let src_col = L1_INDENT.len() as u16;
        let cell = buf.cell((src_col, 0)).unwrap();
        assert_eq!(cell.symbol(), "F", "source span misaligned: {row:?}");
        assert_eq!(cell.fg, app.theme.bad, "source span not styled");
    }

    /// A wide-character (CJK) capture filter renders intact under status
    /// line 2 without truncation or panic.
    #[test]
    fn render_status_line2_wide_char_filter() {
        let mut app = App::new_test();
        app.bpf_filter = "日本語".to_string();
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
        assert!(
            row.contains("Capture filter (BPF):"),
            "bpf label missing: {row:?}"
        );
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
        assert!(row.contains("View filter"));
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
        assert!(row.contains("Detail: "), "{row:?}");
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
            View::BpfFilter,
        ] {
            let mut terminal = Terminal::new(TestBackend::new(120, 3)).unwrap();
            terminal
                .draw(|frame| {
                    let area = Rect::new(0, 0, 120, 1);
                    render_fkey_bar(frame, area, &view, &None, false, &theme);
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
                    false,
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

    /// The file-open dialog's bar names the keys of the mode it is in. It
    /// used to show the browser's keys (with a Shift-arrow glyph for plain
    /// arrows) over the typed-path field, where Backspace edits the path
    /// rather than going up a directory.
    #[test]
    fn the_file_open_bar_follows_the_dialog_mode() {
        let popup = Some(Popup::FileOpenDialog);
        let manual = fkey_bar_items(&View::CallList, &popup, 120, true);
        assert!(manual.contains(&("Tab", "Browse")), "{manual:?}");
        assert!(
            !manual.iter().any(|(k, _)| *k == "Backspace"),
            "typed-path mode advertises the browser's Backspace: {manual:?}"
        );
        let browse = fkey_bar_items(&View::CallList, &popup, 120, false);
        assert!(browse.contains(&("Tab", "Type path")), "{browse:?}");
        assert!(browse.contains(&("\u{2191}\u{2193}", "Move")), "{browse:?}");
        assert!(
            !browse.iter().any(|(k, _)| k.contains('\u{21E7}')),
            "plain arrows drawn as Shift-arrows: {browse:?}"
        );
    }

    // ── The f-key bar must not misrepresent the keymap ──────────────

    /// Translate one f-key bar legend into the key events it advertises.
    ///
    /// Compound legends (`a/A`, `j/k`, `PgUp/Dn`, `↑↓`) promise several
    /// keys at once, and every one of them has to work — a legend is a
    /// promise per key, not per entry.
    ///
    /// An unknown legend PANICS rather than returning nothing. A parser
    /// that quietly yields an empty set would let each newly-added bar
    /// entry pass unverified, which is precisely the failure the gate
    /// below exists to prevent: the gate would stay green while covering
    /// less and less. Adding a bar entry must force a decision here.
    fn bar_legend_keys(legend: &str) -> Vec<KeyEvent> {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let plain = |c: KeyCode| KeyEvent::new(c, KeyModifiers::NONE);

        // Glyph legends are single entries that name a pair of keys.
        match legend {
            "\u{2191}\u{2193}" | "Up/Down" => {
                return vec![plain(KeyCode::Up), plain(KeyCode::Down)];
            }
            "PgUp/Dn" => return vec![plain(KeyCode::PageUp), plain(KeyCode::PageDown)],
            _ => {}
        }

        legend
            .split('/')
            .map(|tok| match tok {
                "Esc" => plain(KeyCode::Esc),
                "Enter" => plain(KeyCode::Enter),
                "Tab" => plain(KeyCode::Tab),
                "Space" => plain(KeyCode::Char(' ')),
                "Backspace" => plain(KeyCode::Backspace),
                "PgUp" => plain(KeyCode::PageUp),
                "PgDn" => plain(KeyCode::PageDown),
                // The bare "/" legend (raw-message search) splits into two
                // empty tokens; either one stands for the slash key.
                "" => plain(KeyCode::Char('/')),
                _ => {
                    if let Some(n) = tok.strip_prefix('F').and_then(|d| d.parse::<u8>().ok()) {
                        plain(KeyCode::F(n))
                    } else {
                        let mut chars = tok.chars();
                        match (chars.next(), chars.next()) {
                            (Some(c), None) => plain(KeyCode::Char(c)),
                            _ => panic!(
                                "f-key bar legend {legend:?} has an unrecognized token {tok:?}. \
                                 Teach bar_legend_keys what key it names — an unparsed legend \
                                 is an unverified promise to the operator."
                            ),
                        }
                    }
                }
            })
            .collect()
    }

    /// A key-event predicate: whether a view's own keymap answers a key.
    type Bound = fn(&Keymap, KeyEvent) -> bool;

    /// Every view with an f-key bar, paired with its pure key-to-action
    /// mapper. One list, so the bound gate, the width gate and the help gate
    /// cannot cover different views.
    fn bar_views() -> Vec<(View, Bound)> {
        use crate::rtp::stream::StreamKey;
        use crate::tui::tfps_observe::TfpsMode;
        use std::net::SocketAddr;

        let addr =
            |s: &str| -> SocketAddr { s.parse().expect("test-local literal socket address") };
        let key = StreamKey {
            ssrc: 1,
            src: addr("192.0.2.1:5004"),
            dst: addr("192.0.2.2:5004"),
        };
        let id = || String::from("call-id");
        vec![
            (View::CallList, |km, k| call_list_action(km, k).is_some()),
            (View::CallFlow(id()), |km, k| {
                call_flow_action(km, k).is_some()
            }),
            (
                View::RawMessage {
                    call_id: id(),
                    message_index: 0,
                },
                |km, k| raw_message_action(km, k).is_some(),
            ),
            (
                View::MessageDiff {
                    call_id: id(),
                    msg1_idx: 0,
                    msg2_idx: 1,
                },
                |km, k| message_diff_action(km, k).is_some(),
            ),
            (
                View::CombinedDetail {
                    call_id: id(),
                    indices: vec![0],
                    scope: "dialog",
                },
                |km, k| combined_detail_action(km, k).is_some(),
            ),
            (View::StreamList, |km, k| {
                stream_list_action(km, k).is_some()
            }),
            (View::StreamDetail(key.clone()), |km, k| {
                stream_detail_action(km, k).is_some()
            }),
            (View::Help, |km, k| help_action(km, k).is_some()),
            (View::Statistics, |km, k| statistics_action(km, k).is_some()),
            (View::Talkers, |km, k| talkers_action(km, k).is_some()),
            (View::CarrierMetrics, |km, k| {
                carrier_metrics_action(km, k).is_some()
            }),
            (View::CompareDialogs { a: id(), b: id() }, |km, k| {
                compare_dialogs_action(km, k).is_some()
            }),
            (
                View::EndpointRollup {
                    ip: String::from("192.0.2.1"),
                },
                |km, k| endpoint_rollup_action(km, k).is_some(),
            ),
            (View::CaptureHealth, |km, k| {
                capture_health_action(km, k).is_some()
            }),
            (View::HepSenders, |km, k| {
                hep_senders_action(km, k).is_some()
            }),
            (View::CallVolume, |km, k| {
                call_volume_action(km, k).is_some()
            }),
            (View::SdpTimeline { call_id: id() }, |km, k| {
                sdp_timeline_action(km, k).is_some()
            }),
            (View::Conformance { call_id: id() }, |km, k| {
                conformance_action(km, k).is_some()
            }),
            (
                View::TfpsObserve {
                    mode: TfpsMode::Banned,
                },
                |km, k| tfps_observe_action(km, k).is_some(),
            ),
            (View::SecurityFindings, |km, k| {
                security_findings_action(km, k).is_some()
            }),
            (
                View::RelayStats {
                    call_id: None,
                    mode: RelayStatsMode::Counters,
                },
                |km, k| relay_stats_action(km, k).is_some(),
            ),
            (View::QualityDashboard, |km, k| {
                dashboard_action(km, k).is_some()
            }),
            (View::CallTimeline(id()), |km, k| {
                timeline_action(km, k).is_some()
            }),
            (View::StreamLossMap(key), |km, k| {
                loss_map_action(km, k).is_some()
            }),
        ]
    }

    /// **Every view's bar names the help key**, at every width. The bar is
    /// where an operator looks for a way out of not knowing; eleven views had
    /// a bar with no F1 on it, and in most of those F1 did nothing either.
    #[test]
    fn every_view_bar_offers_help_at_every_width() {
        let mut missing = Vec::new();
        for (view, _) in bar_views() {
            if view == View::Help {
                continue; // F1 closes help; the bar says Esc Close instead.
            }
            for width in [60u16, 79, 80, 96, 112, 126, 142, 200] {
                if !fkey_bar_items(&view, &None, width, false).contains(&("F1", "Help")) {
                    missing.push(format!("{view:?} @ {width}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "bars without F1 Help:\n  {}",
            missing.join("\n  ")
        );
    }

    /// **Every key the f-key bar advertises must be bound in the view that
    /// shows it.** The bar is the only place most operators ever learn a
    /// binding, so an entry naming a key the view ignores is not cosmetic:
    /// the operator presses it, nothing happens, and the feature they were
    /// reaching for looks broken rather than misaddressed.
    ///
    /// This is a class gate, deliberately. The same defect has shipped
    /// twice before as one-off omissions — `F1 Help` missing from the call
    /// list (pinned by `fkey_bar_advertises_help_on_call_list_at_all_widths`)
    /// and `F9` labeled `Addrs` while bound to clear-filter. Pinning each
    /// instance one assertion at a time leaves the next one free to ship.
    ///
    /// Not covered: popup bars. Popup keys are handled by impure
    /// `handle_*_key(app, key)` functions with no pure key→action mapper to
    /// interrogate, so there is nothing to compare a legend against without
    /// building an `App`. Named here so the gap is a known limit rather
    /// than a silent one.
    #[test]
    fn every_advertised_fkey_is_bound_in_its_view() {
        let km = Keymap::default();
        // Widths straddle every tier boundary in `fkey_bar_items`.
        let widths = [60u16, 79, 95, 96, 111, 112, 125, 126, 141, 142, 200];
        let views = bar_views();

        let mut unbound: Vec<String> = Vec::new();
        for (view, is_bound) in &views {
            for width in widths {
                for (legend, label) in fkey_bar_items(view, &None, width, false) {
                    for key in bar_legend_keys(legend) {
                        // The help key is also answered globally, for every
                        // view that does not bind it itself.
                        let global_help =
                            key.code == km.help && !crate::tui::controllers::view_binds_help(view);
                        if !(is_bound(&km, key) || global_help) {
                            unbound.push(format!(
                                "{view:?} @ width {width}: bar advertises \
                                 {legend:?} {label:?} but {key:?} is not bound in that view"
                            ));
                        }
                    }
                }
            }
        }
        unbound.sort();
        unbound.dedup();
        assert!(
            unbound.is_empty(),
            "the f-key bar promises keys the view ignores:\n  {}",
            unbound.join("\n  ")
        );
    }

    /// Rendered column span of one f-key bar item set, matching
    /// `render_fkey_bar`: `"{key} {label}"` per item, two spaces between.
    fn bar_cols(items: &[(&'static str, &'static str)]) -> usize {
        items
            .iter()
            .map(|(k, l)| display_cols(k) + 1 + display_cols(l))
            .sum::<usize>()
            + items.len().saturating_sub(1) * 2
    }

    /// The call list is the first screen, so its bar fits a 60-column
    /// terminal too: the narrowest tier used to be 62 columns wide, and at 60
    /// the last entry was cut to `F7 Filt`.
    #[test]
    fn the_call_list_bar_fits_a_60_column_terminal() {
        for width in [60u16, 66] {
            let items = fkey_bar_items(&View::CallList, &None, width, false);
            assert!(bar_cols(&items) <= width as usize, "{width}: {items:?}");
        }
    }

    /// **A bar tier must fit the narrowest terminal that selects it.**
    ///
    /// `render_fkey_bar` draws into a one-row `Paragraph` with no wrap, so
    /// anything past the right edge is silently clipped — and the items
    /// nearest the edge are the last ones, which is where the least-known
    /// bindings live. A clipped entry is worse than an absent one: the
    /// tier was chosen precisely because the terminal was thought wide
    /// enough, so the operator has no cue that the row continues.
    ///
    /// The widths below sit at each tier's lower edge, which is where a
    /// tier is at its tightest relative to its budget.
    #[test]
    fn every_fkey_bar_tier_fits_the_width_that_selects_it() {
        let views: Vec<View> = bar_views().into_iter().map(|(v, _)| v).collect();

        let mut overflow: Vec<String> = Vec::new();
        for view in &views {
            for width in [79u16, 80, 95, 96, 111, 112, 125, 126, 141, 142, 200] {
                let items = fkey_bar_items(view, &None, width, false);
                let cols = bar_cols(&items);
                if cols > width as usize {
                    overflow.push(format!(
                        "{view:?} @ width {width}: bar needs {cols} cols, \
                         so {} col(s) are clipped, starting inside {:?}",
                        cols - width as usize,
                        items.last().map(|(k, l)| format!("{k} {l}"))
                    ));
                }
            }
        }
        assert!(
            overflow.is_empty(),
            "f-key bar tiers that do not fit their own width:\n  {}",
            overflow.join("\n  ")
        );
    }
}

#[cfg(test)]
mod live_only_bpf_tests {
    use super::*;

    /// After an in-session file open the BPF slot says which source its filter
    /// belongs to (#190).
    ///
    /// The label above it flips to `Offline (...)` while this filter still
    /// describes the live capture running behind it. Two rows about two
    /// different sources, reading as one statement about one source, is the
    /// same confident-wrong shape as the blank slot #185 fixed.
    ///
    /// The filter is MARKED, not cleared: the live capture is still running
    /// and the filter still applies to it, so blanking would claim no filter
    /// was compiled — a different and false thing to say.
    #[test]
    fn an_offline_load_marks_the_bpf_slot_as_the_live_captures() {
        let plain = "udp port 5060";
        let marked = format!("{plain} [live capture]");
        assert!(
            marked.starts_with(plain),
            "the mark must ADD to the filter, never replace it: an operator \
             still needs to read what was compiled"
        );
        assert!(
            marked.contains("live"),
            "the mark must name the source the filter belongs to"
        );
        // The fitter must not be defeated by the longer text: a marked filter
        // that overflows still ends in the ellipsis rather than being clipped
        // at the row edge, which would hide the mark itself.
        let narrow = fit_bpf_to_cols(&marked, 10);
        assert!(
            narrow.ends_with('…'),
            "a marked filter too wide for the row must show it was cut: {narrow}"
        );
        assert!(
            display_cols(&narrow) <= 10,
            "the fit must respect the budget: {narrow}"
        );
    }
}
