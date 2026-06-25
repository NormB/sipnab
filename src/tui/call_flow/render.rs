//! Rendering functions for call flow ladder diagrams.
//!
//! Contains both the direct buffer-painting path (used by the TUI) and
//! the Paragraph-based rendering path (used for non-interactive output).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::sip::SipMessage;
use crate::sip::dialog_store::DialogStore;

use crate::tui::ColorMode;
use crate::tui::SdpDisplayMode;
use crate::tui::Theme;
use crate::tui::TimestampMode;

use super::FlowDisplayOptions;
use super::arrows::{format_arrow, format_arrow_left, format_arrow_right, truncate};
use super::prepare::{delta_style, format_message_label, format_sdp_codecs, message_style};
use super::{
    ENDPOINT_COL_WIDTH, FormattedMessage, MIN_ARROW_WIDTH, Participant, SelectionState,
    TS_COL_WIDTH,
};

/// Background applied across the full width of the current (selected) message
/// row — a subtle highlight that marks the cursor without shifting content.
const SELECTION_BG: Color = Color::Rgb(40, 40, 60);

// ── Paragraph-based rendering (legacy path) ────────────────────────

/// Build the formatted lines for a call flow ladder diagram.
///
/// Returns `None` if the dialog is not found or has no messages.
/// Returns `Some((msg_count, lines))` on success, where `msg_count` can be
/// used as a cache invalidation key.
pub fn build_call_flow_lines(
    store: &DialogStore,
    call_id: &str,
    theme: &Theme,
) -> Option<(usize, Vec<Line<'static>>)> {
    build_call_flow_lines_with_width(store, call_id, 120, theme)
}

/// Build call flow lines with a specific terminal width for arrow sizing.
pub fn build_call_flow_lines_with_width(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    theme: &Theme,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }

    let arrow_width = term_width
        .saturating_sub(TS_COL_WIDTH + ENDPOINT_COL_WIDTH * 2 + 15)
        .max(MIN_ARROW_WIDTH);

    let msg_count = dialog.messages.len();
    let first_ts = dialog.messages[0].timestamp;
    let mut lines = format_ladder(
        &dialog.messages,
        first_ts,
        dialog.timing.pdd_ms(),
        arrow_width,
        theme,
    );

    // Show correlated dialogs (multi-leg)
    let correlated = store.find_correlated(call_id);
    if !correlated.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Correlated Legs:",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        for leg in &correlated {
            let label = format!(
                "   {} Call-ID: {} ({})",
                "\u{2194}", // ↔
                truncate(&leg.call_id, 40),
                leg.method,
            );
            lines.push(Line::from(Span::styled(
                label,
                Style::default().fg(theme.accent),
            )));
        }
    }

    Some((msg_count, lines))
}

/// Build call flow lines with display options (SDP mode, timestamp mode, color mode, etc.).
pub fn build_call_flow_lines_with_options(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    opts: &FlowDisplayOptions<'_>,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }
    let tw = TS_COL_WIDTH;
    let aw = term_width
        .saturating_sub(tw + ENDPOINT_COL_WIDTH * 2 + 15)
        .max(MIN_ARROW_WIDTH);
    let mc = dialog.messages.len();
    let ft = dialog.messages[0].timestamp;
    let mut lines =
        format_ladder_with_options(&dialog.messages, ft, dialog.timing.pdd_ms(), aw, opts);
    let correlated = store.find_correlated(call_id);
    if !correlated.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Correlated Legs:",
            Style::default()
                .fg(opts.theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        for leg in &correlated {
            lines.push(Line::from(Span::styled(
                format!(
                    "   \u{2194} Call-ID: {} ({})",
                    truncate(&leg.call_id, 40),
                    leg.method
                ),
                Style::default().fg(opts.theme.accent),
            )));
        }
    }
    Some((mc, lines))
}

/// Build extended (multi-leg) flow lines merging correlated dialogs.
pub fn build_extended_flow_lines(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    opts: &FlowDisplayOptions<'_>,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }
    let mut all: Vec<&SipMessage> = dialog.messages.iter().collect();
    let correlated = store.find_correlated(call_id);
    for leg in &correlated {
        all.extend(leg.messages.iter());
    }
    all.sort_by_key(|m| m.timestamp);
    let owned: Vec<SipMessage> = all.into_iter().cloned().collect();
    if owned.is_empty() {
        return None;
    }
    let tw = TS_COL_WIDTH;
    let aw = term_width
        .saturating_sub(tw + ENDPOINT_COL_WIDTH * 2 + 15)
        .max(MIN_ARROW_WIDTH);
    let mc = owned.len();
    let ft = owned[0].timestamp;
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                " Extended Flow: {} + {} correlated leg(s)",
                truncate(call_id, 40),
                correlated.len()
            ),
            Style::default()
                .fg(opts.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    let ext_opts = FlowDisplayOptions {
        show_rtp: false,
        selected_msg: None,
        ..opts.clone()
    };
    lines.extend(format_ladder_with_options(&owned, ft, None, aw, &ext_opts));
    Some((mc, lines))
}

/// Render the call flow ladder diagram for a dialog identified by Call-ID.
pub fn render_call_flow(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    scroll_offset: usize,
    theme: &Theme,
) {
    let term_width = area.width as usize;
    render_call_flow_lines(frame, area, call_id, scroll_offset, theme, || {
        build_call_flow_lines_with_width(store, call_id, term_width, theme)
    });
}

/// Render call flow from pre-built lines or a builder closure.
pub fn render_call_flow_lines(
    frame: &mut Frame,
    area: Rect,
    _call_id: &str,
    scroll_offset: usize,
    theme: &Theme,
    build: impl FnOnce() -> Option<(usize, Vec<Line<'static>>)>,
) {
    let lines = match build() {
        Some((_count, lines)) => lines,
        None => {
            let para = Paragraph::new("Dialog not found or empty.")
                .style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return;
        }
    };

    let para = Paragraph::new(lines)
        .scroll((scroll_offset as u16, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, area);
}

// ── Direct buffer painting (TUI path) ───────────────────────────────

/// Build an RTP-in-flow channel bar: center `label` within `width` columns and
/// fill both sides with the double rail `═` (U+2550) so a live media stream
/// reads as a continuous channel between the two endpoints — visually distinct
/// from the single-line (`─`) SIP signaling arrows. The double rail looks like
/// an elongated `=`, evoking a sustained two-way pipe rather than a one-shot
/// message.
///
/// `label` is the bare text (e.g. ` RTP · PCMU `); the rails are owned
/// here, not baked into the label, so the bar is always centered regardless of
/// label width. If the label is as wide as or wider than `width` it is truncated
/// to `width` columns (rails dropped) so it never overflows past the right pipe
/// and never falls back to left-alignment. Width is counted in characters, not
/// bytes, so multi-byte glyphs like `·` (U+00B7) don't skew the centering.
pub(crate) fn rtp_channel_bar(label: &str, width: usize) -> String {
    let lw = label.chars().count();
    if lw >= width {
        return label.chars().take(width).collect();
    }
    let pad = width - lw;
    let left = pad / 2;
    let right = pad - left;
    let mut s = String::with_capacity(label.len() + (pad * 3));
    for _ in 0..left {
        s.push('\u{2550}');
    }
    s.push_str(label);
    for _ in 0..right {
        s.push('\u{2550}');
    }
    s
}

/// Navigation state for the call flow direct renderer.
pub struct FlowNavigation {
    pub scroll_offset: usize,
    pub mark_index: Option<usize>,
    pub selected_index: usize,
}

/// Render a call flow ladder diagram by painting directly into the terminal buffer.
///
/// Instead of building `Line`/`Span` objects and rendering via `Paragraph`,
/// this writes characters at exact `(x, y)` coordinates in the buffer,
/// guaranteeing perfect column alignment regardless of character widths.
pub fn render_call_flow_direct(
    frame: &mut Frame,
    area: Rect,
    participants: &[Participant],
    messages: &[FormattedMessage],
    nav: &FlowNavigation,
    theme: &Theme,
) {
    let scroll_offset = nav.scroll_offset;
    let mark_index = nav.mark_index;
    let selected_index = nav.selected_index;
    let buf = frame.buffer_mut();
    let width = area.width;
    let height = area.height;

    if width < 30 || height < 5 {
        buf.set_string(
            area.x,
            area.y,
            "Terminal too small",
            Style::default().fg(theme.muted),
        );
        return;
    }

    let n = participants.len();
    if n == 0 {
        buf.set_string(
            area.x,
            area.y,
            "No participants",
            Style::default().fg(theme.muted),
        );
        return;
    }

    let ts_col = area.x;
    let ts_width = TS_COL_WIDTH as u16;

    // Calculate pipe positions for each participant
    let pipe_positions: Vec<u16> = if n <= 1 {
        vec![area.x + ts_width]
    } else {
        let usable = width.saturating_sub(ts_width + 2);
        (0..n)
            .map(|i| area.x + ts_width + (i as u16 * usable / (n as u16 - 1)))
            .collect()
    };

    // Verify minimum arrow width between adjacent pipes
    if n >= 2 {
        let min_gap = pipe_positions
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]))
            .min()
            .unwrap_or(0);
        if min_gap < 10 {
            buf.set_string(
                area.x,
                area.y,
                "Terminal too narrow for ladder",
                Style::default().fg(theme.muted),
            );
            return;
        }
    }

    let label_style = Style::default()
        .fg(theme.header)
        .add_modifier(Modifier::BOLD);
    let pipe_style = Style::default().fg(theme.muted);

    // Row 0: Labels above each pipe, clamped to area bounds
    let area_right = area.x + area.width;
    for (i, p) in participants.iter().enumerate() {
        let pipe_x = pipe_positions[i];
        // Dynamically size label to fit between adjacent pipes
        let max_lbl = if participants.len() == 1 {
            22
        } else if i == 0 {
            // First: from pipe to midpoint with next pipe
            let next = pipe_positions.get(1).copied().unwrap_or(area_right);
            ((next - pipe_x) as usize).min(22)
        } else if i == participants.len() - 1 {
            // Last: from midpoint with prev pipe to area edge
            let prev = pipe_positions[i - 1];
            ((area_right - prev) as usize / 2).min(22)
        } else {
            // Middle: half the gap to each neighbor
            let prev = pipe_positions[i - 1];
            let next = pipe_positions[i + 1];
            (((next - prev) as usize) / 2).min(22)
        };
        let lbl = truncate(&p.label, max_lbl.max(6));
        let lbl_len = lbl.chars().count() as u16;

        // Position: first label left-aligned, last right-aligned, middle centered
        let lbl_x = if i == 0 {
            pipe_x
        } else if i == participants.len() - 1 {
            (pipe_x + 1).saturating_sub(lbl_len)
        } else {
            pipe_x.saturating_sub(lbl_len / 2)
        };
        // Clamp to area bounds
        let lbl_x = lbl_x.max(area.x).min(area_right.saturating_sub(lbl_len));
        buf.set_string(lbl_x, area.y, &lbl, label_style);
    }

    // Row 1: Pipes
    for &px in &pipe_positions {
        buf.set_string(px, area.y + 1, "\u{2502}", pipe_style); // │
    }

    // Mark + Delta badge (Feature 1): render in the top-right corner
    if let Some(mi) = mark_index
        && mi != selected_index
        && mi < messages.len()
        && selected_index < messages.len()
    {
        let mark_ts = messages[mi].raw_timestamp;
        let sel_ts = messages[selected_index].raw_timestamp;
        let delta_ms = sel_ts.signed_duration_since(mark_ts).num_milliseconds();
        let badge = if delta_ms.abs() >= 1000 {
            format!("\u{0394} {:+.3}s", delta_ms as f64 / 1000.0)
        } else {
            format!("\u{0394} {:+}ms", delta_ms)
        };
        let badge_len = badge.len() as u16;
        let badge_x = (area.x + width).saturating_sub(badge_len + 1);
        let badge_style = Style::default()
            .fg(theme.accent)
            .bg(Color::Rgb(40, 35, 20))
            .add_modifier(Modifier::BOLD);
        // Render on row 1 (pipe row) at the far right — avoids overlapping endpoint labels
        buf.set_string(badge_x, area.y + 1, &badge, badge_style);
    }

    // Message rows: we expand each FormattedMessage into 1 + extra_lines rows
    // Scrollable area starts at row 2, ends 2 rows before bottom (footer pipe + labels)
    let mut row: usize = 2;
    let mut logical_row: usize = 0;
    let max_row = (height as usize).saturating_sub(2); // leave room for footer

    for msg in messages {
        let msg_rows = 1 + msg.extra_lines.len();

        // Skip if entirely before the scroll window
        if logical_row + msg_rows <= scroll_offset {
            logical_row += msg_rows;
            continue;
        }

        // Render the main arrow row (may be partially scrolled)
        if logical_row >= scroll_offset && row < max_row {
            let y = area.y + row as u16;

            // Spacer rows: only render pipes and optional gap timestamp
            if msg.is_spacer {
                let spacer_style = Style::default().fg(theme.muted).add_modifier(Modifier::DIM);
                // Timestamp (gap label on first spacer, blank otherwise)
                if !msg.timestamp.trim().is_empty() {
                    buf.set_string(ts_col, y, &msg.timestamp, spacer_style);
                }
                // Dotted pipes at all column positions
                for &px in &pipe_positions {
                    buf.set_string(px, y, "\u{250A}", spacer_style); // ┊
                }
                row += 1;
                logical_row += msg_rows;
                if row >= max_row {
                    break;
                }
                continue;
            }

            // Timestamp column. The current row is shown by a full-row
            // background highlight applied after all content is drawn (see
            // below) — never a leading marker glyph, which would shift the
            // whole row's content right by one column as the cursor moves.
            match msg.selection_state {
                SelectionState::Selected => {
                    if !msg.timestamp.is_empty() {
                        buf.set_string(ts_col, y, &msg.timestamp, msg.timestamp_style);
                    }
                }
                SelectionState::Normal => {
                    if !msg.timestamp.is_empty() {
                        let dim_ts = msg.timestamp_style.add_modifier(Modifier::DIM);
                        buf.set_string(ts_col, y, &msg.timestamp, dim_ts);
                    }
                }
                SelectionState::Related => {
                    if !msg.timestamp.is_empty() {
                        buf.set_string(ts_col, y, &msg.timestamp, msg.timestamp_style);
                    }
                }
            }

            // Pipes at ALL positions
            for &px in &pipe_positions {
                buf.set_string(px, y, "\u{2502}", pipe_style); // │
            }

            // Clamp src_col and dst_col to valid range
            let src_col = msg.src_col.min(n.saturating_sub(1));
            let dst_col = msg.dst_col.min(n.saturating_sub(1));

            // RTP bar: render as a full-width label between the pipes
            if msg.is_rtp_bar {
                let left_pipe = pipe_positions.first().copied().unwrap_or(ts_width);
                let right_pipe = pipe_positions.last().copied().unwrap_or(area.right());
                let bar_x = left_pipe + 1;
                let bar_width = right_pipe.saturating_sub(left_pipe).saturating_sub(1) as usize;
                let padded = rtp_channel_bar(&msg.label, bar_width);
                let bar_style = match msg.selection_state {
                    SelectionState::Selected => {
                        msg.style.bg(SELECTION_BG).add_modifier(Modifier::BOLD)
                    }
                    _ => msg.style,
                };
                buf.set_string(bar_x, y, &padded, bar_style);
            } else {
                // Arrow between source and destination pipes
                let src_x = pipe_positions[src_col];
                let dst_x = pipe_positions[dst_col];
                if src_x != dst_x {
                    let (arrow_str, arrow_x) =
                        format_arrow(&msg.label, src_x, dst_x, msg.is_response);
                    let arrow_style = match msg.selection_state {
                        SelectionState::Selected => {
                            msg.style.bg(SELECTION_BG).add_modifier(Modifier::BOLD)
                        }
                        SelectionState::Related => msg.style,
                        SelectionState::Normal => msg.style.add_modifier(Modifier::DIM),
                    };
                    buf.set_string(arrow_x, y, &arrow_str, arrow_style);
                }
            }

            // PDD annotation after the rightmost pipe
            let mut annotation_x = {
                let rightmost = pipe_positions.last().copied().unwrap_or(0);
                rightmost + 1
            };
            if let Some(ref pdd) = msg.pdd_note {
                buf.set_string(annotation_x, y, pdd, Style::default().fg(theme.accent));
                annotation_x += pdd.len() as u16 + 1;
            }

            // SDP delta badge (Feature 4)
            if let Some(ref badge) = msg.sdp_badge {
                let badge_str = format!(" [{badge}]");
                let badge_style = Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD);
                buf.set_string(annotation_x, y, &badge_str, badge_style);
                annotation_x += badge_str.len() as u16;
            }

            // Fold label (Feature 3)
            if let Some(ref fl) = msg.fold_label {
                let fold_str = format!(" {fl}");
                let fold_style = Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC);
                buf.set_string(annotation_x, y, &fold_str, fold_style);
            }

            // Full-row highlight for the current message: patch a background
            // across the whole row (content keeps its own fg). This marks the
            // cursor without shifting any content horizontally.
            if msg.selection_state == SelectionState::Selected {
                buf.set_style(
                    Rect::new(area.x, y, area.width, 1),
                    Style::default().bg(SELECTION_BG),
                );
            }

            row += 1;
        } else if logical_row < scroll_offset {
            // This main row is scrolled off; advance logical but not visual
        }

        // Render extra lines (SDP, RTP markers)
        for (ei, (text, style)) in msg.extra_lines.iter().enumerate() {
            let extra_logical = logical_row + 1 + ei;
            if extra_logical >= scroll_offset && row < max_row {
                let y = area.y + row as u16;
                buf.set_string(area.x, y, text, *style);
                row += 1;
            }
        }

        logical_row += msg_rows;

        if row >= max_row {
            break;
        }
    }

    // Pinned footer: pipe line + abbreviated labels at bottom rows
    let footer_pipe_y = area.y + height.saturating_sub(2);
    let footer_label_y = area.y + height.saturating_sub(1);
    if height >= 4 {
        for &px in &pipe_positions {
            buf.set_string(px, footer_pipe_y, "\u{2502}", pipe_style); // │
        }

        // Footer labels
        for (i, p) in participants.iter().enumerate() {
            let pipe_x = pipe_positions[i];
            let lbl = truncate(&p.label, 20);
            let lbl_len = lbl.len() as u16;

            if i == 0 {
                // First label: left-aligned at the pipe position
                buf.set_string(pipe_x, footer_label_y, &lbl, label_style);
            } else {
                // Other labels: right-aligned so they end at the pipe position
                let lbl_x = (pipe_x + 1).saturating_sub(lbl_len);
                buf.set_string(lbl_x, footer_label_y, &lbl, label_style);
            }
        }
    }
}

/// Render call flow with a fallback "not found" message using direct buffer painting.
///
/// This is the TUI entry point that replaces the Paragraph-based `render_call_flow_lines`.
pub fn render_call_flow_direct_or_empty(
    frame: &mut Frame,
    area: Rect,
    prepared: Option<&(Vec<Participant>, Vec<FormattedMessage>)>,
    nav: &FlowNavigation,
    theme: &Theme,
) {
    match prepared {
        Some((participants, msgs)) => {
            render_call_flow_direct(frame, area, participants, msgs, nav, theme);
        }
        None => {
            let buf = frame.buffer_mut();
            buf.set_string(
                area.x,
                area.y,
                "Dialog not found or empty.",
                Style::default().fg(theme.muted),
            );
        }
    }
}

/// Render the message detail panel (right side of the split view).
///
/// `focused` highlights the border when the detail pane holds keyboard focus
/// (Tab toggles it). Returns the number of content lines so the caller can
/// clamp the scroll offset to the message length.
#[allow(clippy::too_many_arguments)]
pub fn render_message_detail(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    selected_msg: usize,
    scroll_offset: u16,
    focused: bool,
    theme: &Theme,
) -> usize {
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.").style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return 0;
        }
    };

    let msg = match dialog.messages.get(selected_msg) {
        Some(m) => m,
        None => {
            let para =
                Paragraph::new("No message selected.").style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return 0;
        }
    };

    let title = format!(
        " [{}/{}] {} ",
        selected_msg + 1,
        dialog.messages.len(),
        if msg.is_request {
            msg.method
                .as_ref()
                .map(|m| m.as_str())
                .unwrap_or("?")
                .to_string()
        } else {
            format!(
                "{} {}",
                msg.status_code.unwrap_or(0),
                msg.reason.as_deref().unwrap_or("")
            )
        },
    );

    // A focused pane gets a bright, bold border so the user can see which side
    // the arrow keys are driving.
    let border_style = if focused {
        Style::default()
            .fg(theme.selected)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.border)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(border_style);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let raw_text = String::from_utf8_lossy(&msg.raw);
    let lines = highlight_sip_detail(&raw_text, theme);
    let total_lines = lines.len();

    // Clamp the display scroll so the End key (which sets a large value) and
    // any stale offset never scroll the content entirely out of view.
    let viewport = inner.height as usize;
    let max_scroll = total_lines.saturating_sub(viewport);
    let eff_scroll = (scroll_offset as usize).min(max_scroll) as u16;

    let para = Paragraph::new(lines)
        .scroll((eff_scroll, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, inner);

    // Vertical scrollbar on the right border when the message overflows.
    if total_lines > viewport {
        let mut sb_state = ScrollbarState::new(total_lines)
            .viewport_content_length(viewport)
            .position(eff_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(theme.selected))
            .track_style(Style::default().fg(theme.muted));
        frame.render_stateful_widget(scrollbar, area, &mut sb_state);
    }

    total_lines
}

/// Total logical rows the ladder occupies. Each message paints `1 + extra_lines`
/// rows; this matches the row accounting in [`render_call_flow_direct`] and so
/// is the correct content length for the ladder scrollbar.
pub fn ladder_total_rows(messages: &[FormattedMessage]) -> usize {
    messages.iter().map(|m| 1 + m.extra_lines.len()).sum()
}

/// Number of ladder rows visible at once for a given pane height. The ladder
/// reserves two rows at the top (participant labels + pipes) and two at the
/// bottom (footer), so the scrollable window is `height - 4`.
pub fn ladder_visible_rows(height: u16) -> usize {
    (height as usize).saturating_sub(4)
}

/// Render a vertical scrollbar on the right edge of the ladder pane when the
/// flow is taller than the pane. No-op when everything already fits.
pub fn render_ladder_scrollbar(
    frame: &mut Frame,
    area: Rect,
    total_rows: usize,
    position: usize,
    theme: &Theme,
) {
    let visible = ladder_visible_rows(area.height);
    if total_rows <= visible || area.height < 5 {
        return;
    }
    let mut sb_state = ScrollbarState::new(total_rows)
        .viewport_content_length(visible)
        .position(position);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .thumb_style(Style::default().fg(theme.selected))
        .track_style(Style::default().fg(theme.muted));
    frame.render_stateful_widget(scrollbar, area, &mut sb_state);
}

/// Highlight a raw SIP message for the detail panel.
fn highlight_sip_detail(raw_text: &str, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut in_body = false;
    let mut is_first = true;

    for raw_line in raw_text.lines() {
        if !in_body && raw_line.trim().is_empty() {
            in_body = true;
            lines.push(Line::from(""));
            continue;
        }

        if in_body {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC),
            )));
        } else if is_first {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default()
                    .fg(theme.foreground)
                    .add_modifier(Modifier::BOLD),
            )));
            is_first = false;
        } else if let Some(colon_pos) = raw_line.find(':') {
            let name = &raw_line[..colon_pos];
            let value = &raw_line[colon_pos..];
            lines.push(Line::from(vec![
                Span::styled(name.to_string(), Style::default().fg(theme.header)),
                Span::styled(value.to_string(), Style::default().fg(theme.foreground)),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default().fg(theme.foreground),
            )));
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "(empty message)",
            Style::default().fg(theme.muted),
        )));
    }

    lines
}

// ── Ladder formatting (Paragraph path) ─────────────────────────────

/// Format all messages in a dialog as ladder diagram lines.
pub fn format_ladder(
    messages: &[SipMessage],
    _first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    arrow_width: usize,
    theme: &Theme,
) -> Vec<Line<'static>> {
    if messages.is_empty() {
        return vec![Line::from("(no messages)")];
    }

    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    let left_pipe_col = TS_COL_WIDTH;
    let right_pipe_col = left_pipe_col + 1 + arrow_width;

    let mut lines: Vec<Line<'static>> = Vec::new();

    let left_label = truncate(&left_addr, 25);
    let right_label = truncate(&right_addr, 25);

    let mut header = String::new();
    header.push_str(&format!(
        "{:>width$}",
        left_label,
        width = left_pipe_col + left_label.len() / 2
    ));
    let gap = right_pipe_col.saturating_sub(header.len() + right_label.len() / 2);
    header.push_str(&" ".repeat(gap));
    header.push_str(&right_label);

    lines.push(Line::from(Span::styled(
        header,
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));

    let pipe_line = |prefix: &str| -> String {
        let mut s = String::new();
        s.push_str(prefix);
        let mut col = prefix.chars().count();
        while col < left_pipe_col {
            s.push(' ');
            col += 1;
        }
        s.push('\u{2502}');
        col += 1;
        while col < right_pipe_col {
            s.push(' ');
            col += 1;
        }
        s.push('\u{2502}');
        s
    };

    lines.push(Line::from(pipe_line(&" ".repeat(TS_COL_WIDTH))));

    let mut pdd_annotated = false;

    for msg in messages {
        let ts_str = msg.timestamp.format("%H:%M:%S%.3f").to_string();
        let label = format_message_label(msg);
        let msg_style = message_style(msg, theme);

        let this_src = format!("{}:{}", msg.src_addr, msg.src_port);
        let is_left_to_right = this_src == left_addr;

        let ts_part = format!("{:<width$}", ts_str, width = TS_COL_WIDTH);

        let is_response = !msg.is_request;
        let arrow_span = arrow_width.saturating_sub(1);
        let arrow_line = if is_left_to_right {
            format_arrow_right(&label, arrow_span, is_response)
        } else {
            format_arrow_left(&label, arrow_span, is_response)
        };

        let mut pdd_note = String::new();
        if !pdd_annotated
            && let Some(pdd) = pdd_ms
            && !msg.is_request
            && msg.status_code == Some(180)
        {
            pdd_note = format!("  PDD: {}ms", pdd);
            pdd_annotated = true;
        }

        lines.push(Line::from(vec![
            Span::styled(ts_part, Style::default().fg(theme.muted)),
            Span::styled("\u{2502}", Style::default().fg(theme.muted)),
            Span::styled(arrow_line, msg_style),
            Span::styled("\u{2502}", Style::default().fg(theme.muted)),
            Span::styled(pdd_note, Style::default().fg(theme.accent)),
        ]));
    }

    lines.push(Line::from(pipe_line(&" ".repeat(TS_COL_WIDTH))));

    lines
}

/// Format ladder with full display options (SDP mode, timestamp mode, color, etc.).
fn format_ladder_with_options(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    arrow_width: usize,
    opts: &FlowDisplayOptions<'_>,
) -> Vec<Line<'static>> {
    let sdp_mode = opts.sdp_mode;
    let ts_mode = opts.ts_mode;
    let color_mode = opts.color_mode;
    let show_rtp = opts.show_rtp;
    let selected_msg = opts.selected_msg;
    let theme = opts.theme;
    if messages.is_empty() {
        return vec![Line::from("(no messages)")];
    }

    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    let ts_width = TS_COL_WIDTH;
    let left_pipe_col = ts_width;
    let right_pipe_col = left_pipe_col + 1 + arrow_width;

    let mut lines: Vec<Line<'static>> = Vec::new();
    let left_label = truncate(&left_addr, 25);
    let right_label = truncate(&right_addr, 25);

    let mut hdr = String::new();
    hdr.push_str(&format!(
        "{:>width$}",
        left_label,
        width = left_pipe_col + left_label.len() / 2
    ));
    let g = right_pipe_col.saturating_sub(hdr.len() + right_label.len() / 2);
    hdr.push_str(&" ".repeat(g));
    hdr.push_str(&right_label);
    lines.push(Line::from(Span::styled(
        hdr,
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));

    let ts_prefix = " ".repeat(ts_width);
    let mk_pipe = |pfx: &str| -> String {
        let mut s = String::new();
        s.push_str(pfx);
        let mut col = pfx.chars().count();
        while col < left_pipe_col {
            s.push(' ');
            col += 1;
        }
        s.push('\u{2502}');
        col += 1;
        while col < right_pipe_col {
            s.push(' ');
            col += 1;
        }
        s.push('\u{2502}');
        s
    };
    lines.push(Line::from(mk_pipe(&ts_prefix)));

    let mut pdd_done = false;
    let mut in_call = false;
    let mut prev_ts = first_ts;
    let cid_colors = [
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Red,
    ];

    for (mi, msg) in messages.iter().enumerate() {
        let (ts_str, ts_style) = match ts_mode {
            TimestampMode::Absolute => {
                let s = format!(
                    "{:<width$}",
                    msg.timestamp.format("%H:%M:%S%.3f"),
                    width = ts_width
                );
                (s, Style::default().fg(theme.muted))
            }
            TimestampMode::DeltaPrev => {
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let s = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                prev_ts = msg.timestamp;
                (s, sty)
            }
            TimestampMode::DeltaFirst => {
                let d = msg
                    .timestamp
                    .signed_duration_since(first_ts)
                    .num_milliseconds();
                let s = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                (s, sty)
            }
            TimestampMode::Scaled => {
                // Scaled mode uses delta-prev formatting in the legacy path
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let s = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                prev_ts = msg.timestamp;
                (s, sty)
            }
        };
        let label = format_message_label(msg);
        let sty = match color_mode {
            ColorMode::Method => message_style(msg, theme),
            ColorMode::CallId => {
                let ci = msg.call_id().unwrap_or("");
                let i =
                    ci.bytes().fold(0usize, |a, b| a.wrapping_add(b as usize)) % cid_colors.len();
                Style::default().fg(cid_colors[i])
            }
            ColorMode::CSeq => {
                let cn = msg.cseq().map(|(n, _)| n).unwrap_or(0);
                Style::default().fg(cid_colors[(cn as usize) % cid_colors.len()])
            }
        };
        let sel = selected_msg == Some(mi);
        let fsty = sty;

        let src = format!("{}:{}", msg.src_addr, msg.src_port);
        let ltr = src == left_addr;
        let is_response = !msg.is_request;
        let as_ = arrow_width.saturating_sub(1);
        let al = if ltr {
            format_arrow_right(&label, as_, is_response)
        } else {
            format_arrow_left(&label, as_, is_response)
        };

        let mut pn = String::new();
        if !pdd_done
            && let Some(p) = pdd_ms
            && !msg.is_request
            && msg.status_code == Some(180)
        {
            pn = format!("  PDD: {p}ms");
            pdd_done = true;
        }

        let mut sp = Vec::new();
        if !ts_str.is_empty() {
            sp.push(Span::styled(ts_str, ts_style));
        }
        sp.push(Span::styled("\u{2502}", Style::default().fg(theme.muted)));
        sp.push(Span::styled(al, fsty));
        sp.push(Span::styled("\u{2502}", Style::default().fg(theme.muted)));
        if !pn.is_empty() {
            sp.push(Span::styled(pn, Style::default().fg(theme.accent)));
        }
        if sel {
            sp.push(Span::styled(
                "  [SELECTED]",
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        lines.push(Line::from(sp));

        if sdp_mode != SdpDisplayMode::None
            && let Some(ss) = msg.sdp()
        {
            let ind = " ".repeat(ts_width + 1);
            match sdp_mode {
                SdpDisplayMode::Summary => {
                    let c = format_sdp_codecs(&ss);
                    if !c.is_empty() {
                        lines.push(Line::from(Span::styled(
                            format!("{ind} Codecs: {c}"),
                            Style::default()
                                .fg(theme.muted)
                                .add_modifier(Modifier::ITALIC),
                        )));
                    }
                }
                SdpDisplayMode::Full => {
                    let bt = String::from_utf8_lossy(&msg.body);
                    for sl in bt.lines() {
                        lines.push(Line::from(Span::styled(
                            format!("{ind}  {sl}"),
                            Style::default()
                                .fg(theme.muted)
                                .add_modifier(Modifier::ITALIC),
                        )));
                    }
                }
                SdpDisplayMode::None => {}
            }
        }

        if show_rtp {
            if !msg.is_request && msg.status_code == Some(200) {
                in_call = true;
            }
            if msg.is_request && msg.method.as_ref() == Some(&crate::sip::SipMethod::Bye) && in_call
            {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{}\u{2500}\u{2500}\u{2500}\u{2500} RTP stream active \u{2500}\u{2500}\u{2500}\u{2500}",
                        " ".repeat(ts_width + 1)
                    ),
                    Style::default().fg(theme.muted),
                )));
                in_call = false;
            }
        }
    }

    lines.push(Line::from(mk_pipe(&ts_prefix)));
    lines
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;

    // ── rtp_channel_bar: double-rail centered media channel ───────────

    const RAIL: char = '\u{2550}'; // ═

    #[test]
    fn rtp_bar_centers_with_double_rail() {
        let bar = rtp_channel_bar(" RTP \u{00B7} PCMU ", 40);
        // Exactly `width` display columns, rails on both ends, label intact.
        assert_eq!(bar.chars().count(), 40);
        assert_eq!(bar.chars().next(), Some(RAIL), "left rail missing");
        assert_eq!(bar.chars().last(), Some(RAIL), "right rail missing");
        assert!(bar.contains("RTP \u{00B7} PCMU"), "label lost");
        // Centered: left/right rail runs differ by at most one (odd padding).
        let left = bar.chars().take_while(|&c| c == RAIL).count();
        let right = bar.chars().rev().take_while(|&c| c == RAIL).count();
        assert!(
            left.abs_diff(right) <= 1,
            "not centered: {left} left vs {right} right rails"
        );
        // The rail must NOT be the single-line `─` used by SIP arrows.
        assert!(
            !bar.contains('\u{2500}'),
            "used single line, not double rail"
        );
    }

    #[test]
    fn rtp_bar_truncates_instead_of_overflowing() {
        // Label wider than the gap → truncated to width, never left-aligned
        // overflow past the pipe. (This was the original bug.)
        let bar = rtp_channel_bar(" RTP \u{00B7} PCMA, PCMU, G722, opus \u{00B7} active ", 8);
        assert_eq!(bar.chars().count(), 8, "must clamp to width");
    }

    #[test]
    fn rtp_bar_exact_width_is_label_only() {
        let label = "RTP active"; // 10 chars
        let bar = rtp_channel_bar(label, 10);
        assert_eq!(bar, label, "exact fit should not add rails");
    }

    #[test]
    fn rtp_bar_adversarial_inputs() {
        // Empty label → pure rail.
        let b = rtp_channel_bar("", 6);
        assert_eq!(b, "\u{2550}".repeat(6));
        // Zero width → empty, no panic.
        assert_eq!(rtp_channel_bar(" RTP ", 0), "");
        // Backslash / special chars in the label survive intact.
        let b = rtp_channel_bar(r" a\b\c ", 20);
        assert!(b.contains(r"a\b\c"), "backslashes mangled: {b}");
        assert_eq!(b.chars().count(), 20);
        // Embedded NUL is carried through without truncating the string.
        let b = rtp_channel_bar(" a\0b ", 10);
        assert!(b.contains('\0'), "NUL dropped");
        assert_eq!(b.chars().count(), 10);
        // Width 1, multi-char label → single truncated char, no panic.
        assert_eq!(rtp_channel_bar("xyz", 1).chars().count(), 1);
    }

    #[test]
    fn format_ladder_empty_messages() {
        let theme = crate::tui::Theme::default();
        let lines = format_ladder(&[], chrono::Utc::now(), None, 40, &theme);
        assert_eq!(lines.len(), 1);
    }

    // ── Arrow DIRECTION: requests and responses point opposite ways ────
    // A request travels A→B (arrowhead ▶ on the right); its response travels
    // B→A (arrowhead ◀ on the left). Regression guard for the gap where the
    // ladder direction was never asserted end to end — only the request/response
    // *src↔dst* swap makes the arrow flip, so this exercises real A→B / B→A
    // messages, not the glyph helper in isolation.
    #[test]
    fn ladder_request_points_right_response_points_left() {
        let theme = crate::tui::Theme::default();
        // req() is A→B, resp() is B→A (src/dst swapped), as on a real wire.
        let msgs = vec![
            req("INVITE", "1 INVITE", "dir-call", base_ts()),
            resp(200, "OK", "1 INVITE", "dir-call", base_ts()),
        ];
        let lines = format_ladder(&msgs, base_ts(), None, 48, &theme);
        let text: Vec<String> = lines.iter().map(line_to_string).collect();
        let invite = text
            .iter()
            .find(|l| l.contains("INVITE"))
            .expect("INVITE row");
        let ok = text.iter().find(|l| l.contains("200")).expect("200 OK row");

        // Request: rightward only.
        assert!(
            invite.contains('\u{25B6}') && !invite.contains('\u{25C0}'),
            "request must point right (▶), got: {invite:?}"
        );
        // Response: leftward only — the bug the perf.pcap capture *looked* like
        // (it was actually one-directional synthetic data; here the response is
        // genuinely B→A and must reverse).
        assert!(
            ok.contains('\u{25C0}') && !ok.contains('\u{25B6}'),
            "response must point left (◀), got: {ok:?}"
        );
    }

    // Faithful rendering: when a (malformed/synthetic) response carries the SAME
    // src→dst as the request — e.g. a one-directional load corpus — the arrow
    // follows the actual packet addresses (forward), it is NOT force-flipped by
    // status code. This documents that arrow direction is wire-driven.
    #[test]
    fn ladder_arrow_follows_actual_src_dst_not_status() {
        let theme = crate::tui::Theme::default();
        // Build a 200 OK that (wrongly) travels A→B, like perf.pcap's responses.
        let raw = build_raw(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfwd",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>;tag=t2",
                "Call-ID: fwd-call",
                "CSeq: 1 INVITE",
            ],
            "",
        );
        let fwd_resp = crate::sip::parser::parse_sip(
            &raw,
            base_ts(),
            ip_a(),
            ip_b(), // A→B, NOT swapped
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        let msgs = vec![req("INVITE", "1 INVITE", "fwd-call", base_ts()), fwd_resp];
        let lines = format_ladder(&msgs, base_ts(), None, 48, &theme);
        let text: Vec<String> = lines.iter().map(line_to_string).collect();
        let ok = text.iter().find(|l| l.contains("200")).expect("200 OK row");
        // Same src→dst as the request ⇒ same (rightward) direction. Faithful to
        // the wire, not flipped by the 2xx status.
        assert!(
            ok.contains('\u{25B6}') && !ok.contains('\u{25C0}'),
            "a response that travels A→B on the wire must render forward, got: {ok:?}"
        );
    }

    #[test]
    fn format_ladder_produces_lines() {
        use crate::sip::parser::parse_sip;
        use std::net::{IpAddr, Ipv4Addr};

        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                     From: <sip:alice@example.com>;tag=t1\r\n\
                     To: <sip:bob@example.com>\r\n\
                     Call-ID: ladder-test@example.com\r\n\
                     CSeq: 1 INVITE\r\n\
                     Content-Length: 0\r\n\r\n";

        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 1, 1, 0, 0, 0).unwrap();
        let msg = parse_sip(
            raw,
            ts,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse ok");

        let theme = crate::tui::Theme::default();
        let lines = format_ladder(&[msg], ts, None, 50, &theme);
        // Should have header + bar + message + closing bar
        assert!(lines.len() >= 4);
    }

    // ── Shared helpers for the builder/render coverage tests ───────────

    use crate::sip::dialog_store::DialogStore;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    fn ip_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_raw(first_line: &str, headers: &[&str], body: &str) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(first_line);
        s.push_str("\r\n");
        for h in headers {
            s.push_str(h);
            s.push_str("\r\n");
        }
        s.push_str(&format!("Content-Length: {}\r\n", body.len()));
        s.push_str("\r\n");
        s.push_str(body);
        s.into_bytes()
    }

    /// A->B request message.
    fn req(method: &str, cseq: &str, call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_raw(
            &format!("{method} sip:bob@10.0.0.2 SIP/2.0"),
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKreq",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
            ],
            "",
        );
        parse_sip(&raw, ts, ip_a(), ip_b(), 5060, 5060, TransportProto::Udp).expect("parse request")
    }

    /// B->A response message.
    fn resp(status: u16, reason: &str, cseq: &str, call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_raw(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKreq",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
            ],
            "",
        );
        parse_sip(&raw, ts, ip_b(), ip_a(), 5060, 5060, TransportProto::Udp)
            .expect("parse response")
    }

    /// INVITE A->B carrying an SDP offer.
    fn invite_with_sdp(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let sdp = "v=0\r\n\
                   o=- 1 1 IN IP4 10.0.0.1\r\n\
                   s=-\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 20000 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";
        let raw = build_raw(
            "INVITE sip:bob@10.0.0.2 SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsdp",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
            ],
            sdp,
        );
        parse_sip(&raw, ts, ip_a(), ip_b(), 5060, 5060, TransportProto::Udp)
            .expect("parse INVITE+SDP")
    }

    fn opts<'a>(theme: &'a Theme) -> FlowDisplayOptions<'a> {
        let resolver: &'static crate::names::NameResolver =
            Box::leak(Box::new(crate::names::NameResolver::new()));
        FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::None,
            ts_mode: TimestampMode::Absolute,
            color_mode: ColorMode::Method,
            show_rtp: false,
            selected_msg: None,
            theme,
            resolver,
            name_mode: crate::names::NameMode::Off,
            rtp_segments: &[],
        }
    }

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn lines_to_string(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Store with a complete INVITE/180/200/ACK/BYE/200 dialog.
    fn store_full_dialog(call_id: &str) -> DialogStore {
        let t = base_ts();
        let mut store = DialogStore::new(100, false);
        store.process_message(req("INVITE", "1 INVITE", call_id, t));
        store.process_message(resp(
            180,
            "Ringing",
            "1 INVITE",
            call_id,
            t + TimeDelta::seconds(1),
        ));
        store.process_message(resp(
            200,
            "OK",
            "1 INVITE",
            call_id,
            t + TimeDelta::seconds(2),
        ));
        store.process_message(req(
            "ACK",
            "1 ACK",
            call_id,
            t + TimeDelta::milliseconds(2100),
        ));
        store.process_message(req("BYE", "2 BYE", call_id, t + TimeDelta::seconds(30)));
        store.process_message(resp(
            200,
            "OK",
            "2 BYE",
            call_id,
            t + TimeDelta::seconds(30),
        ));
        store
    }

    fn terminal(w: u16, h: u16) -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(w, h)).unwrap()
    }

    fn buffer_text(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
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

    // ── direct-path selection highlight (R2: no shifting marker) ────────

    fn fmt_msg(
        ts: &str,
        state: SelectionState,
        src_col: usize,
        dst_col: usize,
    ) -> FormattedMessage {
        FormattedMessage {
            timestamp: ts.to_string(),
            timestamp_style: Style::default(),
            label: "INVITE".to_string(),
            style: Style::default(),
            src_col,
            dst_col,
            pdd_note: None,
            extra_lines: Vec::new(),
            selected: matches!(state, SelectionState::Selected),
            call_id: "c@test".to_string(),
            selection_state: state,
            is_response: false,
            raw_timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            folded_count: 0,
            fold_label: None,
            is_spacer: false,
            sdp_badge: None,
            is_retransmission: false,
            is_rtp_bar: false,
        }
    }

    // The current row is marked by a full-width background highlight, never a
    // leading glyph: no '▎'/'>' anywhere, and content is NOT shifted right —
    // the selected row's timestamp still begins in column 0 (SNB UX fix R2).
    #[test]
    fn direct_render_selection_highlights_row_without_shifting() {
        let theme = Theme::default();
        let parts = vec![
            Participant {
                addr: "10.0.0.1:5060".into(),
                label: "10.0.0.1:5060".into(),
            },
            Participant {
                addr: "10.0.0.2:5060".into(),
                label: "10.0.0.2:5060".into(),
            },
        ];
        let msgs = vec![
            fmt_msg("12:00:00.000", SelectionState::Selected, 0, 1),
            fmt_msg("12:00:00.100", SelectionState::Normal, 1, 0),
        ];
        let nav = FlowNavigation {
            scroll_offset: 0,
            mark_index: None,
            selected_index: 0,
        };
        let mut term = terminal(80, 24);
        term.draw(|f| {
            let a = f.area();
            render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();

        // No leading marker glyph survived anywhere.
        assert!(
            !buffer_text(&term).contains('\u{258E}'),
            "marker '▎' must be gone"
        );

        // Exactly one row carries the selection background, and on that row the
        // selected timestamp starts at column 0 (not shifted to column 1).
        let mut highlit_rows = Vec::new();
        for y in 0..buf.area.height {
            if buf.cell((0, y)).unwrap().style().bg == Some(SELECTION_BG) {
                highlit_rows.push(y);
            }
        }
        assert_eq!(
            highlit_rows.len(),
            1,
            "exactly one highlighted (selected) row"
        );
        let y = highlit_rows[0];
        let row: String = (0..buf.area.width)
            .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
            .collect();
        assert!(
            row.starts_with("12:00:00.000"),
            "ts at col 0, unshifted: {row:?}"
        );
    }

    // ── build_call_flow_lines / _with_width ────────────────────────────

    #[test]
    fn build_lines_full_dialog_has_methods_and_status() {
        let theme = Theme::default();
        let store = store_full_dialog("full@test");
        let (count, lines) = build_call_flow_lines(&store, "full@test", &theme).expect("some");
        let stored = store.get("full@test").unwrap().messages.len();
        assert_eq!(count, stored);
        // header + top bar + N messages + bottom bar
        assert_eq!(lines.len(), stored + 3);
        let text = lines_to_string(&lines);
        for needle in ["10.0.0.1:5060", "INVITE", "180", "200", "ACK", "BYE"] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
    }

    #[test]
    fn build_lines_missing_dialog_returns_none() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        assert!(build_call_flow_lines(&store, "nope@test", &theme).is_none());
    }

    #[test]
    fn build_lines_pdd_annotation_on_180() {
        let theme = Theme::default();
        let store = store_full_dialog("pdd@test");
        // 120-wide default => PDD annotated against the 180 Ringing.
        let (_c, lines) = build_call_flow_lines(&store, "pdd@test", &theme).expect("some");
        let text = lines_to_string(&lines);
        assert!(text.contains("PDD:"), "expected PDD annotation in:\n{text}");
    }

    #[test]
    fn build_lines_narrow_width_clamps_arrow() {
        let theme = Theme::default();
        let store = store_full_dialog("narrow@test");
        // width 20 forces saturating_sub to 0 -> MIN_ARROW_WIDTH path.
        let narrow = build_call_flow_lines_with_width(&store, "narrow@test", 20, &theme)
            .expect("some")
            .1;
        let wide = build_call_flow_lines_with_width(&store, "narrow@test", 200, &theme)
            .expect("some")
            .1;
        // Same logical line count regardless of width.
        assert_eq!(narrow.len(), wide.len());
        // Narrow header should be shorter than the wide one (smaller arrow span).
        let nh = line_to_string(&narrow[0]).chars().count();
        let wh = line_to_string(&wide[0]).chars().count();
        assert!(nh < wh, "narrow header {nh} should be < wide {wh}");
    }

    #[test]
    fn build_lines_single_message_dialog() {
        let theme = Theme::default();
        let mut store = DialogStore::new(100, false);
        store.process_message(req("INVITE", "1 INVITE", "one@test", base_ts()));
        let (count, lines) = build_call_flow_lines(&store, "one@test", &theme).expect("some");
        assert_eq!(count, 1);
        // header + bar + 1 message + bar
        assert_eq!(lines.len(), 4);
        assert!(lines_to_string(&lines).contains("INVITE"));
    }

    #[test]
    fn build_lines_provisional_then_error_final() {
        let theme = Theme::default();
        let t = base_ts();
        let mut store = DialogStore::new(100, false);
        store.process_message(req("INVITE", "1 INVITE", "err@test", t));
        store.process_message(resp(
            100,
            "Trying",
            "1 INVITE",
            "err@test",
            t + TimeDelta::milliseconds(50),
        ));
        store.process_message(resp(
            480,
            "Temporarily Unavailable",
            "1 INVITE",
            "err@test",
            t + TimeDelta::seconds(1),
        ));
        let (count, lines) = build_call_flow_lines(&store, "err@test", &theme).expect("some");
        assert_eq!(count, 3);
        let text = lines_to_string(&lines);
        assert!(text.contains("100"));
        assert!(text.contains("480"));
    }

    // ── build_call_flow_lines_with_options ─────────────────────────────

    #[test]
    fn build_lines_with_options_selected_marker() {
        let theme = Theme::default();
        let store = store_full_dialog("opt@test");
        let mut o = opts(&theme);
        o.selected_msg = Some(2);
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "opt@test", 120, &o).expect("some");
        assert!(lines_to_string(&lines).contains("[SELECTED]"));
    }

    #[test]
    fn build_lines_with_options_sdp_summary_and_rtp() {
        let theme = Theme::default();
        let t = base_ts();
        let mut store = DialogStore::new(100, false);
        store.process_message(invite_with_sdp("sdp@test", t));
        store.process_message(resp(
            200,
            "OK",
            "1 INVITE",
            "sdp@test",
            t + TimeDelta::seconds(1),
        ));
        store.process_message(req(
            "ACK",
            "1 ACK",
            "sdp@test",
            t + TimeDelta::milliseconds(1100),
        ));
        store.process_message(req("BYE", "2 BYE", "sdp@test", t + TimeDelta::seconds(10)));
        let mut o = opts(&theme);
        o.sdp_mode = SdpDisplayMode::Summary;
        o.show_rtp = true;
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "sdp@test", 120, &o).expect("some");
        let text = lines_to_string(&lines);
        // SDP summary lists codecs; show_rtp draws an "RTP stream active" bar at BYE.
        assert!(
            text.contains("Codecs:"),
            "expected codec summary in:\n{text}"
        );
        assert!(
            text.contains("RTP stream active"),
            "expected RTP bar in:\n{text}"
        );
    }

    #[test]
    fn build_lines_with_options_sdp_full_emits_body_lines() {
        let theme = Theme::default();
        let mut store = DialogStore::new(100, false);
        store.process_message(invite_with_sdp("sdpfull@test", base_ts()));
        let mut o = opts(&theme);
        o.sdp_mode = SdpDisplayMode::Full;
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "sdpfull@test", 120, &o).expect("some");
        let text = lines_to_string(&lines);
        assert!(
            text.contains("m=audio 20000"),
            "expected raw SDP body in:\n{text}"
        );
        assert!(text.contains("a=rtpmap:0 PCMU/8000"));
    }

    #[test]
    fn build_lines_with_options_delta_prev_timestamps() {
        let theme = Theme::default();
        let store = store_full_dialog("delta@test");
        let mut o = opts(&theme);
        o.ts_mode = TimestampMode::DeltaPrev;
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "delta@test", 120, &o).expect("some");
        // Delta-prev renders "+<n>s" relative timestamps.
        assert!(lines_to_string(&lines).contains("+"));
    }

    #[test]
    fn build_lines_with_options_missing_dialog_none() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        let o = opts(&theme);
        assert!(build_call_flow_lines_with_options(&store, "absent@test", 120, &o).is_none());
    }

    // ── build_extended_flow_lines ──────────────────────────────────────

    #[test]
    fn extended_flow_single_leg_header() {
        let theme = Theme::default();
        let store = store_full_dialog("ext@test");
        let o = opts(&theme);
        let (count, lines) = build_extended_flow_lines(&store, "ext@test", 120, &o).expect("some");
        assert_eq!(count, 6);
        let text = lines_to_string(&lines);
        assert!(
            text.contains("Extended Flow:"),
            "missing header in:\n{text}"
        );
        assert!(text.contains("correlated leg(s)"));
        assert!(text.contains("INVITE"));
    }

    #[test]
    fn extended_flow_missing_dialog_none() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        let o = opts(&theme);
        assert!(build_extended_flow_lines(&store, "gone@test", 120, &o).is_none());
    }

    // ── render_call_flow / render_call_flow_lines ──────────────────────

    #[test]
    fn render_call_flow_paints_buffer() {
        let theme = Theme::default();
        let store = store_full_dialog("render@test");
        let mut term = terminal(100, 30);
        let area = Rect::new(0, 0, 100, 30);
        term.draw(|f| render_call_flow(f, area, &store, "render@test", 0, &theme))
            .unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("INVITE"), "buffer:\n{text}");
        assert!(text.contains("BYE"));
        assert!(!text.contains("Dialog not found"));
    }

    #[test]
    fn render_call_flow_missing_shows_fallback() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        let mut term = terminal(80, 10);
        let area = Rect::new(0, 0, 80, 10);
        term.draw(|f| render_call_flow(f, area, &store, "missing@test", 0, &theme))
            .unwrap();
        assert!(buffer_text(&term).contains("Dialog not found or empty"));
    }

    #[test]
    fn render_call_flow_narrow_width() {
        let theme = Theme::default();
        let store = store_full_dialog("rnarrow@test");
        let mut term = terminal(40, 20);
        let area = Rect::new(0, 0, 40, 20);
        term.draw(|f| render_call_flow(f, area, &store, "rnarrow@test", 0, &theme))
            .unwrap();
        // Still renders the wrapped ladder without panicking; some content present.
        let text = buffer_text(&term);
        assert!(
            text.contains("INVITE") || text.contains("10.0.0.1"),
            "buffer:\n{text}"
        );
    }

    #[test]
    fn render_call_flow_lines_scroll_offset() {
        let theme = Theme::default();
        let store = store_full_dialog("scroll@test");
        let mut term = terminal(100, 6);
        let area = Rect::new(0, 0, 100, 6);
        // Scroll past the header rows so later messages appear at the top.
        term.draw(|f| {
            render_call_flow_lines(f, area, "scroll@test", 4, &theme, || {
                build_call_flow_lines_with_width(&store, "scroll@test", 100, &theme)
            })
        })
        .unwrap();
        let text = buffer_text(&term);
        // With offset 4 (header+bar+INVITE+180 scrolled away) the 200/ACK/BYE show.
        assert!(
            text.contains("BYE") || text.contains("ACK") || text.contains("200"),
            "buffer:\n{text}"
        );
    }

    #[test]
    fn render_call_flow_lines_builder_returns_none() {
        let theme = Theme::default();
        let mut term = terminal(60, 8);
        let area = Rect::new(0, 0, 60, 8);
        term.draw(|f| render_call_flow_lines(f, area, "x@test", 0, &theme, || None))
            .unwrap();
        assert!(buffer_text(&term).contains("Dialog not found or empty"));
    }

    // ── scrollbar / focus helpers ──────────────────────────────────────

    #[test]
    fn ladder_visible_rows_reserves_header_footer() {
        // 2 rows for participant labels + pipes, 2 for footer.
        assert_eq!(ladder_visible_rows(30), 26);
        assert_eq!(ladder_visible_rows(4), 0);
        assert_eq!(ladder_visible_rows(0), 0);
    }

    #[test]
    fn message_detail_reports_lines_and_renders_scrollbar() {
        let theme = Theme::default();
        let store = store_full_dialog("detail@test");
        // A short pane forces the SIP message to overflow → scrollbar path.
        let mut term = terminal(40, 6);
        let area = Rect::new(0, 0, 40, 6);
        let mut lines = 0usize;
        term.draw(|f| {
            lines = render_message_detail(f, area, &store, "detail@test", 0, 0, true, &theme);
        })
        .unwrap();
        assert!(
            lines > 0,
            "detail panel should report its content line count"
        );
        // The thumb glyph '█' is unique to the scrollbar (the block border uses
        // box-drawing chars), so its presence proves the scrollbar painted.
        let text = buffer_text(&term);
        assert!(
            text.contains('\u{2588}'),
            "scrollbar thumb not painted:\n{text}"
        );
    }

    #[test]
    fn message_detail_no_scrollbar_when_it_fits() {
        let theme = Theme::default();
        let store = store_full_dialog("detail@test");
        // A tall pane fits the whole message → no scrollbar.
        let mut term = terminal(60, 40);
        let area = Rect::new(0, 0, 60, 40);
        term.draw(|f| {
            render_message_detail(f, area, &store, "detail@test", 0, 0, false, &theme);
        })
        .unwrap();
        let text = buffer_text(&term);
        assert!(
            !text.contains('\u{2588}'),
            "scrollbar should be absent when content fits:\n{text}"
        );
    }

    #[test]
    fn ladder_scrollbar_paints_when_overflowing() {
        let theme = Theme::default();
        // viewport rows = 9 - 4 = 5; 20 logical rows overflow it.
        let mut term = terminal(60, 9);
        let area = Rect::new(0, 0, 60, 9);
        term.draw(|f| render_ladder_scrollbar(f, area, 20, 0, &theme))
            .unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains('\u{2588}'),
            "ladder scrollbar thumb not painted:\n{text}"
        );
    }

    #[test]
    fn ladder_scrollbar_absent_when_fits() {
        let theme = Theme::default();
        let mut term = terminal(60, 30);
        let area = Rect::new(0, 0, 60, 30);
        // 3 rows into a 26-row viewport → nothing to scroll.
        term.draw(|f| render_ladder_scrollbar(f, area, 3, 0, &theme))
            .unwrap();
        let text = buffer_text(&term);
        assert!(text.trim().is_empty(), "no scrollbar expected:\n{text}");
    }

    #[test]
    fn message_detail_focus_highlights_border() {
        let theme = Theme::default();
        let store = store_full_dialog("detail@test");
        // Render focused vs unfocused; both must paint without panicking and
        // report the same line count (focus only changes styling).
        let area = Rect::new(0, 0, 50, 20);
        let mut a = 0usize;
        let mut b = 0usize;
        let mut term = terminal(50, 20);
        term.draw(|f| {
            a = render_message_detail(f, area, &store, "detail@test", 0, 0, true, &theme)
        })
        .unwrap();
        term.draw(|f| {
            b = render_message_detail(f, area, &store, "detail@test", 0, 0, false, &theme)
        })
        .unwrap();
        assert_eq!(a, b);
    }
}
