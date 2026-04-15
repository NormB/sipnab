//! Rendering functions for call flow ladder diagrams.
//!
//! Contains both the direct buffer-painting path (used by the TUI) and
//! the Paragraph-based rendering path (used for non-interactive output).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::sip::SipMessage;
use crate::sip::dialog_store::DialogStore;

use crate::tui::ColorMode;
use crate::tui::SdpDisplayMode;
use crate::tui::TimestampMode;
use crate::tui::Theme;

use super::arrows::{format_arrow, format_arrow_left, format_arrow_right, truncate};
use super::prepare::{
    delta_style, format_message_label, format_sdp_codecs, message_style,
};
use super::{
    FormattedMessage, Participant, SelectionState, ENDPOINT_COL_WIDTH, MIN_ARROW_WIDTH,
    TS_COL_WIDTH,
};

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
#[allow(clippy::too_many_arguments)]
pub fn build_call_flow_lines_with_options(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    sdp_mode: SdpDisplayMode,
    ts_mode: TimestampMode,
    color_mode: ColorMode,
    show_rtp: bool,
    selected_msg: Option<usize>,
    theme: &Theme,
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
    let mut lines = format_ladder_with_options(
        &dialog.messages,
        ft,
        dialog.timing.pdd_ms(),
        aw,
        sdp_mode,
        ts_mode,
        color_mode,
        show_rtp,
        selected_msg,
        theme,
    );
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
            lines.push(Line::from(Span::styled(
                format!(
                    "   \u{2194} Call-ID: {} ({})",
                    truncate(&leg.call_id, 40),
                    leg.method
                ),
                Style::default().fg(theme.accent),
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
    sdp_mode: SdpDisplayMode,
    ts_mode: TimestampMode,
    color_mode: ColorMode,
    theme: &Theme,
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
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    lines.extend(format_ladder_with_options(
        &owned, ft, None, aw, sdp_mode, ts_mode, color_mode, false, None, theme,
    ));
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

/// Render a call flow ladder diagram by painting directly into the terminal buffer.
///
/// Instead of building `Line`/`Span` objects and rendering via `Paragraph`,
/// this writes characters at exact `(x, y)` coordinates in the buffer,
/// guaranteeing perfect column alignment regardless of character widths.
#[allow(clippy::too_many_arguments)]
pub fn render_call_flow_direct(
    frame: &mut Frame,
    area: Rect,
    participants: &[Participant],
    messages: &[FormattedMessage],
    scroll_offset: usize,
    theme: &Theme,
    mark_index: Option<usize>,
    selected_index: usize,
) {
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
                let spacer_style = Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::DIM);
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

            // Selection accent marker + timestamp
            match msg.selection_state {
                SelectionState::Selected => {
                    let marker_style = Style::default()
                        .fg(theme.selected)
                        .add_modifier(Modifier::BOLD);
                    buf.set_string(ts_col, y, "\u{258E}", marker_style); // ▎
                    if !msg.timestamp.is_empty() {
                        buf.set_string(ts_col + 1, y, &msg.timestamp, msg.timestamp_style);
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
                let label = &msg.label;
                let padded = if label.len() < bar_width {
                    let pad = bar_width.saturating_sub(label.len());
                    let left_pad = pad / 2;
                    let right_pad = pad - left_pad;
                    format!(
                        "{}{}{}",
                        "\u{2500}".repeat(left_pad),
                        label,
                        "\u{2500}".repeat(right_pad),
                    )
                } else {
                    label.to_string()
                };
                let bar_style = match msg.selection_state {
                    SelectionState::Selected => msg
                        .style
                        .bg(Color::Rgb(40, 40, 60))
                        .add_modifier(Modifier::BOLD),
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
                        SelectionState::Selected => msg
                            .style
                            .bg(Color::Rgb(40, 40, 60))
                            .add_modifier(Modifier::BOLD),
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
    scroll_offset: usize,
    theme: &Theme,
    mark_index: Option<usize>,
    selected_index: usize,
) {
    match prepared {
        Some((participants, msgs)) => {
            render_call_flow_direct(frame, area, participants, msgs, scroll_offset, theme, mark_index, selected_index);
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
pub fn render_message_detail(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    selected_msg: usize,
    scroll_offset: u16,
    theme: &Theme,
) {
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para =
                Paragraph::new("Dialog not found.").style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return;
        }
    };

    let msg = match dialog.messages.get(selected_msg) {
        Some(m) => m,
        None => {
            let para =
                Paragraph::new("No message selected.").style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return;
        }
    };

    let title = format!(
        " [{}/{}] {} ",
        selected_msg + 1,
        dialog.messages.len(),
        if msg.is_request {
            msg.method.as_deref().unwrap_or("?").to_string()
        } else {
            format!(
                "{} {}",
                msg.status_code.unwrap_or(0),
                msg.reason.as_deref().unwrap_or("")
            )
        },
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().fg(theme.border));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let raw_text = String::from_utf8_lossy(&msg.raw);
    let lines = highlight_sip_detail(&raw_text, theme);

    let para = Paragraph::new(lines)
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, inner);
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
#[allow(clippy::too_many_arguments)]
fn format_ladder_with_options(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    arrow_width: usize,
    sdp_mode: SdpDisplayMode,
    ts_mode: TimestampMode,
    color_mode: ColorMode,
    show_rtp: bool,
    selected_msg: Option<usize>,
    theme: &Theme,
) -> Vec<Line<'static>> {
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
            if msg.is_request && msg.method.as_deref() == Some("BYE") && in_call {
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

    #[test]
    fn format_ladder_empty_messages() {
        let theme = crate::tui::Theme::default();
        let lines = format_ladder(&[], chrono::Utc::now(), None, 40, &theme);
        assert_eq!(lines.len(), 1);
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
}
