//! Call flow ladder diagram view.
//!
//! Renders a classic SIP ladder diagram for a single dialog, showing
//! message arrows between endpoints with timestamps, method/status
//! annotations, and PDD indicators.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::sip::SipMessage;
use crate::sip::dialog_store::DialogStore;
use crate::sip::sdp; // SDP parser types for codec display

use super::ColorMode; // Color mode enum
use super::SdpDisplayMode; // SDP display mode enum
use super::TimestampMode; // Timestamp display mode enum

// ── Layout constants ────────────────────────────────────────────────

/// Minimum width for the arrow shaft (dashes) between endpoints.
const MIN_ARROW_WIDTH: usize = 24;
/// Width reserved for the timestamp column (`HH:MM:SS.mmm` or `+60.000s ` + padding).
const TS_COL_WIDTH: usize = 13;
/// Width reserved for each endpoint column (pipe + padding).
const ENDPOINT_COL_WIDTH: usize = 20;

// ── Public rendering ────────────────────────────────────────────────

/// Build the formatted lines for a call flow ladder diagram.
///
/// Returns `None` if the dialog is not found or has no messages.
/// Returns `Some((msg_count, lines))` on success, where `msg_count` can be
/// used as a cache invalidation key.
pub fn build_call_flow_lines(
    store: &DialogStore,
    call_id: &str,
) -> Option<(usize, Vec<Line<'static>>)> {
    build_call_flow_lines_with_width(store, call_id, 120)
}

/// Build call flow lines with a specific terminal width for arrow sizing.
pub fn build_call_flow_lines_with_width(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }

    // Calculate arrow width based on terminal width:
    // term_width = timestamp(13) + left_endpoint(20) + arrow + right_endpoint(20) + pdd(~15)
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
    );

    // Show correlated dialogs (multi-leg)
    let correlated = store.find_correlated(call_id);
    if !correlated.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Correlated Legs:",
            Style::default()
                .fg(Color::Magenta)
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
                Style::default().fg(Color::Magenta),
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
    );
    let correlated = store.find_correlated(call_id);
    if !correlated.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Correlated Legs:",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )));
        for leg in &correlated {
            lines.push(Line::from(Span::styled(
                format!(
                    "   \u{2194} Call-ID: {} ({})",
                    truncate(&leg.call_id, 40),
                    leg.method
                ),
                Style::default().fg(Color::Magenta),
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
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    lines.extend(format_ladder_with_options(
        &owned, ft, None, aw, sdp_mode, ts_mode, color_mode, false, None,
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
) {
    let term_width = area.width as usize;
    render_call_flow_lines(frame, area, call_id, scroll_offset, || {
        build_call_flow_lines_with_width(store, call_id, term_width)
    });
}

/// Render call flow from pre-built lines or a builder closure.
///
/// Used by the caching layer: the closure is only called on cache miss.
pub fn render_call_flow_lines(
    frame: &mut Frame,
    area: Rect,
    _call_id: &str,
    scroll_offset: usize,
    build: impl FnOnce() -> Option<(usize, Vec<Line<'static>>)>,
) {
    let lines = match build() {
        Some((_count, lines)) => lines,
        None => {
            let para = Paragraph::new("Dialog not found or empty.")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(para, area);
            return;
        }
    };

    // No borders — the ladder fills the full main area (sngrep style).
    // The call-id is shown in the status bar area by the caller.
    let para = Paragraph::new(lines)
        .scroll((scroll_offset as u16, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, area);
}

// ── Direct buffer painting (TUI path) ───────────────────────────────

/// Pre-formatted message data for the direct-paint renderer.
///
/// Separates data preparation (display modes, color, timestamps) from
/// the actual buffer painting, keeping the render function simple.
pub struct FormattedMessage {
    /// Formatted timestamp string (or empty if hidden).
    pub timestamp: String,
    /// Style for the timestamp (delta modes use color-coded styles).
    pub timestamp_style: Style,
    /// Arrow label (e.g., "INVITE (SDP)" or "200 OK").
    pub label: String,
    /// Style for the arrow line.
    pub style: Style,
    /// Direction: `true` if the arrow points left-to-right.
    pub is_left_to_right: bool,
    /// Optional PDD annotation (e.g., "  PDD: 1234ms").
    pub pdd_note: Option<String>,
    /// Optional extra lines below the arrow (SDP info, RTP markers, etc.).
    pub extra_lines: Vec<(String, Style)>,
    /// Whether this message is selected (for highlighting).
    pub selected: bool,
}

/// Compute a color-coded style for a delta timestamp based on its magnitude.
///
/// - Green: <100ms (fast / normal)
/// - Yellow: 100ms-1s (moderate delay)
/// - Red: 1s-5s (slow)
/// - Bold red: >5s (very slow / timeout risk)
fn delta_style(delta_ms: i64) -> Style {
    if delta_ms < 100 {
        Style::default().fg(Color::Green)
    } else if delta_ms < 1000 {
        Style::default().fg(Color::Yellow)
    } else if delta_ms < 5000 {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    }
}

/// Prepare formatted messages from a dialog's SIP messages.
///
/// Applies all display modes (SDP, timestamp, color, RTP) and returns
/// a list of `FormattedMessage`s plus the endpoint labels.
#[allow(clippy::too_many_arguments)]
pub fn prepare_messages(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    sdp_mode: SdpDisplayMode,
    ts_mode: TimestampMode,
    color_mode: ColorMode,
    show_rtp: bool,
    selected_msg: Option<usize>,
) -> (String, String, Vec<FormattedMessage>) {
    if messages.is_empty() {
        return (String::new(), String::new(), Vec::new());
    }

    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    let ts_width = TS_COL_WIDTH;

    let cid_colors = [
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Red,
    ];

    let mut pdd_done = false;
    let mut in_call = false;
    let mut result = Vec::with_capacity(messages.len());
    let mut prev_ts = first_ts;

    for (mi, msg) in messages.iter().enumerate() {
        let (timestamp, timestamp_style) = match ts_mode {
            TimestampMode::Absolute => {
                let ts_str = format!(
                    "{:<width$}",
                    msg.timestamp.format("%H:%M:%S%.3f"),
                    width = ts_width
                );
                (ts_str, Style::default().fg(Color::DarkGray))
            }
            TimestampMode::DeltaPrev => {
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let ts_str = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d);
                prev_ts = msg.timestamp;
                (ts_str, sty)
            }
            TimestampMode::DeltaFirst => {
                let d = msg
                    .timestamp
                    .signed_duration_since(first_ts)
                    .num_milliseconds();
                let ts_str = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d);
                (ts_str, sty)
            }
        };

        let label = format_message_label(msg);

        let sty = match color_mode {
            ColorMode::Method => message_style(msg),
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
        let style = if sel {
            sty.add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            sty
        };

        let src = format!("{}:{}", msg.src_addr, msg.src_port);
        let is_left_to_right = src == left_addr;

        let mut pdd_note = None;
        if !pdd_done
            && let Some(p) = pdd_ms
            && !msg.is_request
            && msg.status_code == Some(180)
        {
            pdd_note = Some(format!("  PDD: {p}ms"));
            pdd_done = true;
        }

        let mut extra_lines = Vec::new();

        // SDP info lines
        if sdp_mode != SdpDisplayMode::None
            && let Some(ss) = msg.sdp()
        {
            let ind = " ".repeat(ts_width + 1);
            match sdp_mode {
                SdpDisplayMode::Summary => {
                    let c = format_sdp_codecs(&ss);
                    if !c.is_empty() {
                        extra_lines.push((
                            format!("{ind} Codecs: {c}"),
                            Style::default()
                                .fg(Color::DarkGray)
                                .add_modifier(Modifier::ITALIC),
                        ));
                    }
                }
                SdpDisplayMode::Full => {
                    let bt = String::from_utf8_lossy(&msg.body);
                    for sl in bt.lines() {
                        extra_lines.push((
                            format!("{ind}  {sl}"),
                            Style::default()
                                .fg(Color::DarkGray)
                                .add_modifier(Modifier::ITALIC),
                        ));
                    }
                }
                SdpDisplayMode::None => {}
            }
        }

        // RTP marker
        if show_rtp {
            if !msg.is_request && msg.status_code == Some(200) {
                in_call = true;
            }
            if msg.is_request && msg.method.as_deref() == Some("BYE") && in_call {
                extra_lines.push((
                    format!(
                        "{}\u{2500}\u{2500}\u{2500}\u{2500} RTP stream active \u{2500}\u{2500}\u{2500}\u{2500}",
                        " ".repeat(ts_width + 1)
                    ),
                    Style::default().fg(Color::DarkGray),
                ));
                in_call = false;
            }
        }

        result.push(FormattedMessage {
            timestamp,
            timestamp_style,
            label,
            style,
            is_left_to_right,
            pdd_note,
            extra_lines,
            selected: sel,
        });
    }

    (left_addr, right_addr, result)
}

/// Render a call flow ladder diagram by painting directly into the terminal buffer.
///
/// Instead of building `Line`/`Span` objects and rendering via `Paragraph`,
/// this writes characters at exact `(x, y)` coordinates in the buffer,
/// guaranteeing perfect column alignment regardless of character widths.
pub fn render_call_flow_direct(
    frame: &mut Frame,
    area: Rect,
    messages: &[FormattedMessage],
    scroll_offset: usize,
    left_label: &str,
    right_label: &str,
) {
    let buf = frame.buffer_mut();
    let width = area.width;
    let height = area.height;

    if width < 30 || height < 5 {
        buf.set_string(
            area.x,
            area.y,
            "Terminal too small",
            Style::default().fg(Color::DarkGray),
        );
        return;
    }

    // Fixed column positions — mirrors the original layout:
    //   [timestamp 13] [left_pipe 1] [arrow_width] [right_pipe 1] [pdd ~15]
    let ts_col = area.x;
    let left_pipe = area.x + TS_COL_WIDTH as u16; // col 13
    // Reserve ~15 chars after the right pipe for PDD annotations
    let right_pipe = area.x + width.saturating_sub(16);
    let arrow_start = left_pipe + 1;
    let arrow_end = right_pipe;
    let arrow_width = (arrow_end.saturating_sub(arrow_start)) as usize;

    if arrow_width < 10 {
        buf.set_string(
            area.x,
            area.y,
            "Terminal too narrow for ladder",
            Style::default().fg(Color::DarkGray),
        );
        return;
    }

    let label_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let pipe_style = Style::default().fg(Color::DarkGray);

    // Row 0: Endpoint labels centered around their pipe positions
    let y = area.y;
    let left_lbl = truncate(left_label, 25);
    let left_x = left_pipe.saturating_sub(left_lbl.len() as u16 / 2);
    buf.set_string(left_x, y, &left_lbl, label_style);

    let right_lbl = truncate(right_label, 25);
    let right_x = right_pipe.saturating_sub(right_lbl.len() as u16 / 2);
    buf.set_string(right_x, y, &right_lbl, label_style);

    // Row 1: Pipe line
    let y = area.y + 1;
    buf.set_string(left_pipe, y, "|", pipe_style);
    buf.set_string(right_pipe, y, "|", pipe_style);

    // Message rows: we expand each FormattedMessage into 1 + extra_lines rows
    let mut row: usize = 2;
    // Track the logical row for scrolling (each message contributes 1 + extra_lines.len())
    let mut logical_row: usize = 0;
    let max_row = (height as usize).saturating_sub(1); // leave room for closing pipes

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

            // Timestamp / selection indicator
            if msg.selected {
                // Show `>>>` marker instead of timestamp for the selected row
                let marker_style = Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD);
                buf.set_string(ts_col, y, ">>>", marker_style);
            } else if !msg.timestamp.is_empty() {
                buf.set_string(ts_col, y, &msg.timestamp, msg.timestamp_style);
            }

            // Pipes at fixed positions
            buf.set_string(left_pipe, y, "|", pipe_style);
            buf.set_string(right_pipe, y, "|", pipe_style);

            // Arrow between pipes — use reverse video when selected
            let arrow = if msg.is_left_to_right {
                format_arrow_right(&msg.label, arrow_width.saturating_sub(1))
            } else {
                format_arrow_left(&msg.label, arrow_width.saturating_sub(1))
            };
            let arrow_style = if msg.selected {
                msg.style.add_modifier(Modifier::REVERSED)
            } else {
                msg.style
            };
            buf.set_string(arrow_start, y, &arrow, arrow_style);

            // PDD annotation after right pipe
            if let Some(ref pdd) = msg.pdd_note {
                buf.set_string(right_pipe + 1, y, pdd, Style::default().fg(Color::Magenta));
            }

            row += 1;
        } else if logical_row < scroll_offset {
            // This main row is scrolled off; advance logical but not visual
            // (extra lines handled below)
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

    // Closing pipe line
    if row < height as usize {
        let y = area.y + row as u16;
        buf.set_string(left_pipe, y, "|", pipe_style);
        buf.set_string(right_pipe, y, "|", pipe_style);
    }
}

/// Render call flow with a fallback "not found" message using direct buffer painting.
///
/// This is the TUI entry point that replaces the Paragraph-based `render_call_flow_lines`.
pub fn render_call_flow_direct_or_empty(
    frame: &mut Frame,
    area: Rect,
    messages: Option<&(String, String, Vec<FormattedMessage>)>,
    scroll_offset: usize,
) {
    match messages {
        Some((left, right, msgs)) => {
            render_call_flow_direct(frame, area, msgs, scroll_offset, left, right);
        }
        None => {
            let buf = frame.buffer_mut();
            buf.set_string(
                area.x,
                area.y,
                "Dialog not found or empty.",
                Style::default().fg(Color::DarkGray),
            );
        }
    }
}

/// Render the message detail panel (right side of the split view).
///
/// Shows the raw SIP message of the selected message with syntax highlighting:
/// method/status line in bold, header names in cyan, SDP body dimmed.
pub fn render_message_detail(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    selected_msg: usize,
    scroll_offset: u16,
) {
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para =
                Paragraph::new("Dialog not found.").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(para, area);
            return;
        }
    };

    let msg = match dialog.messages.get(selected_msg) {
        Some(m) => m,
        None => {
            let para =
                Paragraph::new("No message selected.").style(Style::default().fg(Color::DarkGray));
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
        .style(Style::default().fg(Color::White));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build highlighted lines from the raw SIP message
    let raw_text = String::from_utf8_lossy(&msg.raw);
    let lines = highlight_sip_detail(&raw_text);

    let para = Paragraph::new(lines)
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, inner);
}

/// Highlight a raw SIP message for the detail panel.
///
/// - First line (request/status): bold white
/// - Header names (before ':'): cyan
/// - Header values: default
/// - SDP body lines: dimmed italic
fn highlight_sip_detail(raw_text: &str) -> Vec<Line<'static>> {
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
            // SDP / body: dimmed italic
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
        } else if is_first {
            // Request/status line: bold
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )));
            is_first = false;
        } else if let Some(colon_pos) = raw_line.find(':') {
            // Header: name in cyan, value in default
            let name = &raw_line[..colon_pos];
            let value = &raw_line[colon_pos..];
            lines.push(Line::from(vec![
                Span::styled(name.to_string(), Style::default().fg(Color::Cyan)),
                Span::styled(value.to_string(), Style::default().fg(Color::White)),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default().fg(Color::White),
            )));
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "(empty message)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines
}

// ── Ladder formatting ───────────────────────────────────────────────

/// Format all messages in a dialog as ladder diagram lines.
///
/// Each message becomes an arrow line between the two endpoints,
/// annotated with the method/status and relative timestamp.
///
/// # Arguments
///
/// * `messages` — Messages in chronological order.
/// * `first_ts` — Timestamp of the first message (for delta calculation).
/// * `pdd_ms` — Post-dial delay if known (annotated on the 180 Ringing line).
///
/// # Returns
///
/// A vector of styled [`Line`]s suitable for a [`Paragraph`] widget.
pub fn format_ladder(
    messages: &[SipMessage],
    _first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    arrow_width: usize,
) -> Vec<Line<'static>> {
    if messages.is_empty() {
        return vec![Line::from("(no messages)")];
    }

    // Determine the two primary endpoints
    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    // Fixed column positions:
    //   [timestamp 13] [left_pipe 1] [arrow_width] [right_pipe 1]
    // Left pipe is at column TS_COL_WIDTH (13)
    // Right pipe is at column TS_COL_WIDTH + 1 + arrow_width
    // Endpoint labels are centered above their respective pipes

    let left_pipe_col = TS_COL_WIDTH;
    let right_pipe_col = left_pipe_col + 1 + arrow_width;

    let mut lines: Vec<Line<'static>> = Vec::new();

    // Header: endpoint labels centered above their pipe positions
    let mut header = String::new();
    // Pad to left pipe position, then place left label centered around it
    let left_label = truncate(&left_addr, 25);
    let right_label = truncate(&right_addr, 25);

    // Left label: right-aligned to end near the pipe position
    header.push_str(&format!(
        "{:>width$}",
        left_label,
        width = left_pipe_col + left_label.len() / 2
    ));
    // Gap to right label
    let gap = right_pipe_col.saturating_sub(header.len() + right_label.len() / 2);
    header.push_str(&" ".repeat(gap));
    header.push_str(&right_label);

    lines.push(Line::from(Span::styled(
        header,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    // Pipe line helper
    let pipe_line = |prefix: &str| -> String {
        let mut s = String::new();
        s.push_str(prefix);
        // Pad to left_pipe_col
        while s.len() < left_pipe_col {
            s.push(' ');
        }
        s.push('|');
        // Pad to right_pipe_col
        while s.len() < right_pipe_col {
            s.push(' ');
        }
        s.push('|');
        s
    };

    // Vertical bars header
    lines.push(Line::from(pipe_line(&" ".repeat(TS_COL_WIDTH))));

    let mut pdd_annotated = false;

    for msg in messages {
        let ts_str = msg.timestamp.format("%H:%M:%S%.3f").to_string();
        let label = format_message_label(msg);
        let msg_style = message_style(msg);

        let this_src = format!("{}:{}", msg.src_addr, msg.src_port);
        let is_left_to_right = this_src == left_addr;

        // Build the full line: timestamp + pipe + arrow + pipe
        let ts_part = format!("{:<width$}", ts_str, width = TS_COL_WIDTH);

        // Arrow spans from left_pipe_col+1 to right_pipe_col-1
        let arrow_span = arrow_width.saturating_sub(1);
        let arrow_line = if is_left_to_right {
            format_arrow_right(&label, arrow_span)
        } else {
            format_arrow_left(&label, arrow_span)
        };

        // PDD annotation
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
            Span::styled(ts_part, Style::default().fg(Color::DarkGray)),
            Span::raw("|"),
            Span::styled(arrow_line, msg_style),
            Span::raw("|"),
            Span::styled(pdd_note, Style::default().fg(Color::Magenta)),
        ]));
    }

    // Closing bars
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
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    let ts_prefix = " ".repeat(ts_width);
    let mk_pipe = |pfx: &str| -> String {
        let mut s = String::new();
        s.push_str(pfx);
        while s.len() < left_pipe_col {
            s.push(' ');
        }
        s.push('|');
        while s.len() < right_pipe_col {
            s.push(' ');
        }
        s.push('|');
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
                (s, Style::default().fg(Color::DarkGray))
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
                let sty = delta_style(d);
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
                let sty = delta_style(d);
                (s, sty)
            }
        };
        let label = format_message_label(msg);
        let sty = match color_mode {
            ColorMode::Method => message_style(msg),
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
        let fsty = if sel {
            sty.add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            sty
        };

        let src = format!("{}:{}", msg.src_addr, msg.src_port);
        let ltr = src == left_addr;
        let as_ = arrow_width.saturating_sub(1);
        let al = if ltr {
            format_arrow_right(&label, as_)
        } else {
            format_arrow_left(&label, as_)
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
        sp.push(Span::raw("|"));
        sp.push(Span::styled(al, fsty));
        sp.push(Span::raw("|"));
        if !pn.is_empty() {
            sp.push(Span::styled(pn, Style::default().fg(Color::Magenta)));
        }
        if sel {
            sp.push(Span::styled(
                "  [SELECTED]",
                Style::default()
                    .fg(Color::Yellow)
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
                                .fg(Color::DarkGray)
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
                                .fg(Color::DarkGray)
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
                    format!("{}\u{2500}\u{2500}\u{2500}\u{2500} RTP stream active \u{2500}\u{2500}\u{2500}\u{2500}", " ".repeat(ts_width + 1)),
                    Style::default().fg(Color::DarkGray),
                )));
                in_call = false;
            }
        }
    }

    lines.push(Line::from(mk_pipe(&ts_prefix)));
    lines
}

/// Format SDP codec list from an SDP session for the summary display.
fn format_sdp_codecs(session: &sdp::SdpSession) -> String {
    let mut codecs = Vec::new();
    for media in &session.media {
        for rm in &media.rtpmap {
            codecs.push(rm.encoding.clone());
        }
        if media.rtpmap.is_empty() {
            for f in &media.formats {
                codecs.push(
                    match f.as_str() {
                        "0" => "PCMU",
                        "8" => "PCMA",
                        "9" => "G722",
                        "18" => "G729",
                        "4" => "G723",
                        "3" => "GSM",
                        "101" => "telephone-event",
                        o => o,
                    }
                    .to_string(),
                );
            }
        }
    }
    codecs.join(", ")
}

// ── Arrow formatting helpers ────────────────────────────────────────

/// Format a right-pointing arrow with the label centered: `------- LABEL -------->`
fn format_arrow_right(label: &str, width: usize) -> String {
    let label_with_pad = label.len() + 2; // space on each side of label
    if width <= label_with_pad + 3 {
        return format!("-- {label} ->");
    }
    // Total dashes = width - label_with_pad - 1 (for '>')
    let total_dashes = width.saturating_sub(label_with_pad + 1);
    let left_dashes = total_dashes / 2;
    let right_dashes = total_dashes - left_dashes;
    format!(
        "{} {} {}",
        "-".repeat(left_dashes),
        label,
        "-".repeat(right_dashes) + ">"
    )
}

/// Format a left-pointing arrow with the label centered: `<-------- LABEL -------`
fn format_arrow_left(label: &str, width: usize) -> String {
    let label_with_pad = label.len() + 2;
    if width <= label_with_pad + 3 {
        return format!("<- {label} --");
    }
    // Total dashes = width - label_with_pad - 1 (for '<')
    let total_dashes = width.saturating_sub(label_with_pad + 1);
    let left_dashes = total_dashes / 2;
    let right_dashes = total_dashes - left_dashes;
    format!(
        "{} {} {}",
        "<".to_string() + &"-".repeat(left_dashes),
        label,
        "-".repeat(right_dashes)
    )
}

/// Build a label string for a message (e.g., "INVITE (SDP)" or "200 OK").
///
/// Appends "(SDP)" when the message body contains SDP, matching sngrep style.
fn format_message_label(msg: &SipMessage) -> String {
    let has_sdp = msg
        .content_type()
        .is_some_and(|ct| ct.contains("application/sdp"))
        || (!msg.body.is_empty()
            && std::str::from_utf8(&msg.body)
                .ok()
                .is_some_and(|b| b.starts_with("v=")));

    let sdp_suffix = if has_sdp { " (SDP)" } else { "" };

    if msg.is_request {
        format!("{}{}", msg.method.as_deref().unwrap_or("?"), sdp_suffix)
    } else {
        let code = msg.status_code.unwrap_or(0);
        let reason = msg.reason.as_deref().unwrap_or("");
        format!("{} {}{}", code, reason, sdp_suffix)
    }
}

/// Choose a style based on message type (sngrep colors).
///
/// Requests: green for INVITE, red for BYE, yellow for CANCEL, white for others.
/// Responses: cyan for provisional/success, red for errors.
fn message_style(msg: &SipMessage) -> Style {
    if msg.is_request {
        let method = msg.method.as_deref().unwrap_or("");
        match method {
            "INVITE" => Style::default().fg(Color::Green),
            "BYE" => Style::default().fg(Color::Red),
            "CANCEL" => Style::default().fg(Color::Yellow),
            "ACK" => Style::default().fg(Color::Cyan),
            _ => Style::default().fg(Color::White),
        }
    } else {
        let code = msg.status_code.unwrap_or(0);
        match code {
            100..=199 => Style::default().fg(Color::Cyan),
            200..=299 => Style::default().fg(Color::Cyan),
            400..=699 => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            _ => Style::default(),
        }
    }
}

/// Truncate a string to a maximum length, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;

    #[test]
    fn format_arrow_right_contains_label() {
        let arrow = format_arrow_right("INVITE", 24);
        assert!(arrow.contains("INVITE"));
        assert!(arrow.ends_with('>'));
    }

    #[test]
    fn format_arrow_left_contains_label() {
        let arrow = format_arrow_left("200 OK", 24);
        assert!(arrow.contains("200 OK"));
        assert!(arrow.starts_with('<'));
    }

    #[test]
    fn format_ladder_empty_messages() {
        let lines = format_ladder(&[], chrono::Utc::now(), None, 40);
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

        let lines = format_ladder(&[msg], ts, None, 50);
        // Should have header + bar + message + closing bar
        assert!(lines.len() >= 4);
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world foo", 10), "hello w...");
    }

    #[test]
    fn truncate_short_max() {
        assert_eq!(truncate("hello", 3), "hel");
    }
}
