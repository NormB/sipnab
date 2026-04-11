//! Call flow ladder diagram view.
//!
//! Renders a classic SIP ladder diagram for a single dialog, showing
//! message arrows between endpoints with timestamps, method/status
//! annotations, and PDD indicators.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::sip::SipMessage;
use crate::sip::dialog_store::DialogStore;
use crate::sip::sdp; // SDP parser types for codec display

use super::ColorMode; // Color mode enum
use super::SdpDisplayMode; // SDP display mode enum
use super::TimestampMode; // Timestamp display mode enum

// ── Layout constants ────────────────────────────────────────────────

/// Minimum width for the arrow shaft (dashes) between endpoints.
const MIN_ARROW_WIDTH: usize = 24;
/// Width reserved for the timestamp column (HH:MM:SS + 2 spaces).
const TS_COL_WIDTH: usize = 10;
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
    // term_width = timestamp(10) + left_endpoint(20) + arrow + right_endpoint(20) + pdd(~15)
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
    let tw = match ts_mode {
        TimestampMode::Absolute | TimestampMode::Relative => TS_COL_WIDTH,
        TimestampMode::Hidden => 0,
    };
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
    let tw = match ts_mode {
        TimestampMode::Absolute | TimestampMode::Relative => TS_COL_WIDTH,
        TimestampMode::Hidden => 0,
    };
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
    //   [timestamp 10] [left_pipe 1] [arrow_width] [right_pipe 1]
    // Left pipe is at column TS_COL_WIDTH (10)
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
    lines.push(Line::from(pipe_line("          ")));

    let mut pdd_annotated = false;

    for msg in messages {
        let ts_str = msg.timestamp.format("%H:%M:%S").to_string();
        let label = format_message_label(msg);
        let msg_style = message_style(msg);

        let this_src = format!("{}:{}", msg.src_addr, msg.src_port);
        let is_left_to_right = this_src == left_addr;

        // Build the full line: timestamp + pipe + arrow + pipe
        let ts_part = format!("{:<10}", ts_str);

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
    lines.push(Line::from(pipe_line("          ")));

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

    let ts_width = match ts_mode {
        TimestampMode::Absolute | TimestampMode::Relative => TS_COL_WIDTH,
        TimestampMode::Hidden => 0,
    };
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
    let cid_colors = [
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Red,
    ];

    for (mi, msg) in messages.iter().enumerate() {
        let ts_str = match ts_mode {
            TimestampMode::Absolute => format!(
                "{:<width$}",
                msg.timestamp.format("%H:%M:%S"),
                width = ts_width
            ),
            TimestampMode::Relative => {
                let d = msg
                    .timestamp
                    .signed_duration_since(first_ts)
                    .num_milliseconds();
                format!(
                    "{:<width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width
                )
            }
            TimestampMode::Hidden => String::new(),
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
            sp.push(Span::styled(ts_str, Style::default().fg(Color::DarkGray)));
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
            "UDP",
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
