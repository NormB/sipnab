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

// ── Arrow width constant ────────────────────────────────────────────

/// Width of the arrow shaft (dashes) between endpoints.
const ARROW_WIDTH: usize = 24;

// ── Public rendering ────────────────────────────────────────────────

/// Render the call flow ladder diagram for a dialog identified by Call-ID.
pub fn render_call_flow(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    scroll_offset: usize,
) {
    let block = Block::default().borders(Borders::ALL).title(format!(
        " Call Flow: {} (Esc: Back | Enter: Raw) ",
        truncate(call_id, 40)
    ));

    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.")
                .block(block)
                .style(Style::default().fg(Color::Red));
            frame.render_widget(para, area);
            return;
        }
    };

    if dialog.messages.is_empty() {
        let para = Paragraph::new("No messages in dialog.")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(para, area);
        return;
    }

    let first_ts = dialog.messages[0].timestamp;
    let lines = format_ladder(&dialog.messages, first_ts, dialog.timing.pdd_ms());

    let para = Paragraph::new(lines)
        .block(block)
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
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
) -> Vec<Line<'static>> {
    if messages.is_empty() {
        return vec![Line::from("(no messages)")];
    }

    // Determine the two primary endpoints
    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    let mut lines: Vec<Line<'static>> = Vec::new();

    // Header with endpoint labels
    let left_label = format!("{:^20}", truncate(&left_addr, 20));
    let right_label = format!("{:^20}", truncate(&right_addr, 20));
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {left_label}"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{:^width$}", "", width = ARROW_WIDTH + 2)),
        Span::styled(
            right_label,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    // Vertical bars header
    lines.push(Line::from(format!(
        "  {:^20}{:^width$}{:^20}",
        "|",
        "",
        "|",
        width = ARROW_WIDTH + 2
    )));

    // Keep track of whether we've annotated PDD
    let mut pdd_annotated = false;

    for msg in messages {
        let delta = msg.timestamp.signed_duration_since(first_ts);
        let delta_str = format!("+{:.3}s", delta.num_milliseconds() as f64 / 1000.0);

        let label = format_message_label(msg);
        let msg_style = message_style(msg);

        let this_src = format!("{}:{}", msg.src_addr, msg.src_port);
        let is_left_to_right = this_src == left_addr;

        // Build the arrow line
        let arrow_line = if is_left_to_right {
            format_arrow_right(&label, ARROW_WIDTH)
        } else {
            format_arrow_left(&label, ARROW_WIDTH)
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
            Span::raw(format!("  {:^20}", "|")),
            Span::styled(arrow_line, msg_style),
            Span::raw(format!("{:^20}", "|")),
            Span::styled(
                format!("  {delta_str}"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(pdd_note, Style::default().fg(Color::Magenta)),
        ]));
    }

    // Closing bars
    lines.push(Line::from(format!(
        "  {:^20}{:^width$}{:^20}",
        "|",
        "",
        "|",
        width = ARROW_WIDTH + 2
    )));

    lines
}

// ── Arrow formatting helpers ────────────────────────────────────────

/// Format a right-pointing arrow: `── LABEL ──────────>`
fn format_arrow_right(label: &str, width: usize) -> String {
    let label_space = label.len() + 2; // space on each side
    if width <= label_space + 4 {
        return format!("--{label}->");
    }
    let left_dashes = 2;
    let right_dashes = width.saturating_sub(left_dashes + label_space + 1);
    format!(
        "{} {} {}",
        "-".repeat(left_dashes),
        label,
        "-".repeat(right_dashes) + ">"
    )
}

/// Format a left-pointing arrow: `<────────── LABEL ──`
fn format_arrow_left(label: &str, width: usize) -> String {
    let label_space = label.len() + 2;
    if width <= label_space + 4 {
        return format!("<-{label}--");
    }
    let right_dashes = 2;
    let left_dashes = width.saturating_sub(right_dashes + label_space + 1);
    format!(
        "{} {} {}",
        "<".to_string() + &"-".repeat(left_dashes),
        label,
        "-".repeat(right_dashes)
    )
}

/// Build a label string for a message (e.g., "INVITE" or "200 OK").
fn format_message_label(msg: &SipMessage) -> String {
    if msg.is_request {
        msg.method.as_deref().unwrap_or("?").to_string()
    } else {
        let code = msg.status_code.unwrap_or(0);
        let reason = msg.reason.as_deref().unwrap_or("");
        format!("{} {}", code, reason)
    }
}

/// Choose a style based on message type.
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
            200..=299 => Style::default().fg(Color::Green),
            100..=199 => Style::default().fg(Color::Cyan),
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
        let lines = format_ladder(&[], chrono::Utc::now(), None);
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

        let lines = format_ladder(&[msg], ts, None);
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
