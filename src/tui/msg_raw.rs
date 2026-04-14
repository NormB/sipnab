//! Raw SIP message viewer with syntax highlighting.
//!
//! Displays the full text of a SIP message with colorized method/status
//! lines, header names, and SDP body sections. Supports scrolling and
//! in-message search highlighting.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::sip::dialog_store::DialogStore;

// ── Public rendering ────────────────────────────────────────────────

/// Render the raw SIP message text with syntax highlighting.
///
/// # Arguments
///
/// * `store` — Dialog store to look up the message.
/// * `call_id` — Call-ID of the dialog.
/// * `message_index` — Index of the message within the dialog.
/// * `scroll_offset` — Vertical scroll position.
/// * `search_query` — Text to highlight within the message.
#[allow(clippy::too_many_arguments)]
pub fn render_raw_message(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    message_index: usize,
    scroll_offset: u16,
    search_query: &str,
    theme: &super::Theme,
) {
    let title = format!(
        " Raw SIP Message [{}/{}] (Esc: Back | /: Search) ",
        message_index + 1,
        store.get(call_id).map(|d| d.messages.len()).unwrap_or(0)
    );

    let block = Block::default().borders(Borders::ALL).title(title);

    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.")
                .block(block)
                .style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return;
        }
    };

    let msg = match dialog.messages.get(message_index) {
        Some(m) => m,
        None => {
            let para = Paragraph::new("Message not found.")
                .block(block)
                .style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return;
        }
    };

    // Header info line
    let info = format!(
        "{} {}:{} -> {}:{} [{}]",
        msg.timestamp.format("%H:%M:%S%.3f"),
        msg.src_addr,
        msg.src_port,
        msg.dst_addr,
        msg.dst_port,
        msg.transport,
    );

    let raw_text = String::from_utf8_lossy(&msg.raw);
    let lines = highlight_sip_message(&info, &raw_text, search_query, theme);

    let para = Paragraph::new(lines)
        .block(block)
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, area);
}

// ── Syntax highlighting ─────────────────────────────────────────────

/// Highlight a SIP message with basic syntax coloring.
///
/// - First line (method/status): bold
/// - Header names: cyan
/// - Header values: default
/// - SDP body: dimmed/italic
/// - Search matches: highlighted background
fn highlight_sip_message<'a>(info: &str, raw_text: &str, search_query: &str, theme: &super::Theme) -> Vec<Line<'a>> {
    let mut lines: Vec<Line<'a>> = Vec::new();

    // Info line
    lines.push(Line::from(Span::styled(
        info.to_string(),
        Style::default()
            .fg(theme.muted)
            .add_modifier(Modifier::ITALIC),
    )));
    lines.push(Line::from(""));

    let mut in_body = false;
    let search_lower = search_query.to_ascii_lowercase();

    for raw_line in raw_text.lines() {
        // Detect body separator (empty line after headers)
        if !in_body && raw_line.trim().is_empty() {
            in_body = true;
            lines.push(Line::from(""));
            continue;
        }

        if in_body {
            // SDP body: dimmed and italic
            let styled_line = if !search_query.is_empty()
                && raw_line.to_ascii_lowercase().contains(&search_lower)
            {
                highlight_search_in_line(
                    raw_line,
                    search_query,
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::ITALIC),
                )
            } else {
                Line::from(Span::styled(
                    raw_line.to_string(),
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::ITALIC),
                ))
            };
            lines.push(styled_line);
        } else if lines.len() == 2 {
            // First line of the SIP message: method/status — bold
            let styled_line = if !search_query.is_empty()
                && raw_line.to_ascii_lowercase().contains(&search_lower)
            {
                highlight_search_in_line(
                    raw_line,
                    search_query,
                    Style::default().add_modifier(Modifier::BOLD),
                )
            } else {
                Line::from(Span::styled(
                    raw_line.to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ))
            };
            lines.push(styled_line);
        } else {
            // Header line: split at first ':'
            let styled_line = if let Some(colon_pos) = raw_line.find(':') {
                let name = &raw_line[..colon_pos];
                let value = &raw_line[colon_pos..];

                if !search_query.is_empty() && raw_line.to_ascii_lowercase().contains(&search_lower)
                {
                    highlight_search_in_line(raw_line, search_query, Style::default())
                } else {
                    Line::from(vec![
                        Span::styled(name.to_string(), Style::default().fg(theme.header)),
                        Span::raw(value.to_string()),
                    ])
                }
            } else if !search_query.is_empty()
                && raw_line.to_ascii_lowercase().contains(&search_lower)
            {
                highlight_search_in_line(raw_line, search_query, Style::default())
            } else {
                Line::from(Span::raw(raw_line.to_string()))
            };
            lines.push(styled_line);
        }
    }

    lines
}

/// Highlight occurrences of `query` in a line with a colored background.
fn highlight_search_in_line<'a>(line: &str, query: &str, base_style: Style) -> Line<'a> {
    if query.is_empty() {
        return Line::from(Span::styled(line.to_string(), base_style));
    }

    let highlight_style = Style::default()
        .bg(Color::Yellow)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD);

    // to_ascii_lowercase preserves byte length (1:1 mapping), so byte
    // offsets from match_indices on the lowered string are valid for the
    // original. This is safe because ASCII lowercasing never changes byte count.
    let lower_line = line.to_ascii_lowercase();
    let lower_query = query.to_ascii_lowercase();
    let qlen = lower_query.len();

    let mut spans: Vec<Span<'a>> = Vec::new();
    let mut last_end = 0;

    for (start, _) in lower_line.match_indices(&lower_query) {
        let end = start + qlen;
        // Verify byte offsets land on char boundaries in the original string
        if !line.is_char_boundary(start) || !line.is_char_boundary(end) {
            continue;
        }
        if start > last_end {
            spans.push(Span::styled(line[last_end..start].to_string(), base_style));
        }
        spans.push(Span::styled(
            line[start..end].to_string(),
            highlight_style,
        ));
        last_end = end;
    }

    if last_end < line.len() {
        spans.push(Span::styled(line[last_end..].to_string(), base_style));
    }

    Line::from(spans)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlight_search_in_line_no_match() {
        let line = highlight_search_in_line("Hello World", "xyz", Style::default());
        assert_eq!(line.spans.len(), 1);
    }

    #[test]
    fn highlight_search_in_line_with_match() {
        let line = highlight_search_in_line("Hello World Hello", "Hello", Style::default());
        // "Hello" appears twice, so we get: match, " World ", match
        assert!(line.spans.len() >= 3);
    }

    #[test]
    fn highlight_search_case_insensitive() {
        let line = highlight_search_in_line("INVITE sip:foo", "invite", Style::default());
        assert!(line.spans.len() >= 2);
    }

    #[test]
    fn highlight_sip_message_basic() {
        let theme = crate::tui::Theme::default();
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\nFrom: alice\r\n\r\nv=0\r\n";
        let lines = highlight_sip_message("info line", raw, "", &theme);
        // info + blank + first line + header + blank separator + sdp line
        assert!(lines.len() >= 4);
    }
}
