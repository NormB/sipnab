// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Navigation and display state for the raw message viewer.
pub struct RawMessageView<'a> {
    /// Call-ID of the dialog whose message is shown.
    pub call_id: &'a str,
    /// Index of the message within the dialog's message list.
    pub message_index: usize,
    /// Vertical scroll offset in rendered (wrapped) rows.
    pub scroll_offset: u16,
    /// Active search query; matches are background-highlighted.
    pub search_query: &'a str,
    /// When `false`, render the message as plain unstyled text.
    pub syntax_highlight: bool,
    /// Header-name display form (as captured / expanded / compact).
    pub header_form: super::header_form::HeaderFormMode,
    /// Color theme used for all styling.
    pub theme: &'a super::Theme,
}

/// Estimated rendered rows for `lines` wrapped to `width` columns: the ceil
/// of each line's display width. Word-wrap can add a stray row; close enough
/// to clamp the scroll near the true bottom. Pure.
fn estimated_rows(lines: &[Line<'_>], width: u16) -> u16 {
    let w = (width.max(1)) as usize;
    lines
        .iter()
        .map(|l| {
            let lw = l.width();
            if lw == 0 { 1 } else { lw.div_ceil(w) }
        })
        .sum::<usize>()
        .min(u16::MAX as usize) as u16
}

/// Render the raw SIP message text with syntax highlighting.
///
/// Looks up the message via `view.call_id`/`view.message_index`, applies the
/// header-form rewrite, and draws it (highlighted or plain per
/// `view.syntax_highlight`) with wrapping and the stored scroll offset.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full main-pane area for the viewer (block border included).
/// * `store` - Dialog store snapshot the message is read from.
/// * `view` - Navigation and display state (see `RawMessageView`).
///
/// # Returns
/// The estimated content height in rendered rows, so the caller can clamp
/// its stored scroll offset to the content; `0` when the dialog or message
/// is missing (a placeholder notice is drawn instead).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub fn render_raw_message(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    view: &RawMessageView<'_>,
) -> u16 {
    let call_id = view.call_id;
    let message_index = view.message_index;
    let scroll_offset = view.scroll_offset;
    let search_query = view.search_query;
    let theme = view.theme;
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
            return 0;
        }
    };

    let msg = match dialog.messages.get(message_index) {
        Some(m) => m,
        None => {
            let para = Paragraph::new("Message not found.")
                .block(block)
                .style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return 0;
        }
    };

    let (info, raw_text) = raw_display_text(msg, view.header_form);
    let lines = if view.syntax_highlight {
        highlight_sip_message(&info, &raw_text, search_query, theme)
    } else {
        plain_sip_message(&info, &raw_text)
    };
    let total_rows = estimated_rows(&lines, area.width.saturating_sub(2));

    let para = Paragraph::new(lines)
        .block(block)
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, area);
    total_rows
}

/// The exact text the raw view displays for `msg` — the info line plus the
/// header-reformatted raw message — so rendering and search-match
/// navigation always agree on line positions.
///
/// # Returns
/// `(info, raw_text)`: the timestamp/endpoint info line and the raw message
/// text after the `header_form` rewrite. Pure.
pub fn raw_display_text(
    msg: &crate::sip::SipMessage,
    header_form: super::header_form::HeaderFormMode,
) -> (String, String) {
    let info = format!(
        "{} {}:{} -> {}:{} [{}]",
        msg.timestamp.format("%H:%M:%S%.3f"),
        msg.src_addr,
        msg.src_port,
        msg.dst_addr,
        msg.dst_port,
        msg.transport,
    );
    let raw_bytes = String::from_utf8_lossy(&msg.raw);
    let raw_text = super::header_form::reformat_headers(&raw_bytes, header_form).to_string();
    (info, raw_text)
}

/// Wrapped-row scroll offsets of the display lines whose text contains
/// `query`, case-insensitively. The display layout (shared by
/// `plain_sip_message` and `highlight_sip_message`) is: info line, blank,
/// then one line per raw line.
///
/// The raw view scrolls by wrapped rows (`Paragraph` with `Wrap`), so a
/// match's offset is the cumulative wrapped height of every preceding
/// display line — not its unwrapped index. Wrapped height is
/// `ceil(display_width / wrap_width)` (min 1), the same accounting
/// `estimated_rows` uses to clamp the scroll, so n/N lands exactly on the
/// match even when earlier lines wrap. Powers n/N match navigation.
///
/// # Arguments
/// * `wrap_width` - Content width the view wraps at (main-pane width minus
///   the block borders); values below 1 are treated as 1.
///
/// # Returns
/// Ascending wrapped-row offsets of matching lines; empty when `query` is
/// empty or nothing matches. Pure.
pub fn search_match_lines(info: &str, raw_text: &str, query: &str, wrap_width: u16) -> Vec<u16> {
    if query.is_empty() {
        return Vec::new();
    }
    let q = query.to_ascii_lowercase();
    let w = (wrap_width.max(1)) as usize;
    // Wrapped rows a single display line occupies (mirrors `estimated_rows`:
    // an empty line still takes one row).
    let wrapped_height = |text: &str| -> usize {
        let dw = unicode_width::UnicodeWidthStr::width(text);
        if dw == 0 { 1 } else { dw.div_ceil(w) }
    };

    let mut out = Vec::new();
    let mut row: usize = 0;
    let push_if_match = |text: &str, row: usize, out: &mut Vec<u16>| {
        if text.to_ascii_lowercase().contains(&q) {
            out.push(row.min(u16::MAX as usize) as u16);
        }
    };

    // Display line 0: info; display line 1: blank separator.
    push_if_match(info, row, &mut out);
    row += wrapped_height(info);
    row += wrapped_height("");

    // Display lines 2..: one per raw line, each starting at `row`.
    for line in raw_text.lines() {
        push_if_match(line, row, &mut out);
        row += wrapped_height(line);
    }
    out
}

/// Navigation and display state for the combined (transaction/dialog) viewer.
pub struct CombinedDetailView<'a> {
    /// Call-ID of the dialog whose messages are shown.
    pub call_id: &'a str,
    /// Original message indices to show, in order.
    pub indices: &'a [usize],
    /// Scope label for the title (e.g. "Transaction" / "Dialog").
    pub scope: &'a str,
    /// Vertical scroll offset in rendered (wrapped) rows.
    pub scroll_offset: u16,
    /// When `false`, render the messages as plain unstyled text.
    pub syntax_highlight: bool,
    /// Header-name display form (as captured / expanded / compact).
    pub header_form: super::header_form::HeaderFormMode,
    /// Color theme used for all styling.
    pub theme: &'a super::Theme,
}

/// Render several messages' raw detail stacked into one scrollable view —
/// every message of a transaction or dialog read together. `indices` are
/// original positions into the dialog's message list.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full main-pane area for the viewer (block border included).
/// * `store` - Dialog store snapshot the messages are read from.
/// * `view` - Navigation and display state (see `CombinedDetailView`).
///
/// # Returns
/// The estimated content height in rendered rows, so the caller can clamp
/// its stored scroll offset to the content; `0` when the dialog is missing
/// (a placeholder notice is drawn instead). Out-of-range indices are
/// silently skipped.
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub fn render_combined_detail(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    view: &CombinedDetailView<'_>,
) -> u16 {
    let call_id = view.call_id;
    let indices = view.indices;
    let scope = view.scope;
    let scroll_offset = view.scroll_offset;
    let theme = view.theme;
    let title = format!(
        " {scope} detail — {} message(s) (Esc: Back · ↑/↓ PgUp/PgDn scroll) ",
        indices.len()
    );
    let block = Block::default().borders(Borders::ALL).title(title);

    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.")
                .block(block)
                .style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return 0;
        }
    };

    let total = indices.len();
    // Pre-render each message's (possibly header-reformatted) text into
    // owned storage that outlives the styled lines borrowing from it.
    let entries: Vec<(String, String)> = indices
        .iter()
        .filter_map(|&idx| {
            let msg = dialog.messages.get(idx)?;
            let raw_bytes = String::from_utf8_lossy(&msg.raw);
            let text =
                super::header_form::reformat_headers(&raw_bytes, view.header_form).into_owned();
            let info = format!(
                "{} {}:{} -> {}:{} [{}]",
                msg.timestamp.format("%H:%M:%S%.3f"),
                msg.src_addr,
                msg.src_port,
                msg.dst_addr,
                msg.dst_port,
                msg.transport,
            );
            Some((info, text))
        })
        .collect();

    let mut lines: Vec<Line<'_>> = Vec::new();
    for (n, (info, raw_text)) in entries.iter().enumerate() {
        if n > 0 {
            lines.push(Line::from(""));
        }
        // Separator header: position + the message's request/status line.
        let start_line = raw_text.lines().next().unwrap_or("").trim();
        lines.push(Line::from(Span::styled(
            format!("──── [{}/{total}] {start_line} ", n + 1),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        if view.syntax_highlight {
            lines.extend(highlight_sip_message(info, raw_text, "", theme));
        } else {
            lines.extend(plain_sip_message(info, raw_text));
        }
    }

    let total_rows = estimated_rows(&lines, area.width.saturating_sub(2));
    let para = Paragraph::new(lines)
        .block(block)
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
    total_rows
}

/// Plain (unstyled) rendering of a SIP message: the info line followed by
/// the raw text, one Line per row — used when syntax highlighting is off.
fn plain_sip_message(info: &str, raw_text: &str) -> Vec<Line<'static>> {
    let mut lines = vec![Line::raw(info.to_string()), Line::raw("")];
    for l in raw_text.lines() {
        lines.push(Line::raw(l.to_string()));
    }
    lines
}

// ── Syntax highlighting ─────────────────────────────────────────────

/// Highlight a SIP message with basic syntax coloring.
///
/// - First line (method/status): bold
/// - Header names: cyan
/// - Header values: default
/// - SDP body: dimmed/italic
/// - Search matches: highlighted background
///
/// # Returns
/// The styled display lines: info line, blank, then one line per raw line
/// (headers and body). Pure.
fn highlight_sip_message<'a>(
    info: &str,
    raw_text: &str,
    search_query: &str,
    theme: &super::Theme,
) -> Vec<Line<'a>> {
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

/// Highlight occurrences of `query` in a line with a colored background,
/// case-insensitively; non-matching segments keep `base_style`. Pure.
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
        spans.push(Span::styled(line[start..end].to_string(), highlight_style));
        last_end = end;
    }

    if last_end < line.len() {
        spans.push(Span::styled(line[last_end..].to_string(), base_style));
    }

    Line::from(spans)
}

// ── Tests ───────────────────────────────────────────────────────────

/// Unit tests for search highlighting and message styling.
#[cfg(test)]
mod tests {
    use super::*;

    /// A query with no occurrence yields a single unhighlighted span.
    #[test]
    fn highlight_search_in_line_no_match() {
        let line = highlight_search_in_line("Hello World", "xyz", Style::default());
        assert_eq!(line.spans.len(), 1);
    }

    /// Repeated matches split the line into alternating match/text spans.
    #[test]
    fn highlight_search_in_line_with_match() {
        let line = highlight_search_in_line("Hello World Hello", "Hello", Style::default());
        // "Hello" appears twice, so we get: match, " World ", match
        assert!(line.spans.len() >= 3);
    }

    /// Lowercase query still highlights an uppercase occurrence.
    #[test]
    fn highlight_search_case_insensitive() {
        let line = highlight_search_in_line("INVITE sip:foo", "invite", Style::default());
        assert!(line.spans.len() >= 2);
    }

    /// The raw view scrolls by wrapped rows, so a match's scroll offset
    /// must count the wrapped height of every preceding display line — not
    /// its unwrapped line index. With a line before the match wrapping to
    /// several rows, the two disagree, and n/N lands short if the unwrapped
    /// index is used.
    #[test]
    fn search_match_lines_maps_to_wrapped_row_offset() {
        // At width 10: info(1 row) + blank(1 row) + a 20-col line(2 rows)
        // put the matching 23-col line at wrapped row 4 — while its
        // unwrapped display index would be only 3.
        let info = "info";
        let raw_text = "AAAAAAAAAAAAAAAAAAAA\nBBBBBBBBBB MATCHME BBBB";
        let rows = search_match_lines(info, raw_text, "matchme", 10);
        assert_eq!(
            rows,
            vec![4],
            "match offset must be the wrapped-row start of the line, not its \
             unwrapped index (3)"
        );
    }

    /// With no wrapping (width wider than every line) the wrapped-row
    /// offsets collapse back to the plain display-line indices: info at 0,
    /// the second raw line at 3 (info, blank, line0, line1).
    #[test]
    fn search_match_lines_unwrapped_matches_display_indices() {
        let info = "INVITE probe";
        let raw_text = "Via: udp\nCSeq: 1 INVITE";
        let rows = search_match_lines(info, raw_text, "cseq", 200);
        assert_eq!(rows, vec![3]);
    }

    /// A minimal INVITE produces the expected line layout: info, blank,
    /// start-line, header, body separator, SDP line.
    #[test]
    fn highlight_sip_message_basic() {
        let theme = crate::tui::Theme::default();
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\nFrom: alice\r\n\r\nv=0\r\n";
        let lines = highlight_sip_message("info line", raw, "", &theme);
        // info + blank + first line + header + blank separator + sdp line
        assert!(lines.len() >= 4);
    }
}
