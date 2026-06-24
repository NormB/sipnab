//! Help view — keybinding reference overlay.
//!
//! Displays a categorized reference of all keyboard shortcuts available
//! in the TUI. Rendered as a styled [`Paragraph`] widget.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

/// The full help text as a constant for testing.
pub const HELP_TEXT: &str = "\
sipnab \u{2014} Keyboard Shortcuts

CALL LIST:
  \u{2191}/\u{2193}, j/k       Navigate dialogs
  PgUp/PgDn       Page scroll
  Home/End         Jump to first/last
  Enter            Open call flow
  Space            Select/deselect dialog
  Esc, q           Quit
  < / >            Change sort column
  Z                Reverse sort direction
  A                Toggle autoscroll
  p                Pause/resume capture
  /                Search
  i                Clear non-matching dialogs
  I                Clear matching dialogs
  F1               This help
  F2               Save capture (PCAP/PCAP-NG/TXT)
  F3               Search (same as /)
  F5, Ctrl+L       Clear calls
  r, F6            Show raw SIP message
  F7               Filter dialog
  F8               Settings
  t                Cycle timestamps (absolute / delta-prev / delta-first)
  u                Cycle From/To column (user / host:port / both)
  n                Cycle name resolution (off / static / DNS)
  N                Name selected address (IP -> host / FQDN)
  O                Open pcap file
  s                Statistics view
  F9               Clear active filter
  F10              Column selector
  Tab              Switch to RTP Streams
  v                Show version / git commit

CALL FLOW:
  \u{2191}/\u{2193}             Navigate messages (detail panel updates)
  PgUp/PgDn       Page through messages
  Home/End         First/last message
  Enter            Full-screen raw message
  Space            Select message for diff (press twice to compare)
  a / A            Combined detail: this transaction / whole dialog
  f                Filter ladder to this transaction (toggle)
  Esc              Back to call list
  Tab              Switch focus: ladder <-> detail pane
  \u{2191}/\u{2193}             Navigate ladder, or scroll detail when focused
  d                Cycle SDP display (none / summary / full)
  t                Cycle timestamps (absolute / delta-prev / delta-first)
  c                Cycle colors (method / call-id / cseq)
  R                Toggle detail panel
  m / M            Mark message / clear marks
  e                Fold / expand retransmits
  E                Export Mermaid sequence diagram
  9/0, +/-, ←/→    Resize ladder/detail split
  [ / ]            Scroll detail panel (any focus)
  F2               Save
  F4, x            Extended multi-leg flow
  F6, Ctrl-R       Toggle RTP display
  r                Jump to RTP Streams
  N                Name endpoints (Tab/Shift-Tab between participants)

RAW MESSAGE:
  \u{2191}/\u{2193}             Scroll
  PgUp/PgDn       Page scroll
  /                Search in message
  s                Toggle syntax highlighting
  c                Cycle colors
  Esc              Back to call flow

RTP STREAMS (Tab):
  \u{2191}/\u{2193}             Navigate streams
  Enter            Stream detail
  Tab              Switch to Call List
  F1               Help
  F7               Filter
  N                Name selected address (IP -> host / FQDN)
  Esc              Back to Call List

STREAM DETAIL:
  \u{2191}/\u{2193}             Scroll
  Shift+P          Play / stop audio (G.711, audio build)
  Esc              Back to RTP Streams

Press Esc or F1 to close this help.";

/// Render the help view.
pub fn render_help(
    frame: &mut Frame,
    area: Rect,
    theme: &super::Theme,
    version: &str,
    scroll: u16,
) {
    // Inner width inside the bordered block (one column per side border). The
    // version line is constrained to this width so a long version string
    // (tag + commit + "-dirty" + the full feature list) cannot wrap onto a
    // second row and push the last keybinding off the bottom of the box.
    let inner_width = area.width.saturating_sub(2) as usize;
    let lines = build_help_lines(theme, version, inner_width);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help (\u{2191}/\u{2193} scroll, Esc to close) ");

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    frame.render_widget(paragraph, area);
}

/// Number of rendered help lines (one per `HELP_TEXT` line, plus the version
/// line inserted under the title). Used to clamp the scroll offset.
pub fn help_line_count() -> usize {
    HELP_TEXT.lines().count() + 1
}

/// Build styled help lines from the help text.
fn build_help_lines(theme: &super::Theme, version: &str, inner_width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    for text_line in HELP_TEXT.lines() {
        if text_line.starts_with("sipnab") {
            // Title line
            lines.push(Line::from(Span::styled(
                text_line.to_string(),
                Style::default()
                    .fg(theme.header)
                    .add_modifier(Modifier::BOLD),
            )));
            // Version (with git commit + enabled features) just under the title.
            // Truncate to the box width so a long version (tag + commit +
            // "-dirty" + full feature list) renders on a single row instead of
            // wrapping and pushing the last keybinding off the bottom.
            lines.push(Line::from(Span::styled(
                truncate_to_width(&format!("v{version}"), inner_width),
                Style::default().fg(theme.muted),
            )));
        } else if !text_line.starts_with(' ') && text_line.ends_with(':') {
            // Section headers
            lines.push(Line::from(Span::styled(
                text_line.to_string(),
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD),
            )));
        } else if text_line.starts_with("  ") && text_line.contains("  ") {
            // Key binding line — split at the multi-space boundary
            let trimmed = text_line.trim_start();
            if let Some(split_pos) = find_description_start(trimmed) {
                let key_part = &trimmed[..split_pos];
                let desc_part = trimmed[split_pos..].trim_start();
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{:<18}", key_part), Style::default().fg(theme.good)),
                    Span::raw(desc_part.to_string()),
                ]));
            } else {
                lines.push(Line::from(Span::raw(text_line.to_string())));
            }
        } else if text_line.trim().is_empty() {
            lines.push(Line::from(""));
        } else {
            lines.push(Line::from(Span::styled(
                text_line.to_string(),
                Style::default().fg(theme.muted),
            )));
        }
    }

    lines
}

/// Find the position where the description starts in a key binding line.
///
/// Looks for two or more consecutive spaces after the key name.
fn find_description_start(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    // Skip leading non-space characters (the key part)
    let mut found_key = false;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            if found_key {
                // Check for at least 2 spaces
                if i + 1 < bytes.len() && bytes[i + 1] == b' ' {
                    return Some(i);
                }
            }
        } else {
            found_key = true;
        }
        i += 1;
    }
    None
}

/// Truncate `s` to at most `max` display columns, appending an ellipsis ('…')
/// when it would otherwise overflow. The help version string is ASCII (semver,
/// hex commit, "-dirty", feature names) so a char count equals its column
/// width; the ellipsis itself occupies the final column when truncating.
fn truncate_to_width(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('\u{2026}');
    out
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_text_contains_call_list() {
        assert!(HELP_TEXT.contains("CALL LIST:"));
    }

    #[test]
    fn help_text_contains_quit() {
        assert!(HELP_TEXT.contains("Quit"));
    }

    #[test]
    fn help_text_contains_call_flow() {
        assert!(HELP_TEXT.contains("CALL FLOW:"));
    }

    #[test]
    fn help_text_contains_raw_message() {
        assert!(HELP_TEXT.contains("RAW MESSAGE:"));
    }

    #[test]
    fn help_text_contains_rtp_streams() {
        assert!(HELP_TEXT.contains("RTP STREAMS"));
    }

    #[test]
    fn help_text_contains_f1() {
        assert!(HELP_TEXT.contains("F1"));
    }

    #[test]
    fn help_text_contains_f7() {
        assert!(HELP_TEXT.contains("F7"));
    }

    #[test]
    fn help_text_contains_enter() {
        assert!(HELP_TEXT.contains("Enter"));
    }

    #[test]
    fn help_text_contains_esc() {
        assert!(HELP_TEXT.contains("Esc"));
    }

    #[test]
    fn build_help_lines_non_empty() {
        let theme = crate::tui::Theme::default();
        let lines = build_help_lines(&theme, "1.2.3", 78);
        assert!(!lines.is_empty());
        assert!(lines.len() > 10);
    }

    #[test]
    fn help_text_documents_version_key() {
        assert!(HELP_TEXT.contains("Show version"));
    }

    #[test]
    fn build_help_lines_includes_version() {
        let theme = crate::tui::Theme::default();
        let lines = build_help_lines(&theme, "9.9.9 (abc) features: tui", 78);
        // The injected version appears on the line just under the title.
        let rendered: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            rendered.contains("9.9.9 (abc) features: tui"),
            "got: {rendered}"
        );
    }

    #[test]
    fn truncate_to_width_passes_short_strings_through() {
        assert_eq!(truncate_to_width("v1.2.3", 78), "v1.2.3");
        // Exactly at the limit is untouched.
        assert_eq!(truncate_to_width("abcd", 4), "abcd");
    }

    #[test]
    fn truncate_to_width_elides_overflow() {
        // 5 chars into width 4 -> 3 kept + ellipsis, total 4 columns.
        let out = truncate_to_width("abcde", 4);
        assert_eq!(out, "abc\u{2026}");
        assert_eq!(out.chars().count(), 4);
    }

    #[test]
    fn truncate_to_width_zero_width_is_empty() {
        assert_eq!(truncate_to_width("anything", 0), "");
    }

    #[test]
    fn truncate_to_width_long_version_fits_in_box() {
        let v =
            "v0.4.3 (v0.4.3 a84ac0ca-dirty) features: native,tui,audio,tls,hep,api,mcp,mcp-http";
        let out = truncate_to_width(v, 78);
        assert!(out.chars().count() <= 78);
        assert!(out.ends_with('\u{2026}'));
    }

    #[test]
    fn truncate_to_width_handles_multibyte_and_control_chars() {
        // Backslashes / embedded control chars must not panic or split a char.
        assert_eq!(truncate_to_width("a\\b\tc", 99), "a\\b\tc");
        // Multibyte input truncated on a char boundary (no byte-slice panic).
        let out = truncate_to_width("ααααα", 3);
        assert_eq!(out.chars().count(), 3);
        assert!(out.ends_with('\u{2026}'));
    }
}
