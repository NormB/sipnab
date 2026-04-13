//! Help view — keybinding reference overlay.
//!
//! Displays a categorized reference of all keyboard shortcuts available
//! in the TUI. Rendered as a styled [`Paragraph`] widget.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
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
  F5               Clear calls
  F6               Show raw SIP message
  F7               Filter dialog
  F9               Clear active filter
  F10              Column selector
  Tab              Switch to RTP Streams

CALL FLOW:
  \u{2191}/\u{2193}             Navigate messages (detail panel updates)
  PgUp/PgDn       Page through messages
  Home/End         First/last message
  Enter            Full-screen raw message
  Space            Select message for diff (press twice to compare)
  Esc              Back to call list
  d                Cycle SDP display (none / summary / full)
  t                Cycle timestamps (absolute / delta-prev / delta-first)
  c                Cycle colors (method / call-id / cseq)
  R                Toggle detail panel
  9/0, +/-, ←/→    Resize ladder/detail split
  [ / ]            Scroll detail panel
  F2               Save
  F4, x            Extended multi-leg flow
  F6               Toggle RTP display

RAW MESSAGE:
  \u{2191}/\u{2193}             Scroll
  PgUp/PgDn       Page scroll
  /                Search in message
  s                Toggle syntax highlighting
  c                Cycle colors
  Esc              Back to call flow

RTP STREAMS (Tab):
  \u{2191}/\u{2193}             Navigate streams
  Tab              Switch to Call List
  F1               Help
  F7               Filter
  Esc              Back to Call List

Press Esc or F1 to close this help.";

/// Render the help view.
pub fn render_help(frame: &mut Frame, area: Rect) {
    let lines = build_help_lines();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help (Esc to close) ");

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

/// Build styled help lines from the help text.
fn build_help_lines() -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    for text_line in HELP_TEXT.lines() {
        if text_line.starts_with("sipnab") {
            // Title line
            lines.push(Line::from(Span::styled(
                text_line.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
        } else if !text_line.starts_with(' ') && text_line.ends_with(':') {
            // Section headers
            lines.push(Line::from(Span::styled(
                text_line.to_string(),
                Style::default()
                    .fg(Color::Yellow)
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
                    Span::styled(
                        format!("{:<18}", key_part),
                        Style::default().fg(Color::Green),
                    ),
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
                Style::default().fg(Color::DarkGray),
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
        let lines = build_help_lines();
        assert!(!lines.is_empty());
        assert!(lines.len() > 10);
    }
}
