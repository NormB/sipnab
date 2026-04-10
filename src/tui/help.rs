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
sipnab v0.1.0-alpha \u{2014} Keyboard Shortcuts

Navigation:
  \u{2191}/\u{2193} or j/k     Scroll list / view
  Enter           Open selected item
  Esc             Go back to previous view
  Tab             Switch between Call List / Stream List
  Home / End      Jump to first / last item
  PgUp / PgDn     Scroll by page
  q               Quit sipnab
  Ctrl-C          Force quit

Views:
  F1              Toggle this help screen
  F2              Save dialog (placeholder)
  F7              Open filter dialog
  s               Statistics view
  /               Search within current view

Call List:
  Space           Toggle multi-select on current row
  Enter           Open Call Flow for selected dialog

Call Flow:
  \u{2191}/\u{2193}             Scroll through messages
  Enter           View raw SIP message at current position
  Esc             Return to Call List

Raw Message:
  \u{2191}/\u{2193}             Scroll message text
  PgUp / PgDn     Page scroll
  /               Search within message (highlights matches)
  Esc             Return to Call Flow

Stream List:
  Tab             Switch back to Call List
  Esc             Return to Call List

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
    fn help_text_contains_navigation() {
        assert!(HELP_TEXT.contains("Navigation:"));
    }

    #[test]
    fn help_text_contains_quit() {
        assert!(HELP_TEXT.contains("Quit"));
    }

    #[test]
    fn help_text_contains_call_list() {
        assert!(HELP_TEXT.contains("Call List:"));
    }

    #[test]
    fn help_text_contains_call_flow() {
        assert!(HELP_TEXT.contains("Call Flow:"));
    }

    #[test]
    fn help_text_contains_raw_message() {
        assert!(HELP_TEXT.contains("Raw Message:"));
    }

    #[test]
    fn help_text_contains_stream_list() {
        assert!(HELP_TEXT.contains("Stream List:"));
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
