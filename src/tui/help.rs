// SPDX-License-Identifier: MIT OR Apache-2.0

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
  /                Search (arrows/Space work while typing; Enter opens)
  i                Clear non-matching dialogs
  I                Clear matching dialogs
  F1, ?            This help (? works in every view)
  F2               Save capture (Tab cycles PCAP/TXT/JSON/WAV/Mermaid/...)
  F3               Search (same as /)
  F5, Ctrl+L       Clear calls
  r, F6            Show raw SIP message
  F7               Filter dialog
  F8               Settings
  t                Cycle timestamps (absolute / delta-prev / delta-first / scaled)
  u                Cycle From/To (default/host:port/user/user@host:port)
  n                Cycle name resolution (off/static/DNS) \u{2014} global
  N                Name selected address (IP -> host / FQDN)
  O                Open pcap file
  s                Statistics view
  D                Quality dashboard (live MOS/jitter/loss)
  T                Call timeline (selected dialog)
  F9               Clear active filter
  F10              Column selector
  Tab              Switch to RTP Streams
  v                Show version / git commit \u{2014} global

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
  t                Cycle timestamps (absolute / delta-prev / delta-first / scaled)
  c                Cycle colors (method / call-id / cseq)
  h                Header names (as captured / expanded / compact)
  R                Toggle detail panel
  w                Toggle line wrap in the detail panel
  m / M            Mark message / clear marks
  e                Fold / expand retransmits
  E                Export Mermaid sequence diagram
  9/0, +/-, ←/→    Resize ladder/detail split
  ←/→              Scroll detail horizontally (focused, wrap off)
  [ / ]            Scroll detail panel (any focus)
  F2               Save
  F4, x            Extended multi-leg flow
  F6, Ctrl-R       Toggle RTP display
  r                Jump to RTP Streams
  N                Name endpoints (Tab/Shift-Tab between participants)

RAW MESSAGE:
  \u{2191}/\u{2193}             Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  /                Search in message
  n / N            Next / previous search match (wraps)
  s                Toggle syntax highlighting
  c                Cycle colors
  h                Header names (as captured / expanded / compact)
  Esc              Back to previous view

MESSAGE DIFF / COMBINED DETAIL / STATISTICS:
  \u{2191}/\u{2193}, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  h                Header names (diff and combined detail)
  Esc              Back
  q, s             Close statistics (Statistics view)

QUALITY DASHBOARD:
  \u{2191}/\u{2193}, j/k       Select stream (worst quality first)
  PgUp/PgDn       Page through streams
  Home/End         Jump to best/worst
  Enter            Open stream detail
  Esc, q, D        Close dashboard

RTP STREAMS (Tab):
  \u{2191}/\u{2193}             Navigate streams
  PgUp/PgDn       Page scroll
  /                Search streams (arrows work while typing; Enter opens)
  Enter            Stream detail
  D                Quality dashboard (live MOS/jitter/loss)
  Tab              Switch to Call List
  F1               Help
  F7               Filter
  N                Name selected address (IP -> host / FQDN)
  Esc              Back to Call List

STREAM DETAIL:
  \u{2191}/\u{2193}             Scroll
  PgUp/PgDn, Home/End  Page / jump
  Shift+P          Play / stop audio (G.711, audio build)
  Esc              Back to RTP Streams

Mouse wheel scrolls every view.

Press Esc or F1 to close this help.";

/// Render the help view.
///
/// # Arguments
///
/// * `frame` — frame to draw into.
/// * `area` — screen rectangle the help box fills.
/// * `theme` — colors for the title, headers, keys and muted text.
/// * `version` — version string shown under the title (truncated to the
///   box width).
/// * `scroll` — vertical scroll offset in lines.
///
/// # Side effects
///
/// Draws a bordered, wrapped paragraph widget into `frame`.
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
///
/// # Arguments
///
/// * `theme` — colors applied per line class (title, section, key, muted).
/// * `version` — version string inserted under the title line.
/// * `inner_width` — box inner width the version line is truncated to.
///
/// # Returns
///
/// One styled `Line` per `HELP_TEXT` line plus the inserted version line:
/// the title bold in the header color, section headers bold in the
/// selected color, keybinding lines split into a padded key column and
/// description, everything else muted.
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
///
/// # Returns
///
/// Byte offset in `line` of the first space of that gap, or `None` when
/// no such multi-space boundary follows a non-space character.
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

/// Tests pinning the help text's section/key coverage, the styled-line
/// builder, and the width-truncation helper.
#[cfg(test)]
mod tests {
    use super::*;

    /// The help text documents the CALL LIST section.
    #[test]
    fn help_text_contains_call_list() {
        assert!(HELP_TEXT.contains("CALL LIST:"));
    }

    /// The help text documents how to quit.
    #[test]
    fn help_text_contains_quit() {
        assert!(HELP_TEXT.contains("Quit"));
    }

    /// The help text documents the CALL FLOW section.
    #[test]
    fn help_text_contains_call_flow() {
        assert!(HELP_TEXT.contains("CALL FLOW:"));
    }

    /// The help text documents the RAW MESSAGE section.
    #[test]
    fn help_text_contains_raw_message() {
        assert!(HELP_TEXT.contains("RAW MESSAGE:"));
    }

    /// The help text documents the RTP STREAMS section.
    #[test]
    fn help_text_contains_rtp_streams() {
        assert!(HELP_TEXT.contains("RTP STREAMS"));
    }

    /// The help text mentions the F1 help key.
    #[test]
    fn help_text_contains_f1() {
        assert!(HELP_TEXT.contains("F1"));
    }

    /// The help text mentions the F7 filter key.
    #[test]
    fn help_text_contains_f7() {
        assert!(HELP_TEXT.contains("F7"));
    }

    /// The help text mentions the Enter key.
    #[test]
    fn help_text_contains_enter() {
        assert!(HELP_TEXT.contains("Enter"));
    }

    /// The help text mentions the Esc key.
    #[test]
    fn help_text_contains_esc() {
        assert!(HELP_TEXT.contains("Esc"));
    }

    /// The styled-line builder produces a substantial number of lines.
    #[test]
    fn build_help_lines_non_empty() {
        let theme = crate::tui::Theme::default();
        let lines = build_help_lines(&theme, "1.2.3", 78);
        assert!(!lines.is_empty());
        assert!(lines.len() > 10);
    }

    /// The help text documents the `v` show-version key.
    #[test]
    fn help_text_documents_version_key() {
        assert!(HELP_TEXT.contains("Show version"));
    }

    /// The injected version string appears in the rendered lines (just
    /// under the title).
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

    /// Strings at or under the width limit pass through unchanged.
    #[test]
    fn truncate_to_width_passes_short_strings_through() {
        assert_eq!(truncate_to_width("v1.2.3", 78), "v1.2.3");
        // Exactly at the limit is untouched.
        assert_eq!(truncate_to_width("abcd", 4), "abcd");
    }

    /// Overflowing strings are cut to width-1 chars plus an ellipsis.
    #[test]
    fn truncate_to_width_elides_overflow() {
        // 5 chars into width 4 -> 3 kept + ellipsis, total 4 columns.
        let out = truncate_to_width("abcde", 4);
        assert_eq!(out, "abc\u{2026}");
        assert_eq!(out.chars().count(), 4);
    }

    /// A zero-column width yields an empty string (no panic).
    #[test]
    fn truncate_to_width_zero_width_is_empty() {
        assert_eq!(truncate_to_width("anything", 0), "");
    }

    /// A realistic long version string is elided to fit the 78-column box.
    #[test]
    fn truncate_to_width_long_version_fits_in_box() {
        let v =
            "v0.4.3 (v0.4.3 a84ac0ca-dirty) features: native,tui,audio,tls,hep,api,mcp,mcp-http";
        let out = truncate_to_width(v, 78);
        assert!(out.chars().count() <= 78);
        assert!(out.ends_with('\u{2026}'));
    }

    /// Multibyte and control characters truncate on char boundaries
    /// without panicking.
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
