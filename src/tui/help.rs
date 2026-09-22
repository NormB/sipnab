// SPDX-License-Identifier: MIT OR Apache-2.0

//! Help view — keybinding reference overlay.
//!
//! Displays a categorized reference of all keyboard shortcuts available
//! in the TUI. Rendered as a styled [`Paragraph`] widget.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// The full help text as a constant for testing.
pub const HELP_TEXT: &str = "\
sipnab \u{2014} Keyboard Shortcuts

CALL LIST:
  \u{2191}/\u{2193}, j/k       Navigate dialogs
  PgUp/PgDn       Page scroll
  Home/End         Jump to first/last
  Enter            Open call flow
  Space            Select/deselect dialog
  Esc, q           Quit (asks first, Ctrl+C quits at once)
  < / >            Change sort column
  Z                Reverse sort direction
  A                Toggle autoscroll
  p                Pause/resume capture
  /                Search (arrows/Space work while typing; Enter opens)
  i                Clear non-matching dialogs
  I                Clear matching dialogs
  F1, ?            This help (? works in every view)
  F2               Save capture: PCAP, PCAP-NG, TXT, SIPp, JSON, NDJSON, CSV, HTML (Mermaid ladder), Markdown, WAV, RTP JSON, NOTES (Tab cycles)
  F3               Search (same as /)
  F5, Ctrl+L       Clear calls
  r, F6            Show raw SIP message
  F7               Filter dialog
  F8               Settings
  t                Cycle timestamps (absolute / delta from previous / delta from first / scaled)
  u                Cycle From/To (default/host:port/user/user@host:port)
  n                Cycle name resolution (off/static/DNS) \u{2014} global
  N                Name selected address (IP -> host / FQDN)
  O                Open pcap file
  s                Statistics view
  g                Top talkers (busiest participants, by source IP)
  m                Carrier metrics (ASR/NER/ACD by destination IP)
  c                Compare two checked calls (Space to check exactly two)
  e                Endpoint rollup (everything this call's source did)
  h                Capture health (dropped/undecodable/NAT counters)
  b                Call volume histogram (calls per time bucket)
  o                SDP offer/answer timeline of the selected call
  f                RFC conformance findings of the selected call
  x                TFPS observe (enforcing peer's bans and drop counters)
  a                Security findings (armed detectors' alerts)
  S                Relay statistics view (asks the relay)
  B                Edit the BPF capture filter (append)
  D                Quality dashboard (live MOS/jitter/loss)
  T                Call timeline (selected dialog)
  F9               Clear the view filter and search
  F10              Choose columns
  Tab              Switch to RTP streams
  v                Show version / git commit \u{2014} global

CALL FLOW:
  \u{2191}/\u{2193}             Move through messages, or scroll the detail pane when it has focus
  PgUp/PgDn       Page through messages
  Home/End         First/last message
  Enter            Full-screen raw message
  Space            Select message for diff (press twice to compare)
  a / A            Combined detail: this transaction / whole dialog
  f                Filter ladder to this transaction (toggle)
  Esc              Back to call list
  Tab              Switch focus: ladder <-> detail pane
  d                Cycle SDP display (hidden / summary / full)
  t                Cycle timestamps (absolute / delta from previous / delta from first / scaled)
  c                Cycle colors (method / Call-ID / CSeq)
  h                Header names (as captured / expanded / compact)
  R                Show or hide the detail pane
  w                Toggle line wrap in the detail pane
  m / M            Mark message / clear marks
  e                Fold / expand retransmits
  E                Export Mermaid sequence diagram
  C                Operator note on this message (yours, never analysis)
  9/0, +/-, ←/→    Resize the detail pane
  ←/→              Scroll detail horizontally (focused, wrap off)
  [ / ]            Scroll the detail pane (any focus)
  F2               Save
  F4, x            Extended multi-leg flow
  F6, Ctrl+R       Toggle RTP display
  r                Jump to RTP Streams
  N                Name endpoints (Tab/Shift+Tab between participants)

RAW MESSAGE:
  \u{2191}/\u{2193}             Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  /                Search in message
  n / N            Next / previous search match (wraps)
  s                Toggle syntax colors
  c                Cycle colors
  h                Header names (as captured / expanded / compact)
  y                Copy displayed message to clipboard (OSC 52)
  C                Operator note on this message
  Esc              Back to previous view

MESSAGE DIFF / COMBINED DETAIL / STATISTICS:
  \u{2191}/\u{2193}, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  h                Header names (diff and combined detail)
  Esc              Back
  q, s             Close statistics (Statistics view)

TOP TALKERS:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, g        Close

CARRIER METRICS:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, m        Close

COMPARE TWO CALLS:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, c        Close

ENDPOINT ROLLUP:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, e        Close

CAPTURE HEALTH:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  s                HEP senders (who feeds the -L listener)
  Esc, q, h        Close

HEP SENDERS:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, s        Back to capture health

CALL VOLUME HISTOGRAM:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, b        Close

SDP OFFER/ANSWER TIMELINE:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, o        Close

RFC CONFORMANCE:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, f        Close

TFPS OBSERVE:
  b                Banned sources
  d                Drop counters
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Esc, q, x        Close

SECURITY FINDINGS:
  ↑/↓, j/k       Scroll
  PgUp/PgDn       Page scroll
  Home/End         Jump to top/bottom
  Esc, q, a        Close

RELAY STATISTICS VIEW (S asks the relay directly):
  ?                Names the relay knows (what to ask for)
  K                Compare relay vs capture (per-call)
  H                What the relay is holding now (Call-IDs)
  \u{2191}/\u{2193}, j/k       Scroll
  Esc, S           Close

QUALITY DASHBOARD:
  \u{2191}/\u{2193}, j/k       Select stream (worst quality first)
  PgUp/PgDn       Page through streams
  Home/End         Jump to best/worst
  Enter            Open stream detail
  L                Packet loss map (RTP loss pattern)
  Esc, q, D        Close

RTP STREAMS (Tab):
  \u{2191}/\u{2193}             Navigate streams
  PgUp/PgDn       Page scroll
  /                Search streams (arrows work while typing; Enter opens)
  Enter            Stream detail
  D                Quality dashboard (live MOS/jitter/loss)
  Tab              Switch to the call list
  F1               Help
  F7               Filter
  N                Name selected address (IP -> host / FQDN)
  Esc              Back to the call list

STREAM DETAIL:
  \u{2191}/\u{2193}             Scroll
  PgUp/PgDn, Home/End  Page / jump
  Shift+P          Play / stop audio (G.711, audio build)
  L                Packet loss map (RTP loss pattern)
  Esc              Back to RTP streams

TERMS:
  ASR      Answer-seizure ratio: share of call attempts answered
  NER      Network effectiveness ratio: far end answered or refused
  ACD      Average call duration of answered calls
  PDD      Post-dial delay: INVITE to the first 180 or 183
  MOS      Mean opinion score: call quality, 1 to 5, higher is better
  SSRC     Synchronization source: the ID of one RTP stream
  BPF      Berkeley Packet Filter: the kernel's capture filter
  HEP      Homer Encapsulation Protocol: SIP mirrored by a proxy
  TFPS     Optional peer that bans sources (sipnab only asks it)

ARCHIVE PASSWORD (a load waits on an encrypted archive member):
  Enter            Try the password (three attempts per archive)
  Esc              Skip this archive's locked members
  Ctrl-R           Show or hide what you typed, until the next attempt
  Ctrl-U           Clear the entry

COPY & PASTE:
  y                Copy displayed message to clipboard (raw message view)
  E                Export Mermaid diagram to clipboard (call flow view)
  F12              Toggle mouse capture for native drag-to-select \u{2014} global

VCON EXPORT (one call, for handing to somebody else):
A call exports as a vCon of what sipnab observed (the ladder, audio if kept).
sipnab signs nothing, and each states what it lost: GET /v1/dialogs/<id>/vcon

Copies use OSC 52, which works over SSH (most modern terminals support it).
Mouse wheel scrolls or moves the selection in the scrollable views while
capture is on (the call timeline is a single fixed screen — nothing to
scroll); with capture off (F12), drag selects text natively.
Shift+drag bypasses capture in many terminals.

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
/// * `libpcap` — the running libpcap's summary line, shown under the version
///   (truncated the same way).
/// * `scroll` — vertical scroll offset in lines.
///
/// # Side effects
///
/// Draws a bordered paragraph of pre-wrapped rows into `frame`.
pub fn render_help(
    frame: &mut Frame,
    area: Rect,
    theme: &super::Theme,
    version: &str,
    libpcap: &str,
    scroll: u16,
) {
    // Inner width inside the bordered block (one column per side border). The
    // version line is constrained to this width so a long version string
    // (tag + commit + "-dirty" + the full feature list) cannot wrap onto a
    // second row and push the last keybinding off the bottom of the box.
    let inner_width = area.width.saturating_sub(2) as usize;
    let lines = build_help_lines(theme, version, libpcap, inner_width);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help (\u{2191}/\u{2193} scroll, Esc close) ");

    // Pre-wrapped by `build_help_lines`, so the rows drawn are the rows
    // `help_line_count` counts.
    let paragraph = Paragraph::new(lines).block(block).scroll((scroll, 0));

    frame.render_widget(paragraph, area);
}

/// Number of rendered help rows at `inner_width` columns: every `HELP_TEXT`
/// line as the builder wraps it, plus the version and libpcap rows inserted
/// under the title. Used to clamp the scroll offset, so it counts exactly
/// what [`render_help`] draws; counting source lines instead left the end of
/// the help unreachable once wrapped lines outnumbered the slack.
pub fn help_line_count(inner_width: usize) -> usize {
    build_help_lines(&super::Theme::default(), "", "", inner_width).len()
}

/// Build styled help lines from the help text.
///
/// # Arguments
///
/// * `theme` — colors applied per line class (title, section, key, muted).
/// * `version` — version string inserted under the title line.
/// * `libpcap` — the running libpcap's summary line, inserted under the
///   version.
/// * `inner_width` — box inner width the version and libpcap lines are
///   truncated to.
///
/// # Returns
///
/// One styled `Line` per `HELP_TEXT` line plus the inserted version and
/// libpcap lines: the title bold in the header color, section headers bold
/// in the selected color, keybinding lines split into a padded key column
/// and description, everything else muted.
fn build_help_lines(
    theme: &super::Theme,
    version: &str,
    libpcap: &str,
    inner_width: usize,
) -> Vec<Line<'static>> {
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
            // The running libpcap, the report `--version` prints, on its own
            // row and truncated the same way: which alternate capture backends
            // this binary can reach is decided by that library, not by sipnab.
            lines.push(Line::from(Span::styled(
                truncate_to_width(libpcap, inner_width),
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
                // The description wraps under itself, never under the key
                // column, so a long line still reads as one binding. The key
                // always keeps a space after it, even when it overflows the
                // column (`PgUp/PgDn, Home/End` ran into its description).
                let rows = crate::tui::render::wrap_to_width(
                    desc_part,
                    u16::try_from(inner_width.saturating_sub(HELP_DESC_COL))
                        .unwrap_or(u16::MAX)
                        .max(HELP_MIN_DESC_COLS),
                );
                for (i, row) in rows.into_iter().enumerate() {
                    let key = if i == 0 { key_part } else { "" };
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(format!("{key:<17} "), Style::default().fg(theme.good)),
                        Span::raw(row),
                    ]));
                }
            } else {
                lines.push(Line::from(Span::raw(text_line.to_string())));
            }
        } else if text_line.trim().is_empty() {
            lines.push(Line::from(""));
        } else {
            let width = u16::try_from(inner_width).unwrap_or(u16::MAX).max(1);
            for row in crate::tui::render::wrap_to_width(text_line, width) {
                lines.push(Line::from(Span::styled(
                    row,
                    Style::default().fg(theme.muted),
                )));
            }
        }
    }

    lines
}

/// The column a binding's description starts at: two spaces of indent plus
/// the 18-column key field.
const HELP_DESC_COL: usize = 20;

/// The narrowest a wrapped description is allowed to get on a tiny screen.
const HELP_MIN_DESC_COLS: u16 = 10;

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

    /// The number of rendered help lines MUST equal [`help_line_count`],
    /// which the scroll clamp trusts. This ties the hardcoded `+2` for the
    /// synthesized version and libpcap lines to the actual builder: any
    /// future `HELP_TEXT` edit (or builder change) that adds or drops a line
    /// the count does not account for — e.g. a third synthesized line, or the
    /// version line being removed — desyncs the two and fails here.
    #[test]
    fn rendered_help_line_count_matches_help_line_count() {
        let theme = crate::tui::Theme::default();
        for width in [40usize, 78, 120] {
            let lines = build_help_lines(&theme, "1.2.3", "libpcap version 1.2.3", width);
            assert_eq!(lines.len(), help_line_count(width), "at {width} columns");
        }
    }

    /// The styled-line builder produces a substantial number of lines.
    #[test]
    fn build_help_lines_non_empty() {
        let theme = crate::tui::Theme::default();
        let lines = build_help_lines(&theme, "1.2.3", "libpcap version 1.2.3", 78);
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
        let lines = build_help_lines(
            &theme,
            "9.9.9 (abc) features: tui",
            "libpcap version 1.2.3",
            78,
        );
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

    /// The running libpcap sits on its own row just under the version, so an
    /// operator at the console can see which alternate capture backends this
    /// binary's libpcap names without leaving the TUI.
    #[test]
    fn build_help_lines_puts_the_libpcap_line_under_the_version() {
        let theme = crate::tui::Theme::default();
        let pcap = "libpcap version 1.10.6 (64-bit time_t, with TPACKET_V3 and netmap); \
                    alternate capture backends named: netmap";
        let lines = build_help_lines(&theme, "1.2.3", pcap, 200);
        let text =
            |i: usize| -> String { lines[i].spans.iter().map(|s| s.content.as_ref()).collect() };
        assert_eq!(text(1), "v1.2.3");
        assert_eq!(text(2), pcap);
    }

    /// Truncated to the box like the version line, so a long banner cannot
    /// wrap onto a second row and push the keybindings down.
    #[test]
    fn the_libpcap_line_is_truncated_to_the_box() {
        let theme = crate::tui::Theme::default();
        let pcap = "libpcap version 1.10.6 (64-bit time_t, with TPACKET_V3 and netmap); \
                    alternate capture backends named: netmap";
        let lines = build_help_lines(&theme, "1.2.3", pcap, 20);
        let row: String = lines[2].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            row.starts_with("libpcap version")
                && unicode_width::UnicodeWidthStr::width(row.as_str()) <= 20,
            "got {row:?}"
        );
    }

    /// Every clause the vCon note must carry, checked one at a time.
    ///
    /// Listed here rather than compared as one blob so a failure names the
    /// clause that went missing. Each is a thing an operator would otherwise
    /// have to already know: that sipnab only WATCHED the call, that the
    /// container holds no audio, that nothing in it is signed, and that a
    /// capture which lost messages says so inside the container.
    const REQUIRED_VCON_CLAUSES: &[&str] = &[
        "vCon",
        "sipnab observed",
        // NOT "no audio". This gate required that clause while the container
        // was signaling-only and went on requiring it after media landed \u{2014} so
        // it enforced a sentence that had become false on an operator-facing
        // screen, and correcting the screen would have failed the test. A gate
        // and the text it guards have to derive from one rule.
        "audio",
        "sipnab signs nothing",
        "what it lost",
        "/vcon",
    ];

    /// The help text names vCon export and, beside it, what it leaves out.
    ///
    /// The failure this prevents is the one the whole feature turns on: an
    /// operator handing a sipnab vCon to somebody who reads it as a recording
    /// of the call. Naming the export without naming its limits would make
    /// this surface the cause of that rather than the guard against it.
    #[test]
    fn help_text_names_vcon_export_and_what_it_leaves_out() {
        for clause in REQUIRED_VCON_CLAUSES {
            assert!(
                HELP_TEXT.contains(clause),
                "the vCon note lost `{clause}` — a container described only by \
                 what it contains reads as a complete record of the call"
            );
        }
    }

    /// The note REACHES a rendered frame, not merely the constant.
    ///
    /// `HELP_TEXT` is the source; `build_help_lines` is what an operator sees.
    /// The two can part company — the builder classifies every line and could
    /// drop or swallow one — and a caveat that exists only in a constant has
    /// warned nobody.
    #[test]
    fn the_vcon_note_reaches_the_rendered_help() {
        let theme = crate::tui::Theme::default();
        let lines = build_help_lines(&theme, "1.2.3", "libpcap version 1.2.3", 78);
        let rendered: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        for clause in REQUIRED_VCON_CLAUSES {
            assert!(
                rendered.contains(clause),
                "`{clause}` is in HELP_TEXT and never reaches the screen: \
                 {rendered}"
            );
        }
    }

    /// The note is prose, and no line of it can be read as a key binding.
    ///
    /// Not cosmetic. `tests/keybinding_drift_test.rs` takes everything before
    /// the first run of two or more spaces on ANY help line as key tokens, and
    /// checks them against the keymap. A prose line aligned with two spaces
    /// would inject words like "vCon" into that set and fail a gate that has
    /// nothing to do with this change — and the obvious repair, relaxing the
    /// gate, would cost the project the drift check on every real binding.
    ///
    /// This note deliberately binds no key: sipnab's TUI cannot write a vCon,
    /// and a key that did nothing in a build without the `vcon` feature is the
    /// failure the REST route's `#[cfg]` gate exists to avoid.
    #[test]
    fn the_vcon_note_carries_no_key_binding_column() {
        let offenders: Vec<&str> = HELP_TEXT
            .lines()
            .filter(|l| l.contains("vCon") || l.contains("vcon"))
            .filter(|l| l.trim_start().contains("  "))
            .collect();
        assert!(
            offenders.is_empty(),
            "these vCon lines have a two-space gap and read as key bindings to \
             the keybinding-drift gate: {offenders:?}"
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
