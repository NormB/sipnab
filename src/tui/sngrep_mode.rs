// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! sngrep mode — sngrep's keys and colors on sipnab's screens.
//!
//! Off by default. With `--sngrep-mode` (or `[display] sngrep_mode = true`)
//! a key pressed on a screen sngrep also has (call list, call flow, raw
//! message, message compare) does what it does in sngrep. The mode is a
//! translation layer in front of the normal key handling: a sngrep key is
//! rewritten into the sipnab key that performs the same action, a sipnab
//! command whose key sngrep uses moves to a free key, and a sngrep key
//! sipnab has no equivalent for says so on the status line. Every other
//! screen, and every key this table does not name, behaves exactly as in
//! normal mode. With the mode off nothing here runs.
//!
//! The colors are sngrep's: the cyan title and status bands, white on blue
//! for the current call, the method and state columns, red requests and
//! green responses in the ladder (or the seven-color Call-ID / CSeq
//! rotation), a bold current arrow, and sngrep's raw-message syntax colors.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::Theme;
use super::state::View;
use super::theme::Keymap;
use crate::sip::dialog::DialogState;

/// What a key press becomes in sngrep mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Translated {
    /// Not a sngrep key on this screen: handle it as in normal mode.
    Pass,
    /// Handle this sipnab key instead.
    Key(KeyEvent),
    /// A sngrep action no single sipnab key performs on this screen.
    Act(SngrepAction),
    /// A sngrep key with no sipnab equivalent; the text names it.
    Unsupported(&'static str),
}

/// sngrep actions run directly on the app state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SngrepAction {
    /// `C` / F8 — toggle SIP syntax colors.
    ToggleSyntax,
    /// `c` — cycle the ladder color mode (request / Call-ID / CSeq).
    CycleColorMode,
    /// `p` — pause / resume the capture.
    TogglePause,
    /// `o` / `O` — the settings popup.
    OpenSettings,
    /// `K` — the bottom key bar names each command's alternative key.
    ToggleHints,
    /// Ctrl+W on the call list — uncheck every checked call.
    UncheckAll,
    /// `9` in the call flow — the raw pane two columns wider.
    IncreaseRaw,
    /// `0` in the call flow — the raw pane two columns narrower.
    DecreaseRaw,
    /// `T` in the call flow — the raw pane back to its computed width.
    ResetRaw,
    /// `D` in the call flow — only the messages that carry SDP.
    OnlySdp,
    /// `M` in the call flow — only the media (RTP) arrows.
    OnlyMedia,
    /// `s` in the call flow — one column per host, not per address:port.
    Compress,
    /// F5 / Ctrl+L (all) or F9 (`soft`: keep the calls matching the filter)
    /// on the flow and raw screens: back to the call list, which clears.
    ClearCalls {
        /// F9: keep the calls the display filter matches.
        soft: bool,
    },
    /// `-` / `+` in the column selector — move the column up / down.
    MoveColumn {
        /// `true` for `+` (down), `false` for `-` (up).
        down: bool,
    },
}

/// The screens sngrep has. Every other view passes keys through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    CallList,
    CallFlow,
    Raw,
    Diff,
}

fn screen_of(view: &View) -> Option<Screen> {
    match view {
        View::CallList => Some(Screen::CallList),
        View::CallFlow(_) => Some(Screen::CallFlow),
        View::RawMessage { .. } | View::CombinedDetail { .. } => Some(Screen::Raw),
        View::MessageDiff { .. } => Some(Screen::Diff),
        _ => None,
    }
}

fn k(code: KeyCode) -> Translated {
    Translated::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ch(c: char) -> Translated {
    k(KeyCode::Char(c))
}

/// Translate one key press for the current view.
///
/// `km` is the user's keymap: a sngrep key that means a rebindable sipnab
/// action (help, save, filter, …) becomes whatever key the user bound it
/// to. Pure.
pub fn translate(view: &View, km: &Keymap, key: KeyEvent) -> Translated {
    let Some(screen) = screen_of(view) else {
        return Translated::Pass;
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    // Movement keys every sngrep screen answers alike.
    if ctrl {
        return match key.code {
            KeyCode::Char('f') | KeyCode::Char('d') => k(KeyCode::PageDown),
            KeyCode::Char('b') | KeyCode::Char('u') => k(KeyCode::PageUp),
            KeyCode::Char('a') => k(KeyCode::Home),
            KeyCode::Char('e') => k(KeyCode::End),
            KeyCode::Char('w') => match screen {
                Screen::CallList => Translated::Act(SngrepAction::UncheckAll),
                Screen::CallFlow => k(km.clear_calls), // reset the compare selection
                _ => Translated::Pass,
            },
            // On the flow and raw screens "clear calls" goes back to the
            // call list, which clears.
            KeyCode::Char('l') if matches!(screen, Screen::CallFlow | Screen::Raw) => {
                Translated::Act(SngrepAction::ClearCalls { soft: false })
            }
            _ => Translated::Pass,
        };
    }

    match screen {
        Screen::CallList => call_list(km, key.code),
        Screen::CallFlow => call_flow(km, key.code),
        Screen::Raw => raw(km, key.code),
        Screen::Diff => diff(key.code),
    }
}

/// Keys every sngrep screen shares: help, back, alias, hints.
fn common(code: KeyCode) -> Option<Translated> {
    Some(match code {
        KeyCode::Char('Q') | KeyCode::Char('q') => k(KeyCode::Esc),
        KeyCode::Char('a') => ch('n'), // sngrep alias = sipnab name resolution cycle
        KeyCode::Char('K') => Translated::Act(SngrepAction::ToggleHints),
        _ => return None,
    })
}

fn help_key(km: &Keymap, code: KeyCode) -> Option<Translated> {
    matches!(code, KeyCode::Char('h') | KeyCode::Char('H')).then(|| k(km.help))
}

/// The call list's sngrep keys.
fn call_list(km: &Keymap, code: KeyCode) -> Translated {
    if let Some(t) = help_key(km, code) {
        return t;
    }
    match code {
        // sngrep: q and Q leave sngrep from the call list, like sipnab's quit.
        KeyCode::Char('Q') => k(km.quit),
        KeyCode::Char('a') => ch('n'),
        KeyCode::Char('K') => common(code).unwrap_or(Translated::Pass),
        KeyCode::Tab | KeyCode::F(3) | KeyCode::Char('P') => k(km.search),
        KeyCode::Char('R') => k(KeyCode::F(6)),
        KeyCode::Char('x') => k(km.extended_flow),
        KeyCode::Char('f') | KeyCode::Char('F') => k(km.filter),
        KeyCode::Char('t') | KeyCode::Char('T') => k(km.column_selector),
        KeyCode::Char('o') | KeyCode::Char('O') => Translated::Act(SngrepAction::OpenSettings),
        KeyCode::F(8) => Translated::Act(SngrepAction::OpenSettings),
        KeyCode::Char('i') => ch('s'), // sngrep stats
        KeyCode::Char('s') | KeyCode::Char('S') => k(km.save),
        KeyCode::F(9) => ch('i'), // sngrep soft clear keeps the calls matching the filter
        KeyCode::Char('z') => ch('Z'),
        KeyCode::Char('C') => Translated::Act(SngrepAction::ToggleSyntax),
        KeyCode::Char('c') => Translated::Act(SngrepAction::CycleColorMode),
        // sngrep moves a column with -/+ in its column selector (F10), not
        // here; on its call list the keys do nothing.
        KeyCode::Char('-') | KeyCode::Char('+') => Translated::Unsupported(
            "sngrep -/+ move a column in the column selector: press F10 (or t) first",
        ),
        // The sipnab commands whose keys sngrep uses, on their new keys.
        KeyCode::Char('L') => k(KeyCode::Tab), // RTP streams
        KeyCode::Char('M') => ch('L'),         // last updated last (L is RTP streams here)
        KeyCode::Char('w') => ch('t'),         // cycle timestamps
        KeyCode::Char('W') => ch('S'),         // relay statistics
        KeyCode::Char('X') => ch('x'),         // TFPS observe
        KeyCode::Char('J') => ch('f'),         // RFC conformance
        KeyCode::Char('G') => k(km.filter_detail),
        KeyCode::Char('Y') => ch('o'),           // SDP timeline
        KeyCode::Char('U') => ch('O'),           // open pcap file
        KeyCode::Char('E') => ch('a'),           // security findings
        KeyCode::Char('y') => ch('T'),           // call timeline
        KeyCode::Char('#') => ch('h'),           // capture health
        KeyCode::Char('=') => ch('c'),           // compare two calls
        KeyCode::Char('\\') => k(KeyCode::F(9)), // clear view filter and search
        _ => Translated::Pass,
    }
}

/// The call flow's sngrep keys.
fn call_flow(km: &Keymap, code: KeyCode) -> Translated {
    if let Some(t) = help_key(km, code) {
        return t;
    }
    if let Some(t) = common(code) {
        return t;
    }
    match code {
        KeyCode::F(6) | KeyCode::Char('R') | KeyCode::Char('r') => ch('A'), // raw of the whole call
        KeyCode::Char('9') => Translated::Act(SngrepAction::IncreaseRaw),
        KeyCode::Char('0') => Translated::Act(SngrepAction::DecreaseRaw),
        KeyCode::Char('T') => Translated::Act(SngrepAction::ResetRaw),
        KeyCode::Char('D') => Translated::Act(SngrepAction::OnlySdp),
        KeyCode::Char('M') => Translated::Act(SngrepAction::OnlyMedia),
        KeyCode::Char('s') => Translated::Act(SngrepAction::Compress),
        // sngrep's ladder has no left/right; the raw pane is sized by 9/0.
        KeyCode::Left | KeyCode::Right => {
            Translated::Unsupported("sngrep: 9 / 0 widen / narrow the raw pane, T resets it")
        }
        KeyCode::F(2) => ch('d'),                               // SDP info
        KeyCode::F(3) | KeyCode::Char('m') => k(KeyCode::F(6)), // media in the ladder
        KeyCode::Char('t') => ch('R'),                          // show / hide the raw pane
        KeyCode::Char('S') => k(km.save),
        KeyCode::Char('w') => ch('t'), // absolute / delta time
        KeyCode::Char('f') | KeyCode::Char('F') => k(km.filter),
        KeyCode::Char('C') | KeyCode::F(8) => Translated::Act(SngrepAction::ToggleSyntax),
        KeyCode::Char('p') => Translated::Act(SngrepAction::TogglePause),
        KeyCode::Char('o') | KeyCode::Char('O') => Translated::Act(SngrepAction::OpenSettings),
        KeyCode::F(5) => Translated::Act(SngrepAction::ClearCalls { soft: false }),
        KeyCode::F(9) => Translated::Act(SngrepAction::ClearCalls { soft: true }),
        // The sipnab commands whose keys sngrep uses, on their new keys.
        KeyCode::Char('L') => ch('r'), // RTP streams of this call
        KeyCode::Char('W') => ch('S'), // relay statistics
        KeyCode::Char('b') => ch('m'), // mark message
        KeyCode::Char('B') => ch('M'), // clear marks
        KeyCode::Char('g') => ch('a'), // combined detail: this transaction
        KeyCode::Char('u') => ch('h'), // header names form
        KeyCode::Char('Y') => ch('w'), // wrap
        KeyCode::Char('Z') => ch('C'), // operator note
        KeyCode::Char('J') => ch('f'), // filter ladder to this transaction
        KeyCode::Char('G') => k(km.filter_detail),
        KeyCode::Char('\\') => k(KeyCode::F(9)), // clear view filter and search
        _ => Translated::Pass,
    }
}

/// The raw message screen's sngrep keys.
fn raw(km: &Keymap, code: KeyCode) -> Translated {
    if let Some(t) = help_key(km, code) {
        return t;
    }
    if let Some(t) = common(code) {
        return t;
    }
    match code {
        KeyCode::Char('s') | KeyCode::Char('S') => k(km.save),
        KeyCode::Char('C') | KeyCode::F(8) => ch('s'), // syntax colors
        KeyCode::Char('p') => Translated::Act(SngrepAction::TogglePause),
        KeyCode::Char('o') | KeyCode::Char('O') => Translated::Act(SngrepAction::OpenSettings),
        KeyCode::F(5) => Translated::Act(SngrepAction::ClearCalls { soft: false }),
        KeyCode::F(9) => Translated::Act(SngrepAction::ClearCalls { soft: true }),
        KeyCode::Char('u') => ch('h'), // header names form
        KeyCode::Char('Z') => ch('C'), // operator note
        KeyCode::Char('G') => k(km.filter_detail),
        _ => Translated::Pass,
    }
}

/// The column selector's sngrep keys, open over the call list:
/// `-` / `+` move the current column up / down, `q` / `Q` leave. Every
/// other key is the selector's own (arrows, j/k, Space, Enter, Esc, `s`).
pub fn translate_column_select(key: KeyEvent) -> Translated {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return Translated::Pass;
    }
    match key.code {
        KeyCode::Char('-') => Translated::Act(SngrepAction::MoveColumn { down: false }),
        KeyCode::Char('+') => Translated::Act(SngrepAction::MoveColumn { down: true }),
        KeyCode::Char('q') | KeyCode::Char('Q') => k(KeyCode::Esc),
        _ => Translated::Pass,
    }
}

// ── Raw pane width (9 / 0 / T) ──────────────────────────────────────

/// The narrowest raw pane the computed width gives.
pub const RAW_MIN_WIDTH: u16 = 40;
/// Columns one `9` / `0` press moves the raw pane by.
pub const RAW_STEP: u16 = 2;
/// The narrowest raw pane `0` reaches.
const RAW_FLOOR: u16 = 10;
/// What the ladder keeps for each participant beside the raw pane: room for
/// a method or status label with an address on its arrow.
const LADDER_PER_PARTICIPANT: u16 = 28;
/// The extra room a message from the last participant to itself needs on
/// the right of its column.
const SELF_LOOP_ROOM: u16 = 12;

/// The columns the ladder needs: the time column, then one
/// [`LADDER_PER_PARTICIPANT`] per participant, plus [`SELF_LOOP_ROOM`] when
/// the last participant sends to itself.
pub fn ladder_need(participants: usize, self_loop_last: bool) -> u16 {
    let n = u16::try_from(participants).unwrap_or(u16::MAX);
    let mut need = (super::call_flow::TS_COL_WIDTH as u16)
        .saturating_add(n.saturating_mul(LADDER_PER_PARTICIPANT));
    if self_loop_last {
        need = need.saturating_add(SELF_LOOP_ROOM);
    }
    need
}

/// The raw pane's text width in sngrep mode. A width the user set with
/// `9` / `0` (`fixed`) is kept; otherwise the pane takes what the ladder
/// (`need`, from [`ladder_need`]) leaves of `screen`, less its two border
/// columns, and never less than [`RAW_MIN_WIDTH`].
pub fn raw_width(screen: u16, need: u16, fixed: Option<u16>) -> u16 {
    fixed.unwrap_or_else(|| {
        screen
            .saturating_sub(need)
            .saturating_sub(2)
            .max(RAW_MIN_WIDTH)
    })
}

/// The raw pane width after one `9` (`grow`) or `0` press from `current` on
/// a `screen` columns wide, or `None` when the press would leave the ladder
/// less than its time column or the pane less than [`RAW_FLOOR`].
pub fn step_raw(current: u16, screen: u16, grow: bool) -> Option<u16> {
    if grow {
        let widest = screen.saturating_sub(super::call_flow::TS_COL_WIDTH as u16 + 2);
        let w = current.saturating_add(RAW_STEP);
        (w <= widest).then_some(w)
    } else {
        let w = current.checked_sub(RAW_STEP)?;
        (w >= RAW_FLOOR).then_some(w)
    }
}

// ── Call-list autoscroll (A) ────────────────────────────────────────

/// The row autoscroll keeps the cursor on: the newest dialog in the
/// current sort order — the bottom row when the sort is ascending, the top
/// row when it is descending. `None` on an empty list. Applied on every
/// redraw while autoscroll is on, so `A` jumps at once and every new dialog
/// pulls the cursor wherever it was.
pub fn autoscroll_row(len: usize, ascending: bool) -> Option<usize> {
    (len > 0).then(|| if ascending { len - 1 } else { 0 })
}

/// Whether a key pressed on the call list switches autoscroll off, as in
/// sngrep: the moves (Up/Down, j/k, page keys, Ctrl+F/B/D/U, Home/End, Ctrl+A/E) and
/// the search (F3, `/`, Tab). The key is the one the user pressed, before
/// the sngrep-mode translation. sngrep's `P` (full-text panel) leaves it on.
pub fn stops_autoscroll(key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return matches!(
            key.code,
            KeyCode::Char('f')
                | KeyCode::Char('b')
                | KeyCode::Char('d')
                | KeyCode::Char('u')
                | KeyCode::Char('a')
                | KeyCode::Char('e')
        );
    }
    matches!(
        key.code,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::Char('j')
            | KeyCode::Char('k')
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::F(3)
            | KeyCode::Char('/')
            | KeyCode::Tab
    )
}

// ── Ladder filters (D, M) and compressed columns (s) ───────────────

/// Keep the ladder rows sngrep shows with `D` (`sdp_only`: the messages that
/// carry SDP) and `M` (`only_media`: no SIP message at all, only the media
/// arrows the RTP display draws). Spacers go with the filtered messages.
/// `has_sdp` answers for a message row's `raw_index`.
pub fn filter_rows(
    rows: Vec<super::call_flow::LayoutRow>,
    sdp_only: bool,
    only_media: bool,
    has_sdp: impl Fn(usize) -> bool,
) -> Vec<super::call_flow::LayoutRow> {
    use super::call_flow::prepare::RowKind;
    if !sdp_only && !only_media {
        return rows;
    }
    rows.into_iter()
        .filter(|r| match r.kind {
            RowKind::Message { .. } => {
                !only_media && (!sdp_only || r.raw_index.is_some_and(&has_sdp))
            }
            RowKind::Spacer => false,
            RowKind::RtpBar | RowKind::RtpStream => true,
        })
        .collect()
}

/// The host part of a participant address: `10.0.0.1:5060` → `10.0.0.1`,
/// `[2001:db8::1]:5060` → `2001:db8::1`, a bare address unchanged.
pub fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match addr.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => addr,
    }
}

/// The compressed call flow (`s`): columns matched by
/// name (`label_of` the host: its alias, or the address) instead of by
/// address:port, so every address of one alias is one column; every row's
/// columns are remapped onto them.
pub fn compress_participants(
    participants: Vec<super::call_flow::Participant>,
    mut rows: Vec<super::call_flow::LayoutRow>,
    label_of: impl Fn(&str) -> String,
) -> (
    Vec<super::call_flow::Participant>,
    Vec<super::call_flow::LayoutRow>,
) {
    let mut merged: Vec<super::call_flow::Participant> = Vec::new();
    let mut map: Vec<usize> = Vec::with_capacity(participants.len());
    for p in &participants {
        let host = host_of(&p.addr);
        let label = label_of(host);
        let col = match merged.iter().position(|m| m.label == label) {
            Some(c) => c,
            None => {
                merged.push(super::call_flow::Participant {
                    addr: host.to_string(),
                    label,
                });
                merged.len() - 1
            }
        };
        map.push(col);
    }
    for r in &mut rows {
        r.src_col = map.get(r.src_col).copied().unwrap_or(r.src_col);
        r.dst_col = map.get(r.dst_col).copied().unwrap_or(r.dst_col);
    }
    (merged, rows)
}

/// The message compare screen's sngrep keys.
fn diff(code: KeyCode) -> Translated {
    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => k(KeyCode::Esc),
        KeyCode::Char('h') | KeyCode::Char('H') => k(KeyCode::F(1)),
        KeyCode::Char('u') => ch('h'), // header names form
        _ => Translated::Pass,
    }
}

// ── Colors ─────────────────────────────────────────────────────────

/// The seven colors the Call-ID and CSeq ladder color modes take in turn.
pub const ROTATION: [Color; 7] = [
    Color::Cyan,
    Color::Yellow,
    Color::Magenta,
    Color::Green,
    Color::Red,
    Color::Blue,
    Color::White,
];

/// One command on the sngrep-mode key bar: its function or named key, the
/// letter that does the same (`None` when it has only the one key), and
/// what it does, in sipnab's words.
type BarEntry = (&'static str, Option<&'static str>, &'static str);

const LIST_BAR: &[BarEntry] = &[
    ("Esc", Some("q"), "Quit"),
    ("F1", Some("h"), "Help"),
    ("Enter", None, "Open call"),
    ("Space", None, "Check"),
    ("F2", Some("s"), "Save"),
    ("F3", Some("/"), "Search"),
    ("P", None, "Full text"),
    ("F4", Some("x"), "Extend"),
    ("F5", Some("^L"), "Clear calls"),
    ("F7", Some("f"), "Filter"),
    ("F8", Some("o"), "Settings"),
    ("F9", None, "Clear unmatched"),
    ("F10", Some("t"), "Columns"),
];

const FLOW_BAR: &[BarEntry] = &[
    ("Esc", Some("q"), "Back"),
    ("F1", Some("h"), "Help"),
    ("Enter", None, "Raw"),
    ("Space", None, "Compare"),
    ("F2", Some("d"), "SDP"),
    ("F3", Some("m"), "Media"),
    ("F4", Some("x"), "Extend"),
    ("F6", Some("R"), "Raw call"),
    ("s", None, "Compress"),
    ("c", None, "Color"),
    ("9", None, "Raw wider"),
];

const RAW_BAR: &[BarEntry] = &[
    ("Esc", Some("q"), "Back"),
    ("F1", Some("h"), "Help"),
    ("F2", Some("s"), "Save"),
    ("C", None, "Syntax"),
    ("/", None, "Search"),
];

/// The bottom key bar sngrep mode draws on the call list, the call flow and
/// the raw message screen. With `alt` (the `K` key) each command shows its
/// letter instead of its function key; a command with one key shows it in
/// both. `None` on every other view keeps sipnab's own bar.
pub fn fkey_bar(view: &View, alt: bool) -> Option<Vec<(&'static str, &'static str)>> {
    let table = match view {
        View::CallList => LIST_BAR,
        View::CallFlow(_) => FLOW_BAR,
        View::RawMessage { .. } => RAW_BAR,
        _ => return None,
    };
    Some(
        table
            .iter()
            .map(|&(key, letter, label)| {
                let shown = if alt { letter.unwrap_or(key) } else { key };
                (shown, label)
            })
            .collect(),
    )
}

/// The theme slots sngrep paints: cyan title and status bands, the current
/// row on blue.
pub fn apply_theme(theme: &mut Theme) {
    if theme.no_color {
        return;
    }
    theme.sngrep = true;
    theme.sngrep_alt_hints = false;
    theme.header = Color::Cyan;
    theme.status_bg = Color::Cyan;
    theme.selected = Color::Blue;
}

/// The current call-list row: white on blue, like sngrep.
pub fn list_highlight() -> Style {
    Style::default().fg(Color::White).bg(Color::Blue)
}

/// The Method column colors of sngrep mode.
pub fn method_style(method: &str) -> Style {
    match method {
        "INVITE" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "NOTIFY" | "OPTIONS" => Style::default().fg(Color::Yellow),
        "REGISTER" => Style::default().fg(Color::Magenta),
        "SUBSCRIBE" => Style::default().fg(Color::Blue),
        "KDMQ" => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        _ => Style::default(),
    }
}

/// sngrep's call state colors: CALL SETUP yellow, IN CALL blue, COMPLETED
/// green, CANCELLED / REJECTED red, DIVERTED cyan.
pub fn state_style(state: &DialogState) -> Style {
    match state {
        DialogState::Trying | DialogState::Ringing => Style::default().fg(Color::Yellow),
        DialogState::InCall | DialogState::Active => Style::default().fg(Color::Blue),
        DialogState::Completed | DialogState::Registered => Style::default().fg(Color::Green),
        DialogState::Canceled | DialogState::Failed => Style::default().fg(Color::Red),
        DialogState::Redirected => Style::default().fg(Color::Cyan),
        _ => Style::default(),
    }
}

/// sngrep "request" color mode: requests red, responses green.
pub fn arrow_style(is_request: bool) -> Style {
    Style::default().fg(if is_request { Color::Red } else { Color::Green })
}

/// sngrep Call-ID / CSeq color mode: position `idx` of the rotation.
pub fn rotation_style(idx: usize) -> Style {
    Style::default().fg(ROTATION[idx % ROTATION.len()])
}

/// The current ladder arrow, its label and its media lines: reverse
/// video, no band.
pub fn flow_selection() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// Characters that end a colored word in a raw SIP line.
const WORD_END: [char; 4] = [' ', ';', '<', '>'];

/// Builds one line of spans, merging neighbours of the same style.
#[derive(Default)]
struct LinePainter {
    spans: Vec<Span<'static>>,
}

impl LinePainter {
    fn put(&mut self, text: &str, style: Style) {
        if text.is_empty() {
            return;
        }
        match self.spans.last_mut() {
            Some(last) if last.style == style => last.content.to_mut().push_str(text),
            _ => self.spans.push(Span::styled(text.to_string(), style)),
        }
    }

    /// `text` up to its first [`WORD_END`] in `style`, the rest plain.
    fn word_then_plain(&mut self, text: &str, style: Style) {
        let end = text.find(WORD_END).unwrap_or(text.len());
        self.put(&text[..end], style);
        self.put(&text[end..], Style::default());
    }
}

fn bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

/// Whether header name `name` is `long` or its compact form `short`
/// (RFC 3261 section 7.3.3), in any case.
fn header_is(name: &str, long: &str, short: &str) -> bool {
    name.eq_ignore_ascii_case(long) || name.eq_ignore_ascii_case(short)
}

/// The colors sngrep mode gives a raw SIP message, one [`Line`] per line:
///
/// * a request line: the method bold yellow, the Request-URI bold cyan up to
///   its first parameter, the rest plain;
/// * a status line: the status code bold red, the rest plain;
/// * a header: the name and its colon green; the Call-ID value bold
///   magenta; the CSeq method yellow; a `branch` parameter bold cyan and a
///   `tag` parameter bold green (bold without a color on From);
/// * the body, after the blank line, plain.
///
/// A colored word ends at a space, `;`, `<` or `>`.
pub fn syntax_lines(raw_text: &str) -> Vec<Line<'static>> {
    let mut text_lines: Vec<&str> = raw_text.split('\n').collect();
    if text_lines.last().is_some_and(|l| l.is_empty()) {
        text_lines.pop();
    }
    let mut in_body = false;
    let mut out = Vec::with_capacity(text_lines.len());
    for (n, line) in text_lines.into_iter().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let mut p = LinePainter::default();
        if n == 0 {
            paint_start_line(&mut p, line);
        } else if in_body || line.starts_with([' ', '\t']) {
            p.put(line, Style::default());
        } else if line.is_empty() {
            in_body = true;
        } else {
            paint_header(&mut p, line);
        }
        out.push(Line::from(p.spans));
    }
    out
}

fn paint_start_line(p: &mut LinePainter, line: &str) {
    if let Some(rest) = line.strip_prefix("SIP/2.0 ") {
        p.put("SIP/2.0 ", Style::default());
        p.word_then_plain(rest, bold(Color::Red));
        return;
    }
    let (method, rest) = line.split_once(' ').unwrap_or((line, ""));
    p.put(method, bold(Color::Yellow));
    if method.len() < line.len() {
        p.put(" ", Style::default());
    }
    p.word_then_plain(rest, bold(Color::Cyan));
}

fn paint_header(p: &mut LinePainter, line: &str) {
    let Some(colon) = line.find(':') else {
        p.put(line, Style::default());
        return;
    };
    let (name_colon, value) = line.split_at(colon + 1);
    p.put(name_colon, Style::default().fg(Color::Green));
    let name = name_colon[..colon].trim();
    let trimmed = value.trim_start();
    let (space, trimmed_value) = value.split_at(value.len() - trimmed.len());
    if header_is(name, "Call-ID", "i") {
        p.put(space, Style::default());
        p.word_then_plain(trimmed_value, bold(Color::Magenta));
    } else if name.eq_ignore_ascii_case("CSeq") {
        // `CSeq: 1 INVITE`: the sequence number plain, the method yellow.
        let digits = trimmed_value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed_value.len());
        let after = &trimmed_value[digits..];
        let gap = after.len() - after.trim_start().len();
        p.put(space, Style::default());
        p.put(&trimmed_value[..digits + gap], Style::default());
        p.word_then_plain(&after[gap..], Style::default().fg(Color::Yellow));
    } else {
        paint_params(p, value, header_is(name, "From", "f"));
    }
}

/// A header value: plain, except its `branch` and `tag` parameters.
fn paint_params(p: &mut LinePainter, value: &str, from: bool) {
    for (i, part) in value.split(';').enumerate() {
        if i == 0 {
            p.put(part, Style::default());
            continue;
        }
        p.put(";", Style::default());
        let name = part.split(['=', ' ', '<', '>']).next().unwrap_or("");
        let style = if name.eq_ignore_ascii_case("branch") {
            bold(Color::Cyan)
        } else if name.eq_ignore_ascii_case("tag") {
            if from {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                bold(Color::Green)
            }
        } else {
            Style::default()
        };
        p.word_then_plain(part, style);
    }
}

/// The time from `prev` to `cur` as a signed seconds value with six
/// decimals (`+0.500000`), right-aligned in the ladder's time column.
pub fn delta_text(
    prev: chrono::DateTime<chrono::Utc>,
    cur: chrono::DateTime<chrono::Utc>,
) -> String {
    let micros = cur
        .signed_duration_since(prev)
        .num_microseconds()
        .unwrap_or(0);
    let sign = if micros < 0 { '-' } else { '+' };
    let abs = micros.unsigned_abs();
    let text = format!("{sign}{}.{:06}", abs / 1_000_000, abs % 1_000_000);
    format!(
        "{text:>width$}",
        width = crate::tui::call_flow::TS_COL_WIDTH - 1
    )
}

/// The name of the codec a media line offers first: the encoding name of its
/// `a=rtpmap` for that payload type, else the static name RFC 3551 (the IANA
/// RTP payload type registry) gives it, else `dynamic` for 96-127 and
/// `unassigned` for the rest.
fn first_codec(media: &crate::sip::sdp::SdpMedia) -> Option<String> {
    let pt: u8 = media.formats.first()?.parse().ok()?;
    let name = media
        .rtpmap
        .iter()
        .find(|m| m.payload_type == pt)
        .map(|m| m.encoding.clone())
        .or_else(|| crate::sip::sdp::static_payload_name(pt).map(str::to_string))
        .unwrap_or_else(|| {
            if (96..=127).contains(&pt) {
                "dynamic".to_string()
            } else {
                "unassigned".to_string()
            }
        });
    Some(name)
}

/// The SDP form sngrep mode draws on a ladder arrow, for a message whose
/// start line begins with `head` (the method, or the status code) and whose
/// body is `body`: the arrow title is `head`'s first three letters and the
/// first media's address (`INV (192.168.1.26)`), then one line per RTP media,
/// `audio 12220 (PCMU)`, naming the codec it offers first. A media's address
/// is its own `c=` line, else the session's (RFC 4566 section 5.7). Only
/// media carried over RTP count (a T.38 `udptl` media does not); `None` when
/// the body has none, and the arrow keeps its plain label.
pub fn sdp_info(head: &str, body: &[u8]) -> Option<(String, Vec<String>)> {
    let session = crate::sip::sdp::parse_sdp(body).ok()?;
    let rtp: Vec<_> = session
        .media
        .iter()
        .filter(|m| m.proto.split('/').any(|part| part == "RTP"))
        .filter_map(|m| Some((m, first_codec(m)?)))
        .collect();
    let (first, _) = rtp.first()?;
    let addr = crate::sip::sdp::effective_address(first, &session).unwrap_or_default();
    let title = format!("{} ({addr})", head.chars().take(3).collect::<String>());
    let lines = rtp
        .iter()
        .map(|(m, codec)| format!("{} {} ({codec})", m.media_type, m.port))
        .collect();
    Some((title, lines))
}

/// The sngrep-mode section of the help screen: the key map, the moved
/// sipnab keys and the sngrep keys sipnab does not have.
pub const HELP_TEXT: &str = "\
SNGREP MODE (--sngrep-mode): sngrep's keys and colors
  Every key below does what it does in sngrep. Keys not listed work as in sipnab.

SNGREP MODE \u{2014} CALL LIST:
  Ctrl+F/Ctrl+B    Page down / up (Ctrl+D/Ctrl+U too; sipnab has no half page)
  Ctrl+A/Ctrl+E    First / last call
  Enter            Call flow
  F4, x            Extended call flow
  F6, r, R         Raw messages of the call
  F7, f, F         Filter dialog
  F3, /, Tab, P    Search (full text)
  F10, t, T        Choose columns (in it: - / + move a column)
  F8, o, O         Settings
  F2, s, S         Save
  F5, Ctrl+L       Clear calls
  F9               Clear calls not matching the filter
  i                Statistics
  c / C            Cycle ladder colors / toggle syntax colors
  a                Cycle name resolution (sngrep alias)
  z                Reverse sort; < > change sort column
  M                Last updated last; again = number order (sipnab's L)
  d                Only the dialogs not over; again = all
  p, Space         Pause, check a call
  A                Autoscroll on (jumps to the newest call, follows new ones;\n\
\x20                  \"A\" at the left of the column header) / off. Moving the\n\
\x20                  cursor (arrows, j/k, page keys, Home/End, mouse wheel) or\n\
\x20                  F3, /, Tab switches it off. Starts off, as in sngrep.
  Ctrl+W           Uncheck all calls
  K                Alternative key hints on the bottom bar
  F1, h, H, ?      This help
  q, Q, Esc        Quit

SNGREP MODE \u{2014} CALL FLOW:
  Enter            Raw message (selected)
  F6, r, R         Raw messages of the whole call
  F2, d            SDP info: Hidden, Summary, Full, sngrep (starts at sngrep:\n\
\x20                  \"INV (192.168.1.26)\" on the arrow, one \"audio 12220\n\
\x20                  (PCMU)\" line per RTP media under it)
  F3, m            Media (RTP) in the ladder
  F4, x            Extended call flow
  F7, f, F         Filter dialog
  9 / 0            Wider / narrower raw pane (2 columns a press)
  T                Raw pane back to its default width
  t                Show / hide the raw pane
  D                Only the messages with SDP
  M                Only media
  s                Compressed participants (one column per host)
  F5, Ctrl+L, F9   Clear calls (F9: the ones not matching the filter)
  K                Alternative key hints
  w                Absolute / delta time
  c / C, F8        Cycle colors / toggle syntax colors
  Space            Compare two messages (Ctrl+W resets)
  S                Save
  q, Q, Esc        Back to the call list
  Colors as sngrep's call flow: requests red, responses green (c cycles
  to Call-ID and CSeq colors); the current arrow, its label and its media
  lines in reverse video, its time bold; the raw pane after a blue line,
  with sngrep's syntax colors (;branch bold cyan, ;tag bold).

SNGREP MODE \u{2014} RAW MESSAGE:
  F2, s, S         Save
  C, F8            Toggle syntax colors
  F5, Ctrl+L, F9   Clear calls (F9: the ones not matching the filter)
  q, Q, Esc        Back

SNGREP MODE \u{2014} SIPNAB COMMANDS ON NEW KEYS:
  L                RTP streams (list: was Tab; flow: was r)
  w                Cycle timestamps (list: was t)
  W                Relay statistics (was S)
  X                TFPS observe (list: was x)
  J                RFC conformance (list) / transaction filter (flow) (was f)
  G                Filter summary / full (was F)
  Y                SDP timeline (list: was o) / wrap (flow: was w)
  U                Open pcap file (was O)
  E                Security findings (was a)
  y                Call timeline (list: was T)
  #                Capture health (was h)
  =                Compare two calls (was c)
  \\                Clear view filter and search (was F9)
  b / B            Mark / clear marks (flow: was m / M)
  g                Combined detail, transaction (flow: was a)
  u                Header names form (was h)
  Z                Operator note (flow, raw: was C)
  s                Statistics in sipnab views is i (was s)
";

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn to(t: Translated) -> KeyCode {
        match t {
            Translated::Key(e) => e.code,
            other => panic!("expected a key, got {other:?}"),
        }
    }

    fn flow() -> View {
        View::CallFlow("cid".to_string())
    }

    #[test]
    fn call_list_key_map_matches_sngrep() {
        let km = Keymap::default();
        let v = View::CallList;
        let t = |c| to(translate(&v, &km, key(c)));
        assert_eq!(t(KeyCode::Char('h')), KeyCode::F(1));
        assert_eq!(t(KeyCode::Char('H')), KeyCode::F(1));
        assert_eq!(t(KeyCode::Char('Q')), KeyCode::Char('q'));
        assert_eq!(t(KeyCode::Tab), KeyCode::Char('/'));
        assert_eq!(t(KeyCode::F(3)), KeyCode::Char('/'));
        assert_eq!(t(KeyCode::Char('R')), KeyCode::F(6));
        assert_eq!(t(KeyCode::Char('x')), KeyCode::F(4));
        assert_eq!(t(KeyCode::Char('f')), KeyCode::F(7));
        assert_eq!(t(KeyCode::Char('F')), KeyCode::F(7));
        assert_eq!(t(KeyCode::Char('t')), KeyCode::F(10));
        assert_eq!(t(KeyCode::Char('i')), KeyCode::Char('s'));
        assert_eq!(t(KeyCode::Char('s')), KeyCode::F(2));
        assert_eq!(t(KeyCode::F(9)), KeyCode::Char('i'));
        assert_eq!(t(KeyCode::Char('z')), KeyCode::Char('Z'));
        assert_eq!(t(KeyCode::Char('a')), KeyCode::Char('n'));
        assert_eq!(
            translate(&v, &km, key(KeyCode::Char('c'))),
            Translated::Act(SngrepAction::CycleColorMode)
        );
        assert_eq!(
            translate(&v, &km, key(KeyCode::Char('o'))),
            Translated::Act(SngrepAction::OpenSettings)
        );
        assert_eq!(to(translate(&v, &km, ctrl('f'))), KeyCode::PageDown);
        assert_eq!(to(translate(&v, &km, ctrl('b'))), KeyCode::PageUp);
        assert_eq!(to(translate(&v, &km, ctrl('a'))), KeyCode::Home);
        assert_eq!(to(translate(&v, &km, ctrl('e'))), KeyCode::End);
        // Keys sngrep and sipnab already share pass through untouched.
        for c in [
            KeyCode::Enter,
            KeyCode::Char(' '),
            KeyCode::Char('p'),
            KeyCode::Char('A'),
            KeyCode::Char('<'),
            KeyCode::F(5),
            KeyCode::Up,
        ] {
            assert_eq!(translate(&v, &km, key(c)), Translated::Pass, "{c:?}");
        }
    }

    #[test]
    fn moved_sipnab_keys_reach_their_command() {
        let km = Keymap::default();
        let v = View::CallList;
        let t = |c| to(translate(&v, &km, key(KeyCode::Char(c))));
        assert_eq!(t('L'), KeyCode::Tab);
        assert_eq!(t('w'), KeyCode::Char('t'));
        assert_eq!(t('W'), KeyCode::Char('S'));
        assert_eq!(t('X'), KeyCode::Char('x'));
        assert_eq!(t('J'), KeyCode::Char('f'));
        assert_eq!(t('G'), KeyCode::Char('F'));
        assert_eq!(t('Y'), KeyCode::Char('o'));
        assert_eq!(t('U'), KeyCode::Char('O'));
        assert_eq!(t('E'), KeyCode::Char('a'));
        assert_eq!(t('y'), KeyCode::Char('T'));
        assert_eq!(t('#'), KeyCode::Char('h'));
        assert_eq!(t('='), KeyCode::Char('c'));
        assert_eq!(t('\\'), KeyCode::F(9));
    }

    #[test]
    fn call_flow_key_map_matches_sngrep() {
        let km = Keymap::default();
        let v = flow();
        let t = |c| to(translate(&v, &km, key(c)));
        assert_eq!(t(KeyCode::Char('q')), KeyCode::Esc);
        assert_eq!(t(KeyCode::Char('Q')), KeyCode::Esc);
        assert_eq!(t(KeyCode::Char('h')), KeyCode::F(1));
        assert_eq!(t(KeyCode::F(6)), KeyCode::Char('A'));
        assert_eq!(t(KeyCode::Char('r')), KeyCode::Char('A'));
        assert_eq!(t(KeyCode::F(2)), KeyCode::Char('d'));
        assert_eq!(t(KeyCode::Char('m')), KeyCode::F(6));
        assert_eq!(t(KeyCode::Char('t')), KeyCode::Char('R'));
        assert_eq!(t(KeyCode::Char('w')), KeyCode::Char('t'));
        assert_eq!(t(KeyCode::Char('S')), KeyCode::F(2));
        assert_eq!(t(KeyCode::Char('f')), KeyCode::F(7));
        assert_eq!(t(KeyCode::Char('b')), KeyCode::Char('m'));
        assert_eq!(t(KeyCode::Char('u')), KeyCode::Char('h'));
        assert_eq!(t(KeyCode::Char('Z')), KeyCode::Char('C'));
        assert_eq!(
            translate(&v, &km, key(KeyCode::Char('C'))),
            Translated::Act(SngrepAction::ToggleSyntax)
        );
        for (c, a) in [
            ('9', SngrepAction::IncreaseRaw),
            ('0', SngrepAction::DecreaseRaw),
            ('T', SngrepAction::ResetRaw),
            ('D', SngrepAction::OnlySdp),
            ('M', SngrepAction::OnlyMedia),
            ('s', SngrepAction::Compress),
            ('K', SngrepAction::ToggleHints),
        ] {
            assert_eq!(
                translate(&v, &km, key(KeyCode::Char(c))),
                Translated::Act(a),
                "{c}"
            );
        }
        assert_eq!(
            translate(&v, &km, key(KeyCode::F(5))),
            Translated::Act(SngrepAction::ClearCalls { soft: false })
        );
        assert_eq!(
            translate(&v, &km, ctrl('l')),
            Translated::Act(SngrepAction::ClearCalls { soft: false })
        );
        assert_eq!(
            translate(&v, &km, key(KeyCode::F(9))),
            Translated::Act(SngrepAction::ClearCalls { soft: true })
        );
        for c in [
            KeyCode::Enter,
            KeyCode::Char(' '),
            KeyCode::Char('d'),
            KeyCode::F(4),
        ] {
            assert_eq!(translate(&v, &km, key(c)), Translated::Pass, "{c:?}");
        }
    }

    #[test]
    fn raw_and_diff_key_map_matches_sngrep() {
        let km = Keymap::default();
        let raw = View::RawMessage {
            call_id: "cid".to_string(),
            message_index: 0,
        };
        assert_eq!(
            to(translate(&raw, &km, key(KeyCode::Char('s')))),
            KeyCode::F(2)
        );
        assert_eq!(
            to(translate(&raw, &km, key(KeyCode::Char('C')))),
            KeyCode::Char('s')
        );
        assert_eq!(
            to(translate(&raw, &km, key(KeyCode::F(8)))),
            KeyCode::Char('s')
        );
        assert_eq!(
            to(translate(&raw, &km, key(KeyCode::Char('q')))),
            KeyCode::Esc
        );
        assert_eq!(
            translate(&raw, &km, key(KeyCode::Char('/'))),
            Translated::Pass
        );
    }

    #[test]
    fn rebound_keys_follow_the_keymap() {
        let km = Keymap {
            help: KeyCode::F(11),
            ..Default::default()
        };
        assert_eq!(
            to(translate(&View::CallList, &km, key(KeyCode::Char('h')))),
            KeyCode::F(11)
        );
    }

    #[test]
    fn other_views_pass_every_key() {
        let km = Keymap::default();
        for c in ['h', 'q', 's', 'f', 't'] {
            assert_eq!(
                translate(&View::Statistics, &km, key(KeyCode::Char(c))),
                Translated::Pass
            );
        }
    }

    #[test]
    fn colors_match_sngrep() {
        assert_eq!(method_style("INVITE").fg, Some(Color::Red));
        assert!(method_style("INVITE").add_modifier.contains(Modifier::BOLD));
        assert_eq!(method_style("REGISTER").fg, Some(Color::Magenta));
        assert_eq!(method_style("OPTIONS").fg, Some(Color::Yellow));
        assert_eq!(method_style("SUBSCRIBE").fg, Some(Color::Blue));
        assert_eq!(state_style(&DialogState::InCall).fg, Some(Color::Blue));
        assert_eq!(state_style(&DialogState::Completed).fg, Some(Color::Green));
        assert_eq!(state_style(&DialogState::Failed).fg, Some(Color::Red));
        assert_eq!(state_style(&DialogState::Ringing).fg, Some(Color::Yellow));
        assert_eq!(arrow_style(true).fg, Some(Color::Red));
        assert_eq!(arrow_style(false).fg, Some(Color::Green));
        assert_eq!(rotation_style(0).fg, Some(Color::Cyan));
        assert_eq!(rotation_style(7).fg, Some(Color::Cyan));
        assert_eq!(list_highlight().bg, Some(Color::Blue));
        assert_eq!(list_highlight().fg, Some(Color::White));
        assert!(flow_selection().bg.is_none());
        assert!(flow_selection().add_modifier.contains(Modifier::REVERSED));

        let mut theme = Theme::default();
        apply_theme(&mut theme);
        assert!(theme.sngrep);
        assert_eq!(theme.status_bg, Color::Cyan);
        assert_eq!(theme.header, Color::Cyan);
        let mut mono = Theme::monochrome();
        apply_theme(&mut mono);
        assert!(!mono.sngrep, "NO_COLOR wins over sngrep colors");
    }

    #[test]
    fn syntax_colors_match_sngrep() {
        let raw =
            "INVITE sip:9021@x SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nVia: v\r\n\r\nv=0\r\n";
        let l = syntax_lines(raw);
        assert_eq!(l[0].spans[0].style.fg, Some(Color::Yellow));
        assert_eq!(l[0].spans[2].style.fg, Some(Color::Cyan));
        assert_eq!(l[1].spans[0].style.fg, Some(Color::Green));
        assert_eq!(l[1].spans[2].style.fg, Some(Color::Magenta));
        assert_eq!(l[2].spans[2].style.fg, Some(Color::Yellow));
        assert_eq!(l[2].spans[2].content, "INVITE");
        assert_eq!(l[5].spans[0].style.fg, None, "body is plain");
        let resp = syntax_lines("SIP/2.0 486 Busy Here\r\n");
        assert_eq!(resp[0].spans[1].style.fg, Some(Color::Red));
    }

    /// The raw pane colors: a header name WITH its colon green, `;branch`
    /// bold cyan, `;tag` bold green except on From:, where it is bold
    /// default; a space or `;` ends a run.
    #[test]
    fn syntax_tag_branch_and_colon_match_sngrep() {
        let raw = "INVITE sip:9021@x;transport=udp SIP/2.0\r\n\
                   Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n\
                   From: <sip:a@x>;tag=f1\r\n\
                   To: <sip:b@x>;tag=t2\r\n\
                   \r\n\
                   m=audio 1 RTP/AVP 0\r\n";
        let l = syntax_lines(raw);
        let span = |line: usize, text: &str| {
            l[line]
                .spans
                .iter()
                .find(|s| s.content == text)
                .map(|s| s.style)
                .unwrap_or_else(|| panic!("no span {text:?} in {:?}", l[line]))
        };
        let bold = |c| Style::default().fg(c).add_modifier(Modifier::BOLD);
        assert_eq!(span(0, "sip:9021@x"), bold(Color::Cyan), "URI up to the ;");
        assert_eq!(span(1, "Via:"), Style::default().fg(Color::Green));
        assert_eq!(span(1, "branch=z9hG4bK1"), bold(Color::Cyan));
        assert_eq!(
            span(2, "tag=f1"),
            Style::default().add_modifier(Modifier::BOLD)
        );
        assert_eq!(span(3, "tag=t2"), bold(Color::Green));
        assert_eq!(l[4].spans.len(), 0, "the blank line");
        assert_eq!(l[5].spans[0].style, Style::default(), "SDP plain");
        let resp = syntax_lines("SIP/2.0 486 Busy Here\r\n");
        assert_eq!(resp[0].spans[1].content, "486", "only the code is red");
    }

    /// The SDP form on the arrow: the first three letters and the first
    /// media's address, one line per RTP media naming its first codec.
    #[test]
    fn sdp_info_names_media_and_codec() {
        let offer = b"v=0\r\no=- 1 1 IN IP4 192.168.1.26\r\ns=-\r\n\
                      c=IN IP4 192.168.1.26\r\nt=0 0\r\n\
                      m=audio 12220 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\n\
                      m=video 12222 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n";
        let (title, media) = sdp_info("INVITE", offer).expect("media");
        assert_eq!(title, "INV (192.168.1.26)");
        assert_eq!(media, ["audio 12220 (PCMU)", "video 12222 (H264)"]);

        let answer = b"v=0\r\nc=IN IP4 192.168.1.27\r\n\
                       m=audio 30000 RTP/AVP 8 101\r\nm=video 0 RTP/AVP 96\r\n";
        let (title, media) = sdp_info("200 OK", answer).expect("media");
        assert_eq!(title, "200 (192.168.1.27)");
        assert_eq!(media, ["audio 30000 (PCMA)", "video 0 (dynamic)"]);

        // A media-level c= is the media's own address (RFC 4566 5.7).
        let own = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 18\r\nc=IN IP4 10.0.0.9\r\n";
        let (title, media) = sdp_info("UPDATE", own).expect("media");
        assert_eq!(title, "UPD (10.0.0.9)");
        assert_eq!(media, ["audio 4000 (G729)"]);
        // SRTP over DTLS is RTP too; T.38 over udptl alone is no RTP media.
        let webrtc = b"v=0\r\nc=IN IP4 10.0.0.2\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                       a=rtpmap:111 opus/48000/2\r\n";
        assert_eq!(
            sdp_info("INVITE", webrtc).expect("media").1,
            ["audio 9 (opus)"]
        );
        assert!(
            sdp_info(
                "INVITE",
                b"v=0\r\nc=IN IP4 1.2.3.4\r\nm=image 5000 udptl t38\r\n"
            )
            .is_none()
        );
        assert!(sdp_info("INVITE", b"").is_none());
    }

    /// Every key the sngrep-mode bar names reaches a sipnab command.
    #[test]
    fn every_key_on_the_sngrep_bar_is_answered() {
        let km = Keymap::default();
        let views = [
            View::CallList,
            flow(),
            View::RawMessage {
                call_id: "cid".to_string(),
                message_index: 0,
            },
        ];
        for (view, alt) in views.iter().flat_map(|v| [(v, false), (v, true)]) {
            let Some(bar) = fkey_bar(view, alt) else {
                panic!("no sngrep bar");
            };
            for (legend, _) in bar {
                if legend.is_empty() {
                    continue; // sngrep prints no alternative for F9
                }
                if legend == "^L" {
                    // sipnab's own Ctrl+L (list) or the sngrep clear (flow).
                    assert!(!matches!(
                        translate(view, &km, ctrl('l')),
                        Translated::Unsupported(_)
                    ));
                    continue;
                }
                let code = match legend {
                    "Esc" => KeyCode::Esc,
                    "Enter" => KeyCode::Enter,
                    "Space" => KeyCode::Char(' '),
                    f if f.starts_with('F') && f.len() > 1 => {
                        KeyCode::F(f[1..].parse().unwrap_or(0))
                    }
                    c => KeyCode::Char(c.chars().next().unwrap_or(' ')),
                };
                assert!(
                    !matches!(translate(view, &km, key(code)), Translated::Unsupported(_)),
                    "{legend} is on the sngrep bar but has no sipnab command"
                );
            }
        }
    }

    /// `K` swaps each function key on the bar for the letter that does the
    /// same; a command with one key keeps it.
    #[test]
    fn alternative_hints_show_the_letters() {
        let legends = |v: &View, alt| -> Vec<&str> {
            fkey_bar(v, alt)
                .unwrap_or_default()
                .iter()
                .map(|(k, _)| *k)
                .collect()
        };
        assert_eq!(
            legends(&View::CallList, true),
            [
                "q", "h", "Enter", "Space", "s", "/", "P", "x", "^L", "f", "o", "F9", "t"
            ]
        );
        assert_eq!(
            legends(&View::CallList, false),
            [
                "Esc", "F1", "Enter", "Space", "F2", "F3", "P", "F4", "F5", "F7", "F8", "F9", "F10"
            ]
        );
        assert_eq!(
            legends(&flow(), true),
            [
                "q", "h", "Enter", "Space", "d", "m", "x", "R", "s", "c", "9"
            ]
        );
        assert!(fkey_bar(&View::Help, false).is_none());
        let km = Keymap::default();
        assert_eq!(
            translate(&View::CallList, &km, key(KeyCode::Char('K'))),
            Translated::Act(SngrepAction::ToggleHints)
        );
    }

    #[test]
    fn autoscroll_row_is_sngreps_last() {
        assert_eq!(autoscroll_row(0, true), None);
        assert_eq!(autoscroll_row(5, true), Some(4));
        assert_eq!(autoscroll_row(5, false), Some(0));
    }

    #[test]
    fn autoscroll_stops_on_sngreps_keys_only() {
        for c in [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Char('j'),
            KeyCode::Char('k'),
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::F(3),
            KeyCode::Char('/'),
            KeyCode::Tab,
        ] {
            assert!(stops_autoscroll(key(c)), "{c:?}");
        }
        for c in ['f', 'b', 'd', 'u', 'a', 'e'] {
            assert!(stops_autoscroll(ctrl(c)), "Ctrl+{c}");
        }
        for c in [
            KeyCode::Char('A'),
            KeyCode::Char('P'),
            KeyCode::Char(' '),
            KeyCode::Enter,
            KeyCode::Char('z'),
            KeyCode::F(7),
        ] {
            assert!(!stops_autoscroll(key(c)), "{c:?}");
        }
        assert!(!stops_autoscroll(ctrl('w')));
    }

    #[test]
    fn ctrl_w_unchecks_all_calls() {
        let km = Keymap::default();
        assert_eq!(
            translate(&View::CallList, &km, ctrl('w')),
            Translated::Act(SngrepAction::UncheckAll)
        );
    }

    #[test]
    fn column_selector_minus_plus_move_a_column() {
        assert_eq!(
            translate_column_select(key(KeyCode::Char('-'))),
            Translated::Act(SngrepAction::MoveColumn { down: false })
        );
        assert_eq!(
            translate_column_select(key(KeyCode::Char('+'))),
            Translated::Act(SngrepAction::MoveColumn { down: true })
        );
        assert_eq!(
            translate_column_select(key(KeyCode::Char('q'))),
            Translated::Key(key(KeyCode::Esc))
        );
        assert_eq!(
            translate_column_select(key(KeyCode::Char(' '))),
            Translated::Pass
        );
        let mut st = crate::tui::call_list::CallListState::new();
        st.column_selector_cursor = 2;
        st.move_column(true);
        assert_eq!(st.column_selector_cursor, 3);
        assert_eq!(&st.column_order[..4], [0, 1, 3, 2]);
        st.move_column(false);
        st.move_column(false);
        assert_eq!(&st.column_order[..4], [0, 2, 1, 3]);
        st.column_selector_cursor = 0;
        st.move_column(false);
        assert_eq!(st.column_order[0], 0);
        st.column_selector_cursor = 10;
        st.move_column(true);
        assert_eq!(st.column_selector_cursor, 10);
        // Space toggles the column under the cursor, wherever it moved.
        st.column_selector_cursor = 1;
        st.toggle_column_visibility();
        assert!(!st.visible_columns[2]);
    }

    /// The raw pane takes what the ladder leaves, at least 40 columns; 9 / 0
    /// step 2 columns and stop at the time column / ten columns; T (fixed =
    /// None) recomputes.
    #[test]
    fn raw_pane_takes_what_the_ladder_leaves() {
        let three = ladder_need(3, false);
        assert_eq!(three, 13 + 3 * 28);
        assert_eq!(ladder_need(3, true), three + 12);
        assert_eq!(raw_width(200, three, None), 200 - three - 2);
        assert_eq!(
            raw_width(120, three, None),
            RAW_MIN_WIDTH,
            "never below the minimum"
        );
        assert_eq!(
            raw_width(200, three, Some(60)),
            60,
            "a width set with 9 / 0 is kept"
        );
        assert_eq!(step_raw(100, 200, true), Some(102));
        assert_eq!(step_raw(100, 200, false), Some(98));
        assert_eq!(step_raw(183, 200, true), Some(185));
        assert_eq!(step_raw(184, 200, true), None, "the time column stays");
        assert_eq!(step_raw(12, 200, false), Some(10));
        assert_eq!(step_raw(11, 200, false), None, "the pane keeps ten columns");
    }

    fn row(
        kind: crate::tui::call_flow::prepare::RowKind,
        raw: Option<usize>,
        s: usize,
        d: usize,
    ) -> crate::tui::call_flow::LayoutRow {
        crate::tui::call_flow::LayoutRow {
            timestamp: String::new(),
            ts_class: crate::tui::call_flow::prepare::TsClass::Muted,
            label: String::new(),
            kind,
            src_col: s,
            dst_col: d,
            pdd_note: None,
            extra_lines: Vec::new(),
            extra_centered: false,
            call_id: String::new(),
            is_response: false,
            raw_timestamp: chrono::DateTime::<chrono::Utc>::default(),
            folded_count: 0,
            fold_label: None,
            sdp_badge: None,
            is_retransmission: false,
            raw_index: raw,
            diagnosis_note: None,
            label_fallbacks: Vec::new(),
            stream_key: None,
        }
    }

    fn msg() -> crate::tui::call_flow::prepare::RowKind {
        crate::tui::call_flow::prepare::RowKind::Message {
            class: crate::tui::call_flow::prepare::MessageClass::OtherRequest,
            cid_idx: 0,
            cseq_idx: 0,
        }
    }

    #[test]
    fn sdp_only_and_only_media_filter_the_ladder() {
        use crate::tui::call_flow::prepare::RowKind;
        let rows = vec![
            row(msg(), Some(0), 0, 1),
            row(RowKind::Spacer, None, 0, 0),
            row(msg(), Some(1), 1, 0),
            row(RowKind::RtpStream, None, 0, 1),
        ];
        let has_sdp = |i: usize| i == 0;
        let d = filter_rows(rows.clone(), true, false, has_sdp);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].raw_index, Some(0));
        let m = filter_rows(rows.clone(), false, true, has_sdp);
        assert_eq!(m.len(), 1);
        assert!(matches!(m[0].kind, RowKind::RtpStream));
        assert_eq!(filter_rows(rows.clone(), false, false, has_sdp).len(), 4);
    }

    #[test]
    fn compress_merges_columns_by_host() {
        use crate::tui::call_flow::Participant;
        let p = |a: &str| Participant {
            addr: a.to_string(),
            label: a.to_string(),
        };
        let parts = vec![
            p("10.0.0.1:5060"),
            p("10.0.0.2:5060"),
            p("10.0.0.1:5080"),
            p("[2001:db8::1]:5060"),
        ];
        let rows = vec![row(msg(), Some(0), 2, 1)];
        let (m, r) = compress_participants(parts, rows, |h| format!("<{h}>"));
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].addr, "10.0.0.1");
        assert_eq!(m[2].label, "<2001:db8::1>");
        assert_eq!((r[0].src_col, r[0].dst_col), (0, 1));
        assert_eq!(host_of("sbc.example"), "sbc.example");
        // Two addresses with one alias are one column, as in sngrep.
        let parts = vec![
            p("10.0.206.111:5070"),
            p("5.149.35.19:15100"),
            p("128.199.52.218:5060"),
        ];
        let rows = vec![row(msg(), Some(0), 2, 1)];
        let alias = |h: &str| {
            if h == "5.149.35.19" {
                h.to_string()
            } else {
                "proxy".to_string()
            }
        };
        let (m, r) = compress_participants(parts, rows, alias);
        assert_eq!(m.len(), 2);
        assert_eq!((r[0].src_col, r[0].dst_col), (0, 1));
    }
}
