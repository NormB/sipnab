//! Interactive terminal UI for sipnab.
//!
//! Provides the sngrep-replacement mode: a full-screen TUI with call list,
//! RTP stream list, call flow ladder diagrams, and raw message viewing.
//! Built on [`ratatui`] + [`crossterm`] with adaptive refresh rates
//! (100ms active, 500ms idle, immediate on keypress).

pub mod call_flow;
pub mod call_list;
pub mod help;
pub mod msg_raw;
pub mod stream_detail;
pub mod stream_list;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use parking_lot::RwLock;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;

use call_list::CallListState;
use stream_list::StreamListState;

use crate::config::{KeybindingsConfig, ThemeConfig, parse_color, parse_keycode};

// ── Resolved theme and keymap ──────────────────────────────────────

/// Resolved TUI color theme — all fields are concrete `Color` values.
#[derive(Debug, Clone)]
pub struct Theme {
    pub background: Color,
    pub foreground: Color,
    pub header: Color,
    pub selected: Color,
    pub accent: Color,
    pub good: Color,
    pub warning: Color,
    pub bad: Color,
    pub muted: Color,
    pub border: Color,
    /// Status bar background — distinct from terminal bg for visibility.
    pub status_bg: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            background: Color::Reset,
            foreground: Color::White,
            header: Color::Cyan,
            selected: Color::Yellow,
            accent: Color::Magenta,
            good: Color::Green,
            warning: Color::Yellow,
            bad: Color::Red,
            muted: Color::DarkGray,
            border: Color::White,
            status_bg: Color::Rgb(48, 48, 64), // Dark blue-gray, readable on both dark and light
        }
    }
}

/// Apply an optional config color string to a theme field.
fn apply_color(field: &mut Color, value: &Option<String>) {
    if let Some(s) = value
        && let Some(c) = parse_color(s)
    {
        *field = c;
    }
}

/// Apply an optional config key string to a keymap field.
fn apply_key(field: &mut KeyCode, value: &Option<String>) {
    if let Some(s) = value
        && let Some(k) = parse_keycode(s)
    {
        *field = k;
    }
}

impl Theme {
    /// Build a resolved theme from config, falling back to defaults.
    pub fn from_config(config: &ThemeConfig) -> Self {
        let mut t = Self::default();
        apply_color(&mut t.background, &config.background);
        apply_color(&mut t.foreground, &config.foreground);
        apply_color(&mut t.header, &config.header);
        // "highlight" is a legacy alias for "selected"
        apply_color(&mut t.selected, &config.highlight);
        apply_color(&mut t.selected, &config.selected);
        apply_color(&mut t.accent, &config.accent);
        apply_color(&mut t.good, &config.good);
        apply_color(&mut t.warning, &config.warning);
        apply_color(&mut t.bad, &config.bad);
        apply_color(&mut t.muted, &config.muted);
        apply_color(&mut t.border, &config.border);
        t
    }
}

/// Resolved keymap — all fields are concrete `KeyCode` values.
#[derive(Debug, Clone)]
pub struct Keymap {
    pub quit: KeyCode,
    pub help: KeyCode,
    pub save: KeyCode,
    pub search: KeyCode,
    pub filter: KeyCode,
    pub settings: KeyCode,
    pub pause: KeyCode,
    pub autoscroll: KeyCode,
    pub extended_flow: KeyCode,
    pub clear_calls: KeyCode,
    pub column_selector: KeyCode,
}

impl Default for Keymap {
    fn default() -> Self {
        Self {
            quit: KeyCode::Char('q'),
            help: KeyCode::F(1),
            save: KeyCode::F(2),
            search: KeyCode::Char('/'),
            filter: KeyCode::F(7),
            settings: KeyCode::F(8),
            pause: KeyCode::Char('p'),
            autoscroll: KeyCode::Char('A'),
            extended_flow: KeyCode::F(4),
            clear_calls: KeyCode::F(5),
            column_selector: KeyCode::F(10),
        }
    }
}

impl Keymap {
    /// Build a resolved keymap from config, falling back to defaults.
    pub fn from_config(config: &KeybindingsConfig) -> Self {
        let mut km = Self::default();
        apply_key(&mut km.quit, &config.quit);
        apply_key(&mut km.help, &config.help);
        apply_key(&mut km.save, &config.save);
        apply_key(&mut km.search, &config.search);
        apply_key(&mut km.filter, &config.filter);
        apply_key(&mut km.settings, &config.settings);
        apply_key(&mut km.pause, &config.pause);
        apply_key(&mut km.autoscroll, &config.autoscroll);
        apply_key(&mut km.extended_flow, &config.extended_flow);
        apply_key(&mut km.clear_calls, &config.clear_calls);
        apply_key(&mut km.column_selector, &config.column_selector);
        km
    }
}

// ── Adaptive refresh constants ──────────────────────────────────────

/// Poll timeout when data was recently updated.
const ACTIVE_POLL_MS: u64 = 100;
/// Poll timeout when idle (no recent updates).
const IDLE_POLL_MS: u64 = 500;
/// Duration after the last data update before switching to idle polling.
const IDLE_THRESHOLD: Duration = Duration::from_secs(2);

// ── Display mode enums ──────────────────────────────────────────────

/// SDP display mode for the call flow ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SdpDisplayMode {
    /// No SDP detail — just "(SDP)" label on the arrow.
    #[default]
    None,
    /// Summary — show codec list below the arrow.
    Summary,
    /// Full — show complete SDP body below the arrow.
    Full,
}

impl SdpDisplayMode {
    /// Cycle to the next mode.
    fn next(self) -> Self {
        match self {
            Self::None => Self::Summary,
            Self::Summary => Self::Full,
            Self::Full => Self::None,
        }
    }

    /// Human-readable label for the status bar.
    fn label(self) -> &'static str {
        match self {
            Self::None => "SDP: Hidden",
            Self::Summary => "SDP: Summary",
            Self::Full => "SDP: Full",
        }
    }
}

/// Timestamp display mode for the call flow ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimestampMode {
    /// Absolute `HH:MM:SS.mmm`.
    Absolute,
    /// Delta from the previous message (`+N.NNNs`).
    #[default]
    DeltaPrev,
    /// Delta from the first message (`+N.NNNs`).
    DeltaFirst,
    /// Time-proportional: insert spacer rows for large timing gaps.
    Scaled,
}

impl TimestampMode {
    fn next(self) -> Self {
        match self {
            Self::Absolute => Self::DeltaPrev,
            Self::DeltaPrev => Self::DeltaFirst,
            Self::DeltaFirst => Self::Scaled,
            Self::Scaled => Self::Absolute,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Absolute => "Time: Absolute",
            Self::DeltaPrev => "Time: Delta-prev",
            Self::DeltaFirst => "Time: Delta-first",
            Self::Scaled => "Time: Scaled",
        }
    }
}

/// Color mode for call flow arrows and raw message highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// Color by SIP method (INVITE=green, BYE=red, ...).
    #[default]
    Method,
    /// All messages in the same dialog share a color, different dialogs rotate.
    CallId,
    /// Color by CSeq number.
    CSeq,
}

impl ColorMode {
    fn next(self) -> Self {
        match self {
            Self::Method => Self::CallId,
            Self::CallId => Self::CSeq,
            Self::CSeq => Self::Method,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Method => "Color: Method",
            Self::CallId => "Color: Call-ID",
            Self::CSeq => "Color: CSeq",
        }
    }
}

/// Save file format for the F2 save dialog.
///
/// Cycle order (Tab): PCAP → PCAP-NG → TXT → JSON → NDJSON → CSV →
/// HTML → Markdown → WAV → SIPp → RTP → PCAP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaveFormat {
    /// Standard pcap format.
    #[default]
    Pcap,
    /// PCAP-NG format.
    PcapNg,
    /// Plain text SIP messages (sngrep-compatible .txt/.sip).
    Txt,
    /// JSON — full call detail with parsed headers, timings, RTP stats.
    Json,
    /// NDJSON — newline-delimited JSON, streaming-friendly for large captures.
    Ndjson,
    /// CSV — summary rows per call/dialog for spreadsheets and BI tools.
    Csv,
    /// HTML ladder diagram (Mermaid + renderer, zero dependencies).
    Html,
    /// Markdown call summary — for tickets and incident documentation.
    Markdown,
    /// WAV audio extracted from RTP (G.711 mu-law/A-law).
    Wav,
    /// SIPp XML scenario for call replay/testing.
    SippXml,
    /// RTP/RTCP quality JSON — jitter, loss, MOS per stream.
    RtpJson,
}

impl SaveFormat {
    /// Cycle to the next format (Tab).
    pub fn next(self) -> Self {
        match self {
            Self::Pcap => Self::PcapNg,
            Self::PcapNg => Self::Txt,
            Self::Txt => Self::Json,
            Self::Json => Self::Ndjson,
            Self::Ndjson => Self::Csv,
            Self::Csv => Self::Html,
            Self::Html => Self::Markdown,
            Self::Markdown => Self::Wav,
            Self::Wav => Self::SippXml,
            Self::SippXml => Self::RtpJson,
            Self::RtpJson => Self::Pcap,
        }
    }

    /// Cycle to the previous format (Shift-Tab).
    pub fn prev(self) -> Self {
        match self {
            Self::Pcap => Self::RtpJson,
            Self::PcapNg => Self::Pcap,
            Self::Txt => Self::PcapNg,
            Self::Json => Self::Txt,
            Self::Ndjson => Self::Json,
            Self::Csv => Self::Ndjson,
            Self::Html => Self::Csv,
            Self::Markdown => Self::Html,
            Self::Wav => Self::Markdown,
            Self::SippXml => Self::Wav,
            Self::RtpJson => Self::SippXml,
        }
    }

    /// File extension for this format.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
            Self::Txt => "txt",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Csv => "csv",
            Self::Html => "html",
            Self::Markdown => "md",
            Self::Wav => "wav",
            Self::SippXml => "xml",
            Self::RtpJson => "rtp.json",
        }
    }

    /// Display label for this format.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pcap => "PCAP",
            Self::PcapNg => "PCAP-NG",
            Self::Txt => "TXT",
            Self::Json => "JSON",
            Self::Ndjson => "NDJSON",
            Self::Csv => "CSV",
            Self::Html => "HTML",
            Self::Markdown => "MD",
            Self::Wav => "WAV",
            Self::SippXml => "SIPp",
            Self::RtpJson => "RTP",
        }
    }

    /// Category grouping for the save dialog display.
    pub fn category(self) -> &'static str {
        match self {
            Self::Pcap | Self::PcapNg => "Packet Capture",
            Self::Txt | Self::SippXml => "SIP-Specific",
            Self::Json | Self::Ndjson | Self::Csv => "Structured/Analytics",
            Self::Html | Self::Markdown => "Reporting",
            Self::Wav | Self::RtpJson => "RTP/Media",
        }
    }

    /// Short description for the save dialog.
    pub fn description(self) -> &'static str {
        match self {
            Self::Pcap => "Universal baseline (Wireshark, tcpdump, Homer)",
            Self::PcapNg => "Modern format with metadata and annotations",
            Self::Txt => "Plain text SIP messages (sngrep-compatible)",
            Self::Json => "Full call detail for ELK, ClickHouse, etc.",
            Self::Ndjson => "Streaming-friendly for large captures",
            Self::Csv => "Summary rows for spreadsheets and BI tools",
            Self::Html => "Self-contained ladder diagram, zero dependencies",
            Self::Markdown => "Call summary for tickets and incidents",
            Self::Wav => "Decoded G.711 audio per RTP stream",
            Self::SippXml => "Replayable SIPp scenario for QA testing",
            Self::RtpJson => "Jitter, packet loss, MOS per stream",
        }
    }
}

// ── Filter dialog state ────────────────────────────────────────────

/// SIP methods displayed as checkboxes in the filter dialog.
/// Arranged in two columns matching sngrep's layout.
const FILTER_METHODS: [&str; 10] = [
    "REGISTER",
    "OPTIONS",
    "INVITE",
    "PUBLISH",
    "SUBSCRIBE",
    "MESSAGE",
    "NOTIFY",
    "REFER",
    "INFO",
    "UPDATE",
];

/// Number of text input fields in the filter dialog.
const FILTER_TEXT_FIELD_COUNT: usize = 5;

/// Total focusable items: 5 text fields + 10 checkboxes + 2 buttons.
const FILTER_ITEM_COUNT: usize = FILTER_TEXT_FIELD_COUNT + FILTER_METHODS.len() + 2;

/// Index of the "Filter" button in focused_field.
const FILTER_BUTTON_IDX: usize = FILTER_TEXT_FIELD_COUNT + FILTER_METHODS.len();
/// Index of the "Cancel" button in focused_field.
const CANCEL_BUTTON_IDX: usize = FILTER_BUTTON_IDX + 1;

/// Number of rows in the settings popup.
const SETTINGS_ITEM_COUNT: usize = 6;

/// Structured state for the settings popup dialog.
#[derive(Debug, Clone, Default)]
struct SettingsDialogState {
    /// Currently highlighted row (0-based).
    focused_item: usize,
}

/// Structured state for the sngrep-style filter dialog.
#[derive(Debug, Clone, Default)]
pub struct FilterDialogState {
    /// SIP From header filter text.
    sip_from: String,
    /// SIP To header filter text.
    sip_to: String,
    /// Source IP/port filter text.
    source: String,
    /// Destination IP/port filter text.
    destination: String,
    /// Payload content filter text.
    payload: String,
    /// Method checkbox states, indexed by position in FILTER_METHODS.
    methods: [bool; 10],
    /// Currently focused UI element index.
    /// 0-4 = text fields, 5-14 = checkboxes, 15 = Filter button, 16 = Cancel button.
    focused_field: usize,
    /// Cursor position within the currently focused text field.
    cursor_pos: usize,
}

impl FilterDialogState {
    /// Get a reference to the text field at the given index (0-4).
    fn text_field(&self, idx: usize) -> &str {
        match idx {
            0 => &self.sip_from,
            1 => &self.sip_to,
            2 => &self.source,
            3 => &self.destination,
            4 => &self.payload,
            _ => "",
        }
    }

    /// Get a mutable reference to the text field at the given index (0-4).
    fn text_field_mut(&mut self, idx: usize) -> Option<&mut String> {
        match idx {
            0 => Some(&mut self.sip_from),
            1 => Some(&mut self.sip_to),
            2 => Some(&mut self.source),
            3 => Some(&mut self.destination),
            4 => Some(&mut self.payload),
            _ => None,
        }
    }

    /// Whether the currently focused element is a text field.
    fn is_text_field_focused(&self) -> bool {
        self.focused_field < FILTER_TEXT_FIELD_COUNT
    }

    /// Whether the currently focused element is a checkbox.
    fn is_checkbox_focused(&self) -> bool {
        self.focused_field >= FILTER_TEXT_FIELD_COUNT && self.focused_field < FILTER_BUTTON_IDX
    }

    /// Get the checkbox index (0-9) for the currently focused element.
    fn checkbox_index(&self) -> Option<usize> {
        if self.is_checkbox_focused() {
            Some(self.focused_field - FILTER_TEXT_FIELD_COUNT)
        } else {
            None
        }
    }

    /// Move focus to the next element.
    fn focus_next(&mut self) {
        if self.focused_field + 1 < FILTER_ITEM_COUNT {
            self.focused_field += 1;
        } else {
            self.focused_field = 0;
        }
        self.sync_cursor();
    }

    /// Move focus to the previous element.
    fn focus_prev(&mut self) {
        if self.focused_field > 0 {
            self.focused_field -= 1;
        } else {
            self.focused_field = FILTER_ITEM_COUNT - 1;
        }
        self.sync_cursor();
    }

    /// Sync cursor position to end of the newly focused text field.
    fn sync_cursor(&mut self) {
        if self.is_text_field_focused() {
            let len = self.text_field(self.focused_field).len();
            self.cursor_pos = len;
        }
    }

    /// Move checkbox focus down one row (same column).
    fn checkbox_down(&mut self) {
        if let Some(idx) = self.checkbox_index() {
            let next = idx + 2;
            if next < FILTER_METHODS.len() {
                self.focused_field = FILTER_TEXT_FIELD_COUNT + next;
            } else {
                // Move to buttons row
                self.focused_field = FILTER_BUTTON_IDX;
            }
        }
    }

    /// Move checkbox focus up one row (same column).
    fn checkbox_up(&mut self) {
        if let Some(idx) = self.checkbox_index() {
            if idx >= 2 {
                self.focused_field = FILTER_TEXT_FIELD_COUNT + (idx - 2);
            } else {
                // Move up to last text field
                self.focused_field = FILTER_TEXT_FIELD_COUNT - 1;
                self.sync_cursor();
            }
        }
    }

    /// Move checkbox focus right one column (same row).
    fn checkbox_right(&mut self) {
        if let Some(idx) = self.checkbox_index()
            && idx % 2 == 0
            && idx + 1 < FILTER_METHODS.len()
        {
            self.focused_field = FILTER_TEXT_FIELD_COUNT + idx + 1;
        }
    }

    /// Move checkbox focus left one column (same row).
    fn checkbox_left(&mut self) {
        if let Some(idx) = self.checkbox_index()
            && idx % 2 == 1
        {
            self.focused_field = FILTER_TEXT_FIELD_COUNT + idx - 1;
        }
    }

    /// Toggle the currently focused checkbox.
    fn toggle_checkbox(&mut self) {
        if let Some(idx) = self.checkbox_index() {
            self.methods[idx] = !self.methods[idx];
        }
    }

    /// Build a DSL filter expression from the current dialog state.
    /// Returns `None` if all fields are empty and no methods are checked.
    fn build_filter_expression(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();

        if !self.sip_from.is_empty() {
            parts.push(format!("from.user =~ '{}'", self.sip_from));
        }
        if !self.sip_to.is_empty() {
            parts.push(format!("to.user =~ '{}'", self.sip_to));
        }
        if !self.source.is_empty() {
            parts.push(format!("src.ip =~ '{}'", self.source));
        }
        if !self.destination.is_empty() {
            parts.push(format!("dst.ip =~ '{}'", self.destination));
        }
        // Payload is not in the DSL; skip it for now (placeholder for future)

        // Method filter: if some (but not all or none) methods are checked
        let checked: Vec<&str> = self
            .methods
            .iter()
            .enumerate()
            .filter(|(_, v)| **v)
            .map(|(i, _)| FILTER_METHODS[i])
            .collect();
        let total = self.methods.len();
        if !checked.is_empty() && checked.len() < total {
            let method_filter = checked
                .iter()
                .map(|m| format!("method == '{m}'"))
                .collect::<Vec<_>>()
                .join(" OR ");
            parts.push(format!("({})", method_filter));
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" AND "))
        }
    }

    /// Clear all fields and checkboxes back to defaults.
    fn clear(&mut self) {
        self.sip_from.clear();
        self.sip_to.clear();
        self.source.clear();
        self.destination.clear();
        self.payload.clear();
        self.methods = [false; 10];
        self.focused_field = 0;
        self.cursor_pos = 0;
    }

    /// Return the currently focused field index (for testing).
    pub fn focused_field(&self) -> usize {
        self.focused_field
    }

    /// Whether all fields are empty and no methods are checked.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.sip_from.is_empty()
            && self.sip_to.is_empty()
            && self.source.is_empty()
            && self.destination.is_empty()
            && self.payload.is_empty()
            && self.methods.iter().all(|&v| !v)
    }
}

// ── View enum ───────────────────────────────────────────────────────

/// Which view is currently displayed in the TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// Main call/dialog list table.
    CallList,
    /// RTP stream list table.
    StreamList,
    /// Ladder diagram for a specific dialog (by Call-ID).
    CallFlow(String),
    /// Raw SIP message viewer (message index within a dialog).
    RawMessage {
        /// Call-ID of the dialog containing this message.
        call_id: String,
        /// Index into the dialog's message list.
        message_index: usize,
    },
    /// Side-by-side diff of two SIP messages.
    MessageDiff {
        /// Call-ID of the dialog.
        call_id: String,
        /// Index of the first message.
        msg1_idx: usize,
        /// Index of the second message.
        msg2_idx: usize,
    },
    /// Keybinding help overlay.
    Help,
    /// Statistics summary view.
    Statistics,
    /// RTP stream detail (by StreamKey).
    StreamDetail(crate::rtp::stream::StreamKey),
}

/// Modal popup dialogs that overlay the current view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Popup {
    /// Save capture popup with editable file path.
    SaveDialog,
    /// Filter expression input popup.
    FilterDialog,
    /// Settings/preferences popup.
    SettingsDialog,
    /// File-open dialog for loading a pcap file.
    FileOpenDialog,
}

// ── App state ───────────────────────────────────────────────────────

/// Top-level application state for the TUI.
pub struct App {
    /// Shared dialog store (written by the processing thread).
    dialog_store: Arc<RwLock<DialogStore>>,
    /// Shared RTP stream store (written by the processing thread).
    stream_store: Arc<RwLock<StreamStore>>,
    /// Currently active view.
    current_view: View,
    /// Active modal popup overlay (rendered on top of the current view).
    active_popup: Option<Popup>,
    /// State for the call list table.
    call_list: CallListState,
    /// State for the stream list table.
    stream_list: StreamListState,
    /// Set to `true` to exit the event loop.
    should_quit: bool,
    /// When data was last updated (for adaptive refresh).
    last_data_update: Instant,
    last_known_dialog_count: usize,
    stream_detail_scroll: usize,
    /// Structured filter dialog state (preserved between opens).
    pub filter_dialog: FilterDialogState,
    /// Settings popup state.
    settings_dialog: SettingsDialogState,
    /// Active filter expression (applied to the call list).
    active_filter: Option<FilterExpr>,
    /// Human-readable text of the active filter (for the status bar).
    active_filter_text: String,
    /// Transient status bar error message (cleared on next view change).
    status_error: Option<String>,
    /// Scroll offset for call flow view.
    call_flow_scroll: usize,
    /// Scroll offset for raw message view.
    raw_msg_scroll: u16,
    /// Search query for inline search.
    search_query: String,
    /// Whether search input mode is active.
    search_active: bool,
    /// Capture mode label: "Online (device)" or "Offline (filename)".
    capture_mode: String,
    /// BPF filter string if set via CLI.
    bpf_filter: String,
    /// Cached total dialog count (updated when lock is available).
    cached_dialog_count: usize,
    /// Cached displayed dialog count (updated when lock is available).
    cached_displayed_count: usize,
    /// Cached rendered message count for the current call flow (after folding).
    cached_flow_msg_count: usize,
    /// Indices of FormattedMessages that carry an RTP bar (for Enter drill-down).
    cached_rtp_bar_indices: std::collections::HashSet<usize>,
    /// Call flow line cache: `(call_id, msg_count) -> formatted lines`.
    /// Invalidated when the dialog's message count changes.
    call_flow_cache: HashMap<String, (usize, Vec<Line<'static>>)>,
    /// Save dialog file path input.
    save_path: String,
    /// Cursor position within the save path string.
    save_cursor: usize,
    /// Cached message/dialog counts for the save dialog display.
    save_dialog_count: usize,
    /// Cached selected dialog count for the save dialog display.
    save_selected_count: usize,
    /// Cached total message count for the save dialog display.
    save_message_count: usize,
    /// Selected save format (PCAP, PCAP-NG, or TXT).
    save_format: SaveFormat,
    /// File-open dialog: path being edited.
    open_path: String,
    /// File-open dialog: cursor position in path.
    open_cursor: usize,

    // ── Call flow display modes ────────────────────────────────────
    /// SDP display mode (None / Summary / Full).
    sdp_display_mode: SdpDisplayMode,
    /// Timestamp display mode (Absolute / Delta-prev / Delta-first).
    timestamp_mode: TimestampMode,
    /// Color mode for arrows (Method / CallId / CSeq).
    color_mode: ColorMode,
    /// Whether the raw preview split is active in call flow view.
    /// Default is `true` (matching sngrep: split view on by default).
    raw_preview: bool,
    /// Split percentage for the raw preview (right) pane (10..=80, default 40).
    raw_preview_pct: u16,
    /// Index of the currently selected message in the call flow ladder.
    selected_msg_index: usize,
    /// Scroll offset for the detail (right) panel in split view.
    detail_scroll: u16,
    /// Whether extended (multi-leg) flow is active.
    extended_flow: bool,
    /// Whether RTP stream info is displayed in the call flow.
    show_rtp_in_flow: bool,
    /// First selected message index for diff comparison (Space key).
    diff_selected_msg: Option<usize>,
    /// Marked message index for delta measurement (set with 'm').
    mark_index: Option<usize>,
    /// Set of message indices where folds are expanded (press 'e' to toggle).
    fold_expanded: HashSet<usize>,
    /// Whether syntax highlighting is enabled in raw message view.
    syntax_highlight: bool,
    /// Whether packet processing is paused (TUI-local flag).
    paused: bool,
    /// Shared pause flag for the processing thread.
    /// When `true`, the processing thread skips `process_message()`.
    paused_flag: Arc<AtomicBool>,
    /// Resolved TUI color theme.
    pub theme: Theme,
    /// Resolved key bindings.
    pub keymap: Keymap,
}

impl App {
    /// Create a new application state with shared stores.
    pub fn new(
        dialog_store: Arc<RwLock<DialogStore>>,
        stream_store: Arc<RwLock<StreamStore>>,
        theme: Theme,
        keymap: Keymap,
    ) -> Self {
        Self {
            dialog_store,
            stream_store,
            current_view: View::CallList,
            active_popup: None,
            call_list: CallListState::new(),
            stream_list: StreamListState::new(),
            should_quit: false,
            last_data_update: Instant::now(),
            last_known_dialog_count: 0,
            stream_detail_scroll: 0,
            filter_dialog: FilterDialogState::default(),
            settings_dialog: SettingsDialogState::default(),
            active_filter: None,
            active_filter_text: String::new(),
            status_error: None,
            call_flow_scroll: 0,
            raw_msg_scroll: 0,
            search_query: String::new(),
            search_active: false,
            capture_mode: "Online (any)".to_string(),
            bpf_filter: String::new(),
            cached_dialog_count: 0,
            cached_displayed_count: 0,
            cached_flow_msg_count: 0,
            cached_rtp_bar_indices: std::collections::HashSet::new(),
            call_flow_cache: HashMap::new(),
            save_path: String::new(),
            save_cursor: 0,
            save_dialog_count: 0,
            save_selected_count: 0,
            save_message_count: 0,
            save_format: SaveFormat::default(),
            open_path: String::new(),
            open_cursor: 0,
            sdp_display_mode: SdpDisplayMode::default(),
            timestamp_mode: TimestampMode::default(),
            color_mode: ColorMode::default(),
            raw_preview: true,
            raw_preview_pct: 40,
            selected_msg_index: 0,
            detail_scroll: 0,
            extended_flow: false,
            show_rtp_in_flow: false,
            diff_selected_msg: None,
            mark_index: None,
            fold_expanded: HashSet::new(),
            syntax_highlight: true,
            paused: false,
            paused_flag: Arc::new(AtomicBool::new(false)),
            theme,
            keymap,
        }
    }

    /// Set the capture mode label displayed in the status bar.
    pub fn set_capture_mode(&mut self, mode: String) {
        self.capture_mode = mode;
    }

    /// Set the BPF filter string displayed in the status bar.
    pub fn set_bpf_filter(&mut self, filter: String) {
        self.bpf_filter = filter;
    }

    /// Mark data as freshly updated (resets adaptive refresh timer).
    pub fn mark_data_updated(&mut self) {
        self.last_data_update = Instant::now();
    }

    /// Return whether packet processing is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Compute the poll timeout based on how recently data was updated.
    fn poll_timeout(&self) -> Duration {
        if self.last_data_update.elapsed() < IDLE_THRESHOLD {
            Duration::from_millis(ACTIVE_POLL_MS)
        } else {
            Duration::from_millis(IDLE_POLL_MS)
        }
    }
}

// ── Terminal guard ──────────────────────────────────────────────────

/// RAII guard that restores the terminal on drop, even during panics.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), crossterm::cursor::Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

// ── Public entry point ──────────────────────────────────────────────

/// Run the interactive TUI event loop.
///
/// This function takes ownership of the main thread. It sets up the
/// terminal, enters the event loop, and restores the terminal on exit
/// (including on panic via a Drop guard).
///
/// # Arguments
///
/// * `dialog_store` — Shared dialog store, updated by the processing thread.
/// * `stream_store` — Shared stream store, updated by the processing thread.
///
/// # Errors
///
/// Returns an error if terminal initialization or rendering fails.
pub fn run_tui(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
) -> Result<()> {
    run_tui_with_pause(dialog_store, stream_store, None, Theme::default(), Keymap::default())
}

/// Run the TUI with an optional shared pause flag.
///
/// When `paused_flag` is `Some`, the flag is shared with the processing
/// thread so that toggling pause in the TUI also pauses packet processing.
pub fn run_tui_with_pause(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    paused_flag: Option<Arc<AtomicBool>>,
    theme: Theme,
    keymap: Keymap,
) -> Result<()> {
    // Setup terminal
    terminal::enable_raw_mode()?;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::cursor::Hide,
        crossterm::cursor::MoveTo(0, 0)
    )?;

    // Guard ensures terminal is restored even on panic
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(dialog_store, stream_store, theme, keymap);
    if let Some(flag) = paused_flag {
        app.paused_flag = flag;
    }

    // Main event loop
    loop {
        if app.should_quit {
            break;
        }

        // Render
        terminal.draw(|frame| render_app(frame, &mut app))?;

        // Poll with adaptive timeout
        let timeout = app.poll_timeout();
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle_key_event(&mut app, key);
        }

        // Only mark data updated when store counts actually change
        // (prevents the TUI from staying in active-poll mode on static pcaps)
        let current_count = app.dialog_store.try_read().map(|ds| ds.len());
        if let Some(count) = current_count
            && count != app.last_known_dialog_count
        {
            app.last_known_dialog_count = count;
            app.mark_data_updated();
        }
    }

    Ok(())
}

// ── Rendering ───────────────────────────────────────────────────────

/// Render the entire application frame based on the current view.
///
/// Uses `try_read()` for the shared stores so the TUI never blocks waiting
/// for the processing thread to release a write lock. When the lock is
/// contended, the previous frame's cached counts are shown in the status
/// bar, and the main view simply skips its render (the terminal retains
/// the last-drawn content).
fn render_app(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();

    // Layout: 3 status lines at top (sngrep-style), main content, F-key bar at bottom
    let [
        status1_area,
        status2_area,
        status3_area,
        main_area,
        fkey_area,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // Update cached counts when the lock is available (non-blocking)
    if let Some(store) = app.dialog_store.try_read() {
        app.cached_dialog_count = store.len();
        app.cached_displayed_count = {
            let mut count = if let Some(ref filter) = app.active_filter {
                store.iter().filter(|d| filter.matches_dialog(d, &[])).count()
            } else {
                store.len()
            };
            // Apply text search filter to the count
            if !app.search_query.is_empty() {
                let q = app.search_query.to_ascii_lowercase();
                count = store.iter()
                    .filter(|d| {
                        if let Some(ref filter) = app.active_filter
                            && !filter.matches_dialog(d, &[])
                        {
                            return false;
                        }
                        d.call_id.to_ascii_lowercase().contains(&q)
                            || d.method.to_ascii_lowercase().contains(&q)
                            || d.from_user.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                            || d.to_user.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                            || d.src_addr.to_string().contains(&q)
                            || d.dst_addr.to_string().contains(&q)
                            || call_list::state_display_str(&d.state).to_ascii_lowercase().contains(&q)
                    })
                    .count();
            }
            count
        };
    }

    // Status lines at top (sngrep-style) — use cached counts
    render_status_line1(frame, status1_area, app);
    render_status_line2(frame, status2_area, app);
    render_status_line3(frame, status3_area, app);

    // Render the current view using try_read() to avoid blocking.
    // If the lock is contended, skip the render — the terminal retains
    // the previous frame's content, so the user sees no flicker.
    match &app.current_view.clone() {
        View::CallList => {
            if let Some(store) = app.dialog_store.try_read() {
                call_list::render_call_list(
                    frame,
                    main_area,
                    &mut app.call_list,
                    &store,
                    app.active_filter.as_ref(),
                    &app.search_query,
                    app.timestamp_mode,
                    &app.theme,
                );
            }
        }
        View::StreamList => {
            if let Some(store) = app.stream_store.try_read() {
                stream_list::render_stream_list(frame, main_area, &mut app.stream_list, &store, &app.theme);
            }
        }
        View::StreamDetail(key) => {
            if let Some(store) = app.stream_store.try_read() {
                stream_detail::render_stream_detail(
                    frame, main_area, key, &store, app.stream_detail_scroll, &app.theme,
                );
            }
        }
        View::CallFlow(call_id) => {
            if let Some(store) = app.dialog_store.try_read() {
                let cid = call_id.clone();
                let scroll = app.call_flow_scroll;
                let sel = app.selected_msg_index;

                // Horizontal split: ladder on left, raw detail on right (sngrep style)
                let (ladder_area, detail_area) = if app.raw_preview {
                    let pct = app.raw_preview_pct;
                    let [left, right] = Layout::horizontal([
                        Constraint::Percentage(100 - pct),
                        Constraint::Percentage(pct),
                    ])
                    .areas(main_area);
                    (left, Some(right))
                } else {
                    (main_area, None)
                };

                // Gather messages for the direct-paint renderer.
                // For extended flow, merge correlated dialog messages.
                let prepared = if app.extended_flow {
                    // Extended: merge all correlated legs
                    let dialog = store.get(&cid);
                    if let Some(d) = dialog {
                        let mut all: Vec<&crate::sip::SipMessage> = d.messages.iter().collect();
                        let correlated = store.find_correlated(&cid);
                        for leg in &correlated {
                            all.extend(leg.messages.iter());
                        }
                        all.sort_by_key(|m| m.timestamp);
                        let owned: Vec<crate::sip::SipMessage> = all.into_iter().cloned().collect();
                        if owned.is_empty() {
                            None
                        } else {
                            let ft = owned[0].timestamp;
                            let (participants, msgs) = call_flow::prepare_messages(
                                &owned,
                                ft,
                                None,
                                app.sdp_display_mode,
                                app.timestamp_mode,
                                app.color_mode,
                                false,
                                Some(sel),
                                &app.theme,
                                &app.fold_expanded,
                            );
                            Some((participants, msgs))
                        }
                    } else {
                        None
                    }
                } else {
                    let dialog = store.get(&cid);
                    if let Some(d) = dialog {
                        if d.messages.is_empty() {
                            None
                        } else {
                            let ft = d.messages[0].timestamp;
                            let pdd = d.timing.pdd_ms();
                            let (participants, msgs) = call_flow::prepare_messages(
                                &d.messages,
                                ft,
                                pdd,
                                app.sdp_display_mode,
                                app.timestamp_mode,
                                app.color_mode,
                                app.show_rtp_in_flow,
                                Some(sel),
                                &app.theme,
                                &app.fold_expanded,
                            );
                            Some((participants, msgs))
                        }
                    } else {
                        None
                    }
                };

                // Update cached rendered message count (excluding spacers)
                // and track which indices carry an RTP bar for Enter drill-down
                if let Some((_, ref msgs)) = prepared {
                    app.cached_flow_msg_count = msgs.iter().filter(|m| !m.is_spacer).count();
                    app.cached_rtp_bar_indices = msgs
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| m.is_rtp_bar)
                        .map(|(i, _)| i)
                        .collect();
                }

                // Render ladder using direct buffer painting
                call_flow::render_call_flow_direct_or_empty(
                    frame,
                    ladder_area,
                    prepared.as_ref(),
                    scroll,
                    &app.theme,
                    app.mark_index,
                    sel,
                );

                // Render message detail panel (right side) if split is active
                if let Some(detail_area) = detail_area {
                    call_flow::render_message_detail(
                        frame,
                        detail_area,
                        &store,
                        &cid,
                        sel,
                        app.detail_scroll,
                        &app.theme,
                    );
                }
            }
        }
        View::RawMessage {
            call_id,
            message_index,
        } => {
            if let Some(store) = app.dialog_store.try_read() {
                msg_raw::render_raw_message(
                    frame,
                    main_area,
                    &store,
                    call_id,
                    *message_index,
                    app.raw_msg_scroll,
                    &app.search_query,
                    &app.theme,
                );
            }
        }
        View::MessageDiff {
            call_id,
            msg1_idx,
            msg2_idx,
        } => {
            if let Some(store) = app.dialog_store.try_read() {
                render_message_diff(frame, main_area, &store, call_id, *msg1_idx, *msg2_idx, &app.theme);
            }
        }
        View::Help => {
            help::render_help(frame, main_area, &app.theme);
        }
        View::Statistics => {
            render_statistics(frame, main_area, app);
        }
    }

    // F-key bar (sngrep-style, context-sensitive) at bottom
    render_fkey_bar(frame, fkey_area, &app.current_view, &app.active_popup, &app.theme);

    // Render popup overlay on top of everything (if active)
    if let Some(popup) = &app.active_popup.clone() {
        match popup {
            Popup::SaveDialog => {
                render_save_popup(frame, area, app);
            }
            Popup::FilterDialog => {
                render_filter_popup(frame, area, &app.filter_dialog, &app.theme);
            }
            Popup::SettingsDialog => {
                render_settings_popup(frame, area, app);
            }
            Popup::FileOpenDialog => {
                render_file_open_popup(frame, area, app);
            }
        }
    }

    // Render column selector popup (not a Popup variant — it's call_list internal state)
    if app.call_list.column_selector_open {
        call_list::render_column_selector(frame, area, &app.call_list, &app.theme);
    }
}

/// Render status line 1 (sngrep-style): `Current Mode: Online (any)    Dialogs: N (N displayed)`
fn render_status_line1(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let total_count = app.cached_dialog_count;
    let displayed_count = app.cached_displayed_count;

    // Determine if online (live capture) or offline (pcap file)
    let is_online = app.capture_mode.starts_with("Online");
    let mode_style = if is_online {
        Style::default().fg(app.theme.good)
    } else {
        Style::default().fg(app.theme.bad)
    };

    // Build status indicators for paused/autoscroll
    let mut indicators = String::new();
    if app.paused {
        indicators.push_str("  PAUSED");
    }
    if app.call_list.autoscroll {
        indicators.push_str("  [A]");
    }

    let content = format!(
        " Current Mode: {}    Dialogs: {} ({} displayed){}",
        app.capture_mode, total_count, displayed_count, indicators
    );
    let padded = format!("{:<width$}", content, width = area.width as usize);

    // Build spans with styling for the mode portion
    let mode_start = " Current Mode: ".len();
    let mode_end = mode_start + app.capture_mode.len();

    // Find indicator positions for coloring
    let paused_start = if app.paused {
        padded.find("PAUSED")
    } else {
        None
    };

    let mut spans = vec![
        Span::raw(&padded[..mode_start]),
        Span::styled(padded[mode_start..mode_end].to_string(), mode_style),
    ];

    if let Some(ps) = paused_start {
        spans.push(Span::raw(padded[mode_end..ps].to_string()));
        spans.push(Span::styled(
            "PAUSED".to_string(),
            Style::default().fg(app.theme.bad).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(padded[ps + 6..].to_string()));
    } else {
        spans.push(Span::raw(padded[mode_end..].to_string()));
    };

    let line1 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line1, area);
}

/// Render status line 2 (sngrep-style): `Match Expression: <expr>    BPF Filter: <bpf>`
fn render_status_line2(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let yellow = Style::default().fg(app.theme.selected);

    // Build styled spans with trailing padding for solid background
    let prefix1 = " Match Expression: ";
    let filter_text = &app.active_filter_text;
    let mid = "    BPF Filter: ";
    let bpf_text = &app.bpf_filter;
    let styled_len = prefix1.len() + filter_text.len() + mid.len() + bpf_text.len();
    let trailing_pad = if styled_len < area.width as usize {
        " ".repeat(area.width as usize - styled_len)
    } else {
        String::new()
    };

    let spans = vec![
        Span::raw(prefix1),
        Span::styled(filter_text.clone(), yellow),
        Span::raw(mid),
        Span::styled(bpf_text.clone(), yellow),
        Span::raw(trailing_pad),
    ];

    let line2 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line2, area);
}

/// Render status line 3 (sngrep-style): `Display Filter: <filter>` or search/error overlay.
fn render_status_line3(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let w = area.width as usize;

    let spans = if app.search_active {
        let content = format!(" /{}", app.search_query);
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(app.theme.selected),
        )]
    } else if let Some(ref err) = app.status_error {
        let content = format!(" {}", err);
        // Use bright foreground + bold for high contrast on the dark status bar.
        // Actual errors (containing "error" or "fail") get the bad/red color.
        let is_error = err.to_ascii_lowercase().contains("error")
            || err.to_ascii_lowercase().contains("fail");
        let fg = if is_error {
            app.theme.bad
        } else {
            app.theme.foreground
        };
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(fg).add_modifier(Modifier::BOLD),
        )]
    } else if let View::CallFlow(_) = app.current_view {
        // In call flow: show current display modes so user knows what t/d/c do
        let cyan = Style::default().fg(app.theme.header);
        let content = format!(
            " {} | {} | {} | Split: {}%",
            app.timestamp_mode.label(),
            app.sdp_display_mode.label(),
            app.color_mode.label(),
            if app.raw_preview {
                app.raw_preview_pct
            } else {
                0
            },
        );
        let trailing = " ".repeat(w.saturating_sub(content.len()));
        vec![Span::styled(content, cyan), Span::raw(trailing)]
    } else {
        let yellow = Style::default().fg(app.theme.selected);
        let prefix = " Display Filter: ";
        let filter_text = &app.active_filter_text;
        let trailing = if prefix.len() + filter_text.len() < w {
            " ".repeat(w - prefix.len() - filter_text.len())
        } else {
            String::new()
        };
        vec![
            Span::raw(prefix),
            Span::styled(filter_text.clone(), yellow),
            Span::raw(trailing),
        ]
    };

    let line3 = Paragraph::new(Line::from(spans)).style(Style::default().bg(app.theme.status_bg));
    frame.render_widget(line3, area);
}

/// Render the sngrep-style F-key bar at the bottom of the screen.
///
/// Format: `Esc Quit  Enter Show  F2 Save  ...`
/// Key names in bold white, labels in default. Full-width dark background.
/// The bar is context-sensitive based on the current view. On narrow
/// terminals, lower-priority items are dropped to avoid truncation.
fn render_fkey_bar(frame: &mut ratatui::Frame, area: Rect, view: &View, popup: &Option<Popup>, theme: &Theme) {
    let key_style = Style::default()
        .fg(theme.foreground)
        .add_modifier(Modifier::BOLD);
    let label_style = Style::default().fg(theme.foreground);

    let width = area.width;

    // Full item sets per view; items near the end are lower priority.
    // Popup-specific bars take precedence.
    let items: Vec<(&str, &str)> = if let Some(p) = popup {
        match p {
            Popup::SaveDialog => vec![("Enter", "Save"), ("Tab", "Format"), ("Esc", "Cancel")],
            Popup::FilterDialog => {
                vec![
                    ("Tab", "Next"),
                    ("Space", "Toggle"),
                    ("Enter", "Apply"),
                    ("Esc", "Cancel"),
                    ("F9", "Clear"),
                ]
            }
            Popup::SettingsDialog => {
                vec![
                    ("Up/Down", "Navigate"),
                    ("Enter", "Toggle"),
                    ("Esc", "Close"),
                ]
            }
            Popup::FileOpenDialog => vec![("Enter", "Open"), ("Esc", "Cancel")],
        }
    } else {
        match view {
            View::CallList => {
                if width < 80 {
                    vec![
                        ("Esc", "Quit"),
                        ("Enter", "Show"),
                        ("F2", "Save"),
                        ("F7", "Filter"),
                    ]
                } else if width < 100 {
                    vec![
                        ("Esc", "Quit"),
                        ("Enter", "Show"),
                        ("F2", "Save"),
                        ("F3", "Search"),
                        ("F6", "Raw"),
                        ("F7", "Filter"),
                        ("F9", "Addrs"),
                    ]
                } else {
                    vec![
                        ("Esc", "Quit"),
                        ("Enter", "Show"),
                        ("F2", "Save"),
                        ("F3", "Search"),
                        ("F4", "Extended"),
                        ("F5", "Clear"),
                        ("F6", "Raw"),
                        ("F7", "Filter"),
                        ("F9", "Addrs"),
                        ("F10", "Columns"),
                    ]
                }
            }
            View::CallFlow(_) => {
                if width < 80 {
                    vec![
                        ("Esc", "Back"),
                        ("\u{2191}\u{2193}", "Nav"),
                        ("Enter", "Raw"),
                    ]
                } else if width < 120 {
                    vec![
                        ("Esc", "Back"),
                        ("\u{2191}\u{2193}", "Nav"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Split"),
                    ]
                } else {
                    vec![
                        ("Esc", "Back"),
                        ("\u{2191}\u{2193}", "Nav"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "Split"),
                        ("9/0", "Resize"),
                        ("F4", "Extend"),
                        ("F6", "RTP"),
                    ]
                }
            }
            View::RawMessage { .. } => {
                if width < 80 {
                    vec![("Esc", "Back"), ("s", "Highlight"), ("F2", "Save")]
                } else {
                    vec![
                        ("Esc", "Back"),
                        ("s", "Highlight"),
                        ("c", "Color"),
                        ("/", "Search"),
                        ("F2", "Save"),
                    ]
                }
            }
            View::MessageDiff { .. } => vec![("Esc", "Back")],
            View::StreamList => vec![("Esc", "Back"), ("Enter", "Detail"), ("Tab", "Calls"), ("F7", "Filter")],
            View::StreamDetail(_) => vec![("Esc", "Back"), ("j/k", "Scroll"), ("PgUp/Dn", "Page")],
            _ => vec![("Esc", "Back")],
        }
    };

    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label)) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(format!("{key} "), key_style));
        spans.push(Span::styled((*label).to_string(), label_style));
    }

    // Pad to full width for solid background
    let content_len: usize = spans.iter().map(|s| s.content.len()).sum();
    if content_len < width as usize {
        spans.push(Span::raw(" ".repeat(width as usize - content_len)));
    }

    let bar = Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.status_bg));
    frame.render_widget(bar, area);
}

// ── Popup rendering ────────────────────────────────────────────────

/// Compute a centered popup rectangle within the given area.
fn centered_popup(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

/// Render the save dialog as a centered popup overlay.
fn render_save_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 72.min(area.width.saturating_sub(4));
    let popup_area = centered_popup(area, popup_width, 20);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Save Capture ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build vertical format list grouped by category.
    let all_formats = [
        SaveFormat::Pcap, SaveFormat::PcapNg,          // Packet Capture
        SaveFormat::Txt, SaveFormat::SippXml,           // SIP-Specific
        SaveFormat::Json, SaveFormat::Ndjson, SaveFormat::Csv, // Structured
        SaveFormat::Html, SaveFormat::Markdown,          // Reporting
        SaveFormat::Wav, SaveFormat::RtpJson,            // RTP/Media
    ];
    let mut fmt_lines: Vec<Line<'_>> = Vec::new();
    let mut last_cat = "";
    for fmt in &all_formats {
        let cat = fmt.category();
        if cat != last_cat {
            // Category header
            if !last_cat.is_empty() {
                fmt_lines.push(Line::from("")); // spacer between categories
            }
            fmt_lines.push(Line::from(Span::styled(
                format!("  {cat}"),
                Style::default().fg(app.theme.accent).add_modifier(Modifier::BOLD),
            )));
            last_cat = cat;
        }
        let is_selected = *fmt == app.save_format;
        let marker = if is_selected { "\u{25B8} " } else { "  " }; // ▸ or space
        let label_style = if is_selected {
            Style::default().fg(app.theme.foreground).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.muted)
        };
        let desc_style = if is_selected {
            Style::default().fg(app.theme.foreground)
        } else {
            Style::default().fg(app.theme.muted)
        };
        fmt_lines.push(Line::from(vec![
            Span::styled(format!("    {marker}"), label_style),
            Span::styled(format!("{:<7}", fmt.label()), label_style),
            Span::styled(format!(" {}", fmt.description()), desc_style),
        ]));
    }

    let info_line = format!(
        "  Dialogs: {} ({} selected) \u{00B7} Messages: {}",
        app.save_dialog_count, app.save_selected_count, app.save_message_count
    );

    // Build the path display with a visible cursor (reverse video at cursor position)
    let path = &app.save_path;
    let cursor = app.save_cursor.min(path.len());
    let mut path_spans: Vec<Span<'_>> = vec![Span::styled(
        "  Save to: ",
        Style::default().fg(app.theme.header),
    )];
    if path.is_empty() {
        path_spans.push(Span::styled(
            " ",
            Style::default().bg(Color::White).fg(Color::Black),
        ));
    } else {
        // Text before cursor
        if cursor > 0 {
            path_spans.push(Span::styled(
                path[..cursor].to_string(),
                Style::default()
                    .fg(app.theme.foreground)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        // Cursor character (reverse video)
        if cursor < path.len() {
            path_spans.push(Span::styled(
                path[cursor..cursor + 1].to_string(),
                Style::default().bg(Color::White).fg(Color::Black),
            ));
            // Text after cursor
            if cursor + 1 < path.len() {
                path_spans.push(Span::styled(
                    path[cursor + 1..].to_string(),
                    Style::default()
                        .fg(app.theme.foreground)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        } else {
            // Cursor at end — show block cursor
            path_spans.push(Span::styled(
                " ",
                Style::default().bg(Color::White).fg(Color::Black),
            ));
        }
    }

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(""),
        Line::from(path_spans),
        Line::from(""),
    ];
    lines.extend(fmt_lines);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        info_line,
        Style::default().fg(app.theme.muted),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "  [Enter]",
            Style::default()
                .fg(app.theme.good)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Save  "),
        Span::styled(
            "[Tab/\u{21E7}Tab]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Format  "),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(app.theme.warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Cancel"),
    ]));

    // Ensure we don't exceed the inner area height
    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// Render the file-open dialog as a centered popup overlay.
fn render_file_open_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 70.min(area.width.saturating_sub(4));
    let popup_area = centered_popup(area, popup_width, 8);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Open PCAP File ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build the path display with a visible cursor (reverse video at cursor position)
    let path = &app.open_path;
    let cursor = app.open_cursor.min(path.len());
    let mut path_spans: Vec<Span<'_>> = vec![Span::styled(
        "  File: ",
        Style::default().fg(app.theme.header),
    )];
    if path.is_empty() {
        path_spans.push(Span::styled(
            " ",
            Style::default().bg(Color::White).fg(Color::Black),
        ));
    } else {
        // Text before cursor
        if cursor > 0 {
            path_spans.push(Span::styled(
                path[..cursor].to_string(),
                Style::default()
                    .fg(app.theme.foreground)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        // Cursor character (reverse video)
        if cursor < path.len() {
            path_spans.push(Span::styled(
                path[cursor..cursor + 1].to_string(),
                Style::default().bg(Color::White).fg(Color::Black),
            ));
            // Text after cursor
            if cursor + 1 < path.len() {
                path_spans.push(Span::styled(
                    path[cursor + 1..].to_string(),
                    Style::default()
                        .fg(app.theme.foreground)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        } else {
            // Cursor at end — show block cursor
            path_spans.push(Span::styled(
                " ",
                Style::default().bg(Color::White).fg(Color::Black),
            ));
        }
    }

    let lines: Vec<Line<'_>> = vec![
        Line::from(""),
        Line::from(path_spans),
        Line::from(""),
        Line::from(Span::styled(
            "  Supports .pcap, .pcapng, .cap files",
            Style::default().fg(app.theme.muted),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Enter]",
                Style::default()
                    .fg(app.theme.good)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Open  "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(app.theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Cancel"),
        ]),
    ];

    // Ensure we don't exceed the inner area height
    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// Render a text input field with cursor for the filter dialog.
///
/// Paints: `label [content_with_cursor_________________]`
/// The field content is rendered with a block cursor at `cursor_pos` when focused.
#[allow(clippy::too_many_arguments)]
fn render_filter_text_field(
    buf: &mut ratatui::buffer::Buffer,
    x: u16,
    y: u16,
    label: &str,
    value: &str,
    field_width: u16,
    focused: bool,
    cursor_pos: usize,
    theme: &Theme,
) {
    let label_style = Style::default().fg(theme.header);
    let bracket_style = if focused {
        Style::default().fg(theme.foreground)
    } else {
        Style::default().fg(theme.muted)
    };

    // Paint label
    let label_area = Rect::new(x, y, label.len() as u16, 1);
    buf.set_string(label_area.x, label_area.y, label, label_style);

    // Paint opening bracket
    let field_x = x + label.len() as u16;
    buf.set_string(field_x, y, "[", bracket_style);

    // Paint field content with cursor
    let content_x = field_x + 1;
    let inner_width = (field_width - 2) as usize; // subtract brackets
    let cursor = cursor_pos.min(value.len());

    if focused {
        // Before cursor
        let before = &value[..cursor.min(inner_width)];
        buf.set_string(
            content_x,
            y,
            before,
            Style::default()
                .fg(theme.foreground)
                .add_modifier(Modifier::BOLD),
        );
        // Cursor character (reverse video)
        let cursor_char = if cursor < value.len() {
            &value[cursor..cursor + 1]
        } else {
            " "
        };
        buf.set_string(
            content_x + cursor as u16,
            y,
            cursor_char,
            Style::default().bg(Color::White).fg(Color::Black),
        );
        // After cursor
        if cursor + 1 < value.len() {
            let after_end = value.len().min(inner_width);
            let after = &value[cursor + 1..after_end];
            buf.set_string(
                content_x + cursor as u16 + 1,
                y,
                after,
                Style::default()
                    .fg(theme.foreground)
                    .add_modifier(Modifier::BOLD),
            );
        }
        // Fill remaining with spaces
        let filled = value.len().max(cursor + 1).min(inner_width);
        if filled < inner_width {
            let pad = " ".repeat(inner_width - filled);
            buf.set_string(content_x + filled as u16, y, &pad, Style::default());
        }
    } else {
        // Not focused: just show value dimmed
        let display = if value.len() > inner_width {
            &value[..inner_width]
        } else {
            value
        };
        buf.set_string(content_x, y, display, Style::default().fg(theme.foreground));
        // Fill remaining
        if display.len() < inner_width {
            let pad = " ".repeat(inner_width - display.len());
            buf.set_string(content_x + display.len() as u16, y, &pad, Style::default());
        }
    }

    // Closing bracket
    buf.set_string(field_x + field_width - 1, y, "]", bracket_style);
}

/// Render the filter dialog as a centered popup overlay (sngrep-style).
///
/// Layout:
/// ```text
/// +- Filter -----------------------------------------+
/// |                                                    |
/// |  SIP From:    [                             ]      |
/// |  SIP To:      [                             ]      |
/// |  Source:      [                             ]      |
/// |  Destination: [                             ]      |
/// |  Payload:     [                             ]      |
/// |  ──────────────────────────────────────────────    |
/// |  REGISTER [*]          OPTIONS  [ ]                |
/// |  INVITE   [*]          PUBLISH  [ ]                |
/// |  SUBSCRIBE[ ]          MESSAGE  [ ]                |
/// |  NOTIFY   [ ]          REFER    [ ]                |
/// |  INFO     [ ]          UPDATE   [ ]                |
/// |                                                    |
/// |     [ Filter ]              [ Cancel ]             |
/// |                                                    |
/// +----------------------------------------------------+
/// ```
fn render_filter_popup(frame: &mut ratatui::Frame, area: Rect, state: &FilterDialogState, theme: &Theme) {
    let popup_width: u16 = 56;
    let popup_height: u16 = 19;
    let popup_area = centered_popup(area, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter ")
        .style(Style::default().bg(theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let buf = frame.buffer_mut();
    let ix = inner.x;
    let iy = inner.y;
    let iw = inner.width;

    // ── Text input fields ──────────────────────────────────────────
    let labels = [
        "  SIP From:    ",
        "  SIP To:      ",
        "  Source:      ",
        "  Destination: ",
        "  Payload:     ",
    ];
    let field_width = iw.saturating_sub(labels[0].len() as u16 + 2); // +2 for margin

    for (i, label) in labels.iter().enumerate() {
        let focused = state.focused_field == i;
        let cursor = if focused { state.cursor_pos } else { 0 };
        render_filter_text_field(
            buf,
            ix,
            iy + 1 + i as u16,
            label,
            state.text_field(i),
            field_width,
            focused,
            cursor,
            theme,
        );
    }

    // ── Separator line ─────────────────────────────────────────────
    let sep_y = iy + 1 + labels.len() as u16;
    let sep = "\u{2500}".repeat((iw - 4) as usize);
    buf.set_string(ix + 2, sep_y, &sep, Style::default().fg(theme.muted));

    // ── Method checkboxes (two columns, 5 rows) ───────────────────
    let cb_y = sep_y + 1;
    let col1_x = ix + 2;
    let col2_x = ix + (iw / 2) + 1;

    for row in 0..5u16 {
        let left_idx = (row * 2) as usize;
        let right_idx = left_idx + 1;

        // Left column
        if left_idx < FILTER_METHODS.len() {
            let method = FILTER_METHODS[left_idx];
            let checked = state.methods[left_idx];
            let focused = state.focused_field == FILTER_TEXT_FIELD_COUNT + left_idx;
            let marker = if checked { "[*]" } else { "[ ]" };
            let name = format!("{:<10}", method);
            let style = if focused {
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.foreground)
            };
            buf.set_string(col1_x, cb_y + row, &name, style);
            buf.set_string(col1_x + 10, cb_y + row, marker, style);
        }

        // Right column
        if right_idx < FILTER_METHODS.len() {
            let method = FILTER_METHODS[right_idx];
            let checked = state.methods[right_idx];
            let focused = state.focused_field == FILTER_TEXT_FIELD_COUNT + right_idx;
            let marker = if checked { "[*]" } else { "[ ]" };
            let name = format!("{:<10}", method);
            let style = if focused {
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.foreground)
            };
            buf.set_string(col2_x, cb_y + row, &name, style);
            buf.set_string(col2_x + 10, cb_y + row, marker, style);
        }
    }

    // ── Buttons ────────────────────────────────────────────────────
    let btn_y = cb_y + 6;
    let filter_focused = state.focused_field == FILTER_BUTTON_IDX;
    let cancel_focused = state.focused_field == CANCEL_BUTTON_IDX;

    let filter_style = if filter_focused {
        Style::default()
            .fg(theme.good)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };
    let cancel_style = if cancel_focused {
        Style::default()
            .fg(theme.warning)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };

    let btn_col1 = ix + 5;
    let btn_col2 = ix + iw / 2 + 5;
    buf.set_string(btn_col1, btn_y, "[ Filter ]", filter_style);
    buf.set_string(btn_col2, btn_y, "[ Cancel ]", cancel_style);
}

/// Render the settings popup as a centered overlay.
fn render_settings_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width: u16 = 50;
    let popup_height: u16 = 12;
    let popup_area = centered_popup(area, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Settings ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let buf = frame.buffer_mut();
    let ix = inner.x;
    let iy = inner.y;

    let labels = [
        "Color Mode:",
        "Timestamp Mode:",
        "Autoscroll:",
        "Raw Preview:",
        "SDP Display:",
        "Syntax Highlight:",
    ];

    let values = [
        match app.color_mode {
            ColorMode::Method => "Method",
            ColorMode::CallId => "CallId",
            ColorMode::CSeq => "CSeq",
        },
        match app.timestamp_mode {
            TimestampMode::Absolute => "Absolute",
            TimestampMode::DeltaPrev => "DeltaPrev",
            TimestampMode::DeltaFirst => "DeltaFirst",
            TimestampMode::Scaled => "Scaled",
        },
        if app.call_list.autoscroll { "ON" } else { "OFF" },
        if app.raw_preview { "ON" } else { "OFF" },
        match app.sdp_display_mode {
            SdpDisplayMode::None => "None",
            SdpDisplayMode::Summary => "Summary",
            SdpDisplayMode::Full => "Full",
        },
        if app.syntax_highlight { "ON" } else { "OFF" },
    ];

    for (i, (label, value)) in labels.iter().zip(values.iter()).enumerate() {
        let focused = app.settings_dialog.focused_item == i;
        let style = if focused {
            Style::default()
                .fg(app.theme.selected)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.foreground)
        };
        let value_style = if focused {
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.good)
        };

        let row_y = iy + 1 + i as u16;
        buf.set_string(ix + 2, row_y, format!("{:<18}", label), style);
        buf.set_string(ix + 20, row_y, format!("[{}]", value), value_style);
    }
}

/// Render the statistics summary view with real data from stores.
fn render_statistics(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    use crate::sip::dialog::DialogState;
    use std::collections::HashMap;

    // Use try_read() to avoid blocking the TUI render loop
    let ds = match app.dialog_store.try_read() {
        Some(guard) => guard,
        None => return,
    };
    let ss = match app.stream_store.try_read() {
        Some(guard) => guard,
        None => return,
    };

    let dialog_count = ds.len();
    let active_count = ds.active_count();
    let stream_count = ss.len();
    let orphaned = ss.orphaned_count();

    // Per-state counts
    let mut state_counts: HashMap<&str, usize> = HashMap::new();
    let mut method_counts: HashMap<&str, usize> = HashMap::new();
    let mut total_messages: usize = 0;

    for dialog in ds.iter() {
        let state_name = match dialog.state {
            DialogState::Trying => "Trying",
            DialogState::Ringing => "Ringing",
            DialogState::InCall => "InCall",
            DialogState::Completed => "Completed",
            DialogState::Cancelled => "Cancelled",
            DialogState::Failed => "Failed",
            DialogState::Registered => "Registered",
            DialogState::Expired => "Expired",
            DialogState::Pending => "Pending",
            DialogState::Active => "Active",
            DialogState::Terminated => "Terminated",
            DialogState::Transferring => "Transferring",
        };
        *state_counts.entry(state_name).or_insert(0) += 1;
        *method_counts.entry(dialog.method.as_str()).or_insert(0) += 1;
        total_messages += dialog.messages.len();
    }

    // Sort methods by count descending, then alphabetically
    let mut methods: Vec<(&&str, &usize)> = method_counts.iter().collect();
    methods.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut text = format!(
        "sipnab Statistics\n\n\
         Dialogs:           {dialog_count}\n\
         Active Calls:      {active_count}\n\
         Total Messages:    {total_messages}\n\
         RTP Streams:       {stream_count}\n\
         Orphaned Streams:  {orphaned}\n"
    );

    // State breakdown
    if !state_counts.is_empty() {
        text.push_str("\nDialog States:\n");
        let mut states: Vec<(&&str, &usize)> = state_counts.iter().collect();
        states.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (state, count) in states {
            text.push_str(&format!("  {:<16} {count}\n", state));
        }
    }

    // Method distribution
    if !methods.is_empty() {
        text.push_str("\nMethod Distribution:\n");
        for (method, count) in methods {
            text.push_str(&format!("  {:<16} {count}\n", method));
        }
    }

    text.push_str("\nPress Esc to return.");

    let block = Block::default().borders(Borders::ALL).title(" Statistics ");

    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(app.theme.foreground));

    frame.render_widget(paragraph, area);
}

/// Render a side-by-side diff of two SIP messages.
fn render_message_diff(
    frame: &mut ratatui::Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    msg1_idx: usize,
    msg2_idx: usize,
    theme: &Theme,
) {
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.").style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return;
        }
    };

    let msg1 = dialog.messages.get(msg1_idx);
    let msg2 = dialog.messages.get(msg2_idx);

    let (Some(msg1), Some(msg2)) = (msg1, msg2) else {
        let para = Paragraph::new("Message not found.").style(Style::default().fg(theme.bad));
        frame.render_widget(para, area);
        return;
    };

    let raw1 = String::from_utf8_lossy(&msg1.raw);
    let raw2 = String::from_utf8_lossy(&msg2.raw);

    let lines1: Vec<&str> = raw1.lines().collect();
    let lines2: Vec<&str> = raw2.lines().collect();
    let max_lines = lines1.len().max(lines2.len());

    // Split area into two halves
    let half_width = area.width / 2;
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Length(half_width), Constraint::Fill(1)]).areas(area);

    let mut left_lines: Vec<Line<'static>> = Vec::new();
    let mut right_lines: Vec<Line<'static>> = Vec::new();

    // Header lines
    left_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg1_idx + 1),
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));
    right_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg2_idx + 1),
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));

    let diff_style = Style::default()
        .fg(theme.warning)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default();

    for i in 0..max_lines {
        let l1 = lines1.get(i).copied().unwrap_or("");
        let l2 = lines2.get(i).copied().unwrap_or("");

        let is_diff = l1 != l2;
        let style = if is_diff { diff_style } else { normal_style };

        left_lines.push(Line::from(Span::styled(l1.to_string(), style)));
        right_lines.push(Line::from(Span::styled(l2.to_string(), style)));
    }

    let left_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Message {} ", msg1_idx + 1));
    let right_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Message {} ", msg2_idx + 1));

    let left_para = Paragraph::new(left_lines)
        .block(left_block)
        .wrap(Wrap { trim: false });
    let right_para = Paragraph::new(right_lines)
        .block(right_block)
        .wrap(Wrap { trim: false });

    frame.render_widget(left_para, left_area);
    frame.render_widget(right_para, right_area);
}

// ── Key handling ────────────────────────────────────────────────────

/// Dispatch a key event to the handler for the current view.
fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Global shortcuts (Ctrl-C always quits)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    // Popup input takes priority over everything else
    if app.active_popup.is_some() {
        handle_popup_key(app, key);
        return;
    }

    // Search mode input
    if app.search_active {
        handle_search_input(app, key);
        return;
    }

    match &app.current_view {
        View::CallList => handle_call_list_key(app, key),
        View::StreamList => handle_stream_list_key(app, key),
        View::StreamDetail(_) => handle_stream_detail_key(app, key),
        View::CallFlow(_) => handle_call_flow_key(app, key),
        View::RawMessage { .. } => handle_raw_message_key(app, key),
        View::MessageDiff { .. } => handle_message_diff_key(app, key),
        View::Help => handle_help_key(app, key),
        View::Statistics => handle_statistics_key(app, key),
    }
}

/// Handle search input mode.
fn handle_search_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.search_active = false;
            app.search_query.clear();
        }
        KeyCode::Enter => {
            app.search_active = false;
            // search_query remains for highlighting
        }
        KeyCode::Backspace => {
            app.search_query.pop();
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
        }
        _ => {}
    }
}

/// Handle keys in the call list view.
fn handle_call_list_key(app: &mut App, key: KeyEvent) {
    // Column selector popup captures keys when open
    if app.call_list.column_selector_open {
        handle_column_selector_key(app, key);
        return;
    }

    let dialog_count = filtered_dialog_count(app);

    // Check for Ctrl-L (clear calls, same as F5)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
        clear_calls(app);
        return;
    }

    match key.code {
        k if k == app.keymap.quit || k == KeyCode::Esc => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.call_list.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.call_list.move_down(dialog_count),
        KeyCode::Home => app.call_list.move_to_top(),
        KeyCode::End => app.call_list.move_to_bottom(dialog_count),
        KeyCode::PageUp => app.call_list.page_up(),
        KeyCode::PageDown => app.call_list.page_down(dialog_count),
        KeyCode::Enter => {
            // Open call flow for selected dialog
            if let Some(call_id) = get_selected_call_id(app) {
                app.call_flow_scroll = 0;
                app.selected_msg_index = 0;
                app.detail_scroll = 0;
                app.current_view = View::CallFlow(call_id);
            }
        }
        KeyCode::Tab => {
            app.current_view = View::StreamList;
        }
        KeyCode::Char(' ') => {
            app.call_list.toggle_selection();
        }
        k if k == app.keymap.search => {
            app.search_active = true;
            app.search_query.clear();
        }
        // F5 — Clear calls
        k if k == app.keymap.clear_calls => {
            clear_calls(app);
        }
        // F6 / r — Raw view for selected dialog's first message
        KeyCode::F(6) | KeyCode::Char('r') => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.raw_msg_scroll = 0;
                app.current_view = View::RawMessage {
                    call_id,
                    message_index: 0,
                };
            }
        }
        // t — Cycle timestamp display mode
        KeyCode::Char('t') => {
            app.timestamp_mode = app.timestamp_mode.next();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        // F10 — Column selector popup
        k if k == app.keymap.column_selector => {
            app.call_list.column_selector_open = true;
            app.call_list.column_selector_cursor = 0;
        }
        // < — Sort by previous column
        KeyCode::Char('<') => {
            app.call_list.sort_prev_column();
        }
        // > — Sort by next column
        KeyCode::Char('>') => {
            app.call_list.sort_next_column();
        }
        // Z — Reverse sort direction
        KeyCode::Char('Z') => {
            app.call_list.reverse_sort();
        }
        // A — Toggle autoscroll
        k if k == app.keymap.autoscroll => {
            app.call_list.autoscroll = !app.call_list.autoscroll;
        }
        // p — Pause/resume capture processing
        k if k == app.keymap.pause => {
            app.paused = !app.paused;
            app.paused_flag.store(app.paused, AtomicOrdering::Relaxed);
        }
        // i — Clear calls that DON'T match the current filter
        KeyCode::Char('i') => {
            clear_non_matching(app);
        }
        // I — Clear calls that DO match the current filter
        KeyCode::Char('I') => {
            clear_matching(app);
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        KeyCode::F(3) => {
            // F3 Search — same as '/' search
            app.search_active = true;
            app.search_query.clear();
        }
        k if k == app.keymap.extended_flow => {
            if let Some(call_id) = get_selected_call_id(app) {
                app.extended_flow = true;
                app.call_flow_scroll = 0;
                app.selected_msg_index = 0;
                app.detail_scroll = 0;
                app.call_flow_cache.clear();
                app.current_view = View::CallFlow(call_id);
            }
        }
        k if k == app.keymap.filter => {
            // Always open the filter dialog (state is preserved)
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        k if k == app.keymap.settings => {
            app.settings_dialog.focused_item = 0;
            app.active_popup = Some(Popup::SettingsDialog);
        }
        KeyCode::F(9) => {
            // F9 Clear Filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_dialog.clear();
            app.status_error = None;
        }
        // O — Open pcap file
        KeyCode::Char('O') => {
            app.open_path = String::new();
            app.open_cursor = 0;
            app.active_popup = Some(Popup::FileOpenDialog);
        }
        KeyCode::Char('s') => app.current_view = View::Statistics,
        _ => {}
    }
}

/// Handle keys when the column selector popup is open.
fn handle_column_selector_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.call_list.column_selector_up(),
        KeyCode::Down | KeyCode::Char('j') => app.call_list.column_selector_down(),
        KeyCode::Char(' ') => app.call_list.toggle_column_visibility(),
        KeyCode::Enter | KeyCode::Esc => {
            app.call_list.column_selector_open = false;
        }
        _ => {}
    }
}

/// Clear calls from the dialog and stream stores.
///
/// If any rows are multi-selected, only those dialogs are removed.
/// Otherwise all dialogs are cleared.
fn clear_calls(app: &mut App) {
    let selected_rows: Vec<usize> = app.call_list.selected_rows().iter().copied().collect();

    if selected_rows.is_empty() {
        // Clear everything
        let count = {
            let mut ds = app.dialog_store.write();
            let n = ds.len();
            ds.clear();
            n
        };
        app.stream_store.write().clear();
        app.call_flow_cache.clear();
        app.call_list.clear_selections();
        app.call_list.move_to_top();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    } else {
        // Clear only selected rows: collect the Call-IDs to remove
        let call_ids_to_remove: Vec<String> = {
            let store = app.dialog_store.read();
            let dialogs: Vec<_> = if let Some(ref filter) = app.active_filter {
                store
                    .iter()
                    .filter(|d| filter.matches_dialog(d, &[]))
                    .collect()
            } else {
                store.iter().collect()
            };
            selected_rows
                .iter()
                .filter_map(|&idx| dialogs.get(idx).map(|d| d.call_id.clone()))
                .collect()
        };

        let count = call_ids_to_remove.len();
        {
            let mut ds = app.dialog_store.write();
            ds.retain(|d| !call_ids_to_remove.contains(&d.call_id));
        }
        // Invalidate call flow cache for removed dialogs
        for cid in &call_ids_to_remove {
            app.call_flow_cache.remove(cid);
        }
        app.call_list.clear_selections();
        app.status_error = Some(format!("Cleared {} dialogs", count));
    }
}

/// Clear calls that do NOT match the current filter (keep matching ones).
fn clear_non_matching(app: &mut App) {
    let filter = match &app.active_filter {
        Some(f) => f.clone(),
        None => return, // no filter active, do nothing
    };

    let removed = {
        let mut ds = app.dialog_store.write();
        let before = ds.len();
        ds.retain(|d| filter.matches_dialog(d, &[]));
        before - ds.len()
    };
    app.call_flow_cache.clear();
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} non-matching dialogs", removed));
}

/// Clear calls that DO match the current filter (keep non-matching ones).
fn clear_matching(app: &mut App) {
    let filter = match &app.active_filter {
        Some(f) => f.clone(),
        None => return, // no filter active, do nothing
    };

    let removed = {
        let mut ds = app.dialog_store.write();
        let before = ds.len();
        ds.retain(|d| !filter.matches_dialog(d, &[]));
        before - ds.len()
    };
    app.call_flow_cache.clear();
    app.call_list.clear_selections();
    app.call_list.move_to_top();
    app.status_error = Some(format!("Cleared {} matching dialogs", removed));
}

/// Handle keys in the stream list view.
fn handle_stream_list_key(app: &mut App, key: KeyEvent) {
    let stream_count = app.stream_store.read().len();

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.stream_list.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.stream_list.move_down(stream_count),
        KeyCode::Home => app.stream_list.move_to_top(),
        KeyCode::End => app.stream_list.move_to_bottom(stream_count),
        KeyCode::Tab => {
            app.current_view = View::CallList;
        }
        k if k == app.keymap.search => {
            app.search_active = true;
            app.search_query.clear();
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.filter => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        KeyCode::Enter => {
            if let Some(key) = get_selected_stream_key(app) {
                app.stream_detail_scroll = 0;
                app.current_view = View::StreamDetail(key);
            }
        }
        KeyCode::Esc => app.current_view = View::CallList,
        _ => {}
    }
}

/// Handle keys in the RTP stream detail view.
fn handle_stream_detail_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.stream_detail_scroll += 1;
        }
        KeyCode::PageUp => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.stream_detail_scroll += 20;
        }
        KeyCode::Home => app.stream_detail_scroll = 0,
        k if k == app.keymap.help => app.current_view = View::Help,
        KeyCode::Esc => app.current_view = View::StreamList,
        _ => {}
    }
}

/// Get the StreamKey for the currently selected row in the stream list.
fn get_selected_stream_key(app: &App) -> Option<crate::rtp::stream::StreamKey> {
    let store = app.stream_store.read();
    let streams: Vec<_> = store.iter().collect();
    let idx = app.stream_list.selected();
    streams.get(idx).map(|s| s.key.clone())
}

/// Handle keys in the call flow view.
fn handle_call_flow_key(app: &mut App, key: KeyEvent) {
    // Use the rendered (folded) message count. For extended flow, this includes
    // correlated legs. Fall back to raw dialog count if render hasn't run yet.
    let raw_count = if let View::CallFlow(ref call_id) = app.current_view {
        if app.extended_flow {
            // Extended: sum messages from main dialog + all correlated
            app.dialog_store
                .try_read()
                .map(|s| {
                    let base = s.get(call_id).map(|d| d.messages.len()).unwrap_or(0);
                    let correlated: usize = s.find_correlated(call_id).iter().map(|d| d.messages.len()).sum();
                    base + correlated
                })
                .unwrap_or(0)
        } else {
            app.dialog_store
                .try_read()
                .and_then(|s| s.get(call_id).map(|d| d.messages.len()))
                .unwrap_or(0)
        }
    } else {
        0
    };
    // Use cached rendered count if available, but never less than raw count
    // (folding reduces count, but raw count is the safe upper bound for navigation)
    let msg_count = if app.cached_flow_msg_count > 0 {
        app.cached_flow_msg_count.max(raw_count)
    } else {
        raw_count
    };

    // Clamp selected_msg_index to valid range
    if msg_count > 0 && app.selected_msg_index >= msg_count {
        app.selected_msg_index = msg_count - 1;
    }

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_msg_index > 0 {
                app.selected_msg_index -= 1;
                app.detail_scroll = 0;
            }
            // Auto-scroll ladder to keep selection visible
            if app.selected_msg_index < app.call_flow_scroll {
                app.call_flow_scroll = app.selected_msg_index;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if msg_count > 0 && app.selected_msg_index < msg_count - 1 {
                app.selected_msg_index += 1;
                app.detail_scroll = 0;
            }
            // Auto-scroll ladder to keep selection visible
            // (each message takes ~1 row in the ladder, header takes 2 rows)
            let visible_rows = app.call_flow_scroll + 20; // approximate
            if app.selected_msg_index >= visible_rows {
                app.call_flow_scroll = app.selected_msg_index.saturating_sub(10);
            }
        }
        KeyCode::PageUp => {
            app.selected_msg_index = app.selected_msg_index.saturating_sub(20);
            app.call_flow_scroll = app.call_flow_scroll.saturating_sub(20);
            app.detail_scroll = 0;
        }
        KeyCode::PageDown => {
            let max = if msg_count > 0 { msg_count - 1 } else { 0 };
            app.selected_msg_index = (app.selected_msg_index + 20).min(max);
            app.call_flow_scroll += 20;
            app.detail_scroll = 0;
        }
        KeyCode::Home => {
            app.selected_msg_index = 0;
            app.call_flow_scroll = 0;
            app.detail_scroll = 0;
        }
        KeyCode::End => {
            if msg_count > 0 {
                app.selected_msg_index = msg_count - 1;
                app.call_flow_scroll = msg_count.saturating_sub(1);
            }
            app.detail_scroll = 0;
        }
        KeyCode::Enter => {
            if let View::CallFlow(ref call_id) = app.current_view
                && app.selected_msg_index < msg_count
            {
                if app.cached_rtp_bar_indices.contains(&app.selected_msg_index) {
                    // RTP bar selected — drill down to stream detail for this dialog
                    let cid = call_id.clone();
                    let stream_key = app.stream_store.try_read().and_then(|store| {
                        store
                            .iter()
                            .find(|s| s.associated_dialog.as_deref() == Some(&cid))
                            .map(|s| s.key.clone())
                    });
                    if let Some(key) = stream_key {
                        app.current_view = View::StreamDetail(key);
                    } else {
                        app.status_error =
                            Some("No RTP stream found for this dialog".to_string());
                    }
                } else {
                    // Open full-screen raw message view for the selected message
                    let cid = call_id.clone();
                    app.raw_msg_scroll = 0;
                    app.current_view = View::RawMessage {
                        call_id: cid,
                        message_index: app.selected_msg_index,
                    };
                }
            }
        }
        KeyCode::Char(' ') => {
            // Select message for diff comparison
            if let View::CallFlow(ref call_id) = app.current_view
                && app.selected_msg_index < msg_count
            {
                if let Some(first) = app.diff_selected_msg {
                    if first != app.selected_msg_index {
                        // Second selection — open diff view
                        let cid = call_id.clone();
                        let msg2 = app.selected_msg_index;
                        app.diff_selected_msg = None;
                        app.current_view = View::MessageDiff {
                            call_id: cid,
                            msg1_idx: first,
                            msg2_idx: msg2,
                        };
                    }
                } else {
                    // First selection
                    app.diff_selected_msg = Some(app.selected_msg_index);
                    app.status_error = Some(format!(
                        "Selected: message {} (press Space on another to diff)",
                        app.selected_msg_index + 1
                    ));
                }
            }
        }
        KeyCode::Char('d') => {
            // Toggle SDP display mode
            app.sdp_display_mode = app.sdp_display_mode.next();
            app.call_flow_cache.clear();
            app.status_error = Some(app.sdp_display_mode.label().to_string());
        }
        KeyCode::Char('t') => {
            // Toggle timestamp display
            app.timestamp_mode = app.timestamp_mode.next();
            app.call_flow_cache.clear();
            app.status_error = Some(app.timestamp_mode.label().to_string());
        }
        KeyCode::Char('c') => {
            // Cycle color mode
            app.color_mode = app.color_mode.next();
            app.call_flow_cache.clear();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        KeyCode::Char('R') => {
            // Toggle raw preview split
            app.raw_preview = !app.raw_preview;
            app.status_error = Some(if app.raw_preview {
                "Raw preview: ON".to_string()
            } else {
                "Raw preview: OFF".to_string()
            });
        }
        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('0') | KeyCode::Left => {
            // Increase detail panel size (Left = push split leftward = detail wider)
            if app.raw_preview && app.raw_preview_pct < 80 {
                app.raw_preview_pct = (app.raw_preview_pct + 5).min(80);
                app.status_error = Some(format!("Detail panel: {}%", app.raw_preview_pct));
            }
        }
        KeyCode::Char('-') | KeyCode::Char('9') | KeyCode::Right => {
            // Decrease detail panel size (Right = push split rightward = ladder wider)
            if app.raw_preview && app.raw_preview_pct > 10 {
                app.raw_preview_pct = app.raw_preview_pct.saturating_sub(5).max(10);
                app.status_error = Some(format!("Detail panel: {}%", app.raw_preview_pct));
            }
        }
        KeyCode::Char('[') => {
            // Scroll detail panel up
            app.detail_scroll = app.detail_scroll.saturating_sub(1);
        }
        KeyCode::Char(']') => {
            // Scroll detail panel down
            app.detail_scroll = app.detail_scroll.saturating_add(1);
        }
        k if k == app.keymap.extended_flow || k == KeyCode::Char('x') => {
            // Toggle extended (multi-leg) flow
            app.extended_flow = !app.extended_flow;
            app.call_flow_cache.clear();
            app.status_error = Some(if app.extended_flow {
                "Extended flow: ON (multi-leg)".to_string()
            } else {
                "Extended flow: OFF".to_string()
            });
        }
        KeyCode::F(6) => {
            // Toggle RTP display in flow
            app.show_rtp_in_flow = !app.show_rtp_in_flow;
            app.call_flow_cache.clear();
            app.status_error = Some(if app.show_rtp_in_flow {
                "RTP in flow: ON".to_string()
            } else {
                "RTP in flow: OFF".to_string()
            });
        }
        KeyCode::Char('m') => {
            app.mark_index = Some(app.selected_msg_index);
            app.status_error = Some("Mark set".to_string());
        }
        KeyCode::Char('M') => {
            app.mark_index = None;
            app.status_error = Some("Mark cleared".to_string());
        }
        KeyCode::Char('e') => {
            let idx = app.selected_msg_index;
            if app.fold_expanded.contains(&idx) {
                app.fold_expanded.remove(&idx);
            } else {
                app.fold_expanded.insert(idx);
            }
            app.call_flow_cache.clear();
        }
        KeyCode::Char('E') => {
            // Export Mermaid sequence diagram to clipboard
            if let View::CallFlow(ref call_id) = app.current_view
                && let Some(store) = app.dialog_store.try_read()
            {
                let prepared = store.get(call_id).and_then(|d| {
                    if d.messages.is_empty() {
                        return None;
                    }
                    let ft = d.messages[0].timestamp;
                    let pdd = d.timing.pdd_ms();
                    let (participants, msgs) = call_flow::prepare_messages(
                        &d.messages,
                        ft,
                        pdd,
                        app.sdp_display_mode,
                        app.timestamp_mode,
                        app.color_mode,
                        app.show_rtp_in_flow,
                        None,
                        &app.theme,
                        &app.fold_expanded,
                    );
                    Some((participants, msgs))
                });
                if let Some((ref participants, ref msgs)) = prepared {
                    let mermaid = call_flow::export::export_mermaid(participants, msgs);
                    let cmd = if cfg!(target_os = "macos") {
                        "pbcopy"
                    } else {
                        "xclip"
                    };
                    let args: Vec<&str> = if cfg!(target_os = "macos") {
                        vec![]
                    } else {
                        vec!["-selection", "clipboard"]
                    };
                    let result = std::process::Command::new(cmd)
                        .args(&args)
                        .stdin(std::process::Stdio::piped())
                        .spawn()
                        .and_then(|mut child| {
                            use std::io::Write;
                            if let Some(ref mut stdin) = child.stdin {
                                stdin.write_all(mermaid.as_bytes())?;
                            }
                            child.wait()
                        });
                    match result {
                        Ok(_) => {
                            app.status_error =
                                Some("Mermaid diagram copied to clipboard".to_string());
                        }
                        Err(e) => {
                            app.status_error = Some(format!("Clipboard: {e}"));
                        }
                    }
                } else {
                    app.status_error = Some("No messages to export".to_string());
                }
            }
        }
        KeyCode::Esc => {
            app.diff_selected_msg = None;
            app.current_view = View::CallList;
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        k if k == app.keymap.clear_calls => {
            // F5 also starts compare mode (same as first Space press)
            app.diff_selected_msg = None;
            app.status_error =
                Some("Compare: press Space on first message, then Space on second".to_string());
        }
        k if k == app.keymap.filter => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        KeyCode::F(9) => {
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_dialog.clear();
            app.status_error = None;
        }
        _ => {}
    }
}

/// Handle keys in the raw message view.
fn handle_raw_message_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.raw_msg_scroll = app.raw_msg_scroll.saturating_add(20);
        }
        KeyCode::Home => app.raw_msg_scroll = 0,
        k if k == app.keymap.search => {
            app.search_active = true;
            app.search_query.clear();
        }
        KeyCode::Char('s') => {
            // Toggle syntax highlighting
            app.syntax_highlight = !app.syntax_highlight;
            app.status_error = Some(if app.syntax_highlight {
                "Syntax highlighting: ON".to_string()
            } else {
                "Syntax highlighting: OFF".to_string()
            });
        }
        KeyCode::Char('c') => {
            // Cycle color mode
            app.color_mode = app.color_mode.next();
            app.status_error = Some(app.color_mode.label().to_string());
        }
        KeyCode::Esc => {
            if let View::RawMessage { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        _ => {}
    }
}

/// Handle keys in the message diff view.
fn handle_message_diff_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Esc => {
            if let View::MessageDiff { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        KeyCode::F(1) => app.current_view = View::Help,
        _ => {}
    }
}

/// Handle keys in the help view.
fn handle_help_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == KeyCode::Esc || k == app.keymap.help || k == app.keymap.quit => {
            app.current_view = View::CallList;
        }
        _ => {}
    }
}

/// Open the save popup, pre-populating path and counts.
fn open_save_popup(app: &mut App) {
    // Reset format to default (PCAP)
    app.save_format = SaveFormat::default();

    // Generate default path with timestamp
    let now = chrono::Local::now();
    let default_path = format!("/tmp/sipnab_{}.pcap", now.format("%Y%m%d_%H%M%S"));
    app.save_path = default_path;
    app.save_cursor = app.save_path.len();

    // Cache counts for display
    let store = app.dialog_store.read();
    app.save_dialog_count = store.len();
    app.save_selected_count = app.call_list.selected_rows_count();
    app.save_message_count = store.iter().map(|d| d.messages.len()).sum();
    drop(store);

    app.active_popup = Some(Popup::SaveDialog);
}

/// Handle keys for any active popup dialog.
fn handle_popup_key(app: &mut App, key: KeyEvent) {
    let popup = match &app.active_popup {
        Some(p) => p.clone(),
        None => return,
    };

    match popup {
        Popup::SaveDialog => handle_save_popup_key(app, key),
        Popup::FilterDialog => handle_filter_popup_key(app, key),
        Popup::SettingsDialog => handle_settings_popup_key(app, key),
        Popup::FileOpenDialog => handle_file_open_popup_key(app, key),
    }
}

/// Handle keys in the save dialog popup.
fn handle_save_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            let path = app.save_path.clone();
            let msg = match app.save_format {
                SaveFormat::Pcap => save_to_pcap_path(app, &path, false),
                SaveFormat::PcapNg => save_to_pcap_path(app, &path, true),
                SaveFormat::Txt => save_to_txt_path(app, &path),
                SaveFormat::Json => save_to_json_path(app, &path),
                SaveFormat::Ndjson => save_to_ndjson_path(app, &path),
                SaveFormat::Csv => save_to_csv_path(app, &path),
                SaveFormat::Html => save_to_mermaid_path(app, &path),
                SaveFormat::Markdown => save_to_markdown_path(app, &path),
                SaveFormat::Wav => save_to_wav_path(app, &path),
                SaveFormat::SippXml => save_to_sipp_path(app, &path),
                SaveFormat::RtpJson => save_to_rtp_json_path(app, &path),
            };
            app.status_error = Some(msg);
            app.active_popup = None;
        }
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Down | KeyCode::Up => {
            // Cycle save format and update file extension
            let old_ext = app.save_format.extension();
            app.save_format = if key.code == KeyCode::BackTab || key.code == KeyCode::Up {
                app.save_format.prev()
            } else {
                app.save_format.next()
            };
            let new_ext = app.save_format.extension();
            // Update the file extension in the path
            if let Some(dot_pos) = app.save_path.rfind('.') {
                let after_dot = &app.save_path[dot_pos + 1..];
                if after_dot == old_ext {
                    app.save_path.truncate(dot_pos + 1);
                    app.save_path.push_str(new_ext);
                    app.save_cursor = app.save_path.len();
                }
            }
        }
        KeyCode::Backspace => {
            if app.save_cursor > 0 {
                // Find the previous char boundary
                let prev = app.save_path[..app.save_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.save_path.remove(prev);
                app.save_cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.save_cursor > 0 {
                app.save_cursor = app.save_path[..app.save_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.save_cursor < app.save_path.len() {
                app.save_cursor = app.save_path[app.save_cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.save_cursor + i)
                    .unwrap_or(app.save_path.len());
            }
        }
        KeyCode::Home => {
            app.save_cursor = 0;
        }
        KeyCode::End => {
            app.save_cursor = app.save_path.len();
        }
        KeyCode::Char(c) => {
            app.save_path.insert(app.save_cursor, c);
            app.save_cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Handle keys in the file-open dialog popup.
fn handle_file_open_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            let path = app.open_path.clone();
            if path.is_empty() {
                app.status_error = Some("No file path specified".to_string());
                app.active_popup = None;
                return;
            }
            let msg = load_pcap_file(app, &path);
            app.status_error = Some(msg);
            app.active_popup = None;
        }
        KeyCode::Backspace => {
            if app.open_cursor > 0 {
                let prev = app.open_path[..app.open_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.open_path.remove(prev);
                app.open_cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.open_cursor > 0 {
                app.open_cursor = app.open_path[..app.open_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.open_cursor < app.open_path.len() {
                app.open_cursor = app.open_path[app.open_cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.open_cursor + i)
                    .unwrap_or(app.open_path.len());
            }
        }
        KeyCode::Home => {
            app.open_cursor = 0;
        }
        KeyCode::End => {
            app.open_cursor = app.open_path.len();
        }
        KeyCode::Char(c) => {
            app.open_path.insert(app.open_cursor, c);
            app.open_cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Load a pcap file into the application, replacing all existing data.
///
/// Parses each packet through etherparse, extracts SIP messages, and feeds
/// them into the dialog store. Returns a status message describing the result.
fn load_pcap_file(app: &mut App, path_str: &str) -> String {
    use std::path::Path;

    let path = Path::new(path_str);
    if !path.exists() {
        return format!("File not found: {path_str}");
    }

    // Open pcap file
    let mut cap = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => return format!("Failed to open: {e}"),
    };

    // Clear existing data
    {
        let mut ds = app.dialog_store.write();
        ds.clear();
    }
    {
        let mut ss = app.stream_store.write();
        ss.clear();
    }

    // Reset TUI state
    app.call_list = CallListState::new();
    app.stream_list = StreamListState::new();
    app.active_filter = None;
    app.active_filter_text.clear();
    app.call_flow_cache.clear();
    app.selected_msg_index = 0;
    app.call_flow_scroll = 0;
    app.cached_flow_msg_count = 0;
    app.cached_rtp_bar_indices.clear();
    app.fold_expanded.clear();
    app.mark_index = None;
    app.current_view = View::CallList;

    // Process packets using the existing parse pipeline
    let mut packet_count = 0u64;
    let mut sip_count = 0u64;
    let link_type = cap.get_datalink().0;

    while let Ok(pkt) = cap.next_packet() {
        packet_count += 1;

        let ts = chrono::DateTime::from_timestamp(
            pkt.header.ts.tv_sec,
            (pkt.header.ts.tv_usec as u32) * 1000,
        )
        .unwrap_or_else(chrono::Utc::now);

        let capture_pkt = crate::capture::Packet::new(
            ts,
            pkt.data.to_vec(),
            pkt.header.caplen as usize,
            pkt.header.len as usize,
            None,
            link_type,
        );

        if let Ok(parsed) = crate::capture::parse::parse_packet(&capture_pkt)
            && !parsed.payload.is_empty()
            && crate::sip::is_sip_message(&parsed.payload)
            && let Ok(sip_msg) = crate::sip::parser::parse_sip(
                &parsed.payload,
                parsed.timestamp,
                parsed.src_addr,
                parsed.dst_addr,
                parsed.src_port,
                parsed.dst_port,
                parsed.transport,
            )
        {
            app.dialog_store.write().process_message(sip_msg);
            sip_count += 1;
        }
    }

    // Update capture mode display
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path_str);
    app.set_capture_mode(format!("Offline ({filename})"));
    app.mark_data_updated();

    format!("Loaded {sip_count} SIP messages from {packet_count} packets ({filename})")
}

/// Apply the filter dialog state: build a DSL expression, parse it, and set the active filter.
fn apply_filter_dialog(app: &mut App) {
    match app.filter_dialog.build_filter_expression() {
        Some(expr_text) => match FilterExpr::parse(&expr_text) {
            Ok(expr) => {
                app.active_filter = Some(expr);
                app.active_filter_text = expr_text;
                app.status_error = None;
            }
            Err(e) => {
                app.status_error = Some(format!("Filter error: {e}"));
            }
        },
        None => {
            // All fields empty — clear any active filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
        }
    }
    app.active_popup = None;
}

/// Handle keys in the filter dialog popup.
fn handle_filter_popup_key(app: &mut App, key: KeyEvent) {
    let is_shift = key.modifiers.contains(KeyModifiers::SHIFT);

    match key.code {
        KeyCode::Esc => {
            // Cancel without applying
            app.active_popup = None;
        }
        KeyCode::Enter => {
            if app.filter_dialog.focused_field == CANCEL_BUTTON_IDX {
                // Cancel button
                app.active_popup = None;
            } else {
                // Apply filter (from Filter button or any other field)
                apply_filter_dialog(app);
            }
        }
        KeyCode::Tab => {
            if is_shift {
                app.filter_dialog.focus_prev();
            } else {
                app.filter_dialog.focus_next();
            }
        }
        KeyCode::BackTab => {
            app.filter_dialog.focus_prev();
        }
        KeyCode::Down => {
            if app.filter_dialog.is_checkbox_focused() {
                app.filter_dialog.checkbox_down();
            } else {
                app.filter_dialog.focus_next();
            }
        }
        KeyCode::Up => {
            if app.filter_dialog.is_checkbox_focused() {
                app.filter_dialog.checkbox_up();
            } else {
                app.filter_dialog.focus_prev();
            }
        }
        KeyCode::Right if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.checkbox_right();
        }
        KeyCode::Left if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.checkbox_left();
        }
        KeyCode::F(9) => {
            // F9 clears all fields and the active filter, closes popup
            app.filter_dialog.clear();
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
            app.active_popup = None;
        }
        KeyCode::Char(' ') if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.toggle_checkbox();
        }
        KeyCode::Char(' ') if app.filter_dialog.focused_field == FILTER_BUTTON_IDX => {
            apply_filter_dialog(app);
        }
        KeyCode::Char(' ') if app.filter_dialog.focused_field == CANCEL_BUTTON_IDX => {
            app.active_popup = None;
        }
        // Text editing (only when a text field is focused)
        KeyCode::Backspace if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if cursor > 0
                && let Some(field) = app.filter_dialog.text_field_mut(idx)
            {
                field.remove(cursor - 1);
                app.filter_dialog.cursor_pos -= 1;
            }
        }
        KeyCode::Delete if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if let Some(field) = app.filter_dialog.text_field_mut(idx)
                && cursor < field.len()
            {
                field.remove(cursor);
            }
        }
        KeyCode::Left if app.filter_dialog.is_text_field_focused() => {
            app.filter_dialog.cursor_pos = app.filter_dialog.cursor_pos.saturating_sub(1);
        }
        KeyCode::Right if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let len = app.filter_dialog.text_field(idx).len();
            if app.filter_dialog.cursor_pos < len {
                app.filter_dialog.cursor_pos += 1;
            }
        }
        KeyCode::Home if app.filter_dialog.is_text_field_focused() => {
            app.filter_dialog.cursor_pos = 0;
        }
        KeyCode::End if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            app.filter_dialog.cursor_pos = app.filter_dialog.text_field(idx).len();
        }
        KeyCode::Char(c) if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if let Some(field) = app.filter_dialog.text_field_mut(idx) {
                field.insert(cursor, c);
                app.filter_dialog.cursor_pos += 1;
            }
        }
        _ => {}
    }
}

/// Handle keys in the settings popup.
fn handle_settings_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.settings_dialog.focused_item > 0 {
                app.settings_dialog.focused_item -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.settings_dialog.focused_item + 1 < SETTINGS_ITEM_COUNT {
                app.settings_dialog.focused_item += 1;
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            match app.settings_dialog.focused_item {
                0 => app.color_mode = app.color_mode.next(),
                1 => app.timestamp_mode = app.timestamp_mode.next(),
                2 => app.call_list.autoscroll = !app.call_list.autoscroll,
                3 => app.raw_preview = !app.raw_preview,
                4 => app.sdp_display_mode = app.sdp_display_mode.next(),
                5 => app.syntax_highlight = !app.syntax_highlight,
                _ => {}
            }
            app.call_flow_cache.clear();
        }
        _ => {}
    }
}

/// Handle keys in the statistics view.
fn handle_statistics_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == KeyCode::Esc || k == app.keymap.quit || k == KeyCode::Char('s') => {
            app.current_view = View::CallList;
        }
        _ => {}
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Get the Call-ID of the currently selected dialog in the call list,
/// respecting the active filter.
fn get_selected_call_id(app: &App) -> Option<String> {
    let store = app.dialog_store.read();
    let dialogs: Vec<_> = if let Some(ref filter) = app.active_filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .collect()
    } else {
        store.iter().collect()
    };
    let idx = app.call_list.selected();
    dialogs.get(idx).map(|d| d.call_id.clone())
}

/// Count dialogs visible after applying the active filter.
fn filtered_dialog_count(app: &App) -> usize {
    let store = app.dialog_store.read();
    if let Some(ref filter) = app.active_filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .count()
    } else {
        store.len()
    }
}

// ── Save functionality ─────────────────────────────────────────────

/// Build a synthetic Ethernet + IPv4 + UDP packet from a SIP message's raw bytes.
///
/// The link-layer type is DLT_EN10MB (1). IP addresses and ports come from
/// the SipMessage metadata.
fn build_synthetic_packet(msg: &crate::sip::SipMessage) -> crate::capture::Packet {
    let payload = &msg.raw;
    // Saturate instead of silently truncating for large payloads
    let udp_len: u16 = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let ip_total_len: u16 = 20u16.saturating_add(udp_len);
    let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes, no options)
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
    pkt.push(64); // TTL
    pkt.push(17); // protocol: UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (skip)
    match msg.src_addr {
        IpAddr::V4(v4) => pkt.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => pkt.extend_from_slice(&[0; 4]), // fallback for v6
    }
    match msg.dst_addr {
        IpAddr::V4(v4) => pkt.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => pkt.extend_from_slice(&[0; 4]),
    }

    // UDP header (8 bytes)
    pkt.extend_from_slice(&msg.src_port.to_be_bytes());
    pkt.extend_from_slice(&msg.dst_port.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum

    // Payload
    pkt.extend_from_slice(payload);

    let len = pkt.len();
    crate::capture::Packet::new(msg.timestamp, pkt, len, len, None, 1) // DLT_EN10MB
}

/// Save all dialogs to a pcap or pcap-ng file.
fn save_to_pcap_path(app: &App, path_str: &str, pcapng: bool) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Collect all messages across all dialogs
    let messages: Vec<&crate::sip::SipMessage> =
        store.iter().flat_map(|d| d.messages.iter()).collect();

    if messages.is_empty() {
        return "No messages to save".to_string();
    }

    // Create writer (DLT_EN10MB = 1)
    let mut writer = match crate::capture::PcapWriter::with_format(&path, 1, None, None, pcapng) {
        Ok(w) => w,
        Err(e) => return format!("Save failed: {e}"),
    };

    let fmt_label = if pcapng { "pcapng" } else { "pcap" };
    let mut count = 0;
    for msg in &messages {
        let pkt = build_synthetic_packet(msg);
        if let Err(e) = writer.write(&pkt) {
            return format!("Write error after {count} packets: {e}");
        }
        count += 1;
    }

    format!("Saved {count} packets ({fmt_label}) to {}", path.display())
}

/// Save all dialogs as plain text SIP messages.
fn save_to_txt_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    let messages: Vec<&crate::sip::SipMessage> =
        store.iter().flat_map(|d| d.messages.iter()).collect();

    if messages.is_empty() {
        return "No messages to save".to_string();
    }

    let mut output = String::new();
    for (i, msg) in messages.iter().enumerate() {
        if i > 0 {
            output.push_str("\n---\n\n");
        }
        // Header with timestamp, source, destination, and transport
        output.push_str(&format!(
            "# Message {} | {} | {} {}:{} -> {}:{}\n",
            i + 1,
            msg.timestamp.format("%Y-%m-%d %H:%M:%S%.3f UTC"),
            msg.transport,
            msg.src_addr,
            msg.src_port,
            msg.dst_addr,
            msg.dst_port,
        ));
        // Raw SIP message
        match std::str::from_utf8(&msg.raw) {
            Ok(text) => output.push_str(text),
            Err(_) => output.push_str(&format!("(binary: {} bytes)", msg.raw.len())),
        }
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }

    match std::fs::write(&path, &output) {
        Ok(()) => format!(
            "Saved {} messages (txt) to {}",
            messages.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Save current call flow as a Mermaid sequence diagram.
fn save_to_mermaid_path(app: &App, path_str: &str) -> String {
    let path = std::path::PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Collect messages based on current view
    let messages: Vec<crate::sip::SipMessage> = if let View::CallFlow(ref call_id) = app.current_view {
        // In call flow: export just this dialog (+ correlated if extended)
        if app.extended_flow {
            if let Some(dialog) = store.get(call_id) {
                let mut all: Vec<&crate::sip::SipMessage> = dialog.messages.iter().collect();
                let correlated = store.find_correlated(call_id);
                for leg in &correlated {
                    all.extend(leg.messages.iter());
                }
                all.sort_by_key(|m| m.timestamp);
                all.into_iter().cloned().collect()
            } else {
                Vec::new()
            }
        } else if let Some(dialog) = store.get(call_id) {
            dialog.messages.clone()
        } else {
            Vec::new()
        }
    } else {
        // In call list: export all dialogs
        store.iter().flat_map(|d| d.messages.clone()).collect()
    };

    if messages.is_empty() {
        return "No messages to export".to_string();
    }

    let ft = messages[0].timestamp;
    let (participants, msgs) = call_flow::prepare_messages(
        &messages,
        ft,
        None,
        SdpDisplayMode::None,
        TimestampMode::Absolute,
        ColorMode::Method,
        false,
        None,
        &app.theme,
        &std::collections::HashSet::new(),
    );

    let mermaid = call_flow::export::export_mermaid_html(&participants, &msgs);

    match std::fs::write(&path, &mermaid) {
        Ok(()) => format!(
            "Saved Mermaid diagram ({} messages) to {}",
            msgs.iter().filter(|m| !m.is_spacer).count(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Format a [`DialogState`] as a display string for export.
fn format_dialog_state(state: &crate::sip::dialog::DialogState) -> &'static str {
    use crate::sip::dialog::DialogState;
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => "Failed",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Escape a field for CSV output: if it contains commas, quotes, or newlines,
/// wrap in double quotes and double any existing quotes.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Export all dialogs as pretty-printed JSON with parsed headers, timing, and state.
fn save_to_json_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let json_dialogs: Vec<serde_json::Value> = dialogs
        .iter()
        .map(|d| {
            let messages: Vec<serde_json::Value> = d
                .messages
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "timestamp": m.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "is_request": m.is_request,
                        "method": m.method,
                        "status_code": m.status_code,
                        "src": format!("{}:{}", m.src_addr, m.src_port),
                        "dst": format!("{}:{}", m.dst_addr, m.dst_port),
                        "is_retransmission": m.is_retransmission,
                    })
                })
                .collect();

            let duration_ms = d.timing.bye_sent.and_then(|bye| {
                d.timing.answered_at.map(|ans| (bye - ans).num_milliseconds())
            });
            let timing = serde_json::json!({
                "pdd_ms": d.timing.pdd_ms(),
                "setup_ms": d.timing.setup_ms(),
                "duration_ms": duration_ms,
            });

            serde_json::json!({
                "call_id": d.call_id,
                "method": d.method,
                "state": format_dialog_state(&d.state),
                "from_user": d.from_user,
                "to_user": d.to_user,
                "src_addr": d.src_addr.to_string(),
                "dst_addr": d.dst_addr.to_string(),
                "created_at": d.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "message_count": d.messages.len(),
                "timing": timing,
                "messages": messages,
            })
        })
        .collect();

    match serde_json::to_string_pretty(&json_dialogs) {
        Ok(json_str) => match std::fs::write(&path, &json_str) {
            Ok(()) => format!(
                "Saved {} dialogs (JSON) to {}",
                dialogs.len(),
                path.display()
            ),
            Err(e) => format!("Save failed: {e}"),
        },
        Err(e) => format!("JSON serialization failed: {e}"),
    }
}

/// Export all dialogs as newline-delimited JSON (one JSON object per line).
fn save_to_ndjson_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let mut output = String::new();
    for d in &dialogs {
        let messages: Vec<serde_json::Value> = d
            .messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "timestamp": m.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "is_request": m.is_request,
                    "method": m.method,
                    "status_code": m.status_code,
                    "src": format!("{}:{}", m.src_addr, m.src_port),
                    "dst": format!("{}:{}", m.dst_addr, m.dst_port),
                })
            })
            .collect();

        let duration_ms = d.timing.bye_sent.and_then(|bye| {
            d.timing.answered_at.map(|ans| (bye - ans).num_milliseconds())
        });
        let timing = serde_json::json!({
            "pdd_ms": d.timing.pdd_ms(),
            "setup_ms": d.timing.setup_ms(),
            "duration_ms": duration_ms,
        });

        let obj = serde_json::json!({
            "call_id": d.call_id,
            "method": d.method,
            "state": format_dialog_state(&d.state),
            "from_user": d.from_user,
            "to_user": d.to_user,
            "src_addr": d.src_addr.to_string(),
            "dst_addr": d.dst_addr.to_string(),
            "created_at": d.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "message_count": d.messages.len(),
            "timing": timing,
            "messages": messages,
        });

        match serde_json::to_string(&obj) {
            Ok(line) => {
                output.push_str(&line);
                output.push('\n');
            }
            Err(e) => return format!("JSON serialization failed: {e}"),
        }
    }

    match std::fs::write(&path, &output) {
        Ok(()) => format!(
            "Saved {} dialogs (NDJSON) to {}",
            dialogs.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export dialog summaries as CSV (one row per dialog).
fn save_to_csv_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let mut output = String::from("call_id,method,state,from,to,src_ip,dst_ip,messages,pdd_ms,setup_ms,created_at\n");

    for d in &dialogs {
        let row = format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&d.call_id),
            csv_escape(&d.method),
            csv_escape(format_dialog_state(&d.state)),
            csv_escape(d.from_user.as_deref().unwrap_or("")),
            csv_escape(d.to_user.as_deref().unwrap_or("")),
            csv_escape(&d.src_addr.to_string()),
            csv_escape(&d.dst_addr.to_string()),
            d.messages.len(),
            d.timing.pdd_ms().map_or(String::new(), |v| v.to_string()),
            d.timing.setup_ms().map_or(String::new(), |v| v.to_string()),
            d.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        output.push_str(&row);
    }

    match std::fs::write(&path, &output) {
        Ok(()) => format!(
            "Saved {} dialogs (CSV) to {}",
            dialogs.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export a Markdown call summary suitable for tickets and incident docs.
fn save_to_markdown_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let mut md = String::from("# Call Summary\n\nGenerated by sipnab v0.3.1\n\n");

    for d in &dialogs {
        md.push_str(&format!(
            "## Dialog: {} ({})\n\n",
            d.call_id, d.method,
        ));

        md.push_str("| Field | Value |\n|-------|-------|\n");
        md.push_str(&format!("| State | {} |\n", format_dialog_state(&d.state)));
        md.push_str(&format!(
            "| From | {} |\n",
            d.from_user.as_deref().unwrap_or("-")
        ));
        md.push_str(&format!(
            "| To | {} |\n",
            d.to_user.as_deref().unwrap_or("-")
        ));

        // Source/destination from first message if available
        if let Some(first) = d.messages.first() {
            md.push_str(&format!(
                "| Source | {}:{} |\n",
                first.src_addr, first.src_port
            ));
            md.push_str(&format!(
                "| Destination | {}:{} |\n",
                first.dst_addr, first.dst_port
            ));
        }

        md.push_str(&format!("| Messages | {} |\n", d.messages.len()));

        if let Some(pdd) = d.timing.pdd_ms() {
            md.push_str(&format!("| PDD | {pdd}ms |\n"));
        }
        if let Some(setup) = d.timing.setup_ms() {
            md.push_str(&format!("| Setup | {setup}ms |\n"));
        }

        md.push_str(&format!(
            "| Created | {} |\n\n",
            d.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Message flow table
        if !d.messages.is_empty() {
            md.push_str("### Message Flow\n\n");
            md.push_str("| # | Time | Direction | Method/Status |\n");
            md.push_str("|---|------|-----------|---------------|\n");

            for (i, m) in d.messages.iter().enumerate() {
                let direction = if m.is_request {
                    "\u{2192}" // →
                } else {
                    "\u{2190}" // ←
                };
                let label = if m.is_request {
                    m.method.as_deref().unwrap_or("?").to_string()
                } else {
                    match (m.status_code, m.reason.as_deref()) {
                        (Some(code), Some(reason)) => format!("{code} {reason}"),
                        (Some(code), None) => code.to_string(),
                        _ => "?".to_string(),
                    }
                };
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    i + 1,
                    m.timestamp.format("%H:%M:%S%.3f"),
                    direction,
                    label,
                ));
            }
            md.push('\n');
        }
    }

    match std::fs::write(&path, &md) {
        Ok(()) => format!(
            "Saved {} dialogs (Markdown) to {}",
            dialogs.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// WAV export stub — requires RTP payload storage not yet available.
fn save_to_wav_path(_app: &App, _path_str: &str) -> String {
    "WAV export: G.711 audio extraction requires RTP payload capture (planned for v0.4)".to_string()
}

/// Export a SIPp scenario XML from the current dialog's call flow.
fn save_to_sipp_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Pick dialog: current call flow view or first dialog
    let dialog = if let View::CallFlow(ref call_id) = app.current_view {
        store.get(call_id)
    } else {
        store.iter().next()
    };

    let dialog = match dialog {
        Some(d) => d,
        None => return "No dialog to export".to_string(),
    };

    if dialog.messages.is_empty() {
        return "No messages in dialog".to_string();
    }

    // Determine the "caller" side from the first request
    let caller_addr = dialog.messages.first().map(|m| (m.src_addr, m.src_port));

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<!-- Generated by sipnab v0.3.1 -->\n");
    xml.push_str(&format!(
        "<scenario name=\"sipnab_{}\">\n",
        dialog.method.to_lowercase()
    ));

    let mut prev_ts = dialog.messages[0].timestamp;
    for m in &dialog.messages {
        // Insert pause for gaps > 500ms
        let gap_ms = (m.timestamp - prev_ts).num_milliseconds();
        if gap_ms > 500 {
            xml.push_str(&format!(
                "\n  <pause milliseconds=\"{}\"/>\n",
                gap_ms
            ));
        }
        prev_ts = m.timestamp;

        let is_from_caller = caller_addr
            .map(|(addr, port)| m.src_addr == addr && m.src_port == port)
            .unwrap_or(false);

        if m.is_request {
            if is_from_caller {
                // Caller sends request
                let method = m.method.as_deref().unwrap_or("UNKNOWN");
                let ruri = m.request_uri.as_deref().unwrap_or("sip:[service]@[remote_ip]:[remote_port]");
                let ruri_sipp = ruri
                    .replace(&m.dst_addr.to_string(), "[remote_ip]")
                    .replace(&m.dst_port.to_string(), "[remote_port]");

                xml.push_str("\n  <send>\n    <![CDATA[\n");
                xml.push_str(&format!("      {} {} SIP/2.0\r\n", method, ruri_sipp));
                xml.push_str("      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\r\n");
                xml.push_str(&format!(
                    "      From: <sip:{}@[local_ip]>;tag=[call_number]\r\n",
                    dialog.from_user.as_deref().unwrap_or("user")
                ));
                xml.push_str(&format!(
                    "      To: <sip:{}@[remote_ip]>\r\n",
                    dialog.to_user.as_deref().unwrap_or("service")
                ));
                xml.push_str("      Call-ID: [call_id]\r\n");
                // Derive CSeq from the original message
                let cseq = m.cseq().map_or_else(
                    || format!("1 {method}"),
                    |(num, meth)| format!("{num} {meth}"),
                );
                xml.push_str(&format!("      CSeq: {cseq}\r\n"));
                xml.push_str("      Max-Forwards: 70\r\n");
                xml.push_str("      Content-Length: [len]\r\n");
                xml.push_str("    ]]>\n  </send>\n");
            } else {
                // Callee sends request (e.g., BYE from remote) — receive it
                let method = m.method.as_deref().unwrap_or("UNKNOWN");
                xml.push_str(&format!(
                    "\n  <recv request=\"{method}\"/>\n"
                ));
            }
        } else {
            // Response
            let code = m.status_code.unwrap_or(0);
            if is_from_caller {
                // Caller sending a response (unusual, but handle it)
                xml.push_str(&format!(
                    "\n  <send>\n    <![CDATA[\n      SIP/2.0 {} {}\r\n      [last_Via:]\r\n      [last_From:]\r\n      [last_To:]\r\n      [last_Call-ID:]\r\n      [last_CSeq:]\r\n      Content-Length: 0\r\n\n    ]]>\n  </send>\n",
                    code,
                    m.reason.as_deref().unwrap_or("OK"),
                ));
            } else {
                // Receive response from remote
                let optional = if (100..200).contains(&code) {
                    " optional=\"true\""
                } else {
                    ""
                };
                xml.push_str(&format!(
                    "\n  <recv response=\"{code}\"{optional}/>\n"
                ));
            }
        }
    }

    xml.push_str("\n</scenario>\n");

    match std::fs::write(&path, &xml) {
        Ok(()) => format!(
            "Saved SIPp scenario ({} messages) to {}",
            dialog.messages.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export RTP/RTCP stream quality data as JSON.
fn save_to_rtp_json_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let stream_store = app.stream_store.read();
    let streams: Vec<&crate::rtp::stream::RtpStream> = stream_store.iter().collect();

    if streams.is_empty() {
        return "No RTP streams to save".to_string();
    }

    let json_streams: Vec<serde_json::Value> = streams
        .iter()
        .map(|s| {
            let total = s.packet_count + s.lost_packets;
            let loss_pct = if total > 0 {
                (s.lost_packets as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let duration_secs = s
                .last_seen
                .signed_duration_since(s.first_seen)
                .num_milliseconds() as f64
                / 1000.0;

            // Simplified E-model R-factor → MOS estimate
            // R = 93.2 - loss% * 2.5 - jitter_ms * 0.1
            let r_factor = (93.2 - loss_pct * 2.5 - s.jitter * 0.1).clamp(0.0, 100.0);
            let mos = if r_factor < 6.5 {
                1.0
            } else {
                1.0 + 0.035 * r_factor + r_factor * (r_factor - 60.0) * (100.0 - r_factor) * 7e-6
            };
            let mos = (mos * 10.0).round() / 10.0; // Round to 1 decimal

            serde_json::json!({
                "ssrc": format!("0x{:08x}", s.key.ssrc),
                "src": s.key.src.to_string(),
                "dst": s.key.dst.to_string(),
                "codec": s.codec.as_deref().unwrap_or("unknown"),
                "packets": s.packet_count,
                "jitter_ms": (s.jitter * 10.0).round() / 10.0,
                "loss_pct": (loss_pct * 10.0).round() / 10.0,
                "mos": mos,
                "duration_secs": (duration_secs * 10.0).round() / 10.0,
                "cn_frames": s.cn_frames,
                "silence_periods": s.silence_periods.len(),
            })
        })
        .collect();

    match serde_json::to_string_pretty(&json_streams) {
        Ok(json_str) => match std::fs::write(&path, &json_str) {
            Ok(()) => format!(
                "Saved {} RTP streams (JSON) to {}",
                streams.len(),
                path.display()
            ),
            Err(e) => format!("Save failed: {e}"),
        },
        Err(e) => format!("JSON serialization failed: {e}"),
    }
}

// ── Test helpers (public for integration tests) ────────────────────

/// Test helper methods for App, available in test builds.
///
/// These are feature-gated behind `#[cfg(test)]` or `#[cfg(feature = "tui")]`
/// and exposed publicly for integration tests.
impl App {
    /// Create an App with empty stores for testing.
    pub fn new_test() -> Self {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        Self::new(ds, ss, Theme::default(), Keymap::default())
    }

    /// Create an App whose dialog store already contains the given messages.
    ///
    /// Each slice of `SipMessage`s is processed in order so that the dialog
    /// store builds dialogs and runs the state machine.
    pub fn with_processed_messages(messages: Vec<crate::sip::SipMessage>) -> Self {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        {
            let mut store = ds.write();
            for msg in messages {
                store.process_message(msg);
            }
        }
        Self::new(ds, ss, Theme::default(), Keymap::default())
    }

    /// Simulate a single keypress.
    pub fn handle_key(&mut self, code: KeyCode) {
        let key = KeyEvent::new(code, KeyModifiers::NONE);
        handle_key_event(self, key);
    }

    /// Simulate a keypress with modifiers.
    pub fn handle_key_with_modifiers(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        let key = KeyEvent::new(code, modifiers);
        handle_key_event(self, key);
    }

    /// Return the current view.
    pub fn current_view(&self) -> &View {
        &self.current_view
    }

    /// Return the active popup, if any.
    pub fn active_popup(&self) -> Option<&Popup> {
        self.active_popup.as_ref()
    }

    /// Return whether the quit flag is set.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// Return whether the paused flag is set.
    pub fn paused(&self) -> bool {
        self.paused
    }

    /// Return a reference to the call list state.
    pub fn call_list_state(&self) -> &CallListState {
        &self.call_list
    }

    /// Return the current timestamp display mode.
    pub fn timestamp_mode(&self) -> TimestampMode {
        self.timestamp_mode
    }

    /// Count dialogs visible after applying the active filter.
    pub fn visible_dialog_count(&self) -> usize {
        filtered_dialog_count(self)
    }

    /// Return a reference to the filter dialog state (for tests).
    pub fn filter_dialog_state(&self) -> &FilterDialogState {
        &self.filter_dialog
    }

    /// Return a mutable reference to the filter dialog state (for tests).
    pub fn filter_dialog_state_mut(&mut self) -> &mut FilterDialogState {
        &mut self.filter_dialog
    }

    /// Return the current SDP display mode.
    pub fn sdp_display_mode(&self) -> SdpDisplayMode {
        self.sdp_display_mode
    }

    /// Return the current color mode.
    pub fn color_mode(&self) -> ColorMode {
        self.color_mode
    }

    /// Return whether the raw preview split is active.
    pub fn raw_preview(&self) -> bool {
        self.raw_preview
    }

    /// Return the raw preview pane percentage.
    pub fn raw_preview_pct(&self) -> u16 {
        self.raw_preview_pct
    }

    /// Return whether extended multi-leg flow is active.
    pub fn extended_flow(&self) -> bool {
        self.extended_flow
    }

    /// Return whether RTP is shown in the call flow.
    pub fn show_rtp_in_flow(&self) -> bool {
        self.show_rtp_in_flow
    }

    /// Return whether search mode is active.
    pub fn search_active(&self) -> bool {
        self.search_active
    }

    /// Return the current search query.
    pub fn search_query(&self) -> &str {
        &self.search_query
    }

    /// Return whether syntax highlighting is enabled.
    pub fn syntax_highlight(&self) -> bool {
        self.syntax_highlight
    }

    /// Return the current status error message, if any.
    pub fn status_error(&self) -> Option<&str> {
        self.status_error.as_deref()
    }

    /// Return the selected message index in the call flow.
    pub fn selected_msg_index(&self) -> usize {
        self.selected_msg_index
    }

    /// Return the detail panel scroll offset.
    pub fn detail_scroll(&self) -> u16 {
        self.detail_scroll
    }

    /// Return the raw message view scroll offset.
    pub fn raw_msg_scroll(&self) -> u16 {
        self.raw_msg_scroll
    }

    /// Return the call flow ladder scroll offset.
    pub fn call_flow_scroll(&self) -> usize {
        self.call_flow_scroll
    }

    /// Return the first selected message for diff comparison.
    pub fn diff_selected_msg(&self) -> Option<usize> {
        self.diff_selected_msg
    }

    /// Return the marked message index (for mark + delta).
    pub fn mark_index(&self) -> Option<usize> {
        self.mark_index
    }

    /// Return the set of expanded fold indices.
    pub fn fold_expanded(&self) -> &HashSet<usize> {
        &self.fold_expanded
    }

    /// Return the selected save format.
    pub fn save_format(&self) -> SaveFormat {
        self.save_format
    }

    /// Return the save dialog file path.
    pub fn save_path(&self) -> &str {
        &self.save_path
    }

    /// Return the save dialog cursor position.
    pub fn save_cursor(&self) -> usize {
        self.save_cursor
    }

    /// Return the file-open dialog path.
    pub fn open_path(&self) -> &str {
        &self.open_path
    }

    /// Return the file-open dialog cursor position.
    pub fn open_cursor(&self) -> usize {
        self.open_cursor
    }

    /// Override the save dialog path (for deterministic snapshot tests).
    pub fn set_save_path(&mut self, path: &str) {
        self.save_path = path.to_string();
        self.save_cursor = path.len();
    }

    /// Render the full application frame into the given frame (for snapshot tests).
    pub fn render(&mut self, frame: &mut ratatui::Frame) {
        render_app(frame, self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_default_view_is_call_list() {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let app = App::new(ds, ss, Theme::default(), Keymap::default());
        assert_eq!(app.current_view, View::CallList);
        assert!(!app.should_quit);
    }

    #[test]
    fn adaptive_timeout_active_vs_idle() {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let mut app = App::new(ds, ss, Theme::default(), Keymap::default());

        // Just created — should be active
        assert!(app.poll_timeout() <= Duration::from_millis(ACTIVE_POLL_MS));

        // Simulate idle by backdating the timestamp
        app.last_data_update = Instant::now() - Duration::from_secs(10);
        assert!(app.poll_timeout() >= Duration::from_millis(IDLE_POLL_MS));
    }

    #[test]
    fn theme_from_config_selected_overrides_highlight() {
        let config = ThemeConfig {
            highlight: Some("red".to_string()),
            selected: Some("blue".to_string()),
            ..Default::default()
        };
        let theme = Theme::from_config(&config);
        assert_eq!(theme.selected, Color::Blue); // selected wins over highlight
    }

    #[test]
    fn theme_from_config_highlight_fallback() {
        let config = ThemeConfig {
            highlight: Some("red".to_string()),
            ..Default::default()
        };
        let theme = Theme::from_config(&config);
        assert_eq!(theme.selected, Color::Red); // highlight applies when selected is None
    }

    #[test]
    fn keymap_from_config_overrides_default() {
        let config = KeybindingsConfig {
            quit: Some("x".to_string()),
            ..Default::default()
        };
        let keymap = Keymap::from_config(&config);
        assert_eq!(keymap.quit, KeyCode::Char('x'));
        assert_eq!(keymap.help, KeyCode::F(1)); // unchanged default
    }

    #[test]
    fn csv_escape_quotes_commas() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn view_equality() {
        assert_eq!(View::CallList, View::CallList);
        assert_ne!(View::CallList, View::StreamList);
        assert_eq!(
            View::CallFlow("abc".to_string()),
            View::CallFlow("abc".to_string())
        );
        assert_ne!(
            View::CallFlow("abc".to_string()),
            View::CallFlow("def".to_string())
        );
    }

    #[test]
    fn build_synthetic_packet_large_payload_no_panic() {
        // Verify that a SIP message with a raw payload exceeding 65535 bytes
        // does not panic due to u16 overflow in UDP/IP length fields.
        // The fix uses u16 saturation (unwrap_or(u16::MAX) / saturating_add).
        use std::net::{IpAddr, Ipv4Addr};
        use crate::capture::parse::TransportProto;
        use crate::sip::SipMessage;
        use chrono::Utc;

        let large_body = vec![b'X'; 70_000]; // > u16::MAX (65535)
        let msg = SipMessage {
            raw: large_body,
            is_request: true,
            method: Some("INVITE".to_string()),
            status_code: None,
            reason: None,
            request_uri: Some("sip:test@example.com".to_string()),
            headers: vec![],
            body: vec![],
            parse_error: false,
            timestamp: Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
            is_retransmission: false,
        };

        // This must not panic — the u16 fields saturate instead of overflowing.
        let pkt = build_synthetic_packet(&msg);

        // Sanity: packet should contain the Ethernet + IP + UDP headers plus payload
        assert!(pkt.data.len() > 42, "packet must contain headers + payload");
        // IP total length field (bytes 16-17 of the packet, offset 14+2 into Ethernet)
        let ip_total = u16::from_be_bytes([pkt.data[16], pkt.data[17]]);
        // With saturation, udp_len = u16::MAX and ip_total_len = 20.saturating_add(u16::MAX) = u16::MAX
        assert_eq!(ip_total, u16::MAX, "IP total length should saturate to u16::MAX");
    }
}
