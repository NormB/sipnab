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

use crate::names::{NameMode, NameResolver};
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;

use call_list::CallListState;
use stream_list::StreamListState;

use crate::config::{KeybindingsConfig, ThemeConfig, parse_color, parse_keycode};

mod events;
mod render;
mod save;
mod theme;

use events::*;
use render::*;
use save::*;
pub use theme::*;

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

/// How the call-list From/To columns render a SIP address.
///
/// Cycled with the `u` key. The username is often absent (e.g. domain-only or
/// device URIs), so the default falls back to the host instead of a bare `-`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FromToMode {
    /// Username if present, else host[:port] (else `-`).
    #[default]
    Default,
    /// Host[:port] only (else `-`).
    HostPort,
    /// Username only (else `-`) — the legacy behavior.
    User,
    /// `user@host:port` when both exist, else whichever exists (else `-`).
    UserHostPort,
}

impl FromToMode {
    /// Cycle to the next mode.
    fn next(self) -> Self {
        match self {
            Self::Default => Self::HostPort,
            Self::HostPort => Self::User,
            Self::User => Self::UserHostPort,
            Self::UserHostPort => Self::Default,
        }
    }

    /// Human-readable label for the status bar.
    fn label(self) -> &'static str {
        match self {
            Self::Default => "From/To: Default (user or host)",
            Self::HostPort => "From/To: Host:port",
            Self::User => "From/To: User only",
            Self::UserHostPort => "From/To: User@host:port",
        }
    }

    /// Stable string used in config (`[display] from_to = ...`) and the CLI.
    pub fn as_config_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::HostPort => "host-port",
            Self::User => "user",
            Self::UserHostPort => "user-host-port",
        }
    }

    /// Parse a config/CLI value into a mode. Returns `None` for unknown values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "host-port" => Some(Self::HostPort),
            "user" => Some(Self::User),
            "user-host-port" => Some(Self::UserHostPort),
            _ => None,
        }
    }

    /// Format a From/To cell from the (already name-resolved) user and host.
    fn format(self, user: Option<&str>, host: Option<&str>) -> String {
        const DASH: &str = "-";
        match self {
            Self::Default => user.or(host).unwrap_or(DASH).to_string(),
            Self::HostPort => host.unwrap_or(DASH).to_string(),
            Self::User => user.unwrap_or(DASH).to_string(),
            Self::UserHostPort => match (user, host) {
                (Some(u), Some(h)) => format!("{u}@{h}"),
                (Some(u), None) => u.to_string(),
                (None, Some(h)) => h.to_string(),
                (None, None) => DASH.to_string(),
            },
        }
    }
}

/// A single entry in the file-open browser's directory listing.
#[derive(Debug, Clone)]
struct FileEntry {
    /// File name (no path) — what the user sees in the list.
    name: String,
    /// Absolute path — what we pass to `load_pcap_file` or `cd` into.
    path: PathBuf,
    /// Whether this entry is a directory.
    is_dir: bool,
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

/// State for the "Name Address" popup (map an IP to a host/FQDN).
#[derive(Debug, Clone, Default)]
struct NameDialogState {
    /// The IP being named (display only; the resolution key).
    ip: String,
    /// Editable name text field.
    name: String,
    /// Cursor position within `name`.
    cursor: usize,
}

/// Structured state for the sngrep-style filter dialog.
#[derive(Debug, Clone)]
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

impl Default for FilterDialogState {
    fn default() -> Self {
        Self {
            sip_from: String::new(),
            sip_to: String::new(),
            source: String::new(),
            destination: String::new(),
            payload: String::new(),
            // All SIP methods checked by default == show every message. The
            // method filter only narrows once the user unchecks something.
            methods: [true; 10],
            focused_field: 0,
            cursor_pos: 0,
        }
    }
}

impl FilterDialogState {
    /// Whether at least one SIP method checkbox is checked. When none are
    /// checked the call list shows nothing (see `apply_filter_dialog`).
    fn any_method_checked(&self) -> bool {
        self.methods.iter().any(|&v| v)
    }

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

    /// Move checkbox focus down one row.
    ///
    /// The checkboxes are a 2-column grid (left = even indices, right = odd).
    /// Down walks a column to its bottom, then continues into the top of the
    /// next column, then to the buttons — so vertical navigation alone reaches
    /// every checkbox (the right column was previously unreachable this way).
    fn checkbox_down(&mut self) {
        if let Some(idx) = self.checkbox_index() {
            let next = idx + 2;
            if next < FILTER_METHODS.len() {
                // Same column, one row down.
                self.focused_field = FILTER_TEXT_FIELD_COUNT + next;
            } else if idx % 2 == 0 {
                // Bottom of the LEFT column -> top of the RIGHT column.
                self.focused_field = FILTER_TEXT_FIELD_COUNT + 1;
            } else {
                // Bottom of the RIGHT column -> buttons row.
                self.focused_field = FILTER_BUTTON_IDX;
            }
        }
    }

    /// Move checkbox focus up one row (reverse of [`Self::checkbox_down`]).
    fn checkbox_up(&mut self) {
        if let Some(idx) = self.checkbox_index() {
            if idx >= 2 {
                // Same column, one row up.
                self.focused_field = FILTER_TEXT_FIELD_COUNT + (idx - 2);
            } else if idx == 1 {
                // Top of the RIGHT column -> bottom of the LEFT column.
                self.focused_field = FILTER_TEXT_FIELD_COUNT + (FILTER_METHODS.len() - 2);
            } else {
                // Top of the LEFT column -> last text field.
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
        // Re-check every method so "clear filter" means show all, matching the
        // dialog's default state.
        self.methods = [true; 10];
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
            // All methods checked == no method narrowing == an "empty" filter.
            && self.methods.iter().all(|&v| v)
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
    /// "Name Address" popup: map the selected IP to a host/FQDN.
    NameAddress,
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
    /// Version string (semver + git commit + compiled feature list) shown in
    /// the help view. Stored on the App so tests can inject a deterministic
    /// value instead of the build-dependent `cli::build_version()` output.
    version: String,
    /// When data was last updated (for adaptive refresh).
    last_data_update: Instant,
    last_known_dialog_count: usize,
    stream_detail_scroll: usize,
    /// View to return to when pressing Esc from StreamDetail.
    stream_detail_return_view: Option<View>,
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
    /// Scroll offset for the F1 help view (clamped to content height in render).
    help_scroll: u16,
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
    /// File-open dialog: path being edited (used only in manual-path mode).
    open_path: String,
    /// File-open dialog: cursor position in path.
    open_cursor: usize,
    /// File-open dialog: current directory being browsed.
    open_dir: std::path::PathBuf,
    /// File-open dialog: entries in the current directory (dirs first, then pcaps).
    open_entries: Vec<FileEntry>,
    /// File-open dialog: selected row in the entries list.
    open_selected: usize,
    /// File-open dialog: typed filter substring (narrows the entries list).
    open_filter: String,
    /// File-open dialog: manual-path edit mode (Tab toggles).
    open_manual_mode: bool,
    /// File-open dialog: error from the last directory read (e.g. permission
    /// denied after a privilege drop), shown in the browser instead of a blank
    /// list. `None` when the directory was read successfully.
    open_error: Option<String>,

    // ── Call flow display modes ────────────────────────────────────
    /// SDP display mode (None / Summary / Full).
    /// Name-resolution display mode (Off / Names / Dns).
    name_mode: NameMode,
    /// Shared IP -> name resolver (manual mappings, hosts, reverse DNS).
    resolver: Arc<NameResolver>,
    /// Path the manual mappings persist to (set from config/CLI).
    names_save_path: Option<PathBuf>,
    /// When `Some`, `N`-dialog edits are also written into this sipnabrc's
    /// `[names.manual]` table (opt-in via `[names] persist_to_config`).
    names_config_path: Option<PathBuf>,
    /// "Name Address" popup state.
    name_dialog: NameDialogState,
    sdp_display_mode: SdpDisplayMode,
    /// Timestamp display mode (Absolute / Delta-prev / Delta-first).
    timestamp_mode: TimestampMode,
    /// Color mode for arrows (Method / CallId / CSeq).
    color_mode: ColorMode,
    /// How the call-list From/To columns render (user / host:port / both).
    from_to_mode: FromToMode,
    /// Whether the raw preview split is active in call flow view.
    /// Default is `true` (matching sngrep: split view on by default).
    raw_preview: bool,
    /// Split percentage for the raw preview (right) pane (10..=80, default 40).
    raw_preview_pct: u16,
    /// Index of the currently selected message in the call flow ladder.
    selected_msg_index: usize,
    /// Scroll offset for the detail (right) panel in split view.
    detail_scroll: u16,
    /// In the call flow split view, whether keyboard focus is on the detail
    /// (right) pane. `false` = ladder (left). Toggled with Tab. Only meaningful
    /// while [`Self::raw_preview`] is on; navigation keys act on the focused pane.
    call_flow_detail_focused: bool,
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
    /// Audio player for RTP stream playback (lazily initialized).
    #[cfg(feature = "audio")]
    audio_player: Option<crate::rtp::playback::AudioPlayer>,
    /// Cached message from a previously failed audio-init attempt.
    /// Once set, subsequent Play presses surface this instead of
    /// retrying (which would re-emit libasound errors).
    #[cfg(feature = "audio")]
    audio_init_error: Option<String>,
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
            version: crate::cli::build_version(),
            current_view: View::CallList,
            active_popup: None,
            call_list: CallListState::new(),
            stream_list: StreamListState::new(),
            should_quit: false,
            last_data_update: Instant::now(),
            last_known_dialog_count: 0,
            stream_detail_scroll: 0,
            stream_detail_return_view: None,
            filter_dialog: FilterDialogState::default(),
            settings_dialog: SettingsDialogState::default(),
            active_filter: None,
            active_filter_text: String::new(),
            status_error: None,
            call_flow_scroll: 0,
            raw_msg_scroll: 0,
            help_scroll: 0,
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
            open_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            open_entries: Vec::new(),
            open_selected: 0,
            open_filter: String::new(),
            open_manual_mode: false,
            open_error: None,
            name_mode: NameMode::default(),
            resolver: Arc::new(NameResolver::new()),
            names_save_path: None,
            names_config_path: None,
            name_dialog: NameDialogState::default(),
            sdp_display_mode: SdpDisplayMode::default(),
            timestamp_mode: TimestampMode::default(),
            color_mode: ColorMode::default(),
            from_to_mode: FromToMode::default(),
            raw_preview: true,
            raw_preview_pct: 40,
            selected_msg_index: 0,
            detail_scroll: 0,
            call_flow_detail_focused: false,
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
            #[cfg(feature = "audio")]
            audio_player: None,
            #[cfg(feature = "audio")]
            audio_init_error: None,
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
/// Name-resolution wiring passed into the TUI from CLI/config.
pub struct NameSetup {
    /// Shared resolver (already populated with hosts / manual mappings).
    pub resolver: Arc<NameResolver>,
    /// Initial name-resolution display mode.
    pub mode: NameMode,
    /// Where the TUI persists manual mappings edited via the `N` dialog.
    pub save_path: Option<PathBuf>,
    /// When `Some`, `N`-dialog edits are ALSO written into the `[names.manual]`
    /// table of this sipnabrc (opt-in via `[names] persist_to_config`).
    pub config_path: Option<PathBuf>,
}

impl Default for NameSetup {
    fn default() -> Self {
        Self {
            resolver: Arc::new(NameResolver::new()),
            mode: NameMode::Off,
            save_path: None,
            config_path: None,
        }
    }
}

pub fn run_tui(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
) -> Result<()> {
    run_tui_with_pause(
        dialog_store,
        stream_store,
        None,
        Theme::default(),
        Keymap::default(),
        None,
        NameSetup::default(),
        FromToMode::default(),
    )
}

/// Run the TUI with an optional shared pause flag.
///
/// When `paused_flag` is `Some`, the flag is shared with the processing
/// thread so that toggling pause in the TUI also pauses packet processing.
#[allow(clippy::too_many_arguments)]
pub fn run_tui_with_pause(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    paused_flag: Option<Arc<AtomicBool>>,
    theme: Theme,
    keymap: Keymap,
    visible_columns: Option<Vec<String>>,
    name_setup: NameSetup,
    from_to_mode: FromToMode,
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
    if let Some(ref cols) = visible_columns {
        app.call_list.apply_visible_columns(cols);
    }
    app.set_from_to_mode(from_to_mode);
    app.set_resolver(name_setup.resolver);
    app.set_name_mode(name_setup.mode);
    app.set_names_save_path(name_setup.save_path);
    app.set_names_config_path(name_setup.config_path);

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
        let mut app = Self::new(ds, ss, Theme::default(), Keymap::default());
        // Pin a deterministic version so help-view snapshots don't depend on
        // the build's git commit/tag/dirty state or the compiled feature set.
        app.version = "0.0.0-test".to_string();
        app
    }

    /// Override the version string shown in the help view (test helper).
    #[doc(hidden)]
    pub fn set_version_for_test(&mut self, version: impl Into<String>) {
        self.version = version.into();
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

    #[doc(hidden)]
    pub fn open_path_clear_for_test(&mut self) {
        self.open_path.clear();
        self.open_cursor = 0;
    }

    /// Set the filter-dialog SIP-method checkboxes and apply the filter, exactly
    /// as pressing Enter in the dialog would (test helper for set/unset scenarios).
    #[doc(hidden)]
    pub fn apply_method_filter_for_test(&mut self, methods: [bool; 10]) {
        self.filter_dialog.methods = methods;
        apply_filter_dialog(self);
    }

    /// Inspect the filter dialog's focused element and method-checkbox states
    /// (test helper for navigation/toggle scenarios).
    #[doc(hidden)]
    pub fn filter_focus_and_methods_for_test(&self) -> (usize, [bool; 10]) {
        (self.filter_dialog.focused_field, self.filter_dialog.methods)
    }

    #[doc(hidden)]
    pub fn set_open_dir_for_test(&mut self, dir: PathBuf) {
        self.open_dir = dir;
    }

    #[doc(hidden)]
    pub fn open_dir_for_test(&self) -> &std::path::Path {
        &self.open_dir
    }

    #[doc(hidden)]
    pub fn open_entry_names_for_test(&self) -> Vec<String> {
        self.open_entries.iter().map(|e| e.name.clone()).collect()
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

    /// Return the current From/To column display mode.
    pub fn from_to_mode(&self) -> FromToMode {
        self.from_to_mode
    }

    /// Set the From/To column display mode (used to apply the startup default
    /// from config/CLI).
    pub fn set_from_to_mode(&mut self, mode: FromToMode) {
        self.from_to_mode = mode;
    }

    /// Current name-resolution display mode.
    pub fn name_mode(&self) -> NameMode {
        self.name_mode
    }

    /// Set the name-resolution display mode.
    pub fn set_name_mode(&mut self, mode: NameMode) {
        self.name_mode = mode;
    }

    /// Shared name resolver (manual mappings, hosts file, reverse DNS).
    pub fn resolver(&self) -> &Arc<NameResolver> {
        &self.resolver
    }

    /// Inject the shared resolver (built from config/CLI in `run`).
    pub fn set_resolver(&mut self, resolver: Arc<NameResolver>) {
        self.resolver = resolver;
    }

    /// Where to persist manual name mappings when edited in the TUI.
    pub fn set_names_save_path(&mut self, path: Option<PathBuf>) {
        self.names_save_path = path;
    }

    /// When `Some`, `N`-dialog edits also persist into this sipnabrc's
    /// `[names.manual]` table.
    pub fn set_names_config_path(&mut self, path: Option<PathBuf>) {
        self.names_config_path = path;
    }

    /// Count dialogs visible after applying the active filter.
    pub fn visible_dialog_count(&self) -> usize {
        filtered_dialog_count(self)
    }

    /// Return the number of tracked RTP streams (exposed for integration tests).
    #[doc(hidden)]
    pub fn stream_count_for_test(&self) -> usize {
        self.stream_store.read().len()
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

    /// Dialogs that a call-list action (save, clear) applies to, in the
    /// order shown on screen: the checkbox-selected rows if any are checked,
    /// otherwise every displayed (filtered + searched) dialog.
    ///
    /// Borrows from the provided store guard. This mirrors what the user sees
    /// — selection indices are positions in the rendered, sorted list — so
    /// the same helper backs both rendering and these actions.
    pub(super) fn dialogs_to_export<'a>(
        &self,
        store: &'a DialogStore,
    ) -> Vec<&'a crate::sip::dialog::SipDialog> {
        let displayed = call_list::displayed_dialogs(
            store,
            self.active_filter.as_ref(),
            &self.search_query,
            self.call_list.sort_column(),
            self.call_list.sort_ascending(),
        );
        let selected = self.call_list.selected_rows();
        if selected.is_empty() {
            displayed
        } else {
            displayed
                .into_iter()
                .enumerate()
                .filter(|(i, _)| selected.contains(i))
                .map(|(_, d)| d)
                .collect()
        }
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

    /// Return the stream detail scroll offset.
    pub fn stream_detail_scroll(&self) -> usize {
        self.stream_detail_scroll
    }

    /// Override the save dialog path (for deterministic snapshot tests).
    pub fn set_save_path(&mut self, path: &str) {
        self.save_path = path.to_string();
        self.save_cursor = path.len();
    }

    /// Return a reference to the shared dialog store (for tests).
    pub fn dialog_store_ref(&self) -> &Arc<RwLock<DialogStore>> {
        &self.dialog_store
    }

    /// Render the full application frame into the given frame (for snapshot tests).
    pub fn render(&mut self, frame: &mut ratatui::Frame) {
        render_app(frame, self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F1 opens the help overlay, but nothing on a POPULATED call list
    /// said so (only the empty-state message did) — the f-key bar listed
    /// F2..F10 but never F1. Help must be advertised at every width.
    #[test]
    fn fkey_bar_advertises_help_on_call_list_at_all_widths() {
        for width in [60u16, 90, 120] {
            let items = fkey_bar_items(&View::CallList, &None, width);
            assert!(
                items.contains(&("F1", "Help")),
                "width {width}: F1 Help missing from f-key bar: {items:?}"
            );
        }
    }

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

    // ── SaveFormat round-trips ──────────────────────────────────────

    #[test]
    fn save_format_next_full_cycle() {
        // 11 formats — next() applied 11 times returns to start.
        let mut f = SaveFormat::Pcap;
        for _ in 0..11 {
            f = f.next();
        }
        assert_eq!(f, SaveFormat::Pcap);
    }

    #[test]
    fn save_format_prev_is_inverse_of_next() {
        let formats = [
            SaveFormat::Pcap,
            SaveFormat::PcapNg,
            SaveFormat::Txt,
            SaveFormat::Json,
            SaveFormat::Ndjson,
            SaveFormat::Csv,
            SaveFormat::Html,
            SaveFormat::Markdown,
            SaveFormat::Wav,
            SaveFormat::SippXml,
            SaveFormat::RtpJson,
        ];
        for &f in &formats {
            assert_eq!(f.next().prev(), f, "prev∘next != id for {f:?}");
            assert_eq!(f.prev().next(), f, "next∘prev != id for {f:?}");
        }
    }

    #[test]
    fn save_format_extension_label_category_description_nonempty() {
        let formats = [
            SaveFormat::Pcap,
            SaveFormat::PcapNg,
            SaveFormat::Txt,
            SaveFormat::Json,
            SaveFormat::Ndjson,
            SaveFormat::Csv,
            SaveFormat::Html,
            SaveFormat::Markdown,
            SaveFormat::Wav,
            SaveFormat::SippXml,
            SaveFormat::RtpJson,
        ];
        for &f in &formats {
            assert!(!f.extension().is_empty());
            assert!(!f.label().is_empty());
            assert!(!f.category().is_empty());
            assert!(!f.description().is_empty());
        }
        assert_eq!(SaveFormat::Pcap.extension(), "pcap");
        assert_eq!(SaveFormat::RtpJson.extension(), "rtp.json");
        assert_eq!(SaveFormat::Pcap.category(), "Packet Capture");
        assert_eq!(SaveFormat::Json.category(), "Structured/Analytics");
    }

    // ── Display-mode enum cycles ────────────────────────────────────

    #[test]
    fn sdp_display_mode_cycle_and_labels() {
        assert_eq!(SdpDisplayMode::None.next(), SdpDisplayMode::Summary);
        assert_eq!(SdpDisplayMode::Summary.next(), SdpDisplayMode::Full);
        assert_eq!(SdpDisplayMode::Full.next(), SdpDisplayMode::None);
        assert!(SdpDisplayMode::None.label().contains("SDP"));
        assert!(SdpDisplayMode::Summary.label().contains("Summary"));
        assert!(SdpDisplayMode::Full.label().contains("Full"));
    }

    #[test]
    fn timestamp_mode_cycle_and_labels() {
        assert_eq!(TimestampMode::Absolute.next(), TimestampMode::DeltaPrev);
        assert_eq!(TimestampMode::DeltaPrev.next(), TimestampMode::DeltaFirst);
        assert_eq!(TimestampMode::DeltaFirst.next(), TimestampMode::Scaled);
        assert_eq!(TimestampMode::Scaled.next(), TimestampMode::Absolute);
        for m in [
            TimestampMode::Absolute,
            TimestampMode::DeltaPrev,
            TimestampMode::DeltaFirst,
            TimestampMode::Scaled,
        ] {
            assert!(m.label().contains("Time"));
        }
    }

    #[test]
    fn color_mode_cycle_and_labels() {
        assert_eq!(ColorMode::Method.next(), ColorMode::CallId);
        assert_eq!(ColorMode::CallId.next(), ColorMode::CSeq);
        assert_eq!(ColorMode::CSeq.next(), ColorMode::Method);
        for m in [ColorMode::Method, ColorMode::CallId, ColorMode::CSeq] {
            assert!(m.label().contains("Color"));
        }
    }

    // ── FilterDialogState navigation & build ────────────────────────

    #[test]
    fn filter_dialog_text_field_accessors() {
        let mut st = FilterDialogState {
            sip_from: "a".to_string(),
            sip_to: "b".to_string(),
            source: "c".to_string(),
            destination: "d".to_string(),
            payload: "e".to_string(),
            ..Default::default()
        };
        assert_eq!(st.text_field(0), "a");
        assert_eq!(st.text_field(1), "b");
        assert_eq!(st.text_field(2), "c");
        assert_eq!(st.text_field(3), "d");
        assert_eq!(st.text_field(4), "e");
        assert_eq!(st.text_field(99), "");
        // mutable accessor
        if let Some(s) = st.text_field_mut(0) {
            s.push('z');
        }
        assert_eq!(st.text_field(0), "az");
        assert!(st.text_field_mut(99).is_none());
    }

    #[test]
    fn filter_dialog_focus_wraps_both_directions() {
        let mut st = FilterDialogState::default();
        assert_eq!(st.focused_field(), 0);
        st.focus_prev(); // wrap to last
        assert_eq!(st.focused_field(), FILTER_ITEM_COUNT - 1);
        st.focus_next(); // wrap back to 0
        assert_eq!(st.focused_field(), 0);
    }

    #[test]
    fn filter_dialog_focus_classification() {
        let mut st = FilterDialogState {
            focused_field: 0,
            ..Default::default()
        };
        // text fields 0..5
        assert!(st.is_text_field_focused());
        assert!(!st.is_checkbox_focused());
        assert!(st.checkbox_index().is_none());
        // checkbox region
        st.focused_field = FILTER_TEXT_FIELD_COUNT; // first checkbox
        assert!(st.is_checkbox_focused());
        assert_eq!(st.checkbox_index(), Some(0));
        // button region
        st.focused_field = FILTER_BUTTON_IDX;
        assert!(!st.is_text_field_focused());
        assert!(!st.is_checkbox_focused());
    }

    #[test]
    fn filter_dialog_checkbox_grid_navigation() {
        let mut st = FilterDialogState {
            focused_field: FILTER_TEXT_FIELD_COUNT,
            ..Default::default()
        };
        // Focus first checkbox (index 0).
        st.checkbox_right(); // 0 -> 1
        assert_eq!(st.checkbox_index(), Some(1));
        st.checkbox_left(); // 1 -> 0
        assert_eq!(st.checkbox_index(), Some(0));
        st.checkbox_down(); // 0 -> 2
        assert_eq!(st.checkbox_index(), Some(2));
        st.checkbox_up(); // 2 -> 0
        assert_eq!(st.checkbox_index(), Some(0));
        // Up from top row → moves to last text field.
        st.checkbox_up();
        assert!(st.is_text_field_focused());
        assert_eq!(st.focused_field(), FILTER_TEXT_FIELD_COUNT - 1);
    }

    #[test]
    fn filter_dialog_checkbox_down_traverses_both_columns_then_buttons() {
        // Down walks the LEFT column to its bottom, then continues into the
        // RIGHT column, then to the buttons — so the right column is reachable
        // by vertical navigation.
        let mut st = FilterDialogState {
            focused_field: FILTER_TEXT_FIELD_COUNT + 8, // INFO (left col bottom, idx 8)
            ..Default::default()
        };
        st.checkbox_down(); // -> top of RIGHT column (OPTIONS, idx 1)
        assert_eq!(st.checkbox_index(), Some(1));
        st.checkbox_down(); // idx 1 -> 3
        st.checkbox_down(); // 3 -> 5
        st.checkbox_down(); // 5 -> 7
        st.checkbox_down(); // 7 -> 9 (UPDATE, right col bottom)
        assert_eq!(st.checkbox_index(), Some(9));
        st.checkbox_down(); // bottom of RIGHT column -> buttons
        assert_eq!(st.focused_field(), FILTER_BUTTON_IDX);

        // Up reverses: from OPTIONS (idx 1) back to INFO (idx 8).
        let mut st = FilterDialogState {
            focused_field: FILTER_TEXT_FIELD_COUNT + 1,
            ..Default::default()
        };
        st.checkbox_up();
        assert_eq!(st.checkbox_index(), Some(8));
    }

    #[test]
    fn filter_dialog_default_all_methods_checked() {
        // SIP messages must be checked by default → no narrowing → no expression.
        let st = FilterDialogState::default();
        assert!(
            st.methods.iter().all(|&v| v),
            "all methods should default to checked"
        );
        assert!(st.any_method_checked());
        assert!(
            st.is_empty(),
            "all-checked + empty text == no active filter"
        );
        assert!(st.build_filter_expression().is_none());
    }

    #[test]
    fn filter_dialog_clear_resets_to_all_checked() {
        let mut st = FilterDialogState {
            methods: [false; 10],
            sip_from: "x".to_string(),
            ..Default::default()
        };
        st.clear();
        assert!(
            st.methods.iter().all(|&v| v),
            "clear() must re-check all methods (show all)"
        );
        assert!(st.is_empty());
    }

    #[test]
    fn filter_dialog_any_method_checked_tracks_state() {
        let mut st = FilterDialogState::default();
        assert!(st.any_method_checked());
        st.methods = [false; 10];
        assert!(
            !st.any_method_checked(),
            "no methods checked → show nothing"
        );
        st.methods[3] = true;
        assert!(st.any_method_checked());
    }

    #[test]
    fn filter_dialog_uncheck_one_excludes_that_method() {
        // From the all-checked default, unchecking INVITE (index 2) must produce
        // a method filter over the OTHER nine and exclude INVITE.
        let mut st = FilterDialogState {
            focused_field: FILTER_TEXT_FIELD_COUNT + 2, // INVITE
            ..Default::default()
        };
        st.toggle_checkbox();
        assert!(!st.methods[2], "INVITE now unchecked");
        let expr = st
            .build_filter_expression()
            .expect("partial selection → expression");
        assert!(
            !expr.contains("'INVITE'"),
            "unchecked INVITE must be excluded: {expr}"
        );
        assert!(expr.contains("method == 'REGISTER'"));
        assert!(expr.contains(" OR "));

        // Text fields AND-join with the method clause.
        st.sip_from = "1001".to_string();
        st.source = "10.0.0.1".to_string();
        let expr = st.build_filter_expression().unwrap();
        assert!(expr.contains("from.user") && expr.contains("src.ip") && expr.contains(" AND "));
    }

    #[test]
    fn filter_dialog_all_methods_checked_yields_no_method_filter() {
        let st = FilterDialogState {
            methods: [true; 10],
            ..Default::default()
        };
        // All checked → method filter omitted; with no text fields → None.
        assert!(st.build_filter_expression().is_none());
    }

    #[test]
    fn filter_dialog_clear_resets_everything() {
        let mut st = FilterDialogState {
            sip_from: "x".to_string(),
            sip_to: "y".to_string(),
            ..Default::default()
        };
        st.methods[0] = true;
        st.focused_field = 7;
        st.cursor_pos = 3;
        st.clear();
        assert!(st.is_empty());
        assert_eq!(st.focused_field(), 0);
        assert_eq!(st.cursor_pos, 0);
    }

    #[test]
    fn filter_dialog_sync_cursor_to_field_end() {
        let mut st = FilterDialogState {
            sip_to: "hello".to_string(),
            focused_field: 1, // SIP To
            cursor_pos: 0,
            ..Default::default()
        };
        st.sync_cursor();
        assert_eq!(st.cursor_pos, 5);
    }

    // ── FromToMode ───────────────────────────────────────────────────

    #[test]
    fn from_to_mode_default_prefers_user_then_host() {
        let m = FromToMode::Default;
        assert_eq!(m.format(Some("1001"), Some("h:5060")), "1001");
        assert_eq!(m.format(None, Some("h:5060")), "h:5060");
        assert_eq!(m.format(None, None), "-");
    }

    #[test]
    fn from_to_mode_host_port_only() {
        let m = FromToMode::HostPort;
        assert_eq!(m.format(Some("1001"), Some("h:5060")), "h:5060");
        assert_eq!(
            m.format(Some("1001"), None),
            "-",
            "host mode ignores the user"
        );
    }

    #[test]
    fn from_to_mode_user_only_is_legacy_behavior() {
        let m = FromToMode::User;
        assert_eq!(m.format(Some("1001"), Some("h")), "1001");
        assert_eq!(
            m.format(None, Some("h")),
            "-",
            "user mode shows '-' when no user"
        );
    }

    #[test]
    fn from_to_mode_user_host_combines() {
        let m = FromToMode::UserHostPort;
        assert_eq!(m.format(Some("1001"), Some("h:5060")), "1001@h:5060");
        assert_eq!(m.format(Some("1001"), None), "1001");
        assert_eq!(m.format(None, Some("h:5060")), "h:5060");
        assert_eq!(m.format(None, None), "-");
    }

    #[test]
    fn from_to_mode_cycle_is_four_states() {
        let m = FromToMode::default();
        assert_eq!(m, FromToMode::Default);
        assert_eq!(m.next(), FromToMode::HostPort);
        assert_eq!(m.next().next(), FromToMode::User);
        assert_eq!(m.next().next().next(), FromToMode::UserHostPort);
        assert_eq!(
            m.next().next().next().next(),
            FromToMode::Default,
            "cycles back to Default"
        );
    }

    #[test]
    fn from_to_mode_parse_roundtrip_and_invalid() {
        for m in [
            FromToMode::Default,
            FromToMode::HostPort,
            FromToMode::User,
            FromToMode::UserHostPort,
        ] {
            assert_eq!(FromToMode::parse(m.as_config_str()), Some(m));
        }
        assert_eq!(FromToMode::parse("bogus"), None);
        assert_eq!(FromToMode::parse(""), None);
    }

    // ── App state setters ───────────────────────────────────────────

    #[test]
    fn app_set_capture_mode_and_bpf_filter() {
        let mut app = App::new_test();
        app.set_capture_mode("Offline (cap.pcap)".to_string());
        assert_eq!(app.capture_mode, "Offline (cap.pcap)");
        app.set_bpf_filter("udp port 5060".to_string());
        assert_eq!(app.bpf_filter, "udp port 5060");
    }

    #[test]
    fn app_mark_data_updated_resets_to_active() {
        let mut app = App::new_test();
        app.last_data_update = Instant::now() - Duration::from_secs(10);
        assert!(app.poll_timeout() >= Duration::from_millis(IDLE_POLL_MS));
        app.mark_data_updated();
        assert!(app.poll_timeout() <= Duration::from_millis(ACTIVE_POLL_MS));
    }

    #[test]
    fn app_is_paused_reflects_flag() {
        let mut app = App::new_test();
        assert!(!app.is_paused());
        app.paused = true;
        assert!(app.is_paused());
    }
}
