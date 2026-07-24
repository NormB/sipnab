// SPDX-License-Identifier: MIT OR Apache-2.0

//! Plain state types for the TUI: display-mode enums, save formats,
//! the per-dialog/popup state structs and the View/Popup enums.
//! [`crate::tui::App`] composes these; the controllers mutate them.

use crate::tui::*;

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
    pub(in crate::tui) fn next(self) -> Self {
        match self {
            Self::None => Self::Summary,
            Self::Summary => Self::Full,
            Self::Full => Self::None,
        }
    }

    /// Human-readable label for the status bar.
    pub(in crate::tui) fn label(self) -> &'static str {
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
    /// Cycle to the next mode.
    pub(in crate::tui) fn next(self) -> Self {
        match self {
            Self::Absolute => Self::DeltaPrev,
            Self::DeltaPrev => Self::DeltaFirst,
            Self::DeltaFirst => Self::Scaled,
            Self::Scaled => Self::Absolute,
        }
    }

    /// Human-readable label for the status bar.
    pub(in crate::tui) fn label(self) -> &'static str {
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
    /// Cycle to the next mode.
    pub(in crate::tui) fn next(self) -> Self {
        match self {
            Self::Method => Self::CallId,
            Self::CallId => Self::CSeq,
            Self::CSeq => Self::Method,
        }
    }

    /// Human-readable label for the status bar.
    pub(in crate::tui) fn label(self) -> &'static str {
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
    /// Username if present, else `host[:port]` (else `-`).
    #[default]
    Default,
    /// `Host[:port]` only (else `-`).
    HostPort,
    /// Username only (else `-`) — the legacy behavior.
    User,
    /// `user@host:port` when both exist, else whichever exists (else `-`).
    UserHostPort,
}

impl FromToMode {
    /// Cycle to the next mode.
    pub(in crate::tui) fn next(self) -> Self {
        match self {
            Self::Default => Self::HostPort,
            Self::HostPort => Self::User,
            Self::User => Self::UserHostPort,
            Self::UserHostPort => Self::Default,
        }
    }

    /// Human-readable label for the status bar.
    pub(in crate::tui) fn label(self) -> &'static str {
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
    pub(in crate::tui) fn format(self, user: Option<&str>, host: Option<&str>) -> String {
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

// ── Session wiring passed in from CLI/config ────────────────────────

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
    /// Empty wiring: a fresh resolver, name display off, no persistence
    /// paths.
    fn default() -> Self {
        Self {
            resolver: Arc::new(NameResolver::new()),
            mode: NameMode::Off,
            save_path: None,
            config_path: None,
        }
    }
}

/// Presentation and naming options for a TUI session, resolved from
/// config/CLI by the caller.
#[derive(Default)]
pub struct TuiOptions {
    /// Resolved color theme.
    pub theme: Theme,
    /// Resolved key bindings.
    pub keymap: Keymap,
    /// Call-list columns to show (config `[display] visible_columns`).
    pub visible_columns: Option<Vec<String>>,
    /// Name-resolution wiring (resolver, mode, persistence paths).
    pub name_setup: NameSetup,
    /// Initial From/To column display mode.
    pub from_to_mode: FromToMode,
}

/// A single entry in the file-open browser's directory listing.
#[derive(Debug, Clone)]
pub(in crate::tui) struct FileEntry {
    /// File name (no path) — what the user sees in the list.
    pub(in crate::tui) name: String,
    /// Absolute path — what we pass to `load_pcap_file` or `cd` into.
    pub(in crate::tui) path: PathBuf,
    /// Whether this entry is a directory.
    pub(in crate::tui) is_dir: bool,
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
pub(in crate::tui) const FILTER_METHODS: [&str; 10] = [
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
pub(in crate::tui) const FILTER_TEXT_FIELD_COUNT: usize = 5;

/// Total focusable items: 5 text fields + 10 method checkboxes + the
/// "All" master checkbox + 2 buttons.
pub(in crate::tui) const FILTER_ITEM_COUNT: usize =
    FILTER_TEXT_FIELD_COUNT + FILTER_METHODS.len() + 3;

/// Focus index of the "All" master checkbox (enable/disable every method
/// at once), right after the text fields and ABOVE the method grid — it
/// governs the methods, so it reads and tabs first.
pub(in crate::tui) const ALL_METHODS_IDX: usize = FILTER_TEXT_FIELD_COUNT;
/// Focus index of the FIRST per-method checkbox (REGISTER).
pub(in crate::tui) const METHOD_CHECKBOX_BASE: usize = ALL_METHODS_IDX + 1;
/// Index of the "Filter" button in focused_field.
pub(in crate::tui) const FILTER_BUTTON_IDX: usize = METHOD_CHECKBOX_BASE + FILTER_METHODS.len();
/// Index of the "Cancel" button in focused_field.
pub(in crate::tui) const CANCEL_BUTTON_IDX: usize = FILTER_BUTTON_IDX + 1;

/// Number of rows in the settings popup.
pub(in crate::tui) const SETTINGS_ITEM_COUNT: usize = 6;

/// Structured state for the settings popup dialog.
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct SettingsDialogState {
    /// Currently highlighted row (0-based).
    pub(in crate::tui) focused_item: usize,
}

/// One endpoint offered for naming in the "Name Address" popup.
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct NameTarget {
    /// The IP being named (display + resolution key).
    pub(in crate::tui) ip: String,
    /// Editable name text for this IP.
    pub(in crate::tui) name: String,
}

/// State for the "Name Address" popup (map IPs to host/FQDN names).
///
/// Holds every endpoint the current view exposes — a call's participants, or a
/// stream's two ends — so the user can `Tab`/`Shift-Tab` between them and edit
/// any one's name, not just the first. Each target keeps its own edited text;
/// `Enter` applies them all.
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct NameDialogState {
    /// Endpoints available to name, in display order.
    pub(in crate::tui) targets: Vec<NameTarget>,
    /// Index of the endpoint currently being edited.
    pub(in crate::tui) active: usize,
    /// Cursor position within the active target's name.
    pub(in crate::tui) cursor: usize,
    /// Validation error shown inline; while set, Enter keeps the popup
    /// open so the typed name can be corrected instead of being discarded.
    pub(in crate::tui) error: Option<String>,
}

/// State for the F2 save dialog popup.
///
/// Kept on [`App`] (not inside the popup variant) so the edited path and
/// chosen format survive closing and reopening the dialog.
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct SaveDialogState {
    /// File path input.
    pub(in crate::tui) path: String,
    /// Cursor position within the path string.
    pub(in crate::tui) cursor: usize,
    /// Cached total dialog count for the dialog display.
    pub(in crate::tui) dialog_count: usize,
    /// Cached selected dialog count for the dialog display.
    pub(in crate::tui) selected_count: usize,
    /// Cached total message count for the dialog display.
    pub(in crate::tui) message_count: usize,
    /// Selected save format (PCAP, PCAP-NG, TXT, ...).
    pub(in crate::tui) format: SaveFormat,
}

/// State for the file-open dialog (browser + manual path entry).
///
/// Kept on [`App`] so the last-browsed directory is the starting point the
/// next time the dialog opens.
#[derive(Debug, Clone)]
pub(in crate::tui) struct FileOpenState {
    /// Path being edited (used only in manual-path mode).
    pub(in crate::tui) path: String,
    /// Cursor position in the manual path.
    pub(in crate::tui) cursor: usize,
    /// Current directory being browsed.
    pub(in crate::tui) dir: PathBuf,
    /// Entries in the current directory (dirs first, then pcaps).
    pub(in crate::tui) entries: Vec<FileEntry>,
    /// Selected row in the entries list.
    pub(in crate::tui) selected: usize,
    /// Typed filter substring (narrows the entries list).
    pub(in crate::tui) filter: String,
    /// Manual-path edit mode (Tab toggles).
    pub(in crate::tui) manual_mode: bool,
    /// Error from the last directory read (e.g. permission denied after a
    /// privilege drop), shown in the browser instead of a blank list.
    /// `None` when the directory was read successfully.
    pub(in crate::tui) error: Option<String>,
}

impl Default for FileOpenState {
    /// Browser mode starting in the process's current directory (falling
    /// back to `/`), with empty path, filter and entries.
    fn default() -> Self {
        Self {
            path: String::new(),
            cursor: 0,
            dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            entries: Vec::new(),
            selected: 0,
            filter: String::new(),
            manual_mode: false,
            error: None,
        }
    }
}

/// Per-view state for the call flow ladder: selection, scrolling, display
/// toggles and the render-time caches that map visible rows back to raw
/// message indices.
#[derive(Debug, Clone)]
pub(in crate::tui) struct CallFlowViewState {
    /// Scroll offset for the ladder.
    pub(in crate::tui) scroll: usize,
    /// Index of the currently selected message in the ladder.
    pub(in crate::tui) selected: usize,
    /// Scroll offset for the detail (right) panel in split view.
    pub(in crate::tui) detail_scroll: u16,
    /// Line-wrap mode for the detail panel: `true` wraps long header lines
    /// at the pane width, `false` truncates them and lets ←/→ scroll
    /// horizontally (an h-scrollbar appears when lines overflow). Toggled
    /// with `w`; toggling resets [`Self::detail_hscroll`].
    pub(in crate::tui) detail_wrap: bool,
    /// Horizontal scroll offset (display columns) for the detail panel,
    /// only active while [`Self::detail_wrap`] is off.
    pub(in crate::tui) detail_hscroll: u16,
    /// In the split view, whether keyboard focus is on the detail (right)
    /// pane. `false` = ladder (left). Toggled with Tab. Only meaningful while
    /// [`Self::raw_preview`] is on; navigation keys act on the focused pane.
    pub(in crate::tui) detail_focused: bool,
    /// Whether the raw preview split is active.
    /// Default is `true` (matching sngrep: split view on by default).
    pub(in crate::tui) raw_preview: bool,
    /// Split percentage for the raw preview (right) pane (10..=80, default 40).
    pub(in crate::tui) raw_preview_pct: u16,
    /// Whether extended (multi-leg) flow is active.
    pub(in crate::tui) extended: bool,
    /// Call-IDs of the checkbox-selected dialogs this flow merges, in
    /// display order (Enter on a multi-selection). Empty = classic
    /// single-dialog flow of the view's anchor Call-ID.
    pub(in crate::tui) merged_calls: Vec<String>,
    /// When set, the ladder is filtered to a single transaction — the CSeq
    /// grouping key (number + method) anchored when the filter was toggled
    /// on. `None` shows the whole dialog. See [`call_flow::transaction_key`].
    pub(in crate::tui) transaction_filter: Option<(u32, String)>,
    /// Whether RTP stream info is displayed in the flow.
    pub(in crate::tui) show_rtp: bool,
    /// First selected message for diff comparison (Space key): the dialog
    /// it lives in and its index there (merged flows interleave dialogs).
    pub(in crate::tui) diff_selected: Option<(String, usize)>,
    /// Marked message index for delta measurement (set with 'm').
    pub(in crate::tui) mark_index: Option<usize>,
    /// Set of message indices where folds are expanded ('e' toggles).
    pub(in crate::tui) fold_expanded: HashSet<usize>,
    /// Cached rendered message count (after folding).
    pub(in crate::tui) cached_msg_count: usize,
    /// Indices of FormattedMessages that carry an RTP bar (Enter drill-down).
    pub(in crate::tui) cached_rtp_bar_indices: std::collections::HashSet<usize>,
    /// Per visible ladder row, the raw message index it renders (`None` for
    /// RTP bars). Updated on every render; maps [`Self::selected`] (a
    /// visible-row position) back to the underlying message for the detail
    /// pane, Enter, diff selection and fold expansion.
    pub(in crate::tui) cached_raw_indices: Vec<Option<usize>>,
    /// Cross-tick ladder layout cache (WS4.3c), refreshed by
    /// `App::sync_caches`; the render pass only re-styles it.
    pub(in crate::tui) ladder: LadderCache,
}

impl Default for CallFlowViewState {
    /// Top of the ladder, split raw-preview on at 40%, wrap on, all
    /// toggles/marks/caches cleared.
    fn default() -> Self {
        Self {
            scroll: 0,
            selected: 0,
            detail_scroll: 0,
            detail_wrap: true,
            detail_hscroll: 0,
            detail_focused: false,
            raw_preview: true,
            raw_preview_pct: 40,
            extended: false,
            merged_calls: Vec::new(),
            transaction_filter: None,
            show_rtp: false,
            diff_selected: None,
            mark_index: None,
            fold_expanded: HashSet::new(),
            cached_msg_count: 0,
            cached_rtp_bar_indices: std::collections::HashSet::new(),
            cached_raw_indices: Vec::new(),
            ladder: LadderCache::default(),
        }
    }
}

/// Which dialog-store state a cached ladder layout was derived from.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::tui) enum LadderSource {
    /// Single-dialog view: the dialog's `(messages.len, updated_at)`
    /// fingerprint — traffic on unrelated dialogs keeps the cache warm.
    Dialog(usize, chrono::DateTime<chrono::Utc>),
    /// Extended (multi-leg) view: the whole-store generation, since
    /// correlated legs can appear anywhere. `find_correlated` and the
    /// merge+sort of leg messages therefore run only on a layout miss.
    ExtendedStore(u64),
}

/// Key identifying one exact ladder-layout derivation: if every field
/// matches, the cached participants/rows are still valid and only the
/// style stage needs to run. Style-only inputs (theme, color mode,
/// selection) are deliberately absent.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::tui) struct LadderKey {
    /// Anchor dialog's Call-ID (the view's subject).
    pub(in crate::tui) call_id: String,
    /// Store-state fingerprint the layout was derived from.
    pub(in crate::tui) source: LadderSource,
    /// Active single-transaction filter, if any.
    pub(in crate::tui) transaction_filter: Option<(u32, String)>,
    /// SDP display mode (changes row content/heights).
    pub(in crate::tui) sdp_mode: SdpDisplayMode,
    /// Timestamp display mode (Scaled inserts spacer rows).
    pub(in crate::tui) ts_mode: TimestampMode,
    /// Whether RTP bars are laid out between messages.
    pub(in crate::tui) show_rtp: bool,
    /// Name-resolution mode (changes participant labels).
    pub(in crate::tui) name_mode: crate::names::NameMode,
    /// [`crate::names::NameResolver::generation`] — participant labels.
    pub(in crate::tui) resolver_generation: u64,
    /// [`crate::rtp::stream_store::StreamStore::generation`] when RTP
    /// segments feed the layout (plain view with RTP bars on) — `None`
    /// when they don't (extended view, or bars off).
    pub(in crate::tui) stream_generation: Option<u64>,
    /// Message indices whose retransmit folds are expanded.
    pub(in crate::tui) fold_expanded: HashSet<usize>,
    /// Checked dialogs a multi-selection flow merges (display order);
    /// empty for the classic single-dialog ladder.
    pub(in crate::tui) merged_calls: Vec<String>,
}

/// Cross-tick cache of the laid-out ladder (the theme-free, expensive half
/// of a prepared call flow): derived at most once per tick by
/// `App::sync_caches` and reused across ticks while [`LadderKey`] matches;
/// the render pass re-runs only the cheap style stage over it.
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct LadderCache {
    /// Key the cached layout was derived under; `None` until first derivation.
    pub(in crate::tui) key: Option<LadderKey>,
    /// Laid-out participant columns (endpoints), in display order.
    pub(in crate::tui) participants: Vec<call_flow::Participant>,
    /// Laid-out ladder rows (messages, SDP detail, RTP bars, spacers).
    pub(in crate::tui) rows: Vec<call_flow::LayoutRow>,
    /// Cached RTP codec segments for `segs_key`'s dialog — the layout
    /// input recomputed only when the stream store structurally changes.
    /// (A segment's `end` may lag behind live packets; nothing reads it.)
    pub(in crate::tui) rtp_segs: Vec<call_flow::RtpCodecSegment>,
    /// `(call_id, stream-store generation)` the segments were derived at.
    pub(in crate::tui) segs_key: Option<(String, u64)>,
    /// Per position in the laid-out message slice: which dialog the
    /// message belongs to and its index within THAT dialog's messages.
    /// Filled for merged/extended ladders (their slice interleaves several
    /// dialogs); empty for single-dialog ladders, where the position IS
    /// the index into the anchor dialog.
    pub(in crate::tui) index_map: Vec<(String, usize)>,
    /// Floors churn-driven relayouts: store/stream generation advances
    /// are adopted at most once per floor while every other key change
    /// (user input, dialog's own messages) still relays out immediately.
    pub(in crate::tui) churn: ChurnFloor,
}

impl NameDialogState {
    /// IP string of the active target (empty if none).
    pub(in crate::tui) fn active_ip(&self) -> &str {
        self.targets.get(self.active).map_or("", |t| t.ip.as_str())
    }

    /// Editable name of the active target (empty if none).
    pub(in crate::tui) fn active_name(&self) -> &str {
        self.targets
            .get(self.active)
            .map_or("", |t| t.name.as_str())
    }

    /// Mutable handle to the active target's name, if any.
    pub(in crate::tui) fn active_name_mut(&mut self) -> Option<&mut String> {
        let a = self.active;
        self.targets.get_mut(a).map(|t| &mut t.name)
    }

    /// Move the active target to the next endpoint (wraps), placing the cursor
    /// at the end of its current name.
    pub(in crate::tui) fn focus_next(&mut self) {
        if !self.targets.is_empty() {
            self.active = (self.active + 1) % self.targets.len();
            self.cursor = self.active_name().len();
        }
    }

    /// Move the active target to the previous endpoint (wraps).
    pub(in crate::tui) fn focus_prev(&mut self) {
        if !self.targets.is_empty() {
            self.active = (self.active + self.targets.len() - 1) % self.targets.len();
            self.cursor = self.active_name().len();
        }
    }
}

/// Structured state for the sngrep-style filter dialog.
#[derive(Debug, Clone)]
pub struct FilterDialogState {
    /// SIP From header filter text.
    pub(in crate::tui) sip_from: String,
    /// SIP To header filter text.
    pub(in crate::tui) sip_to: String,
    /// Source IP/port filter text.
    pub(in crate::tui) source: String,
    /// Destination IP/port filter text.
    pub(in crate::tui) destination: String,
    /// Payload content filter text.
    pub(in crate::tui) payload: String,
    /// Method checkbox states, indexed by position in FILTER_METHODS.
    pub(in crate::tui) methods: [bool; 10],
    /// Currently focused UI element index.
    /// 0-4 = text fields, 5 = "All" master checkbox, 6-15 = method
    /// checkboxes, 16 = Filter button, 17 = Cancel button.
    pub(in crate::tui) focused_field: usize,
    /// Cursor position within the currently focused text field.
    pub(in crate::tui) cursor_pos: usize,
    /// Parse error shown inline; while set, Enter keeps the dialog open so
    /// the typed values can be corrected instead of being discarded.
    pub(in crate::tui) error: Option<String>,
}

impl Default for FilterDialogState {
    /// Empty text fields, every method checked (show all), focus on the
    /// first field, no error.
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
            error: None,
        }
    }
}

impl FilterDialogState {
    /// Whether at least one SIP method checkbox is checked. When none are
    /// checked the call list shows nothing (see `apply_filter_dialog`).
    pub(in crate::tui) fn any_method_checked(&self) -> bool {
        self.methods.iter().any(|&v| v)
    }

    /// Whether every SIP method checkbox is checked — the "All" master
    /// checkbox renders checked exactly then.
    pub(in crate::tui) fn all_methods_checked(&self) -> bool {
        self.methods.iter().all(|&v| v)
    }

    /// The "All" master checkbox: from a fully-checked state it disables
    /// every method; from any other state it enables every method first.
    pub(in crate::tui) fn toggle_all_methods(&mut self) {
        let target = !self.all_methods_checked();
        self.methods = [target; 10];
    }

    /// Get a reference to the text field at the given index (0-4).
    pub(in crate::tui) fn text_field(&self, idx: usize) -> &str {
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
    pub(in crate::tui) fn text_field_mut(&mut self, idx: usize) -> Option<&mut String> {
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
    pub(in crate::tui) fn is_text_field_focused(&self) -> bool {
        self.focused_field < FILTER_TEXT_FIELD_COUNT
    }

    /// Whether the currently focused element is a checkbox.
    pub(in crate::tui) fn is_checkbox_focused(&self) -> bool {
        self.focused_field >= FILTER_TEXT_FIELD_COUNT && self.focused_field < FILTER_BUTTON_IDX
    }

    /// Get the METHOD checkbox index (0-9) for the currently focused
    /// element; the "All" master checkbox is not a method slot.
    pub(in crate::tui) fn checkbox_index(&self) -> Option<usize> {
        if self.is_checkbox_focused() && self.focused_field != ALL_METHODS_IDX {
            Some(self.focused_field - METHOD_CHECKBOX_BASE)
        } else {
            None
        }
    }

    /// Move focus to the next element.
    pub(in crate::tui) fn focus_next(&mut self) {
        if self.focused_field + 1 < FILTER_ITEM_COUNT {
            self.focused_field += 1;
        } else {
            self.focused_field = 0;
        }
        self.sync_cursor();
    }

    /// Move focus to the previous element.
    pub(in crate::tui) fn focus_prev(&mut self) {
        if self.focused_field > 0 {
            self.focused_field -= 1;
        } else {
            self.focused_field = FILTER_ITEM_COUNT - 1;
        }
        self.sync_cursor();
    }

    /// Sync cursor position to end of the newly focused text field.
    pub(in crate::tui) fn sync_cursor(&mut self) {
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
    pub(in crate::tui) fn checkbox_down(&mut self) {
        if self.focused_field == ALL_METHODS_IDX {
            // "All" row (above the grid) -> first method (REGISTER).
            self.focused_field = METHOD_CHECKBOX_BASE;
            return;
        }
        if let Some(idx) = self.checkbox_index() {
            let next = idx + 2;
            if next < FILTER_METHODS.len() {
                // Same column, one row down.
                self.focused_field = METHOD_CHECKBOX_BASE + next;
            } else if idx % 2 == 0 {
                // Bottom of the LEFT column -> top of the RIGHT column.
                self.focused_field = METHOD_CHECKBOX_BASE + 1;
            } else {
                // Bottom of the RIGHT column -> the buttons row.
                self.focused_field = FILTER_BUTTON_IDX;
            }
        }
    }

    /// Move checkbox focus up one row (reverse of [`Self::checkbox_down`]).
    pub(in crate::tui) fn checkbox_up(&mut self) {
        if self.focused_field == ALL_METHODS_IDX {
            // "All" row (above the grid) -> last text field.
            self.focused_field = FILTER_TEXT_FIELD_COUNT - 1;
            self.sync_cursor();
            return;
        }
        if let Some(idx) = self.checkbox_index() {
            if idx >= 2 {
                // Same column, one row up.
                self.focused_field = METHOD_CHECKBOX_BASE + (idx - 2);
            } else if idx == 1 {
                // Top of the RIGHT column -> bottom of the LEFT column.
                self.focused_field = METHOD_CHECKBOX_BASE + (FILTER_METHODS.len() - 2);
            } else {
                // Top of the LEFT column (REGISTER) -> the "All" row.
                self.focused_field = ALL_METHODS_IDX;
            }
        }
    }

    /// Move checkbox focus right one column (same row).
    pub(in crate::tui) fn checkbox_right(&mut self) {
        if let Some(idx) = self.checkbox_index()
            && idx % 2 == 0
            && idx + 1 < FILTER_METHODS.len()
        {
            self.focused_field = METHOD_CHECKBOX_BASE + idx + 1;
        }
    }

    /// Move checkbox focus left one column (same row).
    pub(in crate::tui) fn checkbox_left(&mut self) {
        if let Some(idx) = self.checkbox_index()
            && idx % 2 == 1
        {
            self.focused_field = METHOD_CHECKBOX_BASE + idx - 1;
        }
    }

    /// Toggle the currently focused checkbox ("All" toggles every method).
    pub(in crate::tui) fn toggle_checkbox(&mut self) {
        if self.focused_field == ALL_METHODS_IDX {
            self.toggle_all_methods();
        } else if let Some(idx) = self.checkbox_index() {
            self.methods[idx] = !self.methods[idx];
        }
    }

    /// Build a DSL filter expression from the current dialog state.
    /// Returns `None` if all fields are empty and no methods are checked.
    ///
    /// Field text is matched as a LITERAL substring: it is regex-escaped
    /// before being embedded, so `a+b` means the user a+b and an unbalanced
    /// `(` can never produce a parse error.
    pub(in crate::tui) fn build_filter_expression(&self) -> Option<String> {
        /// Regex-escape user text for embedding in a DSL string literal.
        /// The DSL string literal has no escape sequences, so a literal quote
        /// is smuggled through as the regex byte escape \x27 / \x22.
        fn escape_filter_text(s: &str) -> String {
            regex::escape(s)
                .replace('\'', "\\x27")
                .replace('"', "\\x22")
        }
        let mut parts: Vec<String> = Vec::new();

        if !self.sip_from.is_empty() {
            parts.push(format!(
                "from.user =~ '{}'",
                escape_filter_text(&self.sip_from)
            ));
        }
        if !self.sip_to.is_empty() {
            parts.push(format!("to.user =~ '{}'", escape_filter_text(&self.sip_to)));
        }
        if !self.source.is_empty() {
            parts.push(format!("src.ip =~ '{}'", escape_filter_text(&self.source)));
        }
        if !self.destination.is_empty() {
            parts.push(format!(
                "dst.ip =~ '{}'",
                escape_filter_text(&self.destination)
            ));
        }
        if !self.payload.is_empty() {
            parts.push(format!(
                "payload =~ '{}'",
                escape_filter_text(&self.payload)
            ));
        }

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
    pub(in crate::tui) fn clear(&mut self) {
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
    ///
    /// Retained as the completing predicate of the filter-dialog API (the
    /// inverse of "has the user entered any filter criteria?"), symmetric
    /// with [`Self::clear`] and [`Self::build_filter_expression`]. No caller
    /// gates on it today — the apply path calls `build_filter_expression`,
    /// which already returns `None` for an all-empty dialog, so no separate
    /// emptiness check is needed — hence `dead_code` is allowed rather than
    /// deleting a correct, self-contained predicate that a future empty-
    /// state guard would only have to re-add.
    #[allow(dead_code)]
    pub(in crate::tui) fn is_empty(&self) -> bool {
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
    /// Chronological call-timeline view for a specific dialog (by Call-ID).
    CallTimeline(String),
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
    /// Combined raw detail of several messages (one transaction or the whole
    /// dialog) stacked into a single scrollable view.
    CombinedDetail {
        /// Call-ID of the dialog.
        call_id: String,
        /// Original message indices to show, in order.
        indices: Vec<usize>,
        /// Scope label for the title (e.g. "transaction" or "dialog").
        scope: &'static str,
    },
    /// Keybinding help overlay.
    Help,
    /// Statistics summary view.
    Statistics,
    /// Live call-quality dashboard (aggregate MOS/jitter/loss, worst first).
    QualityDashboard,
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

/// Key identifying one exact displayed-dialog derivation: if every field
/// matches, the cached row order is still valid.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::tui) struct DisplayedKey {
    /// [`crate::sip::dialog_store::DialogStore::generation`] at derivation.
    pub(in crate::tui) generation: u64,
    /// Human-readable active-filter text (uniquely describes the filter).
    pub(in crate::tui) filter_text: String,
    /// Search query in effect at derivation.
    pub(in crate::tui) query: String,
    /// Sort column in effect at derivation.
    pub(in crate::tui) sort_column: crate::tui::call_list::SortColumn,
    /// Sort direction in effect at derivation (`true` = ascending).
    pub(in crate::tui) sort_ascending: bool,
}

/// Cross-tick cache of the displayed dialog list (filter + search + sort):
/// derived at most once per tick by `App::sync_caches`, reused by the
/// status-bar counts, autoscroll and the render pass — and reused across
/// ticks entirely while the store generation and view inputs are unchanged.
#[derive(Debug, Default)]
pub(in crate::tui) struct DisplayedCache {
    /// Key the cached list was derived under; `None` until first derivation.
    pub(in crate::tui) key: Option<DisplayedKey>,
    /// Call-IDs in display order.
    pub(in crate::tui) ids: Vec<String>,
    /// Floors generation-driven rebuilds (user inputs bypass it).
    pub(in crate::tui) floor: ChurnFloor,
}

/// Rate limiter for generation-driven cache rebuilds: `ready()` is true
/// when at least [`CHURN_REBUILD_MIN`] has passed since the last `mark()`
/// (or nothing was ever marked, so first derivations are immediate).
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct ChurnFloor(Option<std::time::Instant>);

impl ChurnFloor {
    /// Whether a churn-driven rebuild is allowed now: `true` when at
    /// least `CHURN_REBUILD_MIN` has passed since the last `mark()` or
    /// nothing was ever marked.
    pub(in crate::tui) fn ready(&self) -> bool {
        self.0.is_none_or(|t| t.elapsed() >= CHURN_REBUILD_MIN)
    }

    /// Record that a rebuild just happened, starting a new floor window.
    pub(in crate::tui) fn mark(&mut self) {
        self.0 = Some(std::time::Instant::now());
    }

    /// Reset the floor so the next `ready()` is immediately true. Used on
    /// discrete completion events (a background pcap load landing) — the
    /// UI must reflect those on the very next tick, not a floor later.
    pub(in crate::tui) fn clear(&mut self) {
        self.0 = None;
    }

    /// Backdate the floor so the next `ready()` is true — stands in for
    /// real time passing between ticks (test helper).
    pub(in crate::tui) fn elapse_for_test(&mut self) {
        self.0 = self.0.map(|t| t - 2 * CHURN_REBUILD_MIN);
    }
}

/// Everything that shaped the cached stream-list rows.
#[derive(Debug, PartialEq)]
pub(in crate::tui) struct StreamDisplayedKey {
    /// Stream-store generation at derivation.
    pub(in crate::tui) stream_generation: u64,
    /// Dialog-store generation — the display filter matches through the
    /// associated dialog, so dialog changes reshape the list too. `None`
    /// when no filter was active (dialogs then don't participate).
    pub(in crate::tui) dialog_generation: Option<u64>,
    /// Human-readable active-filter text at derivation.
    pub(in crate::tui) filter_text: String,
    /// Search query at derivation.
    pub(in crate::tui) query: String,
}

/// Cross-tick cache of the displayed stream list (search + filter):
/// derived in `App::sync_caches`, consumed by the stream-list render and
/// the navigation clamps — which previously re-filtered the whole store
/// under a blocking read lock on every keypress.
#[derive(Debug, Default)]
pub(in crate::tui) struct StreamDisplayedCache {
    /// Key the cached rows were derived under; `None` until first derivation.
    pub(in crate::tui) key: Option<StreamDisplayedKey>,
    /// Stream keys in display order.
    pub(in crate::tui) keys: Vec<crate::rtp::stream::StreamKey>,
    /// Floors generation-driven rebuilds (user inputs bypass it).
    pub(in crate::tui) floor: ChurnFloor,
}

/// Cross-tick cache of the statistics view's aggregate text, previously
/// recomputed from every dialog on every frame.
#[derive(Debug, Default)]
pub(in crate::tui) struct StatsCache {
    /// (dialog generation, stream generation) the text was derived from.
    pub(in crate::tui) key: Option<(u64, u64)>,
    /// Pre-rendered statistics text the view scrolls through.
    pub(in crate::tui) text: String,
    /// Floors generation-driven recomputation of the aggregate text.
    pub(in crate::tui) floor: ChurnFloor,
}

// ── Background work shared with the event loop ─────────────────────

/// Progress shared between the UI thread and a background pcap-load worker.
/// The worker increments `packets` while parsing, then deposits the
/// [`PcapLoadOutcome`] and flips `done`; the event-loop tick polls it.
pub struct PcapLoadProgress {
    /// Basename shown in the "Loading …" status line.
    pub filename: String,
    /// Packets parsed so far (worker-incremented).
    pub packets: std::sync::atomic::AtomicU64,
    /// Set by the worker once parsing finished and `result` is present.
    pub done: std::sync::atomic::AtomicBool,
    /// The finished load's outcome, taken exactly once by the poller.
    pub result: parking_lot::Mutex<Option<PcapLoadOutcome>>,
}

impl PcapLoadProgress {
    /// Fresh progress for a load of `filename`.
    pub fn new(filename: &str) -> Self {
        Self {
            filename: filename.to_string(),
            packets: std::sync::atomic::AtomicU64::new(0),
            done: std::sync::atomic::AtomicBool::new(false),
            result: parking_lot::Mutex::new(None),
        }
    }
}

/// Everything a finished background pcap load hands back to the UI thread.
/// Stores are already populated (the worker writes through the shared
/// `Arc<RwLock>` stores exactly like live capture); this carries only what
/// needs the `&mut App` the worker cannot have.
pub struct PcapLoadOutcome {
    /// Final status-line message.
    pub message: String,
    /// SIP message count (0 with streams present ⇒ jump to the stream list).
    pub sip_count: u64,
    /// Capture-mode label ("Offline (file)").
    pub capture_mode: String,
    /// Names from an embedded pcapng Name Resolution Block, applied to the
    /// resolver on the UI thread.
    pub file_names: Vec<(std::net::IpAddr, String)>,
}

/// A save accepted by the save dialog but deferred one event-loop tick, so
/// the "Saving…" status paints before the (blocking) write runs.
pub struct PendingSave {
    /// Export format chosen in the dialog.
    pub format: SaveFormat,
    /// Destination path as typed.
    pub path: String,
}
