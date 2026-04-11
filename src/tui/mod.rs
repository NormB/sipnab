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
pub mod stream_list;

use std::collections::HashMap;
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
    /// Absolute HH:MM:SS.
    #[default]
    Absolute,
    /// Relative delta from the first message (+0.000s, +1.234s, ...).
    Relative,
    /// Hidden — no timestamp column.
    Hidden,
}

impl TimestampMode {
    fn next(self) -> Self {
        match self {
            Self::Absolute => Self::Relative,
            Self::Relative => Self::Hidden,
            Self::Hidden => Self::Absolute,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Absolute => "Time: Absolute",
            Self::Relative => "Time: Relative",
            Self::Hidden => "Time: Hidden",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaveFormat {
    /// Standard pcap format.
    #[default]
    Pcap,
    /// PCAP-NG format.
    PcapNg,
    /// Plain text SIP messages.
    Txt,
}

impl SaveFormat {
    /// Cycle to the next format.
    fn next(self) -> Self {
        match self {
            Self::Pcap => Self::PcapNg,
            Self::PcapNg => Self::Txt,
            Self::Txt => Self::Pcap,
        }
    }

    /// File extension for this format.
    fn extension(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
            Self::Txt => "txt",
        }
    }

    /// Display label for this format.
    fn label(self) -> &'static str {
        match self {
            Self::Pcap => "PCAP",
            Self::PcapNg => "PCAP-NG",
            Self::Txt => "TXT",
        }
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
}

/// Modal popup dialogs that overlay the current view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Popup {
    /// Save capture popup with editable file path.
    SaveDialog,
    /// Filter expression input popup.
    FilterDialog,
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
    /// Filter input buffer (for filter popup).
    filter_input: String,
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

    // ── Call flow display modes ────────────────────────────────────
    /// SDP display mode (None / Summary / Full).
    sdp_display_mode: SdpDisplayMode,
    /// Timestamp display mode (Absolute / Relative / Hidden).
    timestamp_mode: TimestampMode,
    /// Color mode for arrows (Method / CallId / CSeq).
    color_mode: ColorMode,
    /// Whether the raw preview split is active in call flow view.
    raw_preview: bool,
    /// Split percentage for the raw preview pane (10..=80, default 33).
    raw_preview_pct: u16,
    /// Whether extended (multi-leg) flow is active.
    extended_flow: bool,
    /// Whether RTP stream info is displayed in the call flow.
    show_rtp_in_flow: bool,
    /// First selected message index for diff comparison (Space key).
    diff_selected_msg: Option<usize>,
    /// Whether syntax highlighting is enabled in raw message view.
    syntax_highlight: bool,
    /// Whether packet processing is paused (TUI-local flag).
    paused: bool,
    /// Shared pause flag for the processing thread.
    /// When `true`, the processing thread skips `process_message()`.
    paused_flag: Arc<AtomicBool>,
}

impl App {
    /// Create a new application state with shared stores.
    pub fn new(
        dialog_store: Arc<RwLock<DialogStore>>,
        stream_store: Arc<RwLock<StreamStore>>,
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
            filter_input: String::new(),
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
            call_flow_cache: HashMap::new(),
            save_path: String::new(),
            save_cursor: 0,
            save_dialog_count: 0,
            save_selected_count: 0,
            save_message_count: 0,
            save_format: SaveFormat::default(),
            sdp_display_mode: SdpDisplayMode::default(),
            timestamp_mode: TimestampMode::default(),
            color_mode: ColorMode::default(),
            raw_preview: false,
            raw_preview_pct: 33,
            extended_flow: false,
            show_rtp_in_flow: false,
            diff_selected_msg: None,
            syntax_highlight: true,
            paused: false,
            paused_flag: Arc::new(AtomicBool::new(false)),
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
    run_tui_with_pause(dialog_store, stream_store, None)
}

/// Run the TUI with an optional shared pause flag.
///
/// When `paused_flag` is `Some`, the flag is shared with the processing
/// thread so that toggling pause in the TUI also pauses packet processing.
pub fn run_tui_with_pause(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    paused_flag: Option<Arc<AtomicBool>>,
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

    let mut app = App::new(dialog_store, stream_store);
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

        // Mark data updated on every iteration (the stores are live)
        app.mark_data_updated();
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
        app.cached_displayed_count = if let Some(ref filter) = app.active_filter {
            store
                .iter()
                .filter(|d| filter.matches_dialog(d, &[]))
                .count()
        } else {
            store.len()
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
                );
            }
        }
        View::StreamList => {
            if let Some(store) = app.stream_store.try_read() {
                stream_list::render_stream_list(frame, main_area, &mut app.stream_list, &store);
            }
        }
        View::CallFlow(call_id) => {
            if let Some(store) = app.dialog_store.try_read() {
                let cid = call_id.clone();
                let scroll = app.call_flow_scroll;

                // Split area when raw preview is active
                let (ladder_area, raw_area) = if app.raw_preview {
                    let pct = app.raw_preview_pct;
                    let raw_height = (main_area.height as u32 * pct as u32 / 100) as u16;
                    let ladder_height = main_area.height.saturating_sub(raw_height);
                    let chunks = Layout::vertical([
                        Constraint::Length(ladder_height),
                        Constraint::Length(raw_height),
                    ])
                    .areas::<2>(main_area);
                    (chunks[0], Some(chunks[1]))
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
                            let (l, r, msgs) = call_flow::prepare_messages(
                                &owned,
                                ft,
                                None,
                                app.sdp_display_mode,
                                app.timestamp_mode,
                                app.color_mode,
                                false,
                                None,
                            );
                            Some((l, r, msgs))
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
                            let (l, r, msgs) = call_flow::prepare_messages(
                                &d.messages,
                                ft,
                                pdd,
                                app.sdp_display_mode,
                                app.timestamp_mode,
                                app.color_mode,
                                app.show_rtp_in_flow,
                                app.diff_selected_msg,
                            );
                            Some((l, r, msgs))
                        }
                    } else {
                        None
                    }
                };

                // Render using direct buffer painting
                call_flow::render_call_flow_direct_or_empty(
                    frame,
                    ladder_area,
                    prepared.as_ref(),
                    scroll,
                );

                // Render raw preview pane if active
                if let Some(raw_area) = raw_area {
                    msg_raw::render_raw_message(
                        frame, raw_area, &store, &cid,
                        scroll, // show raw of the message at current scroll position
                        0, "",
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
                );
            }
        }
        View::MessageDiff {
            call_id,
            msg1_idx,
            msg2_idx,
        } => {
            if let Some(store) = app.dialog_store.try_read() {
                render_message_diff(frame, main_area, &store, call_id, *msg1_idx, *msg2_idx);
            }
        }
        View::Help => {
            help::render_help(frame, main_area);
        }
        View::Statistics => {
            render_statistics(frame, main_area, app);
        }
    }

    // F-key bar (sngrep-style, context-sensitive) at bottom
    render_fkey_bar(frame, fkey_area, &app.current_view, &app.active_popup);

    // Render popup overlay on top of everything (if active)
    if let Some(popup) = &app.active_popup.clone() {
        match popup {
            Popup::SaveDialog => {
                render_save_popup(frame, area, app);
            }
            Popup::FilterDialog => {
                render_filter_popup(frame, area, &app.filter_input);
            }
        }
    }

    // Render column selector popup (not a Popup variant — it's call_list internal state)
    if app.call_list.column_selector_open {
        call_list::render_column_selector(frame, area, &app.call_list);
    }
}

/// Render status line 1 (sngrep-style): `Current Mode: Online (any)    Dialogs: N (N displayed)`
fn render_status_line1(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let total_count = app.cached_dialog_count;
    let displayed_count = app.cached_displayed_count;

    // Determine if online (live capture) or offline (pcap file)
    let is_online = app.capture_mode.starts_with("Online");
    let mode_style = if is_online {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
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
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(padded[ps + 6..].to_string()));
    } else {
        spans.push(Span::raw(padded[mode_end..].to_string()));
    };

    let line1 = Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::DarkGray));
    frame.render_widget(line1, area);
}

/// Render status line 2 (sngrep-style): `Match Expression: <expr>    BPF Filter: <bpf>`
fn render_status_line2(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let yellow = Style::default().fg(Color::Yellow);

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

    let line2 = Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::DarkGray));
    frame.render_widget(line2, area);
}

/// Render status line 3 (sngrep-style): `Display Filter: <filter>` or search/error overlay.
fn render_status_line3(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let w = area.width as usize;

    let spans = if app.search_active {
        let content = format!(" /{}", app.search_query);
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(Color::Yellow),
        )]
    } else if let Some(ref err) = app.status_error {
        let content = format!(" {}", err);
        vec![Span::styled(
            format!("{:<width$}", content, width = w),
            Style::default().fg(Color::Red),
        )]
    } else {
        let yellow = Style::default().fg(Color::Yellow);
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

    let line3 = Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::DarkGray));
    frame.render_widget(line3, area);
}

/// Render the sngrep-style F-key bar at the bottom of the screen.
///
/// Format: `Esc Quit  Enter Show  F2 Save  ...`
/// Key names in bold white, labels in default. Full-width dark background.
/// The bar is context-sensitive based on the current view. On narrow
/// terminals, lower-priority items are dropped to avoid truncation.
fn render_fkey_bar(frame: &mut ratatui::Frame, area: Rect, view: &View, popup: &Option<Popup>) {
    let key_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let label_style = Style::default().fg(Color::White);

    let width = area.width;

    // Full item sets per view; items near the end are lower priority.
    // Popup-specific bars take precedence.
    let items: Vec<(&str, &str)> = if let Some(p) = popup {
        match p {
            Popup::SaveDialog => vec![("Enter", "Save"), ("Tab", "Format"), ("Esc", "Cancel")],
            Popup::FilterDialog => {
                vec![("Enter", "Apply"), ("Esc", "Cancel"), ("F9", "Clear")]
            }
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
                    vec![("Esc", "Back"), ("Enter", "Raw"), ("Space", "Diff")]
                } else if width < 120 {
                    vec![
                        ("Esc", "Back"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("F4", "Extend"),
                    ]
                } else {
                    vec![
                        ("Esc", "Back"),
                        ("Enter", "Raw"),
                        ("Space", "Diff"),
                        ("d", "SDP"),
                        ("t", "Time"),
                        ("c", "Color"),
                        ("R", "RawSplit"),
                        ("F4", "Extend"),
                        ("F6", "RTP"),
                        ("F7", "Filter"),
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
            View::StreamList => vec![("Esc", "Back"), ("Tab", "Calls"), ("F7", "Filter")],
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

    let bar = Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::DarkGray));
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
    let popup_area = centered_popup(area, 60, 12);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Save Capture ")
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build format selector spans: highlight the active format, dim the others.
    let formats = [SaveFormat::Pcap, SaveFormat::PcapNg, SaveFormat::Txt];
    let mut fmt_spans: Vec<Span<'_>> = vec![Span::styled(
        "  Format:  ",
        Style::default().fg(Color::Cyan),
    )];
    for (i, fmt) in formats.iter().enumerate() {
        if i > 0 {
            fmt_spans.push(Span::raw("  "));
        }
        if *fmt == app.save_format {
            fmt_spans.push(Span::styled(
                format!("[{}]", fmt.label()),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            fmt_spans.push(Span::styled(
                fmt.label().to_string(),
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    fmt_spans.push(Span::styled(
        "      (Tab)",
        Style::default().fg(Color::DarkGray),
    ));

    let dialog_info = format!(
        "  Dialogs: {} ({} selected)",
        app.save_dialog_count, app.save_selected_count
    );
    let msg_info = format!("  Messages: {}", app.save_message_count);

    let lines: Vec<Line<'_>> = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Save to: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                app.save_path.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(fmt_spans),
        Line::from(""),
        Line::from(Span::styled(
            dialog_info,
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(msg_info, Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Enter]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Save  "),
            Span::styled(
                "[Tab]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Format  "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Cancel"),
        ]),
    ];

    // Ensure we don't exceed the inner area height
    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(Color::Black));
    frame.render_widget(para, inner);
}

/// Render the filter dialog as a centered popup overlay.
fn render_filter_popup(frame: &mut ratatui::Frame, area: Rect, input: &str) {
    let popup_area = centered_popup(area, 60, 12);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter ")
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let expr_display = if input.is_empty() {
        Span::styled(
            "method == 'INVITE'",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )
    } else {
        Span::styled(
            input.to_string(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    };

    let lines: Vec<Line<'_>> = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Expression: ", Style::default().fg(Color::Cyan)),
            expr_display,
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Examples: method == 'INVITE', state == 'Failed'",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "            from =~ '1001', to =~ 'bob'",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Enter]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Apply  "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Cancel  "),
            Span::styled(
                "[F9]",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Clear"),
        ]),
    ];

    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(Color::Black));
    frame.render_widget(para, inner);
}

/// Render the statistics summary view with real data from stores.
fn render_statistics(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    use crate::sip::dialog::DialogState;
    use std::collections::HashMap;

    let ds = app.dialog_store.read();
    let ss = app.stream_store.read();

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
        .style(Style::default().fg(Color::White));

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
) {
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.").style(Style::default().fg(Color::Red));
            frame.render_widget(para, area);
            return;
        }
    };

    let msg1 = dialog.messages.get(msg1_idx);
    let msg2 = dialog.messages.get(msg2_idx);

    if msg1.is_none() || msg2.is_none() {
        let para = Paragraph::new("Message not found.").style(Style::default().fg(Color::Red));
        frame.render_widget(para, area);
        return;
    }

    let msg1 = msg1.unwrap();
    let msg2 = msg2.unwrap();

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
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    right_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg2_idx + 1),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    let diff_style = Style::default()
        .fg(Color::Yellow)
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
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
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
                app.current_view = View::CallFlow(call_id);
            }
        }
        KeyCode::Tab => {
            app.current_view = View::StreamList;
        }
        KeyCode::Char(' ') => {
            app.call_list.toggle_selection();
        }
        KeyCode::Char('/') => {
            app.search_active = true;
            app.search_query.clear();
        }
        // F5 — Clear calls
        KeyCode::F(5) => {
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
        // F10 / t — Column selector popup
        KeyCode::F(10) | KeyCode::Char('t') => {
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
        KeyCode::Char('A') => {
            app.call_list.autoscroll = !app.call_list.autoscroll;
        }
        // p — Pause/resume capture processing
        KeyCode::Char('p') => {
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
        KeyCode::F(1) => app.current_view = View::Help,
        KeyCode::F(2) => {
            open_save_popup(app);
        }
        KeyCode::F(3) => {
            // F3 Search — same as '/' search
            app.search_active = true;
            app.search_query.clear();
        }
        KeyCode::F(4) => {
            app.status_error = Some("Extended view not yet implemented".to_string());
        }
        KeyCode::F(7) => {
            if app.active_filter.is_some() {
                // F7 again clears the active filter
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                app.filter_input.clear();
                app.active_popup = Some(Popup::FilterDialog);
            }
        }
        KeyCode::F(8) => {
            app.status_error = Some("Settings not yet implemented".to_string());
        }
        KeyCode::F(9) => {
            // F9 Clear Filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
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
    let selected_rows = app.call_list.selected_rows().to_vec();

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
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.stream_list.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.stream_list.move_down(stream_count),
        KeyCode::Home => app.stream_list.move_to_top(),
        KeyCode::End => app.stream_list.move_to_bottom(stream_count),
        KeyCode::Tab => {
            app.current_view = View::CallList;
        }
        KeyCode::Char('/') => {
            app.search_active = true;
            app.search_query.clear();
        }
        KeyCode::F(1) => app.current_view = View::Help,
        KeyCode::F(7) => {
            if app.active_filter.is_some() {
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                app.filter_input.clear();
                app.active_popup = Some(Popup::FilterDialog);
            }
        }
        KeyCode::Esc => app.current_view = View::CallList,
        _ => {}
    }
}

/// Handle keys in the call flow view.
fn handle_call_flow_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            app.call_flow_scroll = app.call_flow_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.call_flow_scroll = app.call_flow_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.call_flow_scroll = app.call_flow_scroll.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.call_flow_scroll = app.call_flow_scroll.saturating_add(20);
        }
        KeyCode::Home => app.call_flow_scroll = 0,
        KeyCode::End => {
            // Jump to last message
            if let View::CallFlow(ref call_id) = app.current_view {
                let store = app.dialog_store.read();
                if let Some(dialog) = store.get(call_id) {
                    app.call_flow_scroll = dialog.messages.len().saturating_sub(1);
                }
            }
        }
        KeyCode::Enter => {
            // Open raw message for the line at scroll offset
            if let View::CallFlow(ref call_id) = app.current_view {
                let store = app.dialog_store.read();
                if let Some(dialog) = store.get(call_id) {
                    let msg_count = dialog.messages.len();
                    if app.call_flow_scroll < msg_count {
                        let cid = call_id.clone();
                        drop(store);
                        app.raw_msg_scroll = 0;
                        app.current_view = View::RawMessage {
                            call_id: cid,
                            message_index: app.call_flow_scroll,
                        };
                    }
                }
            }
        }
        KeyCode::Char(' ') => {
            // Select message for diff comparison
            if let View::CallFlow(ref call_id) = app.current_view {
                let store = app.dialog_store.read();
                if let Some(dialog) = store.get(call_id) {
                    let msg_count = dialog.messages.len();
                    if app.call_flow_scroll < msg_count {
                        if let Some(first) = app.diff_selected_msg {
                            if first != app.call_flow_scroll {
                                // Second selection — open diff view
                                let cid = call_id.clone();
                                let msg2 = app.call_flow_scroll;
                                app.diff_selected_msg = None;
                                drop(store);
                                app.current_view = View::MessageDiff {
                                    call_id: cid,
                                    msg1_idx: first,
                                    msg2_idx: msg2,
                                };
                            }
                        } else {
                            // First selection
                            app.diff_selected_msg = Some(app.call_flow_scroll);
                            app.status_error = Some(format!(
                                "Selected: message {} (press Space on another to diff)",
                                app.call_flow_scroll + 1
                            ));
                        }
                    }
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
        KeyCode::Char('+') | KeyCode::Char('=') => {
            // Increase raw preview size
            if app.raw_preview && app.raw_preview_pct < 80 {
                app.raw_preview_pct = (app.raw_preview_pct + 5).min(80);
                app.status_error = Some(format!("Raw preview: {}%", app.raw_preview_pct));
            }
        }
        KeyCode::Char('-') => {
            // Decrease raw preview size
            if app.raw_preview && app.raw_preview_pct > 10 {
                app.raw_preview_pct = app.raw_preview_pct.saturating_sub(5).max(10);
                app.status_error = Some(format!("Raw preview: {}%", app.raw_preview_pct));
            }
        }
        KeyCode::F(4) | KeyCode::Char('x') => {
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
        KeyCode::Esc => {
            app.diff_selected_msg = None;
            app.current_view = View::CallList;
        }
        KeyCode::F(1) => app.current_view = View::Help,
        KeyCode::F(2) => {
            open_save_popup(app);
        }
        KeyCode::F(5) => {
            // F5 also starts compare mode (same as first Space press)
            app.diff_selected_msg = None;
            app.status_error =
                Some("Compare: press Space on first message, then Space on second".to_string());
        }
        KeyCode::F(7) => {
            if app.active_filter.is_some() {
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                app.filter_input.clear();
                app.active_popup = Some(Popup::FilterDialog);
            }
        }
        KeyCode::F(9) => {
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
        }
        _ => {}
    }
}

/// Handle keys in the raw message view.
fn handle_raw_message_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
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
        KeyCode::Char('/') => {
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
        KeyCode::F(1) => app.current_view = View::Help,
        KeyCode::F(2) => {
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
        KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('q') => {
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
            };
            app.status_error = Some(msg);
            app.active_popup = None;
        }
        KeyCode::Tab | KeyCode::BackTab => {
            // Cycle save format and update file extension
            let old_ext = app.save_format.extension();
            app.save_format = if key.code == KeyCode::BackTab {
                // Reverse cycle on Shift+Tab
                match app.save_format {
                    SaveFormat::Pcap => SaveFormat::Txt,
                    SaveFormat::PcapNg => SaveFormat::Pcap,
                    SaveFormat::Txt => SaveFormat::PcapNg,
                }
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
                app.save_cursor -= 1;
                app.save_path.remove(app.save_cursor);
            }
        }
        KeyCode::Left => {
            app.save_cursor = app.save_cursor.saturating_sub(1);
        }
        KeyCode::Right => {
            if app.save_cursor < app.save_path.len() {
                app.save_cursor += 1;
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
            app.save_cursor += 1;
        }
        _ => {}
    }
}

/// Handle keys in the filter dialog popup.
fn handle_filter_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            // Cancel without applying
            app.active_popup = None;
        }
        KeyCode::Enter => {
            let input = app.filter_input.trim().to_string();
            if input.is_empty() {
                // Empty input clears any active filter
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                match FilterExpr::parse(&input) {
                    Ok(expr) => {
                        app.active_filter = Some(expr);
                        app.active_filter_text = input;
                        app.status_error = None;
                    }
                    Err(e) => {
                        app.status_error = Some(format!("Filter error: {e}"));
                    }
                }
            }
            app.active_popup = None;
        }
        KeyCode::F(9) => {
            // F9 clears filter and closes popup
            app.active_filter = None;
            app.active_filter_text.clear();
            app.filter_input.clear();
            app.status_error = None;
            app.active_popup = None;
        }
        KeyCode::Backspace => {
            app.filter_input.pop();
        }
        KeyCode::Char(c) => {
            app.filter_input.push(c);
        }
        _ => {}
    }
}

/// Handle keys in the statistics view.
fn handle_statistics_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') => {
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
    let udp_len: u16 = (8 + payload.len()) as u16;
    let ip_total_len: u16 = 20 + udp_len;
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
        Self::new(ds, ss)
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
        Self::new(ds, ss)
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

    /// Count dialogs visible after applying the active filter.
    pub fn visible_dialog_count(&self) -> usize {
        filtered_dialog_count(self)
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
        let app = App::new(ds, ss);
        assert_eq!(app.current_view, View::CallList);
        assert!(!app.should_quit);
    }

    #[test]
    fn adaptive_timeout_active_vs_idle() {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let mut app = App::new(ds, ss);

        // Just created — should be active
        assert!(app.poll_timeout() <= Duration::from_millis(ACTIVE_POLL_MS));

        // Simulate idle by backdating the timestamp
        app.last_data_update = Instant::now() - Duration::from_secs(10);
        assert!(app.poll_timeout() >= Duration::from_millis(IDLE_POLL_MS));
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
}
