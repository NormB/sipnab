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

use std::collections::HashSet;
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

mod controllers;
mod render;
mod save;
mod state;
mod test_api;
mod theme;

use controllers::*;
#[doc(hidden)]
pub use controllers::{CallListAction, call_list_action};
use render::*;
use save::*;
pub use state::*;
pub use theme::*;

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
    /// View to return to when pressing Esc from RawMessage (the raw view can
    /// be opened from the call list OR the call flow).
    raw_msg_return_view: Option<View>,
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
    /// Call flow ladder state (selection, scroll, toggles, render caches).
    flow: CallFlowViewState,
    /// Scroll offset for raw message view.
    raw_msg_scroll: u16,
    /// Scroll offset for the F1 help view (clamped to content height in render).
    help_scroll: u16,
    /// Scroll offset for the statistics view (clamped to content in render).
    stats_scroll: u16,
    /// Displayed dialog-row count at the previous render (autoscroll's
    /// sticky-bottom reference point).
    last_rendered_dialog_rows: usize,
    /// Scroll offset for the message diff view (clamped to content in render).
    diff_scroll: u16,
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
    /// Save dialog popup state (path/format survive reopening).
    save: SaveDialogState,
    /// File-open dialog state (last-browsed directory survives reopening).
    file_open: FileOpenState,

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
            raw_msg_return_view: None,
            filter_dialog: FilterDialogState::default(),
            settings_dialog: SettingsDialogState::default(),
            active_filter: None,
            active_filter_text: String::new(),
            status_error: None,
            flow: CallFlowViewState::default(),
            raw_msg_scroll: 0,
            help_scroll: 0,
            stats_scroll: 0,
            last_rendered_dialog_rows: 0,
            diff_scroll: 0,
            search_query: String::new(),
            search_active: false,
            capture_mode: "Online (any)".to_string(),
            bpf_filter: String::new(),
            cached_dialog_count: 0,
            cached_displayed_count: 0,
            save: SaveDialogState::default(),
            file_open: FileOpenState::default(),
            name_mode: NameMode::default(),
            resolver: Arc::new(NameResolver::new()),
            names_save_path: None,
            names_config_path: None,
            name_dialog: NameDialogState::default(),
            sdp_display_mode: SdpDisplayMode::default(),
            timestamp_mode: TimestampMode::default(),
            color_mode: ColorMode::default(),
            from_to_mode: FromToMode::default(),
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

    /// Reset all per-call transient state when entering a call flow view.
    /// Scroll, selection, fold expansion, marks and diff selection are all
    /// positions within ONE dialog's ladder; carrying them into another
    /// dialog would highlight/expand arbitrary rows there. Display settings
    /// (timestamp mode, SDP mode, colors, split) are app-global and persist.
    pub(crate) fn reset_call_flow_view_state(&mut self) {
        self.flow.scroll = 0;
        self.flow.selected = 0;
        self.flow.detail_scroll = 0;
        self.flow.transaction_filter = None;
        self.flow.cached_msg_count = 0;
        self.flow.cached_rtp_bar_indices.clear();
        self.flow.cached_raw_indices.clear();
        self.flow.fold_expanded.clear();
        self.flow.mark_index = None;
        self.flow.diff_selected = None;
    }

    /// Refresh the store-derived count caches and apply sticky-bottom
    /// autoscroll. Called from the event-loop tick before each render (the
    /// only writer besides [`Self::apply_render_feedback`]), so the render
    /// pass itself stays free of state writes.
    ///
    /// Uses `try_read()`: on lock contention the caches simply keep their
    /// previous values until the next tick, matching the render pass's
    /// skip-on-contention behavior.
    fn sync_caches(&mut self) {
        let Some(store) = self.dialog_store.try_read() else {
            return;
        };
        self.cached_dialog_count = store.len();
        self.cached_displayed_count = {
            let mut count = if let Some(ref filter) = self.active_filter {
                store
                    .iter()
                    .filter(|d| filter.matches_dialog(d, &[]))
                    .count()
            } else {
                store.len()
            };
            // Apply text search filter to the count
            if !self.search_query.is_empty() {
                let q = self.search_query.to_ascii_lowercase();
                count = store
                    .iter()
                    .filter(|d| {
                        if let Some(ref filter) = self.active_filter
                            && !filter.matches_dialog(d, &[])
                        {
                            return false;
                        }
                        d.call_id.to_ascii_lowercase().contains(&q)
                            || d.method.as_str().to_ascii_lowercase().contains(&q)
                            || d.from_user
                                .as_deref()
                                .unwrap_or("")
                                .to_ascii_lowercase()
                                .contains(&q)
                            || d.to_user
                                .as_deref()
                                .unwrap_or("")
                                .to_ascii_lowercase()
                                .contains(&q)
                            || d.src_addr.to_string().contains(&q)
                            || d.dst_addr.to_string().contains(&q)
                            || call_list::state_display_str(d.state())
                                .to_ascii_lowercase()
                                .contains(&q)
                            || d.messages.iter().any(|msg| {
                                String::from_utf8_lossy(&msg.raw)
                                    .to_ascii_lowercase()
                                    .contains(&q)
                            })
                    })
                    .count();
            }
            count
        };

        // Autoscroll: sticky-bottom. When enabled and the selection already
        // sits on the last row, newly arrived dialogs pull it to the new
        // bottom; a selection elsewhere is never yanked.
        if self.current_view == View::CallList {
            let displayed_len = call_list::displayed_dialogs(
                &store,
                self.active_filter.as_ref(),
                &self.search_query,
                self.call_list.sort_column(),
                self.call_list.sort_ascending(),
            )
            .len();
            if self.call_list.autoscroll
                && self.last_rendered_dialog_rows > 0
                && displayed_len > self.last_rendered_dialog_rows
                && self.call_list.selected() + 1 >= self.last_rendered_dialog_rows
            {
                self.call_list.move_to_bottom(displayed_len);
            }
            self.last_rendered_dialog_rows = displayed_len;
        }
    }

    /// Write back the geometry- and content-dependent values a render pass
    /// computed (clamped scrolls, call-flow row caches). Applied by the
    /// event loop right after `terminal.draw`, which is the same point in
    /// the frame timeline the render pass used to write them directly.
    fn apply_render_feedback(&mut self, fb: RenderFeedback) {
        if let Some(v) = fb.stream_detail_scroll {
            self.stream_detail_scroll = v;
        }
        if let Some(v) = fb.flow_scroll {
            self.flow.scroll = v;
        }
        if let Some(v) = fb.flow_detail_scroll {
            self.flow.detail_scroll = v;
        }
        if let Some((count, bars, raws)) = fb.flow_caches {
            self.flow.cached_msg_count = count;
            self.flow.cached_rtp_bar_indices = bars;
            self.flow.cached_raw_indices = raws;
        }
        if let Some(v) = fb.raw_msg_scroll {
            self.raw_msg_scroll = v;
        }
        if let Some(v) = fb.diff_scroll {
            self.diff_scroll = v;
        }
        if let Some(v) = fb.help_scroll {
            self.help_scroll = v;
        }
        if let Some(v) = fb.stats_scroll {
            self.stats_scroll = v;
        }
    }

    /// Return whether packet processing is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Observed RTP codec segments for a dialog, oldest first — the codecs
    /// actually carried on the wire (resolved from each stream's payload type),
    /// each with the window it was seen. Drives the call-flow RTP-in-flow bar so
    /// it shows the *used* codec (and a re-INVITE codec switch as a later
    /// segment), not the full SDP offer. Empty when no RTP is linked to the
    /// dialog, in which case the bar falls back to the negotiated SDP answer.
    fn rtp_codec_segments(&self, call_id: &str) -> Vec<call_flow::RtpCodecSegment> {
        let Some(store) = self.stream_store.try_read() else {
            return Vec::new();
        };
        let mut segs: Vec<call_flow::RtpCodecSegment> = store
            .streams_for(call_id)
            .filter_map(|s| {
                s.codec.clone().map(|codec| call_flow::RtpCodecSegment {
                    codec,
                    start: s.first_seen,
                    end: s.last_seen,
                })
            })
            .collect();
        segs.sort_by_key(|s| s.start);
        segs
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
        let _ = execute!(
            io::stdout(),
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show,
            LeaveAlternateScreen
        );
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
    run_tui_with_pause(dialog_store, stream_store, None, TuiOptions::default())
}

/// Presentation and naming options for a TUI session, resolved from
/// config/CLI by the caller.
#[derive(Default)]
pub struct TuiOptions {
    pub theme: Theme,
    pub keymap: Keymap,
    /// Call-list columns to show (config `[display] visible_columns`).
    pub visible_columns: Option<Vec<String>>,
    pub name_setup: NameSetup,
    pub from_to_mode: FromToMode,
}

/// Run the TUI with an optional shared pause flag.
///
/// When `paused_flag` is `Some`, the flag is shared with the processing
/// thread so that toggling pause in the TUI also pauses packet processing.
pub fn run_tui_with_pause(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    paused_flag: Option<Arc<AtomicBool>>,
    options: TuiOptions,
) -> Result<()> {
    let TuiOptions {
        theme,
        keymap,
        visible_columns,
        name_setup,
        from_to_mode,
    } = options;
    // Setup terminal
    terminal::enable_raw_mode()?;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        crossterm::event::EnableMouseCapture,
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

        // Tick: refresh store-derived caches, render read-only, then
        // persist what the render pass computed (clamps, flow row caches).
        app.sync_caches();
        let mut fb = RenderFeedback::default();
        terminal.draw(|frame| fb = render_app(frame, &mut app))?;
        app.apply_render_feedback(fb);

        // Poll with adaptive timeout, then drain every queued event before
        // the next redraw — a paste or key burst must not be metered out at
        // one event per frame.
        let timeout = app.poll_timeout();
        if event::poll(timeout)? {
            loop {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        handle_key_event(&mut app, key);
                    }
                    Event::Mouse(m) => {
                        controllers::handle_mouse_event(&mut app, m.kind);
                    }
                    _ => {}
                }
                if app.should_quit || !event::poll(std::time::Duration::ZERO)? {
                    break;
                }
            }
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

    /// The status-bar dialog counts must refresh from the store on the
    /// event-loop tick itself — not as a render side effect.
    #[test]
    fn sync_caches_refreshes_dialog_counts_without_rendering() {
        use controllers::test_support::{base_ts, make_invite};
        let mut app = App::with_processed_messages(vec![
            make_invite("sync-1@test", "1001", "1002", base_ts()),
            make_invite("sync-2@test", "1003", "1004", base_ts()),
        ]);
        assert_eq!(app.cached_dialog_count, 0, "no tick has run yet");
        app.sync_caches();
        assert_eq!(app.cached_dialog_count, 2);
        assert_eq!(app.cached_displayed_count, 2);
    }

    /// Sticky-bottom autoscroll is tick logic, not render logic: with the
    /// selection on the last row and new dialogs arriving, sync_caches()
    /// must pull the selection to the new bottom.
    #[test]
    fn sync_caches_applies_sticky_bottom_autoscroll() {
        use controllers::test_support::{base_ts, make_invite};
        let mut app = App::with_processed_messages(vec![make_invite(
            "auto-1@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        app.call_list.autoscroll = true;
        app.sync_caches(); // selection on row 0 == last row; rows recorded
        assert_eq!(app.last_rendered_dialog_rows, 1);

        // Two more dialogs arrive.
        for cid in ["auto-2@test", "auto-3@test"] {
            let msg = make_invite(cid, "1005", "1006", base_ts());
            app.dialog_store.write().process_message(msg);
        }
        app.sync_caches();
        assert_eq!(app.last_rendered_dialog_rows, 3);
        assert_eq!(
            app.call_list.selected(),
            2,
            "selection must follow the new bottom row"
        );
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
