// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interactive terminal UI for sipnab.
//!
//! Provides the sngrep-replacement mode: a full-screen TUI with call list,
//! RTP stream list, call flow ladder diagrams, and raw message viewing.
//! Built on [`ratatui`] + [`crossterm`] with adaptive refresh rates
//! (100ms active, 500ms idle, immediate on keypress).

pub mod call_flow;
pub mod call_list;
pub mod dashboard;
pub mod header_form;
pub mod help;
pub(crate) mod loss_map;
pub mod msg_raw;
pub mod stream_detail;
pub mod stream_list;
pub(crate) mod timeline;

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

mod clipboard;
mod controllers;
mod render;
mod save;
mod state;
mod test_api;
mod theme;

use controllers::*;
#[doc(hidden)]
pub use controllers::{
    CallFlowAction, CallListAction, CombinedDetailAction, DashboardAction, HelpAction,
    LossMapAction, MessageDiffAction, RawMessageAction, StatisticsAction, StreamDetailAction,
    StreamListAction, TimelineAction, call_flow_action, call_list_action, combined_detail_action,
    dashboard_action, help_action, loss_map_action, message_diff_action, raw_message_action,
    statistics_action, stream_detail_action, stream_list_action, timeline_action,
};
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
    /// Dialog count at the last event-loop check; a change marks data as
    /// freshly updated so the poll rate stays in active mode.
    last_known_dialog_count: usize,
    /// Consecutive render ticks skipped because a store write lock was
    /// contended; at FORCED_DRAW_AFTER_SKIPS the next tick blocks instead
    /// of skipping, so a write-saturated capture can't starve the UI.
    contended_skips: u32,
    /// Scroll offset (lines) for the stream detail view.
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
    /// Horizontal headroom the call-flow detail pane had at the last frame
    /// that drew it: `Some(0)` means the message fits and ←/→ cannot move
    /// it, `None` means no frame has drawn the pane yet (nothing to
    /// report). Written by [`App::apply_render_feedback`], read by the
    /// call-flow controller — the pane width is render-only knowledge, and
    /// without it a clamped ←/→ press was indistinguishable from a working
    /// one and so said nothing at all (#188).
    ///
    /// Belongs in [`CallFlowViewState`] beside `detail_hscroll`; it sits on
    /// `App` only because that struct was held by another change.
    flow_detail_max_hscroll: Option<u16>,
    /// Scroll offset for raw message view.
    raw_msg_scroll: u16,
    /// Scroll offset for the F1 help view (clamped to content height in render).
    help_scroll: u16,
    /// Scroll offset for the statistics view (clamped to content in render).
    stats_scroll: u16,
    /// Selected row in the quality dashboard's worst-streams table.
    dashboard_selected: usize,
    /// View to return to when closing the quality dashboard.
    dashboard_return_view: Option<View>,
    /// Snapshot the quality dashboard renders from; rebuilt in
    /// `sync_caches` while the dashboard is open so the draw pass stays
    /// read-only (skip-tick contract).
    dashboard_snapshot: Option<dashboard::DashboardSnapshot>,
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
    /// BPF filter string shown in status line 2: the expression this
    /// session's capture was compiled with, set once at startup from
    /// [`TuiOptions::bpf_filter`](crate::tui::state::TuiOptions::bpf_filter)
    /// via [`TuiOptions::into_app`](crate::tui::state::TuiOptions::into_app).
    ///
    /// It is the EFFECTIVE filter — what `bootstrap::plan` handed to libpcap
    /// — and not what the operator typed, because on a live capture those
    /// differ: with no filter given, `plan` generates one from
    /// `--portrange`, and the kernel drops what it does not match. Empty
    /// therefore means no filter was compiled, which is the normal state for
    /// `-I` and never the state of a live capture.
    ///
    /// Not updated by an in-session `O` file open: that path reads its file
    /// with no filter at all, and the label above it changes to
    /// `Offline (…)` while the live capture this describes keeps running.
    bpf_filter: String,
    /// True once an in-session `O` open loaded a file, so `bpf_filter`
    /// describes the LIVE capture and not what is on screen (#190).
    ///
    /// The slot is marked rather than cleared. The live capture keeps running
    /// and keeps writing to the same stores, so the filter is still in force
    /// for that half — blanking it would replace an incomplete truth with a
    /// false one, and "no filter compiled" is a specific claim this session
    /// cannot make.
    bpf_is_live_only: bool,
    /// Cached total dialog count (updated when lock is available).
    cached_dialog_count: usize,
    /// Displayed dialog list cache (filter+search+sort, derived per tick).
    displayed: DisplayedCache,
    /// Cached displayed dialog count (updated when lock is available).
    cached_displayed_count: usize,
    /// Displayed stream list cache (search+filter, derived per tick).
    stream_displayed: StreamDisplayedCache,
    /// Statistics view aggregate-text cache.
    stats: StatsCache,
    /// Stream-store generation the dashboard snapshot was derived from.
    dashboard_generation: Option<u64>,
    /// Floors churn-driven dashboard snapshot rebuilds.
    dashboard_floor: ChurnFloor,
    /// Save dialog popup state (path/format survive reopening).
    save: SaveDialogState,
    /// File-open dialog state (last-browsed directory survives reopening).
    file_open: FileOpenState,
    /// In-flight background pcap load, polled by the event-loop tick.
    pcap_load: Option<Arc<PcapLoadProgress>>,
    /// Save deferred one tick so the "Saving…" status paints before the
    /// (blocking) write runs.
    pending_save: Option<PendingSave>,
    /// Completion messages pushed by detached workers (clipboard export),
    /// drained into the status line each tick.
    async_messages: Arc<parking_lot::Mutex<Vec<String>>>,
    /// Whether the terminal should capture mouse events (wheel scrolling).
    /// Toggled with F12; while `false` the terminal's native drag-to-select
    /// works, at the cost of wheel scrolling. The event loop reconciles the
    /// terminal state with this flag after each input drain.
    mouse_capture_enabled: bool,

    // ── Call flow display modes ────────────────────────────────────
    /// Header-name display form (as captured / expanded / compact) for
    /// every view that shows full message text.
    header_form: header_form::HeaderFormMode,
    /// Name-resolution display mode (Off / Names / Dns).
    name_mode: NameMode,
    /// One-way path delay the operator declared, if any — see
    /// [`crate::rtp::quality::resolve_one_way_delay`]. `None` means they said
    /// nothing, not that they chose the default.
    pub(crate) declared_one_way_delay_ms: Option<f64>,
    /// The one band set every view in this session colours from, resolved at
    /// startup from `--jitter-warn-ms` and friends over `[quality]`.
    ///
    /// Held here for the same reason [`Self::theme`] is: it is a decision the
    /// session makes once, and a view free to resolve its own is free to
    /// disagree with the pane beside it. That disagreement is not
    /// hypothetical — it is the defect [`crate::rtp::bands::QualityBands`] was
    /// written to end, where four views banded one stream three ways.
    pub(crate) quality_bands: crate::rtp::bands::QualityBands,
    /// Shared IP -> name resolver (manual mappings, hosts, reverse DNS).
    resolver: Arc<NameResolver>,
    /// Path the manual mappings persist to (set from config/CLI).
    names_save_path: Option<PathBuf>,
    /// When `Some`, `N`-dialog edits are also written into this sipnabrc's
    /// `[names.manual]` table (opt-in via `[names] persist_to_config`).
    names_config_path: Option<PathBuf>,
    /// Where the F10 column selector's `s` (save) action writes
    /// `[display] visible_columns`. `None` in tests / when no home dir exists.
    column_config_path: Option<PathBuf>,
    /// "Name Address" popup state.
    name_dialog: NameDialogState,
    /// SDP display mode (None / Summary / Full).
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
    /// Playback deferred one tick so the "Decoding…" status paints before
    /// the (blocking) decode/resample runs — same pattern as pending_save.
    #[cfg(feature = "audio")]
    pending_audio_play: bool,
    /// Capture files this session is reading, which a save must never write
    /// over. Seeded from `-I` and extended by every capture opened in-session.
    protected_inputs: crate::capture::output_guard::ProtectedInputs,
}

impl App {
    /// Create a new application state with shared stores.
    ///
    /// # Arguments
    ///
    /// * `dialog_store` — shared SIP dialog store, written by the
    ///   processing thread.
    /// * `stream_store` — shared RTP stream store, written by the
    ///   processing thread.
    /// * `theme` — resolved color theme.
    /// * `keymap` — resolved key bindings.
    ///
    /// # Returns
    ///
    /// A fresh `App` on the call-list view with default display modes,
    /// empty caches, and a private (unshared) pause flag.
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
            contended_skips: 0,
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
            flow_detail_max_hscroll: None,
            bpf_is_live_only: false,
            raw_msg_scroll: 0,
            help_scroll: 0,
            stats_scroll: 0,
            dashboard_selected: 0,
            stream_displayed: StreamDisplayedCache::default(),
            stats: StatsCache::default(),
            dashboard_generation: None,
            dashboard_floor: ChurnFloor::default(),
            dashboard_return_view: None,
            dashboard_snapshot: None,
            last_rendered_dialog_rows: 0,
            diff_scroll: 0,
            search_query: String::new(),
            search_active: false,
            capture_mode: "Online (any)".to_string(),
            bpf_filter: String::new(),
            cached_dialog_count: 0,
            displayed: DisplayedCache::default(),
            cached_displayed_count: 0,
            save: SaveDialogState::default(),
            file_open: FileOpenState::default(),
            pcap_load: None,
            pending_save: None,
            async_messages: Arc::new(parking_lot::Mutex::new(Vec::new())),
            mouse_capture_enabled: true,
            name_mode: NameMode::default(),
            declared_one_way_delay_ms: None,
            quality_bands: crate::rtp::bands::QualityBands::default(),
            resolver: Arc::new(NameResolver::new()),
            names_save_path: None,
            names_config_path: None,
            column_config_path: None,
            name_dialog: NameDialogState::default(),
            header_form: header_form::HeaderFormMode::default(),
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
            #[cfg(feature = "audio")]
            pending_audio_play: false,
            protected_inputs: Default::default(),
        }
    }

    /// Declare the capture files this session reads, so the save dialog
    /// refuses to write over them.
    pub fn set_protected_inputs(
        &mut self,
        protected: crate::capture::output_guard::ProtectedInputs,
    ) {
        self.protected_inputs = protected;
    }

    /// Add a capture opened during the session to the protected set. The file
    /// the TUI is displaying is an input whether the command line named it or
    /// the file-open dialog did.
    pub(crate) fn protect_input_file(&mut self, path: &std::path::Path) {
        self.protected_inputs.protect_file(path);
    }

    /// Set the capture mode label (`mode`) displayed in the status bar.
    pub fn set_capture_mode(&mut self, mode: String) {
        self.capture_mode = mode;
    }

    /// Set the BPF filter string (`filter`) displayed in the status bar.
    pub fn set_bpf_filter(&mut self, filter: String) {
        self.bpf_filter = filter;
    }

    /// Mark data as freshly updated: resets the adaptive refresh timer so
    /// `poll_timeout` returns the active (fast) interval.
    pub fn mark_data_updated(&mut self) {
        self.last_data_update = Instant::now();
    }

    /// Drain completion messages pushed by detached workers into the status
    /// line — one per tick, so consecutive results each get a visible frame.
    ///
    /// # Side effects
    ///
    /// Locks the `async_messages` mutex briefly; when the queue is
    /// non-empty, removes its first entry and overwrites `status_error`
    /// with it.
    pub(crate) fn drain_async_messages(&mut self) {
        let mut queue = self.async_messages.lock();
        if !queue.is_empty() {
            self.status_error = Some(queue.remove(0));
        }
    }

    /// Execute a playback request deferred by one tick (the "Decoding…"
    /// frame has painted by the time this runs): lazy player init, decode/
    /// resample, and the plugin play call.
    ///
    /// No-op unless `pending_audio_play` is set (it is always cleared).
    ///
    /// # Side effects
    ///
    /// Lazily constructs `audio_player` on first use; on init failure
    /// caches the message in `audio_init_error` so later presses don't
    /// retry. Takes a read lock on the stream store, may block on decode/
    /// resample plus the audio backend, and writes the outcome (played /
    /// error / "Stream not found") into `status_error`.
    #[cfg(feature = "audio")]
    pub(crate) fn run_pending_audio(&mut self) {
        if !self.pending_audio_play {
            return;
        }
        self.pending_audio_play = false;

        if self.audio_player.is_none() {
            match crate::rtp::playback::AudioPlayer::new() {
                Ok(player) => self.audio_player = Some(player),
                Err(e) => {
                    let msg = format!("Audio init failed: {e}");
                    self.status_error = Some(msg.clone());
                    self.audio_init_error = Some(msg);
                    return;
                }
            }
        }

        if let Some(player) = &self.audio_player
            && let View::StreamDetail(ref key) = self.current_view
        {
            let result = {
                let store = self.stream_store.read();
                store.get(key).map(|stream| player.play_stream(stream))
            };
            match result {
                Some(Ok(msg)) => self.status_error = Some(msg),
                Some(Err(e)) => self.status_error = Some(format!("Playback error: {e}")),
                None => self.status_error = Some("Stream not found".to_string()),
            }
        }
    }

    /// No-op without the audio feature so callers stay cfg-free.
    #[cfg(not(feature = "audio"))]
    pub(crate) fn run_pending_audio(&mut self) {}

    /// Execute a save the dialog deferred by one tick (the "Saving…" frame
    /// has painted by the time this runs, right after the draw).
    ///
    /// No-op when no save is pending (`pending_save` is always taken).
    ///
    /// # Side effects
    ///
    /// Dispatches to the format-specific writer, which takes store read
    /// locks and performs blocking file I/O; the result message (success
    /// or failure) is written into `status_error`.
    pub(crate) fn run_pending_save(&mut self) {
        let Some(pending) = self.pending_save.take() else {
            return;
        };
        let path = pending.path;
        // The save dialog takes a free-form path, and the capture on screen is
        // the obvious name to type. Every writer below creates-or-truncates, so
        // this is checked before dispatch, not inside each of the eleven
        // formats — a guard in ten of eleven places is not a guard.
        if let Err(msg) = self
            .protected_inputs
            .check(std::path::Path::new(&path), "Save to", false)
        {
            self.status_error = Some(msg);
            return;
        }
        let msg = match pending.format {
            SaveFormat::Pcap => save_to_pcap_path(self, &path, false),
            SaveFormat::PcapNg => save_to_pcap_path(self, &path, true),
            SaveFormat::Txt => save_to_txt_path(self, &path),
            SaveFormat::Json => save_to_json_path(self, &path),
            SaveFormat::Ndjson => save_to_ndjson_path(self, &path),
            SaveFormat::Csv => save_to_csv_path(self, &path),
            SaveFormat::Html => save_to_mermaid_path(self, &path),
            SaveFormat::Markdown => save_to_markdown_path(self, &path),
            SaveFormat::Wav => save_to_wav_path(self, &path),
            SaveFormat::SippXml => save_to_sipp_path(self, &path),
            SaveFormat::RtpJson => save_to_rtp_json_path(self, &path),
        };
        self.status_error = Some(msg);
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
        self.flow.merged_calls.clear();
    }

    /// Refresh the store-derived caches and apply sticky-bottom autoscroll.
    /// Called from the event-loop tick before each render (the only writer
    /// besides [`Self::apply_render_feedback`]), so the render pass itself
    /// stays free of state writes.
    ///
    /// The displayed dialog list (filter + search + sort) is derived AT
    /// MOST once here and cached in [`DisplayedCache`], keyed on the store
    /// generation plus every view input that affects it — the status-bar
    /// count, autoscroll and the render pass all reuse it, and while
    /// nothing changed it survives across ticks untouched.
    ///
    /// Uses `try_read()`: on lock contention the caches simply keep their
    /// previous values until the next tick, matching the render pass's
    /// skip-on-contention behavior.
    ///
    /// # Side effects
    ///
    /// * Takes non-blocking (`try_read`) read locks on the dialog store
    ///   and, per view, the stream store — never a write lock, never
    ///   blocking.
    /// * Rebuilds, at most once per churn floor: the quality-dashboard
    ///   snapshot, the displayed dialog-ID cache (`displayed`), the
    ///   displayed stream-key cache (`stream_displayed`), the statistics
    ///   text (`stats`), and the call-flow ladder layout
    ///   (`flow.ladder`) — each keyed on store generations plus the view
    ///   inputs that shape it; changed user inputs bypass the floor.
    /// * Updates `cached_dialog_count` / `cached_displayed_count`, clamps
    ///   the call-list and dashboard selections to the shrunk lists, and
    ///   applies sticky-bottom autoscroll (updating
    ///   `last_rendered_dialog_rows`).
    /// * Marks each rebuilt cache's `ChurnFloor`.
    fn sync_caches(&mut self) {
        // Quality dashboard: rebuild the snapshot outside the render pass
        // (render is read-only under the skip-tick contract). try_read so
        // a write-saturated capture skips the refresh, not the frame.
        if matches!(self.current_view, View::QualityDashboard)
            && let Some(ss) = self.stream_store.try_read()
        {
            let g = ss.generation();
            // First snapshot immediately; churn refreshes at the floor.
            let force = self.dashboard_snapshot.is_none();
            let stale = self.dashboard_generation != Some(g);
            if force || (stale && self.dashboard_floor.ready()) {
                let snap = dashboard::DashboardSnapshot::from_streams(&ss);
                self.dashboard_selected = self
                    .dashboard_selected
                    .min(snap.rows.len().saturating_sub(1));
                self.dashboard_snapshot = Some(snap);
                self.dashboard_generation = Some(g);
                self.dashboard_floor.mark();
            }
        }

        let Some(store) = self.dialog_store.try_read() else {
            return;
        };
        self.cached_dialog_count = store.len();

        let inputs_fresh = self.displayed.key.as_ref().is_some_and(|k| {
            k.filter_text == self.active_filter_text
                && k.query == self.search_query
                && k.sort_column == self.call_list.sort_column()
                && k.sort_ascending == self.call_list.sort_ascending()
        });
        let data_fresh = self
            .displayed
            .key
            .as_ref()
            .is_some_and(|k| k.generation == store.generation());
        // Generation churn alone (busy capture) refreshes at most once per
        // CHURN_REBUILD_MIN — between refreshes the cached list serves
        // the frame, so cursor movement never waits on a filter+sort pass.
        // A changed user input (filter/search/sort) always rebuilds now.
        let churn_floored = inputs_fresh && !self.displayed.floor.ready();
        let fresh = inputs_fresh && data_fresh;
        if !fresh && !churn_floored {
            self.displayed.ids = call_list::displayed_dialogs(
                &store,
                self.active_filter.as_ref(),
                &self.search_query,
                self.call_list.sort_column(),
                self.call_list.sort_ascending(),
            )
            .iter()
            .map(|d| d.call_id.clone())
            .collect();
            self.displayed.key = Some(DisplayedKey {
                generation: store.generation(),
                filter_text: self.active_filter_text.clone(),
                query: self.search_query.clone(),
                sort_column: self.call_list.sort_column(),
                sort_ascending: self.call_list.sort_ascending(),
            });
            self.displayed.floor.mark();
        }
        self.cached_displayed_count = self.displayed.ids.len();

        // Autoscroll: sticky-bottom. When enabled and the selection already
        // sits on the last row, newly arrived dialogs pull it to the new
        // bottom; a selection elsewhere is never yanked.
        if self.current_view == View::CallList {
            let displayed_len = self.displayed.ids.len();
            // A narrowed filter/search (or eviction) can strand the
            // selection past the new end; pull it back onto a real row.
            self.call_list.clamp_to(displayed_len);
            if self.call_list.autoscroll
                && self.last_rendered_dialog_rows > 0
                && displayed_len > self.last_rendered_dialog_rows
                && self.call_list.selected() + 1 >= self.last_rendered_dialog_rows
            {
                self.call_list.move_to_bottom(displayed_len);
            }
            self.last_rendered_dialog_rows = displayed_len;
        }

        // Stream-list rows (search + filter): derived here at most once
        // per churn floor. The render and every navigation clamp
        // previously re-filtered the whole stream store — under a
        // BLOCKING read — on each keypress.
        if self.current_view == View::StreamList
            && let Some(ss) = self.stream_store.try_read()
        {
            // The display filter matches through the associated dialog,
            // so dialog churn reshapes the list only when a filter is on.
            let dialog_generation = self.active_filter.as_ref().map(|_| store.generation());
            let inputs_fresh = self.stream_displayed.key.as_ref().is_some_and(|k| {
                k.filter_text == self.active_filter_text && k.query == self.search_query
            });
            let data_fresh = self.stream_displayed.key.as_ref().is_some_and(|k| {
                k.stream_generation == ss.generation() && k.dialog_generation == dialog_generation
            });
            let churn_floored = inputs_fresh && !self.stream_displayed.floor.ready();
            let fresh = inputs_fresh && data_fresh;
            if !fresh && !churn_floored {
                self.stream_displayed.keys = stream_list::displayed_streams(
                    ss.iter(),
                    Some(&store),
                    self.active_filter.as_ref(),
                    &self.search_query,
                )
                .iter()
                .map(|s| s.key.clone())
                .collect();
                self.stream_displayed.key = Some(StreamDisplayedKey {
                    stream_generation: ss.generation(),
                    dialog_generation,
                    filter_text: self.active_filter_text.clone(),
                    query: self.search_query.clone(),
                });
                self.stream_displayed.floor.mark();
            }
        }

        // Statistics text: a full-store aggregation, previously recomputed
        // on every frame while the view was open.
        if self.current_view == View::Statistics
            && let Some(ss) = self.stream_store.try_read()
        {
            let key = (store.generation(), ss.generation());
            let force = self.stats.key.is_none();
            let stale = self.stats.key != Some(key);
            if force || (stale && self.stats.floor.ready()) {
                self.stats.text = render::statistics_text(&store, &ss);
                self.stats.key = Some(key);
                self.stats.floor.mark();
            }
        }

        // CallFlow ladder cache (WS4.3c): the theme-free layout half is
        // derived at most once here, keyed on everything that shapes it
        // ([`LadderKey`]); the render pass only re-styles the cached rows.
        if let View::CallFlow(ref view_cid) = self.current_view {
            let cid = view_cid.clone();

            // RTP codec segments feed the layout only in the plain view
            // with RTP bars on; recompute them only when the stream store
            // structurally changed (on contention keep the previous ones).
            let mut stream_generation = None;
            if self.flow.show_rtp && !self.flow.extended {
                if let Some(ss) = self.stream_store.try_read() {
                    let g = ss.generation();
                    let same_cid = self
                        .flow
                        .ladder
                        .segs_key
                        .as_ref()
                        .is_some_and(|(c, _)| c == &cid);
                    let same = self
                        .flow
                        .ladder
                        .segs_key
                        .as_ref()
                        .is_some_and(|(c, gg)| c == &cid && *gg == g);
                    // Same dialog + stream churn only: adopt the new
                    // generation at the churn floor. A different dialog
                    // (user navigation) refreshes immediately.
                    if !same && (!same_cid || self.flow.ladder.churn.ready()) {
                        self.flow.ladder.rtp_segs = Self::rtp_codec_segments_from(&ss, &cid);
                        self.flow.ladder.segs_key = Some((cid.clone(), g));
                        self.flow.ladder.churn.mark();
                    }
                    stream_generation = self.flow.ladder.segs_key.as_ref().map(|(_, g)| *g);
                } else {
                    // Contended: reuse the segments (and their generation)
                    // the cache already holds so the ladder key still hits.
                    stream_generation = self.flow.ladder.segs_key.as_ref().map(|(_, g)| *g);
                }
            }

            let source = if self.flow.extended || !self.flow.merged_calls.is_empty() {
                // Extended legs / merged multi-selection can span the whole
                // store, so store changes must re-derive — but a busy store
                // bumps its generation every tick, which forced a full
                // multi-leg relayout per tick. Adopt a new generation at
                // most once per churn floor; between adoptions the held
                // generation keeps the ladder key (and layout) stable.
                let g_now = store.generation();
                let held = match &self.flow.ladder.key {
                    Some(k) if k.call_id == cid => match &k.source {
                        LadderSource::ExtendedStore(g) => Some(*g),
                        LadderSource::Dialog(..) => None,
                    },
                    _ => None,
                };
                let g = match held {
                    Some(h) if h != g_now && !self.flow.ladder.churn.ready() => h,
                    _ => g_now,
                };
                LadderSource::ExtendedStore(g)
            } else {
                match store.get(&cid) {
                    Some(d) => LadderSource::Dialog(d.messages.len(), d.updated_at),
                    // Dialog gone (evicted/cleared): an empty layout still
                    // gets cached so this doesn't rescan every tick.
                    None => LadderSource::Dialog(0, chrono::DateTime::<chrono::Utc>::MIN_UTC),
                }
            };
            let key = LadderKey {
                call_id: cid.clone(),
                source,
                transaction_filter: self.flow.transaction_filter.clone(),
                sdp_mode: self.sdp_display_mode,
                ts_mode: self.timestamp_mode,
                show_rtp: self.flow.show_rtp,
                name_mode: self.name_mode,
                resolver_generation: self.resolver.generation(),
                stream_generation,
                fold_expanded: self.flow.fold_expanded.clone(),
                merged_calls: self.flow.merged_calls.clone(),
            };
            if self.flow.ladder.key.as_ref() != Some(&key) {
                // Provenance travels with the layout: cleared here, filled
                // by the merged/extended branches that interleave dialogs.
                self.flow.ladder.index_map.clear();
                let (participants, rows) = if !self.flow.merged_calls.is_empty() {
                    // Merged multi-selection flow: every checked dialog's
                    // messages, chronological, with per-row provenance so
                    // drill-down opens the row's OWN dialog.
                    let mut tagged: Vec<(&crate::sip::SipMessage, (String, usize))> = Vec::new();
                    for mcid in &self.flow.merged_calls {
                        if let Some(d) = store.get(mcid) {
                            tagged.extend(
                                d.messages
                                    .iter()
                                    .enumerate()
                                    .map(|(i, m)| (m, (mcid.clone(), i))),
                            );
                        }
                    }
                    // Sort references (the timestamp key is Copy) and clone
                    // each message once AFTER the sort, mirroring the extended
                    // branch — the sort no longer shuffles full SipMessages.
                    tagged.sort_by_key(|(m, _)| m.timestamp);
                    let (owned, index_map): (Vec<crate::sip::SipMessage>, Vec<(String, usize)>) =
                        tagged.into_iter().map(|(m, t)| (m.clone(), t)).unzip();
                    self.flow.ladder.index_map = index_map;
                    if owned.is_empty() {
                        (Vec::new(), Vec::new())
                    } else {
                        let lopts = call_flow::LayoutOptions {
                            sdp_mode: self.sdp_display_mode,
                            ts_mode: self.timestamp_mode,
                            // Merged view spans dialogs: no RTP bars (the
                            // cached segments belong to one dialog) and no
                            // single-dialog PDD note.
                            show_rtp: false,
                            resolver: self.resolver.as_ref(),
                            name_mode: self.name_mode,
                            rtp_segments: &[],
                        };
                        call_flow::layout(
                            &owned,
                            owned[0].timestamp,
                            None,
                            &lopts,
                            &self.flow.fold_expanded,
                        )
                    }
                } else if self.flow.extended {
                    // Extended: merge all correlated legs (only on a miss).
                    match store.get(&cid) {
                        Some(d) => {
                            let mut all: Vec<(&crate::sip::SipMessage, (String, usize))> = d
                                .messages
                                .iter()
                                .enumerate()
                                .map(|(i, m)| (m, (cid.clone(), i)))
                                .collect();
                            let correlated = store.find_correlated(&cid);
                            for leg in &correlated {
                                all.extend(
                                    leg.messages
                                        .iter()
                                        .enumerate()
                                        .map(|(i, m)| (m, (leg.call_id.clone(), i))),
                                );
                            }
                            all.sort_by_key(|(m, _)| m.timestamp);
                            let (owned, index_map): (
                                Vec<crate::sip::SipMessage>,
                                Vec<(String, usize)>,
                            ) = all.into_iter().map(|(m, t)| (m.clone(), t)).unzip();
                            self.flow.ladder.index_map = index_map;
                            if owned.is_empty() {
                                (Vec::new(), Vec::new())
                            } else {
                                let lopts = call_flow::LayoutOptions {
                                    sdp_mode: self.sdp_display_mode,
                                    ts_mode: self.timestamp_mode,
                                    // Extended/combined view draws no RTP bars.
                                    show_rtp: false,
                                    resolver: self.resolver.as_ref(),
                                    name_mode: self.name_mode,
                                    rtp_segments: &[],
                                };
                                call_flow::layout(
                                    &owned,
                                    owned[0].timestamp,
                                    None,
                                    &lopts,
                                    &self.flow.fold_expanded,
                                )
                            }
                        }
                        None => (Vec::new(), Vec::new()),
                    }
                } else {
                    match store.get(&cid) {
                        Some(d) => {
                            // Transaction filter (R5a): when active, show only
                            // the anchored transaction's messages. A stale key
                            // that matches nothing falls back to the dialog.
                            let filtered: Option<Vec<crate::sip::SipMessage>> =
                                self.flow.transaction_filter.as_ref().and_then(|key| {
                                    let v: Vec<crate::sip::SipMessage> = d
                                        .messages
                                        .iter()
                                        .filter(|m| {
                                            call_flow::transaction_key(m).as_ref() == Some(key)
                                        })
                                        .cloned()
                                        .collect();
                                    (!v.is_empty()).then_some(v)
                                });
                            let msgs_ref: &[crate::sip::SipMessage] =
                                filtered.as_deref().unwrap_or(&d.messages);
                            if msgs_ref.is_empty() {
                                (Vec::new(), Vec::new())
                            } else {
                                let lopts = call_flow::LayoutOptions {
                                    sdp_mode: self.sdp_display_mode,
                                    ts_mode: self.timestamp_mode,
                                    show_rtp: self.flow.show_rtp,
                                    resolver: self.resolver.as_ref(),
                                    name_mode: self.name_mode,
                                    rtp_segments: &self.flow.ladder.rtp_segs,
                                };
                                call_flow::layout(
                                    msgs_ref,
                                    msgs_ref[0].timestamp,
                                    d.timing.pdd_ms(),
                                    &lopts,
                                    &self.flow.fold_expanded,
                                )
                            }
                        }
                        None => (Vec::new(), Vec::new()),
                    }
                };
                self.flow.ladder.participants = participants;
                self.flow.ladder.rows = rows;
                self.flow.ladder.key = Some(key);
                self.flow.ladder.churn.mark();
            }
        }
    }

    /// Write back the geometry- and content-dependent values a render pass
    /// computed (clamped scrolls, call-flow row caches). Applied by the
    /// event loop right after `terminal.draw`, which is the same point in
    /// the frame timeline the render pass used to write them directly.
    ///
    /// # Arguments
    ///
    /// * `fb` — the feedback produced by `render_app`; `None` fields left
    ///   by views that didn't render are skipped, so unrelated state is
    ///   never clobbered.
    ///
    /// # Side effects
    ///
    /// Overwrites the scroll offsets (stream detail, flow ladder/detail,
    /// raw message, diff, help, statistics), the call-flow detail pane's
    /// h-scroll headroom, and the call-flow row caches
    /// (`cached_msg_count`, `cached_rtp_bar_indices`,
    /// `cached_raw_indices`) for each `Some` field.
    /// Whether `bpf_filter` describes the live capture rather than what is
    /// currently displayed (#190).
    pub(in crate::tui) fn bpf_is_live_only(&self) -> bool {
        self.bpf_is_live_only
    }

    /// Record that an in-session file open replaced what is on screen, so the
    /// BPF slot must say which source its filter belongs to.
    ///
    /// One-way on purpose: the live capture is still running and its filter
    /// still applies to it, so there is no state in which the mark becomes
    /// wrong again. Clearing it on some later event would be inventing a
    /// transition that does not exist.
    pub(in crate::tui) fn mark_bpf_live_only(&mut self) {
        self.bpf_is_live_only = true;
    }

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
        if let Some(v) = fb.flow_detail_hscroll {
            self.flow.detail_hscroll = v;
        }
        // Kept as the render measured it, including 0 ("the message fits"):
        // that is precisely the case the controller has to explain rather
        // than swallow (#188).
        if let Some(v) = fb.flow_detail_max_hscroll {
            self.flow_detail_max_hscroll = Some(v);
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
    ///
    /// # Arguments
    ///
    /// * `call_id` — Call-ID of the dialog whose linked streams to scan.
    ///
    /// # Returns
    ///
    /// Codec segments sorted by start time; empty only when no linked
    /// stream carries a resolved codec.
    fn rtp_codec_segments(&self, call_id: &str) -> Vec<call_flow::RtpCodecSegment> {
        // Blocking read: the only caller is the Mermaid export path, which
        // is not frame-rate-critical — an export must never silently drop
        // RTP segments because the processing thread transiently held the
        // write lock. (The ladder render never calls this; it re-styles
        // the segments cached by `sync_caches`.) Acquired dialog→stream,
        // the same order as every other multi-lock site.
        let store = self.stream_store.read();
        Self::rtp_codec_segments_from(&store, call_id)
    }

    /// Build sorted RTP codec segments for `call_id` from an already-acquired
    /// stream store. Shared by [`Self::rtp_codec_segments`] (the blocking
    /// export path) and the `sync_caches` ladder cache, which holds a
    /// non-blocking read guard and must not re-lock the store.
    fn rtp_codec_segments_from(
        store: &StreamStore,
        call_id: &str,
    ) -> Vec<call_flow::RtpCodecSegment> {
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

    /// Reset every UI-cache churn floor: called on discrete completion
    /// events (background pcap load landing) so the next tick re-derives
    /// everything immediately instead of up to a floor later.
    pub(in crate::tui) fn clear_churn_floors(&mut self) {
        self.displayed.floor.clear();
        self.stream_displayed.floor.clear();
        self.stats.floor.clear();
        self.dashboard_floor.clear();
        self.flow.ladder.churn.clear();
    }

    /// Compute the poll timeout based on how recently data was updated.
    ///
    /// # Returns
    ///
    /// `ACTIVE_POLL_MS` while the last data update is within
    /// `IDLE_THRESHOLD`, else the slower `IDLE_POLL_MS`.
    fn poll_timeout(&self) -> Duration {
        if self.last_data_update.elapsed() < IDLE_THRESHOLD {
            Duration::from_millis(ACTIVE_POLL_MS)
        } else {
            Duration::from_millis(IDLE_POLL_MS)
        }
    }

    /// Reconcile the adaptive poll cadence with a dialog-store read attempt.
    ///
    /// `count` is the store length from a non-blocking `try_read`, or `None`
    /// when that read failed because a writer holds the lock. Both fresh data
    /// (a changed count) and a failed read under contention mean the capture
    /// is active, so both keep the fast poll cadence; only a successful,
    /// unchanged read is genuinely idle and leaves the timer alone.
    ///
    /// Keeping this a pure function of the `try_read` outcome lets the busy
    /// case be pinned without real timing: a `None` must never be conflated
    /// with "no change / idle", or a sustained busy capture (which starves
    /// the non-blocking read) would sink the UI into the slow idle poll.
    fn reconcile_dialog_count(&mut self, count: Option<usize>) {
        match count {
            Some(count) => {
                if count != self.last_known_dialog_count {
                    self.last_known_dialog_count = count;
                    self.mark_data_updated();
                }
            }
            // try_read failed: a writer holds the lock → the capture is busy.
            // Contention is activity, so stay in the responsive cadence.
            None => self.mark_data_updated(),
        }
    }
}

// ── Render tick ─────────────────────────────────────────────────────

/// One render tick: draw the frame from a consistent read snapshot of
/// both stores, or — when the processing thread holds (or is queued on)
/// either write lock — skip the tick entirely. Returns whether a frame
/// was drawn.
///
/// Skipping must happen BEFORE `Terminal::draw`: ratatui resets the back
/// buffer after every completed frame, so a frame rendered without store
/// access flushes a blank main pane which the next frame repaints — a
/// visible flicker every time the render tick lost the try_read race on
/// a busy capture. An aborted tick flushes nothing, and the previous
/// frame stays on screen.
///
/// After `FORCED_DRAW_AFTER_SKIPS` consecutive skips the tick takes
/// blocking reads instead, so a write-saturated capture degrades to a
/// briefly stale frame, never a frozen UI. Acquisition is always
/// dialog→stream, the same order as every other multi-lock site.
///
/// # Arguments
///
/// * `terminal` — the ratatui terminal to draw into.
/// * `app` — application state; read for rendering, mutated for the
///   skip counter and render feedback.
///
/// # Returns
///
/// `Ok(true)` when a frame was drawn, `Ok(false)` when the tick was
/// skipped on lock contention.
///
/// # Errors
///
/// Propagates the backend's draw error (terminal write failure).
///
/// # Side effects
///
/// Takes read locks on both stores (non-blocking, or blocking once the
/// skip threshold is reached); increments `app.contended_skips` on a
/// skip and resets it on success; flushes a frame to the terminal; and
/// applies the render feedback (scroll clamps, flow row caches) to
/// `app`.
fn draw_frame<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<bool, B::Error> {
    let dialogs = app.dialog_store.clone();
    let streams = app.stream_store.clone();
    let guards = if app.contended_skips >= FORCED_DRAW_AFTER_SKIPS {
        Some((dialogs.read(), streams.read()))
    } else {
        dialogs.try_read().zip(streams.try_read())
    };
    let Some((ds, ss)) = guards else {
        app.contended_skips += 1;
        return Ok(false);
    };
    app.contended_skips = 0;
    let mut fb = RenderFeedback::default();
    terminal.draw(|frame| fb = render_app(frame, app, &ds, &ss))?;
    app.apply_render_feedback(fb);
    Ok(true)
}

// ── Terminal guard ──────────────────────────────────────────────────

/// RAII guard that restores the terminal on drop, even during panics.
struct TerminalGuard;

impl Drop for TerminalGuard {
    /// Restore the terminal: disable mouse capture, re-show the cursor,
    /// leave the alternate screen and drop raw mode (errors ignored —
    /// there is no recovery path during teardown), then tell the crash
    /// hook the terminal is sane so it won't restore twice.
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
        // The terminal is sane again; the crash hook must not restore twice.
        crate::crash::set_terminal_raw(false);
    }
}

// ── Public entry point ──────────────────────────────────────────────

/// Run the TUI with an optional shared pause flag.
///
/// When `paused_flag` is `Some`, the flag is shared with the processing
/// thread so that toggling pause in the TUI also pauses packet processing.
/// Takes ownership of the calling thread until the user quits.
///
/// # Arguments
///
/// * `dialog_store` — Shared dialog store, updated by the processing thread.
/// * `stream_store` — Shared stream store, updated by the processing thread.
/// * `paused_flag` — Pause flag shared with the processing thread; `None`
///   keeps pause TUI-local.
/// * `options` — Theme, keymap, visible columns, name wiring and From/To
///   mode resolved from config/CLI.
///
/// # Returns
///
/// `Ok(())` after the user quits and the terminal is restored.
///
/// # Errors
///
/// Returns an error if enabling raw mode, entering the alternate screen,
/// constructing the terminal, drawing a frame, or polling/reading input
/// events fails.
///
/// # Side effects
///
/// * Terminal: enables raw mode, enters the alternate screen, enables
///   mouse capture (F12 toggles it at runtime for native drag-to-select),
///   hides the cursor; arms the crash hook
///   (`crate::crash::set_terminal_raw`) and an RAII guard so all of it is
///   undone on return or panic.
/// * Logs keymap collision warnings via `tracing::warn` and surfaces the
///   first one on the status line.
/// * Runs the event loop each tick: polls background pcap loads, drains
///   worker messages, syncs store-derived caches (store read locks),
///   draws frames, runs deferred saves/audio playback, and drains all
///   queued key/mouse events before the next redraw.
pub fn run_tui_with_pause(
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    paused_flag: Option<Arc<AtomicBool>>,
    options: TuiOptions,
) -> Result<()> {
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
    // Let the crash hook know it must undo raw mode / mouse capture
    // before printing a panic: release builds abort without unwinding,
    // so the Drop guard below never runs there.
    crate::crash::set_terminal_raw(true);

    // Guard ensures terminal is restored even on panic
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Every resolved option reaches the App through one function, which the
    // snapshot suite calls too — an option that arrives here and is never
    // handed on renders as an empty slot and nothing else, which is how the
    // BPF filter went unwired for the life of the status bar.
    let mut app = options.into_app(dialog_store, stream_store);
    if let Some(flag) = paused_flag {
        app.paused_flag = flag;
    }
    // The F10 column selector's `s` saves into the user's sipnabrc.
    app.set_column_config_path(crate::config::default_user_config_path());

    // Dead rebinds (duplicates, or shadowed by a view's built-in key) used
    // to fail silently; warn on stderr and in the status line at startup.
    let keymap_warnings = app.keymap.collisions();
    for warning in &keymap_warnings {
        tracing::warn!("{warning}");
    }
    if let Some(first) = keymap_warnings.first() {
        app.status_error = Some(first.clone());
    }

    // Terminal-side mouse-capture state, reconciled with the F12 toggle
    // flag after each input drain (the controller layer only flips the
    // flag; all terminal I/O stays here).
    let mut mouse_captured = true;

    // Main event loop
    loop {
        if app.should_quit {
            break;
        }

        // Background work: apply a finished pcap load (or refresh its
        // progress line) and drain detached-worker completion messages.
        controllers::poll_pcap_load(&mut app);
        app.drain_async_messages();

        // Tick: refresh store-derived caches, render read-only, then
        // persist what the render pass computed (clamps, flow row caches).
        app.sync_caches();
        let drew = draw_frame(&mut terminal, &mut app)?;

        // Deferred work runs here, AFTER the frame that painted its
        // "Saving…"/"Decoding…" status — the work itself may block. A
        // contended tick drew no frame, so the status isn't on screen
        // yet: hold the work until one draws (bounded — draw_frame
        // forces a blocking frame after FORCED_DRAW_AFTER_SKIPS skips).
        if drew {
            app.run_pending_save();
            app.run_pending_audio();
        }

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

        // Apply an F12 mouse-capture toggle to the terminal. While capture
        // is off the terminal's native drag-to-select works (wheel
        // scrolling pauses); the restore paths (guard drop + crash hook)
        // stay unconditional — crossterm's DisableMouseCapture just writes
        // the reset sequences, harmless when capture is already off.
        if app.mouse_capture_enabled != mouse_captured {
            if app.mouse_capture_enabled {
                execute!(io::stdout(), crossterm::event::EnableMouseCapture)?;
            } else {
                execute!(io::stdout(), crossterm::event::DisableMouseCapture)?;
            }
            mouse_captured = app.mouse_capture_enabled;
        }

        // Feed the adaptive cadence: a changed count is fresh data, and a
        // failed try_read means a writer holds the lock (busy capture) —
        // both keep active polling. Only a successful, unchanged read is
        // idle, so a static pcap still relaxes to the slow poll.
        let current_count = app.dialog_store.try_read().map(|ds| ds.len());
        app.reconcile_dialog_count(current_count);
    }

    Ok(())
}

/// Unit tests for the App event-loop contracts: cache churn floors,
/// contended-store render ticks, multi-selection flows, filter/search
/// visibility, and the display-mode enum cycles.
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

    /// A fresh App starts on the call-list view with the quit flag clear.
    #[test]
    fn app_default_view_is_call_list() {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let app = App::new(ds, ss, Theme::default(), Keymap::default());
        assert_eq!(app.current_view, View::CallList);
        assert!(!app.should_quit);
    }

    /// WS4.3: one frame derives the displayed dialog list AT MOST once,
    /// and an unchanged store + unchanged view inputs mean the next frame
    /// derives it ZERO times (cache hit keyed on the store generation).
    #[test]
    fn call_list_frame_derives_displayed_rows_at_most_once() {
        use controllers::test_support::{base_ts, make_invite};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![
            make_invite("once-1@test", "1001", "1002", base_ts()),
            make_invite("once-2@test", "1003", "1004", base_ts()),
        ]);
        let calls = || call_list::DISPLAYED_DIALOGS_CALLS.with(|c| c.get());
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        let before = calls();
        terminal.draw(|f| app.render(f)).unwrap();
        let first = calls() - before;
        assert!(
            first <= 1,
            "one frame must derive the displayed list at most once, did {first}x"
        );

        let mid = calls();
        terminal.draw(|f| app.render(f)).unwrap();
        assert_eq!(
            calls() - mid,
            0,
            "unchanged data: the next frame must reuse the cached list"
        );
    }

    /// A busy capture bumps the store generation on every ingest, so on a
    /// loaded server EVERY tick — including the one right after each arrow
    /// keypress — re-derived the displayed list (full filter-DSL pass +
    /// sort + call-id clones over the whole store). Cursor movement paid
    /// tens-to-hundreds of ms per keypress. Contract: data churn alone
    /// refreshes the list at most once per DISPLAYED_REBUILD_MIN; between
    /// refreshes the cached list serves the frame.
    #[test]
    fn busy_generation_churn_does_not_rederive_displayed_list_per_tick() {
        use controllers::test_support::{base_ts, make_invite};
        let mut app = App::with_processed_messages(vec![make_invite(
            "busy-0@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        let calls = || call_list::DISPLAYED_DIALOGS_CALLS.with(|c| c.get());
        app.sync_caches(); // initial derivation

        let ds = app.dialog_store.clone();
        let before = calls();
        for i in 1..=5 {
            ds.write().process_message(make_invite(
                &format!("busy-{i}@test"),
                "1001",
                "1002",
                base_ts(),
            ));
            app.sync_caches(); // the tick that follows a keypress
        }
        assert_eq!(
            calls() - before,
            0,
            "generation churn within the rebuild floor must serve the \
             cached list, not re-derive it every tick"
        );

        // Once the floor elapses the next tick picks up the churned data.
        app.elapse_churn_floors_for_test();
        let before = calls();
        app.sync_caches();
        assert_eq!(calls() - before, 1, "floor elapsed: refresh expected");
        assert_eq!(
            app.cached_displayed_count, 6,
            "the refresh must pick up dialogs ingested while throttled"
        );
    }

    /// Explicit user actions must never be throttled: changing the search
    /// query (or filter/sort — same key) re-derives immediately even when
    /// the churn floor has not elapsed.
    #[test]
    fn user_input_changes_bypass_the_displayed_rebuild_floor() {
        use controllers::test_support::{base_ts, make_invite};
        let mut app = App::with_processed_messages(vec![
            make_invite("bypass-1@test", "1001", "1002", base_ts()),
            make_invite("bypass-2@test", "2001", "2002", base_ts()),
        ]);
        let calls = || call_list::DISPLAYED_DIALOGS_CALLS.with(|c| c.get());
        app.sync_caches(); // initial derivation — floor starts now

        app.search_query = "1001".into();
        let before = calls();
        app.sync_caches();
        assert_eq!(
            calls() - before,
            1,
            "a changed user input must re-derive immediately, floor or not"
        );
        assert_eq!(app.cached_displayed_count, 1, "search narrowed the list");
    }

    /// Insert one synthetic RTP stream (unique SSRC/ports per `i`).
    fn push_rtp_stream(ss: &mut crate::rtp::stream_store::StreamStore, i: u16) {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let parsed = crate::capture::ParsedPacket {
            frame: None,
            timestamp: ts,
            src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 20000 + i * 2,
            dst_port: 30000 + i * 2,
            transport: crate::capture::parse::TransportProto::Udp,
            payload: vec![0u8; 172].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        };
        let rtp = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xBBBB_0000 + u32::from(i),
            payload_offset: 12,
        };
        ss.process_rtp(&parsed, &rtp, ts);
    }

    /// Stream list, same contract as the call list: stream-store churn
    /// alone must not re-filter the store per tick, keypresses must
    /// navigate the cached rows (they used to re-filter under a BLOCKING
    /// read per keypress), and a user input change bypasses the floor.
    #[test]
    fn stream_list_churn_and_keypresses_do_not_rederive_displayed() {
        use crossterm::event::KeyCode;
        let mut app = App::new_test();
        {
            let ss = app.stream_store.clone();
            let mut ss = ss.write();
            push_rtp_stream(&mut ss, 0);
            push_rtp_stream(&mut ss, 1);
            push_rtp_stream(&mut ss, 2);
        }
        app.current_view = View::StreamList;
        let calls = || stream_list::DISPLAYED_STREAMS_CALLS.with(|c| c.get());
        app.sync_caches(); // initial derivation
        assert_eq!(app.stream_displayed.keys.len(), 3);

        let before = calls();
        for i in 3..6 {
            app.stream_store.clone().write().process_rtp(
                &crate::capture::ParsedPacket {
                    frame: None,
                    timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                    src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                    dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                    src_port: 20000 + i * 2,
                    dst_port: 30000 + i * 2,
                    transport: crate::capture::parse::TransportProto::Udp,
                    payload: vec![0u8; 172].into(),
                    ip_id: None,
                    tcp_seq: None,
                    tcp_flags: None,
                    fragment_offset: None,
                    more_fragments: false,
                    ip_protocol: 17,
                    from_hep: false,
                },
                &crate::rtp::parser::RtpHeader {
                    version: 2,
                    padding: false,
                    extension: false,
                    csrc_count: 0,
                    marker: false,
                    payload_type: 0,
                    sequence: 1,
                    timestamp: 0,
                    ssrc: 0xBBBB_0000 + u32::from(i),
                    payload_offset: 12,
                },
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            );
            app.handle_key(KeyCode::Down); // navigates + settles a tick
            app.sync_caches();
        }
        assert_eq!(
            calls() - before,
            0,
            "stream churn within the floor (and keypresses) must not \
             re-filter the store"
        );
        assert_eq!(
            app.stream_list.selected(),
            2,
            "keypresses must navigate the cached rows"
        );

        // Floor elapses: next tick picks up the churned streams.
        app.elapse_churn_floors_for_test();
        let before = calls();
        app.sync_caches();
        assert_eq!(calls() - before, 1, "floor elapsed: refresh expected");
        assert_eq!(app.stream_displayed.keys.len(), 6);

        // A user input (search) bypasses the floor immediately.
        {
            let ss = app.stream_store.clone();
            let mut ss = ss.write();
            push_rtp_stream(&mut ss, 7);
        }
        app.search_query = "bbbb0000".into();
        let before = calls();
        app.sync_caches();
        assert_eq!(calls() - before, 1, "changed search must re-derive now");
        assert_eq!(
            app.stream_displayed.keys.len(),
            1,
            "search narrowed to SSRC BBBB0000"
        );
    }

    /// E (Mermaid export) reads codec segments while the processing
    /// thread may hold the stream-store write lock. A `try_read` miss
    /// used to return an EMPTY segment list, silently exporting a
    /// diagram without any RTP segments. The export path is not
    /// frame-rate-critical: it must wait out transient contention and
    /// never drop segments.
    #[test]
    fn rtp_codec_segments_survive_stream_store_write_contention() {
        let app = App::new_test();
        {
            let ss = app.stream_store.clone();
            let mut ss = ss.write();
            push_rtp_stream(&mut ss, 0);
            ss.link_to_dialog(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                30000,
                "contended@test",
            );
        }
        assert_eq!(
            app.rtp_codec_segments("contended@test").len(),
            1,
            "fixture sanity: one linked PCMU stream uncontended"
        );

        // Simulate the processing thread mid-ingest: hold the write lock
        // on another thread for a bounded window spanning the export's
        // read. The signal guarantees the lock is held when we read.
        let ss = app.stream_store.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let _w = ss.write();
            locked_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        locked_rx.recv().unwrap();
        let segs = app.rtp_codec_segments("contended@test");
        writer.join().unwrap();
        assert_eq!(
            segs.len(),
            1,
            "export must never silently drop RTP segments on transient \
             stream-store lock contention"
        );
    }

    /// Selection resolution (Enter → stream detail, naming) must resolve
    /// from the cached display order, lock-free — index into the cache.
    #[test]
    fn stream_selection_resolves_from_cached_order() {
        let mut app = App::new_test();
        {
            let ss = app.stream_store.clone();
            let mut ss = ss.write();
            push_rtp_stream(&mut ss, 0);
            push_rtp_stream(&mut ss, 1);
        }
        app.current_view = View::StreamList;
        app.sync_caches();
        app.stream_list.move_down(app.stream_displayed.keys.len());
        let key = controllers::get_selected_stream_key(&app).expect("selected stream");
        assert_eq!(key, app.stream_displayed.keys[1]);
        // Selection past the cached end (evicted rows): no panic, None.
        app.stream_list.move_to_bottom(100);
        assert_eq!(controllers::get_selected_stream_key(&app), None);
    }

    /// Quality dashboard: stream churn refreshes the snapshot at the
    /// floor, never per tick; the first snapshot after opening the view
    /// is immediate.
    #[test]
    fn dashboard_snapshot_churn_is_floored() {
        let mut app = App::new_test();
        {
            let ss = app.stream_store.clone();
            let mut ss = ss.write();
            push_rtp_stream(&mut ss, 0);
        }
        app.current_view = View::QualityDashboard;
        app.sync_caches(); // first snapshot: immediate
        let rows = app
            .dashboard_snapshot
            .as_ref()
            .expect("snapshot")
            .rows
            .len();
        assert_eq!(rows, 1);

        {
            let ss = app.stream_store.clone();
            let mut ss = ss.write();
            push_rtp_stream(&mut ss, 1);
        }
        app.sync_caches();
        assert_eq!(
            app.dashboard_snapshot.as_ref().unwrap().rows.len(),
            1,
            "churn within the floor must keep serving the cached snapshot"
        );

        app.elapse_churn_floors_for_test();
        app.sync_caches();
        assert_eq!(
            app.dashboard_snapshot.as_ref().unwrap().rows.len(),
            2,
            "floor elapsed: snapshot must pick up the new stream"
        );
    }

    /// Statistics view: the aggregate text is derived at the floor, not
    /// per tick (it walks every dialog).
    #[test]
    fn statistics_text_churn_is_floored() {
        use controllers::test_support::{base_ts, make_invite};
        let mut app = App::with_processed_messages(vec![make_invite(
            "stats-1@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        app.current_view = View::Statistics;
        app.sync_caches();
        assert!(
            app.stats.text.contains("Dialogs:           1"),
            "first derivation is immediate: {}",
            app.stats.text
        );

        app.dialog_store
            .clone()
            .write()
            .process_message(make_invite("stats-2@test", "1003", "1004", base_ts()));
        app.sync_caches();
        assert!(
            app.stats.text.contains("Dialogs:           1"),
            "churn within the floor must keep the cached text"
        );

        app.elapse_churn_floors_for_test();
        app.sync_caches();
        assert!(
            app.stats.text.contains("Dialogs:           2"),
            "floor elapsed: text must pick up the new dialog: {}",
            app.stats.text
        );
    }

    /// Extended/merged call-flow: a busy store must not force a full
    /// multi-leg relayout every tick — the ladder key holds the adopted
    /// store generation until the churn floor elapses.
    #[test]
    fn extended_ladder_holds_store_generation_under_churn() {
        use controllers::test_support::{base_ts, make_invite};
        let mut app = App::with_processed_messages(vec![make_invite(
            "ext-1@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        app.current_view = View::CallFlow("ext-1@test".to_string());
        app.flow.extended = true;
        app.sync_caches();
        let g0 = match &app.flow.ladder.key {
            Some(LadderKey {
                source: LadderSource::ExtendedStore(g),
                ..
            }) => *g,
            other => panic!("expected extended ladder key, got {other:?}"),
        };

        app.dialog_store
            .clone()
            .write()
            .process_message(make_invite("ext-2@test", "1003", "1004", base_ts()));
        app.sync_caches();
        match &app.flow.ladder.key {
            Some(LadderKey {
                source: LadderSource::ExtendedStore(g),
                ..
            }) => assert_eq!(
                *g, g0,
                "store churn within the floor must hold the adopted generation"
            ),
            other => panic!("expected extended ladder key, got {other:?}"),
        }

        app.elapse_churn_floors_for_test();
        app.sync_caches();
        match &app.flow.ladder.key {
            Some(LadderKey {
                source: LadderSource::ExtendedStore(g),
                ..
            }) => assert!(
                *g > g0,
                "floor elapsed: the new store generation must be adopted"
            ),
            other => panic!("expected extended ladder key, got {other:?}"),
        }
    }

    // ── Contended-store render ticks (busy-capture flicker) ────────
    //
    // ratatui resets the back buffer after every completed frame, so a
    // frame whose main view silently skips rendering (store lock lost to
    // the processing thread) flushes a BLANK pane and the next frame
    // repaints it — a visible flicker every few seconds on a busy box.
    // The contract: a contended tick skips the whole frame (nothing is
    // flushed, previous frame stays on screen), and sustained contention
    // eventually forces a blocking frame instead of starving the UI.

    /// Concatenate every cell symbol of the test backend's buffer into one
    /// string, for substring assertions on the rendered frame.
    fn backend_text(terminal: &Terminal<ratatui::backend::TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    /// A tick under a contended dialog-store write lock skips the frame
    /// and leaves the previous frame on screen (no blank flash).
    #[test]
    fn contended_dialog_write_lock_must_not_blank_the_frame() {
        use controllers::test_support::{base_ts, make_invite};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![make_invite(
            "flicker@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        app.sync_caches();
        assert!(draw_frame(&mut terminal, &mut app).unwrap());
        let before = terminal.backend().buffer().clone();
        assert!(
            backend_text(&terminal).contains("1001"),
            "sanity: the call row is on screen before contention"
        );

        // The processing thread holds the write lock for this whole tick.
        let ds = app.dialog_store.clone();
        let _writer = ds.write();
        app.sync_caches(); // the real loop runs this every tick too
        let drew = draw_frame(&mut terminal, &mut app).unwrap();
        assert!(!drew, "a tick under a contended store must skip the frame");
        assert_eq!(
            terminal.backend().buffer(),
            &before,
            "a skipped tick must leave the previous frame on screen (no blank flash)"
        );
    }

    /// A contended stream-store write lock also skips the whole frame —
    /// rendering needs a consistent snapshot of BOTH stores or none.
    #[test]
    fn contended_stream_write_lock_also_skips_the_frame() {
        use controllers::test_support::{base_ts, make_invite};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![make_invite(
            "flicker-ss@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        app.sync_caches();
        assert!(draw_frame(&mut terminal, &mut app).unwrap());
        let before = terminal.backend().buffer().clone();

        let ss = app.stream_store.clone();
        let _writer = ss.write();
        let drew = draw_frame(&mut terminal, &mut app).unwrap();
        assert!(
            !drew,
            "the frame renders from a consistent snapshot of BOTH stores or not at all"
        );
        assert_eq!(terminal.backend().buffer(), &before);
    }

    /// Contention on the very first tick (nothing drawn yet) skips
    /// without panicking or flushing anything.
    #[test]
    fn first_tick_under_contention_skips_cleanly() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::new_test();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let ds = app.dialog_store.clone();
        let _writer = ds.write();
        // Nothing drawn yet: skipping must not panic or flush anything.
        assert!(!draw_frame(&mut terminal, &mut app).unwrap());
    }

    /// Once contention clears the next tick draws again, and the
    /// successful draw resets the skip counter (a stale counter would
    /// force a blocking read and deadlock on the same-thread guard).
    #[test]
    fn tick_after_contention_clears_redraws_and_resets_the_skip_counter() {
        use controllers::test_support::{base_ts, make_invite};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![make_invite(
            "recover@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        app.sync_caches();
        assert!(draw_frame(&mut terminal, &mut app).unwrap());

        let ds = app.dialog_store.clone();
        {
            let _writer = ds.write();
            assert!(!draw_frame(&mut terminal, &mut app).unwrap());
        }
        // Contention cleared: the next tick draws again.
        assert!(draw_frame(&mut terminal, &mut app).unwrap());
        assert!(backend_text(&terminal).contains("1001"));
        // And the successful draw reset the skip counter: a fresh
        // contended tick skips (a stale counter would block forever here,
        // deadlocking on the same-thread write guard).
        let _writer = ds.write();
        assert!(!draw_frame(&mut terminal, &mut app).unwrap());
    }

    /// After FORCED_DRAW_AFTER_SKIPS consecutive skipped ticks, the next
    /// tick takes blocking reads and draws — contention never starves
    /// the UI indefinitely.
    #[test]
    fn sustained_contention_forces_a_blocking_frame() {
        use controllers::test_support::{base_ts, make_invite};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![make_invite(
            "starve@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        app.sync_caches();
        assert!(draw_frame(&mut terminal, &mut app).unwrap());

        let ds = app.dialog_store.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let guard = ds.write();
            locked_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(guard);
        });
        locked_rx.recv().unwrap();
        for _ in 0..FORCED_DRAW_AFTER_SKIPS {
            assert!(
                !draw_frame(&mut terminal, &mut app).unwrap(),
                "ticks under contention skip while below the force threshold"
            );
        }
        // The next tick refuses to starve: it takes blocking reads and
        // draws as soon as the writer releases.
        assert!(draw_frame(&mut terminal, &mut app).unwrap());
        writer.join().unwrap();
    }

    /// WS4.3c: one CallFlow frame lays out the ladder AT MOST once; an
    /// unchanged dialog + unchanged layout inputs mean the next frame lays
    /// out ZERO times (style-only inputs like the color mode re-style the
    /// cached layout); a store mutation re-derives exactly once.
    #[test]
    fn call_flow_frame_lays_out_ladder_at_most_once() {
        use controllers::test_support::{base_ts, make_invite, make_ok};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![make_invite(
            "flow-1@test",
            "1001",
            "1002",
            base_ts(),
        )]);
        app.current_view = View::CallFlow("flow-1@test".to_string());
        let calls = || call_flow::prepare::LAYOUT_CALLS.with(|c| c.get());
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        let before = calls();
        terminal.draw(|f| app.render(f)).unwrap();
        let first = calls() - before;
        assert!(
            first <= 1,
            "one frame must lay out the ladder at most once, did {first}x"
        );

        let mid = calls();
        terminal.draw(|f| app.render(f)).unwrap();
        assert_eq!(
            calls() - mid,
            0,
            "unchanged data: the next frame must reuse the cached layout"
        );

        // Style-only input change: re-style the cached layout, no re-layout.
        app.color_mode = ColorMode::CallId;
        terminal.draw(|f| app.render(f)).unwrap();
        assert_eq!(
            calls() - mid,
            0,
            "a color-mode change is style-only and must not re-layout"
        );

        // A store mutation must re-derive the layout exactly once.
        app.dialog_store.write().process_message(make_ok(
            "flow-1@test",
            base_ts() + chrono::TimeDelta::seconds(1),
        ));
        terminal.draw(|f| app.render(f)).unwrap();
        assert_eq!(
            calls() - mid,
            1,
            "a dialog mutation must re-derive the layout exactly once"
        );
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

        // Two more dialogs arrive; the churn floor elapses before the next
        // tick (sticky-bottom follows at the refresh cadence, ≤300 ms).
        for cid in ["auto-2@test", "auto-3@test"] {
            let msg = make_invite(cid, "1005", "1006", base_ts());
            app.dialog_store.write().process_message(msg);
        }
        app.elapse_churn_floors_for_test();
        app.sync_caches();
        assert_eq!(app.last_rendered_dialog_rows, 3);
        assert_eq!(
            app.call_list.selected(),
            2,
            "selection must follow the new bottom row"
        );
    }

    /// Field crash regression: with the selection on the bottom row of a
    /// short window (saved scroll offset 3), narrowing the search so only
    /// two rows remain displayed panicked the next render pass with
    /// "range start index 3 out of range for slice of length 2"
    /// (call_list.rs visible-window slice). The render must survive and
    /// the tick must clamp the selection back onto a real row.
    #[test]
    fn call_list_render_survives_display_shrink_with_stale_offset() {
        use controllers::test_support::{base_ts, make_invite};
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![
            make_invite("keep-1@test", "1001", "1002", base_ts()),
            make_invite("keep-2@test", "1003", "1004", base_ts()),
            make_invite("drop-3@test", "1005", "1006", base_ts()),
            make_invite("drop-4@test", "1007", "1008", base_ts()),
        ]);
        // 6-row terminal: 3 status lines + f-key bar + table header leave
        // exactly ONE visible data row, so selecting the bottom row stores
        // scroll offset 3 in the table state.
        let mut terminal = Terminal::new(TestBackend::new(120, 6)).unwrap();
        app.sync_caches();
        assert_eq!(app.displayed.ids.len(), 4);
        app.call_list.move_to_bottom(app.displayed.ids.len());
        terminal.draw(|f| app.render(f)).unwrap();

        // Narrow the search: only the two "keep" dialogs stay displayed.
        app.search_query = "keep".into();
        app.sync_caches();
        terminal.draw(|f| app.render(f)).unwrap(); // panicked before the fix

        assert!(
            app.call_list.selected() < 2,
            "selection must be clamped to the shrunken list, got {}",
            app.call_list.selected()
        );
    }

    /// Same defect class in the stream list: a stale bottom-row selection
    /// plus a search that narrows the displayed streams must not push the
    /// visible-window slice start past the list length.
    #[test]
    fn stream_list_render_survives_display_shrink_with_stale_selection() {
        use ratatui::{Terminal, backend::TestBackend};
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        {
            let mut store = ss.write();
            let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
            for i in 0..4u16 {
                let parsed = crate::capture::ParsedPacket {
                    frame: None,
                    timestamp: ts,
                    src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                    dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                    src_port: 20000 + i * 2,
                    dst_port: 30000 + i * 2,
                    transport: crate::capture::parse::TransportProto::Udp,
                    payload: vec![0u8; 172].into(),
                    ip_id: None,
                    tcp_seq: None,
                    tcp_flags: None,
                    fragment_offset: None,
                    more_fragments: false,
                    ip_protocol: 17,
                    from_hep: false,
                };
                let rtp = crate::rtp::parser::RtpHeader {
                    version: 2,
                    padding: false,
                    extension: false,
                    csrc_count: 0,
                    marker: false,
                    payload_type: 0,
                    sequence: 1,
                    timestamp: 0,
                    ssrc: 0xAAAA_0000 + u32::from(i),
                    payload_offset: 12,
                };
                store.process_rtp(&parsed, &rtp, ts);
            }
            // Link only one stream to a dialog: a Call-ID search will keep
            // just this one displayed.
            store.link_to_dialog(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                30000,
                "keep-1@test",
            );
        }
        let mut app = App::new(ds, ss, Theme::default(), Keymap::default());
        app.current_view = View::StreamList;
        let mut terminal = Terminal::new(TestBackend::new(120, 7)).unwrap();
        app.stream_list.move_to_bottom(4);
        terminal.draw(|f| app.render(f)).unwrap();

        // Narrow the search so a single stream remains displayed.
        app.search_query = "keep-1".into();
        terminal.draw(|f| app.render(f)).unwrap(); // panicked before the fix
    }

    /// Enter with multiple rows checked (`[*]`) must open a flow showing ALL
    /// checked dialogs' messages merged chronologically — not just the
    /// cursor (>) row's dialog — and drilling into a row must open the raw
    /// view of THAT row's dialog.
    #[test]
    fn enter_with_multi_selection_shows_all_checked_dialogs() {
        use controllers::test_support::{base_ts, make_invite};
        use crossterm::event::KeyCode;
        use ratatui::{Terminal, backend::TestBackend};
        let mut app = App::with_processed_messages(vec![
            make_invite("a@test", "1001", "1002", base_ts()),
            make_invite(
                "b@test",
                "1003",
                "1004",
                base_ts() + chrono::TimeDelta::seconds(5),
            ),
            make_invite(
                "c@test",
                "1005",
                "1006",
                base_ts() + chrono::TimeDelta::seconds(10),
            ),
        ]);
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|f| app.render(f)).unwrap();

        // Check rows 0 (a@test) and 2 (c@test), cursor ends on row 2.
        app.handle_key(KeyCode::Char(' '));
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Char(' '));
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view, View::CallFlow(_)));
        terminal.draw(|f| app.render(f)).unwrap();

        // The ladder must contain message rows from BOTH checked dialogs.
        let row_cids: std::collections::HashSet<&str> = app
            .flow
            .ladder
            .rows
            .iter()
            .filter(|r| matches!(r.kind, call_flow::prepare::RowKind::Message { .. }))
            .map(|r| r.call_id.as_str())
            .collect();
        assert_eq!(
            row_cids,
            ["a@test", "c@test"].into_iter().collect(),
            "flow must merge all checked dialogs, got rows from {row_cids:?}"
        );

        // Row 0 is a@test's INVITE (earliest); Enter must open ITS raw view.
        app.handle_key(KeyCode::Enter);
        match &app.current_view {
            View::RawMessage {
                call_id,
                message_index,
            } => {
                assert_eq!(call_id, "a@test", "raw view must show the row's own dialog");
                assert_eq!(*message_index, 0);
            }
            v => panic!("expected RawMessage view, got {v:?}"),
        }
    }

    /// A single checked row (or none) keeps the classic behavior: Enter
    /// opens the cursor row's dialog flow.
    #[test]
    fn enter_with_single_or_no_selection_opens_cursor_dialog() {
        use controllers::test_support::{base_ts, make_invite};
        use crossterm::event::KeyCode;
        let mut app = App::with_processed_messages(vec![
            make_invite("a@test", "1001", "1002", base_ts()),
            make_invite(
                "b@test",
                "1003",
                "1004",
                base_ts() + chrono::TimeDelta::seconds(5),
            ),
        ]);
        app.sync_caches();
        // No checkboxes: cursor row wins.
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.current_view, View::CallFlow("b@test".to_string()));
        app.handle_key(KeyCode::Esc);
        // One checkbox on the cursor row: same as classic single-dialog open.
        app.handle_key(KeyCode::Char(' '));
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.current_view, View::CallFlow("b@test".to_string()));
    }

    /// Render one frame and return the given buffer row as a string.
    fn rendered_row(app: &mut App, width: u16, height: u16, y: u16) -> String {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.render(f)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..width)
            .map(|x| buf[(x, y)].symbol().to_string())
            .collect()
    }

    /// Field incident regression (the "filter does not work" report): a
    /// search query persisted with Enter keeps narrowing the call list, so
    /// it must stay VISIBLE on the status line after leaving search mode —
    /// otherwise a later filter change appears broken (148 dialogs, match
    /// expression `(method == 'OPTIONS' OR method == 'INVITE')`, yet "4
    /// displayed" because an invisible query "559" was still ANDed in).
    #[test]
    fn persisted_search_query_stays_visible_on_status_line() {
        use controllers::test_support::{base_ts, make_invite};
        use crossterm::event::KeyCode;
        let mut app = App::with_processed_messages(vec![
            make_invite("x559@test", "1001", "1002", base_ts()),
            make_invite("other@test", "1003", "1004", base_ts()),
        ]);
        app.handle_key(KeyCode::F(3));
        for c in "559".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        // Enter commits the query AND opens the highlighted row's flow;
        // Esc returns to the call list with the query still persisted.
        app.handle_key(KeyCode::Enter);
        assert!(!app.search_active);
        assert!(matches!(app.current_view, View::CallFlow(_)));
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.current_view, View::CallList);
        assert_eq!(app.search_query, "559");
        app.sync_caches();
        assert_eq!(
            app.cached_displayed_count, 1,
            "persisted query must narrow the list (that is its point)"
        );
        let line3 = rendered_row(&mut app, 120, 24, 2);
        assert!(
            line3.contains("559"),
            "a query that still narrows the list must be visible on the \
             status line, got: {line3:?}"
        );
    }

    /// F9 (clear filter) must clear EVERYTHING that narrows the call list —
    /// the match expression AND the persisted search query — restoring the
    /// full dialog count. Mirrors the field incident's dialog population
    /// (OPTIONS + INVITE) and its exact match expression.
    #[test]
    fn clear_filter_key_clears_match_expression_and_search() {
        use controllers::test_support::{base_ts, make_invite, make_request};
        use crossterm::event::KeyCode;
        let mut messages: Vec<crate::sip::SipMessage> = (0..6)
            .map(|i| {
                make_request(
                    "OPTIONS",
                    &format!("opt-{i}@test"),
                    "sipsak",
                    "proxy",
                    base_ts() + chrono::TimeDelta::seconds(i),
                )
            })
            .collect();
        messages.push(make_invite(
            "inv-559@test",
            "1001",
            "1002",
            base_ts() + chrono::TimeDelta::seconds(10),
        ));
        messages.push(make_invite(
            "inv-2@test",
            "1003",
            "1004",
            base_ts() + chrono::TimeDelta::seconds(11),
        ));
        let mut app = App::with_processed_messages(messages);

        // The incident's exact match expression: matches ALL 8 dialogs.
        let expr = "(method == 'OPTIONS' OR method == 'INVITE')";
        app.active_filter = Some(crate::sip::dsl::FilterExpr::parse(expr).unwrap());
        app.active_filter_text = expr.to_string();
        app.sync_caches();
        assert_eq!(
            app.cached_displayed_count, 8,
            "the filter alone hides nothing"
        );

        // A persisted search query silently narrows to 1.
        app.handle_key(KeyCode::F(3));
        for c in "559".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        // Enter commits the query and opens the row's flow; Esc back.
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Esc);
        app.sync_caches();
        assert_eq!(app.cached_displayed_count, 1);

        // F9 must restore the full list: no invisible narrowing survives.
        app.handle_key(KeyCode::F(9));
        app.sync_caches();
        assert!(app.active_filter.is_none());
        assert_eq!(app.search_query, "", "F9 must also drop the search query");
        assert_eq!(
            app.cached_displayed_count, 8,
            "after clear-filter every dialog must be displayed again"
        );
    }

    /// Field report: "the PDD shown looks like the length of the call".
    /// Pin the semantics with a call whose PDD (INVITE→180 = 1.5 s) and
    /// length (INVITE→final 200 = 61.5 s) are wildly different: the PDD
    /// column must show the 1.5 s, and the call length must be visible in
    /// its own Duration column — both values available, never conflated.
    #[test]
    fn pdd_column_is_pdd_and_duration_column_is_call_length() {
        use controllers::test_support::{base_ts, make_invite, make_request, make_response};
        let t0 = base_ts();
        let mut app = App::with_processed_messages(vec![
            make_invite("call-pdd@test", "1001", "1002", t0),
            make_response(
                "180 Ringing",
                "call-pdd@test",
                "INVITE",
                t0 + chrono::TimeDelta::milliseconds(1500),
            ),
            make_response(
                "200 OK",
                "call-pdd@test",
                "INVITE",
                t0 + chrono::TimeDelta::seconds(3),
            ),
            make_request(
                "BYE",
                "call-pdd@test",
                "1001",
                "1002",
                t0 + chrono::TimeDelta::seconds(61),
            ),
            make_response(
                "200 OK",
                "call-pdd@test",
                "BYE",
                t0 + chrono::TimeDelta::milliseconds(61_500),
            ),
        ]);
        app.sync_caches();

        // Ground truth from the store before looking at the rendering.
        {
            let store = app.dialog_store.read();
            let d = store.get("call-pdd@test").expect("dialog exists");
            assert_eq!(d.timing.pdd_ms(), Some(1500), "PDD is INVITE→180");
            assert_eq!(
                (d.updated_at - d.created_at).num_milliseconds(),
                61_500,
                "call length is first→last message"
            );
        }

        // Header advertises both columns; the row shows both values.
        let header = rendered_row(&mut app, 160, 10, 3);
        assert!(
            header.contains("PDD") && header.contains("Duration"),
            "both PDD and Duration columns must exist, header: {header:?}"
        );
        let row = rendered_row(&mut app, 160, 10, 4);
        assert!(
            row.contains("1500ms"),
            "PDD column must show INVITE→180, row: {row:?}"
        );
        assert!(
            row.contains("1m1s"),
            "Duration column must show the call length, row: {row:?}"
        );
    }

    /// Recent data updates yield the fast active poll timeout; an idle
    /// (backdated) timestamp yields the slow idle timeout.
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

    /// A failed `try_read` (the store's write lock is held by a busy
    /// capture) is activity, not idleness: the adaptive poll cadence must
    /// stay fast. Previously a `None` read was treated like an unchanged
    /// count, downgrading the loop to the slow idle poll under contention.
    #[test]
    fn contended_dialog_read_keeps_active_poll() {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let mut app = App::new(ds.clone(), ss, Theme::default(), Keymap::default());

        // Backdate so, absent any activity signal, poll_timeout is idle.
        app.last_data_update = Instant::now() - Duration::from_secs(10);
        assert!(app.poll_timeout() >= Duration::from_millis(IDLE_POLL_MS));

        // Hold the write lock so the event loop's non-blocking read fails,
        // exactly as under a sustained busy capture.
        let guard = ds.write();
        let count = ds.try_read().map(|d| d.len());
        assert!(count.is_none(), "held write lock must make try_read fail");
        app.reconcile_dialog_count(count);
        drop(guard);

        assert!(
            app.poll_timeout() <= Duration::from_millis(ACTIVE_POLL_MS),
            "contention must keep the responsive poll cadence"
        );
    }

    /// A successful, unchanged read is genuinely idle: the cadence is left
    /// alone (no spurious activity signal on a static pcap).
    #[test]
    fn unchanged_dialog_count_stays_idle() {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let mut app = App::new(ds, ss, Theme::default(), Keymap::default());

        app.last_data_update = Instant::now() - Duration::from_secs(10);
        app.last_known_dialog_count = 0;
        app.reconcile_dialog_count(Some(0));
        assert!(
            app.poll_timeout() >= Duration::from_millis(IDLE_POLL_MS),
            "an unchanged count must not reset the idle timer"
        );

        // A changed count is fresh data → back to active.
        app.reconcile_dialog_count(Some(3));
        assert_eq!(app.last_known_dialog_count, 3);
        assert!(app.poll_timeout() <= Duration::from_millis(ACTIVE_POLL_MS));
    }

    /// When config sets both `selected` and its legacy alias `highlight`,
    /// `selected` wins.
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

    /// The legacy `highlight` alias applies to `selected` when no
    /// explicit `selected` color is configured.
    #[test]
    fn theme_from_config_highlight_fallback() {
        let config = ThemeConfig {
            highlight: Some("red".to_string()),
            ..Default::default()
        };
        let theme = Theme::from_config(&config);
        assert_eq!(theme.selected, Color::Red); // highlight applies when selected is None
    }

    /// A configured rebind replaces the default key while unconfigured
    /// actions keep their defaults.
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

    /// `csv_escape` quotes fields containing commas, quotes or newlines
    /// and doubles embedded quotes; plain text passes through.
    #[test]
    fn csv_escape_quotes_commas() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    /// `View` equality compares variants and their payloads (Call-IDs).
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

    /// `SaveFormat::next` cycles through all 11 formats back to the start.
    #[test]
    fn save_format_next_full_cycle() {
        // 11 formats — next() applied 11 times returns to start.
        let mut f = SaveFormat::Pcap;
        for _ in 0..11 {
            f = f.next();
        }
        assert_eq!(f, SaveFormat::Pcap);
    }

    /// `prev` is the exact inverse of `next` for every format.
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

    /// Every format has non-empty extension/label/category/description,
    /// with a few exact values spot-checked.
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

    /// SDP display mode cycles None → Summary → Full → None with
    /// matching status-bar labels.
    #[test]
    fn sdp_display_mode_cycle_and_labels() {
        assert_eq!(SdpDisplayMode::None.next(), SdpDisplayMode::Summary);
        assert_eq!(SdpDisplayMode::Summary.next(), SdpDisplayMode::Full);
        assert_eq!(SdpDisplayMode::Full.next(), SdpDisplayMode::None);
        assert!(SdpDisplayMode::None.label().contains("SDP"));
        assert!(SdpDisplayMode::Summary.label().contains("Summary"));
        assert!(SdpDisplayMode::Full.label().contains("Full"));
    }

    /// Timestamp mode cycles Absolute → DeltaPrev → DeltaFirst → Scaled
    /// → Absolute with "Time:" labels.
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

    /// Color mode cycles Method → CallId → CSeq → Method with "Color:"
    /// labels.
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

    /// `text_field`/`text_field_mut` map indices 0-4 to the five filter
    /// fields; out-of-range indices yield ""/None.
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

    /// Tab focus wraps from the first element to the last and back.
    #[test]
    fn filter_dialog_focus_wraps_both_directions() {
        let mut st = FilterDialogState::default();
        assert_eq!(st.focused_field(), 0);
        st.focus_prev(); // wrap to last
        assert_eq!(st.focused_field(), FILTER_ITEM_COUNT - 1);
        st.focus_next(); // wrap back to 0
        assert_eq!(st.focused_field(), 0);
    }

    /// Focus indices classify correctly as text field, "All" master
    /// checkbox (not a method slot), method checkbox, or button.
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
        // "All" master checkbox sits right after the text fields, above the
        // method grid — a checkbox, but not a method slot.
        st.focused_field = ALL_METHODS_IDX;
        assert!(st.is_checkbox_focused());
        assert!(st.checkbox_index().is_none());
        // first METHOD checkbox (REGISTER)
        st.focused_field = METHOD_CHECKBOX_BASE;
        assert!(st.is_checkbox_focused());
        assert_eq!(st.checkbox_index(), Some(0));
        // button region
        st.focused_field = FILTER_BUTTON_IDX;
        assert!(!st.is_text_field_focused());
        assert!(!st.is_checkbox_focused());
    }

    /// Arrow navigation moves through the 2-column method grid and exits
    /// upward via the "All" row to the last text field.
    #[test]
    fn filter_dialog_checkbox_grid_navigation() {
        let mut st = FilterDialogState {
            focused_field: METHOD_CHECKBOX_BASE,
            ..Default::default()
        };
        // Focus first method checkbox (index 0).
        st.checkbox_right(); // 0 -> 1
        assert_eq!(st.checkbox_index(), Some(1));
        st.checkbox_left(); // 1 -> 0
        assert_eq!(st.checkbox_index(), Some(0));
        st.checkbox_down(); // 0 -> 2
        assert_eq!(st.checkbox_index(), Some(2));
        st.checkbox_up(); // 2 -> 0
        assert_eq!(st.checkbox_index(), Some(0));
        // Up from the top method row → the "All" row above the grid.
        st.checkbox_up();
        assert_eq!(st.focused_field(), ALL_METHODS_IDX);
        // Up from "All" → the last text field.
        st.checkbox_up();
        assert!(st.is_text_field_focused());
        assert_eq!(st.focused_field(), FILTER_TEXT_FIELD_COUNT - 1);
    }

    /// Down walks the left column, continues into the right column, then
    /// reaches the buttons — vertical navigation covers every checkbox.
    #[test]
    fn filter_dialog_checkbox_down_traverses_both_columns_then_buttons() {
        // Down walks the LEFT column to its bottom, then continues into the
        // RIGHT column, then to the buttons — so the right column is reachable
        // by vertical navigation.
        let mut st = FilterDialogState {
            focused_field: METHOD_CHECKBOX_BASE + 8, // INFO (left col bottom, idx 8)
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

        // The "All" row sits ABOVE the grid: Down enters at REGISTER, Up
        // leaves to it from the top-left method.
        let mut st = FilterDialogState {
            focused_field: ALL_METHODS_IDX,
            ..Default::default()
        };
        st.checkbox_down();
        assert_eq!(st.checkbox_index(), Some(0), "All -> REGISTER");
        st.checkbox_up();
        assert_eq!(st.focused_field(), ALL_METHODS_IDX, "REGISTER -> All");

        // Up reverses: from OPTIONS (idx 1) back to INFO (idx 8).
        let mut st = FilterDialogState {
            focused_field: METHOD_CHECKBOX_BASE + 1,
            ..Default::default()
        };
        st.checkbox_up();
        assert_eq!(st.checkbox_index(), Some(8));
    }

    /// Default state: all methods checked, no narrowing, no expression.
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

    /// `clear()` re-checks every method (show all) and empties the state.
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

    /// `any_method_checked` follows the checkbox array (none checked
    /// means "show nothing").
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

    /// Unchecking one method builds an OR expression over the other nine
    /// (excluding it), and text fields AND-join with the method clause.
    #[test]
    fn filter_dialog_uncheck_one_excludes_that_method() {
        // From the all-checked default, unchecking INVITE (index 2) must produce
        // a method filter over the OTHER nine and exclude INVITE.
        let mut st = FilterDialogState {
            focused_field: METHOD_CHECKBOX_BASE + 2, // INVITE
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

    /// All methods checked plus empty text fields builds no expression.
    #[test]
    fn filter_dialog_all_methods_checked_yields_no_method_filter() {
        let st = FilterDialogState {
            methods: [true; 10],
            ..Default::default()
        };
        // All checked → method filter omitted; with no text fields → None.
        assert!(st.build_filter_expression().is_none());
    }

    /// `clear()` also resets focus and cursor position, not just fields.
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

    /// `sync_cursor` places the cursor at the end of the focused field.
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

    /// Default mode shows the user, falls back to host, then "-".
    #[test]
    fn from_to_mode_default_prefers_user_then_host() {
        let m = FromToMode::Default;
        assert_eq!(m.format(Some("1001"), Some("h:5060")), "1001");
        assert_eq!(m.format(None, Some("h:5060")), "h:5060");
        assert_eq!(m.format(None, None), "-");
    }

    /// HostPort mode shows only the host and ignores the user entirely.
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

    /// User mode shows only the user, with "-" when absent (legacy).
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

    /// UserHostPort mode combines `user@host`, degrading to whichever
    /// part exists.
    #[test]
    fn from_to_mode_user_host_combines() {
        let m = FromToMode::UserHostPort;
        assert_eq!(m.format(Some("1001"), Some("h:5060")), "1001@h:5060");
        assert_eq!(m.format(Some("1001"), None), "1001");
        assert_eq!(m.format(None, Some("h:5060")), "h:5060");
        assert_eq!(m.format(None, None), "-");
    }

    /// The `u`-key cycle visits all four modes and returns to Default.
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

    /// `parse` round-trips every `as_config_str` value and rejects
    /// unknown/empty strings with None.
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

    /// The capture-mode and BPF-filter setters store the given strings.
    #[test]
    fn app_set_capture_mode_and_bpf_filter() {
        let mut app = App::new_test();
        app.set_capture_mode("Offline (cap.pcap)".to_string());
        assert_eq!(app.capture_mode, "Offline (cap.pcap)");
        app.set_bpf_filter("udp port 5060".to_string());
        assert_eq!(app.bpf_filter, "udp port 5060");
    }

    /// `mark_data_updated` flips an idle App back to active polling.
    #[test]
    fn app_mark_data_updated_resets_to_active() {
        let mut app = App::new_test();
        app.last_data_update = Instant::now() - Duration::from_secs(10);
        assert!(app.poll_timeout() >= Duration::from_millis(IDLE_POLL_MS));
        app.mark_data_updated();
        assert!(app.poll_timeout() <= Duration::from_millis(ACTIVE_POLL_MS));
    }

    /// `is_paused` mirrors the TUI-local paused flag.
    #[test]
    fn app_is_paused_reflects_flag() {
        let mut app = App::new_test();
        assert!(!app.is_paused());
        app.paused = true;
        assert!(app.is_paused());
    }
}
