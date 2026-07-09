//! Test-only-in-spirit App accessors, exposed publicly for the
//! integration suites (tui_state_test, snapshots) and the in-crate
//! unit tests. Moved verbatim from `tui/mod.rs`.

use crate::tui::*;

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

    /// Simulate a single keypress, then settle any background work — the
    /// real event loop ticks between key events, so tests keep synchronous
    /// load/save semantics.
    pub fn handle_key(&mut self, code: KeyCode) {
        let key = KeyEvent::new(code, KeyModifiers::NONE);
        handle_key_event(self, key);
        self.settle_background_work();
    }

    /// Settle everything the real event loop would process across ticks:
    /// wait for an in-flight background pcap load and apply its outcome,
    /// execute a deferred save, and drain detached-worker messages.
    pub fn settle_background_work(&mut self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while self.pcap_load.is_some() {
            controllers::poll_pcap_load(self);
            if self.pcap_load.is_none() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!("background pcap load did not settle within 30s");
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        self.run_pending_save();
        self.run_pending_audio();
        while !self.async_messages.lock().is_empty() {
            self.drain_async_messages();
        }
    }

    #[doc(hidden)]
    pub fn open_path_clear_for_test(&mut self) {
        self.file_open.path.clear();
        self.file_open.cursor = 0;
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
        self.file_open.dir = dir;
    }

    #[doc(hidden)]
    pub fn open_dir_for_test(&self) -> &std::path::Path {
        &self.file_open.dir
    }

    #[doc(hidden)]
    pub fn open_entry_names_for_test(&self) -> Vec<String> {
        self.file_open
            .entries
            .iter()
            .map(|e| e.name.clone())
            .collect()
    }

    /// Handle a mouse event kind (wheel scrolling) against the current view.
    pub fn handle_mouse_kind(&mut self, kind: crossterm::event::MouseEventKind) {
        controllers::handle_mouse_event(self, kind);
    }

    /// Simulate a keypress with modifiers (settles background work like
    /// [`Self::handle_key`]).
    pub fn handle_key_with_modifiers(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        let key = KeyEvent::new(code, modifiers);
        handle_key_event(self, key);
        self.settle_background_work();
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
        self.flow.raw_preview
    }

    /// Return the raw preview pane percentage.
    pub fn raw_preview_pct(&self) -> u16 {
        self.flow.raw_preview_pct
    }

    /// Return whether extended multi-leg flow is active.
    pub fn extended_flow(&self) -> bool {
        self.flow.extended
    }

    /// Return whether RTP is shown in the call flow.
    pub fn show_rtp_in_flow(&self) -> bool {
        self.flow.show_rtp
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
                .filter(|d| selected.contains(d.call_id.as_str()))
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
        self.flow.selected
    }

    /// Return the detail panel scroll offset.
    pub fn detail_scroll(&self) -> u16 {
        self.flow.detail_scroll
    }

    /// Return the help view scroll offset.
    pub fn help_scroll(&self) -> u16 {
        self.help_scroll
    }

    /// Return the statistics view scroll offset.
    pub fn stats_scroll(&self) -> u16 {
        self.stats_scroll
    }

    /// Return the message diff view scroll offset.
    pub fn diff_scroll(&self) -> u16 {
        self.diff_scroll
    }

    /// Return the raw message view scroll offset.
    pub fn raw_msg_scroll(&self) -> u16 {
        self.raw_msg_scroll
    }

    /// Return the call flow ladder scroll offset.
    pub fn call_flow_scroll(&self) -> usize {
        self.flow.scroll
    }

    /// Return the first selected message for diff comparison.
    pub fn diff_selected_msg(&self) -> Option<usize> {
        self.flow.diff_selected.as_ref().map(|&(_, idx)| idx)
    }

    /// Return the marked message index (for mark + delta).
    pub fn mark_index(&self) -> Option<usize> {
        self.flow.mark_index
    }

    /// Return the set of expanded fold indices.
    pub fn fold_expanded(&self) -> &HashSet<usize> {
        &self.flow.fold_expanded
    }

    /// Return the selected save format.
    pub fn save_format(&self) -> SaveFormat {
        self.save.format
    }

    /// Return the save dialog file path.
    pub fn save_path(&self) -> &str {
        &self.save.path
    }

    /// Return the save dialog cursor position.
    pub fn save_cursor(&self) -> usize {
        self.save.cursor
    }

    /// Return the file-open dialog path.
    pub fn open_path(&self) -> &str {
        &self.file_open.path
    }

    /// Return the file-open dialog cursor position.
    pub fn open_cursor(&self) -> usize {
        self.file_open.cursor
    }

    /// Return the stream detail scroll offset.
    pub fn stream_detail_scroll(&self) -> usize {
        self.stream_detail_scroll
    }

    /// Override the save dialog path (for deterministic snapshot tests).
    pub fn set_save_path(&mut self, path: &str) {
        self.save.path = path.to_string();
        self.save.cursor = path.len();
    }

    /// Return a reference to the shared dialog store (for tests).
    pub fn dialog_store_ref(&self) -> &Arc<RwLock<DialogStore>> {
        &self.dialog_store
    }

    /// Render one full application tick into the given frame (for snapshot
    /// tests): cache sync, the read-only render pass, and the render
    /// feedback write-back — exactly the event loop's sequence.
    pub fn render(&mut self, frame: &mut ratatui::Frame) {
        self.sync_caches();
        let fb = render_app(frame, self);
        self.apply_render_feedback(fb);
    }
}
