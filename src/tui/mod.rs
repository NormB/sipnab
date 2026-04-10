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

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use parking_lot::RwLock;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

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
    /// Keybinding help overlay.
    Help,
    /// Filter input dialog (placeholder).
    FilterDialog,
    /// Statistics summary view (placeholder).
    Statistics,
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
    /// State for the call list table.
    call_list: CallListState,
    /// State for the stream list table.
    stream_list: StreamListState,
    /// Set to `true` to exit the event loop.
    should_quit: bool,
    /// When data was last updated (for adaptive refresh).
    last_data_update: Instant,
    /// Filter input buffer (for FilterDialog view).
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
        }
    }

    /// Mark data as freshly updated (resets adaptive refresh timer).
    pub fn mark_data_updated(&mut self) {
        self.last_data_update = Instant::now();
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
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
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
    // Setup terminal
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;

    // Guard ensures terminal is restored even on panic
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(dialog_store, stream_store);

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
fn render_app(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();

    // Layout: main area + status bar
    let [main_area, status_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);

    // Render the current view
    match &app.current_view.clone() {
        View::CallList => {
            let store = app.dialog_store.read();
            call_list::render_call_list(
                frame,
                main_area,
                &mut app.call_list,
                &store,
                app.active_filter.as_ref(),
            );
        }
        View::StreamList => {
            let store = app.stream_store.read();
            stream_list::render_stream_list(frame, main_area, &mut app.stream_list, &store);
        }
        View::CallFlow(call_id) => {
            let store = app.dialog_store.read();
            call_flow::render_call_flow(frame, main_area, &store, call_id, app.call_flow_scroll);
        }
        View::RawMessage {
            call_id,
            message_index,
        } => {
            let store = app.dialog_store.read();
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
        View::Help => {
            help::render_help(frame, main_area);
        }
        View::FilterDialog => {
            render_filter_dialog(frame, main_area, &app.filter_input);
        }
        View::Statistics => {
            render_statistics(frame, main_area, app);
        }
    }

    // Status bar
    render_status_bar(frame, status_area, app);
}

/// Render the bottom status bar.
fn render_status_bar(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let dialog_count = app.dialog_store.read().len();
    let stream_count = app.stream_store.read().len();
    let active_count = app.dialog_store.read().active_count();

    let view_name = match &app.current_view {
        View::CallList => "Call List",
        View::StreamList => "Stream List",
        View::CallFlow(_) => "Call Flow",
        View::RawMessage { .. } => "Raw Message",
        View::Help => "Help",
        View::FilterDialog => "Filter",
        View::Statistics => "Statistics",
    };

    let status_text = if app.search_active {
        format!("/{}", app.search_query)
    } else if let Some(ref err) = app.status_error {
        format!(" {err}")
    } else if !app.active_filter_text.is_empty() {
        format!(
            " sipnab | {} | Filter: {} | Dialogs: {} (active: {}) | Streams: {} | F7:Clear",
            view_name, app.active_filter_text, dialog_count, active_count, stream_count,
        )
    } else {
        format!(
            " sipnab | {} | Dialogs: {} (active: {}) | Streams: {} | F1:Help q:Quit",
            view_name, dialog_count, active_count, stream_count,
        )
    };

    let status = Paragraph::new(Line::from(vec![Span::styled(
        status_text,
        Style::default()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )]))
    .style(Style::default().bg(Color::DarkGray));

    frame.render_widget(status, area);
}

/// Render a placeholder filter dialog.
fn render_filter_dialog(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, input: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter Expression (F7) ");

    let text = if input.is_empty() {
        "Enter filter expression (e.g., method == 'INVITE', state == 'Failed')\n\nPress Enter to apply, Esc to cancel"
    } else {
        input
    };

    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(Color::White));

    frame.render_widget(paragraph, area);
}

/// Render a placeholder statistics view.
fn render_statistics(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let dialog_count = app.dialog_store.read().len();
    let active_count = app.dialog_store.read().active_count();
    let stream_count = app.stream_store.read().len();
    let orphaned = app.stream_store.read().orphaned_count();

    let text = format!(
        "sipnab Statistics\n\n\
         Dialogs:        {dialog_count}\n\
         Active Calls:   {active_count}\n\
         RTP Streams:    {stream_count}\n\
         Orphaned:       {orphaned}\n\n\
         Press Esc to return."
    );

    let block = Block::default().borders(Borders::ALL).title(" Statistics ");

    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(Color::White));

    frame.render_widget(paragraph, area);
}

// ── Key handling ────────────────────────────────────────────────────

/// Dispatch a key event to the handler for the current view.
fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Global shortcuts (Ctrl-C always quits)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
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
        View::Help => handle_help_key(app, key),
        View::FilterDialog => handle_filter_key(app, key),
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
    let dialog_count = filtered_dialog_count(app);

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
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
        KeyCode::F(1) => app.current_view = View::Help,
        KeyCode::F(2) => { /* placeholder: save dialog */ }
        KeyCode::F(7) => {
            if app.active_filter.is_some() {
                // F7 again clears the active filter
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                app.filter_input.clear();
                app.current_view = View::FilterDialog;
            }
        }
        KeyCode::Char('s') => app.current_view = View::Statistics,
        _ => {}
    }
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
        KeyCode::Esc => {
            app.current_view = View::CallList;
        }
        KeyCode::F(1) => app.current_view = View::Help,
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
        KeyCode::Esc => {
            if let View::RawMessage { ref call_id, .. } = app.current_view {
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

/// Handle keys in the filter dialog.
fn handle_filter_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            // Cancel without applying
            app.current_view = View::CallList;
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
            app.current_view = View::CallList;
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

    /// Return the current view.
    pub fn current_view(&self) -> &View {
        &self.current_view
    }

    /// Return whether the quit flag is set.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// Count dialogs visible after applying the active filter.
    pub fn visible_dialog_count(&self) -> usize {
        filtered_dialog_count(self)
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
