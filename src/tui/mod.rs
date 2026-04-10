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
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
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
    /// Filter input dialog.
    FilterDialog,
    /// Statistics summary view.
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
    /// Capture mode label: "Online (device)" or "Offline (filename)".
    capture_mode: String,
    /// BPF filter string if set via CLI.
    bpf_filter: String,
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
            capture_mode: "Online (any)".to_string(),
            bpf_filter: String::new(),
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

    // Layout: main area + separator + status bar + F-key bar
    // The separator prevents visual overlap between content and bottom bars.
    let [main_area, _sep, status_area, fkey_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1), // blank separator line
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);

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

    // Status bar (sngrep-style)
    render_status_bar(frame, status_area, app);

    // F-key bar (sngrep-style, context-sensitive)
    render_fkey_bar(frame, fkey_area, &app.current_view);
}

/// Render the sngrep-style status bar above the F-key bar.
///
/// Format: `Current Mode: Online (any)    Dialogs: 10    Match Expression:     BPF Filter:`
fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let dialog_count = app.dialog_store.read().len();

    let status_text = if app.search_active {
        format!("/{}", app.search_query)
    } else if let Some(ref err) = app.status_error {
        err.clone()
    } else {
        let match_expr = &app.active_filter_text;
        let bpf = &app.bpf_filter;
        format!(
            " Current Mode: {}    Dialogs: {}    Match Expression: {}    BPF Filter: {}",
            app.capture_mode, dialog_count, match_expr, bpf,
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

/// Render the sngrep-style F-key bar at the bottom of the screen.
///
/// Each F-key label is a pair: the key name (white on blue) and the action
/// label (black on cyan), matching sngrep's distinctive appearance.
/// The bar is context-sensitive based on the current view.
fn render_fkey_bar(frame: &mut ratatui::Frame, area: Rect, view: &View) {
    let key_style = Style::default().fg(Color::White).bg(Color::Blue);
    let label_style = Style::default().fg(Color::Black).bg(Color::Cyan);

    let items: &[(&str, &str)] = match view {
        View::CallList => &[
            ("F1", "Help "),
            ("F2", "Save "),
            ("F3", "Search "),
            ("F4", "Extended "),
            ("F5", "Compare "),
            ("F6", "RTP "),
            ("F7", "Filter "),
            ("F8", "Settings "),
            ("F9", "ClearFilter "),
            ("F10", "Columns "),
        ],
        View::CallFlow(_) => &[
            ("F1", "Help "),
            ("F2", "Save "),
            ("F5", "Compare "),
            ("F7", "Filter "),
            ("F9", "ClearFilter "),
        ],
        View::RawMessage { .. } => &[("F1", "Help "), ("F2", "Save ")],
        View::StreamList => &[("F1", "Help "), ("F7", "Filter ")],
        _ => &[("F1", "Help ")],
    };

    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label)) in items.iter().enumerate() {
        if i > 0 {
            // Space between F-key pairs
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled((*key).to_string(), key_style));
        spans.push(Span::styled((*label).to_string(), label_style));
    }

    // Pad remaining space
    let used_width: usize =
        items.iter().map(|(k, l)| k.len() + l.len()).sum::<usize>() + items.len().saturating_sub(1); // account for spaces between pairs
    let remaining = (area.width as usize).saturating_sub(used_width);
    if remaining > 0 {
        spans.push(Span::raw(" ".repeat(remaining)));
    }

    let bar = Paragraph::new(Line::from(spans));
    frame.render_widget(bar, area);
}

/// Render the filter dialog input view.
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
        KeyCode::F(2) => {
            // Save: if a dialog is selected, save just that dialog;
            // otherwise save all dialogs.
            let selected_call_id = get_selected_call_id(app);
            let msg = save_to_pcap(app, selected_call_id.as_deref());
            app.status_error = Some(msg);
        }
        KeyCode::F(3) => {
            // F3 Search — same as '/' search
            app.search_active = true;
            app.search_query.clear();
        }
        KeyCode::F(4) => {
            app.status_error = Some("Extended view not yet implemented".to_string());
        }
        KeyCode::F(5) => {
            app.status_error = Some("Compare not yet implemented".to_string());
        }
        KeyCode::F(6) => {
            // F6 RTP — switch to stream list (same as Tab)
            app.current_view = View::StreamList;
        }
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
        KeyCode::F(8) => {
            app.status_error = Some("Settings not yet implemented".to_string());
        }
        KeyCode::F(9) => {
            // F9 Clear Filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
        }
        KeyCode::F(10) => {
            app.status_error = Some("Column selection not yet implemented".to_string());
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
        KeyCode::F(7) => {
            if app.active_filter.is_some() {
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                app.filter_input.clear();
                app.current_view = View::FilterDialog;
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
        KeyCode::F(2) => {
            if let View::CallFlow(ref call_id) = app.current_view {
                let cid = call_id.clone();
                let msg = save_to_pcap(app, Some(&cid));
                app.status_error = Some(msg);
            }
        }
        KeyCode::F(5) => {
            app.status_error = Some("Compare not yet implemented".to_string());
        }
        KeyCode::F(7) => {
            if app.active_filter.is_some() {
                app.active_filter = None;
                app.active_filter_text.clear();
                app.status_error = None;
            } else {
                app.filter_input.clear();
                app.current_view = View::FilterDialog;
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
        KeyCode::Esc => {
            if let View::RawMessage { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                app.current_view = View::CallFlow(cid);
            }
        }
        KeyCode::F(1) => app.current_view = View::Help,
        KeyCode::F(2) => {
            if let View::RawMessage { ref call_id, .. } = app.current_view {
                let cid = call_id.clone();
                let msg = save_to_pcap(app, Some(&cid));
                app.status_error = Some(msg);
            }
        }
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

// ── Save functionality ─────────────────────────────────────────────

/// Choose a non-colliding output path. If `sipnab_save.pcap` exists, try
/// `sipnab_save_1.pcap`, `sipnab_save_2.pcap`, etc.
fn choose_save_path() -> PathBuf {
    let base = PathBuf::from("sipnab_save.pcap");
    if !base.exists() {
        return base;
    }
    for i in 1..1000 {
        let candidate = PathBuf::from(format!("sipnab_save_{i}.pcap"));
        if !candidate.exists() {
            return candidate;
        }
    }
    // Fallback — overwrite
    base
}

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

/// Save dialogs to a pcap file. If `call_id` is `Some`, save only that dialog;
/// otherwise save all dialogs.
fn save_to_pcap(app: &App, call_id: Option<&str>) -> String {
    let path = choose_save_path();
    let store = app.dialog_store.read();

    // Collect messages
    let messages: Vec<&crate::sip::SipMessage> = if let Some(cid) = call_id {
        store
            .get(cid)
            .map(|d| d.messages.iter().collect())
            .unwrap_or_default()
    } else {
        store.iter().flat_map(|d| d.messages.iter()).collect()
    };

    if messages.is_empty() {
        return "No messages to save".to_string();
    }

    // Create writer (DLT_EN10MB = 1)
    let mut writer = match crate::capture::PcapWriter::new(&path, 1, None, None) {
        Ok(w) => w,
        Err(e) => return format!("Save failed: {e}"),
    };

    let mut count = 0;
    for msg in &messages {
        let pkt = build_synthetic_packet(msg);
        if let Err(e) = writer.write(&pkt) {
            return format!("Write error after {count} packets: {e}");
        }
        count += 1;
    }

    format!("Saved {count} packets to {}", path.display())
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
