//! Call list view — sortable, filterable dialog table.
//!
//! Displays all tracked SIP dialogs in a table with columns for index,
//! method, from/to users, source/destination addresses, state, message
//! count, duration, and PDD. Rows are color-coded by dialog state and
//! show diagnosis warning indicators.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::sip::dialog::DialogState;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;

// ── Sort column ─────────────────────────────────────────────────────

/// Columns available for sorting the call list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    /// Sort by dialog index (insertion order).
    Index,
    /// Sort by initial SIP method.
    Method,
    /// Sort by From user.
    From,
    /// Sort by To user.
    To,
    /// Sort by dialog state.
    State,
    /// Sort by message count.
    Messages,
}

// ── Call list state ─────────────────────────────────────────────────

/// Persistent state for the call list view.
pub struct CallListState {
    /// ratatui table widget state (tracks selected row).
    table_state: TableState,
    /// Which column to sort by.
    sort_column: SortColumn,
    /// Sort in ascending order.
    sort_ascending: bool,
    /// Set of selected (multi-select) row indices.
    selected_rows: Vec<usize>,
}

impl CallListState {
    /// Create a new call list state with the first row selected.
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            table_state,
            sort_column: SortColumn::Index,
            sort_ascending: true,
            selected_rows: Vec::new(),
        }
    }

    /// Return the currently selected row index.
    pub fn selected(&self) -> usize {
        self.table_state.selected().unwrap_or(0)
    }

    /// Move selection up by one row.
    pub fn move_up(&mut self) {
        let current = self.selected();
        if current > 0 {
            self.table_state.select(Some(current - 1));
        }
    }

    /// Move selection down by one row, clamped to the last item.
    pub fn move_down(&mut self, item_count: usize) {
        if item_count == 0 {
            return;
        }
        let current = self.selected();
        if current + 1 < item_count {
            self.table_state.select(Some(current + 1));
        }
    }

    /// Move selection to the first row.
    pub fn move_to_top(&mut self) {
        self.table_state.select(Some(0));
    }

    /// Move selection to the last row.
    pub fn move_to_bottom(&mut self, item_count: usize) {
        if item_count > 0 {
            self.table_state.select(Some(item_count - 1));
        }
    }

    /// Move selection up by a page (20 rows).
    pub fn page_up(&mut self) {
        let current = self.selected();
        self.table_state.select(Some(current.saturating_sub(20)));
    }

    /// Move selection down by a page (20 rows), clamped to the last item.
    pub fn page_down(&mut self, item_count: usize) {
        if item_count == 0 {
            return;
        }
        let current = self.selected();
        let new = (current + 20).min(item_count - 1);
        self.table_state.select(Some(new));
    }

    /// Toggle multi-selection for the currently selected row.
    pub fn toggle_selection(&mut self) {
        let idx = self.selected();
        if let Some(pos) = self.selected_rows.iter().position(|&r| r == idx) {
            self.selected_rows.remove(pos);
        } else {
            self.selected_rows.push(idx);
        }
    }

    /// Return the current sort column.
    pub fn sort_column(&self) -> SortColumn {
        self.sort_column
    }

    /// Return whether sort is ascending.
    pub fn sort_ascending(&self) -> bool {
        self.sort_ascending
    }

    /// Set the sort column; toggles direction if already sorting by this column.
    pub fn set_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = column;
            self.sort_ascending = true;
        }
    }
}

impl Default for CallListState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Render the call list table into the given area.
pub fn render_call_list(
    frame: &mut Frame,
    area: Rect,
    state: &mut CallListState,
    store: &DialogStore,
    filter: Option<&FilterExpr>,
) {
    let header = Row::new(vec![
        Cell::from(" # "),
        Cell::from("Method"),
        Cell::from("From"),
        Cell::from("To"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("State"),
        Cell::from("Msgs"),
        Cell::from("Duration"),
        Cell::from("PDD"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(0);

    let dialogs: Vec<_> = if let Some(filter) = filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .collect()
    } else {
        store.iter().collect()
    };

    let rows: Vec<Row> = dialogs
        .iter()
        .enumerate()
        .map(|(idx, dialog)| {
            // Diagnosis and correlation indicators
            let has_retransmits = dialog.timing.total_retransmits() > 0;
            let has_correlated = !store.find_correlated(&dialog.call_id).is_empty();
            let diag_icon = if has_correlated {
                "\u{2194}" // ↔ for correlated legs
            } else if has_retransmits {
                "!"
            } else {
                " "
            };

            let duration = format_duration(dialog.created_at, dialog.updated_at);
            let pdd = dialog
                .timing
                .pdd_ms()
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_default();

            let row = Row::new(vec![
                Cell::from(Span::raw(format!("{}{}", diag_icon, idx + 1))),
                Cell::from(Span::raw(dialog.method.as_str())),
                Cell::from(Span::raw(dialog.from_user.as_deref().unwrap_or("-"))),
                Cell::from(Span::raw(dialog.to_user.as_deref().unwrap_or("-"))),
                Cell::from(Span::raw(dialog.src_addr.to_string())),
                Cell::from(Span::raw(dialog.dst_addr.to_string())),
                Cell::from(Span::styled(
                    format_state(&dialog.state),
                    state_style(&dialog.state),
                )),
                Cell::from(Span::raw(dialog.messages.len().to_string())),
                Cell::from(Span::raw(duration)),
                Cell::from(Span::raw(pdd)),
            ]);

            // Row style based on state
            let row_style = match dialog.state {
                DialogState::Failed => Style::default().fg(Color::Red),
                DialogState::InCall | DialogState::Active => Style::default().fg(Color::Green),
                DialogState::Cancelled => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            };

            // If multi-selected, add underline
            let row_style = if state.selected_rows.contains(&idx) {
                row_style.add_modifier(Modifier::UNDERLINED)
            } else {
                row_style
            };

            row.style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(5),  // #
        Constraint::Length(10), // Method
        Constraint::Length(16), // From
        Constraint::Length(16), // To
        Constraint::Length(16), // Source
        Constraint::Length(16), // Destination
        Constraint::Length(12), // State
        Constraint::Length(5),  // Msgs
        Constraint::Length(10), // Duration
        Constraint::Length(8),  // PDD
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Call List (Tab: Streams | Enter: Flow | F1: Help) "),
        )
        .column_spacing(1)
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(table, area, &mut state.table_state);
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a [`DialogState`] as a short display string.
fn format_state(state: &DialogState) -> String {
    match state {
        DialogState::Trying => "Trying".to_string(),
        DialogState::Ringing => "Ringing".to_string(),
        DialogState::InCall => "InCall".to_string(),
        DialogState::Completed => "Completed".to_string(),
        DialogState::Cancelled => "Cancelled".to_string(),
        DialogState::Failed => "FAILED".to_string(),
        DialogState::Registered => "Registered".to_string(),
        DialogState::Expired => "Expired".to_string(),
        DialogState::Pending => "Pending".to_string(),
        DialogState::Active => "Active".to_string(),
        DialogState::Terminated => "Terminated".to_string(),
    }
}

/// Return a style for a dialog state label.
fn state_style(state: &DialogState) -> Style {
    match state {
        DialogState::Failed => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        DialogState::InCall | DialogState::Active => Style::default().fg(Color::Green),
        DialogState::Cancelled => Style::default().fg(Color::Yellow),
        DialogState::Completed | DialogState::Registered => Style::default().fg(Color::Cyan),
        _ => Style::default(),
    }
}

/// Format the duration between two timestamps as a human-readable string.
fn format_duration(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> String {
    let diff = end.signed_duration_since(start);
    let total_secs = diff.num_seconds();
    if total_secs < 0 {
        return "0s".to_string();
    }
    if total_secs < 60 {
        let ms = diff.num_milliseconds() % 1000;
        return format!("{}.{}s", total_secs, ms / 100);
    }
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    if mins < 60 {
        return format!("{}m{}s", mins, secs);
    }
    let hours = mins / 60;
    let remaining_mins = mins % 60;
    format!("{}h{}m", hours, remaining_mins)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_list_state_move_up_from_zero_stays() {
        let mut state = CallListState::new();
        state.move_up();
        assert_eq!(state.selected(), 0);
    }

    #[test]
    fn call_list_state_move_down_increments() {
        let mut state = CallListState::new();
        state.move_down(10);
        assert_eq!(state.selected(), 1);
    }

    #[test]
    fn call_list_state_move_down_clamps() {
        let mut state = CallListState::new();
        state.move_down(1); // only 1 item, already at 0
        assert_eq!(state.selected(), 0);
    }

    #[test]
    fn call_list_state_move_to_bottom() {
        let mut state = CallListState::new();
        state.move_to_bottom(50);
        assert_eq!(state.selected(), 49);
    }

    #[test]
    fn call_list_state_page_down() {
        let mut state = CallListState::new();
        state.page_down(100);
        assert_eq!(state.selected(), 20);
    }

    #[test]
    fn call_list_state_page_up() {
        let mut state = CallListState::new();
        state.move_to_bottom(100);
        state.page_up();
        assert_eq!(state.selected(), 79);
    }

    #[test]
    fn call_list_state_toggle_selection() {
        let mut state = CallListState::new();
        assert!(state.selected_rows.is_empty());
        state.toggle_selection();
        assert_eq!(state.selected_rows, vec![0]);
        state.toggle_selection();
        assert!(state.selected_rows.is_empty());
    }

    #[test]
    fn sort_column_toggle() {
        let mut state = CallListState::new();
        assert_eq!(state.sort_column(), SortColumn::Index);
        assert!(state.sort_ascending());

        state.set_sort(SortColumn::Method);
        assert_eq!(state.sort_column(), SortColumn::Method);
        assert!(state.sort_ascending());

        // Same column again toggles direction
        state.set_sort(SortColumn::Method);
        assert!(!state.sort_ascending());
    }

    #[test]
    fn format_state_strings() {
        assert_eq!(format_state(&DialogState::Trying), "Trying");
        assert_eq!(format_state(&DialogState::InCall), "InCall");
        assert_eq!(format_state(&DialogState::Failed), "FAILED");
        assert_eq!(format_state(&DialogState::Completed), "Completed");
    }

    #[test]
    fn format_duration_sub_minute() {
        let start = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::TimeDelta::milliseconds(5500);
        assert_eq!(format_duration(start, end), "5.5s");
    }

    #[test]
    fn format_duration_minutes() {
        let start = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::TimeDelta::seconds(125);
        assert_eq!(format_duration(start, end), "2m5s");
    }

    #[test]
    fn format_duration_hours() {
        let start = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::TimeDelta::seconds(3700);
        assert_eq!(format_duration(start, end), "1h1m");
    }
}
