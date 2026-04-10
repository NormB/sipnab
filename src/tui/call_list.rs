//! Call list view — sortable, filterable dialog table.
//!
//! Displays all tracked SIP dialogs in a table with columns for index,
//! method, from/to users, source/destination addresses, state, message
//! count, duration, and PDD. Rows are color-coded by dialog state and
//! show diagnosis warning indicators.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};

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
///
/// Uses sngrep-style: borderless, bold-on-cyan header, reverse-video
/// selected row, full-width layout. No title line -- status is rendered
/// separately at the top of the screen.
pub fn render_call_list(
    frame: &mut Frame,
    area: Rect,
    state: &mut CallListState,
    store: &DialogStore,
    filter: Option<&FilterExpr>,
) {
    // The entire area is used for the table (no title line)
    let table_area = area;

    // sngrep header style: bold on cyan background
    let header_style = Style::default()
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(" # "),
        Cell::from("Method"),
        Cell::from("From"),
        Cell::from("To"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("State"),
        Cell::from("Msgs"),
        Cell::from("Date"),
        Cell::from("PDD"),
    ])
    .style(header_style)
    .bottom_margin(0);

    let dialogs: Vec<_> = if let Some(filter) = filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .collect()
    } else {
        store.iter().collect()
    };

    // Show a centered help message when there are no dialogs
    if dialogs.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No SIP dialogs found.\n\nIf reading a pcap file, it may not contain SIP traffic.\nPress 'q' to quit, F1 for help.",
            )
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
            table_area,
        );
        return;
    }

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

            // Date column: HH:MM:SS of first message
            let date_str = dialog.created_at.format("%H:%M:%S").to_string();

            let pdd = dialog
                .timing
                .pdd_ms()
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_default();

            // Method cell colors (sngrep style)
            let method_style = match dialog.method.as_str() {
                "INVITE" => Style::default().fg(Color::Green),
                "BYE" => Style::default().fg(Color::Red),
                "CANCEL" => Style::default().fg(Color::Yellow),
                "REGISTER" => Style::default().fg(Color::Cyan),
                _ => Style::default(),
            };

            let row = Row::new(vec![
                Cell::from(Span::raw(format!("{}{}", diag_icon, idx + 1))),
                Cell::from(Span::styled(dialog.method.as_str(), method_style)),
                Cell::from(Span::raw(dialog.from_user.as_deref().unwrap_or("-"))),
                Cell::from(Span::raw(dialog.to_user.as_deref().unwrap_or("-"))),
                Cell::from(Span::raw(dialog.src_addr.to_string())),
                Cell::from(Span::raw(dialog.dst_addr.to_string())),
                Cell::from(Span::styled(
                    format_state(&dialog.state),
                    state_style(&dialog.state),
                )),
                Cell::from(Span::raw(dialog.messages.len().to_string())),
                Cell::from(Span::raw(date_str)),
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
        Constraint::Length(10), // Date
        Constraint::Length(8),  // PDD
    ];

    // sngrep-style: no borders, reverse video for selected row
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    frame.render_stateful_widget(table, table_area, &mut state.table_state);
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
}
