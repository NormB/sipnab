//! Call list view — sortable, filterable dialog table.
//!
//! Displays all tracked SIP dialogs in a table with columns for index,
//! method, from/to users, source/destination addresses, state, message
//! count, duration, and PDD. Rows are color-coded by dialog state and
//! show diagnosis warning indicators.

use std::cmp::Ordering;
use std::collections::HashSet;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};

use crate::sip::dialog::DialogState;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;
use super::TimestampMode;

// ── Sort column ─────────────────────────────────────────────────────

/// Column identifiers for the call list table.
///
/// Each variant corresponds to a visible column. The ordering matches
/// the default column display order and is used for sort cycling.
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
    /// Sort by source address.
    Source,
    /// Sort by destination address.
    Destination,
    /// Sort by dialog state.
    State,
    /// Sort by message count.
    Messages,
    /// Sort by creation date.
    Date,
    /// Sort by Post-Dial Delay.
    Pdd,
}

/// All columns in display order, used for cycling with `<` and `>`.
pub const ALL_COLUMNS: [SortColumn; 10] = [
    SortColumn::Index,
    SortColumn::Method,
    SortColumn::From,
    SortColumn::To,
    SortColumn::Source,
    SortColumn::Destination,
    SortColumn::State,
    SortColumn::Messages,
    SortColumn::Date,
    SortColumn::Pdd,
];

/// Column display labels matching [`ALL_COLUMNS`] order.
pub const COLUMN_LABELS: [&str; 10] = [
    "#",
    "Method",
    "From",
    "To",
    "Source",
    "Destination",
    "State",
    "Msgs",
    "Date",
    "PDD",
];

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
    selected_rows: HashSet<usize>,
    /// Per-column visibility (indexed by [`ALL_COLUMNS`] order).
    pub visible_columns: [bool; 10],
    /// Whether the column selector popup is open.
    pub column_selector_open: bool,
    /// Currently highlighted row in the column selector popup.
    pub column_selector_cursor: usize,
    /// Whether autoscroll is enabled (new dialogs scroll to bottom).
    pub autoscroll: bool,
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
            selected_rows: HashSet::new(),
            visible_columns: [true; 10],
            column_selector_open: false,
            column_selector_cursor: 0,
            autoscroll: true,
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
        if !self.selected_rows.remove(&idx) {
            self.selected_rows.insert(idx);
        }
    }

    /// Return the count of multi-selected rows.
    pub fn selected_rows_count(&self) -> usize {
        self.selected_rows.len()
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

    /// Reverse the current sort direction.
    pub fn reverse_sort(&mut self) {
        self.sort_ascending = !self.sort_ascending;
    }

    /// Cycle to the next sort column (wrapping at the end).
    pub fn sort_next_column(&mut self) {
        let current_idx = ALL_COLUMNS
            .iter()
            .position(|c| *c == self.sort_column)
            .unwrap_or(0);
        let next_idx = (current_idx + 1) % ALL_COLUMNS.len();
        self.sort_column = ALL_COLUMNS[next_idx];
        self.sort_ascending = true;
    }

    /// Cycle to the previous sort column (wrapping at the beginning).
    pub fn sort_prev_column(&mut self) {
        let current_idx = ALL_COLUMNS
            .iter()
            .position(|c| *c == self.sort_column)
            .unwrap_or(0);
        let prev_idx = if current_idx == 0 {
            ALL_COLUMNS.len() - 1
        } else {
            current_idx - 1
        };
        self.sort_column = ALL_COLUMNS[prev_idx];
        self.sort_ascending = true;
    }

    /// Return the index of the current sort column in [`ALL_COLUMNS`].
    pub fn sort_column_index(&self) -> usize {
        ALL_COLUMNS
            .iter()
            .position(|c| *c == self.sort_column)
            .unwrap_or(0)
    }

    /// Toggle visibility of the column at the column selector cursor.
    pub fn toggle_column_visibility(&mut self) {
        if self.column_selector_cursor < self.visible_columns.len() {
            self.visible_columns[self.column_selector_cursor] =
                !self.visible_columns[self.column_selector_cursor];
        }
    }

    /// Move the column selector cursor up.
    pub fn column_selector_up(&mut self) {
        if self.column_selector_cursor > 0 {
            self.column_selector_cursor -= 1;
        }
    }

    /// Move the column selector cursor down.
    pub fn column_selector_down(&mut self) {
        if self.column_selector_cursor + 1 < ALL_COLUMNS.len() {
            self.column_selector_cursor += 1;
        }
    }

    /// Apply column visibility from a config list of column names.
    ///
    /// When `names` is non-empty, only columns whose label appears in
    /// the list are visible; all others are hidden. Unknown names are
    /// silently ignored. When `names` is empty, visibility is unchanged.
    pub fn apply_visible_columns(&mut self, names: &[String]) {
        if names.is_empty() {
            return;
        }
        for (i, label) in COLUMN_LABELS.iter().enumerate() {
            self.visible_columns[i] = names.iter().any(|n| n.eq_ignore_ascii_case(label));
        }
    }

    /// Clear the multi-selected rows list.
    pub fn clear_selections(&mut self) {
        self.selected_rows.clear();
    }

    /// Return the multi-selected row indices.
    pub fn selected_rows(&self) -> &HashSet<usize> {
        &self.selected_rows
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
#[allow(clippy::too_many_arguments)]
pub fn render_call_list(
    frame: &mut Frame,
    area: Rect,
    state: &mut CallListState,
    store: &DialogStore,
    filter: Option<&FilterExpr>,
    search_query: &str,
    timestamp_mode: TimestampMode,
    theme: &super::Theme,
) {
    // The entire area is used for the table (no title line)
    let table_area = area;

    // sngrep header style: bold on header-color background
    let header_style = Style::default()
        .bg(theme.header)
        .add_modifier(Modifier::BOLD);

    // Determine which column indices are visible
    let vis_indices: Vec<usize> = (0..10)
        .filter(|&i| state.visible_columns[i])
        .collect();

    // Build header cells with sort indicator on the active sort column
    let sort_col_idx = state.sort_column_index();
    let sort_indicator = if state.sort_ascending() {
        " \u{25b2}"
    } else {
        " \u{25bc}"
    };
    let base_labels = [
        " # ",
        "Method",
        "From",
        "To",
        "Source",
        "Destination",
        "State",
        "Msgs",
        "Date",
        "PDD",
    ];
    let header_cells: Vec<Cell> = vis_indices
        .iter()
        .map(|&i| {
            if i == sort_col_idx {
                Cell::from(format!("{}{}", base_labels[i].trim(), sort_indicator))
            } else {
                Cell::from(base_labels[i])
            }
        })
        .collect();

    let header = Row::new(header_cells).style(header_style).bottom_margin(0);

    // Dynamic column widths based on available terminal width,
    // filtered to only include visible columns.
    let all_widths = compute_column_widths(table_area.width);
    let widths: Vec<Constraint> = vis_indices
        .iter()
        .map(|&i| all_widths[i])
        .collect();

    let mut dialogs: Vec<_> = if let Some(filter) = filter {
        store
            .iter()
            .filter(|d| filter.matches_dialog(d, &[]))
            .collect()
    } else {
        store.iter().collect()
    };

    // Text search: filter across all visible fields (case-insensitive),
    // falling back to raw message body search (like sngrep/Wireshark).
    if !search_query.is_empty() {
        let q = search_query.to_ascii_lowercase();
        dialogs.retain(|d| {
            d.call_id.to_ascii_lowercase().contains(&q)
                || d.method.to_ascii_lowercase().contains(&q)
                || d.from_user.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                || d.to_user.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                || d.src_addr.to_string().contains(&q)
                || d.dst_addr.to_string().contains(&q)
                || state_display_str(&d.state).to_ascii_lowercase().contains(&q)
                || d.messages.iter().any(|msg| {
                    String::from_utf8_lossy(&msg.raw)
                        .to_ascii_lowercase()
                        .contains(&q)
                })
        });
    }

    // Sort dialogs by the selected column
    sort_dialogs(&mut dialogs, state.sort_column(), state.sort_ascending());

    // Always render the header, even when empty (sngrep style).
    // Show a help message below the header if there are no dialogs.
    if dialogs.is_empty() {
        let empty_table = Table::new(Vec::<Row>::new(), widths)
            .header(header)
            .column_spacing(1);
        frame.render_stateful_widget(empty_table, table_area, &mut state.table_state);

        // Render help message below the header row
        if table_area.height > 1 {
            let msg_area = Rect {
                x: table_area.x,
                y: table_area.y + 1,
                width: table_area.width,
                height: table_area.height - 1,
            };
            frame.render_widget(
                Paragraph::new(
                    "\n  No SIP dialogs found.\n\n  If reading a pcap file, it may not contain SIP traffic.\n  Press 'q' to quit, F1 for help.",
                )
                .style(Style::default().fg(theme.muted)),
                msg_area,
            );
        }
        return;
    }

    // Only build Row objects for the visible window. The header takes 1 row,
    // so the visible data rows = area height - 1. We compute the scroll
    // offset from the selected row and only format rows within the window.
    let visible_rows = table_area.height.saturating_sub(1) as usize; // subtract header
    let selected = state.selected();
    let total = dialogs.len();

    // Compute scroll offset: keep selected row within the visible window
    let current_offset = state.table_state.offset();
    let scroll_offset = if selected < current_offset {
        selected
    } else if selected >= current_offset + visible_rows {
        selected.saturating_sub(visible_rows.saturating_sub(1))
    } else {
        current_offset
    };

    let visible_end = (scroll_offset + visible_rows).min(total);
    let visible_dialogs = &dialogs[scroll_offset..visible_end];

    // Reference timestamps for delta modes (from full sorted list, not just visible slice)
    let first_ts = dialogs.first().map(|d| d.created_at);

    let rows: Vec<Row> = visible_dialogs
        .iter()
        .enumerate()
        .map(|(vis_idx, dialog)| {
            let idx = scroll_offset + vis_idx; // original index in full list

            // Show selection marker for multi-selected rows
            let diag_icon = if state.selected_rows.contains(&idx) {
                "\u{25B8}" // ▸
            } else {
                " "
            };

            // Date column formatting based on timestamp mode
            let date_str = match timestamp_mode {
                TimestampMode::Absolute => {
                    dialog.created_at.format("%H:%M:%S").to_string()
                }
                TimestampMode::DeltaPrev => {
                    // Delta from previous dialog in the sorted list
                    let full_idx = scroll_offset + vis_idx;
                    let prev_ts = if full_idx > 0 {
                        Some(dialogs[full_idx - 1].created_at)
                    } else {
                        None
                    };
                    match prev_ts {
                        Some(prev) => format_delta(dialog.created_at - prev),
                        None => "+0.000s".to_string(),
                    }
                }
                TimestampMode::DeltaFirst => {
                    match first_ts {
                        Some(first) => format_delta(dialog.created_at - first),
                        None => "+0.000s".to_string(),
                    }
                }
                TimestampMode::Scaled => {
                    // Scaled mode uses delta-prev in the call list
                    let full_idx = scroll_offset + vis_idx;
                    let prev_ts = if full_idx > 0 {
                        Some(dialogs[full_idx - 1].created_at)
                    } else {
                        None
                    };
                    match prev_ts {
                        Some(prev) => format_delta(dialog.created_at - prev),
                        None => "+0.000s".to_string(),
                    }
                }
            };

            let pdd = dialog
                .timing
                .pdd_ms()
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_default();

            // Method cell colors (sngrep style)
            let method_style = match dialog.method.as_str() {
                "INVITE" => Style::default().fg(theme.good),
                "BYE" => Style::default().fg(theme.bad),
                "CANCEL" => Style::default().fg(theme.warning),
                "REGISTER" => Style::default().fg(theme.header),
                _ => Style::default(),
            };

            let all_cells = [
                Cell::from(Span::raw(format!("{}{}", diag_icon, idx + 1))),
                Cell::from(Span::styled(dialog.method.as_str(), method_style)),
                Cell::from(Span::raw(dialog.from_user.as_deref().unwrap_or("-"))),
                Cell::from(Span::raw(dialog.to_user.as_deref().unwrap_or("-"))),
                Cell::from(Span::raw(dialog.src_addr.to_string())),
                Cell::from(Span::raw(dialog.dst_addr.to_string())),
                Cell::from(Span::styled(
                    state_display_str(&dialog.state),
                    state_style(&dialog.state, theme),
                )),
                Cell::from(Span::raw(dialog.messages.len().to_string())),
                Cell::from(Span::raw(date_str)),
                Cell::from(Span::raw(pdd)),
            ];
            let visible_cells: Vec<Cell> = vis_indices
                .iter()
                .map(|&i| all_cells[i].clone())
                .collect();
            let row = Row::new(visible_cells);

            // Row style based on state
            let row_style = match dialog.state {
                DialogState::Failed => Style::default().fg(theme.bad),
                DialogState::InCall | DialogState::Active => Style::default().fg(theme.good),
                DialogState::Cancelled => Style::default().fg(theme.warning),
                _ => Style::default(),
            };

            // If multi-selected, bold the row instead of underline
            let row_style = if state.selected_rows.contains(&idx) {
                row_style.add_modifier(Modifier::BOLD)
            } else {
                row_style
            };

            row.style(row_style)
        })
        .collect();

    // Adjust TableState: selected row is relative to the visible slice
    let relative_selected = selected.saturating_sub(scroll_offset);
    state.table_state.select(Some(relative_selected));
    *state.table_state.offset_mut() = 0; // rows are pre-sliced, offset is 0

    // sngrep-style: no borders, reverse video for selected row
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    frame.render_stateful_widget(table, table_area, &mut state.table_state);

    // Restore absolute selected index so the rest of the app works correctly
    state.table_state.select(Some(selected));
    *state.table_state.offset_mut() = scroll_offset;
}

// ── Column width calculation ───────────────────────────────────────

/// Compute dynamic column widths based on available terminal width.
///
/// Fixed-width columns (index, method, state, msgs, date, pdd) keep their
/// minimum sizes. From/To and Source/Destination share the remaining space
/// proportionally.
fn compute_column_widths(total_width: u16) -> Vec<Constraint> {
    // Compute explicit column widths to guarantee no truncation of key fields.
    //
    // Fixed columns: # + Method + State + Msgs + Date + PDD
    // Flex columns: From, To, Source, Destination share remaining space.
    //
    // At >= 120 cols: all columns generous, From/To visible.
    // At 80-119 cols: From/To get smaller but still visible.
    // At < 80 cols:   From/To get minimum, everything compressed.

    // Column spacing consumed by ratatui: 1px between each of 10 cols = 9,
    // plus 2 for the highlight symbol ">" prefix.
    let overhead: u16 = 11;

    if total_width >= 120 {
        // Fixed: #(5) + Method(10) + State(12) + Msgs(5) + Date(8) + PDD(8) = 48
        let fixed: u16 = 48 + overhead;
        let flex = total_width.saturating_sub(fixed);
        // Src/Dst each get 21+, From/To split remainder
        let addr_each = 21.min(flex / 4);
        let from_to_pool = flex.saturating_sub(addr_each * 2);
        let from_w = from_to_pool / 2;
        let to_w = from_to_pool - from_w;
        vec![
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Length(from_w),
            Constraint::Length(to_w),
            Constraint::Length(addr_each),
            Constraint::Length(addr_each),
            Constraint::Length(12),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(8),
        ]
    } else {
        // Tighter layout: #(4) + Method(8) + State(10) + Msgs(4) + Date(8) + PDD(6) = 40
        let fixed: u16 = 40 + overhead;
        let flex = total_width.saturating_sub(fixed);
        let addr_each = (flex * 2 / 5).max(11);
        let from_to_pool = flex.saturating_sub(addr_each * 2);
        let from_w = (from_to_pool / 2).max(4);
        let to_w = from_to_pool.saturating_sub(from_w).max(4);
        vec![
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Length(from_w),
            Constraint::Length(to_w),
            Constraint::Length(addr_each),
            Constraint::Length(addr_each),
            Constraint::Length(10),
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Length(6),
        ]
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a [`DialogState`] as a short display string (&'static str, zero-alloc).
pub fn state_display_str(state: &DialogState) -> &'static str {
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => "FAILED",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Sort a list of dialog references by the given column and direction.
fn sort_dialogs(
    dialogs: &mut [&crate::sip::dialog::SipDialog],
    column: SortColumn,
    ascending: bool,
) {
    dialogs.sort_by(|a, b| {
        let ord = match column {
            SortColumn::Index => Ordering::Equal, // insertion order is the default
            SortColumn::Method => a.method.cmp(&b.method),
            SortColumn::From => a
                .from_user
                .as_deref()
                .unwrap_or("")
                .cmp(b.from_user.as_deref().unwrap_or("")),
            SortColumn::To => a
                .to_user
                .as_deref()
                .unwrap_or("")
                .cmp(b.to_user.as_deref().unwrap_or("")),
            SortColumn::Source => a.src_addr.cmp(&b.src_addr),
            SortColumn::Destination => a.dst_addr.cmp(&b.dst_addr),
            SortColumn::State => state_display_str(&a.state).cmp(state_display_str(&b.state)),
            SortColumn::Messages => a.messages.len().cmp(&b.messages.len()),
            SortColumn::Date => a.created_at.cmp(&b.created_at),
            SortColumn::Pdd => a
                .timing
                .pdd_ms()
                .unwrap_or(i64::MAX)
                .cmp(&b.timing.pdd_ms().unwrap_or(i64::MAX)),
        };
        if ascending { ord } else { ord.reverse() }
    });
}

/// Render the column selector popup as a centered overlay.
pub fn render_column_selector(frame: &mut Frame, area: Rect, state: &CallListState, theme: &super::Theme) {
    let popup_width: u16 = 38;
    let popup_height: u16 = (ALL_COLUMNS.len() as u16) + 5; // columns + borders + footer
    let w = popup_width.min(area.width);
    let h = popup_height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup_area = Rect::new(x, y, w, h);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Columns ")
        .style(Style::default().bg(theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let mut lines: Vec<ratatui::text::Line<'_>> = Vec::new();
    for (i, label) in COLUMN_LABELS.iter().enumerate() {
        let check = if state.visible_columns[i] { "x" } else { " " };
        let prefix = if i == state.column_selector_cursor {
            "> "
        } else {
            "  "
        };
        let style = if i == state.column_selector_cursor {
            Style::default()
                .fg(theme.selected)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(ratatui::text::Line::from(Span::styled(
            format!("{}[{}] {:<16}", prefix, check, label),
            style,
        )));
    }
    lines.push(ratatui::text::Line::from(""));
    lines.push(ratatui::text::Line::from(Span::styled(
        "  Space: toggle  Enter: apply",
        Style::default().fg(theme.muted),
    )));

    let visible_lines: Vec<ratatui::text::Line<'_>> =
        lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(theme.background));
    frame.render_widget(para, inner);
}

/// Format a chrono TimeDelta as `+N.NNNs`.
fn format_delta(delta: chrono::TimeDelta) -> String {
    let ms = delta.num_milliseconds();
    format!("+{:.3}s", ms as f64 / 1000.0)
}

/// Return a style for a dialog state label.
fn state_style(state: &DialogState, theme: &super::Theme) -> Style {
    match state {
        DialogState::Failed => Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
        DialogState::InCall | DialogState::Active => Style::default().fg(theme.good),
        DialogState::Cancelled => Style::default().fg(theme.warning),
        DialogState::Completed | DialogState::Registered => Style::default().fg(theme.header),
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
        assert!(state.selected_rows.contains(&0));
        assert_eq!(state.selected_rows.len(), 1);
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
        assert_eq!(state_display_str(&DialogState::Trying), "Trying");
        assert_eq!(state_display_str(&DialogState::InCall), "InCall");
        assert_eq!(state_display_str(&DialogState::Failed), "FAILED");
        assert_eq!(state_display_str(&DialogState::Completed), "Completed");
    }
}
