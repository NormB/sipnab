// SPDX-License-Identifier: MIT OR Apache-2.0

//! Call list view — sortable, filterable dialog table.
//!
//! Displays all tracked SIP dialogs in a table with columns for index,
//! method, from/to users, source/destination addresses, state, message
//! count, duration, and PDD. Rows are color-coded by dialog state, and the
//! State cell carries a `⚠` marker when the dialog has a signalling
//! diagnosis — a final failure, an authentication loop, or an unanswered
//! retransmission.
//!
//! That last sentence used to read "show diagnosis warning indicators" and
//! nothing in this file implemented one. It is true now.

use std::cmp::Ordering;
use std::collections::HashSet;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};

use super::TimestampMode;
use crate::sip::dialog::DialogState;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;

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
    /// Sort by dialog duration (first to last message).
    Duration,
}

/// All columns in display order, used for cycling with `<` and `>`.
pub const ALL_COLUMNS: [SortColumn; 11] = [
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
    SortColumn::Duration,
];

/// Column display labels matching `ALL_COLUMNS` order.
pub const COLUMN_LABELS: [&str; 11] = [
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
    "Duration",
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
    selected_rows: HashSet<String>,
    /// Per-column visibility (indexed by `ALL_COLUMNS` order).
    pub visible_columns: [bool; 11],
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
            visible_columns: [true; 11],
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

    /// Clamp the selection and the saved scroll offset onto the displayed
    /// list after it shrank (narrowed filter/search, evicted dialogs), so
    /// navigation and the render window always anchor to a real row.
    pub fn clamp_to(&mut self, item_count: usize) {
        let last = item_count.saturating_sub(1);
        if self.selected() > last {
            self.table_state.select(Some(last));
        }
        if self.table_state.offset() > last {
            *self.table_state.offset_mut() = last;
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

    /// Toggle multi-selection for the given dialog. Checkmarks are keyed by
    /// Call-ID so they stay on the same call when the list is re-sorted,
    /// re-filtered, or grows while the user works.
    pub fn toggle_selection(&mut self, call_id: &str) {
        if !self.selected_rows.remove(call_id) {
            self.selected_rows.insert(call_id.to_string());
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

    /// Return the index of the current sort column in `ALL_COLUMNS`.
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

    /// The labels of the currently-visible columns, in `COLUMN_LABELS` order.
    /// Inverse of `apply_visible_columns`; used to persist the column
    /// layout to `[display] visible_columns`.
    ///
    /// # Returns
    ///
    /// One label per visible column; empty when every column is hidden.
    pub fn visible_column_names(&self) -> Vec<String> {
        COLUMN_LABELS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.visible_columns[*i])
            .map(|(_, &label)| label.to_string())
            .collect()
    }

    /// Clear the multi-selected rows list.
    pub fn clear_selections(&mut self) {
        self.selected_rows.clear();
    }

    /// Return the multi-selected row indices.
    pub fn selected_rows(&self) -> &HashSet<String> {
        &self.selected_rows
    }
}

impl Default for CallListState {
    /// Equivalent to `CallListState::new()`.
    fn default() -> Self {
        Self::new()
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Display parameters for the call list view.
pub struct CallListDisplay<'a> {
    /// Call-IDs in display order — the tick's cached filter+search+sort
    /// result (`App::sync_caches`), so the render pass derives nothing.
    pub rows: &'a [String],
    /// How the Date column renders timestamps (absolute or delta modes).
    pub timestamp_mode: TimestampMode,
    /// How the From/To columns combine user and host.
    pub from_to_mode: super::FromToMode,
    /// Active color theme.
    pub theme: &'a super::Theme,
    /// IP-to-name resolver for address and host labels.
    pub resolver: &'a crate::names::NameResolver,
    /// Whether/how names are substituted for IPs.
    pub name_mode: crate::names::NameMode,
    /// Reading a pcap file (vs live capture) — selects the empty-state hint.
    pub offline: bool,
}

/// Return true if `dialog` matches the case-insensitive search query,
/// scanning the same fields the call list displays plus raw message bodies
/// (the sngrep/Wireshark-style full-text fallback).
///
/// # Arguments
///
/// * `dialog` — the dialog whose fields and raw messages are scanned.
/// * `query_lower` — the search query, already lowercased by the caller.
///
/// # Returns
///
/// `true` when any of Call-ID, method, From/To user, source/destination
/// address, state label, or any raw message body contains the query
/// (ASCII case folding only); an empty query matches everything.
pub fn dialog_matches_search(dialog: &crate::sip::dialog::SipDialog, query_lower: &str) -> bool {
    let q = query_lower;
    contains_ignore_ascii_case(dialog.call_id.as_bytes(), q)
        || contains_ignore_ascii_case(dialog.method.as_str().as_bytes(), q)
        || contains_ignore_ascii_case(dialog.from_user.as_deref().unwrap_or("").as_bytes(), q)
        || contains_ignore_ascii_case(dialog.to_user.as_deref().unwrap_or("").as_bytes(), q)
        || dialog.src_addr.to_string().contains(q)
        || dialog.dst_addr.to_string().contains(q)
        || contains_ignore_ascii_case(state_display_str(dialog.state()).as_bytes(), q)
        || dialog
            .messages
            .iter()
            .any(|msg| contains_ignore_ascii_case(&msg.raw, q))
}

/// Allocation-free ASCII-case-insensitive substring test — the search hot
/// path. Replaces per-field/per-message `to_ascii_lowercase().contains()`
/// (which copied every stored message body per pass): memchr finds
/// candidate positions of the needle's first byte in either case, then the
/// window is compared with `eq_ignore_ascii_case`. Semantics match the old
/// code: ASCII folding only, non-ASCII bytes verbatim. (Raw bodies are now
/// scanned as bytes rather than through `from_utf8_lossy`; invalid UTF-8
/// sequences no longer turn into U+FFFD before matching.)
fn contains_ignore_ascii_case(haystack: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if haystack.len() < n.len() {
        return false;
    }
    // Candidate first-byte positions must leave room for the whole needle.
    let search_end = haystack.len() - n.len() + 1;
    let lo = n[0].to_ascii_lowercase();
    let up = n[0].to_ascii_uppercase();
    let hit = |pos: usize| haystack[pos..pos + n.len()].eq_ignore_ascii_case(n);
    if lo == up {
        memchr::memchr_iter(lo, &haystack[..search_end]).any(hit)
    } else {
        memchr::memchr2_iter(lo, up, &haystack[..search_end]).any(hit)
    }
}

// Per-thread call counter for `displayed_dialogs`, test-only: pins the
// WS4.3 "derived once per frame" property (thread-local so the parallel
// test runner cannot cross-talk).
#[cfg(test)]
thread_local! {
    /// Test-only per-thread counter of `displayed_dialogs` invocations,
    /// incremented on every call; asserted by frame-derivation tests.
    pub(crate) static DISPLAYED_DIALOGS_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Build the dialog list in the exact order the call list displays it:
/// filtered by `filter`, then by `search_query`, then sorted by the active
/// column/direction.
///
/// This is the single source of truth shared by the renderer and by the
/// save/clear actions, so that multi-select row indices always map to the
/// same dialogs the user sees on screen.
///
/// # Arguments
///
/// * `store` — dialog store to draw candidates from, in insertion order.
/// * `filter` — optional display-filter expression; `None` keeps all.
/// * `search_query` — full-text search narrowing; empty means no narrowing.
/// * `sort_column` — column driving the final ordering.
/// * `sort_ascending` — sort direction.
///
/// # Returns
///
/// Borrowed dialog references in exact display order; empty when nothing
/// passes the filter and search.
///
/// # Side effects
///
/// In test builds only, increments the thread-local
/// `DISPLAYED_DIALOGS_CALLS` counter.
pub fn displayed_dialogs<'a>(
    store: &'a DialogStore,
    filter: Option<&FilterExpr>,
    search_query: &str,
    sort_column: SortColumn,
    sort_ascending: bool,
) -> Vec<&'a crate::sip::dialog::SipDialog> {
    #[cfg(test)]
    DISPLAYED_DIALOGS_CALLS.with(|c| c.set(c.get() + 1));
    let mut dialogs: Vec<_> = match filter {
        // This list is built from dialogs alone; with no stream data it
        // cannot testify that a call carried no media.
        Some(f) => store
            .iter()
            .filter(|d| f.matches_dialog(d, &[], crate::rtp::diagnosis::CaptureMedia::Absent))
            .collect(),
        None => store.iter().collect(),
    };
    if !search_query.is_empty() {
        let q = search_query.to_ascii_lowercase();
        dialogs.retain(|d| dialog_matches_search(d, &q));
    }
    sort_dialogs(&mut dialogs, sort_column, sort_ascending);
    dialogs
}

/// Render the call list table into the given area.
///
/// Uses sngrep-style: borderless, bold-on-cyan header, reverse-video
/// selected row, full-width layout. No title line -- status is rendered
/// separately at the top of the screen. When the displayed list is
/// empty, an empty header plus an offline/live-specific hint is drawn
/// instead.
///
/// # Arguments
///
/// * `frame` — ratatui frame to draw into.
/// * `area` — screen rectangle the table occupies.
/// * `state` — mutable list state (selection, scroll offset, sort,
///   multi-select, column visibility).
/// * `store` — dialog store used to resolve the cached row ids to
///   dialogs for the visible window only.
/// * `display` — per-frame display parameters, including the tick's
///   cached display-ordered row ids.
///
/// # Side effects
///
/// Draws widgets into `frame`. Mutates `state.table_state`: the
/// selection is clamped onto the current row count and the scroll
/// offset is recomputed to keep the selection visible (both are
/// temporarily rebased to the visible slice during the stateful render
/// and then restored to absolute values).
pub fn render_call_list(
    frame: &mut Frame,
    area: Rect,
    state: &mut CallListState,
    store: &DialogStore,
    display: &CallListDisplay<'_>,
) {
    let timestamp_mode = display.timestamp_mode;
    let theme = display.theme;
    // The entire area is used for the table (no title line)
    let table_area = area;

    // sngrep header style: bold on header-color background
    let header_style = Style::default()
        .bg(theme.header)
        .add_modifier(Modifier::BOLD);

    // Determine which column indices are visible
    let vis_indices: Vec<usize> = (0..COLUMN_LABELS.len())
        .filter(|&i| state.visible_columns[i])
        .collect();

    // Build header cells with sort indicator on the active sort column
    let sort_col_idx = state.sort_column_index();
    let sort_indicator = if state.sort_ascending() {
        " \u{25b2}"
    } else {
        " \u{25bc}"
    };
    // Header labels are exactly COLUMN_LABELS, except the index column is
    // padded (" # " vs "#") so its lone glyph isn't cramped against the
    // checkbox in the first cell. Derive from COLUMN_LABELS so the two lists
    // can't drift apart.
    let mut base_labels = COLUMN_LABELS;
    base_labels[0] = " # ";
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
    let widths: Vec<Constraint> = vis_indices.iter().map(|&i| all_widths[i]).collect();

    // The displayed list (filter + search + sort) was derived once this
    // tick by App::sync_caches and arrives as display-ordered call-ids;
    // only the rows actually drawn are resolved against the store.
    let row_ids = display.rows;

    // Always render the header, even when empty (sngrep style).
    // Show a help message below the header if there are no dialogs.
    if row_ids.is_empty() {
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
            let hint = if display.offline {
                "\n  No SIP dialogs found.\n\n  The pcap file may not contain SIP traffic.\n  Press 'q' to quit, F1 for help."
            } else {
                "\n  No SIP dialogs found.\n\n  Waiting for SIP traffic on the capture source\u{2026}\n  Press 'q' to quit, F1 for help."
            };
            frame.render_widget(
                Paragraph::new(hint).style(Style::default().fg(theme.muted)),
                msg_area,
            );
        }
        return;
    }

    // Only build Row objects for the visible window. The header takes 1 row,
    // so the visible data rows = area height - 1. We compute the scroll
    // offset from the selected row and only format rows within the window.
    let visible_rows = table_area.height.saturating_sub(1) as usize; // subtract header
    let total = row_ids.len();
    // The selection and the saved scroll offset may be stale from a frame
    // rendered before the displayed list shrank (filter/search narrowed,
    // dialogs evicted); clamp both so the window slice below stays in
    // bounds. `total > 0` here — the empty list returned above.
    let selected = state.selected().min(total - 1);

    // Compute scroll offset: keep selected row within the visible window
    let current_offset = state.table_state.offset();
    let scroll_offset = if selected < current_offset {
        selected
    } else if selected >= current_offset + visible_rows {
        selected.saturating_sub(visible_rows.saturating_sub(1))
    } else {
        current_offset
    }
    .min(total - 1);

    let visible_end = (scroll_offset + visible_rows).min(total);
    // Resolve only the visible window (a cached id can miss if the dialog
    // was evicted since the tick's sync — the row simply skips one frame).
    let visible_dialogs: Vec<&crate::sip::dialog::SipDialog> = row_ids[scroll_offset..visible_end]
        .iter()
        .filter_map(|id| store.get(id))
        .collect();

    // Reference timestamps for delta modes (from full sorted list, not just visible slice)
    let first_ts = row_ids
        .first()
        .and_then(|id| store.get(id))
        .map(|d| d.created_at);

    let rows: Vec<Row> = visible_dialogs
        .iter()
        .enumerate()
        .map(|(vis_idx, dialog)| {
            let idx = scroll_offset + vis_idx; // original index in full list

            // sngrep-style selection checkbox: [*] when checked, [ ] otherwise.
            // The checkbox marks which dialogs an action (e.g. save) applies to.
            let checkbox = if state.selected_rows.contains(dialog.call_id.as_str()) {
                "[*]"
            } else {
                "[ ]"
            };

            // Method cell colors (sngrep style)
            let method_style = match dialog.method.as_str() {
                "INVITE" => Style::default().fg(theme.good),
                "BYE" => Style::default().fg(theme.bad),
                "CANCEL" => Style::default().fg(theme.warning),
                "REGISTER" => Style::default().fg(theme.header),
                _ => Style::default(),
            };

            // Date column formatting based on timestamp mode. Deferred into a
            // closure so the delta lookups run only when the Date column is
            // actually one of the visible columns.
            let date_str = || -> String {
                match timestamp_mode {
                    TimestampMode::Absolute => dialog.created_at.format("%H:%M:%S").to_string(),
                    // Scaled has no distinct call-list rendering: its spacer-row
                    // stretching is a call-flow concern, so here it falls
                    // through to the same delta-from-previous-dialog display as
                    // DeltaPrev (see `TimestampMode::Scaled`).
                    TimestampMode::DeltaPrev | TimestampMode::Scaled => {
                        // Delta from previous dialog in the sorted list
                        let full_idx = scroll_offset + vis_idx;
                        let prev_ts = if full_idx > 0 {
                            row_ids
                                .get(full_idx - 1)
                                .and_then(|id| store.get(id))
                                .map(|d| d.created_at)
                        } else {
                            None
                        };
                        match prev_ts {
                            Some(prev) => format_delta(dialog.created_at - prev),
                            None => "+0.000s".to_string(),
                        }
                    }
                    TimestampMode::DeltaFirst => match first_ts {
                        Some(first) => format_delta(dialog.created_at - first),
                        None => "+0.000s".to_string(),
                    },
                }
            };

            // Build cells for the visible columns only. Each match arm does its
            // own formatting/allocation on demand, so hidden columns cost
            // nothing and there is no all-columns array to clone per row.
            let visible_cells: Vec<Cell> = vis_indices
                .iter()
                .map(|&i| match i {
                    0 => Cell::from(Span::raw(format!("{}{}", checkbox, idx + 1))),
                    1 => Cell::from(Span::styled(dialog.method.as_str(), method_style)),
                    2 => Cell::from(Span::raw(format_from_to(
                        display.from_to_mode,
                        dialog.from_user.as_deref(),
                        dialog.from_host.as_deref(),
                        display.resolver,
                        display.name_mode,
                    ))),
                    3 => Cell::from(Span::raw(format_from_to(
                        display.from_to_mode,
                        dialog.to_user.as_deref(),
                        dialog.to_host.as_deref(),
                        display.resolver,
                        display.name_mode,
                    ))),
                    4 => Cell::from(Span::raw(
                        display
                            .resolver
                            .label_ip(dialog.src_addr, display.name_mode),
                    )),
                    5 => Cell::from(Span::raw(
                        display
                            .resolver
                            .label_ip(dialog.dst_addr, display.name_mode),
                    )),
                    // State, plus a signalling-diagnosis marker when one fired.
                    //
                    // The marker shares the State cell rather than taking a
                    // twelfth column: a new column would mean widening
                    // COLUMN_LABELS, visible_columns, the column selector and the
                    // width table at three breakpoints, and would move most of
                    // the 51 TUI snapshots — a lot of moving parts for one glyph.
                    //
                    // It is deliberately just a marker. The call list is a dense
                    // scan view; which detection fired and the messages behind it
                    // belong in the call flow, where there is room to name them.
                    // What a badge on a row owes the reader is "this one is worth
                    // opening", and the marker says that in two columns.
                    //
                    // Width: State is 12, and the badge costs 2. Every state
                    // except `Transferring` (exactly 12) leaves room; a
                    // transferring dialog that also has a signalling finding is
                    // the one combination where ratatui will clip the marker.
                    // Accepted over widening every layout for a case that needs a
                    // transfer in flight and a failed transaction at once.
                    6 => {
                        let state = dialog.state();
                        let mut spans = vec![Span::styled(
                            state_display_str(state),
                            state_style(state, theme),
                        )];
                        if signaling_marker(dialog) {
                            spans.push(Span::styled(
                                " \u{26a0}",
                                Style::default().fg(theme.warning),
                            ));
                        }
                        Cell::from(ratatui::text::Line::from(spans))
                    }
                    7 => Cell::from(Span::raw(dialog.messages.len().to_string())),
                    8 => Cell::from(Span::raw(date_str())),
                    9 => Cell::from(Span::raw(
                        dialog
                            .timing
                            .pdd_ms()
                            .map(|ms| format!("{}ms", ms))
                            .unwrap_or_default(),
                    )),
                    // Dialog duration (first to last message) — distinct from
                    // PDD, which is only INVITE→first 18x provisional.
                    10 => Cell::from(Span::raw(format_duration_ms(
                        (dialog.updated_at - dialog.created_at).num_milliseconds(),
                    ))),
                    _ => unreachable!("column index {i} out of range"),
                })
                .collect();
            let row = Row::new(visible_cells);

            // Row style based on state
            let row_style = match dialog.state() {
                DialogState::Failed => Style::default().fg(theme.bad),
                DialogState::InCall | DialogState::Active => Style::default().fg(theme.good),
                DialogState::Cancelled => Style::default().fg(theme.warning),
                _ => Style::default(),
            };

            // If multi-selected, bold the row instead of underline
            let row_style = if state.selected_rows.contains(dialog.call_id.as_str()) {
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
///
/// # Arguments
///
/// * `total_width` — full width of the table area in terminal cells.
///
/// # Returns
///
/// One `Constraint::Length` per column in `ALL_COLUMNS` order (always 11
/// entries, regardless of visibility); wider layouts kick in at >= 120
/// columns.
/// Whether a dialog has any signalling finding worth marking on its row.
///
/// Separate from the diagnosis itself so the render path asks one boolean
/// question and nothing in the hot loop formats a string it will not use. The
/// call list redraws on every frame over every visible dialog, so this runs
/// often; the detections are all linear scans of a dialog's own message list,
/// which is the same order of work the row already does to count messages.
fn signaling_marker(dialog: &crate::sip::dialog::SipDialog) -> bool {
    !crate::sip::diagnosis::diagnose_signaling(&dialog.messages).is_empty()
}

fn compute_column_widths(total_width: u16) -> Vec<Constraint> {
    // Compute explicit column widths to guarantee no truncation of key fields.
    //
    // Fixed columns: # + Method + State + Msgs + Date + PDD
    // Flex columns: From, To, Source, Destination share remaining space.
    //
    // At >= 120 cols: all columns generous, From/To visible.
    // At 80-119 cols: From/To get smaller but still visible.
    // At < 80 cols:   From/To get minimum, everything compressed.

    // Column spacing consumed by ratatui: 1px between each of 11 cols = 10,
    // plus 2 for the highlight symbol ">" prefix.
    let overhead: u16 = 12;

    if total_width >= 120 {
        // Fixed: #(6) + Method(10) + State(12) + Msgs(5) + Date(8) + PDD(8)
        // + Duration(8) = 57. #(6) holds "[ ]" plus up to a 3-digit index.
        let fixed: u16 = 57 + overhead;
        let flex = total_width.saturating_sub(fixed);
        // Src/Dst each get 21+, From/To split remainder
        let addr_each = 21.min(flex / 4);
        let from_to_pool = flex.saturating_sub(addr_each * 2);
        let from_w = from_to_pool / 2;
        let to_w = from_to_pool - from_w;
        vec![
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(from_w),
            Constraint::Length(to_w),
            Constraint::Length(addr_each),
            Constraint::Length(addr_each),
            Constraint::Length(12),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ]
    } else {
        // Tighter layout: #(5) + Method(9) + State(10) + Msgs(4) + Date(8)
        // + PDD(6) + Duration(7) = 49. #(5) holds "[ ]" plus a 2-digit index.
        // Method is 9 so the longest common method (SUBSCRIBE) never truncates.
        let fixed: u16 = 49 + overhead;
        let flex = total_width.saturating_sub(fixed);
        // The four flex columns (From, To, Source, Destination) must fit
        // `flex` EXACTLY. Claiming more does not shrink them: ratatui's layout
        // solver balances the row by taking cells back out of the *fixed*
        // columns, and Method absorbs the largest share of it — the whole
        // deficit at 88 cols (Method 9 -> 6), and 4 of 7 at 80 cols (Method
        // 9 -> 5, State -1, Date -2). That is how "SUBSCRIBE" still rendered
        // as "SUBSCR" in the 88-column demo terminal long after the Method
        // constraint itself was widened to 9: the constraint was honest and
        // the pool was not, so widening Method alone could never reach the
        // screen. Every cell handed out below has to be one this pool owns.
        //
        // Src/Dst each still prefer 2/5 of the pool (min 11), but From/To's
        // floor of 4 each is now reserved FIRST, so a minimum is only ever
        // taken while the pool can still pay for it. `saturating_sub(8)`
        // is that reservation; it also drives `addr_each` to 0 rather than
        // overflowing once the pool is smaller than From/To's own floor.
        let addr_each = (flex * 2 / 5).max(11).min(flex.saturating_sub(8) / 2);
        // Exact, not saturating: `addr_each * 2 <= flex` holds by the clamp
        // above, so the remainder below is what is genuinely left over.
        let from_to_pool = flex - addr_each * 2;
        let from_w = from_to_pool / 2;
        let to_w = from_to_pool - from_w;
        vec![
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(from_w),
            Constraint::Length(to_w),
            Constraint::Length(addr_each),
            Constraint::Length(addr_each),
            Constraint::Length(10),
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(7),
        ]
    }
}

/// Format a dialog duration for the call list: sub-second in ms, under a
/// minute in seconds with one decimal, else `MmSs`.
fn format_duration_ms(ms: i64) -> String {
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let secs = ms / 1000;
        format!("{}m{}s", secs / 60, secs % 60)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a `DialogState` as a short display string, with the caller
/// supplying the label for the `Failed` state (`&'static str`, zero-alloc).
///
/// Every state maps to a fixed label except `Failed`: the call list shouts
/// it as `"FAILED"` while the export path renders a plain `"Failed"`. That
/// one divergence is parameterized so the full 12-arm mapping lives in a
/// single place (shared with [`crate::tui::save::format_dialog_state`]).
pub(in crate::tui) fn state_display_labeled(
    state: &DialogState,
    failed_label: &'static str,
) -> &'static str {
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => failed_label,
        DialogState::Redirected => "Redirected",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Format a `DialogState` as a short display string (&'static str, zero-alloc).
/// The call list renders a failed dialog as `"FAILED"`.
pub fn state_display_str(state: &DialogState) -> &'static str {
    state_display_labeled(state, "FAILED")
}

/// Sort a list of dialog references by the given column and direction.
///
/// # Arguments
///
/// * `dialogs` — slice sorted in place; expected in insertion order on
///   entry (the `Index` fast path relies on it).
/// * `column` — which column's key to compare.
/// * `ascending` — `true` for ascending, `false` reverses the ordering.
///
/// # Side effects
///
/// Reorders `dialogs` in place; no allocation for the `Index` column
/// (identity or plain reversal).
fn sort_dialogs(
    dialogs: &mut [&crate::sip::dialog::SipDialog],
    column: SortColumn,
    ascending: bool,
) {
    // Index = insertion order: the input already arrives in insertion order,
    // so ascending is the identity and descending is a plain reversal. (A
    // comparator returning Equal would make reversing the sort a visible
    // no-op on the default column.)
    if matches!(column, SortColumn::Index) {
        if !ascending {
            dialogs.reverse();
        }
        return;
    }
    dialogs.sort_by(|a, b| {
        let ord = match column {
            SortColumn::Index => Ordering::Equal, // handled above
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
            SortColumn::State => state_display_str(a.state()).cmp(state_display_str(b.state())),
            SortColumn::Messages => a.messages.len().cmp(&b.messages.len()),
            SortColumn::Date => a.created_at.cmp(&b.created_at),
            SortColumn::Pdd => a
                .timing
                .pdd_ms()
                .unwrap_or(i64::MAX)
                .cmp(&b.timing.pdd_ms().unwrap_or(i64::MAX)),
            SortColumn::Duration => {
                (a.updated_at - a.created_at).cmp(&(b.updated_at - b.created_at))
            }
        };
        if ascending { ord } else { ord.reverse() }
    });
}

/// Render the column selector popup as a centered overlay.
///
/// # Arguments
///
/// * `frame` — ratatui frame to draw into.
/// * `area` — full screen area the popup is centered within.
/// * `state` — call list state supplying visibility flags and the
///   selector cursor position.
/// * `theme` — active color theme.
///
/// # Side effects
///
/// Clears the popup rectangle and draws the checkbox list plus a
/// two-line key hint footer into `frame`; lines that do not fit the
/// popup height are dropped.
pub fn render_column_selector(
    frame: &mut Frame,
    area: Rect,
    state: &CallListState,
    theme: &super::Theme,
) {
    let popup_width: u16 = 38;
    let popup_height: u16 = (ALL_COLUMNS.len() as u16) + 6; // columns + borders + 2-line footer
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
    lines.push(ratatui::text::Line::from(Span::styled(
        "  s: save layout to config",
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

/// Resolve an IP-literal host (with optional `:port`) through the name resolver
/// so the From/To columns stay consistent with the Source/Dest columns. FQDN
/// hosts, and IP hosts with no mapping, are returned unchanged.
///
/// # Arguments
///
/// * `host` — host part of a SIP URI: bare IPv4/hostname, bracketed
///   IPv6, either optionally followed by a numeric `:port`.
/// * `resolver` — IP-to-name resolver consulted for a mapping.
/// * `name_mode` — resolution mode; `Off` bypasses resolution entirely.
///
/// # Returns
///
/// The resolved `name[:port]` when the host parses as an IP with a
/// known name; otherwise the input unchanged.
fn resolve_host_label(
    host: &str,
    resolver: &crate::names::NameResolver,
    name_mode: crate::names::NameMode,
) -> String {
    use std::net::IpAddr;
    if name_mode == crate::names::NameMode::Off {
        return host.to_string();
    }
    // Bracketed IPv6: `[addr]` or `[addr]:port`.
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let addr = &rest[..close];
            let suffix = &rest[close + 1..]; // ":5060" or ""
            if let Ok(ip) = addr.parse::<IpAddr>()
                && let Some(name) = resolver.name(ip, name_mode)
            {
                return format!("{name}{suffix}");
            }
        }
        return host.to_string();
    }
    // IPv4 / hostname with an optional numeric `:port`.
    let (addr, suffix) = match host.rsplit_once(':') {
        Some((a, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (a, format!(":{p}"))
        }
        _ => (host, String::new()),
    };
    if let Ok(ip) = addr.parse::<IpAddr>()
        && let Some(name) = resolver.name(ip, name_mode)
    {
        return format!("{name}{suffix}");
    }
    host.to_string()
}

/// Format a From/To column cell for the given `FromToMode`, resolving
/// IP-literal hosts through the name resolver.
///
/// # Arguments
///
/// * `mode` — user/host combination mode driving the final layout.
/// * `user` — SIP user part, when present.
/// * `host` — SIP host part, when present; resolved via `resolve_host_label`.
/// * `resolver` — IP-to-name resolver.
/// * `name_mode` — resolution mode.
///
/// # Returns
///
/// The formatted cell text; `"-"` when the mode has neither part to show.
fn format_from_to(
    mode: super::FromToMode,
    user: Option<&str>,
    host: Option<&str>,
    resolver: &crate::names::NameResolver,
    name_mode: crate::names::NameMode,
) -> String {
    let resolved = host.map(|h| resolve_host_label(h, resolver, name_mode));
    mode.format(user, resolved.as_deref())
}

// ── Tests ───────────────────────────────────────────────────────────

/// Unit tests for column layout, search matching, display ordering,
/// list-state navigation, and column-visibility round-trips.
#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: below 120 cols the Method column was `Length(8)`, which
    /// truncated `SUBSCRIBE` (9 chars) — visible on any 80-119-col terminal
    /// and in the demo recordings.
    ///
    /// NECESSARY BUT NOT SUFFICIENT, and the gap shipped: this assertion has
    /// been green since 2026-07-20 while the homepage Search tab still showed
    /// `SUBSCR`, because a `Constraint` is a request, not a rendered width.
    /// See `column_widths_never_oversubscribe_the_terminal` below for the
    /// invariant that makes the request honest, and
    /// `demo_terminal_renders_every_sip_method_whole` in
    /// `tests/site_journey_test.rs` for what actually reaches the screen.
    #[test]
    fn method_column_fits_longest_sip_method_below_120_cols() {
        // Longest common SIP methods: SUBSCRIBE(9), REGISTER(8), OPTIONS(7).
        for width in [80u16, 98, 110, 119] {
            let widths = compute_column_widths(width);
            // Index 1 is the Method column (see COLUMN_LABELS order).
            assert!(
                matches!(widths[1], Constraint::Length(w) if w >= 9),
                "Method column at {width} cols must be >= 9 to fit SUBSCRIBE, \
                 got {:?}",
                widths[1]
            );
        }
    }

    /// The 11 columns must never claim more cells than the terminal has.
    ///
    /// This is the gate the 2026-07-20 Method widening needed and did not
    /// get. When the columns over-claim, ratatui rebalances by taking cells
    /// back out of the fixed columns, and Method absorbs the largest share:
    /// the entire 3-cell deficit at 88 cols (Method 9 -> 6) and 4 of the 7
    /// at 80 cols (Method 9 -> 5). So `Length(9)` bought nothing at the
    /// measured 88-column VHS demo terminal — the constraint read 9 and the
    /// screen read `SUBSCR`, and the committed 80-col snapshots recorded
    /// `INVIT`. 34 of the 59 widths in 61..=119 were over-subscribed.
    ///
    /// Below 61 cols the fixed columns alone (49) plus overhead (12) cannot
    /// fit, so 61 is the narrowest width at which any allocation can hold.
    #[test]
    fn column_widths_never_oversubscribe_the_terminal() {
        // 10 inter-column gaps (`.column_spacing(1)`) + 2 for the `"> "`
        // highlight symbol; see `compute_column_widths`.
        const OVERHEAD: u16 = 12;
        for width in 61u16..=200 {
            let widths = compute_column_widths(width);
            let sum: u16 = widths
                .iter()
                .map(|c| match c {
                    Constraint::Length(n) => *n,
                    other => panic!("non-Length constraint {other:?} at {width} cols"),
                })
                .sum();
            assert!(
                sum + OVERHEAD <= width,
                "at {width} cols the columns claim {sum} + {OVERHEAD} overhead = {} \
                 cells in a {width}-cell row; ratatui charges the {}-cell deficit back \
                 to the fixed columns, Method absorbing the largest share, so a \
                 standard method renders truncated no matter what Length(..) the \
                 Method column asks for. widths: {widths:?}",
                sum + OVERHEAD,
                sum + OVERHEAD - width,
            );
        }
    }

    /// Edge case: on narrow terminals (below ~83 cols) the flex pool is too
    /// small for two 11-wide address columns, so the `.max(11)` floor used to
    /// push the two Source/Destination columns past the shared flex budget.
    /// They must never together exceed the available flex width.
    #[test]
    fn narrow_layout_address_columns_fit_flex_budget() {
        // Column-spacing + highlight-symbol overhead the layout reserves.
        const OVERHEAD: u16 = 12;
        let len = |c: &Constraint| match c {
            Constraint::Length(n) => *n,
            _ => 0,
        };
        // Fixed (non-flex) columns in the narrow layout: #, Method, State,
        // Msgs, Date, PDD, Duration (indices 0,1,6,7,8,9,10).
        const FIXED_COLS: [usize; 7] = [0, 1, 6, 7, 8, 9, 10];
        // Widths spanning the narrow branch, including ones where the old
        // `.max(11)` floor overflowed the pool (61..=82).
        for width in [61u16, 66, 70, 72, 78, 80, 82] {
            let widths = compute_column_widths(width);
            let fixed_sum: u16 = FIXED_COLS.iter().map(|&i| len(&widths[i])).sum();
            let flex = width.saturating_sub(fixed_sum + OVERHEAD);
            // Indices 4 and 5 are Source/Destination.
            let addr_sum = len(&widths[4]) + len(&widths[5]);
            assert!(
                addr_sum <= flex,
                "at {width} cols the address columns ({addr_sum}) must fit the \
                 flex budget ({flex}), got widths {:?}",
                widths
            );
        }
    }

    /// The allocation-free search must match exactly what
    /// `to_ascii_lowercase().contains()` matched: ASCII case folding only,
    /// empty needle always matches, non-ASCII bytes compared verbatim.
    #[test]
    fn contains_ignore_ascii_case_matches_like_lowercased_contains() {
        assert!(contains_ignore_ascii_case(b"INVITE sip:Bob@x", "invite"));
        assert!(contains_ignore_ascii_case(b"abcDEF", "cde"));
        assert!(contains_ignore_ascii_case(b"abcDEF", "CDE"));
        assert!(!contains_ignore_ascii_case(b"abc", "abcd"));
        assert!(!contains_ignore_ascii_case(b"", "x"));
        assert!(contains_ignore_ascii_case(b"", ""));
        assert!(contains_ignore_ascii_case(b"x", ""));
        // needle at the very end
        assert!(contains_ignore_ascii_case(b"Call-ID: ABC", "abc"));
        // digits/punctuation fold to themselves
        assert!(contains_ignore_ascii_case(b"CSeq: 42 INVITE", "42 inv"));
        // non-ASCII bytes are compared verbatim (ASCII folding only)
        assert!(contains_ignore_ascii_case("Ünicode".as_bytes(), "nicode"));
        assert!(!contains_ignore_ascii_case("Ünicode".as_bytes(), "ünicode"));
    }
    use crate::names::{NameMode, NameResolver};
    use std::net::IpAddr;

    // ── dialog_matches_search: exhaustive field + adversarial coverage ──

    /// Build a dialog whose searchable fields are all distinct, so each
    /// test proves WHICH field matched.
    fn searchable_dialog(
        method: &str,
        call_id: &str,
        from: &str,
        to: &str,
    ) -> crate::sip::dialog::SipDialog {
        let raw = crate::test_utils::build_sip_message(
            &format!("{method} sip:{to}@example.com SIP/2.0"),
            &[
                &format!("From: <sip:{from}@example.com>;tag=t1"),
                &format!("To: <sip:{to}@example.com>"),
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 7 {method}"),
                "User-Agent: NeedleInBody/9.9",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = crate::sip::parser::parse_sip(
            &raw,
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 7, 7, 8, 45, 0).unwrap(),
            "192.0.2.10".parse().unwrap(),
            "198.51.100.20".parse().unwrap(),
            5060,
            5062,
            crate::net::TransportProto::Udp,
        )
        .expect("parse");
        crate::sip::dialog::SipDialog::new(&msg).expect("dialog")
    }

    /// Each field the call list displays (plus the raw body) is reachable
    /// by search: one positive assertion per field.
    #[test]
    fn search_matches_every_displayed_field() {
        let d = searchable_dialog("OPTIONS", "cid-xyz@host", "alice", "bob");
        // One assertion per field the call list displays.
        assert!(dialog_matches_search(&d, "cid-xyz")); // Call-ID
        assert!(dialog_matches_search(&d, "options")); // method, folded
        assert!(dialog_matches_search(&d, "alice")); // From user
        assert!(dialog_matches_search(&d, "bob")); // To user
        assert!(dialog_matches_search(&d, "192.0.2.10")); // source addr
        assert!(dialog_matches_search(&d, "198.51.100.20")); // dest addr
        assert!(dialog_matches_search(&d, "needleinbody")); // raw body, folded
        // State string ("Completed"/"Trying"/... per state_display_str).
        let state = state_display_str(d.state()).to_ascii_lowercase();
        assert!(dialog_matches_search(&d, &state));
    }

    /// Absent needles never match, the empty query matches everything, and
    /// an over-long query returns false without panicking.
    #[test]
    fn search_no_match_and_empty_query() {
        let d = searchable_dialog("OPTIONS", "cid-1@host", "alice", "bob");
        assert!(!dialog_matches_search(&d, "zzz-not-present"));
        // Empty query matches everything (no narrowing).
        assert!(dialog_matches_search(&d, ""));
        // Longer than any field: must not panic, must not match.
        let long = "x".repeat(10_000);
        assert!(!dialog_matches_search(&d, &long));
    }

    /// Mixed-case fields match lower- and upper-case queries alike (ASCII
    /// folding in both directions).
    #[test]
    fn search_is_ascii_case_insensitive_both_directions() {
        let d = searchable_dialog("INVITE", "MiXeD-CaSe@Host", "Alice", "BOB");
        assert!(dialog_matches_search(&d, "mixed-case"));
        assert!(dialog_matches_search(&d, "MIXED-CASE"));
        assert!(dialog_matches_search(&d, "alice"));
        assert!(dialog_matches_search(&d, "ALICE"));
        assert!(dialog_matches_search(&d, "bob"));
    }

    /// Regex metacharacters, control bytes, and RTL/NUL sequences are
    /// treated as literal substrings — never interpreted, never panicking.
    #[test]
    fn search_adversarial_inputs_never_panic() {
        let d = searchable_dialog("INVITE", "adv@host", "a", "b");
        // Backslashes, regex metacharacters, quotes: plain substring
        // semantics, no interpretation, no panic.
        for q in [
            "\\", "\\\\", ".*", "[", "(", ")", "'", "\"", "%s", "\r\n", "\t", "\u{0}", "a\u{0}b",
            "é", "☎", "\u{202e}",
        ] {
            let _ = dialog_matches_search(&d, q);
        }
        // A metacharacter that IS in the message matches literally.
        assert!(dialog_matches_search(&d, "sip:b@example.com"));
        // Backslash present in the raw body is found literally.
        let d2 = searchable_dialog("INVITE", "back\\slash@host", "a", "b");
        assert!(dialog_matches_search(&d2, "back\\slash"));
    }

    /// Raw bodies are scanned as bytes: needles surrounded by NUL and
    /// invalid UTF-8 are still found, absent ones are not.
    #[test]
    fn search_scans_raw_bytes_with_embedded_nul_and_invalid_utf8() {
        let mut d = searchable_dialog("INVITE", "nul@host", "a", "b");
        // Simulate a body carrying NUL and invalid UTF-8 around a needle.
        let mut raw = d.messages[0].raw.to_vec();
        raw.extend_from_slice(b"\x00\xff\xfeHIDDEN-NEEDLE\x00\xff");
        d.messages[0].raw = raw.into();
        assert!(dialog_matches_search(&d, "hidden-needle"));
        assert!(!dialog_matches_search(&d, "absent-needle"));
    }

    // ── displayed_dialogs: filter ∩ search interplay ────────────────────

    /// Store with 3 OPTIONS + 2 INVITE dialogs with distinct users.
    fn mixed_store() -> DialogStore {
        let mut store = DialogStore::new(100, false);
        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 7, 7, 8, 45, 0).unwrap();
        for (i, (method, from)) in [
            ("OPTIONS", "sipsak"),
            ("OPTIONS", "sipsak"),
            ("OPTIONS", "probe"),
            ("INVITE", "alice559"),
            ("INVITE", "carol"),
        ]
        .iter()
        .enumerate()
        {
            let raw = crate::test_utils::build_sip_message(
                &format!("{method} sip:dest@example.com SIP/2.0"),
                &[
                    &format!("From: <sip:{from}@example.com>;tag=t{i}"),
                    "To: <sip:dest@example.com>",
                    &format!("Call-ID: mix-{i}@test"),
                    &format!("CSeq: 1 {method}"),
                    "Content-Length: 0",
                ],
                b"",
            );
            let msg = crate::sip::parser::parse_sip(
                &raw,
                ts + chrono::TimeDelta::seconds(i as i64),
                "192.0.2.10".parse().unwrap(),
                "198.51.100.20".parse().unwrap(),
                5060,
                5060,
                crate::net::TransportProto::Udp,
            )
            .expect("parse");
            store.process_message(msg);
        }
        store
    }

    /// Filter and search narrow independently and intersect: filter-only,
    /// search-only, both, and disjoint combinations all yield the expected
    /// row counts.
    #[test]
    fn displayed_dialogs_filter_and_search_intersect() {
        let store = mixed_store();
        let all = displayed_dialogs(&store, None, "", SortColumn::Index, true);
        assert_eq!(all.len(), 5);

        // The field incident's expression matches everything here.
        let f = crate::sip::dsl::FilterExpr::parse("(method == 'OPTIONS' OR method == 'INVITE')")
            .unwrap();
        assert_eq!(
            displayed_dialogs(&store, Some(&f), "", SortColumn::Index, true).len(),
            5
        );
        // Search alone.
        assert_eq!(
            displayed_dialogs(&store, None, "sipsak", SortColumn::Index, true).len(),
            2
        );
        assert_eq!(
            displayed_dialogs(&store, None, "559", SortColumn::Index, true).len(),
            1
        );
        // Filter ∩ search: the invisible-narrowing composition from the
        // field incident.
        assert_eq!(
            displayed_dialogs(&store, Some(&f), "559", SortColumn::Index, true).len(),
            1
        );
        // A method-restricted filter composes with search on another field.
        let inv = crate::sip::dsl::FilterExpr::parse("method == 'INVITE'").unwrap();
        assert_eq!(
            displayed_dialogs(&store, Some(&inv), "carol", SortColumn::Index, true).len(),
            1
        );
        // Disjoint filter and search: empty, not an error.
        assert_eq!(
            displayed_dialogs(&store, Some(&inv), "sipsak", SortColumn::Index, true).len(),
            0
        );
    }

    /// Adversarial search queries (escapes, quotes, NUL, unbalanced
    /// parens) run through the full display pipeline without panicking.
    #[test]
    fn displayed_dialogs_search_never_errors_on_adversarial_queries() {
        let store = mixed_store();
        for q in ["\\", "'", "\u{0}", ".*", "((((", "559 ", " ", "\u{202e}"] {
            // Must not panic; result count is whatever literally matches.
            let _ = displayed_dialogs(&store, None, q, SortColumn::Index, true);
        }
    }

    /// Duration formatting switches units at 1 s and 60 s boundaries
    /// (ms → decimal seconds → minutes+seconds).
    #[test]
    fn format_duration_ms_scales_units() {
        assert_eq!(format_duration_ms(0), "0ms");
        assert_eq!(format_duration_ms(850), "850ms");
        assert_eq!(format_duration_ms(1_000), "1.0s");
        assert_eq!(format_duration_ms(12_340), "12.3s");
        assert_eq!(format_duration_ms(59_999), "60.0s");
        assert_eq!(format_duration_ms(60_000), "1m0s");
        assert_eq!(format_duration_ms(61_500), "1m1s");
        assert_eq!(format_duration_ms(3_298_856), "54m58s");
    }

    /// Default From/To mode prefers the user, falls back to host[:port]
    /// when the user is missing, and shows a dash when both are absent.
    #[test]
    fn format_from_to_shows_host_when_user_missing() {
        let r = NameResolver::new();
        // Default mode: username present wins.
        assert_eq!(
            format_from_to(
                super::super::FromToMode::Default,
                Some("1001"),
                Some("pbx.example:5060"),
                &r,
                NameMode::Off
            ),
            "1001"
        );
        // Default mode: no username → host[:port] instead of a bare dash.
        assert_eq!(
            format_from_to(
                super::super::FromToMode::Default,
                None,
                Some("pbx.example:5060"),
                &r,
                NameMode::Off
            ),
            "pbx.example:5060"
        );
        // No user and no host → dash.
        assert_eq!(
            format_from_to(
                super::super::FromToMode::Default,
                None,
                None,
                &r,
                NameMode::Off
            ),
            "-"
        );
    }

    /// UserHostPort mode joins user and a bracketed IPv6 host into one
    /// long string without panicking (truncation is left to ratatui).
    #[test]
    fn format_from_to_user_host_combines_long_value() {
        let r = NameResolver::new();
        // UserHostPort with a bracketed IPv6 host must build a single long
        // string without panicking (column truncation is ratatui's job).
        let out = format_from_to(
            super::super::FromToMode::UserHostPort,
            Some("1001"),
            Some("[2001:db8::1]:5060"),
            &r,
            NameMode::Off,
        );
        assert_eq!(out, "1001@[2001:db8::1]:5060");
    }

    /// IPv4 literals resolve to names with the port suffix preserved;
    /// Off mode, unmapped IPs, and FQDNs pass through unchanged.
    #[test]
    fn resolve_host_label_maps_ip_literals_preserving_port() {
        let r = NameResolver::new();
        r.set_manual(
            "10.0.0.7".parse::<IpAddr>().unwrap(),
            "sbc-edge".to_string(),
        );
        // IPv4 with port → name + port.
        assert_eq!(
            resolve_host_label("10.0.0.7:5060", &r, NameMode::Names),
            "sbc-edge:5060"
        );
        // IPv4 no port → bare name.
        assert_eq!(
            resolve_host_label("10.0.0.7", &r, NameMode::Names),
            "sbc-edge"
        );
        // Off mode → never resolves.
        assert_eq!(
            resolve_host_label("10.0.0.7", &r, NameMode::Off),
            "10.0.0.7"
        );
        // Unmapped IP → unchanged.
        assert_eq!(
            resolve_host_label("10.0.0.99:5060", &r, NameMode::Names),
            "10.0.0.99:5060"
        );
        // FQDN host → never touched.
        assert_eq!(
            resolve_host_label("pbx.example:5060", &r, NameMode::Names),
            "pbx.example:5060"
        );
    }

    /// Bracketed IPv6 hosts resolve to names, with and without a port.
    #[test]
    fn resolve_host_label_maps_bracketed_ipv6() {
        let r = NameResolver::new();
        r.set_manual(
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "core6".to_string(),
        );
        assert_eq!(
            resolve_host_label("[2001:db8::1]:5060", &r, NameMode::Names),
            "core6:5060"
        );
        assert_eq!(
            resolve_host_label("[2001:db8::1]", &r, NameMode::Names),
            "core6"
        );
    }

    /// Moving up from row 0 stays at row 0 (no underflow).
    #[test]
    fn call_list_state_move_up_from_zero_stays() {
        let mut state = CallListState::new();
        state.move_up();
        assert_eq!(state.selected(), 0);
    }

    /// Moving down with room advances the selection by one.
    #[test]
    fn call_list_state_move_down_increments() {
        let mut state = CallListState::new();
        state.move_down(10);
        assert_eq!(state.selected(), 1);
    }

    /// Moving down at the last row of a one-item list stays put.
    #[test]
    fn call_list_state_move_down_clamps() {
        let mut state = CallListState::new();
        state.move_down(1); // only 1 item, already at 0
        assert_eq!(state.selected(), 0);
    }

    /// `move_to_bottom` selects the last row of the list.
    #[test]
    fn call_list_state_move_to_bottom() {
        let mut state = CallListState::new();
        state.move_to_bottom(50);
        assert_eq!(state.selected(), 49);
    }

    /// Page-down advances the selection by 20 rows.
    #[test]
    fn call_list_state_page_down() {
        let mut state = CallListState::new();
        state.page_down(100);
        assert_eq!(state.selected(), 20);
    }

    /// Page-up moves the selection back by 20 rows from the bottom.
    #[test]
    fn call_list_state_page_up() {
        let mut state = CallListState::new();
        state.move_to_bottom(100);
        state.page_up();
        assert_eq!(state.selected(), 79);
    }

    /// Toggling the same Call-ID twice checks then unchecks it.
    #[test]
    fn call_list_state_toggle_selection() {
        let mut state = CallListState::new();
        assert!(state.selected_rows.is_empty());
        state.toggle_selection("call-1@test");
        assert!(state.selected_rows.contains("call-1@test"));
        assert_eq!(state.selected_rows.len(), 1);
        state.toggle_selection("call-1@test");
        assert!(state.selected_rows.is_empty());
    }

    /// Setting a new sort column starts ascending; setting the same
    /// column again flips the direction.
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

    /// State labels map to their expected short display strings.
    #[test]
    fn format_state_strings() {
        assert_eq!(state_display_str(&DialogState::Trying), "Trying");
        assert_eq!(state_display_str(&DialogState::InCall), "InCall");
        assert_eq!(state_display_str(&DialogState::Failed), "FAILED");
        assert_eq!(state_display_str(&DialogState::Completed), "Completed");
    }

    /// A fresh state reports every column label as visible.
    #[test]
    fn visible_column_names_default_is_all() {
        let state = CallListState::new();
        assert_eq!(state.visible_column_names(), COLUMN_LABELS.to_vec());
    }

    /// Hiding columns removes exactly their labels while preserving
    /// display order for the rest.
    #[test]
    fn visible_column_names_subset_in_order() {
        let mut state = CallListState::new();
        // Hide "Method" (idx 1) and "Date" (idx 8); the rest stay in order.
        state.visible_columns[1] = false;
        state.visible_columns[8] = false;
        let names = state.visible_column_names();
        assert!(!names.contains(&"Method".to_string()));
        assert!(!names.contains(&"Date".to_string()));
        assert_eq!(names.first().map(String::as_str), Some("#"));
        assert_eq!(names.last().map(String::as_str), Some("Duration"));
        assert_eq!(names.len(), 9);
    }

    /// With every column hidden the visible-name list is empty.
    #[test]
    fn visible_column_names_none_visible_is_empty() {
        let mut state = CallListState::new();
        state.visible_columns = [false; 11];
        assert!(state.visible_column_names().is_empty());
    }

    /// Getter output re-applies to an identical visibility set — the
    /// contract the save-then-reload config path relies on.
    #[test]
    fn visible_column_names_round_trips_through_apply() {
        // Names produced by the getter re-apply to the same visibility set —
        // the exact contract the save→reload path relies on.
        let mut state = CallListState::new();
        state.visible_columns[2] = false; // hide "From"
        state.visible_columns[5] = false; // hide "Destination"
        let names = state.visible_column_names();

        let mut reloaded = CallListState::new();
        reloaded.apply_visible_columns(&names);
        assert_eq!(reloaded.visible_columns, state.visible_columns);
    }

    /// The row marker fires on a signalling finding and stays off otherwise.
    ///
    /// Tested through `signaling_marker` rather than by rendering a frame: what
    /// this owes verifying is the predicate driving the glyph. The snapshot suite
    /// covers the drawing.
    #[test]
    fn signaling_marker_tracks_the_diagnosis() {
        use crate::net::TransportProto;
        use crate::sip::parser::parse_sip;
        use std::net::{IpAddr, Ipv4Addr};

        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let msg = |raw: &str| {
            parse_sip(
                raw.replace('\n', "\r\n").as_bytes(),
                ts,
                ip,
                ip,
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("fixture parses")
        };

        let invite = msg("INVITE sip:b@example.com SIP/2.0\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>\n\
             Call-ID: marker@example.com\n\
             CSeq: 1 INVITE\n\
             Content-Length: 0\n\n");
        let mut dialog = crate::sip::dialog::SipDialog::new(&invite).expect("should create");

        // A lone INVITE has nothing wrong with it.
        assert!(
            !signaling_marker(&dialog),
            "an unanswered single INVITE must not raise the marker"
        );

        dialog.messages.push(msg("SIP/2.0 503 Service Unavailable\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>;tag=2\n\
             Call-ID: marker@example.com\n\
             CSeq: 1 INVITE\n\
             Content-Length: 0\n\n"));
        assert!(
            signaling_marker(&dialog),
            "a 503 outcome must raise the marker"
        );
    }

    /// The State column must hold its longest label plus the marker, so the
    /// common case never clips. `Transferring` is the documented exception.
    #[test]
    fn state_column_fits_its_labels_plus_the_marker() {
        // " ⚠" costs 2 display columns.
        const MARKER: u16 = 2;
        for width in [80u16, 98, 119, 120, 160] {
            let widths = compute_column_widths(width);
            let Constraint::Length(state_w) = widths[6] else {
                panic!("State column should be a fixed Length, got {:?}", widths[6]);
            };
            // FAILED(6) is the state a final-failure diagnosis actually pairs
            // with, and it is the case that must never clip.
            assert!(
                state_w >= 6 + MARKER,
                "at {width} cols State is {state_w}, too narrow for FAILED plus the marker"
            );
        }
    }
}
