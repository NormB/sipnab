//! RTP stream list view — color-coded stream table.
//!
//! Displays all tracked RTP streams with columns for SSRC, codec, source,
//! destination, packets, jitter, loss, duration, associated dialog, and
//! health status. Rows are color-coded by quality thresholds.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::rtp::stream::RtpStream;
use crate::rtp::stream_store::StreamStore;

// ── Quality thresholds ──────────────────────────────────────────────

/// Jitter threshold for "warning" status (milliseconds).
const JITTER_WARN_MS: f64 = 30.0;
/// Jitter threshold for "bad" status (milliseconds).
const JITTER_BAD_MS: f64 = 50.0;
/// Packet loss threshold for "warning" status (percentage).
const LOSS_WARN_PCT: f64 = 1.0;
/// Packet loss threshold for "bad" status (percentage).
const LOSS_BAD_PCT: f64 = 5.0;

// ── Stream health ───────────────────────────────────────────────────

/// Quality classification for an RTP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHealth {
    /// Jitter < 30ms, loss < 1%.
    Good,
    /// Jitter < 50ms, loss < 5%.
    Warning,
    /// Above warning thresholds.
    Bad,
    /// No associated dialog after orphan timeout.
    Orphaned,
}

/// Classify stream health based on jitter and loss metrics.
pub fn classify_stream(stream: &RtpStream) -> StreamHealth {
    if stream.orphaned {
        return StreamHealth::Orphaned;
    }
    let loss_pct = if stream.packet_count > 0 {
        (stream.lost_packets as f64 / (stream.packet_count + stream.lost_packets) as f64) * 100.0
    } else {
        0.0
    };

    if stream.jitter >= JITTER_BAD_MS || loss_pct >= LOSS_BAD_PCT {
        StreamHealth::Bad
    } else if stream.jitter >= JITTER_WARN_MS || loss_pct >= LOSS_WARN_PCT {
        StreamHealth::Warning
    } else {
        StreamHealth::Good
    }
}

// ── Stream list state ───────────────────────────────────────────────

/// Persistent state for the stream list view.
pub struct StreamListState {
    /// ratatui table widget state.
    table_state: TableState,
}

impl StreamListState {
    /// Create a new stream list state.
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self { table_state }
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
}

impl Default for StreamListState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Render the RTP stream list table into the given area.
pub fn render_stream_list(
    frame: &mut Frame,
    area: Rect,
    state: &mut StreamListState,
    store: &StreamStore,
) {
    let header = Row::new(vec![
        Cell::from("SSRC"),
        Cell::from("Codec"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("Pkts"),
        Cell::from("Jitter"),
        Cell::from("Loss"),
        Cell::from("Duration"),
        Cell::from("Dialog"),
        Cell::from("Status"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(0);

    let streams: Vec<_> = store.iter().collect();

    let rows: Vec<Row> = streams
        .iter()
        .map(|stream| {
            let health = classify_stream(stream);
            let loss_pct = if stream.packet_count > 0 {
                (stream.lost_packets as f64 / (stream.packet_count + stream.lost_packets) as f64)
                    * 100.0
            } else {
                0.0
            };

            let duration = {
                let diff = stream.last_seen.signed_duration_since(stream.first_seen);
                let secs = diff.num_seconds();
                if secs < 60 {
                    format!("{}s", secs)
                } else {
                    format!("{}m{}s", secs / 60, secs % 60)
                }
            };

            let dialog_id = stream
                .associated_dialog
                .as_deref()
                .unwrap_or("-")
                .chars()
                .take(16)
                .collect::<String>();

            let status_label = match health {
                StreamHealth::Good => "OK",
                StreamHealth::Warning => "WARN",
                StreamHealth::Bad => "BAD",
                StreamHealth::Orphaned => "ORPHAN",
            };

            let row = Row::new(vec![
                Cell::from(Span::raw(format!("{:08X}", stream.key.ssrc))),
                Cell::from(Span::raw(stream.codec.as_deref().unwrap_or("?"))),
                Cell::from(Span::raw(stream.key.src.to_string())),
                Cell::from(Span::raw(stream.key.dst.to_string())),
                Cell::from(Span::raw(stream.packet_count.to_string())),
                Cell::from(Span::raw(format!("{:.1}ms", stream.jitter))),
                Cell::from(Span::raw(format!("{:.1}%", loss_pct))),
                Cell::from(Span::raw(duration)),
                Cell::from(Span::raw(dialog_id)),
                Cell::from(Span::styled(status_label, health_style(health))),
            ]);

            row.style(health_row_style(health))
        })
        .collect();

    let widths = [
        Constraint::Length(10), // SSRC
        Constraint::Length(8),  // Codec
        Constraint::Length(22), // Source
        Constraint::Length(22), // Destination
        Constraint::Length(8),  // Pkts
        Constraint::Length(9),  // Jitter
        Constraint::Length(7),  // Loss
        Constraint::Length(9),  // Duration
        Constraint::Length(18), // Dialog
        Constraint::Length(7),  // Status
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" RTP Streams (Tab: Calls | Esc: Back) "),
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

/// Return a style for the health status label.
fn health_style(health: StreamHealth) -> Style {
    match health {
        StreamHealth::Good => Style::default().fg(Color::Green),
        StreamHealth::Warning => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        StreamHealth::Bad => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        StreamHealth::Orphaned => Style::default().fg(Color::DarkGray),
    }
}

/// Return a row style for the given stream health.
fn health_row_style(health: StreamHealth) -> Style {
    match health {
        StreamHealth::Good => Style::default().fg(Color::Green),
        StreamHealth::Warning => Style::default().fg(Color::Yellow),
        StreamHealth::Bad => Style::default().fg(Color::Red),
        StreamHealth::Orphaned => Style::default().fg(Color::DarkGray),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_list_state_navigation() {
        let mut state = StreamListState::new();
        assert_eq!(state.selected(), 0);

        state.move_down(10);
        assert_eq!(state.selected(), 1);

        state.move_up();
        assert_eq!(state.selected(), 0);

        state.move_to_bottom(10);
        assert_eq!(state.selected(), 9);

        state.move_to_top();
        assert_eq!(state.selected(), 0);
    }

    #[test]
    fn stream_list_state_empty() {
        let mut state = StreamListState::new();
        state.move_down(0); // no items
        assert_eq!(state.selected(), 0);
    }

    #[test]
    fn classify_stream_good() {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let key = StreamKey {
            ssrc: 0x1234,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc: 0x1234,
            payload_offset: 12,
        };
        let stream = RtpStream::new(key, &hdr, chrono::Utc::now());
        assert_eq!(classify_stream(&stream), StreamHealth::Good);
    }
}
