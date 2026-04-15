//! Call flow ladder diagram view.
//!
//! Renders a classic SIP ladder diagram for a single dialog, showing
//! message arrows between endpoints with timestamps, method/status
//! annotations, and PDD indicators.
//!
//! This module is split into sub-modules:
//! - `prepare` — data preparation (formatting, timestamp modes, SDP)
//! - `render` — buffer painting and Paragraph-based rendering
//! - `arrows` — arrow formatting between column positions

pub mod arrows;
pub mod export;
pub mod prepare;
pub mod render;

use chrono::{DateTime, Utc};
use ratatui::style::Style;

// Re-export everything that external code uses.
pub use arrows::truncate;
pub use prepare::{prepare_messages, delta_style, format_message_label, format_sdp_codecs, message_style};
pub use render::{
    build_call_flow_lines, build_call_flow_lines_with_options, build_call_flow_lines_with_width,
    build_extended_flow_lines, render_call_flow, render_call_flow_direct,
    render_call_flow_direct_or_empty, render_call_flow_lines, render_message_detail,
};

// ── Layout constants ────────────────────────────────────────────────

/// Minimum width for the arrow shaft (dashes) between endpoints.
pub const MIN_ARROW_WIDTH: usize = 24;
/// Width reserved for the timestamp column (`HH:MM:SS.mmm` or `+60.000s ` + padding).
pub const TS_COL_WIDTH: usize = 13;
/// Width reserved for each endpoint column (pipe + padding).
pub const ENDPOINT_COL_WIDTH: usize = 20;

// ── Public types ────────────────────────────────────────────────────

/// Visual selection state for a message in the call flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionState {
    /// This message is the currently selected one.
    Selected,
    /// This message shares a Call-ID with the selected message.
    Related,
    /// This message is unrelated to the selection.
    Normal,
}

/// A participant (endpoint) in the call flow diagram.
#[derive(Debug, Clone)]
pub struct Participant {
    /// Network address "IP:port".
    pub addr: String,
    /// Display label (truncated for rendering).
    pub label: String,
}

/// Pre-formatted message data for the direct-paint renderer.
///
/// Separates data preparation (display modes, color, timestamps) from
/// the actual buffer painting, keeping the render function simple.
pub struct FormattedMessage {
    /// Formatted timestamp string (or empty if hidden).
    pub timestamp: String,
    /// Style for the timestamp (delta modes use color-coded styles).
    pub timestamp_style: Style,
    /// Arrow label (e.g., "INVITE (SDP)" or "200 OK").
    pub label: String,
    /// Style for the arrow line.
    pub style: Style,
    /// Index into participants array for the source endpoint.
    pub src_col: usize,
    /// Index into participants array for the destination endpoint.
    pub dst_col: usize,
    /// Optional PDD annotation (e.g., "  PDD: 1234ms").
    pub pdd_note: Option<String>,
    /// Optional extra lines below the arrow (SDP info, RTP markers, etc.).
    pub extra_lines: Vec<(String, Style)>,
    /// Whether this message is selected (for highlighting).
    pub selected: bool,
    /// Call-ID of the source message (for related-row highlighting).
    pub call_id: String,
    /// Visual selection state.
    pub selection_state: SelectionState,
    /// Whether this is a response (for dashed arrow rendering).
    pub is_response: bool,
    /// Raw timestamp for mark/delta computation (Feature 1: Mark + Delta).
    pub raw_timestamp: DateTime<Utc>,
    /// Number of folded messages (0 = not a fold header).
    pub folded_count: usize,
    /// Annotation for folded messages (e.g., "3 msgs folded - press e to expand").
    pub fold_label: Option<String>,
    /// Whether this is a spacer row (for time-proportional scaling, Phase C).
    pub is_spacer: bool,
    /// SDP change badge for re-INVITEs (e.g., "+G.722", "HOLD").
    pub sdp_badge: Option<String>,
    /// Whether this message is a retransmission.
    pub is_retransmission: bool,
    /// Whether this message has an RTP bar in its extra_lines (for drill-down to stream detail).
    pub is_rtp_bar: bool,
}
