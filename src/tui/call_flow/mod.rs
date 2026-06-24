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

use super::{ColorMode, SdpDisplayMode, Theme, TimestampMode};

// ── Bundled display options ────────────────────────────────────────

/// One observed RTP media segment for a dialog: the codec actually carried on
/// the wire (resolved from the RTP payload type) and the time window it was
/// seen. The RTP-in-flow bar uses these to label the *used* codec rather than
/// the full SDP offer list — and a re-INVITE that switches codecs shows up as a
/// later segment with a different codec. Empty when no RTP was captured
/// (SIP-only), in which case the bar falls back to the negotiated SDP answer.
#[derive(Debug, Clone)]
pub struct RtpCodecSegment {
    /// Resolved codec name, e.g. `PCMU`, `G722`.
    pub codec: String,
    /// First time a packet of this stream was seen.
    pub start: chrono::DateTime<chrono::Utc>,
    /// Last time a packet of this stream was seen.
    pub end: chrono::DateTime<chrono::Utc>,
}

/// Display options for call flow rendering.
///
/// Bundles the display mode parameters that are threaded through
/// `prepare_messages`, `format_ladder_with_options`, and the various
/// `build_*` / `render_*` call flow functions.
#[derive(Debug, Clone)]
pub struct FlowDisplayOptions<'a> {
    pub sdp_mode: SdpDisplayMode,
    pub ts_mode: TimestampMode,
    pub color_mode: ColorMode,
    pub show_rtp: bool,
    pub selected_msg: Option<usize>,
    pub theme: &'a Theme,
    pub resolver: &'a crate::names::NameResolver,
    pub name_mode: crate::names::NameMode,
    /// Observed RTP codec segments for this dialog (authoritative "used"
    /// codec). Empty ⇒ fall back to the negotiated SDP answer codec.
    pub rtp_segments: &'a [RtpCodecSegment],
}

// Re-export everything that external code uses.
pub use arrows::truncate;
pub use prepare::{
    delta_style, format_message_label, format_sdp_codecs, message_style, prepare_messages,
};
pub use render::{
    build_call_flow_lines, build_call_flow_lines_with_options, build_call_flow_lines_with_width,
    build_extended_flow_lines, ladder_total_rows, ladder_visible_rows, render_call_flow,
    render_call_flow_direct, render_call_flow_direct_or_empty, render_call_flow_lines,
    render_ladder_scrollbar, render_message_detail,
};

// ── Transaction grouping ────────────────────────────────────────────

use crate::sip::SipMessage;

/// SIP transaction grouping key: the CSeq sequence number plus method, with
/// `ACK` folded into the `INVITE` transaction it completes — so a call's
/// INVITE / 1xx / 2xx / ACK read as one unit, while a separate BYE (different
/// CSeq number) is its own transaction. Returns `None` for a message with no
/// parseable CSeq.
pub fn transaction_key(msg: &SipMessage) -> Option<(u32, String)> {
    let (num, method) = msg.cseq()?;
    let method = method.trim().to_ascii_uppercase();
    let method = if method == "ACK" {
        "INVITE".to_string()
    } else {
        method
    };
    Some((num, method))
}

/// Indices of every message belonging to the same transaction as
/// `messages[selected]`. Falls back to *all* indices when the selected message
/// has no CSeq, so callers always receive a non-empty, sensible set.
pub fn transaction_indices(messages: &[SipMessage], selected: usize) -> Vec<usize> {
    match messages.get(selected).and_then(transaction_key) {
        Some(key) => messages
            .iter()
            .enumerate()
            .filter(|(_, m)| transaction_key(m).as_ref() == Some(&key))
            .map(|(i, _)| i)
            .collect(),
        None => (0..messages.len()).collect(),
    }
}

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

#[cfg(test)]
mod txn_tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn msg(start_line: &str, cseq: &str) -> SipMessage {
        let raw = format!(
            "{start_line}\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKx\r\n\
             From: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c@x\r\n\
             CSeq: {cseq}\r\nContent-Length: 0\r\n\r\n"
        );
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        crate::sip::parser::parse_sip(
            raw.as_bytes(),
            Utc::now(),
            ip,
            ip,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse")
    }

    fn sample_dialog() -> Vec<SipMessage> {
        vec![
            msg("INVITE sip:b@x SIP/2.0", "1 INVITE"), // 0
            msg("SIP/2.0 180 Ringing", "1 INVITE"),    // 1
            msg("SIP/2.0 200 OK", "1 INVITE"),         // 2
            msg("ACK sip:b@x SIP/2.0", "1 ACK"),       // 3
            msg("BYE sip:b@x SIP/2.0", "2 BYE"),       // 4
            msg("SIP/2.0 200 OK", "2 BYE"),            // 5
        ]
    }

    #[test]
    fn ack_and_responses_group_with_invite() {
        let d = sample_dialog();
        // Selecting any message of the INVITE transaction yields INVITE+1xx+2xx+ACK.
        for sel in [0usize, 1, 2, 3] {
            assert_eq!(transaction_indices(&d, sel), vec![0, 1, 2, 3], "sel={sel}");
        }
    }

    #[test]
    fn bye_transaction_is_separate() {
        let d = sample_dialog();
        assert_eq!(transaction_indices(&d, 4), vec![4, 5]);
        assert_eq!(transaction_indices(&d, 5), vec![4, 5]);
    }

    #[test]
    fn key_folds_ack_into_invite_but_keeps_bye_distinct() {
        let d = sample_dialog();
        assert_eq!(transaction_key(&d[0]), Some((1, "INVITE".to_string())));
        assert_eq!(transaction_key(&d[3]), Some((1, "INVITE".to_string()))); // ACK → INVITE
        assert_eq!(transaction_key(&d[4]), Some((2, "BYE".to_string())));
    }

    #[test]
    fn missing_cseq_falls_back_to_all() {
        // A selected message with no CSeq must not yield an empty set.
        let d = vec![msg("INVITE sip:b@x SIP/2.0", "7 INVITE")];
        assert_eq!(transaction_indices(&d, 0), vec![0]);
        // Out-of-range selection also falls back to all.
        assert_eq!(transaction_indices(&d, 99), vec![0]);
    }
}
