// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! - `export` — Mermaid sequence-diagram export (raw source + HTML page)
//!
//! The module root also owns the shared display types (`FlowDisplayOptions`,
//! `FormattedMessage`, `Participant`, `SelectionState`), the ladder layout
//! constants, SIP transaction grouping (`transaction_key` /
//! `transaction_indices`), and the split-view width math
//! (`ladder_split_width`).

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
    /// How SDP bodies are shown below their message row (none/summary/full).
    pub sdp_mode: SdpDisplayMode,
    /// Timestamp column format (absolute, delta-prev, delta-first, scaled).
    pub ts_mode: TimestampMode,
    /// What drives arrow coloring (method class, Call-ID, or CSeq rotation).
    pub color_mode: ColorMode,
    /// Whether to insert RTP-in-flow channel bars for media segments.
    pub show_rtp: bool,
    /// Index of the selected row among visible (non-spacer) rows, if any.
    pub selected_msg: Option<usize>,
    /// Color theme used for all styling decisions.
    pub theme: &'a Theme,
    /// Resolver mapping endpoint addresses to display names.
    pub resolver: &'a crate::names::NameResolver,
    /// How endpoint labels are displayed (raw address vs resolved name).
    pub name_mode: crate::names::NameMode,
    /// Observed RTP codec segments for this dialog (authoritative "used"
    /// codec). Empty ⇒ fall back to the negotiated SDP answer codec.
    pub rtp_segments: &'a [RtpCodecSegment],
}

// Re-export everything that external code uses.
pub use arrows::truncate;
pub use prepare::{
    LayoutOptions, LayoutRow, StyleOptions, delta_style, format_message_label, format_sdp_codecs,
    layout, message_style, prepare_messages, style,
};
pub use render::{
    build_call_flow_lines, build_call_flow_lines_with_options, build_call_flow_lines_with_width,
    build_extended_flow_lines, ladder_row_of_visible, ladder_total_rows, ladder_visible_rows,
    render_call_flow, render_call_flow_direct, render_call_flow_direct_or_empty,
    render_call_flow_lines, render_ladder_scrollbar, render_message_detail,
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

/// Pipe-to-pipe gap (in columns) an arrow label of `label_len` characters
/// needs to render untruncated across `span` adjacent-column gaps:
/// `format_arrow` fits a label only when the inter-pipe width (`gap - 1`)
/// is at least `label_len + 4` (two pads, at least one dash, the arrowhead).
///
/// # Arguments
/// * `label_len` — arrow label length in characters.
/// * `span` — number of adjacent-column gaps the arrow crosses (clamped to
///   at least 1, so a degenerate `0` never divides by zero).
///
/// # Returns
/// The minimum per-gap column count, rounded up.
pub fn arrow_gap_for_label(label_len: usize, span: usize) -> usize {
    (label_len + 5).div_ceil(span.max(1))
}

/// Width to give the ladder pane when the call-flow view is split with the
/// detail pane (`raw_preview`).
///
/// The ladder spreads `n_participants` columns across its width; the gap
/// between adjacent columns must fit the arrow method/status labels or
/// `format_arrow` truncates them — the multi-leg (B2BUA) case, where legs
/// packed into the default ~60% split squeezed `INVITE (SDP) (+1 retx)`
/// into `INVITE (SD...`. `required_gap` is the widest per-gap label demand
/// actually present (see `arrow_gap_for_label`); when the configured
/// split can't provide it, widen the ladder — shrinking the detail pane
/// down to a floor, and bounding a pathological label's demand so it can't
/// eat the whole pane. The common 2-participant call is unaffected — it
/// keeps the configured split exactly.
///
/// # Arguments
/// * `n_participants` — number of ladder swimlane columns.
/// * `required_gap` — widest per-gap label demand (from `arrow_gap_for_label`).
/// * `detail_pct` — configured detail-pane share of the width, in percent.
/// * `total` — total available width in columns.
///
/// # Returns
/// The ladder pane width in columns; the detail pane gets the remainder.
pub fn ladder_split_width(
    n_participants: usize,
    required_gap: usize,
    detail_pct: u16,
    total: u16,
) -> u16 {
    let default_ladder = total.saturating_mul(100u16.saturating_sub(detail_pct)) / 100;
    if n_participants <= 2 {
        return default_ladder;
    }
    const GAP_FLOOR: u16 = 14; // always fits a ~9-char method + arrowhead
    const GAP_CAP: u16 = 28; // a longer label truncates rather than starving the detail pane
    const DETAIL_FLOOR: u16 = 24; // never shrink the detail pane below this
    let gap = (required_gap.min(u16::MAX as usize) as u16).clamp(GAP_FLOOR, GAP_CAP);
    let n = n_participants as u16;
    let needed = TS_COL_WIDTH as u16 + 2 + n.saturating_sub(1) * gap;
    let cap = total.saturating_sub(DETAIL_FLOOR).max(default_ladder);
    needed.max(default_ladder).min(cap)
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
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
    /// Whether this is a spacer row (time-proportional scaling, Scaled mode).
    pub is_spacer: bool,
    /// SDP change badge for re-INVITEs (e.g., "+G.722", "HOLD").
    pub sdp_badge: Option<String>,
    /// Whether this message is a retransmission.
    pub is_retransmission: bool,
    /// Whether this message has an RTP bar in its extra_lines (for drill-down to stream detail).
    pub is_rtp_bar: bool,
    /// Index into the raw message slice this row renders (`None` for
    /// synthetic rows: spacers and RTP bars). Keeps folding, expansion and
    /// selection independent of display-mode row insertion.
    pub raw_index: Option<usize>,
    /// Signalling-diagnosis annotation when this message is cited as evidence
    /// for a detection — the surface that makes "evidence, not verdicts" visible,
    /// by marking the exact messages a finding was drawn from rather than
    /// asserting the finding somewhere else and leaving the reader to locate them.
    pub diagnosis_note: Option<String>,
}

/// Tests for `ladder_split_width` / `arrow_gap_for_label`: the split-view
/// width math that keeps multi-leg arrow labels from truncating.
#[cfg(test)]
mod ladder_split_tests {
    use super::*;

    /// The gap between adjacent participant pipes for a ladder of width
    /// `ladder_w` with `n` participants, mirroring the renderer's math.
    fn min_gap(ladder_w: u16, n: usize) -> u16 {
        let usable = ladder_w.saturating_sub(TS_COL_WIDTH as u16 + 2);
        usable / (n as u16 - 1)
    }

    /// A 1- or 2-participant ladder keeps the configured split untouched.
    #[test]
    fn two_party_call_keeps_the_configured_split() {
        // The common case must be untouched: 60/40 at 100 cols -> 60,
        // regardless of how demanding the labels are.
        assert_eq!(ladder_split_width(2, 27, 40, 100), 60);
        assert_eq!(ladder_split_width(1, 27, 40, 100), 60);
    }

    /// 3-5 leg ladders widen so a 9-char method still fits every gap.
    #[test]
    fn multileg_widens_so_methods_do_not_truncate() {
        // SUBSCRIBE (9) needs a >= 14-col gap. At the 98-col demo width with
        // 4-5 B2BUA legs, the default 60% split gives gaps < 14 (truncation);
        // the widened ladder must restore a method-fitting gap.
        for n in 3..=5usize {
            let w = ladder_split_width(n, arrow_gap_for_label(9, 1), 40, 98);
            assert!(
                min_gap(w, n) >= 14,
                "n={n}: ladder {w} gives gap {} (< 14, SUBSCRIBE truncates)",
                min_gap(w, n)
            );
        }
    }

    /// The shipped 10-multileg demo defect: 3 B2BUA participants whose
    /// widest adjacent-column arrow label is `INVITE (SDP) (+1 retx)`
    /// (22 chars -> 27-col gap). The old fixed GAP=14 was a no-op at the
    /// 98x28 demo geometry (needed 57 <= default 58) and the label
    /// rendered as "INVITE (SD...". The split must now widen enough.
    #[test]
    fn demo_geometry_fits_the_retx_fold_label() {
        let req = arrow_gap_for_label("INVITE (SDP) (+1 retx)".len(), 1);
        assert_eq!(req, 27);
        let w = ladder_split_width(3, req, 40, 98);
        assert!(
            min_gap(w, 3) >= 27,
            "ladder {w} gives gap {} (< 27, the retx fold label truncates)",
            min_gap(w, 3)
        );
        assert!(98 - w >= 24, "detail pane starved: {} left", 98 - w);
    }

    /// An oversized label demand is capped so the detail pane keeps its floor.
    #[test]
    fn pathological_label_demand_is_bounded() {
        // OpenSIPS' 42-char reason phrase must not eat the detail pane:
        // the gap demand is capped and the label truncates instead.
        let req = arrow_gap_for_label(42, 1);
        let w = ladder_split_width(3, req, 40, 98);
        assert!(98 - w >= 24, "detail pane starved: {} left", 98 - w);
    }

    /// A label spanning several gaps needs only its share per gap; span 0
    /// and empty labels stay well-defined.
    #[test]
    fn multi_column_span_divides_the_demand() {
        // A label on an arrow spanning 3 gaps needs a third per gap.
        assert_eq!(arrow_gap_for_label(22, 3), 9);
        assert_eq!(arrow_gap_for_label(22, 1), 27);
        // Degenerate span never divides by zero.
        assert_eq!(arrow_gap_for_label(22, 0), 27);
        assert_eq!(arrow_gap_for_label(0, 1), 5);
    }

    /// When the terminal is narrower than the detail-pane floor, the widening
    /// math must not underflow or over-widen: `cap` collapses back to
    /// `default_ladder`, so the ladder stays at its configured share and the
    /// (already sub-floor) detail pane simply gets the remainder.
    #[test]
    fn sub_detail_floor_total_keeps_default_split() {
        // total (20) < DETAIL_FLOOR (24), 3 legs, demanding 27-col gap.
        // default_ladder = 20 * (100-40)/100 = 12. The widening demand
        // (needed = 13 + 2 + 2*27 = 69) is clamped by `cap`, which for a
        // sub-floor total saturates to 0 then `.max(default_ladder)` -> 12.
        // The result is exactly 12: not 0 (the underflow the `.max` guards
        // against) and not an over-wide pane.
        let w = ladder_split_width(3, 27, 40, 20);
        assert_eq!(w, 12, "sub-floor total must fall back to the default split");
    }

    /// Even a demanding 6-leg ladder leaves the detail pane its minimum width.
    #[test]
    fn detail_pane_keeps_a_floor() {
        // Even a 6-leg ladder with demanding labels must leave the detail
        // pane usable width.
        let total = 98;
        let w = ladder_split_width(6, 28, 40, total);
        assert!(total - w >= 24, "detail pane starved: {} left", total - w);
    }
}

/// Tests for `transaction_key` / `transaction_indices`: SIP transaction
/// grouping with ACK folded into its INVITE.
#[cfg(test)]
mod txn_tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    /// Parse a minimal SIP message from `start_line` and `cseq` (loopback
    /// addresses, fixed Call-ID) for transaction-grouping tests.
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

    /// A 6-message INVITE dialog: INVITE/180/200/ACK (transaction 1) then
    /// BYE/200 (transaction 2).
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

    /// Selecting any message of the INVITE transaction yields all of
    /// INVITE/1xx/2xx/ACK.
    #[test]
    fn ack_and_responses_group_with_invite() {
        let d = sample_dialog();
        // Selecting any message of the INVITE transaction yields INVITE+1xx+2xx+ACK.
        for sel in [0usize, 1, 2, 3] {
            assert_eq!(transaction_indices(&d, sel), vec![0, 1, 2, 3], "sel={sel}");
        }
    }

    /// The BYE and its 200 form their own transaction, distinct from INVITE.
    #[test]
    fn bye_transaction_is_separate() {
        let d = sample_dialog();
        assert_eq!(transaction_indices(&d, 4), vec![4, 5]);
        assert_eq!(transaction_indices(&d, 5), vec![4, 5]);
    }

    /// `transaction_key` maps ACK to its INVITE's key while BYE keeps its own.
    #[test]
    fn key_folds_ack_into_invite_but_keeps_bye_distinct() {
        let d = sample_dialog();
        assert_eq!(transaction_key(&d[0]), Some((1, "INVITE".to_string())));
        assert_eq!(transaction_key(&d[3]), Some((1, "INVITE".to_string()))); // ACK → INVITE
        assert_eq!(transaction_key(&d[4]), Some((2, "BYE".to_string())));
    }

    /// A selection with no usable CSeq (or out of range) falls back to all
    /// indices rather than an empty set.
    #[test]
    fn missing_cseq_falls_back_to_all() {
        // A selected message with no CSeq must not yield an empty set.
        let d = vec![msg("INVITE sip:b@x SIP/2.0", "7 INVITE")];
        assert_eq!(transaction_indices(&d, 0), vec![0]);
        // Out-of-range selection also falls back to all.
        assert_eq!(transaction_indices(&d, 99), vec![0]);
    }
}
