// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical output projections shared by every serialization surface.
//!
//! Before this module existed, "dialog summary" was implemented five times
//! (CLI/NDJSON, REST API, MCP, TUI save, reports) and had already drifted
//! on the wire: MCP said `message_count` where CLI/API said `msg_count`,
//! and MCP emitted Debug-formatted methods (`Invite`) where the API emitted
//! the canonical form (`INVITE`). Every surface now projects dialogs through
//! `DialogSummary` and streams through `StreamSummary` — one constructor
//! each — so field names and value formats cannot diverge again
//! (`tests/summary_consistency_test.rs` pins this).
//!
//! These are the *compact* projections. The full-fidelity forms (all
//! headers, SDP timelines, quality intervals) remain in `super::json`.

use serde::Serialize;

use crate::rtp::stream::RtpStream;
use crate::sip::dialog::SipDialog;

/// Transaction-timing subset shared by the summary surfaces.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct TimingSummary {
    /// Post-dial delay (INVITE → first 180/183; a 100 Trying does not
    /// count), milliseconds.
    pub pdd_ms: Option<i64>,
    /// Call setup time (INVITE → 200 OK), milliseconds.
    pub setup_ms: Option<i64>,
    /// Total retransmissions observed in the dialog.
    pub retransmits: u32,
    /// Answered-to-BYE call duration, milliseconds (answered calls only).
    pub duration_ms: Option<i64>,
}

/// Canonical compact projection of a `SipDialog`.
///
/// Field names intentionally match `super::json`'s full `DialogJson`
/// (`msg_count`, not `message_count`); `method` and `state` use their
/// canonical string forms (`SipMethod::as_str`, `DialogState`'s `Display`).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct DialogSummary {
    /// Call-ID identifying the dialog.
    pub call_id: String,
    /// Current dialog state (e.g. "InCall", "Completed").
    pub state: String,
    /// SIP method that initiated the dialog, canonical form (e.g. "INVITE").
    pub method: String,
    /// User portion of the From URI, if present.
    pub from_user: Option<String>,
    /// User portion of the To URI, if present.
    pub to_user: Option<String>,
    /// Number of SIP messages in the dialog.
    pub msg_count: usize,
    /// Wall-clock span from first to last message, seconds (0 for
    /// single-message dialogs).
    pub duration_sec: f64,
    /// RFC 3339 timestamp of the first message.
    pub created_at: String,
    /// RFC 3339 timestamp of the most recent message.
    pub updated_at: String,
    /// Transaction timing metrics.
    pub timing: TimingSummary,
    /// Pointer to the frame this dialog opened in, as `<source>#<ordinal>`.
    ///
    /// Feed it to `sipnab --show-frame` to get the bytes back, which either
    /// returns the frame or refuses because the capture changed. Omitted
    /// entirely when the dialog has no frame -- live capture, or any path
    /// that did not carry one. An absent key means "not known here", and is
    /// deliberately not an empty string or a zero ordinal, both of which
    /// would read as a real pointer to frame 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
}

impl From<&SipDialog> for DialogSummary {
    /// Project a dialog into its compact summary: durations are derived
    /// (`duration_sec` spans first→last message, 0 for single-message
    /// dialogs; `duration_ms` is answered→BYE and `None` for unanswered
    /// or still-active calls) and timing metrics are copied from
    /// `d.timing`. Pure — the dialog is not modified.
    fn from(d: &SipDialog) -> Self {
        let duration_sec = if d.messages.len() >= 2 {
            (d.updated_at - d.created_at).num_milliseconds() as f64 / 1000.0
        } else {
            0.0
        };
        let duration_ms = d.timing.bye_sent.and_then(|bye| {
            d.timing
                .answered_at
                .map(|ans| (bye - ans).num_milliseconds())
        });
        Self {
            call_id: d.call_id.clone(),
            state: d.state().to_string(),
            method: d.method.as_str().to_string(),
            from_user: d.from_user.clone(),
            to_user: d.to_user.clone(),
            msg_count: d.messages.len(),
            duration_sec,
            created_at: d.created_at.to_rfc3339(),
            updated_at: d.updated_at.to_rfc3339(),
            timing: TimingSummary {
                pdd_ms: d.timing.pdd_ms(),
                setup_ms: d.timing.setup_ms(),
                retransmits: d.timing.total_retransmits(),
                duration_ms,
            },
            // From the dialog's own record of where it opened, not from
            // `d.messages.first()`, which compaction can replace with a
            // later message.
            frame: d.first_frame.as_ref().map(ToString::to_string),
        }
    }
}

/// Canonical compact projection of an `RtpStream`.
///
/// `ssrc` uses the `0x`-prefixed 8-digit hex form every surface renders;
/// `mos` is the single E-model estimate from
/// `crate::rtp::quality::estimate_mos` (surfaces must not roll their own).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct StreamSummary {
    /// Synchronization source, `0x`-prefixed hex.
    pub ssrc: String,
    /// Codec name from SDP or heuristics, if known.
    pub codec: Option<String>,
    /// Source `ip:port`.
    pub src: String,
    /// Destination `ip:port`.
    pub dst: String,
    /// RTP packets received.
    pub packets: u64,
    /// Interarrival jitter, milliseconds.
    pub jitter_ms: f64,
    /// Packet loss percentage (0–100).
    pub loss_pct: f64,
    /// True when no SIP dialog explains this stream.
    pub orphaned: bool,
    /// Call-ID of the owning dialog, when linked.
    pub associated_dialog: Option<String>,
    /// E-model MOS estimate (1.0–4.5).
    pub mos: f64,
}

impl From<&RtpStream> for StreamSummary {
    /// Project a stream into its compact summary: loss percentage is
    /// derived as `lost / (received + lost)` (0.0 when no packets) and
    /// `mos` is computed via the canonical E-model estimate. Pure — the
    /// stream is not modified.
    fn from(s: &RtpStream) -> Self {
        let total = s.packet_count + s.lost_packets;
        let loss_pct = if total > 0 {
            (s.lost_packets as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        Self {
            ssrc: format!("0x{:08x}", s.key.ssrc),
            codec: s.codec.clone(),
            src: s.key.src.to_string(),
            dst: s.key.dst.to_string(),
            packets: s.packet_count,
            jitter_ms: s.jitter,
            loss_pct,
            orphaned: s.orphaned,
            associated_dialog: s.associated_dialog.clone(),
            mos: crate::rtp::quality::estimate_mos(s.jitter, loss_pct, s.codec.as_deref()),
        }
    }
}
