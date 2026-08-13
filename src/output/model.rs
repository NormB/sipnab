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
/// [`MosDelay::score`](crate::rtp::quality::MosDelay::score) (surfaces must not
/// roll their own).
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
    /// Pointer to the frame this stream's first packet arrived in, as
    /// `<source>#<ordinal>@<digest>`.
    ///
    /// The media counterpart of [`DialogSummary::frame`], and the same
    /// contract: feed it to `sipnab --show-frame` to get the bytes back, which
    /// either returns the frame or refuses because the capture changed.
    /// Omitted entirely when the stream has no frame -- live capture, HEP, or
    /// any path that did not carry one. An absent key means "not known here",
    /// and is deliberately not an empty string or a zero ordinal, both of
    /// which would read as a real pointer to frame 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
    /// Round-trip time in milliseconds, when anything reported one.
    ///
    /// The third of the three numbers that decide whether a call was
    /// acceptable — ITU-T G.114 puts the guidance for interactive speech at
    /// about 150 ms one way — and the only one sipnab cannot measure itself: a
    /// passive tap sees one point on the path and a round trip is about two.
    /// So this is always somebody else's figure, and
    /// [`Self::round_trip_source`] says whose.
    ///
    /// **Absent means not measured, and never zero.** Like [`Self::frame`],
    /// the key is omitted rather than serialised as `null` or `0`. A stream
    /// with clean jitter, no loss and no round-trip figure is not a healthy
    /// stream; it is a stream with one unanswered question, and writing 0 ms
    /// there turns the question into a pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round_trip_ms: Option<f64>,
    /// Where [`Self::round_trip_ms`] came from: `xr_voip_metrics` (the
    /// reporting endpoint's own round trip between the two RTP interfaces, the
    /// quantity G.114 is about) or `sender_report_echo` (derived from an RR's
    /// SR echo and anchored on the capture point, so the full round trip only
    /// when the tap sits with the SR sender, and a lower bound otherwise).
    ///
    /// Carried beside the number rather than folded away because an operator
    /// escalating on 200 ms needs to know whether that describes the call or a
    /// path segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round_trip_source: Option<String>,
}

impl StreamSummary {
    /// Attach a round-trip figure resolved from the store's provenance table.
    ///
    /// Separate from `From<&RtpStream>` because it has to be: the conversion
    /// sees a stream, and this number lives in the store's side-table, filed
    /// beside the stream's own measurements rather than into them. That
    /// separation is deliberate and load-bearing — see
    /// [`StreamStore::process_rtcp`](crate::rtp::stream_store::StreamStore::process_rtcp)
    /// for the bug that came of merging a remote claim into a local one.
    #[must_use]
    pub fn with_round_trip(mut self, rtt: Option<(f64, crate::rtp::rtcp::RttSource)>) -> Self {
        if let Some((ms, source)) = rtt {
            self.round_trip_ms = Some(ms);
            self.round_trip_source = Some(
                match source {
                    crate::rtp::rtcp::RttSource::XrVoipMetrics => "xr_voip_metrics",
                    crate::rtp::rtcp::RttSource::SenderReportEcho => "sender_report_echo",
                }
                .to_string(),
            );
        }
        self
    }

    /// Project a stream into its compact summary: loss percentage is
    /// derived as `lost / (received + lost)` (0.0 when no packets) and
    /// `mos` is computed via the canonical E-model estimate. Pure — the
    /// stream is not modified.
    ///
    /// This replaced a `From<&RtpStream>` impl, and the missing parameter is
    /// why. A conversion FROM a stream can see only what a stream carries, and
    /// the one-way delay the E-model needs is not on it — it is a round trip
    /// somebody else reported, filed in the store's provenance table. So the
    /// impl had no way to ask, and every surface projecting through it —
    /// REST, MCP, the TUI's JSON save — reported a MOS scored on a guessed
    /// 100 ms path. Taking the evidence as an argument makes the answer a
    /// decision each caller states rather than one the type shape forces.
    ///
    /// # Arguments
    ///
    /// * `s` — the stream to project.
    /// * `delay` — one-way-delay evidence; callers holding the store pass
    ///   [`MosDelay::of_run`](crate::rtp::quality::MosDelay::of_run) or
    ///   [`MosDelay::from_capture`](crate::rtp::quality::MosDelay::from_capture).
    #[must_use]
    pub fn of(s: &RtpStream, delay: crate::rtp::quality::MosDelay<'_>) -> Self {
        let loss_pct = s.loss_percent();
        Self {
            ssrc: format!("0x{:08x}", s.key.ssrc),
            codec: s.codec.clone(),
            src: s.key.src.to_string(),
            dst: s.key.dst.to_string(),
            packets: s.packet_count,
            jitter_ms: s.jitter,
            loss_pct,
            orphaned: s.orphaned(),
            associated_dialog: s.associated_dialog.clone(),
            mos: delay.score(s),
            // From the stream's own record of where it began. There is no
            // second source to derive it from: unlike a dialog, a stream
            // retains no packets at all.
            frame: s.first_frame.as_ref().map(ToString::to_string),
            // Not derivable from a stream alone: a round trip is somebody
            // else's measurement, filed in the store's provenance table.
            // `with_round_trip` fills these in for callers that hold the
            // store, and leaving them None here is the honest default —
            // "nobody reported one", which is exactly what a bare stream
            // knows.
            round_trip_ms: None,
            round_trip_source: None,
        }
    }
}
