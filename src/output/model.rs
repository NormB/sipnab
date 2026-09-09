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
    /// Final INVITE response code, when the call reached one.
    ///
    /// Carried beside `state` because `state` collapses every release cause
    /// into one word: 403, 404, 408, 486, 503 and 603 are all `Failed`, and an
    /// agent asked "which cause dominates" cannot answer it from the state.
    /// Named for the wire contract that already carries it -- `DialogJson`,
    /// `tests/schemas/dialog.schema.json` and three MCP answers all say
    /// `final_status_code`, and a second name for one value is the drift this
    /// field exists to remove. The filter DSL spells it `response_code` and
    /// accepts this name too.
    /// Omitted, never null and never zero, while a call is still in progress --
    /// a zero would read as a real code to anything doing arithmetic on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_status_code: Option<u16>,
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
    /// Which capture source delivered the message that OPENED this dialog —
    /// `wire`, `hep` or `uprobe`.
    ///
    /// First, never latest, matching [`Self::frame`]: one process can capture
    /// from an interface and a HEP mirror at once, and with no BPF filter
    /// excluding the mirrored signaling ports the same message arrives from
    /// both, so a field reassigned per message would report whichever spoke
    /// last. Omitted, never null, when the opening message carried no origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_origin: Option<String>,
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
            final_status_code: d.final_status_code(),
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
            // From the same message `frame` came from, so the two cannot name
            // different packets.
            input_origin: d.input_origin.map(|o| o.as_str().to_string()),
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
    /// The E-model R-factor the MOS was converted from, on the same delay
    /// basis and with the same grounding caveat.
    ///
    /// Published because an SLA is written in R, and because R is the linear
    /// scale: eight R-points is a real difference where the MOS gap it maps to
    /// looks like rounding. Read [`Self::mos_grounded`] first — an ungrounded
    /// R is exactly as meaningless as an ungrounded MOS.
    pub r_factor: f64,
    /// Whether [`Self::mos`] rests on a real impairment value rather than the
    /// placeholder.
    ///
    /// Carried beside the number because it is not visible in it. sipnab
    /// returns the same score for a grounded G.711 stream and for a codec
    /// nobody publishes an impairment value for, where the number means
    /// "unknown" — see
    /// [`MosGrounding::Unpublished`](crate::rtp::quality::MosGrounding::Unpublished).
    /// A reader who cannot tell those apart will act on the second as if it
    /// were the first.
    ///
    /// Not `Option`: every stream has a grounding, and an absent key would
    /// read as "not known", which is a different and untrue claim.
    pub mos_grounded: bool,
    /// WHICH grounding: `published`, `operator_declared` or `unpublished`.
    ///
    /// A separate field from [`Self::mos_grounded`] because the remedies
    /// differ. A `published` score that looks wrong means suspecting sipnab's
    /// vantage point; an `operator_declared` one means suspecting a file on
    /// the operator's own disk; an `unpublished` one means the number was
    /// never an estimate. Collapsing the three into the boolean loses the
    /// middle case entirely, and that is the case where the number is right
    /// and the citation would be wrong.
    pub mos_grounding: String,
    /// The caveat that belongs beside [`Self::mos`], when there is one.
    ///
    /// Absent for a published score, where there is nothing to disclose.
    /// Writing a reassurance there instead would train readers to skip the
    /// field on the two occasions it carries a warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mos_note: Option<String>,
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
    /// the key is omitted rather than serialized as `null` or `0`. A stream
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
    /// Which capture source this stream's MEDIA arrived over — `wire`, `hep`
    /// or `uprobe`.
    ///
    /// Absent, never null, when the stream came from no captured packet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_origin: Option<String>,
    /// Which source delivered the SDP that named this stream's dialog,
    /// present **only when it differs** from [`Self::input_origin`].
    ///
    /// Its presence is the honest limit on this stream's attribution. sipnab
    /// binds a dialog to a stream by SDP media endpoint, which never consults
    /// the capture source — that is what lets one process take signaling from
    /// a HEP mirror and media off the NIC at all, and it is also what lets the
    /// two halves come from places that disagree: the SDP says what the proxy
    /// believes it did, the media says what left the box. A reader deciding
    /// whether to act on an attribution needs to know which of those they
    /// have.
    ///
    /// One predicate decides this on every surface
    /// ([`RtpStream::dialog_bound_across_sources`](crate::rtp::stream::RtpStream::dialog_bound_across_sources)),
    /// the same way `dscp_last` is gated, so a cross-source binding cannot
    /// appear on one door and be silent on another. Absent means either a
    /// same-source binding or one whose sources nobody recorded — never "they
    /// agree", which is a claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialog_origin: Option<String>,
    /// WHO asserted the SDP media endpoint that named this stream's dialog:
    /// `signaled` (a negotiating party describing its own address) or
    /// `media-relay` (an rtpengine relay describing a port it allocated).
    ///
    /// Separate from [`Self::dialog_origin`], which says which capture SOURCE
    /// delivered the assertion. A relay's address is authoritative -- it cannot
    /// be wrong about which port it opened -- but it names the leg's MIDPOINT,
    /// not either party's endpoint, so an operator tracing where media actually
    /// went needs to know which kind of claim they are reading.
    ///
    /// Emitted whenever it is known, `signaled` included. Suppressing the
    /// common case would make absence mean both "a party said so" and "nobody
    /// recorded who said so", collapsing the one distinction this field is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialog_assertion: Option<String>,
    /// The single AMR or AMR-WB mode, in kbit/s, that every readable frame of
    /// this stream was coded at.
    ///
    /// Absent unless the SDP pinned the packing AND the sender stayed in one
    /// mode for the whole stream. AMR's design is to switch mode per frame
    /// under congestion, so a stream that pins one is a fact worth stating and
    /// a stream that does not is not a missing measurement.
    ///
    /// Read this beside [`Self::amr_modes_observed`]: absent-with-two-modes
    /// and absent-with-none are opposite confidences, and only the second
    /// means sipnab could not read the payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr_mode_kbps: Option<f64>,
    /// How many DISTINCT AMR speech modes this stream's payloads carried.
    ///
    /// Absent when none were read at all — no AMR codec, no media description
    /// to settle the packing, or nothing but comfort noise. Never zero, so a
    /// present value always means sipnab read the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr_modes_observed: Option<u32>,
    /// `MOS_CQEW` for an AMR-WB stream, on the ITU-T G.107.1 WIDEBAND scale.
    ///
    /// **Not comparable with [`Self::mos`].** That is the narrowband G.107
    /// model, anchored at 93.2; this one anchors at 129. A figure from each is
    /// two different scales, and averaging them, plotting them on one axis, or
    /// meeting one threshold with both is a 35.8-point error.
    ///
    /// Present only when the stream is AMR-WB, its payload headers pinned one
    /// mode, and G.113 publishes a value for that mode in the listening
    /// context in force. When it is absent for an AMR-WB stream,
    /// [`Self::mos_wideband_unavailable`] says which of those failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mos_wideband: Option<f64>,
    /// The listening context [`Self::mos_wideband`] was read in: `monotic` (a
    /// handset or monaural headset) or `diotic` (a stereo headset or
    /// speakerphone).
    ///
    /// Carried with the number rather than assumed, because G.113 tabulates
    /// the two separately and at 6.6 kbit/s they differ by about 0.59 MOS. A
    /// capture cannot tell which the far end used; `[media]
    /// listening_context` declares it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mos_wideband_context: Option<String>,
    /// Why an AMR-WB stream has no wideband score.
    ///
    /// `unpublished_mode` -- G.113 publishes no impairment for that mode in
    /// this context; three of the nine modes have no diotic value at all.
    /// `loss_not_computable` -- the mode is published, the stream lost
    /// packets, and the robustness factor is published for three modes,
    /// diotic only. **AMR-WB under loss on a handset is not computable** from
    /// published data, and saying so is the answer rather than substituting
    /// the diotic figure.
    ///
    /// Absent when a score is present, and absent when the stream is not
    /// AMR-WB at all -- a stream nobody attempted to score wideband is not a
    /// stream that failed to score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mos_wideband_unavailable: Option<String>,
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
            self.round_trip_source = Some(source.as_wire_str().to_string());
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
        let grounding = crate::rtp::quality::mos_grounding(s.codec.as_deref());
        // Wideband is attempted only for AMR-WB with a pinned mode. A stream
        // nobody attempted to score is not a stream that failed to score, so
        // `None` here leaves all three wideband fields absent rather than
        // publishing a reason for a G.711 call.
        let wideband = matches!(
            crate::rtp::amr::amr_flavor(s.codec.as_deref()),
            Some(crate::rtp::amr::AmrFlavor::WideBand)
        )
        .then(|| s.amr_mode_kbps())
        .flatten()
        .map(|kbps| {
            crate::rtp::emodel_wb::score_amr_wb(
                kbps,
                crate::rtp::emodel_wb::declared_listening_context(),
                loss_pct,
            )
        });
        let wideband = match wideband {
            Some(r) => r.map(Some).map_err(Some),
            None => Ok(None),
        };
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
            r_factor: delay.r_factor(s),
            // Resolved once and destructured three ways, so the boolean, the
            // label and the note cannot describe three different groundings of
            // one stream. The vocabulary is the enum's, not this module's.
            mos_grounded: grounding.is_grounded(),
            mos_grounding: grounding.as_str().to_string(),
            mos_note: grounding.note().map(ToString::to_string),
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
            input_origin: s.input_origin.map(|o| o.as_str().to_string()),
            // Emitted only when the binding crossed sources, decided by the
            // one predicate that decides it everywhere.
            dialog_origin: s
                .dialog_bound_across_sources()
                .then(|| s.dialog_origin.map(|o| o.as_str().to_string()))
                .flatten(),
            // Ungated, unlike `dialog_origin`: see the field's own note. The
            // spelling is the enum's, so REST, MCP and the call report cannot
            // name a relay assertion three ways.
            dialog_assertion: s.dialog_assertion.map(|a| a.as_str().to_string()),
            amr_mode_kbps: s.amr_mode_kbps(),
            // `None` rather than `Some(0)`: a present count always means the
            // payloads were read, so a reader never has to decide whether a
            // zero is "no modes" or "not an AMR stream".
            amr_modes_observed: (s.amr_modes_observed() > 0).then(|| s.amr_modes_observed()),
            mos_wideband: wideband.as_ref().ok().and_then(|w| w.map(|w| w.mos)),
            mos_wideband_context: wideband
                .as_ref()
                .ok()
                .and_then(|w| w.map(|w| w.context.as_str().to_string())),
            mos_wideband_unavailable: wideband.as_ref().err().and_then(Option::as_ref).map(|e| {
                match e {
                    crate::rtp::emodel_wb::WidebandUnavailable::UnpublishedMode => {
                        "unpublished_mode"
                    }
                    crate::rtp::emodel_wb::WidebandUnavailable::LossNotComputable => {
                        "loss_not_computable"
                    }
                }
                .to_string()
            }),
        }
    }
}

#[cfg(test)]
/// The wideband fields on `StreamSummary`.
///
/// Every test here is serialized on `listening_context`, and one of them
/// writes it. That declaration is process-wide for the same reason the codec
/// impairment table is -- no surface is threaded a config -- so two of these
/// running concurrently read each other's context and the score changes
/// underneath the assertion. The first draft of this module did exactly that
/// and passed serially while failing in parallel, hours after the same shape
/// was fixed in the Prometheus doors.
mod wideband_tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// An AMR-WB stream whose payloads pinned exactly `ft`, with `lost`
    /// packets against `received`.
    fn amr_wb_stream(ft: u8, received: u64, lost: u64) -> RtpStream {
        let key = StreamKey {
            ssrc: 0x1234,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 96,
            sequence: 1,
            timestamp: 0,
            ssrc: 0x1234,
            payload_offset: 12,
        };
        let mut s = RtpStream::new(key, &hdr, chrono::Utc::now());
        s.codec = Some("AMR-WB".to_string());
        s.amr_frame_types_seen = 1u16 << ft;
        s.packet_count = received;
        s.lost_packets = lost;
        s
    }

    /// A published mode with no loss gets a wideband score, and the score says
    /// which listening context it was read in.
    #[test]
    #[serial_test::serial(listening_context)]
    fn a_published_mode_reaches_the_surface_with_its_context() {
        // Frame type 2 is 12.65 kbit/s, published in both contexts.
        let s = amr_wb_stream(2, 100, 0);
        let out = StreamSummary::of(&s, crate::rtp::quality::MosDelay::unknown());
        let mos = out.mos_wideband.expect("12.65 is published");
        assert!((3.0..=4.5).contains(&mos), "MOS_CQEW out of range: {mos}");
        assert_eq!(out.mos_wideband_context.as_deref(), Some("monotic"));
        assert_eq!(out.mos_wideband_unavailable, None);
        // And it is NOT the narrowband number, which is the whole point of
        // publishing it in its own field.
        assert!(
            (out.mos - mos).abs() > f64::EPSILON,
            "the two scales must not coincide by accident: {} and {mos}",
            out.mos
        );
    }

    /// A mode G.113 does not publish in the context in force says so by name.
    #[test]
    #[serial_test::serial(listening_context)]
    fn an_unpublished_mode_names_itself_rather_than_going_quiet() {
        crate::rtp::emodel_wb::set_listening_context(
            crate::rtp::emodel_wb::ListeningContext::Diotic,
        );
        // Frame type 6 is 19.85 kbit/s: monotic only.
        let s = amr_wb_stream(6, 100, 0);
        let out = StreamSummary::of(&s, crate::rtp::quality::MosDelay::unknown());
        assert_eq!(out.mos_wideband, None);
        assert_eq!(
            out.mos_wideband_unavailable.as_deref(),
            Some("unpublished_mode")
        );
        crate::rtp::emodel_wb::set_listening_context(
            crate::rtp::emodel_wb::ListeningContext::Monotic,
        );
    }

    /// Loss on a mode with no published robustness factor is reported as not
    /// computable, which is a different answer from an unpublished mode.
    #[test]
    #[serial_test::serial(listening_context)]
    fn loss_without_a_robustness_factor_is_reported_as_not_computable() {
        // Frame type 0 is 6.6 kbit/s: an Ie,WB in both contexts, a Bpl,wb in
        // neither, so it scores clean and refuses under loss.
        let clean = StreamSummary::of(
            &amr_wb_stream(0, 100, 0),
            crate::rtp::quality::MosDelay::unknown(),
        );
        assert!(clean.mos_wideband.is_some(), "6.6 scores with no loss");

        let lossy = StreamSummary::of(
            &amr_wb_stream(0, 100, 5),
            crate::rtp::quality::MosDelay::unknown(),
        );
        assert_eq!(lossy.mos_wideband, None);
        assert_eq!(
            lossy.mos_wideband_unavailable.as_deref(),
            Some("loss_not_computable"),
            "and NOT unpublished_mode -- the tables are not silent here, this \
             stream is the thing that cannot be scored"
        );
    }

    /// A stream nobody attempted to score wideband carries no wideband fields
    /// at all, including no reason.
    ///
    /// The negative. Without it every G.711 call on the wire would grow a
    /// field explaining why it has no AMR-WB score.
    #[test]
    #[serial_test::serial(listening_context)]
    fn a_narrowband_stream_carries_no_wideband_fields() {
        let mut s = amr_wb_stream(2, 100, 0);
        s.codec = Some("PCMU".to_string());
        let out = StreamSummary::of(&s, crate::rtp::quality::MosDelay::unknown());
        assert_eq!(out.mos_wideband, None);
        assert_eq!(out.mos_wideband_context, None);
        assert_eq!(out.mos_wideband_unavailable, None);
    }
}
