// SPDX-License-Identifier: MIT OR Apache-2.0

//! Media path diagnosis for RTP streams.
//!
//! Analyzes RTP streams associated with a SIP dialog to detect common
//! VoIP issues: one-way audio, NAT traversal problems, missing media,
//! and (Phase 8.7) per-call asymmetry signals — codec/ptime/payload-type
//! mismatches across the two legs, duration asymmetry, and late media.
//! Generates human-readable hints for each detected condition.

use std::net::IpAddr;

use super::stream::RtpStream;
use crate::sip::dialog::SipDialog;
use crate::sip::sdp::{SdpDirection, SdpSession, effective_address};

/// Codec asymmetry — A leg uses one codec, B leg uses another.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CodecAsymmetry {
    /// Codec on the A (caller) leg.
    pub a_codec: String,
    /// Codec on the B (callee) leg.
    pub b_codec: String,
}

/// Packetization-time asymmetry — A leg sends 20 ms frames, B leg 30 ms (etc.).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PtimeAsymmetry {
    /// Packetization time on the A leg, in milliseconds.
    pub a_ptime_ms: u32,
    /// Packetization time on the B leg, in milliseconds.
    pub b_ptime_ms: u32,
}

/// Payload-type asymmetry — same negotiated codec, different RTP PTs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PayloadTypeAsymmetry {
    /// RTP payload type seen on the A leg.
    pub a_pt: u8,
    /// RTP payload type seen on the B leg.
    pub b_pt: u8,
}

/// Duration asymmetry — one leg's stream lasted noticeably longer than the other.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DurationAsymmetry {
    /// A-leg stream duration in seconds.
    pub a_duration_sec: f64,
    /// B-leg stream duration in seconds.
    pub b_duration_sec: f64,
    /// Absolute duration difference in seconds.
    pub delta_sec: f64,
}

/// Late media — RTP for a leg started significantly after the 200 OK.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LateMedia {
    /// "a" or "b" identifying which leg was late.
    pub leg: String,
    /// How long after the 200 OK the first RTP arrived, in ms.
    pub delay_after_200_ok_ms: i64,
}

/// Result of diagnosing media conditions for a dialog's RTP streams.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MediaDiagnosis {
    /// True if audio flows in only one direction.
    pub one_way_audio: bool,
    /// True if the SDP-negotiated address differs from the observed RTP source.
    pub nat_mismatch: bool,
    /// True if SDP was negotiated but no RTP packets were observed.
    pub no_media: bool,
    /// SDP-negotiated media address string (from `c=` line).
    pub sdp_media: Option<String>,
    /// Observed RTP source address string.
    pub actual_media: Option<String>,
    /// Human-readable diagnostic hints.
    pub hints: Vec<String>,

    // ── Phase 8.7: per-call asymmetry signals ──
    /// Codec mismatch across the two legs of the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec_asymmetry: Option<CodecAsymmetry>,
    /// Packetization-time mismatch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptime_asymmetry: Option<PtimeAsymmetry>,
    /// Payload-type mismatch (same codec negotiated, different PTs observed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_type_asymmetry: Option<PayloadTypeAsymmetry>,
    /// Duration mismatch between the two legs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_asymmetry: Option<DurationAsymmetry>,
    /// Media that started long after the 200 OK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub late_media: Option<LateMedia>,
}

/// Threshold knobs for the asymmetry detectors. Values are chosen to match
/// industry-standard triage signals without being so tight they false-positive
/// on healthy calls.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AsymmetryThresholds {
    /// Minimum percentage delta between leg durations to flag (default 5%).
    pub duration_pct_delta: f64,
    /// Minimum absolute delta between leg durations to flag (default 2.0 s).
    pub duration_min_delta_sec: f64,
    /// Late-media trigger threshold in milliseconds after 200 OK (default 500).
    pub late_media_threshold_ms: i64,
    /// Share of a call's packets that must be comfort noise before comfort
    /// noise is accepted as the explanation for a one-directional media flow
    /// (default 0.3).
    ///
    /// The only figure in this struct that WITHHOLDS a finding instead of
    /// raising one, and it therefore fails quietly. A VoLTE or mobile trunk
    /// runs aggressive voice-activity detection and routinely sends comfort
    /// noise on more than 30 % of packets, at which point one-way audio — the
    /// most-reported VoIP fault there is — becomes undetectable on that trunk
    /// and nothing in the output says why.
    pub cn_suppression_ratio: f64,
}

impl AsymmetryThresholds {
    /// The built-in thresholds: 5% / 2.0 s duration delta, 500 ms late media,
    /// 30 % comfort noise.
    ///
    /// These are what sipnab compares against when the operator has declared
    /// nothing. Kept as a named constant so [`Default::default`] can answer
    /// with the DECLARED values while this stays reachable as the shipped
    /// figure — a test asserting the default moved needs both.
    pub const BUILT_IN: Self = Self {
        duration_pct_delta: 5.0,
        duration_min_delta_sec: 2.0,
        late_media_threshold_ms: 500,
        cn_suppression_ratio: 0.3,
    };
}

/// The thresholds `[diagnosis]` declared, once the run has read its config.
///
/// Process-global and written once at startup, the same shape as
/// [`crate::provenance::set_node_name`] and
/// [`crate::sip::dialog_store::set_idle_compact_after_secs`], and for the same
/// reason: the value is a property of the run, and the alternative is
/// threading it through every caller.
static CONFIGURED: std::sync::OnceLock<AsymmetryThresholds> = std::sync::OnceLock::new();

/// Declare the asymmetry thresholds for this process. Call once, at startup.
///
/// # Side effects
///
/// Writes a process-global `OnceLock`; the first writer wins, so a later call
/// is ignored rather than moving the thresholds mid-run.
pub fn set_asymmetry_thresholds(thresholds: AsymmetryThresholds) {
    let _ = CONFIGURED.set(thresholds);
}

impl Default for AsymmetryThresholds {
    /// What the operator declared, else [`Self::BUILT_IN`].
    ///
    /// # Why this reads a process-global rather than taking a parameter
    ///
    /// Nine production sites ask for "the thresholds" — two in the batch
    /// runner, one in the filter DSL, four in the MCP server and two in the
    /// REST layer — and every one of them wrote `::default()`. Threading a
    /// parameter to all nine leaves nine chances for one to keep its own
    /// answer, which is the defect this type already had in a different form:
    /// the struct was public and tunable and no caller ever supplied a value,
    /// so `[diagnosis] late_media_ms` would have been honoured on some
    /// surfaces and ignored on others.
    ///
    /// `default()` means "what sipnab uses when nobody said otherwise", and an
    /// operator writing it in the config file IS somebody saying otherwise.
    /// The shipped figures remain reachable as [`Self::BUILT_IN`].
    fn default() -> Self {
        CONFIGURED.get().copied().unwrap_or(Self::BUILT_IN)
    }
}

/// Whether the capture as a whole recorded any RTP.
///
/// A run-level fact, not a per-call one, and the difference matters: on a
/// signalling-only capture — a proxy tap that never sees media, a HEP feed,
/// `--no-rtp` — *every* answered call has zero RTP, and a `no_media` flag
/// computed without this would describe where the capture was taken rather
/// than what happened on the call. Measured on one signalling-only corpus
/// capture, the guard is the difference between 338 no-media claims and none.
///
/// It is an enum rather than a `bool` so the call sites read as a statement
/// about the capture instead of an unlabelled `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMedia {
    /// The capture recorded at least one RTP stream, so an individual call
    /// having none is evidence about that call.
    Observed,
    /// The capture recorded no RTP at all, so it cannot answer a question
    /// about any one call's media.
    Absent,
}

impl CaptureMedia {
    /// Read the fact off a stream store.
    pub fn of_store(store: &crate::rtp::stream_store::StreamStore) -> Self {
        if store.is_empty() {
            CaptureMedia::Absent
        } else {
            CaptureMedia::Observed
        }
    }
}

/// The media a dialog negotiated, reduced to what the diagnosis needs.
///
/// # Which offer/answer this reads, and why
///
/// A dialog is not one SDP. It is a sequence of offer/answer exchanges — the
/// initial INVITE and its 200, a re-INVITE for hold, a resume, a codec
/// renegotiation — and "the SDP" is a decision rather than a lookup. This type
/// makes the decision once, explicitly:
///
/// * [`advertised`](Self::advertised) is the union of the connection addresses
///   from **every** exchange in the dialog, offer and answer alike. The RTP a
///   diagnosis compares against spans the whole call, so an anchor that a
///   re-INVITE later replaced was still legitimate while media flowed through
///   it. Reading only the newest exchange would report every hold, resume and
///   anchor change as a NAT fault.
/// * [`expects_media`](Self::expects_media) is true when **any** exchange
///   described media that was actually meant to flow: an RTP transport, a
///   non-zero `m=` port, a connection address that is not the black hole, and
///   a direction other than `a=inactive`. A call held for its entire life
///   carries no RTP by agreement, and calling that "no media" would invent a
///   fault. A call that negotiated `sendrecv` at any point and then carried
///   nothing did fail.
/// * [`advertised_endpoints`](Self::advertised_endpoints) pairs each of those
///   addresses with the `m=` port it was advertised on — the RECEIVE port,
///   which is the only half of the port comparison the packets cannot supply.
///   Descriptions that decline media (`m=` port 0) or carry no RTP at all
///   (T.38's `udptl`) are left out: they name a port nothing was ever going to
///   arrive on.
/// * [`negotiated`](Self::negotiated) is true when SDP appeared in both a
///   request and a response, which is what completes an offer/answer under
///   every ordering — INVITE/200, INVITE/183, and the delayed offer carried in
///   a 200 and answered in the ACK. Counting bodies instead would let an
///   INVITE and its own retransmission look like a negotiation.
///
/// Building one is cheap but not free (it reparses the dialog's SDP bodies),
/// so callers construct it only when a diagnosis is actually going to be read.
#[derive(Debug, Clone)]
pub struct MediaContext {
    /// Every connection address the dialog advertised, in first-seen order.
    /// Addresses that do not parse as an IP (an FQDN `c=` line) are absent,
    /// which suppresses the NAT check rather than guessing at it.
    advertised: Vec<IpAddr>,
    /// Every RTP **receive endpoint** the dialog advertised — the effective
    /// `c=` address paired with the `m=` port — in first-seen order.
    ///
    /// This is the half of the port comparison that only the SDP can supply.
    /// Each side advertises the port it expects RTP to arrive on, and RFC 4961
    /// symmetric RTP says it will also send from that port; NATs and plenty of
    /// endpoints break that, and the far end then replies to a port nothing is
    /// sending from, so no pinhole exists and the audio is one-way. Recording
    /// the address alone leaves that comparison unmakeable.
    ///
    /// Only descriptions that actually ask to receive RTP are recorded: an
    /// `m=` port of zero is a declined stream, and a non-RTP transport
    /// (`m=image ... udptl` for T.38) has no RTP receive port at all. Listing
    /// either would put a number in front of an operator that no RTP was ever
    /// going to arrive on.
    advertised_ports: Vec<(IpAddr, u16)>,
    /// The first advertised address, kept as written, for the report.
    primary: Option<String>,
    /// SDP appeared in both a request and a response: an offer was answered.
    negotiated: bool,
    /// Some exchange described media that was expected to flow.
    expects_media: bool,
    /// The dialog reached a 2xx — media was supposed to happen at all.
    established: bool,
    /// What the capture as a whole saw.
    capture: CaptureMedia,
}

impl Default for MediaContext {
    /// A context that knows nothing: no advertised address, no completed
    /// negotiation, and a capture presumed to hold no media.
    ///
    /// Written out rather than derived because the capture field has no
    /// neutral value. [`CaptureMedia::Absent`] is the choice that withholds a
    /// `no_media` claim, and withholding is what "I know nothing" should do.
    fn default() -> Self {
        MediaContext {
            advertised: Vec::new(),
            advertised_ports: Vec::new(),
            primary: None,
            negotiated: false,
            expects_media: false,
            established: false,
            capture: CaptureMedia::Absent,
        }
    }
}

impl MediaContext {
    /// Read a dialog's negotiation, paired with what the capture could see.
    pub fn for_dialog(dialog: &SipDialog, capture: CaptureMedia) -> Self {
        let mut ctx = MediaContext {
            capture,
            established: matches!(dialog.final_status_code(), Some(200..=299)),
            ..MediaContext::default()
        };

        let (mut sdp_in_request, mut sdp_in_response) = (false, false);
        for msg in &dialog.messages {
            let Some(sdp) = msg.sdp() else { continue };
            if msg.is_request {
                sdp_in_request = true;
            } else {
                sdp_in_response = true;
            }
            ctx.absorb(&sdp);
        }
        ctx.negotiated = sdp_in_request && sdp_in_response;
        ctx
    }

    /// A context that knows one SDP session and nothing about the dialog or
    /// the capture around it. For callers holding a bare session (and for
    /// tests); it can never satisfy `no_media`, which needs the dialog.
    pub fn from_session(sdp: &SdpSession, capture: CaptureMedia) -> Self {
        let mut ctx = MediaContext {
            capture,
            ..MediaContext::default()
        };
        ctx.absorb(sdp);
        ctx
    }

    /// Fold one SDP body into the accumulated view.
    fn absorb(&mut self, sdp: &SdpSession) {
        for media in &sdp.media {
            let Some(addr) = effective_address(media, sdp) else {
                continue;
            };
            if self.primary.is_none() {
                self.primary = Some(addr.clone());
            }
            let parsed = addr.parse::<IpAddr>().ok();
            if let Some(ip) = parsed
                && !self.advertised.contains(&ip)
            {
                self.advertised.push(ip);
            }
            // `c=0.0.0.0` (and the IPv6 `::`) is the RFC 2543 hold form older
            // gateways still emit: it asks for no media at all.
            let black_holed = parsed.is_some_and(|ip| ip.is_unspecified());
            // T.38 (`m=image ... udptl`) and other non-RTP transports carry no
            // RTP by definition, so their absence is not a media failure.
            let carries_rtp = media.proto.to_ascii_uppercase().contains("RTP");
            let asks_for_rtp = carries_rtp && media.port != 0 && !black_holed;
            if let Some(ip) = parsed
                && asks_for_rtp
            {
                let endpoint = (ip, media.port);
                if !self.advertised_ports.contains(&endpoint) {
                    self.advertised_ports.push(endpoint);
                }
            }
            if asks_for_rtp && media.direction != SdpDirection::Inactive {
                self.expects_media = true;
            }
        }
    }

    /// Every connection address the dialog advertised.
    pub fn advertised(&self) -> &[IpAddr] {
        &self.advertised
    }

    /// Whether an offer in this dialog was answered.
    pub fn negotiated(&self) -> bool {
        self.negotiated
    }

    /// Whether any exchange described media that was expected to flow.
    pub fn expects_media(&self) -> bool {
        self.expects_media
    }

    /// Every advertised RTP receive endpoint, in first-seen order.
    pub fn advertised_endpoints(&self) -> &[(IpAddr, u16)] {
        &self.advertised_ports
    }

    /// The receive ports `addr` advertised, in first-seen order.
    ///
    /// Usually one. Two or more is ordinary too — an audio and a video `m=`
    /// line on one address, or a re-INVITE that moved the port — and every one
    /// of them is a port the far end may legitimately have been told to send
    /// to, which is why they are all returned rather than reduced to a
    /// first-wins guess.
    pub fn receive_ports_for(&self, addr: IpAddr) -> Vec<u16> {
        self.advertised_ports
            .iter()
            .filter(|(a, _)| *a == addr)
            .map(|(_, p)| *p)
            .collect()
    }
}

/// The ports `addr` advertised for receiving RTP, when they disagree with a
/// port it was actually observed using.
///
/// `None` is the quiet answer, and it covers the two cases that must stay
/// quiet for different reasons. When the dialog advertised no receive port for
/// this address — no SDP, an FQDN `c=` line, or a source a NAT rewrote so that
/// no SDP describes it — there is nothing to compare and naming a port would
/// be a fabricated value dressed as evidence. When `observed` is one of the
/// advertised ports, RTP is symmetric exactly as RFC 4961 says it should be,
/// and printing "advertised 16384, sends from 16384" on every healthy leg
/// buries the one line that matters.
fn advertised_ports_disagreeing(ctx: &MediaContext, addr: IpAddr, observed: u16) -> Option<String> {
    let ports = ctx.receive_ports_for(addr);
    if ports.is_empty() || ports.contains(&observed) {
        return None;
    }
    Some(
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(" or "),
    )
}

/// `addr:port` when the dialog advertised exactly one receive port for the
/// address, and the bare address otherwise.
///
/// An address advertised on two ports has no single port to name, and picking
/// one would turn a guess into what reads as evidence.
fn advertised_endpoint_label(ctx: &MediaContext, addr: IpAddr) -> String {
    match ctx.receive_ports_for(addr).as_slice() {
        [port] => format!("{addr}:{port}"),
        _ => addr.to_string(),
    }
}

/// Diagnose media path issues for a dialog's associated RTP streams.
///
/// Examines the stream list and the dialog's negotiated media to detect:
/// - **One-way audio:** Streams exist in only one direction while the dialog
///   has been established long enough for bidirectional media.
/// - **NAT mismatch:** A stream's RTP source address is one that no SDP in the
///   dialog advertised — the signature of a NAT rewriting the media source.
/// - **No media:** An answered call negotiated media that was expected to
///   flow, and none arrived.
///
/// `media` is taken by reference rather than as an `Option` on purpose. It
/// used to be `Option<&SdpSession>`, every production caller passed `None`,
/// and `nat_mismatch` and `no_media` were therefore false on every surface
/// sipnab has — silently, because a filter that matches nothing looks exactly
/// like a clean capture. There is no longer a way to ask for the diagnosis and
/// withhold what it needs; a caller with nothing to say passes
/// [`MediaContext::default`], and that reads as the claim it is.
///
/// Returns a `MediaDiagnosis` with boolean flags and descriptive hints.
pub fn diagnose_media(dialog_streams: &[&RtpStream], media: &MediaContext) -> MediaDiagnosis {
    let mut diag = MediaDiagnosis::default();

    // No media detection. Every clause is load-bearing: see `MediaContext`
    // for why an unanswered, held, or black-holed call is not a fault, and
    // `CaptureMedia` for why a capture with no RTP cannot answer at all.
    if dialog_streams.is_empty() {
        diag.sdp_media = media.primary.clone();
        if media.negotiated
            && media.established
            && media.expects_media
            && media.capture == CaptureMedia::Observed
        {
            diag.no_media = true;
            // No RTP means no source or destination port to report, so the
            // advertised receive endpoints are the whole of the evidence — and
            // they are the firewall rule and RTP port range the operator has to
            // go and check. A dialog whose `c=` line was an FQDN advertises
            // none this can name, and then the sentence stops where the data
            // does.
            let endpoints: Vec<String> = media
                .advertised_endpoints()
                .iter()
                .map(|(addr, port)| format!("{addr}:{port}"))
                .collect();
            diag.hints.push(if endpoints.is_empty() {
                "Media was negotiated and answered, but no RTP was observed.".to_string()
            } else {
                format!(
                    "Media was negotiated and answered, but no RTP was observed at the \
                     advertised receive endpoints ({}).",
                    endpoints.join(", ")
                )
            });
        }
        return diag;
    }

    // Collect unique directed endpoints to detect one-way audio.
    // A "direction" is (src_ip, dst_ip) — if we only see one direction,
    // audio is one-way.
    let mut directions: Vec<(IpAddr, IpAddr)> = Vec::new();
    for stream in dialog_streams {
        let dir = (stream.key.src.ip(), stream.key.dst.ip());
        if !directions.contains(&dir) {
            directions.push(dir);
        }
    }

    // Check for reverse direction
    let has_bidirectional = directions
        .iter()
        .any(|(src, dst)| directions.iter().any(|(s2, d2)| s2 == dst && d2 == src));

    if !has_bidirectional && !dialog_streams.is_empty() {
        // Check if comfort noise explains the asymmetry before flagging one-way audio
        let total_cn: u32 = dialog_streams.iter().map(|s| s.cn_frames).sum();
        let total_packets: u64 = dialog_streams.iter().map(|s| s.packet_count).sum();
        // `AsymmetryThresholds::default()` rather than a parameter, for the
        // reason recorded on that impl: `diagnose_media` is called from the
        // batch runner, the filter DSL, the REST layer and the MCP tools, and
        // a threshold threaded to some of those is one honoured on some
        // surfaces and ignored on others.
        let suppression_ratio = AsymmetryThresholds::default().cn_suppression_ratio;
        let cn_suppressed = if total_cn > 0 && total_packets > 0 {
            let cn_ratio = total_cn as f64 / total_packets as f64;
            if cn_ratio > suppression_ratio {
                diag.hints.push(format!(
                    "Asymmetric media may be due to comfort noise ({:.0}% CN frames).",
                    cn_ratio * 100.0
                ));
                true
            } else {
                false
            }
        } else {
            false
        };

        if !cn_suppressed {
            diag.one_way_audio = true;
            // The stream `directions.first()` was derived from: same flow,
            // but with the ports and the SSRC still attached.
            if let Some(stream) = dialog_streams.first() {
                let (src, dst) = (stream.key.src, stream.key.dst);
                // The SSRC earns its place here and nowhere else: `triage_call`
                // answers with a `stream_count`, and the stream tools key on
                // SSRC, so this is what ties the sentence to a row in that list.
                diag.hints.push(format!(
                    "RTP flowed {src} -> {dst} only (SSRC 0x{:08x}). No reverse media \
                     flow detected.",
                    stream.key.ssrc
                ));
                // The sending side against its own SDP. This comparison is the
                // usual cause: the far end replies to the port that was
                // advertised, nothing is sending from it, so no NAT pinhole was
                // ever opened there and the reply is dropped on the way back.
                if let Some(advertised) = advertised_ports_disagreeing(media, src.ip(), src.port())
                {
                    diag.hints.push(format!(
                        "{} advertised {advertised} to receive RTP but sends from {} — \
                         not symmetric (RFC 4961), so {} replies to {advertised}, where \
                         nothing is sending and no NAT pinhole was opened.",
                        src.ip(),
                        src.port(),
                        dst.ip()
                    ));
                }
                // The receiving side against its own SDP. Media aimed at a port
                // the answer never asked for cannot be received however healthy
                // the sender looks.
                if let Some(advertised) = advertised_ports_disagreeing(media, dst.ip(), dst.port())
                {
                    diag.hints.push(format!(
                        "{} advertised {advertised} to receive RTP but the media is \
                         arriving at {} — it is aimed at a port the answer never asked \
                         for.",
                        dst.ip(),
                        dst.port()
                    ));
                }
            }
        }
    }

    // NAT mismatch detection: a stream sourced from an address that no SDP in
    // this dialog ever advertised.
    //
    // Not "the c= address differs from this stream's source", which is the
    // shape this check used to have. A two-way call has TWO advertised
    // addresses — the caller's and the callee's — and RTP flows from both, so
    // comparing every stream against a single `c=` line reports one direction
    // of every healthy call as a NAT fault. Set membership is the question
    // that survives contact with a bidirectional call.
    //
    // The DETECTION compares addresses only, never ports: NAT and RTP proxies
    // rewrite the port on a large share of ordinary calls without breaking
    // anything, while media arriving from an address nobody advertised is the
    // fault operators are actually looking for. The HINT still reports the
    // ports, because `nat_mismatch` is a verdict and the 5-tuple against the
    // advertised endpoint is the evidence for it — a boolean the reader cannot
    // check against the SDP is a boolean they have to take on trust.
    diag.sdp_media = media.primary.clone();
    if !media.advertised.is_empty() {
        for stream in dialog_streams {
            let actual_src = stream.key.src.ip();
            if media.advertised.contains(&actual_src) {
                continue;
            }
            diag.nat_mismatch = true;
            diag.actual_media = Some(actual_src.to_string());
            // The address this leg should have used is an advertised one that
            // is not the far end this stream is aimed at.
            let far_end = stream.key.dst.ip();
            if let Some(expected) = media
                .advertised
                .iter()
                .find(|a| **a != far_end)
                .or_else(|| media.advertised.first())
            {
                diag.sdp_media = Some(expected.to_string());
                let offered = advertised_endpoint_label(media, *expected);
                diag.hints.push(format!(
                    "RTP arrived from {} at {}, and no SDP in this dialog advertised \
                     {actual_src} (it offered {offered}) — the media source was rewritten, \
                     typically by NAT, so replies sent to {offered} never reach it.",
                    stream.key.src, stream.key.dst
                ));
            }
            break;
        }
    }

    // Combine one-way + NAT hint
    if diag.one_way_audio && diag.nat_mismatch {
        diag.hints.push(
            "One-way audio combined with NAT mismatch — media likely being sent to \
             the wrong address."
                .to_string(),
        );
    }

    diag
}

/// Phase 8.7 — per-call asymmetry checks comparing the two RTP legs of a
/// SIP call. Mutates `diag` in place; returns nothing. Each check sets a
/// `Some(_)` field when an asymmetry is detected and leaves the field
/// `None` otherwise. Callers obtain a diagnosis via `diagnose_media`
/// first, then enrich it with this function.
///
/// `dialog` is used only for the `late_media` check (needs `answered_at`).
/// Pass `None` to skip that check.
///
/// "A leg" / "B leg" pairing: if there are exactly two streams, the first
/// in the slice is A, the second is B. If there's a clear bidirectional
/// pair (src/dst swap), they're paired and ordered by `first_seen`. With
/// 0 or 1 stream, no asymmetry is computed.
pub fn diagnose_asymmetry(
    diag: &mut MediaDiagnosis,
    dialog: Option<&SipDialog>,
    dialog_streams: &[&RtpStream],
    thresholds: &AsymmetryThresholds,
) {
    // Need at least two streams to compare.
    let (a, b) = match pick_leg_pair(dialog_streams) {
        Some(pair) => pair,
        None => return,
    };

    // ── Codec asymmetry ────────────────────────────────────────────
    if let (Some(ac), Some(bc)) = (a.codec.as_deref(), b.codec.as_deref())
        && ac != bc
    {
        diag.codec_asymmetry = Some(CodecAsymmetry {
            a_codec: ac.to_string(),
            b_codec: bc.to_string(),
        });
        diag.hints.push(format!(
            "Codec asymmetry: A leg uses {ac}, B leg uses {bc} — likely a \
             transcoding B2BUA on the path."
        ));
    }

    // ── Payload-type asymmetry ─────────────────────────────────────
    // Only meaningful when codecs match but PTs differ (otherwise a codec
    // asymmetry already explains the PT mismatch).
    if a.payload_type != b.payload_type && a.codec.is_some() && a.codec == b.codec {
        diag.payload_type_asymmetry = Some(PayloadTypeAsymmetry {
            a_pt: a.payload_type,
            b_pt: b.payload_type,
        });
        diag.hints.push(format!(
            "Payload-type asymmetry: same codec, different PTs ({} vs {}) — \
             middlebox rewriting or SDP/answer mismatch.",
            a.payload_type, b.payload_type
        ));
    }

    // ── Ptime asymmetry ────────────────────────────────────────────
    let a_ptime = a.inferred_ptime_ms();
    let b_ptime = b.inferred_ptime_ms();
    if let (Some(ap), Some(bp)) = (a_ptime, b_ptime) {
        // Allow 2 ms slack to absorb wall-clock jitter on inter-arrival
        // measurements; SDP-derived ptimes are exact.
        if ap.abs_diff(bp) > 2 {
            diag.ptime_asymmetry = Some(PtimeAsymmetry {
                a_ptime_ms: ap,
                b_ptime_ms: bp,
            });
            diag.hints.push(format!(
                "Ptime asymmetry: {ap} ms vs {bp} ms — different framing per leg."
            ));
        }
    }

    // ── Duration asymmetry ─────────────────────────────────────────
    let a_dur = stream_duration_sec(a);
    let b_dur = stream_duration_sec(b);
    let delta = (a_dur - b_dur).abs();
    let max_dur = a_dur.max(b_dur).max(0.001); // avoid div-by-zero
    let pct_delta = (delta / max_dur) * 100.0;
    if delta >= thresholds.duration_min_delta_sec && pct_delta >= thresholds.duration_pct_delta {
        diag.duration_asymmetry = Some(DurationAsymmetry {
            a_duration_sec: a_dur,
            b_duration_sec: b_dur,
            delta_sec: delta,
        });
        diag.hints.push(format!(
            "Duration asymmetry: A leg lasted {a_dur:.1}s, B leg {b_dur:.1}s \
             (Δ {delta:.1}s) — one side may have hung up or dropped media early."
        ));
    }

    // ── Late media ─────────────────────────────────────────────────
    if let Some(d) = dialog
        && let Some(answered) = d.timing.answered_at
    {
        // Earliest first_seen among the two legs is the start of media.
        let media_start = a.first_seen.min(b.first_seen);
        let delay_ms = (media_start - answered).num_milliseconds();
        if delay_ms > thresholds.late_media_threshold_ms {
            let leg = if a.first_seen <= b.first_seen {
                "a"
            } else {
                "b"
            };
            diag.late_media = Some(LateMedia {
                leg: leg.to_string(),
                delay_after_200_ok_ms: delay_ms,
            });
            diag.hints.push(format!(
                "Late media: RTP started {delay_ms} ms after 200 OK — far end \
                 was slow to send, or the media path wasn't ready when signalling \
                 completed."
            ));
        }
    }
}

/// Pick the two legs of a dialog. With exactly two streams, return them
/// ordered by `first_seen` (A leg = earliest). With more streams, pick the
/// two that form a bidirectional pair (src↔dst), again ordered by
/// `first_seen`. Returns `None` when no valid pair exists.
fn pick_leg_pair<'a>(streams: &[&'a RtpStream]) -> Option<(&'a RtpStream, &'a RtpStream)> {
    if streams.len() < 2 {
        return None;
    }
    if streams.len() == 2 {
        let mut ordered = [streams[0], streams[1]];
        ordered.sort_by_key(|s| s.first_seen);
        return Some((ordered[0], ordered[1]));
    }
    // Look for a bidirectional pair.
    for (i, a) in streams.iter().enumerate() {
        for b in streams.iter().skip(i + 1) {
            if a.key.src.ip() == b.key.dst.ip() && a.key.dst.ip() == b.key.src.ip() {
                let mut pair = [*a, *b];
                pair.sort_by_key(|s| s.first_seen);
                return Some((pair[0], pair[1]));
            }
        }
    }
    None
}

/// Wall-clock duration of a stream in seconds.
fn stream_duration_sec(s: &RtpStream) -> f64 {
    let ms = (s.last_seen - s.first_seen).num_milliseconds();
    ms as f64 / 1000.0
}

/// Unit tests for media-path and per-call asymmetry diagnosis.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::DateTime;

    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::sdp::{SdpConnection, SdpDirection, SdpMedia, SdpSession};

    /// A fixed capture timestamp used across the diagnosis tests.
    fn ts() -> DateTime<chrono::Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid")
    }

    /// Build a 10-packet PCMU stream between the given endpoints.
    fn make_stream(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> RtpStream {
        let key = StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_ip)), src_port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst_ip)), dst_port),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0x12345678,
            payload_offset: 12,
        };
        let mut stream = RtpStream::new(key, &hdr, ts());
        // Simulate some packets
        for i in 1..10u16 {
            let h = RtpHeader {
                sequence: 100 + i,
                timestamp: i as u32 * 160,
                ..hdr.clone()
            };
            stream.update(&h, ts(), 160);
        }
        stream
    }

    /// Build a minimal single-audio-media SDP session with the given
    /// connection address and port.
    fn make_sdp(addr: &str, port: u16) -> SdpSession {
        SdpSession {
            origin: None,
            session_name: None,
            connection: Some(SdpConnection {
                addr: addr.to_string(),
            }),
            media: vec![SdpMedia {
                media_type: "audio".to_string(),
                port,
                proto: "RTP/AVP".to_string(),
                formats: vec!["0".to_string()],
                connection: None,
                direction: SdpDirection::SendRecv,
                rtpmap: Vec::new(),
                fmtp: Vec::new(),
                ptime: None,
                crypto: Vec::new(),
                ice_candidates: Vec::new(),
                rtcp_mux: false,
                rtcp_port: None,
            }],
        }
    }

    /// An audio+video SDP: the session `c=` is `session_addr`, the audio
    /// `m=` overrides it with `audio_addr`, and the video `m=` inherits the
    /// session one. Two advertised addresses from one offer.
    fn audio_video_sdp(session_addr: &str, audio_addr: &str) -> SdpSession {
        let mk_media = |mtype: &str, port: u16, conn: Option<&str>| SdpMedia {
            media_type: mtype.to_string(),
            port,
            proto: "RTP/AVP".to_string(),
            formats: vec!["0".to_string()],
            connection: conn.map(|a| SdpConnection {
                addr: a.to_string(),
            }),
            direction: SdpDirection::SendRecv,
            rtpmap: Vec::new(),
            fmtp: Vec::new(),
            ptime: None,
            crypto: Vec::new(),
            ice_candidates: Vec::new(),
            rtcp_mux: false,
            rtcp_port: None,
        };
        SdpSession {
            origin: None,
            session_name: None,
            connection: Some(SdpConnection {
                addr: session_addr.to_string(),
            }),
            media: vec![
                mk_media("audio", 20000, Some(audio_addr)),
                mk_media("video", 20002, None),
            ],
        }
    }

    /// An audio SDP body advertising `addr:port` as the receive endpoint.
    fn sdp_text(direction: &str, addr: &str, port: u16) -> String {
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a={direction}\r\n"
        )
    }

    /// Build an answered INVITE dialog whose offer and answer both carry an
    /// audio SDP at `addr:port` with the given direction attribute.
    ///
    /// Two SDP bodies, one in the request and one in the response — the shape
    /// [`MediaContext::for_dialog`] reads as a completed offer/answer.
    fn answered_dialog_with_sdp(direction: &str, addr: &str, port: u16) -> SipDialog {
        let body = sdp_text(direction, addr, port);
        answered_dialog_with_bodies(&body, &body)
    }

    /// An answered INVITE whose offer advertises one receive endpoint and
    /// whose answer advertises a different one — the two-sided negotiation a
    /// real call makes, and the only shape that carries a receive port *per
    /// side* for the port hints to compare against.
    fn two_party_dialog(
        caller: &str,
        caller_port: u16,
        callee: &str,
        callee_port: u16,
    ) -> SipDialog {
        answered_dialog_with_bodies(
            &sdp_text("sendrecv", caller, caller_port),
            &sdp_text("sendrecv", callee, callee_port),
        )
    }

    /// An answered INVITE carrying `offer` in the request and `answer` in the
    /// response.
    fn answered_dialog_with_bodies(offer: &str, answer: &str) -> SipDialog {
        use crate::net::TransportProto;
        use crate::sip::parser::parse_sip;
        use crate::test_utils::build_sip_message;

        let build = |first: &str, to: &str, body: &str| {
            let raw = build_sip_message(
                first,
                &[
                    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-diag",
                    "From: <sip:a@example.net>;tag=aaa",
                    to,
                    "Call-ID: media-ctx@example.net",
                    "CSeq: 1 INVITE",
                    "Content-Type: application/sdp",
                    &format!("Content-Length: {}", body.len()),
                ],
                body.as_bytes(),
            );
            parse_sip(
                &raw,
                ts(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("fixture should parse")
        };

        let invite = build(
            "INVITE sip:b@example.net SIP/2.0",
            "To: <sip:b@example.net>",
            offer,
        );
        let ok = build("SIP/2.0 200 OK", "To: <sip:b@example.net>;tag=bbb", answer);
        let mut dialog = SipDialog::new(&invite).expect("dialog from INVITE");
        dialog.messages.push(ok);
        dialog
    }

    /// Two streams in opposite directions are not flagged as one-way audio.
    #[test]
    fn bidirectional_streams_no_one_way() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let s2 = make_stream([10, 0, 0, 2], [10, 0, 0, 1], 30000, 20000);
        let streams: Vec<&RtpStream> = vec![&s1, &s2];

        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(!diag.one_way_audio);
        assert!(diag.hints.is_empty() || !diag.hints.iter().any(|h| h.contains("only")));
    }

    /// A single-direction stream is flagged as one-way audio.
    #[test]
    fn unidirectional_streams_flags_one_way() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(diag.one_way_audio);
        assert!(diag.hints.iter().any(|h| h.contains("only")));
    }

    /// Every hint joined, for the port assertions below.
    fn joined(diag: &MediaDiagnosis) -> String {
        diag.hints.join(" ")
    }

    /// The one-way hint names the source port and the destination port.
    ///
    /// One-way audio is fixed through port-based artifacts — a firewall rule,
    /// a NAT pinhole, an RTP port range, the `m=audio <port>` line — so a hint
    /// that stops at addresses stops exactly where the operator's next action
    /// begins.
    #[test]
    fn one_way_hint_names_both_ports_of_the_flow() {
        let s1 = make_stream([10, 0, 2, 15], [10, 0, 2, 20], 41002, 16386);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(
            joined(&diag).contains("10.0.2.15:41002 -> 10.0.2.20:16386"),
            "the hint must name both ports of the flow it describes: {:?}",
            diag.hints
        );
    }

    /// The one-way hint carries the stream's SSRC.
    ///
    /// `triage_call` reports a `stream_count` and the stream tools key on
    /// SSRC; without it the reader cannot tell which of several streams the
    /// hint is about.
    #[test]
    fn one_way_hint_carries_the_ssrc_of_the_flow() {
        let s1 = make_stream([10, 0, 2, 15], [10, 0, 2, 20], 41002, 16386);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(
            joined(&diag).contains("0x12345678"),
            "the hint must name the SSRC that identifies this stream: {:?}",
            diag.hints
        );
    }

    /// The sending side's advertised receive port is compared against the port
    /// it actually sends from, and the disagreement is stated.
    ///
    /// RFC 4961 symmetric RTP says the two are the same port. When they are
    /// not, the far end replies to an advertised port nothing is sending from,
    /// no NAT pinhole exists there, and the reply is dropped — the leading
    /// cause of one-way audio, and invisible in a hint that prints one port
    /// per side.
    #[test]
    fn one_way_hint_compares_the_advertised_receive_port_with_the_source_port() {
        let dialog = two_party_dialog("10.0.2.15", 16384, "10.0.2.20", 16386);
        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        // Sends from 41002 while its SDP advertised 16384: not symmetric.
        let s1 = make_stream([10, 0, 2, 15], [10, 0, 2, 20], 41002, 16386);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &ctx);
        let text = joined(&diag);
        assert!(
            text.contains("10.0.2.15 advertised 16384"),
            "the hint must name the receive port the SDP advertised: {:?}",
            diag.hints
        );
        assert!(
            text.contains("sends from 41002"),
            "the hint must name the port RTP is actually sourced from: {:?}",
            diag.hints
        );
        assert!(
            text.contains("not symmetric"),
            "the hint must say what the mismatch means: {:?}",
            diag.hints
        );
        assert!(
            text.contains("10.0.2.20 replies to 16384"),
            "the hint must name the port the far end's reply would go to, \
             which is where the missing pinhole is: {:?}",
            diag.hints
        );
    }

    /// A side that sends from the port it advertised gets no port comparison.
    ///
    /// Symmetric RTP is the correct behaviour; printing "advertised 16384 and
    /// sends from 16384" on every healthy leg is noise that buries the case
    /// where the two disagree.
    #[test]
    fn symmetric_rtp_draws_no_advertised_versus_actual_comparison() {
        let dialog = two_party_dialog("10.0.2.15", 16384, "10.0.2.20", 16386);
        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        let s1 = make_stream([10, 0, 2, 15], [10, 0, 2, 20], 16384, 16386);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &ctx);
        assert!(
            !joined(&diag).contains("advertised"),
            "both ports match what was advertised; there is nothing to compare: {:?}",
            diag.hints
        );
    }

    /// RTP arriving at a port the answer never advertised is stated too.
    ///
    /// The mirror of the source-port case: media aimed at a port the far end
    /// never asked for cannot be received, however healthy the sender looks.
    #[test]
    fn one_way_hint_names_a_destination_port_the_answer_never_advertised() {
        let dialog = two_party_dialog("10.0.2.15", 16384, "10.0.2.20", 16386);
        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        // Sent to 9999; the answer advertised 16386.
        let s1 = make_stream([10, 0, 2, 15], [10, 0, 2, 20], 16384, 9999);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &ctx);
        let text = joined(&diag);
        assert!(
            text.contains("10.0.2.20 advertised 16386"),
            "the hint must name the receive port the answer advertised: {:?}",
            diag.hints
        );
        assert!(
            text.contains("arriving at 9999"),
            "the hint must name the port the media is actually aimed at: {:?}",
            diag.hints
        );
    }

    /// A port that was never advertised is never invented.
    ///
    /// With no SDP in hand there is no advertised port to compare against, and
    /// a hint that named one would be a fabricated value dressed as evidence.
    #[test]
    fn no_advertised_port_means_no_comparison_is_claimed() {
        let s1 = make_stream([10, 0, 2, 15], [10, 0, 2, 20], 41002, 16386);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(
            !joined(&diag).contains("advertised"),
            "no SDP was supplied, so no advertised port is knowable: {:?}",
            diag.hints
        );
    }

    /// A declined `m=` line and a non-RTP transport advertise no RTP receive
    /// port.
    ///
    /// `m=audio 0` is how an endpoint says "not this stream", and T.38's
    /// `m=image ... udptl` carries no RTP at all. Both name a number, and
    /// neither is a port RTP was ever going to arrive on — so putting either
    /// in front of an operator sends them to check a firewall rule that was
    /// never going to matter.
    #[test]
    fn declined_and_non_rtp_media_advertise_no_receive_port() {
        let declined = make_sdp("10.0.0.1", 0);
        let ctx = MediaContext::from_session(&declined, CaptureMedia::Observed);
        assert!(
            ctx.advertised_endpoints().is_empty(),
            "a declined m= line advertises no receive port: {:?}",
            ctx.advertised_endpoints()
        );

        let mut t38 = make_sdp("10.0.0.1", 30000);
        t38.media[0].media_type = "image".to_string();
        t38.media[0].proto = "udptl".to_string();
        let ctx = MediaContext::from_session(&t38, CaptureMedia::Observed);
        assert!(
            ctx.advertised_endpoints().is_empty(),
            "a non-RTP transport advertises no RTP receive port: {:?}",
            ctx.advertised_endpoints()
        );
    }

    /// The NAT hint carries the ports its boolean verdict rests on.
    ///
    /// `nat_mismatch` is a verdict; the 5-tuple and the advertised endpoint
    /// are the evidence for it. A boolean an operator cannot check against the
    /// SDP is one they have to take on trust.
    #[test]
    fn nat_hint_names_the_ports_behind_the_verdict() {
        let dialog = two_party_dialog("192.168.1.100", 16384, "203.0.113.9", 16386);
        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        // The caller's RTP leaves a public address no SDP ever advertised.
        let s1 = make_stream([198, 51, 100, 7], [203, 0, 113, 9], 41002, 16386);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &ctx);
        assert!(diag.nat_mismatch, "hints were {:?}", diag.hints);
        // The NAT hint SPECIFICALLY, not the joined text. A one-way call also
        // gets the flow hint, which carries the same 5-tuple — asserting over
        // the join let a NAT hint that had lost its ports pass on the strength
        // of a sentence beside it.
        let nat = diag
            .hints
            .iter()
            .find(|h| h.contains("no SDP in this dialog advertised"))
            .unwrap_or_else(|| panic!("no NAT hint among {:?}", diag.hints));
        assert!(
            nat.contains("198.51.100.7:41002"),
            "the NAT hint must name the source endpoint it saw: {nat}"
        );
        assert!(
            nat.contains("203.0.113.9:16386"),
            "the NAT hint must name where that media was aimed: {nat}"
        );
        assert!(
            nat.contains("192.168.1.100:16384"),
            "the NAT hint must name the endpoint the SDP advertised instead: {nat}"
        );
    }

    /// The no-media hint names the receive endpoints nothing arrived at.
    ///
    /// With no RTP there is no source or destination port to report, so the
    /// advertised endpoints are the whole of the evidence — and they are the
    /// firewall rule the operator has to go and check.
    #[test]
    fn no_media_hint_names_the_advertised_receive_endpoints() {
        let streams: Vec<&RtpStream> = vec![];
        let dialog = two_party_dialog("10.0.2.15", 16384, "10.0.2.20", 16386);

        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        let diag = diagnose_media(&streams, &ctx);
        assert!(diag.no_media, "hints were {:?}", diag.hints);
        let text = joined(&diag);
        assert!(
            text.contains("10.0.2.15:16384") && text.contains("10.0.2.20:16386"),
            "the hint must name the advertised receive endpoints: {:?}",
            diag.hints
        );
    }

    /// An SDP `c=` address that differs from the observed RTP source flags
    /// a NAT mismatch and records both addresses.
    #[test]
    fn sdp_address_differs_from_actual_flags_nat() {
        // SDP says 192.168.1.100, but actual RTP source is 10.0.0.1
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = make_sdp("192.168.1.100", 20000);

        let diag = diagnose_media(
            &streams,
            &MediaContext::from_session(&sdp, CaptureMedia::Observed),
        );
        assert!(diag.nat_mismatch);
        assert_eq!(diag.sdp_media.as_deref(), Some("192.168.1.100"));
        assert_eq!(diag.actual_media.as_deref(), Some("10.0.0.1"));
        assert!(diag.hints.iter().any(|h| h.contains("NAT")));
    }

    /// When the SDP address matches the RTP source, no NAT mismatch is flagged.
    #[test]
    fn sdp_address_matches_no_nat_flag() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = make_sdp("10.0.0.1", 20000);

        let diag = diagnose_media(
            &streams,
            &MediaContext::from_session(&sdp, CaptureMedia::Observed),
        );
        assert!(!diag.nat_mismatch);
    }

    /// An answered call that negotiated media it then never carried flags
    /// `no_media`.
    ///
    /// A bare SDP session is deliberately not enough. `no_media` is a claim
    /// about a *call* — that an offer was answered and audio was supposed to
    /// follow — so it needs the dialog, and a caller holding only a session
    /// cannot accidentally assert it.
    #[test]
    fn answered_negotiation_with_no_rtp_flags_no_media() {
        let streams: Vec<&RtpStream> = vec![];
        let dialog = answered_dialog_with_sdp("sendrecv", "10.0.0.1", 20000);

        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        let diag = diagnose_media(&streams, &ctx);
        assert!(diag.no_media, "hints were {:?}", diag.hints);
        assert!(diag.hints.iter().any(|h| h.contains("no RTP was observed")));
    }

    /// The same call on a capture that recorded no RTP at all does not flag
    /// `no_media`: the capture cannot answer the question it is being asked.
    #[test]
    fn no_media_is_withheld_when_the_capture_recorded_no_rtp() {
        let streams: Vec<&RtpStream> = vec![];
        let dialog = answered_dialog_with_sdp("sendrecv", "10.0.0.1", 20000);

        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Absent);
        let diag = diagnose_media(&streams, &ctx);
        assert!(!diag.no_media);
        assert!(diag.hints.is_empty());
    }

    /// A call whose media was negotiated `a=inactive` throughout carries no
    /// RTP by agreement, so it is not a media failure.
    #[test]
    fn held_call_does_not_flag_no_media() {
        let streams: Vec<&RtpStream> = vec![];
        let dialog = answered_dialog_with_sdp("inactive", "10.0.0.1", 20000);

        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);
        assert!(
            !ctx.expects_media(),
            "inactive media is not expected to flow"
        );
        assert!(!diagnose_media(&streams, &ctx).no_media);
    }

    /// A bare SDP session with no dialog behind it can never assert
    /// `no_media`, whatever the capture saw.
    #[test]
    fn a_session_without_a_dialog_cannot_claim_no_media() {
        let streams: Vec<&RtpStream> = vec![];
        let sdp = make_sdp("10.0.0.1", 20000);

        let ctx = MediaContext::from_session(&sdp, CaptureMedia::Observed);
        assert!(
            !ctx.negotiated(),
            "one session is an offer, not a negotiation"
        );
        assert!(!diagnose_media(&streams, &ctx).no_media);
    }

    /// No streams and no SDP produces a clean diagnosis with no flags or hints.
    #[test]
    fn no_streams_no_sdp_is_clean() {
        let streams: Vec<&RtpStream> = vec![];
        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(!diag.no_media);
        assert!(!diag.one_way_audio);
        assert!(!diag.nat_mismatch);
        assert!(diag.hints.is_empty());
    }

    /// A high comfort-noise ratio suppresses the one-way-audio flag and adds a
    /// comfort-noise hint instead.
    #[test]
    fn comfort_noise_suppresses_one_way_audio() {
        // Create a unidirectional stream with high CN ratio (>30%)
        let mut s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        // packet_count is 10 (initial + 9 updates), set cn_frames > 30%
        s1.cn_frames = 5; // 5/10 = 50% CN
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, &MediaContext::default());
        // With high CN ratio, one_way_audio should NOT be flagged
        assert!(
            !diag.one_way_audio,
            "one_way_audio should be suppressed by comfort noise"
        );
        assert!(
            diag.hints.iter().any(|h| h.contains("comfort noise")),
            "hints should mention comfort noise: {:?}",
            diag.hints
        );
    }

    /// One-way audio plus a NAT mismatch produces the combined "wrong address"
    /// hint.
    #[test]
    fn one_way_plus_nat_gives_combined_hint() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = make_sdp("192.168.1.100", 20000);

        let diag = diagnose_media(
            &streams,
            &MediaContext::from_session(&sdp, CaptureMedia::Observed),
        );
        assert!(diag.one_way_audio);
        assert!(diag.nat_mismatch);
        assert!(diag.hints.iter().any(|h| h.contains("wrong address")));
    }

    // ── Phase 8.7 — asymmetry tests ─────────────────────────────────

    /// Build a stream with explicit codec / payload type / timestamp progression
    /// so the asymmetry tests can assemble realistic-looking pairs.
    #[expect(clippy::too_many_arguments)]
    fn make_stream_with_pt(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        pt: u8,
        codec: &str,
        clock_rate: u32,
        ptime_ms: u32,
        first_seen_offset_secs: i64,
        packet_count: u64,
    ) -> RtpStream {
        let key = StreamKey {
            ssrc: 0xABCDEF00 ^ pt as u32,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_ip)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst_ip)), 30000),
        };
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: pt,
            sequence: 100,
            timestamp: 0,
            ssrc: key.ssrc,
            payload_offset: 12,
        };
        let first_seen = ts() + chrono::Duration::seconds(first_seen_offset_secs);
        let mut s = RtpStream::new(key, &header, first_seen);
        s.codec = Some(codec.to_string());
        s.clock_rate = clock_rate;
        s.packet_count = packet_count;
        // Inferred ptime depends on (last_seen - first_seen) / (packet_count-1)
        let span_ms = ptime_ms as i64 * (packet_count as i64 - 1).max(1);
        s.last_seen = first_seen + chrono::Duration::milliseconds(span_ms);
        s
    }

    /// Build a dialog from an INVITE whose `answered_at` is `secs_after_epoch`
    /// seconds after the fixed test timestamp.
    fn make_dialog_with_answer(secs_after_epoch: i64) -> SipDialog {
        use crate::sip::SipMessage;
        use crate::sip::message::SipHeader;
        use crate::sip::method::SipMethod;
        use std::borrow::Cow;
        let mk_hdr = |name: &'static str, value: &str| SipHeader {
            name: Cow::Borrowed(name),
            value: value.to_string(),
        };
        let invite = SipMessage {
            frame: None,
            timestamp: ts(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5060,
            transport: crate::net::TransportProto::Udp,
            is_request: true,
            method: Some(SipMethod::Invite),
            request_uri: Some("sip:b@10.0.0.2".to_string()),
            status_code: None,
            reason: None,
            headers: vec![
                mk_hdr("Call-ID", "asym-test@10.0.0.1"),
                mk_hdr("From", "<sip:a@10.0.0.1>;tag=A"),
                mk_hdr("To", "<sip:b@10.0.0.2>"),
                mk_hdr("CSeq", "1 INVITE"),
            ],
            body: Default::default(),
            raw: Default::default(),
            parse_error: false,
            dscp: None,
            is_retransmission: false,
        };
        let mut d = SipDialog::new(&invite).expect("dialog from INVITE");
        d.timing.invite_sent = Some(ts());
        d.timing.answered_at = Some(ts() + chrono::Duration::seconds(secs_after_epoch));
        d
    }

    /// Legs using different codecs (PCMU vs G729) set `codec_asymmetry`.
    #[test]
    fn codec_asymmetry_detected_when_legs_differ() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 18, "G729", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let asym = diag.codec_asymmetry.expect("codec asymmetry should be set");
        assert_eq!(asym.a_codec, "PCMU");
        assert_eq!(asym.b_codec, "G729");
    }

    /// Matching codecs on both legs leave `codec_asymmetry` unset.
    #[test]
    fn codec_asymmetry_negative_when_legs_match() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.codec_asymmetry.is_none());
    }

    /// Same codec but different payload types sets `payload_type_asymmetry`.
    #[test]
    fn payload_type_asymmetry_detected_when_codec_matches_pt_differs() {
        // Both legs use PCMA codec but different PTs (one static 8, one dyn 96)
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 8, "PCMA", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 96, "PCMA", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let asym = diag
            .payload_type_asymmetry
            .expect("PT asymmetry should be set");
        assert_eq!((asym.a_pt, asym.b_pt), (8, 96));
    }

    /// When codecs already differ, the PT-asymmetry field is left unset (the
    /// codec asymmetry already covers it).
    #[test]
    fn payload_type_asymmetry_skipped_when_codec_differs() {
        // Codec already differs — payload-type field should NOT be set, since
        // the codec asymmetry message already covers it.
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 8, "PCMA", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.codec_asymmetry.is_some());
        assert!(diag.payload_type_asymmetry.is_none());
    }

    /// Inferred ptimes of 20 ms vs 30 ms set `ptime_asymmetry`.
    #[test]
    fn ptime_asymmetry_detected_20_vs_30() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 30, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let asym = diag.ptime_asymmetry.expect("ptime asymmetry should be set");
        assert_eq!(asym.a_ptime_ms, 20);
        assert_eq!(asym.b_ptime_ms, 30);
    }

    /// Equal ptimes on both legs leave `ptime_asymmetry` unset.
    #[test]
    fn ptime_asymmetry_negative_when_legs_match() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.ptime_asymmetry.is_none());
    }

    /// A 30s-vs-25s duration gap (above both thresholds) sets
    /// `duration_asymmetry`.
    #[test]
    fn duration_asymmetry_detected_when_above_thresholds() {
        // A leg: 30s, B leg: 25s → 5s delta, ~17% pct delta. Above 5%/2s default.
        let mut a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 1500);
        a.last_seen = a.first_seen + chrono::Duration::seconds(30);
        let mut b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 1250);
        b.last_seen = b.first_seen + chrono::Duration::seconds(25);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let dur = diag
            .duration_asymmetry
            .expect("duration asymmetry should be set");
        assert!((dur.a_duration_sec - 30.0).abs() < 0.01);
        assert!((dur.b_duration_sec - 25.0).abs() < 0.01);
        assert!((dur.delta_sec - 5.0).abs() < 0.01);
    }

    /// A sub-2-second duration gap stays below the minimum delta and is not
    /// flagged.
    #[test]
    fn duration_asymmetry_negative_below_minimum_delta() {
        // 30s vs 29.5s — delta 0.5s, below 2.0s minimum.
        let mut a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 1500);
        a.last_seen = a.first_seen + chrono::Duration::seconds(30);
        let mut b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 1475);
        b.last_seen = b.first_seen + chrono::Duration::milliseconds(29_500);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.duration_asymmetry.is_none());
    }

    /// RTP starting well after the 200 OK sets `late_media` with the delay.
    #[test]
    fn late_media_detected_when_rtp_starts_after_threshold() {
        // 200 OK at +0s; RTP starts at +1.5s → 1500 ms delay > 500 ms default
        let dialog = make_dialog_with_answer(0);
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 2, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 2, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(
            &mut diag,
            Some(&dialog),
            &streams,
            &AsymmetryThresholds::default(),
        );
        let lm = diag.late_media.expect("late_media should be set");
        assert!(lm.delay_after_200_ok_ms >= 1_500);
    }

    /// RTP starting promptly after the 200 OK leaves `late_media` unset.
    #[test]
    fn late_media_negative_when_rtp_starts_quickly() {
        let dialog = make_dialog_with_answer(0);
        // RTP at 0s = same as 200 OK; well below 500ms threshold.
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(
            &mut diag,
            Some(&dialog),
            &streams,
            &AsymmetryThresholds::default(),
        );
        assert!(diag.late_media.is_none());
    }

    /// A multi-media offer advertises one address per `m=` line, and RTP
    /// sourced from ANY of them is legitimate.
    ///
    /// The audio `m=` carries a pre-NAT private `c=`; the video `m=` falls
    /// back to the session address, which is where the RTP actually came
    /// from. Judging each `m=` line separately called that a NAT fault. The
    /// dialog advertised the address, so it is not one.
    #[test]
    fn rtp_from_any_advertised_media_is_not_a_nat_mismatch() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = audio_video_sdp("10.0.0.1", "192.168.1.100");

        let diag = diagnose_media(
            &streams,
            &MediaContext::from_session(&sdp, CaptureMedia::Observed),
        );
        assert!(
            !diag.nat_mismatch,
            "10.0.0.1 was advertised by the video m= line; hints were {:?}",
            diag.hints
        );
    }

    /// When the source matches none of several advertised addresses, the
    /// report names an advertised address that is not the far end — the one
    /// this leg should have used — rather than whichever `m=` line came last.
    #[test]
    fn nat_mismatch_names_the_address_this_leg_should_have_used() {
        // Source 198.51.100.7 is advertised nowhere; the far end is 10.0.0.1.
        let s1 = make_stream([198, 51, 100, 7], [10, 0, 0, 1], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = audio_video_sdp("10.0.0.1", "192.168.1.100");

        let diag = diagnose_media(
            &streams,
            &MediaContext::from_session(&sdp, CaptureMedia::Observed),
        );
        assert!(diag.nat_mismatch);
        assert_eq!(diag.actual_media.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            diag.sdp_media.as_deref(),
            Some("192.168.1.100"),
            "the far end is 10.0.0.1, so the address this leg should have used \
             is the other advertised one"
        );
    }

    /// Inferred ptime must not be inflated by packet loss: lost packets still
    /// occupy their packetization slots, so the wall-clock span must be
    /// divided by all intervals (received + lost), not just received − 1.
    #[test]
    fn inferred_ptime_not_inflated_by_loss() {
        // 100 frames of 20 ms were transmitted (99 intervals → 1980 ms span),
        // but half were lost in transit; only 50 packets arrived.
        let mut s = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 50);
        s.last_seen = s.first_seen + chrono::Duration::milliseconds(99 * 20);
        s.lost_packets = 50;
        // Naive span/(received − 1) = 1980/49 ≈ 40 ms; loss-aware = 20 ms.
        assert_eq!(s.inferred_ptime_ms(), Some(20));
    }

    /// With only one stream, no asymmetry fields are computed.
    #[test]
    fn asymmetry_skipped_with_single_stream() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a];

        let mut diag = diagnose_media(&streams, &MediaContext::default());
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.codec_asymmetry.is_none());
        assert!(diag.ptime_asymmetry.is_none());
        assert!(diag.payload_type_asymmetry.is_none());
        assert!(diag.duration_asymmetry.is_none());
        assert!(diag.late_media.is_none());
    }
}
