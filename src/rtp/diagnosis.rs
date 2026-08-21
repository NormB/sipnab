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

/// Why the unroutable address a client advertised is one it had no excuse for.
///
/// Each variant is a different sentence about the SAME condition
/// [`MediaDiagnosis::private_media_address`] raises — never a second condition.
/// See [`StunSdpMismatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StunSdpMismatchReason {
    /// STUN answered with a public address and the client advertised a private
    /// one regardless. The client HAD the right answer and did not use it,
    /// which points at the phone's NAT settings rather than at the network.
    Ignored,
    /// A TURN server allocated this client a relayed transport address and the
    /// client advertised a private one regardless. The same fault as
    /// [`StunSdpMismatchReason::Ignored`] and worse: the client did not merely
    /// LEARN a reachable address, it went to the trouble of reserving one on a
    /// relay and then left it out of the SDP.
    RelayIgnored,
    /// The client's Binding Request drew no response at all, so it never
    /// learned a public address to advertise. RFC 5389 §7.2.1 retransmits only
    /// on timeout, so a retransmitted request is itself proof of the silence —
    /// the shape a firewall dropping UDP to the STUN port makes.
    Unanswered,
}

impl StunSdpMismatchReason {
    /// A short tag for reports and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ignored => "ignored",
            Self::RelayIgnored => "relay_ignored",
            Self::Unanswered => "unanswered",
        }
    }

    /// Whether this reason names an address the client could have advertised
    /// and did not.
    ///
    /// `Unanswered` does not: there is no such address, which is the whole
    /// point of it. See [`StunSdpMismatch::corroborates`], which needs a
    /// different piece of evidence for that shape.
    pub fn names_a_reachable_address(self) -> bool {
        matches!(self, Self::Ignored | Self::RelayIgnored)
    }
}

/// The STUN evidence behind [`MediaDiagnosis::private_media_address`].
///
/// # Why this is not a finding of its own
///
/// It describes the same condition `private_media_address` already raises — an
/// SDP `c=` line naming an address the far end cannot route to — and it is
/// only ever populated on a diagnosis where that flag is set. Reported as a
/// second, parallel finding it would read as two independent problems about
/// one address; carried here it does the one thing it is actually good for,
/// which is to move the reader from "check whether something downstream
/// rewrites this" to "nothing rewrote it, and here is the proof".
///
/// It also WIDENS the flag. `private_media_address` on its own needs an
/// observed stream aimed at a public peer, so a call whose media never arrived
/// at all — the worst case, and the one most likely to be captured — had no
/// peer to test and stayed silent. A mapped or relayed address in public space
/// settles the same question without needing a stream, so this evidence raises
/// the flag on its own when it names one. See
/// [`StunSdpMismatchReason::names_a_reachable_address`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StunSdpMismatch {
    /// The socket the client's STUN request left from, `ip:port`.
    pub client: String,
    /// The public address STUN reported back, when a response arrived. `None`
    /// is the [`StunSdpMismatchReason::Unanswered`] case, where there is no
    /// such address to name — the whole point of that reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped_address: Option<String>,
    /// The relayed transport address a TURN server allocated this client, when
    /// one was allocated. Present on the
    /// [`StunSdpMismatchReason::RelayIgnored`] shape, and the whole of its
    /// evidence: the address existed, was reachable, and was not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relayed_address: Option<String>,
    /// The STUN or TURN server the request went to, `ip:port`.
    ///
    /// Evidence in its own right — it names the box to check, and a reader
    /// chasing silence needs it — and load-bearing for
    /// [`Self::corroborates`]: a probe sent to a server on the public internet
    /// is proof this client's traffic leaves the LAN, and a probe to a server
    /// on the LAN is not.
    pub server: String,
    /// The unroutable address the dialog then advertised in its SDP.
    pub advertised: String,
    /// How many requests the client sent for that transaction. Greater than
    /// one is a retransmission, which proves the earlier attempts drew nothing.
    pub request_count: u32,
    /// Which of the three shapes this is.
    pub reason: StunSdpMismatchReason,
    /// Seconds between the STUN evidence and the start of this dialog —
    /// negative when the probe came first, which is the ordinary case.
    ///
    /// `None` when either time is unknown. Present because the correlation
    /// between the two is by client IP alone: nothing in a Binding Request
    /// names a Call-ID, so a probe from the right address matches this dialog
    /// whether it happened during setup or an hour earlier. Within a call the
    /// finding is an OBSERVATION; far outside it, the same finding is an
    /// INFERENCE that the client's NAT-discovery failure persisted — still
    /// usually true, and not the same claim. Reporting the distance is what
    /// lets a reader tell which one they are being handed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_offset_secs: Option<i64>,
}

/// How far STUN evidence may sit from a dialog before the report stops
/// presenting the correlation as if it had been observed within the call.
///
/// Two minutes: a client's NAT discovery for a call runs at registration or at
/// setup, so evidence inside that window belongs to this call's establishment.
/// Beyond it the probe is a separate event, and the finding rests on the
/// failure having persisted rather than on anything seen during the call.
pub const STUN_CORRELATION_WINDOW_SECS: i64 = 120;

impl StunSdpMismatch {
    /// Whether this evidence is enough, ON ITS OWN, to raise
    /// [`MediaDiagnosis::private_media_address`] — with no observed stream to
    /// prove the peer is on the public internet.
    ///
    /// It matters because the stream-based test cannot fire on the worst case
    /// there is: a call whose media never arrived has no peer to examine, so
    /// the finding that explains it would go unstated exactly when it is most
    /// needed.
    ///
    /// Two shapes qualify, for one reason each:
    ///
    /// * A mapped or relayed address in PUBLIC space. A NAT told this client
    ///   what the internet sees it as, so its private `c=` line cannot be
    ///   reached from the far end. Nothing else is needed.
    /// * Silence — but only from a server that is itself public. A probe that
    ///   left the LAN and drew nothing says the client was trying to reach the
    ///   internet and could not. A probe to a STUN server ON the LAN says no
    ///   such thing, and raising a fault on it would fire on every LAN-only
    ///   capture, which is the false positive `private_media_address` was
    ///   written to avoid in the first place.
    pub fn corroborates(&self) -> bool {
        if self.reason.names_a_reachable_address() {
            return true;
        }
        self.server
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|s| !is_unroutable_publicly(s.ip()))
    }

    /// The disclosure sentence to append when the evidence sits outside
    /// [`STUN_CORRELATION_WINDOW_SECS`], or `None` when it does not.
    ///
    /// `None` is the common case and must stay silent: a probe seen during
    /// setup needs no caveat, and one printed anyway would train readers to
    /// skip the caveat that matters.
    pub fn correlation_caveat(&self) -> Option<String> {
        let offset = self.observed_offset_secs?;
        if offset.abs() <= STUN_CORRELATION_WINDOW_SECS {
            return None;
        }
        let mins = offset.abs() / 60;
        let when = if offset < 0 { "before" } else { "after" };
        Some(format!(
            "the STUN evidence was seen {mins} minute(s) {when} this call, not during it, \
             and is matched to the dialog by the client's IP address alone — so this \
             attributes a NAT-discovery failure that persisted, rather than one observed \
             during setup. Confirm the address names the same host if the captures came \
             from different files or networks."
        ))
    }
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
    /// True when the dialog advertised a PRIVATE media address to a peer that
    /// is not itself private — an RFC 1918 / RFC 4193 / link-local `c=` line
    /// offered across the public internet, which the peer cannot route back to.
    ///
    /// A warning and not an error: it is perfectly correct inside one LAN, and
    /// correct behind an SBC or ALG that rewrites the SDP downstream. It is
    /// wrong when nothing rewrites it, and that case is a silent one — the call
    /// signals cleanly, answers 200, and carries audio in one direction only.
    pub private_media_address: bool,
    /// The STUN evidence behind [`Self::private_media_address`], when the run
    /// held any. Never populated without that flag also being set — see
    /// [`StunSdpMismatch`] for why this is evidence rather than a second
    /// finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_sdp_mismatch: Option<StunSdpMismatch>,
    /// The TURN relay this dialog's media crossed, when it crossed one.
    ///
    /// Context, not a finding — nothing here is wrong. It answers "where did
    /// this call's audio actually go", which for a relayed call previously had
    /// no answer anywhere: the frames are unwrapped and the RTP inside them
    /// reaches the stream store, but the stream that comes out is addressed
    /// phone-to-relay, and nothing said the far socket was a relay, which
    /// address it relayed to, or that its allocation was about to lapse.
    ///
    /// The last of those is why it earns a place beside the findings rather
    /// than in a table somewhere: [`crate::stun::RelayPath::lapsed`] is the
    /// capture-level lapsed-allocation finding, narrowed to THIS call's media.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_relay: Option<crate::stun::RelayPath>,
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
    /// so `[diagnosis] late_media_ms` would have been honored on some
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
/// signaling-only capture — a proxy tap that never sees media, a HEP feed,
/// `--no-rtp` — *every* answered call has zero RTP, and a `no_media` flag
/// computed without this would describe where the capture was taken rather
/// than what happened on the call. Measured on one signaling-only corpus
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
    /// When this dialog started, when it came from one.
    ///
    /// Carried solely so a finding can say how far its evidence sits from the
    /// call it is attributed to. STUN evidence is process-global and is
    /// correlated to a dialog by the client's IP — not by time and not by any
    /// identifier the two share — so a probe seen an hour before the call
    /// matches exactly as strongly as one seen during setup. That is usually
    /// right, because a NAT-discovery failure is a persistent condition rather
    /// than a per-call event, but it is an INFERENCE and the report must not
    /// present it as an observation of this call.
    dialog_start: Option<chrono::DateTime<chrono::Utc>>,
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
            dialog_start: None,
        }
    }
}

impl MediaContext {
    /// Read a dialog's negotiation, paired with what the capture could see.
    pub fn for_dialog(dialog: &SipDialog, capture: CaptureMedia) -> Self {
        let mut ctx = MediaContext {
            capture,
            established: matches!(dialog.final_status_code(), Some(200..=299)),
            dialog_start: dialog.messages.first().map(|m| m.timestamp),
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

/// Where one stream's media actually came from, judged against what its dialog
/// advertised.
///
/// This is the per-stream half of [`MediaDiagnosis::nat_mismatch`], split out
/// so a surface that renders streams one at a time can ask the question
/// directly instead of re-deriving it. [`diagnose_media`] reaches its verdict
/// through this same function, which is the point: the TUI stream list and the
/// hint text cannot disagree about a call, because only one of them decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaOrigin {
    /// No SDP in the dialog advertised a connection address, so there is
    /// nothing to compare against and no verdict to reach. NOT the same as
    /// "fine" — it is "unknowable from this capture".
    Unadvertised,
    /// The source address is one the dialog advertised.
    AsAdvertised,
    /// No exchange in the dialog advertised this source address. This is the
    /// evidence behind `nat_mismatch`.
    Rewritten,
}

/// Whether an address is one nothing on the public internet can route back to:
/// RFC 1918 v4, RFC 4193 unique-local v6, link-local, or loopback.
///
/// Carrier-grade NAT space (RFC 6598, `100.64.0.0/10`) is deliberately NOT
/// here. It is routable within the carrier that assigned it, an endpoint given
/// one is often reachable from its own SBC, and flagging it would fire on every
/// call from a large share of mobile networks — a warning that cries wolf on
/// working calls is one operators learn to skip.
fn is_unroutable_publicly(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            // `is_unique_local` and `is_unicast_link_local` are unstable, so the
            // prefixes are tested directly: fc00::/7 and fe80::/10.
            let seg = v6.segments();
            v6.is_loopback() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Judge one stream's source address against the dialog's advertised set.
///
/// Addresses only, never ports, matching [`diagnose_media`] exactly — and the
/// reasoning is recorded there rather than repeated: NAT and RTP proxies
/// rewrite the port on a large share of ordinary calls without breaking
/// anything, so a port comparison reports working calls as faults.
pub fn media_origin(src: IpAddr, media: &MediaContext) -> MediaOrigin {
    if media.advertised.is_empty() {
        return MediaOrigin::Unadvertised;
    }
    if media.advertised.contains(&src) {
        MediaOrigin::AsAdvertised
    } else {
        MediaOrigin::Rewritten
    }
}

/// The endpoint a dialog advertised for media, as a label a reader can compare
/// against a stream's actual source.
///
/// `None` when the dialog advertised nothing. When it advertised several, the
/// one reported is the first — the same choice `diagnose_media` makes when it
/// names the offered endpoint in a hint.
pub fn advertised_media_label(media: &MediaContext) -> Option<String> {
    let first = media.advertised.first()?;
    Some(advertised_endpoint_label(media, *first))
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
        // Before the return, not after it. A call with no streams at all is
        // the worst case there is, and the private-address finding — with the
        // STUN evidence that can settle it without any stream to look at — is
        // exactly what explains one. Leaving it downstream of this return kept
        // it silent precisely when it mattered most.
        apply_private_media_address(&mut diag, dialog_streams, media);
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
        // a threshold threaded to some of those is one honored on some
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
            // Through `media_origin`, not a second `contains` call: the TUI
            // stream list renders the same judgement per row, and two copies of
            // this test are how the surfaces start disagreeing about one call.
            if media_origin(actual_src, media) != MediaOrigin::Rewritten {
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

    apply_private_media_address(&mut diag, dialog_streams, media);
    apply_media_relay(&mut diag, dialog_streams);

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

/// Attribute this dialog's media to the TURN relay that carried it, when one
/// did.
///
/// # Why this is here rather than on the stream
///
/// The stream store already holds everything the join needs — an SSRC and the
/// socket pair the packets were seen between — and it holds it for a relayed
/// stream exactly as for a direct one, because the pipeline unwraps
/// ChannelData before the stream is ever created. What it cannot hold is the
/// fact that the far socket was a RELAY, which lives in the STUN store on the
/// allocation. This is the one place both are in scope.
///
/// The first match wins and the rest are not searched: a dialog's streams
/// cross one relay in every real deployment, and listing "the relay for stream
/// 3" would invite a reader to look for a per-stream field that does not
/// exist. When a dialog somehow spanned two, the allocation table under
/// `--stun` holds both.
///
/// # Side effects
///
/// Reads the process-global STUN store ([`crate::stun::relay_path_for`]),
/// which answers from a relaxed atomic with no lock on any capture that never
/// saw a TURN allocation granted — that is, on every capture without a relay
/// in it.
fn apply_media_relay(diag: &mut MediaDiagnosis, dialog_streams: &[&RtpStream]) {
    let Some(path) = dialog_streams
        .iter()
        .find_map(|s| crate::stun::relay_path_for(s.key.src, s.key.dst, s.key.ssrc))
    else {
        return;
    };
    // Stated only when it is ACTIONABLE. A relay that is doing its job needs
    // no hint — the `media_relay` field says where the audio went, and a
    // sentence repeating it on every healthy relayed call would be noise in
    // the one list an operator reads for problems. A relay whose allocation
    // lapsed under this call is the opposite: it is the reason the audio
    // stopped, and nothing else in the dialog says so.
    if path.lapsed {
        let relay = path
            .relayed_address
            .map(|a| a.to_string())
            .unwrap_or_else(|| path.server.to_string());
        diag.hints.push(format!(
            "This call's media crossed TURN relay {relay} on channel 0x{:04x}, and that \
             allocation was still carrying traffic after the lifetime the server last \
             granted it had run out, with no Refresh seen. A relay tears an allocation \
             down when its lifetime lapses and the audio stops with it, mid-call, with no \
             SIP message to say why.",
            path.channel
        ));
    }
    diag.media_relay = Some(path);
}

/// Raise [`MediaDiagnosis::private_media_address`], with the STUN evidence for
/// it when the run holds any.
///
/// A function rather than an inline block because [`diagnose_media`] returns
/// EARLY for a dialog with no streams, and that early return is the worst case
/// there is: a call whose media never arrived is exactly the one this explains.
/// Leaving the check downstream of that return meant the finding was silent
/// precisely when it was most needed.
fn apply_private_media_address(
    diag: &mut MediaDiagnosis,
    dialog_streams: &[&RtpStream],
    media: &MediaContext,
) {
    // A private `c=` address offered to a peer that is not itself private.
    //
    // Warning, not error: inside one LAN this is correct, and behind an SBC or
    // ALG that rewrites the SDP downstream it is also correct. It is wrong when
    // nothing rewrites it, and that failure is silent — the call signals
    // cleanly, answers 200, and carries audio one way. Seen in the field as a
    // private `c=` line offered to a public peer, with hundreds of RTP packets
    // leaving and none returning.
    //
    // The peer check is what keeps this quiet on a LAN-only capture: a private
    // address advertised to another private address routes fine.
    //
    // STUN is the second half of the same question, and is folded in here
    // rather than raised beside it. A separate `stun_sdp_mismatch` finding
    // would describe this exact condition a second time, and one capture
    // would then report two independent-looking problems about one address.
    // What STUN adds is CONFIDENCE, and one case of coverage: it can prove
    // the client's traffic reaches the internet without needing an observed
    // stream, which is what lets this fire on a call whose media never
    // arrived at all.
    let peer_is_public = dialog_streams
        .iter()
        .any(|s| !is_unroutable_publicly(s.key.dst.ip()));
    if let Some(private) = media
        .advertised
        .iter()
        .find(|a| is_unroutable_publicly(**a))
        .copied()
    {
        let stun = stun_sdp_mismatch(media);
        // Either half raises the flag: a peer observed on public space (this
        // dialog's own packets), or STUN naming a routable address this client
        // was handed and did not use (evidence from outside the dialog, which
        // is why it carries a temporal caveat). Silence alone raises nothing —
        // see `names_a_reachable_address`.
        let stun_confirms = stun.as_ref().is_some_and(StunSdpMismatch::corroborates);
        if peer_is_public || stun_confirms {
            diag.private_media_address = true;
            let offered = advertised_endpoint_label(media, private);
            match &stun {
                // Nothing corroborates it: the original WARNING, which names
                // the two situations in which this is correct and asks the
                // reader to check which one they are in.
                None => diag.hints.push(format!(
                    "SDP offered the private media address {offered} to a peer on the \
                     public internet, which cannot route back to it. This is correct \
                     only if something downstream rewrites the SDP (an SBC, an ALG, \
                     or a media proxy); if nothing does, the far end sends audio to \
                     an address that does not exist and the call is one-way while \
                     signaling looks healthy."
                )),
                // Corroborated: the same condition, stated as a cause rather
                // than as something to check.
                Some(finding) => {
                    diag.hints.push(stun_hint(finding, &offered));
                    if let (Some(hint), Some(caveat)) =
                        (diag.hints.last_mut(), finding.correlation_caveat())
                    {
                        hint.push_str(" Note: ");
                        hint.push_str(&caveat);
                    }
                }
            }
            // Attached only where the flag was raised, so the evidence can
            // never stand on its own as a finding.
            diag.stun_sdp_mismatch = stun;
        }
    }
}

/// The STUN evidence about the address a dialog advertised, when there is any
/// and when it amounts to a fault.
///
/// # What is compared, and why by IP
///
/// A transaction's `client` is the source socket a request left from;
/// `media.advertised()` is what the dialog put in its `c=`/`m=` lines. A phone
/// probing from `192.168.10.50:5060` and then writing `192.168.10.50` into its
/// SDP is one host, so the IP is the join key. The PORT is not: a phone probes
/// from its signaling port and receives media on a different one by design, so
/// requiring the ports to agree would suppress every real finding. The port is
/// carried into the report as evidence instead.
///
/// # What is deliberately NOT flagged
///
/// A transaction whose mapped OR relayed address IS the advertised one. That
/// is a client on a public address, or behind a full-cone NAT that STUN saw
/// through, or one correctly advertising the relay it reserved — all doing
/// exactly the right thing. It is the false positive that would make this
/// worthless, because it is the common case on any capture from a network that
/// does not NAT.
///
/// # Side effects
///
/// Reads the process-global STUN store ([`crate::stun::transactions_from`]),
/// and only for an advertised address that is itself unroutable — the cheap
/// half of the test is made first, so an ordinary healthy dialog never touches
/// the store's lock. The targeted read matters: this runs once per dialog, and
/// on a LAN-only capture EVERY dialog advertises a private address, so copying
/// the whole transaction table here would make the finding quadratic in the
/// size of the capture.
pub fn stun_sdp_mismatch(media: &MediaContext) -> Option<StunSdpMismatch> {
    for advertised in &media.advertised {
        // Only an unroutable advertised address can be a fault: a client that
        // advertised a public one has nothing to answer for, whatever STUN
        // said. Tested BEFORE the store is touched, so an ordinary healthy
        // dialog costs one range check.
        if !is_unroutable_publicly(*advertised) {
            continue;
        }
        // Only this host's transactions, fetched with one lock and no whole-
        // table copy — see `stun::transactions_from`. Usually empty, and on a
        // capture with no STUN at all this does not even take the lock.
        let matched = crate::stun::transactions_from(*advertised);
        if matched.is_empty() {
            continue;
        }
        let probes = || matched.iter();
        // The false-positive guard, applied before any of the findings.
        if probes().any(|t| {
            t.mapped_address.is_some_and(|m| m.ip() == *advertised)
                || t.relayed_address.is_some_and(|r| r.ip() == *advertised)
        }) {
            continue;
        }

        // The stronger finding first: the client was handed a reachable
        // address and advertised the unreachable one regardless.
        if let Some(tx) = probes().find(|t| {
            t.mapped_address
                .is_some_and(|m| !is_unroutable_publicly(m.ip()))
        }) {
            return Some(mismatch(
                tx,
                *advertised,
                StunSdpMismatchReason::Ignored,
                media,
            ));
        }

        // Then the relay: an Allocate succeeded, the server handed back a
        // routable relayed address, and the SDP named a private one anyway.
        // Checked after the reflexive case only because that one is the older
        // and more common shape, not because it is the less serious.
        if let Some(tx) = probes().find(|t| {
            t.relayed_address
                .is_some_and(|r| !is_unroutable_publicly(r.ip()))
        }) {
            return Some(mismatch(
                tx,
                *advertised,
                StunSdpMismatchReason::RelayIgnored,
                media,
            ));
        }

        // Otherwise: nothing ever answered, so there was no public address to
        // advertise. Prefer the transaction that had to retransmit, because
        // the retransmission is the part that proves the silence.
        if let Some(tx) = probes()
            .filter(|t| t.is_unanswered() && t.silence_is_a_fault())
            .max_by_key(|t| t.request_count)
        {
            return Some(mismatch(
                tx,
                *advertised,
                StunSdpMismatchReason::Unanswered,
                media,
            ));
        }
    }
    None
}

/// Build one [`StunSdpMismatch`] from the transaction that evidences it.
///
/// One constructor for all three reasons, so the evidence fields cannot drift
/// apart between them — the `Unanswered` shape carries no address by
/// construction rather than by each call site remembering to omit it.
fn mismatch(
    tx: &crate::stun::StunTransaction,
    advertised: IpAddr,
    reason: StunSdpMismatchReason,
    media: &MediaContext,
) -> StunSdpMismatch {
    let names_address = reason.names_a_reachable_address();
    StunSdpMismatch {
        client: tx.client.to_string(),
        mapped_address: names_address
            .then(|| tx.mapped_address.map(|m| m.to_string()))
            .flatten(),
        relayed_address: names_address
            .then(|| tx.relayed_address.map(|r| r.to_string()))
            .flatten(),
        server: tx.server.to_string(),
        advertised: advertised.to_string(),
        request_count: tx.request_count,
        reason,
        observed_offset_secs: offset_from_dialog(media, tx),
    }
}

/// Seconds from the start of `media`'s dialog to the STUN transaction's first
/// request. Negative when the probe preceded the call, which is ordinary.
///
/// `None` when either end is unknown — a bare [`MediaContext`] built from a
/// session has no dialog, and reporting a distance from an unknown point would
/// be worse than reporting none.
fn offset_from_dialog(media: &MediaContext, tx: &crate::stun::StunTransaction) -> Option<i64> {
    let start = media.dialog_start?;
    Some((tx.first_request - start).num_seconds())
}

/// The hint for a corroborated private media address, per reason.
///
/// `offered` is the endpoint label the dialog advertised, rendered the same way
/// the uncorroborated hint renders it so the two read as one finding.
fn stun_hint(finding: &StunSdpMismatch, offered: &str) -> String {
    match finding.reason {
        StunSdpMismatchReason::Ignored => {
            let mapped = finding.mapped_address.as_deref().unwrap_or("?");
            format!(
                "STUN told {} its public address is {mapped}, and this dialog advertised \
                 {offered} anyway — an address the far end cannot route to, so media aimed \
                 at it is discarded before it arrives. The client HAD the reachable answer \
                 and did not use it, so look at the phone's NAT settings rather than at \
                 the network.",
                finding.client
            )
        }
        StunSdpMismatchReason::RelayIgnored => {
            let relayed = finding.relayed_address.as_deref().unwrap_or("?");
            format!(
                "A TURN server allocated {} the relayed address {relayed}, and this dialog \
                 advertised {offered} anyway — the relay was set up and then not used, so \
                 media aimed at the advertised address is discarded before it arrives.",
                finding.client
            )
        }
        StunSdpMismatchReason::Unanswered => {
            let retransmitted = if finding.request_count > 1 {
                format!(
                    " ({} requests, retransmitted, which by itself proves the first went \
                     unanswered)",
                    finding.request_count
                )
            } else {
                String::new()
            };
            format!(
                "{}'s STUN request drew no response{retransmitted}, so it never learned a \
                 public address and this dialog advertised {offered} — an address the far \
                 end cannot route to, so media aimed at it is discarded before it arrives. \
                 Silence rather than a refusal points at something in the path dropping \
                 the packets, not at the server ({}).",
                finding.client, finding.server
            )
        }
    }
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
                 was slow to send, or the media path wasn't ready when signaling \
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
    /// Symmetric RTP is the correct behavior; printing "advertised 16384 and
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

    /// Every surface reaches the NAT verdict through ONE function.
    ///
    /// `diagnose_media` sets `nat_mismatch`, and the TUI stream list renders a
    /// per-row column; both call `media_origin`. This asserts they agree on
    /// the same dialog rather than merely each looking correct in isolation —
    /// two independently-correct implementations of the same test are exactly
    /// how `DH1` describes the surfaces drifting apart.
    #[test]
    fn the_per_stream_origin_and_the_dialog_verdict_cannot_disagree() {
        let dialog = two_party_dialog("192.168.1.100", 16384, "203.0.113.9", 16386);
        let ctx = MediaContext::for_dialog(&dialog, CaptureMedia::Observed);

        // A rewritten source: no SDP advertised 198.51.100.7.
        let rewritten = make_stream([198, 51, 100, 7], [203, 0, 113, 9], 41002, 16386);
        // An advertised source, on a port nobody advertised. The port is NOT
        // the test, so this must not read as rewritten.
        let odd_port = make_stream([192, 168, 1, 100], [203, 0, 113, 9], 59999, 16386);

        assert_eq!(
            media_origin(rewritten.key.src.ip(), &ctx),
            MediaOrigin::Rewritten
        );
        assert_eq!(
            media_origin(odd_port.key.src.ip(), &ctx),
            MediaOrigin::AsAdvertised,
            "a rewritten PORT on an advertised address is not a NAT mismatch"
        );

        // The dialog verdict follows the per-stream one, both ways round.
        let only_rewritten: Vec<&RtpStream> = vec![&rewritten];
        assert!(diagnose_media(&only_rewritten, &ctx).nat_mismatch);

        let only_advertised: Vec<&RtpStream> = vec![&odd_port];
        assert!(
            !diagnose_media(&only_advertised, &ctx).nat_mismatch,
            "the verdict disagreed with media_origin on the same stream"
        );
    }

    /// A dialog that advertised nothing is UNKNOWABLE, not clean. The column
    /// renders that distinction, so the enum has to carry it.
    #[test]
    fn a_dialog_that_advertised_nothing_is_not_reported_as_matching() {
        let ctx = MediaContext::default();
        let s = make_stream([198, 51, 100, 7], [203, 0, 113, 9], 41002, 16386);
        assert_eq!(
            media_origin(s.key.src.ip(), &ctx),
            MediaOrigin::Unadvertised
        );
        assert_eq!(advertised_media_label(&ctx), None);
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
            input_origin: None,
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

/// STUN evidence folded into the private-media-address finding.
///
/// Every test here writes the PROCESS-GLOBAL STUN store, so each one resets it
/// first and they are serialized against each other on the `stun_store` key —
/// the same discipline the tracker's own tests keep.
#[cfg(test)]
mod stun_sdp_mismatch_tests {
    use super::*;
    use crate::sip::sdp::{SdpConnection, SdpDirection, SdpMedia, SdpSession};

    /// The transaction ID the fixtures share. Its value is arbitrary; what
    /// matters is that a request and its response carry the same one.
    const TXID: [u8; 12] = [
        0xc5, 0x3a, 0x26, 0xa8, 0x09, 0x5c, 0x16, 0x7e, 0xe1, 0x32, 0x07, 0x00,
    ];

    /// Build a STUN message on the wire and parse it back, so these tests
    /// exercise the same decoder the pipeline does rather than a struct
    /// literal that could drift from it.
    fn wire(msg_type: u16, attrs: &[(u16, Vec<u8>)]) -> crate::stun::StunMessage {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&msg_type.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&crate::stun::MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&TXID);
        m.extend_from_slice(&body);
        crate::stun::parse(&m).expect("the fixture must be well-formed STUN")
    }

    /// An XOR'd IPv4 address attribute value.
    fn xor_v4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let cookie = crate::stun::MAGIC_COOKIE.to_be_bytes();
        let mut v = vec![0, 0x01];
        v.extend_from_slice(&(port ^ ((crate::stun::MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
        for (i, o) in ip.iter().enumerate() {
            v.push(o ^ cookie[i]);
        }
        v
    }

    fn stun_request() -> crate::stun::StunMessage {
        wire(0x0001, &[(0x8022, b"traversal-2.1.0 45".to_vec())])
    }

    fn stun_success(ip: [u8; 4], port: u16) -> crate::stun::StunMessage {
        wire(0x0101, &[(0x0020, xor_v4(ip, port))])
    }

    fn allocate_request() -> crate::stun::StunMessage {
        wire(0x0003, &[(0x0019, vec![17, 0, 0, 0])])
    }

    fn allocate_success(ip: [u8; 4], port: u16) -> crate::stun::StunMessage {
        wire(
            0x0103,
            &[
                (0x0016, xor_v4(ip, port)),
                (0x000D, 600u32.to_be_bytes().to_vec()),
            ],
        )
    }

    /// Record one STUN packet against the global store.
    fn record(msg: &crate::stun::StunMessage, src: &str, dst: &str, ms: i64) {
        crate::stun::note_message(
            msg,
            src.parse().expect("valid source"),
            dst.parse().expect("valid destination"),
            chrono::DateTime::from_timestamp_millis(1_700_000_000_000 + ms).expect("valid"),
        );
    }

    fn sdp(addr: &str) -> SdpSession {
        SdpSession {
            origin: None,
            session_name: None,
            connection: Some(SdpConnection {
                addr: addr.to_string(),
            }),
            media: vec![SdpMedia {
                media_type: "audio".to_string(),
                port: 40000,
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

    /// A dialog that advertised exactly `addr` for media, and nothing else.
    fn advertising(addr: &str) -> MediaContext {
        MediaContext::from_session(&sdp(addr), CaptureMedia::Absent)
    }

    /// As [`advertising`], for a dialog that started `ms` after the same epoch
    /// `record` uses — so a test can place the STUN evidence a chosen distance
    /// from the call.
    fn advertising_at(addr: &str, ms: i64) -> MediaContext {
        let mut ctx = advertising(addr);
        ctx.dialog_start = chrono::DateTime::from_timestamp_millis(1_700_000_000_000 + ms);
        ctx
    }

    /// The case in the motivating capture: the phone's probe drew nothing, so
    /// it never learned a public address and its SDP carries the LAN one. The
    /// retransmission is named because it is the proof.
    ///
    /// No stream is passed, which is the point: `private_media_address` alone
    /// needs an observed public peer, and a call whose media never arrived has
    /// none. The STUN evidence raises the flag anyway.
    #[test]
    #[serial_test::serial(stun_store)]
    fn an_unanswered_probe_explains_a_private_sdp_address() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            500,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        let finding = diag
            .stun_sdp_mismatch
            .as_ref()
            .expect("an unanswered probe against a private SDP address is the finding");
        assert_eq!(finding.reason, StunSdpMismatchReason::Unanswered);
        assert_eq!(finding.client, "192.168.10.50:5060");
        assert_eq!(finding.server, "198.51.100.20:3478");
        assert_eq!(finding.advertised, "192.168.10.50");
        assert_eq!(finding.request_count, 2);
        assert!(finding.mapped_address.is_none());
        assert!(
            diag.private_media_address,
            "the evidence is evidence FOR that flag and must raise it"
        );
        assert!(
            diag.hints.iter().any(|h| h.contains("no response")
                && h.contains("192.168.10.50")
                && h.contains("retransmitted")),
            "the hint must state the silence and the retransmit: {:?}",
            diag.hints
        );
        crate::stun::reset();
    }

    /// STUN answered with a routable address and the SDP advertised the LAN
    /// one regardless. Both addresses belong in the hint: one is what the far
    /// end was told, the other is what it should have been told.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_mapped_address_disagreeing_with_the_sdp_is_reported() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );
        record(
            &stun_success([203, 0, 113, 5], 12262),
            "198.51.100.20:3478",
            "192.168.10.50:5060",
            7,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        let finding = diag
            .stun_sdp_mismatch
            .as_ref()
            .expect("a known public address against a private SDP address is the finding");
        assert_eq!(finding.reason, StunSdpMismatchReason::Ignored);
        assert_eq!(finding.mapped_address.as_deref(), Some("203.0.113.5:12262"));
        assert!(diag.private_media_address);
        assert!(
            diag.hints
                .iter()
                .any(|h| h.contains("203.0.113.5:12262") && h.contains("192.168.10.50")),
            "the hint must carry both addresses: {:?}",
            diag.hints
        );
        crate::stun::reset();
    }

    /// The relay case, and the reason XOR-RELAYED-ADDRESS is decoded at all:
    /// the client allocated a relayed address on a TURN server and then
    /// advertised its LAN address anyway. Same fault as the reflexive one, and
    /// caught by the same finding rather than by a second, parallel one.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_relayed_address_the_sdp_ignored_is_the_same_finding() {
        crate::stun::reset();
        record(
            &allocate_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );
        record(
            &allocate_success([198, 51, 100, 77], 49160),
            "198.51.100.20:3478",
            "192.168.10.50:5060",
            12,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        let finding = diag
            .stun_sdp_mismatch
            .as_ref()
            .expect("an allocated relay against a private SDP address is the finding");
        assert_eq!(finding.reason, StunSdpMismatchReason::RelayIgnored);
        assert_eq!(
            finding.relayed_address.as_deref(),
            Some("198.51.100.77:49160")
        );
        assert!(
            diag.hints
                .iter()
                .any(|h| h.contains("TURN") && h.contains("198.51.100.77:49160")),
            "the hint must name the relay it allocated: {:?}",
            diag.hints
        );
        crate::stun::reset();
    }

    /// The false-positive guard. STUN reported the address the SDP then
    /// advertised, so the client did exactly the right thing — and this is the
    /// common shape on any capture taken inside a network that does not NAT,
    /// which is what would make a finding here worthless.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_mapped_address_matching_the_sdp_reports_nothing() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );
        record(
            &stun_success([192, 168, 10, 50], 16384),
            "198.51.100.20:3478",
            "192.168.10.50:5060",
            7,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        assert!(
            diag.stun_sdp_mismatch.is_none(),
            "STUN agreed with the SDP; there is no fault to report: {:?}",
            diag.stun_sdp_mismatch
        );
        assert!(!diag.private_media_address);
        crate::stun::reset();
    }

    /// A client that advertised the address its RELAY allocated is doing
    /// exactly the right thing. A private TURN server is a real deployment,
    /// and flagging it would be the false positive that makes the whole
    /// finding worthless on any capture holding TURN.
    #[test]
    #[serial_test::serial(stun_store)]
    fn advertising_the_relayed_address_is_not_a_finding() {
        crate::stun::reset();
        record(
            &allocate_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );
        record(
            &allocate_success([192, 168, 10, 50], 49160),
            "198.51.100.20:3478",
            "192.168.10.50:5060",
            12,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        assert!(
            diag.stun_sdp_mismatch.is_none(),
            "the SDP names the address the relay allocated: {:?}",
            diag.stun_sdp_mismatch
        );
        crate::stun::reset();
    }

    /// A client that advertised a ROUTABLE address has nothing to answer for,
    /// whatever became of its probe.
    #[test]
    #[serial_test::serial(stun_store)]
    fn an_unanswered_probe_from_a_public_address_reports_nothing() {
        crate::stun::reset();
        record(&stun_request(), "203.0.113.5:5060", "198.51.100.20:3478", 0);

        let diag = diagnose_media(&[], &advertising("203.0.113.5"));
        assert!(diag.stun_sdp_mismatch.is_none());
        assert!(diag.hints.is_empty(), "{:?}", diag.hints);
        crate::stun::reset();
    }

    /// A probe from some OTHER host says nothing about this dialog: the join
    /// key is the client's own address, not "some STUN failed somewhere".
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_probe_from_a_different_host_is_not_attributed_to_this_dialog() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.99:5060",
            "198.51.100.20:3478",
            0,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        assert!(diag.stun_sdp_mismatch.is_none());
        assert!(diag.hints.is_empty(), "{:?}", diag.hints);
        crate::stun::reset();
    }

    /// Silence from a STUN server ON the LAN proves nothing about whether this
    /// client's traffic reaches the internet, so it must not raise a fault on
    /// its own. This is the LAN-only capture `private_media_address`
    /// deliberately stays quiet about, and the STUN half must not undo that.
    #[test]
    #[serial_test::serial(stun_store)]
    fn silence_from_a_lan_stun_server_raises_nothing_on_its_own() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "192.168.10.1:3478",
            0,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        assert!(
            !diag.private_media_address,
            "a LAN probe to a LAN server is not evidence of anything: {:?}",
            diag.hints
        );
        assert!(diag.stun_sdp_mismatch.is_none());
        crate::stun::reset();
    }

    /// A capture with no STUN in it must diagnose exactly as it did before
    /// this evidence existed — no field, no hint, not even a lock taken.
    #[test]
    #[serial_test::serial(stun_store)]
    fn no_stun_in_the_capture_produces_no_finding() {
        crate::stun::reset();
        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        assert!(diag.stun_sdp_mismatch.is_none());
        assert!(diag.hints.is_empty(), "{:?}", diag.hints);
        assert!(stun_sdp_mismatch(&advertising("192.168.10.50")).is_none());
    }

    /// A probe seen during call setup needs no qualification, and must not get
    /// one. A caveat printed on every finding is a caveat nobody reads, which
    /// would cost the one case below its only warning.
    #[test]
    #[serial_test::serial(stun_store)]
    fn stun_evidence_from_during_the_call_carries_no_caveat() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );

        let diag = diagnose_media(&[], &advertising_at("192.168.10.50", 3_000));
        let finding = diag.stun_sdp_mismatch.as_ref().expect("the finding stands");
        assert_eq!(finding.observed_offset_secs, Some(-3));
        assert!(
            !diag.hints.iter().any(|h| h.contains("not during it")),
            "evidence from inside the call must not be qualified: {:?}",
            diag.hints
        );
        crate::stun::reset();
    }

    /// The merged-capture case. The switch-side pcap and the phone-side pcap
    /// were taken forty minutes apart, and the finding correlates them by the
    /// client's RFC 1918 address alone. That is still a sound inference — a
    /// NAT-discovery failure persists — but it is an INFERENCE, and reporting
    /// it as though the probe were seen during setup overstates it.
    #[test]
    #[serial_test::serial(stun_store)]
    fn stun_evidence_from_long_before_the_call_is_disclosed_as_such() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );

        // Dialog starts 40 minutes BEFORE the probe.
        let diag = diagnose_media(&[], &advertising_at("192.168.10.50", -2_400_000));
        let finding = diag.stun_sdp_mismatch.as_ref().expect("the finding stands");
        assert_eq!(finding.observed_offset_secs, Some(2_400));
        let hint = diag
            .hints
            .iter()
            .find(|h| h.contains("not during it"))
            .unwrap_or_else(|| panic!("the caveat must appear: {:?}", diag.hints));
        assert!(hint.contains("40 minute(s) after"), "{hint}");
        assert!(
            hint.contains("IP address alone"),
            "the caveat must name how the correlation was made: {hint}"
        );
        crate::stun::reset();
    }

    /// Without a dialog there is no point to measure from, and the report says
    /// nothing rather than measuring from a guess.
    #[test]
    #[serial_test::serial(stun_store)]
    fn no_dialog_time_means_no_offset_and_no_caveat() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        let finding = diag.stun_sdp_mismatch.as_ref().expect("the finding stands");
        assert_eq!(finding.observed_offset_secs, None);
        assert!(!diag.hints.iter().any(|h| h.contains("not during it")));
        crate::stun::reset();
    }

    /// One condition, one hint. The corroborated wording REPLACES the
    /// check-this-yourself wording rather than joining it — two sentences
    /// about one address read as two problems.
    #[test]
    #[serial_test::serial(stun_store)]
    fn the_corroborated_hint_replaces_the_uncorroborated_one() {
        crate::stun::reset();
        record(
            &stun_request(),
            "192.168.10.50:5060",
            "198.51.100.20:3478",
            0,
        );

        let diag = diagnose_media(&[], &advertising("192.168.10.50"));
        assert_eq!(
            diag.hints.len(),
            1,
            "one address, one sentence: {:?}",
            diag.hints
        );
        assert!(
            !diag.hints[0].contains("This is correct only if something downstream rewrites"),
            "{:?}",
            diag.hints
        );
        crate::stun::reset();
    }
}

/// The relay a dialog's media crossed, folded into the media diagnosis.
///
/// These write the PROCESS-GLOBAL STUN store, so each resets it first and they
/// are serialized on the `stun_store` key — the same discipline the tracker's
/// own tests keep.
#[cfg(test)]
mod media_relay_tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use chrono::DateTime;
    use std::net::SocketAddr;

    fn ts(ms: i64) -> DateTime<chrono::Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + ms).expect("valid timestamp")
    }

    fn client() -> SocketAddr {
        "192.0.2.10:50000".parse().expect("valid addr")
    }
    fn server() -> SocketAddr {
        "198.51.100.20:3478".parse().expect("valid addr")
    }

    /// One relayed stream, addressed exactly as the pipeline files it: between
    /// the phone and the RELAY, because that is where the packets were seen.
    fn relayed_stream(ssrc: u32) -> RtpStream {
        let key = StreamKey {
            ssrc,
            src: client(),
            dst: server(),
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
            ssrc,
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, ts(30_000))
    }

    /// An Allocate that succeeded with a 60-second lifetime, then relayed
    /// media on channel `0x4001` at `at_ms`.
    fn relay_carrying(ssrc: u32, at_ms: i64) {
        let alloc_req: Vec<u8> = vec![
            0x00, 0x03, 0x00, 0x00, // Allocate Request
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1,
        ];
        crate::stun::note_message(
            &crate::stun::parse(&alloc_req).expect("parses"),
            client(),
            server(),
            ts(0),
        );
        let alloc_ok: Vec<u8> = vec![
            0x01, 0x03, 0x00, 0x14, // Allocate success, 20 bytes of attributes
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0x00, 0x16,
            0x00, 0x08, // XOR-RELAYED-ADDRESS
            0x00, 0x01, // reserved, family IPv4
            0xe1, 0x1a, // port 49160 (0xc008) ^ 0x2112
            0xe7, 0x21, 0xc0, 0x0f, // 198.51.100.77 ^ 21 12 a4 42
            0x00, 0x0d, 0x00, 0x04, // LIFETIME
            0x00, 0x00, 0x00, 0x3c, // 60 seconds
        ];
        crate::stun::note_message(
            &crate::stun::parse(&alloc_ok).expect("parses"),
            server(),
            client(),
            ts(10),
        );
        // A ChannelData frame on 0x4001 wrapping a 12-byte RTP header.
        let mut frame: Vec<u8> = vec![0x40, 0x01, 0x00, 0x0c, 0x80, 0x00, 0x00, 0x01];
        frame.extend_from_slice(&160u32.to_be_bytes());
        frame.extend_from_slice(&ssrc.to_be_bytes());
        crate::stun::note_channel_data(client(), server(), &frame, ts(at_ms));
    }

    /// The attribution reaching the diagnosis: a relayed call must be able to
    /// say which relay its audio crossed, which it previously could not.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_relayed_dialog_names_the_relay_its_media_crossed() {
        crate::stun::reset();
        relay_carrying(0x1122_3344, 30_000);
        let stream = relayed_stream(0x1122_3344);
        let streams = vec![&stream];
        let diag = diagnose_media(&streams, &MediaContext::default());
        let relay = diag.media_relay.expect("the relay must be named");
        assert_eq!(
            relay.relayed_address.map(|a| a.to_string()).as_deref(),
            Some("198.51.100.77:49160")
        );
        assert_eq!(relay.channel, 0x4001);
        assert!(!relay.lapsed);
        // A healthy relay is not a problem, and must not produce a hint: a
        // sentence on every relayed call is noise in the one list an operator
        // reads for faults.
        assert!(
            !diag.hints.iter().any(|h| h.contains("TURN relay")),
            "a working relay needs no hint: {:?}",
            diag.hints
        );
        crate::stun::reset();
    }

    /// And when the allocation lapsed under the call, the dialog says so —
    /// which is the capture-level finding narrowed to THIS call's audio.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_lapsed_relay_is_stated_on_the_call_it_cut_off() {
        crate::stun::reset();
        relay_carrying(0x1122_3344, 90_000);
        let stream = relayed_stream(0x1122_3344);
        let streams = vec![&stream];
        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(diag.media_relay.as_ref().is_some_and(|r| r.lapsed));
        let hint = diag
            .hints
            .iter()
            .find(|h| h.contains("TURN relay"))
            .unwrap_or_else(|| panic!("the lapse must be stated: {:?}", diag.hints));
        assert!(hint.contains("198.51.100.77:49160"), "{hint}");
        assert!(hint.contains("0x4001"), "{hint}");
        crate::stun::reset();
    }

    /// A capture with no relay in it must gain nothing at all. The quiet-run
    /// guarantee: the field stays absent rather than becoming a null nobody
    /// asked for.
    #[test]
    #[serial_test::serial(stun_store)]
    fn a_dialog_with_no_relay_gains_no_relay_field() {
        crate::stun::reset();
        let stream = relayed_stream(0x1122_3344);
        let streams = vec![&stream];
        let diag = diagnose_media(&streams, &MediaContext::default());
        assert!(diag.media_relay.is_none());
        crate::stun::reset();
    }
}
