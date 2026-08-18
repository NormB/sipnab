// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capture-level problem analysis: one ranked answer to "what is wrong with
//! this file".
//!
//! # What this is not
//!
//! It is **not** a second diagnosis engine. Every fact it reports is already
//! computed somewhere else and always has been (design decision D20 — "VoIP
//! diagnosis is built-in, always computed, no flags needed"):
//!
//! | Fact | Computed by |
//! |---|---|
//! | one-way audio, no media, NAT mismatch, late media, STUN/SDP mismatch | [`crate::rtp::diagnosis::diagnose_media`] |
//! | codec / ptime / payload-type / duration asymmetry | [`crate::rtp::diagnosis::diagnose_asymmetry`] |
//! | final failure, auth loop, retransmits, missing ACK, abandoned, PDD, registration, ICMP | [`crate::sip::diagnosis::diagnose_signaling`] |
//! | unanswered STUN Binding transactions | [`crate::stun::report`] |
//! | ICMP against signaling and against media | [`crate::pipeline::icmp_evidence_report`], [`crate::pipeline::icmp_media_report`] |
//! | frames that decoded to nothing | [`crate::capture::undecodable_report`] |
//! | SIP a port gate discarded | [`crate::pipeline::portrange_skip_report`], [`crate::pipeline::ws_port_skip_report`] |
//!
//! What sipnab lacked was the last step: those findings are scattered one
//! dialog at a time across `--report`, `--json-dialogs`, `--call-report`, the
//! stderr summaries and the MCP tools, and nothing anywhere said *worst
//! first*. An operator handed a 40,000-packet file could ask "is call X
//! broken?" and never "what is broken in here?". This module answers the
//! second question by aggregating and ranking the first.
//!
//! # The honesty rule this module is bound by
//!
//! sipnab's totals describe what it **understood**, never what the wire held
//! (see `undecodable_summary` and `no_sip_guidance` in
//! [`crate::app::batch`]). A ranked problem list is the single easiest place
//! in the tool to break that rule, because "no problems found" is exactly what
//! an unread capture produces.
//!
//! So the incompleteness findings are not a footnote printed beside the list —
//! they are findings *in* the list, at [`Severity::Blind`], which sorts above
//! every call fault. Two things follow structurally rather than by a guard
//! somebody has to remember:
//!
//! * a capture that failed to decode, had SIP discarded by a port gate, or hit
//!   a retention cap can never render as clean, because the list is not empty;
//! * the clean line names its own denominators (frames read, dialogs and
//!   streams examined), so "nothing found" is always readable as "nothing
//!   found *in this much*".

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::rtp::diagnosis::{CaptureMedia, MediaContext};
use crate::rtp::stream_store::StreamStore;
use crate::sip::diagnosis::{AbandonedKind, AuthLoopKind, RegistrationFailureKind};
use crate::sip::dialog::SipDialog;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;

/// How many evidence rows a single finding retains.
///
/// A finding that matched 4,000 calls is a count, not a list; keeping every
/// Call-ID would make the report longer than the capture summary it is meant
/// to replace. The exact occurrence count is always carried separately, and a
/// finding that dropped rows says so — the same discipline
/// [`crate::output::stun_report`] and the ICMP summaries follow, and for the
/// same reason: a silently truncated list understates the problem while
/// looking complete.
pub const EVIDENCE_CAP: usize = 10;

/// How bad a finding is.
///
/// # Why this ordering, and not another
///
/// The ladder is ordered by **what the operator lost**, not by how clever the
/// detection was, and the declaration order below IS the sort order.
///
/// [`Severity::Blind`] sits above every call fault deliberately. It is not a
/// problem with the traffic at all — it is a statement that this analysis is
/// incomplete, and it therefore qualifies every other line and every *absence*
/// of a line. Handing an operator "no problems found" for a capture sipnab
/// read 40% of is a worse outcome than any single broken call, because the
/// second is a fault they can go and fix while the first is a fault they will
/// never look for.
///
/// The remaining three are separated by whether audio survived:
///
/// * [`Severity::Critical`] — **nobody could hear.** Media was negotiated and
///   none arrived, arrived in one direction only, or was addressed somewhere
///   the network says it could not be delivered. This is the fault class the
///   tool exists for and the one the user's question named.
/// * [`Severity::Major`] — the call failed or the media path is provably
///   damaged, but audio was not proven absent: a server-class SIP failure, an
///   unconfirmed dialog, media arriving from an address no SDP named, a NAT
///   probe nothing answered.
/// * [`Severity::Minor`] — measurable degradation, or an outcome that is
///   frequently normal and is listed so it can be ruled out: framing and codec
///   asymmetry, late media, slow ring-back, a `4xx`, an abandoned call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// This analysis is incomplete — sipnab did not read part of the input, so
    /// every count below it is a floor and every zero means "unknown".
    Blind,
    /// Nobody could hear.
    Critical,
    /// The call failed, or the media path is provably damaged.
    Major,
    /// Measurable degradation, or an ordinary outcome listed to be ruled out.
    Minor,
}

impl Severity {
    /// The lowercase tag used in reports, JSON and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blind => "blind",
            Self::Critical => "critical",
            Self::Major => "major",
            Self::Minor => "minor",
        }
    }
}

/// The fixed properties of a finding kind.
///
/// One table rather than four parallel `match` statements over the same 25
/// variants: four matches is four chances for a new kind to be added to three
/// of them, and the missing arm would be a compile error in only the ones
/// somebody remembered to write exhaustively.
#[derive(Debug, Clone, Copy)]
pub struct KindMeta {
    /// Stable machine identifier, used as the JSON `kind` and in tests.
    pub id: &'static str,
    /// How bad it is.
    pub severity: Severity,
    /// Short human title for the report's first column.
    pub title: &'static str,
    /// What one occurrence is — `"call"`, `"frame"`, `"transaction"`. Mixed
    /// units are the reason this is carried rather than assumed: an
    /// undecodable-frame count and a broken-call count are both `occurrences`
    /// and are not the same thing.
    pub unit: &'static str,
    /// One sentence saying what the finding means and what to do about it.
    /// Written once per kind here rather than per occurrence, so the prose
    /// cannot drift between two findings of the same kind.
    pub detail: &'static str,
}

/// Every problem `--analyze` can report.
///
/// Declaration order is the deterministic tie-break for the ranked output (see
/// [`rank`]), and is grouped by severity so the enum reads as the ladder it
/// implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    // ── Blind: what sipnab did not read ──────────────────────────────
    /// Frames that reached the parser and produced nothing.
    UndecodableFrames,
    /// Real SIP discarded because both its ports were outside `--portrange`.
    SipDiscardedByPortRange,
    /// Real SIP-over-WebSocket discarded because its port was outside the
    /// configured WebSocket port set.
    SipDiscardedByWebSocketPorts,
    /// Records a store shed at a cap — dialogs, messages, STUN transactions,
    /// ICMP evidence.
    RetentionLoss,

    // ── Critical: nobody could hear ──────────────────────────────────
    /// An answered call negotiated media that was expected to flow, and none
    /// arrived.
    NoMedia,
    /// Audio flowed in one direction only.
    OneWayAudio,
    /// STUN told the client its public address, or never answered at all, and
    /// the SDP advertised an unroutable one regardless.
    StunSdpMismatch,
    /// An ICMP error quoting this dialog's own SIP request.
    IcmpUnreachableSignaling,
    /// An ICMP error quoting a media datagram.
    IcmpUnreachableMedia,

    // ── Major: the call failed, or the path is damaged ───────────────
    /// RTP arrived from an address no SDP in the dialog advertised.
    NatMismatch,
    /// The dialog ended on a `5xx` or `6xx`.
    ServerFailure,
    /// Repeated `401`/`407` challenges with no `2xx`.
    AuthLoop,
    /// A request retransmitted with nothing coming back.
    Retransmissions,
    /// An answered `INVITE` that was never acknowledged.
    AckMissing,
    /// A `REGISTER` rejected, or granted less time than it asked for.
    RegistrationFailure,
    /// A STUN Binding transaction that drew no response.
    UnansweredStunProbe,
    /// A TURN allocation that was still carrying traffic after the lifetime it
    /// was last granted had run out.
    TurnAllocationLapsed,
    /// ICMP named an endpoint unreachable and the quote reached no dialog.
    IcmpUnreachableEndpoint,

    // ── Minor: degradation, or an outcome to rule out ────────────────
    /// The dialog ended on a `4xx`.
    RequestFailure,
    /// The dialog never reached a final response.
    Abandoned,
    /// Ring-back took longer than the post-dial-delay threshold.
    PostDialDelay,
    /// RTP started well after the `200 OK`.
    LateMedia,
    /// The two legs used different codecs.
    CodecAsymmetry,
    /// The two legs used different packetization times.
    PtimeAsymmetry,
    /// The two legs used different RTP payload types for the same codec.
    PayloadTypeAsymmetry,
    /// One leg's media lasted noticeably longer than the other's.
    DurationAsymmetry,
}

impl FindingKind {
    /// The kind's fixed properties.
    #[must_use]
    pub const fn meta(self) -> KindMeta {
        /// Shorthand so the table below stays one line per kind.
        const fn m(
            id: &'static str,
            severity: Severity,
            title: &'static str,
            unit: &'static str,
            detail: &'static str,
        ) -> KindMeta {
            KindMeta {
                id,
                severity,
                title,
                unit,
                detail,
            }
        }
        match self {
            Self::UndecodableFrames => m(
                "undecodable_frames",
                Severity::Blind,
                "Frames not decoded",
                "frame",
                "These frames reached sipnab intact and no decoder here could read them, so \
                 nothing in them is in any count above — a zero elsewhere in this report is not \
                 evidence of absence. Convert the capture (editcap -T ether) or open an issue \
                 naming the link type, EtherType or IP protocol below.",
            ),
            Self::SipDiscardedByPortRange => m(
                "sip_discarded_by_portrange",
                Severity::Blind,
                "SIP discarded by --portrange",
                "message",
                "sipnab recognised these as SIP and then threw them away because neither port \
                 was inside --portrange. They are in no dialog and no count. Widen the range \
                 (--portrange 1-65535 analyses everything) and read the capture again.",
            ),
            Self::SipDiscardedByWebSocketPorts => m(
                "sip_discarded_by_websocket_ports",
                Severity::Blind,
                "SIP-over-WebSocket discarded by port set",
                "message",
                "These were unwrapped far enough to confirm they were SIP and then declined \
                 because the WebSocket port was outside the configured set. A WebRTC signaling \
                 leg terminating off 80/443/8080/8443 vanishes entirely without this line.",
            ),
            Self::RetentionLoss => m(
                "retention_loss",
                Severity::Blind,
                "Records discarded at a store cap",
                "record",
                "sipnab read these and then dropped them to stay inside a size limit, so the \
                 counts in this report are what it KEPT rather than what it read. Raise \
                 --limit, --max-dialogs or --max-streams and run it again.",
            ),
            Self::NoMedia => m(
                "no_media",
                Severity::Critical,
                "No media on an answered call",
                "call",
                "The call was answered and its SDP asked for RTP that was expected to flow, and \
                 not one packet of it arrived. Neither party heard anything. Check that the \
                 capture point sees the media path at all before reading this as a fault.",
            ),
            Self::OneWayAudio => m(
                "one_way_audio",
                Severity::Critical,
                "One-way audio",
                "call",
                "RTP flowed in one direction only: one party heard the other and was not heard \
                 back. The usual causes are a NAT that never opened the return pinhole, an \
                 SDP advertising an address the far end cannot route to, or a firewall \
                 dropping inbound media.",
            ),
            Self::StunSdpMismatch => m(
                "stun_sdp_mismatch",
                Severity::Critical,
                "SDP advertises an address STUN contradicts",
                "call",
                "The client's SDP names an address that STUN is on record either replacing with \
                 a different, reachable one, allocating on a TURN relay, or never answering \
                 about at all: the far end is sending media to an address that cannot receive \
                 it. Where the STUN exchange and the call coincide this is the cause of \
                 one-way audio rather than an inference from it; evidence seen well outside \
                 the call is matched by client IP alone and says so in its notes.",
            ),
            Self::IcmpUnreachableSignaling => m(
                "icmp_unreachable_signaling",
                Severity::Critical,
                "ICMP: SIP request undeliverable",
                "call",
                "A router answered this dialog's own SIP request with an ICMP error. This is the \
                 one packet in a capture that states a cause instead of implying one — the \
                 request was never delivered, so the call could not have carried audio.",
            ),
            Self::IcmpUnreachableMedia => m(
                "icmp_unreachable_media",
                Severity::Critical,
                "ICMP: media undeliverable",
                "flow",
                "A router answered a media datagram with an ICMP error: the audio was sent to a \
                 socket that was not listening. Check that the media relay is running and that \
                 the port the SDP advertised is the port it is bound to.",
            ),
            Self::NatMismatch => m(
                "nat_mismatch",
                Severity::Major,
                "RTP source no SDP advertised",
                "call",
                "Media arrived from an address that no SDP in the dialog named — the signature \
                 of a NAT rewriting the media source. Frequently benign on its own (symmetric \
                 RTP through a NAT looks exactly like this); read it together with any one-way \
                 audio on the same call.",
            ),
            Self::ServerFailure => m(
                "server_failure",
                Severity::Major,
                "Call failed 5xx/6xx",
                "call",
                "The call ended on a server-class or global failure (RFC 3261 §21.5, §21.6). \
                 Unlike a 4xx these are never an ordinary call outcome: something on the path \
                 or at the far end was unable to serve the request.",
            ),
            Self::AuthLoop => m(
                "auth_loop",
                Severity::Major,
                "Authentication loop",
                "call",
                "The endpoint was challenged repeatedly and never reached a 2xx. Either the \
                 credentials are wrong (provisioning) or no Authorization header is ever sent \
                 (a client that does not know the realm, or a proxy stripping it).",
            ),
            Self::Retransmissions => m(
                "retransmissions",
                Severity::Major,
                "Request retransmitted, no response",
                "call",
                "A request was sent repeatedly with nothing coming back — a one-way network \
                 path or a peer that is not there. Look for an ICMP error against the same \
                 destination: it turns this inference into a stated cause.",
            ),
            Self::AckMissing => m(
                "ack_missing",
                Severity::Major,
                "Answered INVITE never acknowledged",
                "call",
                "A 2xx answered the INVITE and no ACK confirmed it (RFC 3261 §13.3.1.4), so the \
                 UAS retransmitted until Timer H and then tore the call down. Audio typically \
                 stops within seconds of the answer.",
            ),
            Self::RegistrationFailure => m(
                "registration_failure",
                Severity::Major,
                "REGISTER failed or was cut short",
                "registration",
                "A registration was rejected, or was granted a shorter expiry than the endpoint \
                 asked for. The first means the phone is not reachable for inbound calls; the \
                 second means it will re-register sooner than it planned, which shows up as \
                 registration churn rather than as a fault.",
            ),
            Self::UnansweredStunProbe => m(
                "unanswered_stun_probe",
                Severity::Major,
                "STUN Binding Request unanswered",
                "transaction",
                "A client asked a STUN server what its public address was and nothing came \
                 back, so it never learned one and will advertise its private address in any \
                 SDP it later sends. RFC 5389 §7.2.1 retransmits only on timeout, so a repeated \
                 request is itself proof the earlier ones drew silence.",
            ),
            Self::TurnAllocationLapsed => m(
                "turn_allocation_lapsed",
                Severity::Major,
                "TURN allocation outlived its lifetime",
                "allocation",
                "Relayed traffic was still flowing after the lifetime the TURN server last \
                 granted had run out, and no Refresh was seen in between. A server tears an \
                 allocation down the moment its lifetime lapses, and the media stops with it — \
                 mid-call, with no SIP message to explain it. Check that the client's Refresh \
                 transactions are reaching the server, and that the capture covers them.",
            ),
            Self::IcmpUnreachableEndpoint => m(
                "icmp_unreachable_endpoint",
                Severity::Major,
                "ICMP: endpoint unreachable, no dialog",
                "error",
                "ICMP named these endpoints unreachable but the quoted bytes stopped before a \
                 Call-ID, or the dialog was never tracked, so the evidence appears against no \
                 call in this report. It is still a real router saying a real socket did not \
                 answer.",
            ),
            Self::RequestFailure => m(
                "request_failure",
                Severity::Minor,
                "Call failed 4xx",
                "call",
                "The call ended on a request failure (RFC 3261 §21.4). Many 4xx codes are \
                 ordinary call outcomes — 486 Busy Here, 404 for a misdialled number, 480 for a \
                 phone that is off — so this is listed to be ruled out rather than acted on. The \
                 codes are named below; a run of 403 or 408 is not an ordinary outcome.",
            ),
            Self::Abandoned => m(
                "abandoned",
                Severity::Minor,
                "No final response",
                "call",
                "The dialog never reached a final response, either because a CANCEL arrived \
                 first or because none was observed. The second is a statement about the \
                 CAPTURE, not the call — the recording may simply have stopped while the phone \
                 was still ringing.",
            ),
            Self::PostDialDelay => m(
                "post_dial_delay",
                Severity::Minor,
                "Slow ring-back",
                "call",
                "The caller waited longer than the post-dial-delay threshold before hearing \
                 anything. Callers hang up on this long before it becomes an outage, so it \
                 reads as random call failure to everyone except the person holding the \
                 capture.",
            ),
            Self::LateMedia => m(
                "late_media",
                Severity::Minor,
                "Media started late",
                "call",
                "RTP began well after the 200 OK, so the first part of the conversation was \
                 clipped. Usually a media relay that had not finished setting the path up when \
                 signaling completed.",
            ),
            Self::CodecAsymmetry => m(
                "codec_asymmetry",
                Severity::Minor,
                "Codec differs between legs",
                "call",
                "The two legs carried different codecs, which means something on the path is \
                 transcoding. Costs CPU on the B2BUA and a measurable amount of audio quality; \
                 expected on an interconnect, suspicious inside one network.",
            ),
            Self::PtimeAsymmetry => m(
                "ptime_asymmetry",
                Severity::Minor,
                "Packetization time differs between legs",
                "call",
                "The two legs framed audio at different packetization times. A repacketizing \
                 middlebox adds a little delay and jitter in each direction.",
            ),
            Self::PayloadTypeAsymmetry => m(
                "payload_type_asymmetry",
                Severity::Minor,
                "Payload type differs between legs",
                "call",
                "Both legs negotiated the same codec and then used different RTP payload type \
                 numbers — a middlebox rewriting them, or an SDP answer that did not echo the \
                 offer's numbering. Endpoints that trust the PT rather than the SDP decode \
                 noise from this.",
            ),
            Self::DurationAsymmetry => m(
                "duration_asymmetry",
                Severity::Minor,
                "Leg durations differ",
                "call",
                "One leg's media ran materially longer than the other's — one side stopped \
                 sending, or stopped being forwarded, before the call ended.",
            ),
        }
    }
}

impl serde::Serialize for FindingKind {
    /// Serializes as the stable [`KindMeta::id`], not as the Rust variant
    /// name, so renaming a variant cannot change a consumer's JSON.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.meta().id)
    }
}

/// One verifiable instance of a finding.
///
/// Every field exists so a reader can go back to the capture and check the
/// claim. A finding an operator cannot verify against the pcap is worthless,
/// and a confident wrong answer is worse than no answer at all — the rule the
/// rest of this crate's evidence types are built on.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Evidence {
    /// The dialog this instance belongs to. `None` for a capture-level finding
    /// that belongs to no call — a STUN probe, an undecodable frame, an ICMP
    /// quote too short to name a Call-ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// The addresses involved, most specific first: an `ip:port` pair, a media
    /// endpoint, a STUN client and server.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// When it happened, when a single timestamp describes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<DateTime<Utc>>,
    /// Named integer counts — packets, streams, messages, errors, status
    /// codes. A `BTreeMap` rather than a `Vec` of pairs so JSON key order is
    /// deterministic and the output stays diffable.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<&'static str, u64>,
    /// The part of the evidence that is not an integer — codec names, a reason
    /// phrase, a router's own words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Evidence {
    /// Evidence attached to one dialog, stamped with when the dialog opened.
    fn for_dialog(dialog: &SipDialog) -> Self {
        Self {
            call_id: Some(dialog.call_id.clone()),
            endpoints: vec![format!(
                "{}:{} -> {}",
                dialog.src_addr, dialog.src_port, dialog.dst_addr
            )],
            at: Some(dialog.created_at),
            ..Self::default()
        }
    }

    /// Add a named count.
    #[must_use]
    fn count(mut self, label: &'static str, value: u64) -> Self {
        self.counts.insert(label, value);
        self
    }

    /// Attach the non-integer half of the evidence.
    #[must_use]
    fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Append an address to [`Self::endpoints`].
    #[must_use]
    fn endpoint(mut self, addr: impl Into<String>) -> Self {
        self.endpoints.push(addr.into());
        self
    }

    /// Stamp the evidence with when it happened.
    #[must_use]
    fn at_time(mut self, at: DateTime<Utc>) -> Self {
        self.at = Some(at);
        self
    }
}

/// One ranked problem, with every occurrence of it counted and a sample of
/// them evidenced.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Finding {
    /// Which problem this is.
    pub kind: FindingKind,
    /// How bad it is. Denormalized from [`FindingKind::meta`] so a JSON
    /// consumer can sort without a copy of the table.
    pub severity: Severity,
    /// How many times it was observed, in [`KindMeta::unit`]s. Exact — it is
    /// not the length of [`Self::evidence`], which is capped.
    pub occurrences: u64,
    /// What one occurrence is.
    pub unit: &'static str,
    /// Up to [`EVIDENCE_CAP`] verifiable instances.
    pub evidence: Vec<Evidence>,
    /// Evidence rows the cap kept out.
    ///
    /// Counted while accumulating rather than derived as
    /// `occurrences - evidence.len()`, because those two are not in the same
    /// unit. One row routinely stands for many occurrences — a port that
    /// discarded 412 messages, an ICMP flow hit 40 times — and the derived
    /// form reported "1 shown, 22 more not listed" for a complete
    /// single-row list, which is a fabricated omission presented as evidence
    /// of one.
    pub evidence_omitted: u64,
}

/// Everything `--analyze` found, ranked, with the denominators it found it in.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct CaptureAnalysis {
    /// Frames handed to the parser. The denominator that makes every other
    /// number readable, and the reason the clean line is honest.
    pub frames_read: u64,
    /// Dialogs the analysis looked at, after `--filter`.
    pub dialogs_examined: usize,
    /// RTP streams linked to those dialogs.
    pub streams_examined: usize,
    /// Whether sipnab read all of its input. False when any [`Severity::Blind`]
    /// finding is present, which is the only thing that can make it false.
    pub complete: bool,
    /// The findings, worst first. See [`rank`].
    pub findings: Vec<Finding>,
}

impl CaptureAnalysis {
    /// Whether nothing at all was found — no problems AND nothing unread.
    ///
    /// Deliberately not "no problems of severity above X": the incompleteness
    /// findings live in the same list precisely so that this cannot answer
    /// `true` for a capture sipnab could not read.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Findings at one severity.
    pub fn at(&self, severity: Severity) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.severity == severity)
    }
}

/// Sort findings worst first, deterministically.
///
/// Three keys, in order:
///
/// 1. **severity ascending** — [`Severity`]'s declared order is the ladder, so
///    `Blind` then `Critical` then `Major` then `Minor`.
/// 2. **occurrences descending** — within a severity, the thing that happened
///    to more calls is the thing to look at first.
/// 3. **kind ascending** — [`FindingKind`]'s declaration order.
///
/// The third key alone is already a total order, because the aggregation emits
/// at most one finding per kind. It is there so the output is byte-stable
/// across runs and therefore diffable: two captures analysed a week apart
/// produce lists that can be compared line by line, and a count that moved is
/// visible instead of being hidden by a reshuffle.
pub fn rank(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.kind.cmp(&b.kind))
    });
}

/// What one kind has accumulated so far.
#[derive(Debug, Default)]
struct Tally {
    /// Exact occurrence count, in the kind's unit.
    occurrences: u64,
    /// Retained evidence rows, at most [`EVIDENCE_CAP`].
    evidence: Vec<Evidence>,
    /// Rows the cap kept out.
    evidence_omitted: u64,
}

/// Accumulator: occurrences and a capped evidence sample, per kind.
#[derive(Debug, Default)]
struct Accumulator {
    /// Per-kind tally. A `BTreeMap` so the pre-sort iteration order is already
    /// deterministic.
    by_kind: BTreeMap<FindingKind, Tally>,
}

impl Accumulator {
    /// Record one occurrence of `kind`, keeping `ev` if there is room.
    fn add(&mut self, kind: FindingKind, ev: Evidence) {
        self.bump(kind, 1, ev);
    }

    /// Record `n` occurrences of `kind` described by a single evidence row.
    ///
    /// Used where one row stands for many occurrences — a port that discarded
    /// 900 messages, an ICMP flow hit 40 times — so the count stays exact
    /// while the evidence stays one line.
    fn bump(&mut self, kind: FindingKind, n: u64, ev: Evidence) {
        let entry = self.by_kind.entry(kind).or_default();
        entry.occurrences += n;
        if entry.evidence.len() < EVIDENCE_CAP {
            entry.evidence.push(ev);
        } else {
            entry.evidence_omitted += 1;
        }
    }

    /// Drain into ranked findings.
    fn into_findings(self) -> Vec<Finding> {
        let mut out: Vec<Finding> = self
            .by_kind
            .into_iter()
            .map(|(kind, tally)| Finding {
                kind,
                severity: kind.meta().severity,
                occurrences: tally.occurrences,
                unit: kind.meta().unit,
                evidence: tally.evidence,
                evidence_omitted: tally.evidence_omitted,
            })
            .collect();
        rank(&mut out);
        out
    }
}

/// What a store shed to stay inside its size limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionCounts {
    /// Messages evicted from retained dialogs by idle compaction.
    pub messages_evicted: u64,
    /// New dialogs refused because the store was at capacity.
    pub dialogs_refused: u64,
    /// Oldest dialogs discarded at capacity by rotation.
    pub dialogs_rotated: u64,
}

impl RetentionCounts {
    /// Read the counters off a dialog store.
    #[must_use]
    pub fn of_store(dialogs: &DialogStore) -> Self {
        Self {
            messages_evicted: dialogs.total_idle_messages_evicted(),
            dialogs_refused: dialogs.total_capacity_dialogs_dropped(),
            dialogs_rotated: dialogs.total_capacity_dialogs_evicted(),
        }
    }
}

/// Everything the analysis reads that is neither a dialog nor a stream.
///
/// Taken as one value rather than read from the process globals inside
/// [`analyze`] for two reasons. It makes the honesty rules — "a capture that
/// did not decode is never clean", "a port gate that ate SIP always shows" —
/// testable by construction instead of only by mutating process-global state
/// under a `serial` lock. And it makes visible, in one struct, exactly which
/// facts a "no problems found" verdict is standing on.
#[derive(Debug, Clone, Default)]
pub struct CaptureFacts {
    /// Frames handed to the parser.
    pub frames_read: u64,
    /// Frames that produced nothing.
    pub undecodable: crate::capture::UndecodableReport,
    /// SIP the `--portrange` gate discarded.
    pub portrange: crate::pipeline::PortrangeSkipReport,
    /// SIP-over-WebSocket the port set discarded.
    pub websocket: crate::pipeline::WsPortSkipReport,
    /// What STUN said.
    pub stun: crate::stun::StunReport,
    /// ICMP errors quoting SIP.
    pub icmp: crate::pipeline::IcmpEvidenceReport,
    /// ICMP errors quoting media, resolved against the stream store.
    pub icmp_media: crate::pipeline::IcmpMediaReport,
    /// What the stores shed at a cap.
    pub retention: RetentionCounts,
}

impl CaptureFacts {
    /// Read every fact off this process's stores.
    ///
    /// # Side effects
    ///
    /// None; takes the STUN and ICMP locks to copy their contents out.
    #[must_use]
    pub fn observed(
        dialog_store: &DialogStore,
        stream_store: &StreamStore,
        frames_read: u64,
    ) -> Self {
        Self {
            frames_read,
            undecodable: crate::capture::undecodable_report(),
            portrange: crate::pipeline::portrange_skip_report(),
            websocket: crate::pipeline::ws_port_skip_report(),
            stun: crate::stun::report(),
            icmp: crate::pipeline::icmp_evidence_report(),
            icmp_media: crate::pipeline::icmp_media_report(stream_store),
            retention: RetentionCounts::of_store(dialog_store),
        }
    }
}

/// Analyse a finished capture and rank everything already diagnosed in it.
///
/// # Arguments
///
/// * `dialog_store` / `stream_store` — the run's final stores.
/// * `filter` — the compiled `--filter` expression, applied to the DIALOG
///   selection only. Capture-level findings (undecodable frames, port-gate
///   discards, STUN, ICMP that reached no dialog, retention losses) are never
///   narrowed by it, for the reason `--stun` is not: the DSL selects dialogs,
///   and a NAT-discovery probe or an unreadable frame belongs to no dialog.
///   Narrowing them would drop exactly the evidence that explains why the
///   selected dialogs are broken.
/// * `frames_read` — frames handed to the parser, carried into the result as
///   the denominator every other number is read against.
///
/// # Side effects
///
/// None. Reads the process-global STUN, ICMP and undecodable stores, and the
/// two port-gate tallies; writes nothing.
#[must_use]
pub fn analyze(
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    filter: Option<&FilterExpr>,
    frames_read: u64,
) -> CaptureAnalysis {
    let facts = CaptureFacts::observed(dialog_store, stream_store, frames_read);
    analyze_with(dialog_store, stream_store, filter, &facts)
}

/// [`analyze`] against facts supplied by the caller.
///
/// The pure form: everything the verdict depends on arrives as an argument, so
/// a test can state the exact capture it is describing.
#[must_use]
pub fn analyze_with(
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    filter: Option<&FilterExpr>,
    facts: &CaptureFacts,
) -> CaptureAnalysis {
    let mut acc = Accumulator::default();

    let selection = crate::sip::dsl::select_dialogs(filter, dialog_store, stream_store);
    let capture = CaptureMedia::of_store(stream_store);
    let thresholds = crate::rtp::diagnosis::AsymmetryThresholds::default();
    let mut streams_examined = 0usize;

    for (dialog, dialog_streams) in &selection.dialogs {
        streams_examined += dialog_streams.len();
        let media = MediaContext::for_dialog(dialog, capture);
        let mut diag = crate::rtp::diagnosis::diagnose_media(dialog_streams, &media);
        crate::rtp::diagnosis::diagnose_asymmetry(
            &mut diag,
            Some(dialog),
            dialog_streams,
            &thresholds,
        );
        collect_media(&mut acc, dialog, dialog_streams, &diag);
        collect_signaling(&mut acc, dialog);
    }

    collect_capture_level(&mut acc, facts);

    let findings = acc.into_findings();
    // `complete` is DERIVED from the list rather than tracked beside it. A
    // separate flag is a second place to forget, and the failure mode of
    // forgetting is a capture that did not decode reporting as a clean one —
    // which is the exact defect this module is written to be incapable of.
    let complete = !findings.iter().any(|f| f.severity == Severity::Blind);
    CaptureAnalysis {
        frames_read: facts.frames_read,
        dialogs_examined: selection.dialogs.len(),
        streams_examined,
        complete,
        findings,
    }
}

/// Fold one dialog's media diagnosis into the accumulator.
fn collect_media(
    acc: &mut Accumulator,
    dialog: &SipDialog,
    streams: &[&crate::rtp::stream::RtpStream],
    diag: &crate::rtp::diagnosis::MediaDiagnosis,
) {
    // The media-path evidence shared by the three address-shaped findings:
    // what the SDP asked for, what actually arrived, and how much of it.
    let path = || {
        let packets: u64 = streams.iter().map(|s| s.packet_count).sum();
        let mut ev = Evidence::for_dialog(dialog)
            .count("streams", streams.len() as u64)
            .count("rtp_packets", packets);
        if let Some(ref sdp) = diag.sdp_media {
            ev = ev.endpoint(format!("SDP {sdp}"));
        }
        if let Some(ref actual) = diag.actual_media {
            ev = ev.endpoint(format!("RTP from {actual}"));
        }
        ev
    };

    if diag.no_media {
        acc.add(FindingKind::NoMedia, path());
    }
    if diag.one_way_audio {
        // Name the direction that DID carry audio: "one-way" without saying
        // which way is half an answer, and the half that is missing is the one
        // that says which endpoint to go and look at.
        let mut ev = path();
        if let Some(carrying) = streams.iter().max_by_key(|s| s.packet_count) {
            ev = ev.note(format!(
                "{} -> {} carried {} packet(s); nothing came back the other way",
                carrying.key.src, carrying.key.dst, carrying.packet_count
            ));
        }
        acc.add(FindingKind::OneWayAudio, ev);
    }
    if diag.nat_mismatch {
        acc.add(FindingKind::NatMismatch, path());
    }
    if let Some(ref m) = diag.stun_sdp_mismatch {
        let ev = Evidence::for_dialog(dialog)
            .endpoint(format!("STUN client {}", m.client))
            .endpoint(format!("SDP advertises {}", m.advertised))
            .count("stun_requests", u64::from(m.request_count))
            .note(match m.reason {
                crate::rtp::diagnosis::StunSdpMismatchReason::Ignored => format!(
                    "STUN answered with {} and the SDP advertised {} regardless",
                    m.mapped_address.as_deref().unwrap_or("a public address"),
                    m.advertised
                ),
                crate::rtp::diagnosis::StunSdpMismatchReason::RelayIgnored => format!(
                    "TURN allocated the relayed address {} and the SDP advertised {} regardless",
                    m.relayed_address.as_deref().unwrap_or("a relayed address"),
                    m.advertised
                ),
                crate::rtp::diagnosis::StunSdpMismatchReason::Unanswered => format!(
                    "{} request(s) drew no STUN response, so the client never learned a public \
                     address and advertised {}",
                    m.request_count, m.advertised
                ),
            });
        // The correlation is by client IP with no shared identifier, so STUN
        // evidence from well outside the call is an inference that the fault
        // persisted rather than something seen during setup. Same sentence the
        // dialog hint carries, from the same method — a qualification that
        // appeared on one surface and not the other would be worse than none.
        let ev = match m.correlation_caveat() {
            Some(caveat) => ev.note(caveat),
            None => ev,
        };
        acc.add(FindingKind::StunSdpMismatch, ev);
    }
    if let Some(ref late) = diag.late_media {
        acc.add(
            FindingKind::LateMedia,
            Evidence::for_dialog(dialog)
                .count(
                    "delay_after_200_ok_ms",
                    late.delay_after_200_ok_ms.max(0) as u64,
                )
                .note(format!("{} leg started late", late.leg)),
        );
    }
    if let Some(ref c) = diag.codec_asymmetry {
        acc.add(
            FindingKind::CodecAsymmetry,
            Evidence::for_dialog(dialog).note(format!("A leg {}, B leg {}", c.a_codec, c.b_codec)),
        );
    }
    if let Some(ref p) = diag.ptime_asymmetry {
        acc.add(
            FindingKind::PtimeAsymmetry,
            Evidence::for_dialog(dialog)
                .count("a_ptime_ms", u64::from(p.a_ptime_ms))
                .count("b_ptime_ms", u64::from(p.b_ptime_ms)),
        );
    }
    if let Some(ref p) = diag.payload_type_asymmetry {
        acc.add(
            FindingKind::PayloadTypeAsymmetry,
            Evidence::for_dialog(dialog)
                .count("a_payload_type", u64::from(p.a_pt))
                .count("b_payload_type", u64::from(p.b_pt)),
        );
    }
    if let Some(ref d) = diag.duration_asymmetry {
        acc.add(
            FindingKind::DurationAsymmetry,
            Evidence::for_dialog(dialog).note(format!(
                "A leg {:.1}s, B leg {:.1}s (delta {:.1}s)",
                d.a_duration_sec, d.b_duration_sec, d.delta_sec
            )),
        );
    }
}

/// Fold one dialog's signaling diagnosis into the accumulator.
fn collect_signaling(acc: &mut Accumulator, dialog: &SipDialog) {
    let diag = crate::sip::diagnosis::diagnose_signaling(&dialog.messages);
    if diag.is_empty() {
        return;
    }

    if let Some(ref f) = diag.final_failure {
        // 4xx and 5xx/6xx are split because RFC 3261 gives them different
        // meanings and an operator reads them differently: a 4xx is a request
        // failure at this server and is routinely an ordinary call outcome
        // (486 Busy, 603 Decline), while a 5xx is the server admitting it
        // could not serve a valid request and a 6xx is a global refusal.
        // Ranking every 4xx alongside them would bury the ones that matter
        // under the busy signals, which is how a ranked list stops being read.
        let kind = if f.code >= 500 {
            FindingKind::ServerFailure
        } else {
            FindingKind::RequestFailure
        };
        let mut note = f.reason_phrase.clone();
        if let Some(ref reason) = f.reason_header {
            note.push_str(&format!(" (Reason: {reason})"));
        }
        if let Some(ref warning) = f.warning {
            note.push_str(&format!(" (Warning: {warning})"));
        }
        acc.add(
            kind,
            Evidence::for_dialog(dialog)
                .count("status_code", u64::from(f.code))
                .note(note),
        );
    }
    if let Some(ref a) = diag.auth_loop {
        acc.add(
            FindingKind::AuthLoop,
            Evidence::for_dialog(dialog)
                .count("challenges", a.challenges as u64)
                .note(match a.kind {
                    AuthLoopKind::CredentialFailure => {
                        "the UAC answers each challenge and is challenged again — wrong \
                         credentials"
                    }
                    AuthLoopKind::SilentDrop => {
                        "the UAC never sends Authorization — a client that does not know the \
                         realm, or a proxy stripping the header"
                    }
                }),
        );
    }
    if let Some(ref r) = diag.retransmissions {
        let mut note = format!(
            "{} transmitted {} time(s) over {:.1}s with no response",
            r.method, r.count, r.span_sec
        );
        if let Some(ref cause) = r.icmp_cause {
            note.push_str(&format!("; ICMP said: {cause}"));
        }
        acc.add(
            FindingKind::Retransmissions,
            Evidence::for_dialog(dialog)
                .count("transmissions", r.count as u64)
                .note(note),
        );
    }
    if let Some(ref a) = diag.ack_missing {
        acc.add(
            FindingKind::AckMissing,
            Evidence::for_dialog(dialog)
                .count("answer_transmissions", a.answer_transmissions as u64)
                .note(format!("{:.1}s elapsed with no ACK", a.waited_sec)),
        );
    }
    if let Some(ref a) = diag.abandoned {
        acc.add(
            FindingKind::Abandoned,
            Evidence::for_dialog(dialog).note(match a.kind {
                AbandonedKind::Canceled => {
                    format!("CANCEL after {:.1}s — the caller hung up", a.elapsed_sec)
                }
                AbandonedKind::NoFinalResponse => format!(
                    "no final response in {:.1}s — this may be where the capture stopped rather \
                     than where the call failed",
                    a.elapsed_sec
                ),
            }),
        );
    }
    if let Some(ref p) = diag.post_dial_delay {
        acc.add(
            FindingKind::PostDialDelay,
            Evidence::for_dialog(dialog).note(format!(
                "{:.1}s to the first {} (threshold {:.1}s)",
                p.delay_sec, p.responded_with, p.threshold_sec
            )),
        );
    }
    if let Some(ref r) = diag.registration_failure {
        let mut note = match r.kind {
            RegistrationFailureKind::Rejected => format!("REGISTER rejected with {}", r.code),
            RegistrationFailureKind::ShortenedExpiry => "registrar granted a shorter expiry than \
                                                         the endpoint asked for"
                .to_string(),
        };
        if let (Some(asked), Some(granted)) = (r.requested_expiry_sec, r.granted_expiry_sec) {
            note.push_str(&format!(" (asked {asked}s, granted {granted}s)"));
        }
        acc.add(
            FindingKind::RegistrationFailure,
            Evidence::for_dialog(dialog)
                .count("status_code", u64::from(r.code))
                .note(note),
        );
    }
    if let Some(ref i) = diag.icmp_unreachable {
        acc.bump(
            FindingKind::IcmpUnreachableSignaling,
            1,
            Evidence::for_dialog(dialog)
                .endpoint(format!("unreachable {}", i.unreachable_endpoint))
                .endpoint(format!("reported by {}", i.reported_by))
                .count("icmp_errors", i.errors as u64)
                .note(format!(
                    "{} (type {}, code {}){}",
                    i.description,
                    i.icmp_type,
                    i.icmp_code,
                    i.method
                        .as_ref()
                        .map(|m| format!(", quoting a {m}"))
                        .unwrap_or_default()
                )),
        );
    }
}

/// Fold everything that belongs to the capture rather than to a call.
fn collect_capture_level(acc: &mut Accumulator, facts: &CaptureFacts) {
    collect_incompleteness(acc, facts);

    // ── STUN: probes nothing answered ────────────────────────────────
    for tx in facts.stun.unanswered() {
        acc.add(
            FindingKind::UnansweredStunProbe,
            Evidence::default()
                .endpoint(format!("client {}", tx.client))
                .endpoint(format!("server {}", tx.server))
                .count("requests", u64::from(tx.request_count))
                .note(if tx.was_retransmitted() {
                    "retransmitted, which by itself proves the first request went unanswered"
                } else {
                    "no response"
                })
                .at_time(tx.first_request),
        );
    }

    // ── TURN: allocations that outlived their lifetime ───────────────
    for alloc in facts.stun.lapsed_allocations() {
        let mut ev = Evidence::default()
            .endpoint(format!("client {}", alloc.client))
            .endpoint(format!("TURN server {}", alloc.server))
            .count("refreshes", u64::from(alloc.refreshes))
            .at_time(alloc.allocated_at);
        if let Some(secs) = alloc.lifetime_secs {
            ev = ev.count("lifetime_secs", u64::from(secs));
        }
        if let Some(relayed) = alloc.relayed_address {
            ev = ev.endpoint(format!("relayed {relayed}"));
        }
        acc.add(
            FindingKind::TurnAllocationLapsed,
            ev.note(
                "traffic continued on this relay after the lifetime it was last granted had \
                 run out, with no Refresh seen in between",
            ),
        );
    }

    // ── ICMP against media ───────────────────────────────────────────
    //
    // Only the flows ICMP actually ties to media are claimed. The report also
    // counts ordinary non-SIP network failures, and claiming those as audio
    // problems would be the confident wrong answer this whole layer is
    // supposed to remove.
    for flow in &facts.icmp_media.flows {
        if !flow.payload.is_media() && flow.matched == crate::pipeline::MediaMatch::None {
            continue;
        }
        let mut ev = Evidence::default()
            .endpoint(format!("unreachable {}", flow.unreachable_endpoint))
            .endpoint(format!("sent from {}", flow.source))
            .endpoint(format!("reported by {}", flow.reported_by))
            .count("icmp_errors", flow.errors)
            .count("streams", flow.streams as u64)
            .note(flow.hint.clone());
        ev.call_id = flow.call_ids.first().cloned();
        acc.bump(FindingKind::IcmpUnreachableMedia, flow.errors, ev);
    }

    // ── ICMP that reached no dialog ──────────────────────────────────
    //
    // The occurrence count is the number of ERRORS that named no call, not the
    // number of endpoints: one endpoint routinely accounts for all of them,
    // and counting endpoints would report a 3,000-error outage as a 1.
    if facts.icmp.unattributed > 0 {
        acc.bump(
            FindingKind::IcmpUnreachableEndpoint,
            facts.icmp.unattributed,
            Evidence::default().count("errors_naming_no_call", facts.icmp.unattributed),
        );
        for endpoint in facts.icmp.endpoints.iter().take(EVIDENCE_CAP - 1) {
            acc.bump(
                FindingKind::IcmpUnreachableEndpoint,
                0,
                Evidence::default()
                    .endpoint(match endpoint.port {
                        Some(p) => format!("{}:{p}", endpoint.addr),
                        None => endpoint.addr.to_string(),
                    })
                    .count("icmp_errors", endpoint.errors)
                    .note(endpoint.description),
            );
        }
    }
}

/// Fold what sipnab did NOT read into the accumulator.
///
/// Split out from [`collect_capture_level`] because it is the part bound by
/// the honesty rule in this module's header: these are the findings whose
/// presence makes a "clean" verdict impossible, and keeping them in one
/// function makes that set readable in one screen.
fn collect_incompleteness(acc: &mut Accumulator, facts: &CaptureFacts) {
    // ── Frames that produced nothing ─────────────────────────────────
    let undecodable = &facts.undecodable;
    if undecodable.frames > 0 {
        let mut ev = Evidence::default()
            .count("frames", undecodable.frames)
            .count("frames_read", facts.frames_read)
            .note(undecodable.reason_list());
        if undecodable.reasons_dropped > 0 {
            ev = ev.count("reasons_not_retained", undecodable.reasons_dropped);
        }
        acc.bump(FindingKind::UndecodableFrames, undecodable.frames, ev);
    }

    // ── SIP a port gate threw away ───────────────────────────────────
    for port in facts.portrange.ports.iter().take(EVIDENCE_CAP) {
        acc.bump(
            FindingKind::SipDiscardedByPortRange,
            port.messages,
            Evidence::default()
                .endpoint(format!("port {}", port.port))
                .count("messages", port.messages),
        );
    }
    for port in facts.websocket.ports.iter().take(EVIDENCE_CAP) {
        acc.bump(
            FindingKind::SipDiscardedByWebSocketPorts,
            port.messages,
            Evidence::default()
                .endpoint(format!("port {}", port.port))
                .count("messages", port.messages),
        );
    }

    // ── Records a cap discarded ──────────────────────────────────────
    //
    // Four stores, one finding: the operator question is identical for all of
    // them ("what did sipnab throw away?") and the remedy is the same shape (a
    // larger limit), so splitting them into four rows would push the call
    // faults further down the page without telling anyone anything more.
    let msgs = facts.retention.messages_evicted;
    let refused = facts.retention.dialogs_refused;
    let rotated = facts.retention.dialogs_rotated;
    if msgs > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            msgs,
            Evidence::default()
                .count("messages", msgs)
                .note("messages evicted from retained dialogs by idle compaction (--limit)"),
        );
    }
    if refused > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            refused,
            Evidence::default()
                .count("dialogs", refused)
                .note("new dialogs refused at capacity (--no-rotate keeps the earliest)"),
        );
    }
    if rotated > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            rotated,
            Evidence::default()
                .count("dialogs", rotated)
                .note("oldest dialogs discarded at capacity by rotation (--max-dialogs)"),
        );
    }
    if facts.stun.dropped > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            facts.stun.dropped,
            Evidence::default()
                .count("stun_transactions", facts.stun.dropped)
                .note("STUN transactions past the tracking cap — the packet count stays exact"),
        );
    }
    if facts.icmp.untracked_dialogs > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            facts.icmp.untracked_dialogs,
            Evidence::default()
                .count("icmp_errors", facts.icmp.untracked_dialogs)
                .note(
                    "ICMP errors that reached no dialog because the tracking cap was full — real \
                     evidence that appears against no call",
                ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A finding with a chosen kind and count, for ranking tests.
    fn finding(kind: FindingKind, occurrences: u64) -> Finding {
        Finding {
            kind,
            severity: kind.meta().severity,
            occurrences,
            unit: kind.meta().unit,
            evidence: Vec::new(),
            evidence_omitted: 0,
        }
    }

    /// The ladder is the declared order, and nothing else. A change to it is a
    /// change to what the tool tells an operator to look at first, so it has
    /// to be deliberate enough to break a test.
    #[test]
    fn severity_orders_blind_above_every_call_fault() {
        assert!(Severity::Blind < Severity::Critical);
        assert!(Severity::Critical < Severity::Major);
        assert!(Severity::Major < Severity::Minor);
    }

    /// Severity dominates the count: one unreadable capture outranks a
    /// thousand slow-setup calls, because it says the thousand may be ten
    /// thousand.
    #[test]
    fn severity_outranks_occurrence_count() {
        let mut f = vec![
            finding(FindingKind::PostDialDelay, 1_000),
            finding(FindingKind::UndecodableFrames, 1),
        ];
        rank(&mut f);
        assert_eq!(f[0].kind, FindingKind::UndecodableFrames);
    }

    /// Within one severity, the problem that hit more calls comes first.
    #[test]
    fn within_a_severity_the_busier_finding_comes_first() {
        let mut f = vec![
            finding(FindingKind::NoMedia, 2),
            finding(FindingKind::OneWayAudio, 40),
        ];
        rank(&mut f);
        assert_eq!(f[0].kind, FindingKind::OneWayAudio);
        assert_eq!(f[1].kind, FindingKind::NoMedia);
    }

    /// Equal severity and equal counts must still produce ONE order, every
    /// time, or the report stops being diffable across runs.
    #[test]
    fn equal_counts_break_the_tie_on_kind_and_stay_stable() {
        let ordered = |mut v: Vec<Finding>| {
            rank(&mut v);
            v.into_iter().map(|f| f.kind).collect::<Vec<_>>()
        };
        let a = ordered(vec![
            finding(FindingKind::StunSdpMismatch, 3),
            finding(FindingKind::NoMedia, 3),
            finding(FindingKind::OneWayAudio, 3),
        ]);
        let b = ordered(vec![
            finding(FindingKind::OneWayAudio, 3),
            finding(FindingKind::NoMedia, 3),
            finding(FindingKind::StunSdpMismatch, 3),
        ]);
        assert_eq!(
            a, b,
            "the same set must rank identically whatever order it arrives in"
        );
        assert_eq!(
            a,
            vec![
                FindingKind::NoMedia,
                FindingKind::OneWayAudio,
                FindingKind::StunSdpMismatch
            ]
        );
    }

    /// Every kind must carry a distinct machine id: two kinds sharing one id
    /// would silently merge in anyone's JSON.
    #[test]
    fn every_kind_has_a_distinct_id_and_a_detail() {
        const ALL: &[FindingKind] = &[
            FindingKind::UndecodableFrames,
            FindingKind::SipDiscardedByPortRange,
            FindingKind::SipDiscardedByWebSocketPorts,
            FindingKind::RetentionLoss,
            FindingKind::NoMedia,
            FindingKind::OneWayAudio,
            FindingKind::StunSdpMismatch,
            FindingKind::IcmpUnreachableSignaling,
            FindingKind::IcmpUnreachableMedia,
            FindingKind::NatMismatch,
            FindingKind::ServerFailure,
            FindingKind::AuthLoop,
            FindingKind::Retransmissions,
            FindingKind::AckMissing,
            FindingKind::RegistrationFailure,
            FindingKind::UnansweredStunProbe,
            FindingKind::IcmpUnreachableEndpoint,
            FindingKind::RequestFailure,
            FindingKind::Abandoned,
            FindingKind::PostDialDelay,
            FindingKind::LateMedia,
            FindingKind::CodecAsymmetry,
            FindingKind::PtimeAsymmetry,
            FindingKind::PayloadTypeAsymmetry,
            FindingKind::DurationAsymmetry,
        ];
        let mut ids: Vec<&str> = ALL.iter().map(|k| k.meta().id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "two kinds share a machine id");
        for kind in ALL {
            let meta = kind.meta();
            assert!(!meta.detail.is_empty(), "{} has no detail", meta.id);
            assert!(!meta.unit.is_empty(), "{} has no unit", meta.id);
            // Prose that runs through a `\` continuation and loses the join is
            // invisible in source and obvious in output. Catch it here.
            assert!(
                !meta.detail.contains("  "),
                "{}: doubled space in operator-facing prose: {:?}",
                meta.id,
                meta.detail
            );
        }
    }

    /// Blind findings are what makes `complete` false; nothing else can.
    #[test]
    fn a_blind_finding_is_the_only_thing_that_makes_a_run_incomplete() {
        let mut analysis = CaptureAnalysis {
            findings: vec![finding(FindingKind::OneWayAudio, 1)],
            complete: true,
            ..CaptureAnalysis::default()
        };
        assert!(!analysis.is_clean(), "a finding is not clean");
        assert!(
            analysis.complete,
            "a call fault does not make the read incomplete"
        );
        analysis
            .findings
            .push(finding(FindingKind::UndecodableFrames, 1));
        rank(&mut analysis.findings);
        analysis.complete = !analysis
            .findings
            .iter()
            .any(|f| f.severity == Severity::Blind);
        assert!(!analysis.complete);
        assert_eq!(analysis.findings[0].kind, FindingKind::UndecodableFrames);
    }

    /// The evidence cap must never make the count lie.
    #[test]
    fn the_occurrence_count_survives_the_evidence_cap() {
        let mut acc = Accumulator::default();
        for i in 0..(EVIDENCE_CAP as u64 + 7) {
            acc.add(
                FindingKind::OneWayAudio,
                Evidence {
                    call_id: Some(format!("call-{i}")),
                    ..Evidence::default()
                },
            );
        }
        let findings = acc.into_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].occurrences, EVIDENCE_CAP as u64 + 7);
        assert_eq!(findings[0].evidence.len(), EVIDENCE_CAP);
        assert_eq!(findings[0].evidence_omitted, 7);
    }

    /// Empty stores and empty facts.
    fn stores() -> (DialogStore, StreamStore) {
        (DialogStore::new(64, true), StreamStore::new(64))
    }

    /// An empty capture that read cleanly is clean — and says so beside its
    /// own denominators, which is the only honest way to say it.
    #[test]
    fn an_empty_clean_capture_reports_no_findings() {
        let (dialogs, streams) = stores();
        let analysis = analyze_with(&dialogs, &streams, None, &CaptureFacts::default());
        assert!(analysis.is_clean(), "{:?}", analysis.findings);
        assert!(analysis.complete);
        assert_eq!(analysis.dialogs_examined, 0);
        assert_eq!(analysis.streams_examined, 0);
    }

    /// The defect this whole layer must not have: a capture sipnab could not
    /// read reporting as a clean one. The undecodable tally alone has to make
    /// the analysis non-clean AND incomplete, and it has to sort first.
    #[test]
    fn a_capture_that_did_not_decode_is_never_clean() {
        let (dialogs, streams) = stores();
        let facts = CaptureFacts {
            frames_read: 7,
            undecodable: crate::capture::UndecodableReport {
                frames: 7,
                reasons: vec![crate::capture::UndecodableTally {
                    reason: crate::capture::UndecodableReason::NotIp(Some(0x8847)),
                    frames: 7,
                }],
                reasons_dropped: 0,
            },
            ..CaptureFacts::default()
        };
        let analysis = analyze_with(&dialogs, &streams, None, &facts);
        assert!(
            !analysis.is_clean(),
            "a capture that decoded nothing must not report clean"
        );
        assert!(!analysis.complete);
        assert_eq!(analysis.findings[0].kind, FindingKind::UndecodableFrames);
        assert_eq!(analysis.findings[0].occurrences, 7);
        assert_eq!(analysis.findings[0].severity, Severity::Blind);
        assert_eq!(analysis.frames_read, 7);
    }

    /// A port gate that discarded real SIP must reach the ranked list, at
    /// Blind: those messages are in no dialog, so every per-call count is a
    /// floor and "no problems found" would be a claim about traffic sipnab
    /// deliberately threw away.
    #[test]
    fn sip_discarded_by_a_port_gate_is_a_blind_finding() {
        let (dialogs, streams) = stores();
        let facts = CaptureFacts {
            frames_read: 900,
            portrange: crate::pipeline::PortrangeSkipReport {
                messages: 412,
                ports: vec![crate::pipeline::SkippedPort {
                    port: 5080,
                    messages: 412,
                }],
            },
            ..CaptureFacts::default()
        };
        let analysis = analyze_with(&dialogs, &streams, None, &facts);
        let found = analysis
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::SipDiscardedByPortRange)
            .expect("the discard must be reported");
        assert_eq!(found.severity, Severity::Blind);
        assert_eq!(found.occurrences, 412);
        assert_eq!(found.evidence[0].endpoints, vec!["port 5080".to_string()]);
        assert!(!analysis.complete);
    }

    /// A retention cap that bit is the third way an analysis can be
    /// incomplete, and all four channels fold into one finding whose count is
    /// exact.
    #[test]
    fn records_discarded_at_a_cap_make_the_analysis_incomplete() {
        let (dialogs, streams) = stores();
        let facts = CaptureFacts {
            frames_read: 1_000,
            retention: RetentionCounts {
                messages_evicted: 30,
                dialogs_refused: 2,
                dialogs_rotated: 5,
            },
            ..CaptureFacts::default()
        };
        let analysis = analyze_with(&dialogs, &streams, None, &facts);
        let found = analysis
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::RetentionLoss)
            .expect("a cap that bit must be reported");
        assert_eq!(found.occurrences, 37);
        assert_eq!(found.evidence.len(), 3);
        assert!(!analysis.complete);
    }

    /// A capture with no SIP at all is still a capture worth analysing: a
    /// STUN-only file has a real finding in it, and the fixture
    /// `tests/fixtures/stun_nat_probe.pcap` is exactly that input.
    #[test]
    fn a_stun_only_capture_still_produces_a_finding() {
        let (dialogs, streams) = stores();
        let tx = crate::stun::StunTransaction {
            transaction_id: "aa".to_string(),
            client: "192.0.2.10:50000".parse().expect("valid addr"),
            server: "198.51.100.20:3478".parse().expect("valid addr"),
            method: 0x001,
            method_name: "Binding".to_string(),
            first_request: DateTime::from_timestamp_millis(0).expect("valid timestamp"),
            last_request: DateTime::from_timestamp_millis(500).expect("valid timestamp"),
            request_count: 2,
            responded_at: None,
            rtt_ms: None,
            mapped_address: None,
            relayed_address: None,
            peer_address: None,
            lifetime_secs: None,
            channel_number: None,
            error_code: None,
            auth_challenge: false,
            software: None,
            ice_role: None,
            use_candidate: false,
            fingerprint_valid: None,
        };
        let facts = CaptureFacts {
            frames_read: 2,
            stun: crate::stun::StunReport {
                transactions: vec![tx],
                packets: 2,
                ..Default::default()
            },
            ..CaptureFacts::default()
        };
        let analysis = analyze_with(&dialogs, &streams, None, &facts);
        assert!(!analysis.is_clean(), "an unanswered probe is a finding");
        assert!(
            analysis.complete,
            "an unanswered probe says nothing about whether sipnab read the file"
        );
        let found = &analysis.findings[0];
        assert_eq!(found.kind, FindingKind::UnansweredStunProbe);
        assert_eq!(found.severity, Severity::Major);
        assert_eq!(found.occurrences, 1);
        assert!(
            found.evidence[0]
                .endpoints
                .iter()
                .any(|e| e.contains("198.51.100.20:3478")),
            "the evidence must name the server: {:?}",
            found.evidence[0]
        );
        assert_eq!(found.evidence[0].counts.get("requests"), Some(&2));
    }
}
