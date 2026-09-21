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
    /// Every severity, in ladder order — worst first, which is also the sort
    /// order. The exhaustive `match` in [`Self::as_str`] is what makes a fifth
    /// rung a compile error until it is listed here too.
    pub const ALL: [Self; 4] = [Self::Blind, Self::Critical, Self::Major, Self::Minor];

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
/// One table rather than four parallel `match` statements over the same 27
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
    /// Two ICE agents on one pair claimed the same role, or answered `487`.
    IceRoleConflict,
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
    /// Every kind, in declaration order — the ladder, worst first.
    ///
    /// The machine contracts are generated from this list: the JSON Schema's
    /// `kind` enum is held to it, and the YANG module renders one identity per
    /// entry. A kind missing from it would be a finding sipnab emits and no
    /// published contract admits, so membership is not left to memory:
    /// [`Self::ordinal`] is an exhaustive `match`, a new variant does not
    /// compile until it has an arm there, and the assertion below this `impl`
    /// fails the build unless every entry here sits at its own ordinal.
    pub const ALL: [Self; 27] = [
        Self::UndecodableFrames,
        Self::SipDiscardedByPortRange,
        Self::SipDiscardedByWebSocketPorts,
        Self::RetentionLoss,
        Self::NoMedia,
        Self::OneWayAudio,
        Self::StunSdpMismatch,
        Self::IcmpUnreachableSignaling,
        Self::IcmpUnreachableMedia,
        Self::NatMismatch,
        Self::ServerFailure,
        Self::AuthLoop,
        Self::Retransmissions,
        Self::AckMissing,
        Self::RegistrationFailure,
        Self::UnansweredStunProbe,
        Self::TurnAllocationLapsed,
        Self::IceRoleConflict,
        Self::IcmpUnreachableEndpoint,
        Self::RequestFailure,
        Self::Abandoned,
        Self::PostDialDelay,
        Self::LateMedia,
        Self::CodecAsymmetry,
        Self::PtimeAsymmetry,
        Self::PayloadTypeAsymmetry,
        Self::DurationAsymmetry,
    ];

    /// This kind's position in [`Self::ALL`].
    ///
    /// Exhaustive on purpose, and written out rather than cast from the
    /// discriminant: adding a variant is a compile error HERE, beside the list
    /// it must also join, instead of a kind that silently never reaches the
    /// schema or the YANG module.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        match self {
            Self::UndecodableFrames => 0,
            Self::SipDiscardedByPortRange => 1,
            Self::SipDiscardedByWebSocketPorts => 2,
            Self::RetentionLoss => 3,
            Self::NoMedia => 4,
            Self::OneWayAudio => 5,
            Self::StunSdpMismatch => 6,
            Self::IcmpUnreachableSignaling => 7,
            Self::IcmpUnreachableMedia => 8,
            Self::NatMismatch => 9,
            Self::ServerFailure => 10,
            Self::AuthLoop => 11,
            Self::Retransmissions => 12,
            Self::AckMissing => 13,
            Self::RegistrationFailure => 14,
            Self::UnansweredStunProbe => 15,
            Self::TurnAllocationLapsed => 16,
            Self::IceRoleConflict => 17,
            Self::IcmpUnreachableEndpoint => 18,
            Self::RequestFailure => 19,
            Self::Abandoned => 20,
            Self::PostDialDelay => 21,
            Self::LateMedia => 22,
            Self::CodecAsymmetry => 23,
            Self::PtimeAsymmetry => 24,
            Self::PayloadTypeAsymmetry => 25,
            Self::DurationAsymmetry => 26,
        }
    }

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
                "sipnab recognized these as SIP and then threw them away because neither port \
                 was inside --portrange. They are in no dialog and no count. Widen the range \
                 (--portrange 1-65535 analyzes everything) and read the capture again.",
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
                 --limit or --max-streams and run it again.",
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
            Self::IceRoleConflict => m(
                "ice_role_conflict",
                Severity::Major,
                "ICE agents disagreed about who was controlling",
                "pair",
                "Both agents on a candidate pair claimed the same ICE role, or one answered 487 \
                 Role Conflict (RFC 8445 §7.3.1.1). ICE resolves this itself — the losing agent \
                 switches role and repeats every check it had already sent — so a conflict that \
                 resolved cost a round trip and nothing else. One that did NOT resolve is a \
                 candidate cause of media that never started, and the evidence says which of \
                 the two this is. The usual source is two endpoints configured with the same \
                 role, or a B2BUA relaying one side's role attribute to the other.",
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

// `ALL` is complete and in declaration order: every entry sits at its own
// ordinal AND at its own discriminant. The discriminant half is what catches a
// variant declared mid-ladder and left out of `ALL`, because every kind after
// it then sits one place early.
const _: () = {
    let mut i = 0;
    while i < FindingKind::ALL.len() {
        assert!(FindingKind::ALL[i].ordinal() == i);
        assert!(FindingKind::ALL[i] as usize == i);
        i += 1;
    }
};

impl serde::Serialize for FindingKind {
    /// Serializes as the stable [`KindMeta::id`], not as the Rust variant
    /// name, so renaming a variant cannot change a consumer's JSON.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.meta().id)
    }
}

/// The name of one integer in [`Evidence::counts`].
///
/// These were string literals at the call sites that wrote them, 25 of them
/// and no list: nothing could say which labels a consumer might meet, so no
/// schema could close the `counts` object and no YANG module could name them.
/// This is the list. Every label the analysis writes is a variant here, so a
/// new one cannot reach the JSON without joining the table the published
/// contracts are generated from.
///
/// Declared in alphabetical order of [`Self::as_str`], and ordered by that
/// text rather than by declaration, because `counts` is a `BTreeMap` and its
/// key order is the JSON's: the table must not reorder a single consumer's
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountLabel {
    /// `a_payload_type`: The RTP payload type number the A leg used, where both legs negotiated the same codec.
    APayloadType,
    /// `a_ptime_ms`: The packetization time the A leg framed its audio at, in milliseconds.
    APtimeMs,
    /// `answer_transmissions`: How many times the 2xx answer to an INVITE was transmitted with no ACK confirming it.
    AnswerTransmissions,
    /// `b_payload_type`: The RTP payload type number the B leg used, where both legs negotiated the same codec.
    BPayloadType,
    /// `b_ptime_ms`: The packetization time the B leg framed its audio at, in milliseconds.
    BPtimeMs,
    /// `challenges`: How many 401 or 407 authentication challenges the dialog drew without reaching a 2xx.
    Challenges,
    /// `delay_after_200_ok_ms`: Milliseconds from the 200 OK to the first RTP packet of the leg that started late.
    DelayAfter200OkMs,
    /// `dialogs`: Dialogs a store refused or discarded at its capacity limit.
    Dialogs,
    /// `errors_naming_no_call`: ICMP errors whose quoted bytes reached no tracked dialog.
    ErrorsNamingNoCall,
    /// `frames`: Frames that reached the parser and decoded to nothing.
    Frames,
    /// `frames_read`: Frames handed to the parser in the whole run: the denominator for the frames that decoded to nothing.
    FramesRead,
    /// `icmp_errors`: ICMP errors counted against this evidence row: one endpoint, one media flow, one dialog's request, or the errors a full tracking table could not attribute.
    IcmpErrors,
    /// `lifetime_secs`: The allocation lifetime the TURN server last granted, in seconds.
    LifetimeSecs,
    /// `messages`: SIP messages: those a port gate discarded, or those evicted from retained dialogs by idle compaction.
    Messages,
    /// `reasons_not_retained`: Distinct reasons frames failed to decode that were counted but not kept, because the reason table was full.
    ReasonsNotRetained,
    /// `refreshes`: TURN Refresh transactions seen for the allocation.
    Refreshes,
    /// `relayed_streams`: RTP streams the capture saw carried on the TURN relay.
    RelayedStreams,
    /// `requests`: STUN Binding Requests the client sent in one transaction that nothing answered.
    Requests,
    /// `role_conflict_responses`: 487 Role Conflict responses exchanged between the two ICE agents.
    RoleConflictResponses,
    /// `rtp_packets`: RTP packets carried by the streams linked to the dialog.
    RtpPackets,
    /// `status_code`: The SIP status code: the final response a call ended on, or the one a REGISTER was answered with.
    StatusCode,
    /// `streams`: RTP streams: those linked to the dialog, or those an ICMP error about a media flow affected.
    Streams,
    /// `stun_requests`: STUN requests the client sent that bear on the address its SDP advertised.
    StunRequests,
    /// `stun_transactions`: STUN transactions past the tracking cap, counted but not kept.
    StunTransactions,
    /// `transmissions`: How many times a request was transmitted with no response coming back.
    Transmissions,
}

impl CountLabel {
    /// Every label, in the order it serializes. The exhaustive matches in
    /// [`Self::as_str`] and [`Self::description`] make a new variant a
    /// compile error until it has a name and a description; the assertion
    /// after this `impl` fails the build unless it is listed here too.
    pub const ALL: [Self; 25] = [
        Self::APayloadType,
        Self::APtimeMs,
        Self::AnswerTransmissions,
        Self::BPayloadType,
        Self::BPtimeMs,
        Self::Challenges,
        Self::DelayAfter200OkMs,
        Self::Dialogs,
        Self::ErrorsNamingNoCall,
        Self::Frames,
        Self::FramesRead,
        Self::IcmpErrors,
        Self::LifetimeSecs,
        Self::Messages,
        Self::ReasonsNotRetained,
        Self::Refreshes,
        Self::RelayedStreams,
        Self::Requests,
        Self::RoleConflictResponses,
        Self::RtpPackets,
        Self::StatusCode,
        Self::Streams,
        Self::StunRequests,
        Self::StunTransactions,
        Self::Transmissions,
    ];

    /// The label as it appears in the JSON and in the text report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::APayloadType => "a_payload_type",
            Self::APtimeMs => "a_ptime_ms",
            Self::AnswerTransmissions => "answer_transmissions",
            Self::BPayloadType => "b_payload_type",
            Self::BPtimeMs => "b_ptime_ms",
            Self::Challenges => "challenges",
            Self::DelayAfter200OkMs => "delay_after_200_ok_ms",
            Self::Dialogs => "dialogs",
            Self::ErrorsNamingNoCall => "errors_naming_no_call",
            Self::Frames => "frames",
            Self::FramesRead => "frames_read",
            Self::IcmpErrors => "icmp_errors",
            Self::LifetimeSecs => "lifetime_secs",
            Self::Messages => "messages",
            Self::ReasonsNotRetained => "reasons_not_retained",
            Self::Refreshes => "refreshes",
            Self::RelayedStreams => "relayed_streams",
            Self::Requests => "requests",
            Self::RoleConflictResponses => "role_conflict_responses",
            Self::RtpPackets => "rtp_packets",
            Self::StatusCode => "status_code",
            Self::Streams => "streams",
            Self::StunRequests => "stun_requests",
            Self::StunTransactions => "stun_transactions",
            Self::Transmissions => "transmissions",
        }
    }

    /// One sentence saying what the number counts. Published as the YANG
    /// identity's description, so the module doubles as the label catalog.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::APayloadType => {
                "The RTP payload type number the A leg used, where both legs negotiated the same codec."
            }
            Self::APtimeMs => {
                "The packetization time the A leg framed its audio at, in milliseconds."
            }
            Self::AnswerTransmissions => {
                "How many times the 2xx answer to an INVITE was transmitted with no ACK confirming it."
            }
            Self::BPayloadType => {
                "The RTP payload type number the B leg used, where both legs negotiated the same codec."
            }
            Self::BPtimeMs => {
                "The packetization time the B leg framed its audio at, in milliseconds."
            }
            Self::Challenges => {
                "How many 401 or 407 authentication challenges the dialog drew without reaching a 2xx."
            }
            Self::DelayAfter200OkMs => {
                "Milliseconds from the 200 OK to the first RTP packet of the leg that started late."
            }
            Self::Dialogs => "Dialogs a store refused or discarded at its capacity limit.",
            Self::ErrorsNamingNoCall => "ICMP errors whose quoted bytes reached no tracked dialog.",
            Self::Frames => "Frames that reached the parser and decoded to nothing.",
            Self::FramesRead => {
                "Frames handed to the parser in the whole run: the denominator for the frames that decoded to nothing."
            }
            Self::IcmpErrors => {
                "ICMP errors counted against this evidence row: one endpoint, one media flow, one dialog's request, or the errors a full tracking table could not attribute."
            }
            Self::LifetimeSecs => {
                "The allocation lifetime the TURN server last granted, in seconds."
            }
            Self::Messages => {
                "SIP messages: those a port gate discarded, or those evicted from retained dialogs by idle compaction."
            }
            Self::ReasonsNotRetained => {
                "Distinct reasons frames failed to decode that were counted but not kept, because the reason table was full."
            }
            Self::Refreshes => "TURN Refresh transactions seen for the allocation.",
            Self::RelayedStreams => "RTP streams the capture saw carried on the TURN relay.",
            Self::Requests => {
                "STUN Binding Requests the client sent in one transaction that nothing answered."
            }
            Self::RoleConflictResponses => {
                "487 Role Conflict responses exchanged between the two ICE agents."
            }
            Self::RtpPackets => "RTP packets carried by the streams linked to the dialog.",
            Self::StatusCode => {
                "The SIP status code: the final response a call ended on, or the one a REGISTER was answered with."
            }
            Self::Streams => {
                "RTP streams: those linked to the dialog, or those an ICMP error about a media flow affected."
            }
            Self::StunRequests => {
                "STUN requests the client sent that bear on the address its SDP advertised."
            }
            Self::StunTransactions => {
                "STUN transactions past the tracking cap, counted but not kept."
            }
            Self::Transmissions => {
                "How many times a request was transmitted with no response coming back."
            }
        }
    }
}

// `CountLabel::ALL` holds every variant in declaration order.
const _: () = {
    let mut i = 0;
    while i < CountLabel::ALL.len() {
        assert!(CountLabel::ALL[i] as usize == i);
        i += 1;
    }
};

impl PartialOrd for CountLabel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CountLabel {
    /// By the label's text, so a `BTreeMap` keyed by labels orders its JSON
    /// keys exactly as it did when the keys were the strings themselves.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl std::borrow::Borrow<str> for CountLabel {
    /// Lets `counts.get("streams")` look a label up by name. Sound because
    /// [`Ord`] and [`PartialEq`] above agree with the text's own.
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for CountLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<&str> for CountLabel {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl serde::Serialize for CountLabel {
    /// Serializes as its text: a `counts` key, exactly as before the table.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
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
    pub counts: BTreeMap<CountLabel, u64>,
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
    fn count(mut self, label: CountLabel, value: u64) -> Self {
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

/// The version of [`CaptureAnalysis`]'s serialized shape.
///
/// `tests/schemas/capture_analysis.schema.json` pins it with `const`, the way
/// the message, dialog and stream schemas pin theirs. A change a consumer
/// would break on — a field removed, renamed or retyped — raises it; a new
/// optional field does not.
pub const CAPTURE_ANALYSIS_SCHEMA_VERSION: u32 = 1;

/// Everything `--analyze` found, ranked, with the denominators it found it in.
///
/// One value, several encodings: `--json-analyze`, `GET /v1/report` and the
/// MCP `get_capture_report` serialize it directly, and the RFC 7951 export is
/// a transform of that same serialization. A field added here reaches every
/// one of them; a field added to only one encoding would make the machine
/// renderings disagree about one analysis.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CaptureAnalysis {
    /// [`CAPTURE_ANALYSIS_SCHEMA_VERSION`]. First, so a consumer reads the
    /// shape it is holding before anything else in it.
    ///
    /// Every other JSON object sipnab emits carried one and this did not, so
    /// the one answer about a whole capture was also the one a consumer could
    /// not tell a future reshaping of.
    pub schema_version: u32,
    /// The filter expression that selected [`Self::dialogs_examined`], when
    /// one did; absent when every dialog was examined.
    ///
    /// Only the dialogs are narrowed — the capture-level findings never are
    /// (see [`analyze`]) — so without this a filtered analysis read exactly
    /// like a whole one that happened to hold fewer calls. The text is the
    /// expression that ran, after alias expansion: [`FilterExpr::source`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
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

impl Default for CaptureAnalysis {
    /// An empty analysis at the current [`CAPTURE_ANALYSIS_SCHEMA_VERSION`]:
    /// nothing read, nothing found, and `complete: false`, because nothing
    /// has established that anything was read in full. Every other field is
    /// what the derive used to produce; it is written out only because a
    /// derived default would stamp version 0 on every analysis built from it.
    fn default() -> Self {
        Self {
            schema_version: CAPTURE_ANALYSIS_SCHEMA_VERSION,
            filter: None,
            frames_read: 0,
            dialogs_examined: 0,
            streams_examined: 0,
            complete: false,
            findings: Vec::new(),
        }
    }
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
/// across runs and therefore diffable: two captures analyzed a week apart
/// produce lists that can be compared line by line, and a count that moved is
/// visible instead of being hidden by a reshuffle.
pub fn rank(findings: &mut [Finding]) {
    crate::sort::sort_by_dyn(findings, &mut |a, b| {
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
    /// Whether an operator stopped this run writing content partway through.
    ///
    /// Not a capture fault, unlike every other field here, and the container's
    /// wording keeps them apart: a reader who cannot tell a deliberate stop
    /// from a missed packet goes looking for a fault that does not exist.
    pub gate_closed_during_run: bool,
    /// Dialogs a deny flag in the signaling removed from this export.
    ///
    /// A decision recorded rather than a gap. Absent, the containers that DID
    /// get written read as the complete set for their predicate.
    pub dialogs_suppressed_by_deny: u64,
    /// Header lines dropped for exceeding the parser's length cap.
    ///
    /// VAL13. The cap keeps one runaway line from being unfolded into memory,
    /// so the bytes genuinely cannot be kept -- but a container that says "No
    /// omissions recorded" over a capture that lost a header is asserting
    /// something false about its own completeness, which is the one thing this
    /// struct exists to prevent.
    pub headers_dropped_oversize: u64,
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
            // Neither is observable from the stores: both are decisions this
            // process made, and the caller that made them sets them.
            gate_closed_during_run: false,
            dialogs_suppressed_by_deny: 0,
            headers_dropped_oversize: crate::sip::parser::oversize_headers_dropped(),
        }
    }
}

/// Analyze a finished capture and rank everything already diagnosed in it.
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
        schema_version: CAPTURE_ANALYSIS_SCHEMA_VERSION,
        filter: filter.map(|f| f.source().to_string()),
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
            .count(CountLabel::Streams, streams.len() as u64)
            .count(CountLabel::RtpPackets, packets);
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
        let mut note = match m.reason {
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
        };
        // The correlation is by client IP with no shared identifier, so STUN
        // evidence from well outside the call is an inference that the fault
        // persisted rather than something seen during setup. Same sentence the
        // dialog hint carries, from the same method — a qualification that
        // appeared on one surface and not the other would be worse than none.
        //
        // APPENDED to the reason, as the hint does, never in place of it: the
        // reason is the only part of this evidence that carries the address
        // STUN offered, and replacing it dropped that address in exactly the
        // case where the finding most needed checking.
        if let Some(caveat) = m.correlation_caveat() {
            note.push_str(" Note: ");
            note.push_str(&caveat);
        }
        let ev = Evidence::for_dialog(dialog)
            .endpoint(format!("STUN client {}", m.client))
            .endpoint(format!("SDP advertises {}", m.advertised))
            .count(CountLabel::StunRequests, u64::from(m.request_count))
            .note(note);
        acc.add(FindingKind::StunSdpMismatch, ev);
    }
    if let Some(ref late) = diag.late_media {
        acc.add(
            FindingKind::LateMedia,
            Evidence::for_dialog(dialog)
                .count(
                    CountLabel::DelayAfter200OkMs,
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
                .count(CountLabel::APtimeMs, u64::from(p.a_ptime_ms))
                .count(CountLabel::BPtimeMs, u64::from(p.b_ptime_ms)),
        );
    }
    if let Some(ref p) = diag.payload_type_asymmetry {
        acc.add(
            FindingKind::PayloadTypeAsymmetry,
            Evidence::for_dialog(dialog)
                .count(CountLabel::APayloadType, u64::from(p.a_pt))
                .count(CountLabel::BPayloadType, u64::from(p.b_pt)),
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
    fold_signaling(acc, dialog, &diag);
}

/// Fold an already-computed signaling diagnosis into the accumulator.
///
/// Split from [`collect_signaling`] so the conversion can be driven with a
/// diagnosis stated outright, the way [`collect_media`] already is: building a
/// message sequence that trips each of the eight it converts would test the
/// diagnoser, not this mapping.
fn fold_signaling(
    acc: &mut Accumulator,
    dialog: &SipDialog,
    diag: &crate::sip::diagnosis::SignalingDiagnosis,
) {
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
                .count(CountLabel::StatusCode, u64::from(f.code))
                .note(note),
        );
    }
    if let Some(ref a) = diag.auth_loop {
        acc.add(
            FindingKind::AuthLoop,
            Evidence::for_dialog(dialog)
                .count(CountLabel::Challenges, a.challenges as u64)
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
                .count(CountLabel::Transmissions, r.count as u64)
                .note(note),
        );
    }
    if let Some(ref a) = diag.ack_missing {
        acc.add(
            FindingKind::AckMissing,
            Evidence::for_dialog(dialog)
                .count(
                    CountLabel::AnswerTransmissions,
                    a.answer_transmissions as u64,
                )
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
                .count(CountLabel::StatusCode, u64::from(r.code))
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
                .count(CountLabel::IcmpErrors, i.errors as u64)
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
                .count(CountLabel::Requests, u64::from(tx.request_count))
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
            .count(CountLabel::Refreshes, u64::from(alloc.refreshes))
            .at_time(alloc.allocated_at);
        if let Some(secs) = alloc.lifetime_secs {
            ev = ev.count(CountLabel::LifetimeSecs, u64::from(secs));
        }
        if let Some(relayed) = alloc.relayed_address {
            ev = ev.endpoint(format!("relayed {relayed}"));
        }
        // Which media died with it. The finding could always say an
        // allocation lapsed and could never say what was ON it, so an
        // operator had no way to get from "a relay was torn down" to the call
        // that went quiet. The streams are named by SSRC because that is the
        // key the stream list is sorted by, and the channel because that is
        // what a follow-up capture has to filter on.
        let streams = alloc.relayed_ssrcs();
        if !streams.is_empty() {
            ev = ev.count(CountLabel::RelayedStreams, streams.len() as u64);
        }
        if let Some(label) = alloc.relayed_media_label() {
            ev = ev.endpoint(format!("media {label}"));
        }
        acc.add(
            FindingKind::TurnAllocationLapsed,
            ev.note(
                "traffic continued on this relay after the lifetime it was last granted had \
                 run out, with no Refresh seen in between",
            ),
        );
    }

    // ── ICE: the two agents disagreed about who was in charge ────────
    //
    // Only the role conflict is raised here. The other two things ICE says
    // are deliberately not findings: a NOMINATED pair is an answer rather
    // than a problem (it belongs in `--stun`, beside the mapped address it is
    // the ICE analogue of), and connectivity checks that all went unanswered
    // are ALREADY reported one by one as `unanswered_stun_probe` — a second
    // finding over the same transactions would report one silence twice.
    for conflict in &facts.stun.ice_summary().role_conflicts {
        let mut ev = Evidence::default()
            .endpoint(conflict.a.to_string())
            .endpoint(conflict.b.to_string())
            .count(
                CountLabel::RoleConflictResponses,
                u64::from(conflict.role_conflict_responses),
            );
        if let Some(role) = conflict.role {
            ev = ev.endpoint(format!("both claimed {}", role.label()));
        }
        acc.add(
            FindingKind::IceRoleConflict,
            ev.note(if conflict.resolved {
                "ICE resolved this itself and a pair was nominated anyway, so it cost a round \
                 trip of repeated checks rather than the call"
            } else {
                "no candidate pair between these two was ever nominated, so this is a \
                 candidate cause of media that never started"
            }),
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
            .count(CountLabel::IcmpErrors, flow.errors)
            .count(CountLabel::Streams, flow.streams as u64)
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
            Evidence::default().count(CountLabel::ErrorsNamingNoCall, facts.icmp.unattributed),
        );
        // Every endpoint goes through the accumulator, which keeps what fits
        // under the cap and COUNTS the rest: a `take` here dropped them before
        // the cap could see them, and the list read as complete.
        for endpoint in &facts.icmp.endpoints {
            acc.bump(
                FindingKind::IcmpUnreachableEndpoint,
                0,
                Evidence::default()
                    .endpoint(match endpoint.port {
                        Some(p) => format!("{}:{p}", endpoint.addr),
                        None => endpoint.addr.to_string(),
                    })
                    .count(CountLabel::IcmpErrors, endpoint.errors)
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
            .count(CountLabel::Frames, undecodable.frames)
            .count(CountLabel::FramesRead, facts.frames_read)
            .note(undecodable.reason_list());
        if undecodable.reasons_dropped > 0 {
            ev = ev.count(CountLabel::ReasonsNotRetained, undecodable.reasons_dropped);
        }
        acc.bump(FindingKind::UndecodableFrames, undecodable.frames, ev);
    }

    // ── SIP a port gate threw away ───────────────────────────────────
    //
    // Every port is bumped, not only the ones that fit on a row: the count is
    // exact and the accumulator caps the rows and counts what it left out.
    // Stopping at the cap summed only the busiest ports' messages and reported
    // that as the total.
    for port in &facts.portrange.ports {
        acc.bump(
            FindingKind::SipDiscardedByPortRange,
            port.messages,
            Evidence::default()
                .endpoint(format!("port {}", port.port))
                .count(CountLabel::Messages, port.messages),
        );
    }
    for port in &facts.websocket.ports {
        acc.bump(
            FindingKind::SipDiscardedByWebSocketPorts,
            port.messages,
            Evidence::default()
                .endpoint(format!("port {}", port.port))
                .count(CountLabel::Messages, port.messages),
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
                .count(CountLabel::Messages, msgs)
                .note("messages evicted from retained dialogs by idle compaction (--limit)"),
        );
    }
    if refused > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            refused,
            Evidence::default()
                .count(CountLabel::Dialogs, refused)
                .note("new dialogs refused at capacity (--no-rotate keeps the earliest)"),
        );
    }
    if rotated > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            rotated,
            Evidence::default()
                .count(CountLabel::Dialogs, rotated)
                .note("oldest dialogs discarded at capacity by rotation (--limit)"),
        );
    }
    if facts.stun.dropped > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            facts.stun.dropped,
            Evidence::default()
                .count(CountLabel::StunTransactions, facts.stun.dropped)
                .note("STUN transactions past the tracking cap — the packet count stays exact"),
        );
    }
    if facts.icmp.untracked_dialogs > 0 {
        acc.bump(
            FindingKind::RetentionLoss,
            facts.icmp.untracked_dialogs,
            Evidence::default()
                .count(CountLabel::IcmpErrors, facts.icmp.untracked_dialogs)
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

    /// The count-label table is complete, unique, snake case, described, and
    /// in the order the JSON has always carried its keys: alphabetical.
    ///
    /// Alphabetical is not a style preference. `Evidence::counts` is a
    /// `BTreeMap`, so its key order IS the JSON key order, and it was the
    /// order of the string literals this table replaced. A label table that
    /// sorted any other way would reorder every consumer's `counts` object.
    #[test]
    fn the_count_label_table_is_unique_sorted_and_described() {
        let names: Vec<&str> = CountLabel::ALL.iter().map(|l| l.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            names, sorted,
            "CountLabel::ALL is not unique and alphabetical"
        );
        for label in CountLabel::ALL {
            let name = label.as_str();
            assert!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "`{name}` is not a snake_case label"
            );
            assert!(
                label.description().ends_with('.') && label.description().len() > 20,
                "`{name}` has no real description: {:?}",
                label.description()
            );
            assert_eq!(label.to_string(), name, "Display must print the label");
        }
    }

    /// A label orders, compares and looks up exactly as its text does.
    ///
    /// `Borrow<str>` promises that, and `BTreeMap::get("streams")` relies on
    /// it: an `Ord` that disagreed with the text would make a lookup by name
    /// miss a key that is present.
    #[test]
    fn a_count_label_orders_and_looks_up_as_its_text() {
        for a in CountLabel::ALL {
            for b in CountLabel::ALL {
                assert_eq!(a.cmp(&b), a.as_str().cmp(b.as_str()), "{a} vs {b}");
                assert_eq!(a == b, a.as_str() == b.as_str(), "{a} vs {b}");
            }
        }
        let ev = Evidence::default()
            .count(CountLabel::Streams, 2)
            .count(CountLabel::RtpPackets, 425);
        assert_eq!(ev.counts.get("streams"), Some(&2));
        assert_eq!(ev.counts.get("rtp_packets"), Some(&425));
        assert_eq!(
            serde_json::to_string(&ev.counts).expect("serializes"),
            r#"{"rtp_packets":425,"streams":2}"#,
            "a label serializes as its text, in text order"
        );
    }

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

    /// A dialog with one INVITE, for the media-finding tests.
    fn media_dialog() -> SipDialog {
        let raw = "INVITE sip:bob@example.invalid SIP/2.0\r\n\
                   Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1\r\n\
                   From: <sip:alice@example.invalid>;tag=a1\r\n\
                   To: <sip:bob@example.invalid>\r\n\
                   Call-ID: media-findings@example.invalid\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\r\n";
        let msg = crate::sip::parser::parse_sip_bytes(
            &bytes::Bytes::from_static(raw.as_bytes()),
            chrono::Utc::now(),
            "198.51.100.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("the fixture INVITE parses");
        SipDialog::new(&msg).expect("it opens a dialog")
    }

    /// Run `collect_media` over one diagnosis and return what it accumulated.
    fn media_findings(diag: crate::rtp::diagnosis::MediaDiagnosis) -> Vec<Finding> {
        let dialog = media_dialog();
        let mut acc = Accumulator::default();
        collect_media(&mut acc, &dialog, &[], &diag);
        acc.into_findings()
    }

    /// Each asymmetry keeps the leg it was measured on.
    ///
    /// Four arms of one `if let` chain, each pulling two fields off a struct
    /// whose members differ only by an `a_`/`b_` prefix. That is the shape a
    /// copy-paste swap survives in: the finding still appears, the numbers are
    /// still both present, and an operator reads the A leg's packetization as
    /// the B leg's. Distinct values per leg are what makes a swap visible.
    #[test]
    fn each_asymmetry_finding_keeps_the_leg_it_was_measured_on() {
        use crate::rtp::diagnosis::{
            CodecAsymmetry, DurationAsymmetry, MediaDiagnosis, PayloadTypeAsymmetry, PtimeAsymmetry,
        };
        let diag = MediaDiagnosis {
            codec_asymmetry: Some(CodecAsymmetry {
                a_codec: "PCMU".to_string(),
                b_codec: "G729".to_string(),
            }),
            ptime_asymmetry: Some(PtimeAsymmetry {
                a_ptime_ms: 20,
                b_ptime_ms: 30,
            }),
            payload_type_asymmetry: Some(PayloadTypeAsymmetry { a_pt: 0, b_pt: 18 }),
            duration_asymmetry: Some(DurationAsymmetry {
                a_duration_sec: 12.5,
                b_duration_sec: 3.25,
                delta_sec: 9.25,
            }),
            ..MediaDiagnosis::default()
        };
        let found = media_findings(diag);
        let of = |k: FindingKind| {
            found
                .iter()
                .find(|f| f.kind == k)
                .unwrap_or_else(|| panic!("{k:?} was not reported"))
        };
        let counts = |f: &Finding| -> Vec<(String, u64)> {
            f.evidence
                .iter()
                .flat_map(|e| e.counts.iter().map(|(k, v)| ((*k).to_string(), *v)))
                .collect()
        };

        let ptime = counts(of(FindingKind::PtimeAsymmetry));
        assert!(
            ptime.contains(&("a_ptime_ms".to_string(), 20)),
            "the A leg's 20ms must be reported as the A leg's: {ptime:?}"
        );
        assert!(
            ptime.contains(&("b_ptime_ms".to_string(), 30)),
            "and the B leg's 30ms as the B leg's: {ptime:?}"
        );

        let pt = counts(of(FindingKind::PayloadTypeAsymmetry));
        assert!(
            pt.contains(&("a_payload_type".to_string(), 0)),
            "payload type 0 was on the A leg: {pt:?}"
        );
        assert!(
            pt.contains(&("b_payload_type".to_string(), 18)),
            "and 18 on the B leg: {pt:?}"
        );

        let codec_notes: Vec<&str> = of(FindingKind::CodecAsymmetry)
            .evidence
            .iter()
            .filter_map(|e| e.note.as_deref())
            .collect();
        assert!(
            codec_notes
                .iter()
                .any(|n| n.contains("A leg PCMU") && n.contains("B leg G729")),
            "each codec must be named against its own leg: {codec_notes:?}"
        );

        let dur_notes: Vec<&str> = of(FindingKind::DurationAsymmetry)
            .evidence
            .iter()
            .filter_map(|e| e.note.as_deref())
            .collect();
        assert!(
            dur_notes
                .iter()
                .any(|n| n.contains("A leg 12.5s") && n.contains("B leg 3.2")),
            "the longer leg is the A leg here, and must read that way: {dur_notes:?}"
        );
    }

    /// Late media names the leg that started late and how late it was.
    ///
    /// The delay is clamped with `.max(0)` before the cast to `u64`. A
    /// negative delay is nonsense the clamp exists to absorb — without it the
    /// cast wraps and an operator reads billions of milliseconds.
    #[test]
    fn late_media_reports_the_leg_and_survives_a_negative_delay() {
        use crate::rtp::diagnosis::{LateMedia, MediaDiagnosis};
        let found = media_findings(MediaDiagnosis {
            late_media: Some(LateMedia {
                leg: "b".to_string(),
                delay_after_200_ok_ms: 4200,
            }),
            ..MediaDiagnosis::default()
        });
        let f = found
            .iter()
            .find(|f| f.kind == FindingKind::LateMedia)
            .expect("late media is reported");
        assert!(
            f.evidence.iter().any(|e| e
                .counts
                .iter()
                .any(|(k, v)| *k == "delay_after_200_ok_ms" && *v == 4200)),
            "the delay is carried as measured"
        );
        assert!(
            f.evidence
                .iter()
                .filter_map(|e| e.note.as_deref())
                .any(|n| n.contains("b leg")),
            "and names the leg that was late"
        );

        // A negative delay must clamp to zero rather than wrap through the
        // cast into an enormous positive number.
        let found = media_findings(MediaDiagnosis {
            late_media: Some(LateMedia {
                leg: "a".to_string(),
                delay_after_200_ok_ms: -1,
            }),
            ..MediaDiagnosis::default()
        });
        let delay = found
            .iter()
            .find(|f| f.kind == FindingKind::LateMedia)
            .and_then(|f| {
                f.evidence
                    .iter()
                    .flat_map(|e| e.counts.iter())
                    .find(|(k, _)| **k == "delay_after_200_ok_ms")
                    .map(|(_, v)| *v)
            })
            .expect("a delay is reported");
        assert_eq!(
            delay, 0,
            "a negative delay clamps to zero; wrapping would report {delay}ms"
        );
    }

    /// A diagnosis with nothing wrong produces no media findings.
    ///
    /// The paired half: a chain of `if let Some` arms that fired on a default
    /// diagnosis would put a fault in front of an operator on every clean call.
    #[test]
    fn a_clean_diagnosis_produces_no_media_findings() {
        let found = media_findings(crate::rtp::diagnosis::MediaDiagnosis::default());
        assert!(
            found.is_empty(),
            "a clean call must raise nothing: {:?}",
            found.iter().map(|f| f.kind).collect::<Vec<_>>()
        );
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
            FindingKind::TurnAllocationLapsed,
            FindingKind::IceRoleConflict,
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

    /// A capture with no SIP at all is still a capture worth analyzing: a
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
            priority: None,
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

    // ── The conversions from each diagnosis into evidence ────────────

    /// The one finding of `kind`, or a panic naming what was reported instead.
    fn only(found: &[Finding], kind: FindingKind) -> &Finding {
        found.iter().find(|f| f.kind == kind).unwrap_or_else(|| {
            panic!(
                "{kind:?} was not reported; got {:?}",
                found.iter().map(|f| f.kind).collect::<Vec<_>>()
            )
        })
    }

    /// The note on a finding's first evidence row.
    fn first_note(f: &Finding) -> &str {
        f.evidence[0]
            .note
            .as_deref()
            .unwrap_or_else(|| panic!("{:?} carries no note: {:?}", f.kind, f.evidence[0]))
    }

    /// An RTP stream from `src` to `dst` that carried `packets` packets.
    fn rtp_stream(src: &str, dst: &str, packets: u64) -> crate::rtp::stream::RtpStream {
        let key = crate::rtp::stream::StreamKey {
            ssrc: 0x0102_0304,
            src: src.parse().expect("a literal socket address parses"),
            dst: dst.parse().expect("a literal socket address parses"),
        };
        let hdr = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 160,
            ssrc: key.ssrc,
            payload_offset: 12,
        };
        let mut s = crate::rtp::stream::RtpStream::new(key, &hdr, Utc::now());
        s.packet_count = packets;
        s
    }

    /// The report tag and the JSON tag are one word per rung. Two spellings
    /// of the same severity is how a consumer filtering on `"critical"`
    /// misses the rows the text report calls critical.
    #[test]
    fn severity_tags_are_the_words_reports_and_json_both_use() {
        for (sev, tag) in [
            (Severity::Blind, "blind"),
            (Severity::Critical, "critical"),
            (Severity::Major, "major"),
            (Severity::Minor, "minor"),
        ] {
            assert_eq!(sev.as_str(), tag);
            assert_eq!(
                serde_json::to_value(sev).expect("a severity serializes"),
                serde_json::Value::String(tag.to_string()),
                "the JSON tag must be the report's tag"
            );
        }
    }

    /// A finding serializes its kind as the stable id, never the Rust variant
    /// name, so renaming a variant cannot change a consumer's JSON.
    #[test]
    fn a_finding_kind_serializes_as_its_stable_id() {
        let json = serde_json::to_value(finding(FindingKind::SipDiscardedByWebSocketPorts, 3))
            .expect("a finding serializes");
        assert_eq!(json["kind"], "sip_discarded_by_websocket_ports");
        assert_eq!(json["severity"], "blind");
        assert_eq!(json["occurrences"], 3);
        assert_eq!(json["unit"], "message");
    }

    /// `at` narrows to one rung and keeps the ranked order within it.
    #[test]
    fn at_selects_only_the_findings_of_one_severity() {
        let mut findings = vec![
            finding(FindingKind::PostDialDelay, 9),
            finding(FindingKind::AuthLoop, 1),
            finding(FindingKind::NoMedia, 4),
            finding(FindingKind::ServerFailure, 6),
        ];
        rank(&mut findings);
        let analysis = CaptureAnalysis {
            findings,
            ..CaptureAnalysis::default()
        };
        let major: Vec<FindingKind> = analysis.at(Severity::Major).map(|f| f.kind).collect();
        assert_eq!(
            major,
            vec![FindingKind::ServerFailure, FindingKind::AuthLoop],
            "only the Major rung, busiest first"
        );
        assert_eq!(analysis.at(Severity::Blind).count(), 0);
    }

    /// No media, and a NAT mismatch, both carry the media path: what the SDP
    /// asked for, what arrived, and how much of it -- the three facts an
    /// operator checks against the capture before believing either.
    #[test]
    fn media_path_findings_carry_what_the_sdp_asked_for_and_what_arrived() {
        use crate::rtp::diagnosis::MediaDiagnosis;
        let dialog = media_dialog();
        let a = rtp_stream("203.0.113.9:4000", "198.51.100.1:5004", 5);
        let b = rtp_stream("198.51.100.1:5004", "203.0.113.9:4000", 7);
        let diag = MediaDiagnosis {
            nat_mismatch: true,
            sdp_media: Some("198.51.100.2:5004".to_string()),
            actual_media: Some("203.0.113.9:4000".to_string()),
            ..MediaDiagnosis::default()
        };
        let mut acc = Accumulator::default();
        collect_media(&mut acc, &dialog, &[&a, &b], &diag);
        let found = acc.into_findings();

        let nat = only(&found, FindingKind::NatMismatch);
        let ev = &nat.evidence[0];
        assert_eq!(
            ev.call_id.as_deref(),
            Some("media-findings@example.invalid")
        );
        assert_eq!(ev.counts.get("streams"), Some(&2));
        assert_eq!(
            ev.counts.get("rtp_packets"),
            Some(&12),
            "packets are summed across every stream of the dialog"
        );
        assert_eq!(
            ev.endpoints,
            vec![
                "198.51.100.1:5060 -> 198.51.100.2".to_string(),
                "SDP 198.51.100.2:5004".to_string(),
                "RTP from 203.0.113.9:4000".to_string(),
            ]
        );

        // No media: nothing arrived, so there is no RTP source to name.
        let found = media_findings(MediaDiagnosis {
            no_media: true,
            sdp_media: Some("198.51.100.2:5004".to_string()),
            ..MediaDiagnosis::default()
        });
        let none = only(&found, FindingKind::NoMedia);
        assert_eq!(none.severity, Severity::Critical);
        assert_eq!(none.evidence[0].counts.get("rtp_packets"), Some(&0));
        assert!(
            !none.evidence[0]
                .endpoints
                .iter()
                .any(|e| e.starts_with("RTP from")),
            "an RTP source nobody observed must not be invented: {:?}",
            none.evidence[0].endpoints
        );
    }

    /// One-way audio names the direction that DID carry audio. "One-way"
    /// without a direction is half an answer, and the missing half is the one
    /// that says which endpoint to go and look at.
    #[test]
    fn one_way_audio_names_the_direction_that_carried_audio() {
        let dialog = media_dialog();
        let heard = rtp_stream("203.0.113.9:4000", "198.51.100.1:5004", 250);
        let silent = rtp_stream("198.51.100.1:5004", "203.0.113.9:4000", 3);
        let diag = crate::rtp::diagnosis::MediaDiagnosis {
            one_way_audio: true,
            ..Default::default()
        };
        let mut acc = Accumulator::default();
        collect_media(&mut acc, &dialog, &[&silent, &heard], &diag);
        let found = acc.into_findings();

        let note = first_note(only(&found, FindingKind::OneWayAudio));
        assert_eq!(
            note,
            "203.0.113.9:4000 -> 198.51.100.1:5004 carried 250 packet(s); nothing came back \
             the other way",
            "the busier stream is the direction that was heard"
        );
    }

    /// A STUN/SDP mismatch for the given reason, with one address of each kind.
    fn stun_mismatch(
        reason: crate::rtp::diagnosis::StunSdpMismatchReason,
        observed_offset_secs: Option<i64>,
    ) -> crate::rtp::diagnosis::StunSdpMismatch {
        crate::rtp::diagnosis::StunSdpMismatch {
            client: "10.0.0.5:50000".to_string(),
            mapped_address: Some("203.0.113.5:61000".to_string()),
            relayed_address: Some("198.51.100.50:49152".to_string()),
            server: "198.51.100.20:3478".to_string(),
            advertised: "10.0.0.5:4000".to_string(),
            request_count: 3,
            reason,
            observed_offset_secs,
        }
    }

    /// The findings a dialog raises for one STUN/SDP mismatch.
    fn stun_findings(m: crate::rtp::diagnosis::StunSdpMismatch) -> Vec<Finding> {
        media_findings(crate::rtp::diagnosis::MediaDiagnosis {
            private_media_address: true,
            stun_sdp_mismatch: Some(m),
            ..Default::default()
        })
    }

    /// Each of the three ways STUN contradicts an SDP is explained in its own
    /// words, and carries the address STUN actually offered -- the one fact in
    /// the evidence the endpoints do not already hold.
    #[test]
    fn each_stun_sdp_mismatch_reason_is_explained_in_its_own_words() {
        use crate::rtp::diagnosis::StunSdpMismatchReason as Why;

        let found = stun_findings(stun_mismatch(Why::Ignored, None));
        let f = only(&found, FindingKind::StunSdpMismatch);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(
            first_note(f),
            "STUN answered with 203.0.113.5:61000 and the SDP advertised 10.0.0.5:4000 regardless"
        );
        assert!(
            f.evidence[0]
                .endpoints
                .contains(&"STUN client 10.0.0.5:50000".to_string())
                && f.evidence[0]
                    .endpoints
                    .contains(&"SDP advertises 10.0.0.5:4000".to_string()),
            "{:?}",
            f.evidence[0].endpoints
        );
        assert_eq!(f.evidence[0].counts.get("stun_requests"), Some(&3));

        let found = stun_findings(stun_mismatch(Why::RelayIgnored, None));
        assert_eq!(
            first_note(only(&found, FindingKind::StunSdpMismatch)),
            "TURN allocated the relayed address 198.51.100.50:49152 and the SDP advertised \
             10.0.0.5:4000 regardless"
        );

        let found = stun_findings(stun_mismatch(Why::Unanswered, None));
        let note = first_note(only(&found, FindingKind::StunSdpMismatch));
        assert!(
            note.starts_with("3 request(s) drew no STUN response")
                && note.ends_with("advertised 10.0.0.5:4000"),
            "{note}"
        );
    }

    /// A mismatch whose STUN evidence carries no address still reads as a
    /// sentence, rather than printing an empty slot where the address was.
    #[test]
    fn a_stun_mismatch_with_no_recorded_address_still_reads_as_a_sentence() {
        use crate::rtp::diagnosis::StunSdpMismatchReason as Why;
        let mut m = stun_mismatch(Why::Ignored, None);
        m.mapped_address = None;
        let found = stun_findings(m);
        assert!(
            first_note(only(&found, FindingKind::StunSdpMismatch))
                .starts_with("STUN answered with a public address and"),
        );

        let mut m = stun_mismatch(Why::RelayIgnored, None);
        m.relayed_address = None;
        let found = stun_findings(m);
        assert!(
            first_note(only(&found, FindingKind::StunSdpMismatch))
                .starts_with("TURN allocated the relayed address a relayed address and"),
        );
    }

    /// STUN evidence seen well outside the call is QUALIFIED, not replaced.
    ///
    /// The caveat says the correlation is by client IP alone. It qualifies the
    /// reason -- it does not stand in for it -- and the dialog hint built from
    /// the same method appends it to the reason for that reason. Replacing the
    /// note dropped the mapped address, which appears nowhere else in the
    /// evidence, exactly when the finding most needed checking.
    #[test]
    fn a_stun_caveat_qualifies_the_reason_rather_than_replacing_it() {
        use crate::rtp::diagnosis::StunSdpMismatchReason as Why;
        let found = stun_findings(stun_mismatch(Why::Ignored, Some(-600)));
        let note = first_note(only(&found, FindingKind::StunSdpMismatch));
        assert!(
            note.contains("STUN answered with 203.0.113.5:61000"),
            "the reason, and the address STUN offered, must survive the caveat: {note}"
        );
        assert!(
            note.contains("10 minute(s) before this call"),
            "and the caveat must still be said: {note}"
        );

        // Inside the correlation window there is nothing to qualify.
        let found = stun_findings(stun_mismatch(Why::Ignored, Some(30)));
        let note = first_note(only(&found, FindingKind::StunSdpMismatch));
        assert!(!note.contains("minute(s)"), "{note}");
    }

    /// The findings one stated signaling diagnosis raises for the fixture
    /// dialog.
    fn signaling_findings(diag: crate::sip::diagnosis::SignalingDiagnosis) -> Vec<Finding> {
        let dialog = media_dialog();
        let mut acc = Accumulator::default();
        fold_signaling(&mut acc, &dialog, &diag);
        acc.into_findings()
    }

    /// A final failure on `code` with no Reason or Warning header.
    fn failed_on(code: u16, phrase: &str) -> crate::sip::diagnosis::SignalingDiagnosis {
        crate::sip::diagnosis::SignalingDiagnosis {
            final_failure: Some(crate::sip::diagnosis::FinalFailure {
                code,
                reason_phrase: phrase.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// [RFC 3261 section 21](https://www.rfc-editor.org/rfc/rfc3261#section-21) splits final failures at 500: a 4xx is a request failure
    /// that is routinely an ordinary outcome, a 5xx or 6xx is a server or a
    /// global refusal. The boundary codes on either side prove the split sits
    /// exactly there.
    #[test]
    fn a_final_failure_splits_at_500_into_request_and_server_failure() {
        for (code, kind) in [
            (486, FindingKind::RequestFailure),
            (499, FindingKind::RequestFailure),
            (500, FindingKind::ServerFailure),
            (603, FindingKind::ServerFailure),
        ] {
            let found = signaling_findings(failed_on(code, "Done"));
            assert_eq!(found.len(), 1, "{code}: {found:?}");
            assert_eq!(found[0].kind, kind, "{code} is a {kind:?}");
            assert_eq!(
                found[0].evidence[0].counts.get("status_code"),
                Some(&u64::from(code))
            );
        }
    }

    /// The Reason and Warning headers ride along with the reason phrase: they
    /// are where a server says WHY, and they are otherwise invisible in a
    /// ranked list.
    #[test]
    fn a_final_failure_note_carries_the_reason_and_warning_headers() {
        let mut diag = failed_on(503, "Service Unavailable");
        if let Some(f) = diag.final_failure.as_mut() {
            f.reason_header = Some("Q.850;cause=34".to_string());
            f.warning = Some("399 sbc \"trunk down\"".to_string());
        }
        let found = signaling_findings(diag);
        assert_eq!(
            first_note(only(&found, FindingKind::ServerFailure)),
            "Service Unavailable (Reason: Q.850;cause=34) (Warning: 399 sbc \"trunk down\")"
        );

        let found = signaling_findings(failed_on(486, "Busy Here"));
        assert_eq!(
            first_note(only(&found, FindingKind::RequestFailure)),
            "Busy Here",
            "absent headers add nothing to the phrase"
        );
    }

    /// The two authentication loops send the operator to different places --
    /// provisioning for one, the client or a proxy for the other -- so the
    /// note has to say which it is.
    #[test]
    fn an_auth_loop_names_which_of_the_two_loops_it_is() {
        use crate::sip::diagnosis::{AuthLoop, AuthLoopKind, SignalingDiagnosis};
        let loop_of = |kind| {
            signaling_findings(SignalingDiagnosis {
                auth_loop: Some(AuthLoop {
                    kind,
                    challenges: 4,
                    evidence: Vec::new(),
                }),
                ..Default::default()
            })
        };

        let found = loop_of(AuthLoopKind::CredentialFailure);
        let f = only(&found, FindingKind::AuthLoop);
        assert_eq!(f.evidence[0].counts.get("challenges"), Some(&4));
        assert!(
            first_note(f).contains("wrong credentials"),
            "{}",
            first_note(f)
        );

        let found = loop_of(AuthLoopKind::SilentDrop);
        let note = first_note(only(&found, FindingKind::AuthLoop));
        assert!(note.contains("never sends Authorization"), "{note}");
    }

    /// A retransmitted request reports what was sent, how often, over how
    /// long -- and, where ICMP said why, that too.
    #[test]
    fn retransmissions_report_the_method_count_span_and_any_icmp_cause() {
        use crate::sip::diagnosis::{Retransmissions, SignalingDiagnosis};
        let retx = |icmp_cause: Option<&str>| {
            signaling_findings(SignalingDiagnosis {
                retransmissions: Some(Retransmissions {
                    method: "INVITE".to_string(),
                    count: 7,
                    span_sec: 31.5,
                    evidence: Vec::new(),
                    icmp_cause: icmp_cause.map(str::to_string),
                }),
                ..Default::default()
            })
        };

        let found = retx(None);
        let f = only(&found, FindingKind::Retransmissions);
        assert_eq!(f.evidence[0].counts.get("transmissions"), Some(&7));
        assert_eq!(
            first_note(f),
            "INVITE transmitted 7 time(s) over 31.5s with no response"
        );

        let found = retx(Some("port unreachable"));
        assert_eq!(
            first_note(only(&found, FindingKind::Retransmissions)),
            "INVITE transmitted 7 time(s) over 31.5s with no response; ICMP said: port unreachable"
        );
    }

    /// An answered INVITE nobody acknowledged reports how long it waited and
    /// how many times the answer was repeated.
    #[test]
    fn a_missing_ack_reports_the_wait_and_the_answer_retransmissions() {
        let found = signaling_findings(crate::sip::diagnosis::SignalingDiagnosis {
            ack_missing: Some(crate::sip::diagnosis::AckMissing {
                waited_sec: 32.25,
                answer_transmissions: 11,
                evidence: Vec::new(),
            }),
            ..Default::default()
        });
        let f = only(&found, FindingKind::AckMissing);
        assert_eq!(f.severity, Severity::Major);
        assert_eq!(f.evidence[0].counts.get("answer_transmissions"), Some(&11));
        assert_eq!(first_note(f), "32.2s elapsed with no ACK");
    }

    /// An abandoned call says whether the caller hung up or the capture
    /// simply stopped: the second is a statement about the recording, and
    /// reading it as a call fault sends an operator after nothing.
    #[test]
    fn an_abandoned_call_distinguishes_a_cancel_from_a_capture_that_stopped() {
        use crate::sip::diagnosis::{Abandoned, AbandonedKind, SignalingDiagnosis};
        let abandoned = |kind| {
            signaling_findings(SignalingDiagnosis {
                abandoned: Some(Abandoned {
                    kind,
                    elapsed_sec: 4.0,
                    evidence: Vec::new(),
                }),
                ..Default::default()
            })
        };
        let found = abandoned(AbandonedKind::Canceled);
        assert_eq!(
            first_note(only(&found, FindingKind::Abandoned)),
            "CANCEL after 4.0s — the caller hung up"
        );
        let found = abandoned(AbandonedKind::NoFinalResponse);
        let note = first_note(only(&found, FindingKind::Abandoned));
        assert!(
            note.starts_with("no final response in 4.0s") && note.contains("capture stopped"),
            "{note}"
        );
    }

    /// Slow ring-back reports the delay beside the threshold it broke, so a
    /// near miss and a disaster do not read the same.
    #[test]
    fn post_dial_delay_reports_the_delay_against_its_threshold() {
        let found = signaling_findings(crate::sip::diagnosis::SignalingDiagnosis {
            post_dial_delay: Some(crate::sip::diagnosis::PostDialDelay {
                delay_sec: 14.5,
                threshold_sec: 11.0,
                responded_with: 180,
                evidence: Vec::new(),
            }),
            ..Default::default()
        });
        let f = only(&found, FindingKind::PostDialDelay);
        assert_eq!(f.severity, Severity::Minor);
        assert_eq!(first_note(f), "14.5s to the first 180 (threshold 11.0s)");
    }

    /// A registration failure says which of its two shapes it is, and quotes
    /// the expiry asked for and granted whenever both are known.
    #[test]
    fn a_registration_failure_names_its_shape_and_what_was_asked_for() {
        use crate::sip::diagnosis::{
            RegistrationFailure, RegistrationFailureKind, SignalingDiagnosis,
        };
        let registration = |kind, code, asked, granted| {
            signaling_findings(SignalingDiagnosis {
                registration_failure: Some(RegistrationFailure {
                    kind,
                    code,
                    requested_expiry_sec: asked,
                    granted_expiry_sec: granted,
                    evidence: Vec::new(),
                }),
                ..Default::default()
            })
        };

        let found = registration(RegistrationFailureKind::Rejected, 403, None, None);
        let f = only(&found, FindingKind::RegistrationFailure);
        assert_eq!(f.evidence[0].counts.get("status_code"), Some(&403));
        assert_eq!(first_note(f), "REGISTER rejected with 403");

        let found = registration(
            RegistrationFailureKind::ShortenedExpiry,
            200,
            Some(3600),
            Some(60),
        );
        assert_eq!(
            first_note(only(&found, FindingKind::RegistrationFailure)),
            "registrar granted a shorter expiry than the endpoint asked for (asked 3600s, \
             granted 60s)"
        );

        // Half the pair is not a pair: nothing is quoted.
        let found = registration(
            RegistrationFailureKind::ShortenedExpiry,
            200,
            Some(3600),
            None,
        );
        assert_eq!(
            first_note(only(&found, FindingKind::RegistrationFailure)),
            "registrar granted a shorter expiry than the endpoint asked for",
            "an expiry that was never granted cannot be quoted"
        );
    }

    /// ICMP against a dialog's own request names the unreachable endpoint,
    /// the router that said so, and -- where the quote reached it -- the
    /// method it quoted.
    #[test]
    fn icmp_against_signaling_names_the_endpoint_the_reporter_and_the_method() {
        use crate::sip::diagnosis::{IcmpUnreachable, SignalingDiagnosis};
        let icmp = |method: Option<&str>| {
            signaling_findings(SignalingDiagnosis {
                icmp_unreachable: Some(IcmpUnreachable {
                    description: "port unreachable".to_string(),
                    icmp_type: 3,
                    icmp_code: 3,
                    unreachable_endpoint: "198.51.100.2:5060".to_string(),
                    reported_by: "198.51.100.2".to_string(),
                    method: method.map(str::to_string),
                    errors: 2,
                    truncated: false,
                    evidence: Vec::new(),
                }),
                ..Default::default()
            })
        };

        let found = icmp(Some("INVITE"));
        let f = only(&found, FindingKind::IcmpUnreachableSignaling);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.occurrences, 1, "one dialog, however many errors");
        assert_eq!(f.evidence[0].counts.get("icmp_errors"), Some(&2));
        assert!(
            f.evidence[0]
                .endpoints
                .contains(&"unreachable 198.51.100.2:5060".to_string())
                && f.evidence[0]
                    .endpoints
                    .contains(&"reported by 198.51.100.2".to_string()),
            "{:?}",
            f.evidence[0].endpoints
        );
        assert_eq!(
            first_note(f),
            "port unreachable (type 3, code 3), quoting a INVITE"
        );

        let found = icmp(None);
        assert_eq!(
            first_note(only(&found, FindingKind::IcmpUnreachableSignaling)),
            "port unreachable (type 3, code 3)",
            "a quote that stopped before the method names none"
        );
    }

    /// A diagnosis with nothing in it raises nothing -- including a diagnosis
    /// that carries only hints, which are prose rather than findings.
    #[test]
    fn a_clean_signaling_diagnosis_raises_nothing() {
        let found = signaling_findings(crate::sip::diagnosis::SignalingDiagnosis {
            hints: vec!["a hint is not a finding".to_string()],
            ..Default::default()
        });
        assert!(found.is_empty(), "{found:?}");
    }

    /// Parse raw SIP between the two fixture hosts.
    fn sip(raw: &str) -> crate::sip::SipMessage {
        crate::sip::parser::parse_sip_bytes(
            &bytes::Bytes::copy_from_slice(raw.as_bytes()),
            Utc::now(),
            "198.51.100.1".parse().expect("valid"),
            "198.51.100.2".parse().expect("valid"),
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("the fixture parses as SIP")
    }

    /// An INVITE for `call_id`, and a final response to it.
    fn invite_answered(call_id: &str, status: &str) -> [crate::sip::SipMessage; 2] {
        let common = format!(
            "Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK-{call_id}\r\n\
             From: <sip:alice@example.invalid>;tag=a1\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n"
        );
        [
            sip(&format!(
                "INVITE sip:bob@example.invalid SIP/2.0\r\n{common}\
                 To: <sip:bob@example.invalid>\r\nContent-Length: 0\r\n\r\n"
            )),
            sip(&format!(
                "SIP/2.0 {status}\r\n{common}\
                 To: <sip:bob@example.invalid>;tag=b1\r\nContent-Length: 0\r\n\r\n"
            )),
        ]
    }

    /// The whole path, end to end: a dialog in the store that ended on a 503
    /// comes out of `analyze_with` as a ranked server failure, counted against
    /// the dialogs it examined.
    #[test]
    fn a_dialog_that_ended_on_a_503_is_ranked_as_a_server_failure() {
        let (mut dialogs, streams) = stores();
        for msg in invite_answered("failed@example.invalid", "503 Service Unavailable") {
            dialogs.process_message(msg);
        }
        let analysis = analyze_with(&dialogs, &streams, None, &CaptureFacts::default());
        assert_eq!(analysis.dialogs_examined, 1);
        let f = only(&analysis.findings, FindingKind::ServerFailure);
        assert_eq!(
            f.evidence[0].call_id.as_deref(),
            Some("failed@example.invalid")
        );
        assert_eq!(f.evidence[0].counts.get("status_code"), Some(&503));
        assert!(
            analysis.complete,
            "a failed call says nothing about the read"
        );
    }

    /// A socket address literal.
    fn sock(s: &str) -> std::net::SocketAddr {
        s.parse().expect("a literal socket address parses")
    }

    /// A timestamp `secs` after the epoch.
    fn at_secs(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("a valid timestamp")
    }

    /// A TURN allocation granted `lifetime` seconds at t=0 and still carrying
    /// traffic at t=`last_activity`.
    fn allocation(lifetime: u32, last_activity: i64) -> crate::stun::TurnAllocation {
        crate::stun::TurnAllocation {
            client: sock("10.0.0.5:50000"),
            server: sock("198.51.100.20:3478"),
            relayed_address: None,
            lifetime_secs: Some(lifetime),
            allocated_at: at_secs(0),
            refreshed_at: None,
            refreshes: 0,
            last_activity: at_secs(last_activity),
            released: false,
            channels: Vec::new(),
            unattributed_frames: 0,
        }
    }

    /// Analyze empty stores against `facts` alone.
    fn facts_findings(facts: &CaptureFacts) -> CaptureAnalysis {
        let (dialogs, streams) = stores();
        analyze_with(&dialogs, &streams, None, facts)
    }

    /// A lapsed allocation names the relay, the lifetime it outlived, and the
    /// media that was on it -- the step from "a relay was torn down" to the
    /// call that went quiet.
    #[test]
    fn a_lapsed_turn_allocation_names_the_relay_its_lifetime_and_its_media() {
        let mut carrying = allocation(600, 700);
        carrying.relayed_address = Some(sock("198.51.100.50:49152"));
        carrying.refreshes = 2;
        carrying.channels = vec![crate::stun::RelayChannel {
            channel: 0x4001,
            peer: Some(sock("203.0.113.9:4000")),
            bound: true,
            frames: 10,
            bytes: 1720,
            first_seen: at_secs(1),
            last_seen: at_secs(700),
            ssrcs: vec![0x1234, 0x5678],
            ssrcs_dropped: 0,
        }];
        let bare = allocation(600, 900);
        // Inside its lifetime: not a finding.
        let healthy = allocation(600, 300);

        let analysis = facts_findings(&CaptureFacts {
            stun: crate::stun::StunReport {
                allocations: vec![carrying, bare, healthy],
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        let f = only(&analysis.findings, FindingKind::TurnAllocationLapsed);
        assert_eq!(
            f.occurrences, 2,
            "only the two that outlived their lifetime"
        );

        let ev = &f.evidence[0];
        assert_eq!(
            ev.at,
            Some(at_secs(0)),
            "stamped with when it was allocated"
        );
        assert_eq!(ev.counts.get("refreshes"), Some(&2));
        assert_eq!(ev.counts.get("lifetime_secs"), Some(&600));
        assert_eq!(ev.counts.get("relayed_streams"), Some(&2));
        assert_eq!(
            ev.endpoints,
            vec![
                "client 10.0.0.5:50000".to_string(),
                "TURN server 198.51.100.20:3478".to_string(),
                "relayed 198.51.100.50:49152".to_string(),
                "media 10 frame(s) on channel 0x4001, carrying 2 stream(s) (SSRC 0x00001234, \
                 0x00005678)"
                    .to_string(),
            ]
        );

        let bare_ev = &f.evidence[1];
        assert_eq!(
            bare_ev.counts.get("relayed_streams"),
            None,
            "no channel carried anything, so no stream count is claimed"
        );
        assert!(
            !bare_ev
                .endpoints
                .iter()
                .any(|e| e.starts_with("media") || e.starts_with("relayed")),
            "{:?}",
            bare_ev.endpoints
        );
    }

    /// An ICE check between `client` and `server`, claiming `role`.
    fn ice_check(
        client: &str,
        server: &str,
        role: Option<crate::stun::IceRole>,
    ) -> crate::stun::StunTransaction {
        crate::stun::StunTransaction {
            transaction_id: format!("{client}>{server}"),
            client: sock(client),
            server: sock(server),
            method: 0x001,
            method_name: "Binding".to_string(),
            first_request: at_secs(0),
            last_request: at_secs(0),
            request_count: 1,
            responded_at: Some(at_secs(0)),
            rtt_ms: None,
            mapped_address: None,
            relayed_address: None,
            peer_address: None,
            lifetime_secs: None,
            channel_number: None,
            error_code: None,
            auth_challenge: false,
            software: None,
            ice_role: role,
            use_candidate: false,
            priority: Some(1),
            fingerprint_valid: None,
        }
    }

    /// A role conflict says whether ICE got past it. One that resolved cost a
    /// round trip; one that did not is a candidate cause of media that never
    /// started, and the two must not read alike.
    #[test]
    fn an_ice_role_conflict_says_whether_ice_resolved_it() {
        use crate::stun::IceRole::Controlling;
        let (a, b) = ("192.0.2.1:5000", "192.0.2.2:6000");
        let conflict = vec![
            ice_check(a, b, Some(Controlling)),
            ice_check(b, a, Some(Controlling)),
        ];
        let analyze_ice = |transactions: Vec<crate::stun::StunTransaction>| {
            facts_findings(&CaptureFacts {
                stun: crate::stun::StunReport {
                    transactions,
                    ..Default::default()
                },
                ..CaptureFacts::default()
            })
        };

        let analysis = analyze_ice(conflict.clone());
        let f = only(&analysis.findings, FindingKind::IceRoleConflict);
        assert_eq!(
            f.evidence[0].endpoints,
            vec![
                a.to_string(),
                b.to_string(),
                "both claimed controlling".to_string()
            ]
        );
        assert_eq!(
            f.evidence[0].counts.get("role_conflict_responses"),
            Some(&0)
        );
        assert!(
            first_note(f).starts_with("no candidate pair between these two was ever nominated"),
            "{}",
            first_note(f)
        );

        // The same conflict, and then a nominated pair: ICE resolved it.
        let mut resolved = conflict;
        let mut nominated = ice_check(a, b, None);
        nominated.use_candidate = true;
        resolved.push(nominated);
        let analysis = analyze_ice(resolved);
        assert!(
            first_note(only(&analysis.findings, FindingKind::IceRoleConflict))
                .starts_with("ICE resolved this itself"),
        );

        // A 487 with no duplicate claim names no shared role.
        let mut answered_487 = ice_check(a, b, None);
        answered_487.error_code = Some(487);
        let analysis = analyze_ice(vec![answered_487]);
        let f = only(&analysis.findings, FindingKind::IceRoleConflict);
        assert_eq!(f.evidence[0].endpoints, vec![a.to_string(), b.to_string()]);
        assert_eq!(
            f.evidence[0].counts.get("role_conflict_responses"),
            Some(&1)
        );
    }

    /// An ICMP-against-media flow with the given payload and match.
    fn media_flow(
        payload: crate::pipeline::QuotedMediaKind,
        matched: crate::rtp::stream_store::MediaMatch,
        errors: u64,
        call_ids: &[&str],
    ) -> crate::pipeline::MediaIcmpFinding {
        crate::pipeline::MediaIcmpFinding {
            source: "198.51.100.1:5004".to_string(),
            unreachable_endpoint: "203.0.113.9:4000".to_string(),
            reported_by: "203.0.113.9".to_string(),
            transport: "udp",
            description: "port unreachable".to_string(),
            icmp_type: 3,
            icmp_code: 3,
            errors,
            payload,
            matched,
            streams: 1,
            call_ids: call_ids.iter().map(|c| (*c).to_string()).collect(),
            hint: "the media relay is not listening".to_string(),
        }
    }

    /// ICMP against media counts every ERROR, and claims only the flows ICMP
    /// actually ties to media. The report also holds ordinary network
    /// failures, and calling those audio problems is the confident wrong
    /// answer this layer exists to remove.
    #[test]
    fn icmp_against_media_counts_every_error_and_skips_flows_that_are_not_media() {
        use crate::pipeline::QuotedMediaKind as Payload;
        use crate::rtp::stream_store::MediaMatch;
        let analysis = facts_findings(&CaptureFacts {
            icmp_media: crate::pipeline::IcmpMediaReport {
                flows: vec![
                    media_flow(
                        Payload::Rtp {
                            ssrc: 7,
                            payload_type: 0,
                        },
                        MediaMatch::Flow,
                        40,
                        &["call-1@x", "call-2@x"],
                    ),
                    // Not media and matched to nothing: a DNS lookup that
                    // failed is not a broken call.
                    media_flow(Payload::NotMedia, MediaMatch::None, 900, &[]),
                    // Unreadable payload, but addressed to a negotiated media
                    // endpoint: still media.
                    media_flow(Payload::Unread, MediaMatch::SdpEndpoint, 2, &[]),
                ],
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        let f = only(&analysis.findings, FindingKind::IcmpUnreachableMedia);
        assert_eq!(
            f.occurrences, 42,
            "every error on the two media flows, and none of the 900 that were not media"
        );
        assert_eq!(f.evidence.len(), 2);
        let ev = &f.evidence[0];
        assert_eq!(ev.call_id.as_deref(), Some("call-1@x"));
        assert_eq!(ev.counts.get("icmp_errors"), Some(&40));
        assert_eq!(ev.counts.get("streams"), Some(&1));
        assert_eq!(ev.note.as_deref(), Some("the media relay is not listening"));
        assert_eq!(
            ev.endpoints,
            vec![
                "unreachable 203.0.113.9:4000".to_string(),
                "sent from 198.51.100.1:5004".to_string(),
                "reported by 203.0.113.9".to_string(),
            ]
        );
        assert_eq!(
            f.evidence[1].call_id, None,
            "a flow tied to no call names none"
        );
    }

    /// An unreachable endpoint no dialog explained.
    fn unreachable(
        addr: &str,
        port: Option<u16>,
        errors: u64,
    ) -> crate::pipeline::UnreachableEndpoint {
        crate::pipeline::UnreachableEndpoint {
            addr: addr.parse().expect("a literal address parses"),
            port,
            errors,
            description: "host unreachable",
        }
    }

    /// ICMP that reached no dialog is counted in ERRORS, not endpoints: one
    /// endpoint routinely accounts for all of them, and counting endpoints
    /// would report a 3,000-error outage as a 1.
    #[test]
    fn icmp_that_reached_no_dialog_counts_errors_not_endpoints() {
        let analysis = facts_findings(&CaptureFacts {
            icmp: crate::pipeline::IcmpEvidenceReport {
                unattributed: 3000,
                endpoints: vec![
                    unreachable("203.0.113.1", Some(5060), 2990),
                    unreachable("203.0.113.2", None, 10),
                ],
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        let f = only(&analysis.findings, FindingKind::IcmpUnreachableEndpoint);
        assert_eq!(f.occurrences, 3000);
        assert_eq!(
            f.evidence[0].counts.get("errors_naming_no_call"),
            Some(&3000)
        );
        assert_eq!(
            f.evidence[1].endpoints,
            vec!["203.0.113.1:5060".to_string()]
        );
        assert_eq!(f.evidence[1].counts.get("icmp_errors"), Some(&2990));
        assert_eq!(f.evidence[1].note.as_deref(), Some("host unreachable"));
        assert_eq!(
            f.evidence[2].endpoints,
            vec!["203.0.113.2".to_string()],
            "a quote with no port names the address alone"
        );

        // Endpoints with no unattributed errors behind them raise nothing.
        let quiet = facts_findings(&CaptureFacts {
            icmp: crate::pipeline::IcmpEvidenceReport {
                endpoints: vec![unreachable("203.0.113.1", Some(5060), 1)],
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        assert!(quiet.is_clean(), "{:?}", quiet.findings);
    }

    /// Endpoints past the evidence cap are COUNTED as omitted, not silently
    /// dropped. A list of ten rows that says nothing about the other six reads
    /// as complete, which is the understatement [`EVIDENCE_CAP`] promises a
    /// finding never makes.
    #[test]
    fn icmp_endpoints_past_the_evidence_cap_are_counted_as_omitted() {
        let endpoints: Vec<_> = (1..=15_u16)
            .map(|i| unreachable("203.0.113.1", Some(5000 + i), 2))
            .collect();
        let analysis = facts_findings(&CaptureFacts {
            icmp: crate::pipeline::IcmpEvidenceReport {
                unattributed: 30,
                endpoints,
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        let f = only(&analysis.findings, FindingKind::IcmpUnreachableEndpoint);
        assert_eq!(
            f.occurrences, 30,
            "the count is errors, whatever the rows do"
        );
        assert_eq!(f.evidence.len(), EVIDENCE_CAP);
        assert_eq!(
            f.evidence_omitted, 6,
            "one summary row and fifteen endpoints is sixteen rows; ten shown, six omitted"
        );
    }

    /// SIP the WebSocket port set declined is Blind, exactly as the
    /// `--portrange` discard is: those messages are in no dialog.
    #[test]
    fn sip_discarded_by_the_websocket_port_set_is_a_blind_finding() {
        let analysis = facts_findings(&CaptureFacts {
            websocket: crate::pipeline::WsPortSkipReport {
                messages: 20,
                ports: vec![crate::pipeline::SkippedPort {
                    port: 8089,
                    messages: 20,
                }],
            },
            ..CaptureFacts::default()
        });
        let f = only(
            &analysis.findings,
            FindingKind::SipDiscardedByWebSocketPorts,
        );
        assert_eq!(f.severity, Severity::Blind);
        assert_eq!(f.occurrences, 20);
        assert_eq!(f.evidence[0].endpoints, vec!["port 8089".to_string()]);
        assert_eq!(f.evidence[0].counts.get("messages"), Some(&20));
        assert!(!analysis.complete);
    }

    /// A port gate that discarded SIP on more ports than the evidence cap still
    /// counts every message it discarded.
    ///
    /// The count is exact and the rows are capped -- the two halves
    /// [`Finding::occurrences`] and [`Finding::evidence_omitted`] exist to keep
    /// apart. Summing only the rows that fit reported the busiest ten ports'
    /// messages as the total, and said nothing about the ports it left out.
    #[test]
    fn a_port_gate_that_discarded_sip_on_many_ports_still_counts_every_message() {
        let ports: Vec<crate::pipeline::SkippedPort> = (0..12_u16)
            .map(|i| crate::pipeline::SkippedPort {
                port: 5070 + i,
                messages: 5,
            })
            .collect();
        let analysis = facts_findings(&CaptureFacts {
            portrange: crate::pipeline::PortrangeSkipReport {
                messages: 60,
                ports: ports.clone(),
            },
            websocket: crate::pipeline::WsPortSkipReport {
                messages: 60,
                ports,
            },
            ..CaptureFacts::default()
        });
        for kind in [
            FindingKind::SipDiscardedByPortRange,
            FindingKind::SipDiscardedByWebSocketPorts,
        ] {
            let f = only(&analysis.findings, kind);
            assert_eq!(
                f.occurrences, 60,
                "{kind:?}: every discarded message, not only those on the rows shown"
            );
            assert_eq!(f.evidence.len(), EVIDENCE_CAP, "{kind:?}");
            assert_eq!(
                f.evidence_omitted, 2,
                "{kind:?}: the two ports left out are said"
            );
        }
    }

    /// Reasons the undecodable table could not retain are counted beside the
    /// ones it did, so the reason list is not read as exhaustive.
    #[test]
    fn undecodable_reasons_that_were_not_retained_are_counted() {
        let facts = |reasons_dropped| CaptureFacts {
            frames_read: 50,
            undecodable: crate::capture::UndecodableReport {
                frames: 9,
                reasons: vec![crate::capture::UndecodableTally {
                    reason: crate::capture::UndecodableReason::NotIp(Some(0x8847)),
                    frames: 9,
                }],
                reasons_dropped,
            },
            ..CaptureFacts::default()
        };

        let analysis = facts_findings(&facts(3));
        let ev = &only(&analysis.findings, FindingKind::UndecodableFrames).evidence[0];
        assert_eq!(ev.counts.get("reasons_not_retained"), Some(&3));
        assert_eq!(ev.counts.get("frames_read"), Some(&50));
        assert_eq!(
            ev.note.as_deref(),
            Some(facts(3).undecodable.reason_list().as_str())
        );

        let analysis = facts_findings(&facts(0));
        let ev = &only(&analysis.findings, FindingKind::UndecodableFrames).evidence[0];
        assert_eq!(
            ev.counts.get("reasons_not_retained"),
            None,
            "nothing was dropped, so nothing is claimed"
        );
    }

    /// STUN transactions past the tracking cap, and ICMP errors that found the
    /// dialog table full, are each a retention loss with their own unit.
    #[test]
    fn stun_and_icmp_records_past_their_caps_are_retention_losses() {
        let analysis = facts_findings(&CaptureFacts {
            stun: crate::stun::StunReport {
                dropped: 5,
                ..Default::default()
            },
            icmp: crate::pipeline::IcmpEvidenceReport {
                untracked_dialogs: 4,
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        let f = only(&analysis.findings, FindingKind::RetentionLoss);
        assert_eq!(f.occurrences, 9);
        assert_eq!(f.evidence[0].counts.get("stun_transactions"), Some(&5));
        assert_eq!(f.evidence[1].counts.get("icmp_errors"), Some(&4));
        assert!(
            !analysis.complete,
            "a record thrown away is a gap in the read"
        );
    }

    /// The retention counters are read off the dialog store, one per way it
    /// sheds a dialog: rotation discards the oldest, no-rotate refuses the
    /// newest.
    #[test]
    fn retention_counts_read_each_way_the_dialog_store_sheds_a_dialog() {
        let fill = |rotate| {
            let mut ds = DialogStore::new(1, rotate);
            for id in ["one@x", "two@x", "three@x"] {
                let [invite, _] = invite_answered(id, "200 OK");
                ds.process_message(invite);
            }
            RetentionCounts::of_store(&ds)
        };

        let rotated = fill(true);
        assert_eq!(rotated.dialogs_rotated, 2, "{rotated:?}");
        assert_eq!(rotated.dialogs_refused, 0, "{rotated:?}");

        let refused = fill(false);
        assert_eq!(refused.dialogs_refused, 2, "{refused:?}");
        assert_eq!(refused.dialogs_rotated, 0, "{refused:?}");
    }

    /// `analyze` carries its denominator through: the frames it was told it
    /// read, and the dialogs and streams it examined.
    ///
    /// It reads process-global tallies other tests write to concurrently, so
    /// this asserts only what those globals cannot move.
    #[test]
    fn analyze_carries_the_frames_it_was_told_it_read() {
        let (mut dialogs, streams) = stores();
        for msg in invite_answered("answered@example.invalid", "200 OK") {
            dialogs.process_message(msg);
        }
        let analysis = analyze(&dialogs, &streams, None, 42);
        assert_eq!(analysis.frames_read, 42);
        assert_eq!(analysis.dialogs_examined, 1);
        assert_eq!(analysis.streams_examined, 0);
    }

    /// An unanswered probe says whether it was retransmitted: a repeat is
    /// itself proof the first request drew silence ([RFC 5389 section 7.2.1](https://www.rfc-editor.org/rfc/rfc5389#section-7.2.1)
    /// retransmits only on timeout), and a single request proves less.
    #[test]
    fn an_unanswered_probe_says_whether_it_was_retransmitted() {
        let probe = |requests| {
            let mut tx = ice_check("192.0.2.10:50000", "198.51.100.20:3478", None);
            tx.priority = None;
            tx.responded_at = None;
            tx.request_count = requests;
            tx
        };
        let analysis = facts_findings(&CaptureFacts {
            stun: crate::stun::StunReport {
                transactions: vec![probe(1), probe(3)],
                ..Default::default()
            },
            ..CaptureFacts::default()
        });
        let f = only(&analysis.findings, FindingKind::UnansweredStunProbe);
        assert_eq!(f.occurrences, 2);
        assert_eq!(f.evidence[0].note.as_deref(), Some("no response"));
        assert_eq!(
            f.evidence[1].note.as_deref(),
            Some("retransmitted, which by itself proves the first request went unanswered")
        );
        assert_eq!(f.evidence[1].counts.get("requests"), Some(&3));
    }
}
