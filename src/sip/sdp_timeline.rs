// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! SDP negotiation timeline tracking for SIP dialogs.
//!
//! Records each SDP offer and answer as messages flow through a dialog,
//! detecting mid-call events such as hold, resume, codec changes, T.38
//! fax switchover, and media anchor (IP:port) changes.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::SipMessage;
use super::sdp::{self, SdpDirection as MediaDirection, SdpSession};

/// A single SDP exchange (offer or answer) within a dialog.
#[derive(Debug, Clone)]
pub struct SdpExchange {
    /// Timestamp of the message carrying this SDP body.
    pub timestamp: DateTime<Utc>,
    /// Whether this SDP is an offer or an answer.
    pub direction: OfferAnswer,
    /// Whether a request carried this SDP, rather than a response.
    ///
    /// Not the same fact as [`Self::direction`]: in a delayed offer the 2xx
    /// (a response) carries the offer and the ACK (a request) the answer. A
    /// relay's rewritten address travels in both a request and a response,
    /// which is how engine selection tells it from a party's own address.
    pub from_request: bool,
    /// The dialog party that sent this SDP body.
    ///
    /// Events compare an exchange with the previous exchange from the same
    /// party: each party's SDP describes that party's own receive address,
    /// direction and codecs, so the other party's SDP is not a prior state.
    pub sender: SdpSender,
    /// Codec names aggregated across all media descriptions' rtpmap entries
    /// (`m=` order, de-duplicated), so audio+video offers list both legs.
    pub codecs: Vec<String>,
    /// Media IP address (effective address from session or media level `c=`).
    pub media_addr: Option<String>,
    /// Media port from the first audio media description.
    pub media_port: Option<u16>,
    /// Stream directionality: `"sendrecv"`, `"sendonly"`, `"recvonly"`, or `"inactive"`.
    pub mode: String,
    /// Whether the first media description is T.38 fax (`m=image`).
    pub is_t38: bool,
    /// Detected mid-call event, if any, compared with the previous exchange
    /// from the same [`Self::sender`].
    pub event: Option<SdpEvent>,
}

/// The dialog party that sent an SDP body, as the timeline identifies it.
///
/// Two exchanges come from the same party when both fields are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpSender {
    /// The sender's own dialog tag: the `From` tag of a request, the `To` tag
    /// of a response ([RFC 3261 section 12](https://www.rfc-editor.org/rfc/rfc3261.html#section-12)).
    /// `None` when the message carries no such tag.
    pub tag: Option<String>,
    /// Source IP address of the message that carried the SDP body.
    ///
    /// Part of the identity because a media relay forwards each message on a
    /// second leg with its own address rewritten into the SDP: the copy on
    /// each leg is compared with that leg's earlier copies, and the rewrite is
    /// not reported as a move. A party whose signaling address changes
    /// mid-dialog therefore starts a new sequence, and its first exchange from
    /// the new address records no event.
    pub addr: IpAddr,
}

impl SdpSender {
    /// The party that sent `msg`.
    fn of(msg: &SipMessage) -> Self {
        let tag = if msg.is_request {
            msg.from_tag()
        } else {
            msg.to_tag()
        };
        Self {
            tag: tag.map(str::to_string),
            addr: msg.src_addr,
        }
    }
}

/// Mid-call SDP event detected by comparing successive exchanges.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SdpEvent {
    /// Call placed on hold (direction changed to `sendonly` or `inactive`).
    Hold,
    /// Call resumed from hold (direction changed back to `sendrecv`).
    Resume,
    /// Codec negotiation changed (different codec set from previous exchange).
    CodecChange,
    /// Media switched to T.38 fax (`m=image` media type).
    T38Switch,
    /// Media anchor (IP address or port) changed.
    MediaAnchorChange,
    /// Call transfer initiated via REFER.
    Transfer {
        /// Refer-To target URI, or `None` when the REFER carried no `Refer-To`.
        ///
        /// `None` rather than a placeholder string: a REFER without `Refer-To`
        /// is malformed, and this used to record the literal `"unknown"`, which
        /// renders in a call-flow export as a transfer to a party named
        /// "unknown" and is indistinguishable from a real target of that name.
        /// A URI-typed field should not be made to hold a non-URI.
        target: Option<String>,
    },
}

/// Whether an SDP body is an offer or an answer in the offer/answer model.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum OfferAnswer {
    /// SDP offer (typically in INVITE or re-INVITE requests).
    Offer,
    /// SDP answer (typically in 200 OK responses to INVITE).
    Answer,
}

/// The media-direction mode recorded for a timeline exchange.
///
/// The first four variants mirror the SDP `a=` direction attributes. The
/// fifth, [`MediaMode::Transfer`], is a dedicated marker for the synthetic
/// exchange emitted by [`track_transfer`]: a REFER carries no media of its
/// own, so it has no real direction — this variant replaces the former magic
/// `"transfer"` string that was stuffed into the mode field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaMode {
    /// Bidirectional media (`a=sendrecv`, the SDP default).
    SendRecv,
    /// Send-only (`a=sendonly`); one hold form.
    SendOnly,
    /// Receive-only (`a=recvonly`).
    RecvOnly,
    /// No media flowing either way (`a=inactive`); the other hold form.
    Inactive,
    /// A REFER-initiated call transfer — not a real SDP direction.
    Transfer,
}

impl MediaMode {
    /// The stable lowercase token used in output and event detection.
    ///
    /// The first four match the SDP `a=` attribute names; `Transfer` renders
    /// as `"transfer"` to preserve the existing serialized form.
    fn as_str(self) -> &'static str {
        match self {
            MediaMode::SendRecv => "sendrecv",
            MediaMode::SendOnly => "sendonly",
            MediaMode::RecvOnly => "recvonly",
            MediaMode::Inactive => "inactive",
            MediaMode::Transfer => "transfer",
        }
    }
}

impl From<&MediaDirection> for MediaMode {
    fn from(direction: &MediaDirection) -> Self {
        match direction {
            MediaDirection::SendRecv => MediaMode::SendRecv,
            MediaDirection::SendOnly => MediaMode::SendOnly,
            MediaDirection::RecvOnly => MediaMode::RecvOnly,
            MediaDirection::Inactive => MediaMode::Inactive,
        }
    }
}

/// Track SDP from a SIP message and append to the timeline.
///
/// If the message contains an `application/sdp` body, parses it and creates
/// an [`SdpExchange`] entry. Compares it with the previous entry from the same
/// [`SdpSender`] to detect mid-call events (hold, resume, codec change, T.38,
/// anchor change); see `detect_event`.
///
/// Messages without SDP bodies are silently ignored.
///
/// # Arguments
///
/// * `timeline` — the dialog's SDP exchange history, oldest first.
/// * `msg` — the SIP message to inspect for an SDP body.
///
/// # Side effects
///
/// Appends one `SdpExchange` to `timeline` when `msg` carries a parseable
/// `application/sdp` body; otherwise leaves it untouched.
pub fn track_sdp(timeline: &mut Vec<SdpExchange>, msg: &SipMessage) {
    let sdp = match msg.sdp() {
        Some(s) => s,
        None => return,
    };

    let direction = determine_offer_answer(timeline, msg);
    let (codecs, media_addr, media_port, mode, is_t38) = extract_media_info(&sdp);

    let mut exchange = SdpExchange {
        timestamp: msg.timestamp,
        direction,
        from_request: msg.is_request,
        sender: SdpSender::of(msg),
        codecs,
        media_addr,
        media_port,
        mode: mode.as_str().to_string(),
        is_t38,
        event: None,
    };
    exchange.event = detect_event(timeline, &exchange);
    timeline.push(exchange);
}

/// Track REFER-based transfer events.
///
/// Appends a [`SdpEvent::Transfer`] entry when the message is a REFER request.
/// Non-REFER messages are silently ignored.
///
/// # Arguments
///
/// * `timeline` — the dialog's SDP exchange history, oldest first.
/// * `msg` — the SIP message to inspect; only REFER requests are recorded.
///
/// # Side effects
///
/// Appends a synthetic `SdpExchange` marked as a transfer (no media fields)
/// to `timeline` for REFER requests; the `Refer-To` header value becomes
/// the transfer target, or `None` when the header is absent — a REFER without
/// one is malformed, and saying so beats inventing a target for it.
pub fn track_transfer(timeline: &mut Vec<SdpExchange>, msg: &SipMessage) {
    if !msg.is_request || msg.method.as_ref() != Some(&super::method::SipMethod::Refer) {
        return;
    }
    let target = msg.header("Refer-To").map(str::to_string);
    timeline.push(SdpExchange {
        timestamp: msg.timestamp,
        direction: OfferAnswer::Offer,
        from_request: true,
        sender: SdpSender::of(msg),
        codecs: Vec::new(),
        media_addr: None,
        media_port: None,
        mode: MediaMode::Transfer.as_str().to_string(),
        is_t38: false,
        event: Some(SdpEvent::Transfer { target }),
    });
}

/// Determine whether an SDP body is an offer or answer, using both the SIP
/// message type and the dialog's offer/answer position so far.
///
/// - Requests (INVITE, UPDATE) normally carry offers.
/// - Responses (200 OK, 183, etc.) normally carry answers.
///
/// Two delayed-offer exceptions ([RFC 3261 section 13.2.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.1)) override the type-based
/// default, because an offerless INVITE carries no SDP and so never produces a
/// timeline entry — the offer/answer roles then land on the response and ACK:
///
/// - An `ACK` request is always the **answer** (SDP in an ACK acknowledges an
///   offer delivered in the 2xx, never an offer of its own).
/// - A response bearing SDP with **no preceding offer** in the dialog is itself
///   the **offer** (the delayed offer carried in the 2xx).
fn determine_offer_answer(timeline: &[SdpExchange], msg: &SipMessage) -> OfferAnswer {
    if msg.is_request {
        if msg.method.as_ref() == Some(&super::method::SipMethod::Ack) {
            // ACK never offers; its SDP answers the offer from the 2xx.
            return OfferAnswer::Answer;
        }
        OfferAnswer::Offer
    } else {
        // Delayed offer: the offerless INVITE left no exchange, so this 2xx's
        // SDP is the first — and thus the offer — when nothing offered before.
        let has_prior_offer = timeline.iter().any(|e| e.direction == OfferAnswer::Offer);
        if has_prior_offer {
            OfferAnswer::Answer
        } else {
            OfferAnswer::Offer
        }
    }
}

/// Extract codec list, media address, port, direction mode, and T.38 flag
/// for a timeline exchange.
///
/// Codecs are aggregated across **all** media descriptions (in `m=` order,
/// de-duplicated) so an audio+video offer lists both legs' codecs rather
/// than dropping the video. The anchor fields (address, port, direction
/// mode, T.38 flag) come from the first media description — the primary
/// call leg that hold/resume/anchor-change detection tracks.
fn extract_media_info(
    sdp: &SdpSession,
) -> (Vec<String>, Option<String>, Option<u16>, MediaMode, bool) {
    let first_media = match sdp.media.first() {
        Some(m) => m,
        None => return (Vec::new(), None, None, MediaMode::SendRecv, false),
    };

    // Codec names come from a=rtpmap where one exists, and from the RFC 3551
    // static assignments where it does not. Both are needed: rtpmap is only
    // mandatory for the dynamic types (96-127), so an SDP offering plain G.711
    // as `m=audio 8000 RTP/AVP 0 8` carries no rtpmap at all and is complete
    // without one.
    //
    // Order follows the m= line, because that is the offerer's stated
    // preference and an operator comparing two offers is usually reading for
    // which codec came first. rtpmap wins over the static table for the same
    // payload number: RFC 3551 §3 allows a static type to be re-bound, and
    // what the wire said is the evidence.
    let mut codecs: Vec<String> = Vec::new();
    for media in &sdp.media {
        for fmt in &media.formats {
            let Ok(pt) = fmt.parse::<u8>() else {
                // Non-numeric format token: `m=image ... udptl t38` and friends
                // carry a format name rather than a payload number, and those
                // are described by the media type, not the codec list.
                continue;
            };
            let name = media
                .rtpmap
                .iter()
                .find(|r| r.payload_type == pt)
                .map(|r| r.encoding.clone())
                .or_else(|| sdp::static_payload_name(pt).map(str::to_owned));
            // A dynamic type with no rtpmap is genuinely unnameable — 96-127
            // mean nothing without the map — so it is omitted rather than
            // guessed at.
            if let Some(name) = name
                && !codecs.contains(&name)
            {
                codecs.push(name);
            }
        }
        // An rtpmap for a payload type absent from the m= line is malformed but
        // observed in the wild; keep it rather than lose a codec the far end
        // clearly named.
        for r in &media.rtpmap {
            if !codecs.contains(&r.encoding) {
                codecs.push(r.encoding.clone());
            }
        }
    }

    let media_addr = sdp::effective_address(first_media, sdp);
    let media_port = Some(first_media.port);

    let mode = MediaMode::from(&first_media.direction);

    let is_t38 = first_media.media_type == "image";

    (codecs, media_addr, media_port, mode, is_t38)
}

/// Whether `exchange` is the synthetic REFER marker from [`track_transfer`],
/// which carries no SDP and so is no party's media state.
fn is_transfer(exchange: &SdpExchange) -> bool {
    matches!(exchange.event, Some(SdpEvent::Transfer { .. }))
}

/// Compare the current SDP exchange with the same party's previous one to
/// detect events.
///
/// Each party's SDP describes that party's own receive address, direction
/// and codecs, so the exchange compared against is the latest one from the
/// same [`SdpSender`], not the latest in the timeline: for an answer that is the
/// other party's offer, and comparing with it labeled every first answer an
/// anchor change.
///
/// Priority order (first match wins):
/// 1. T.38 switch (media type changed to image)
/// 2. Hold (sendrecv → sendonly/inactive)
/// 3. Resume (sendonly/inactive → sendrecv)
/// 4. Media anchor change (IP or port changed)
/// 5. Codec change (different codec set)
///
/// An answer whose event is the event the offer it answers already reported
/// (T.38 switch, hold, resume or codec change) records no event: the answer
/// accepts that change rather than making a second one. A media anchor change
/// is exempt, because an anchor is the sending party's own address and the
/// answerer moving it is a separate fact from the offerer moving theirs.
///
/// # Arguments
///
/// * `timeline` — prior exchanges, oldest first.
/// * `current` — the exchange being added; its `event` is not read.
///
/// # Returns
///
/// The highest-priority detected event, or `None` when the sender has no
/// earlier exchange, nothing changed, or an answer only accepted its offer's
/// change.
fn detect_event(timeline: &[SdpExchange], current: &SdpExchange) -> Option<SdpEvent> {
    let prev = timeline
        .iter()
        .rev()
        .find(|e| e.sender == current.sender && !is_transfer(e))?;
    let event = detect_change(prev, current)?;
    if current.direction == OfferAnswer::Answer && event != SdpEvent::MediaAnchorChange {
        let answered = timeline
            .iter()
            .rev()
            .find(|e| e.direction == OfferAnswer::Offer && !is_transfer(e));
        if answered.and_then(|offer| offer.event.as_ref()) == Some(&event) {
            return None;
        }
    }
    Some(event)
}

/// The highest-priority change from `prev` to `current`, in the order
/// [`detect_event`] documents, or `None` when nothing changed.
fn detect_change(prev: &SdpExchange, current: &SdpExchange) -> Option<SdpEvent> {
    // T.38 switch takes priority. Compare against the previous exchange's
    // media *state*, not its event: repeated T.38 re-INVITEs (session
    // refresh) leave `prev.event` as None, which must not re-trigger.
    if current.is_t38 && !prev.is_t38 {
        return Some(SdpEvent::T38Switch);
    }

    // Hold detection: was sendrecv, now sendonly or inactive
    let prev_active = prev.mode == "sendrecv";
    let now_held = current.mode == "sendonly" || current.mode == "inactive";
    if prev_active && now_held {
        return Some(SdpEvent::Hold);
    }

    // Resume detection: was sendonly/inactive, now sendrecv
    let prev_held = prev.mode == "sendonly" || prev.mode == "inactive";
    let now_active = current.mode == "sendrecv";
    if prev_held && now_active {
        return Some(SdpEvent::Resume);
    }

    // Media anchor change: IP or port changed
    if current.media_addr != prev.media_addr || current.media_port != prev.media_port {
        return Some(SdpEvent::MediaAnchorChange);
    }

    // Codec change: different codec set
    if current.codecs != prev.codecs {
        return Some(SdpEvent::CodecChange);
    }

    None
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for SDP timeline tracking: offer/answer recording, hold/resume,
/// codec change, T.38 switchover, anchor change, and REFER transfers.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    type TestError = Box<dyn std::error::Error>;

    /// Fixed 127.0.0.1 address used for all test messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) tests offset from.
    fn base_ts() -> Result<DateTime<Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build an INVITE carrying `sdp_body` captured at `ts`.
    fn make_invite_with_sdp(sdp_body: &[u8], ts: DateTime<Utc>) -> Result<SipMessage, TestError> {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: sdp-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", sdp_body.len()),
            ],
            sdp_body,
        );
        Ok(parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// Build a 200 OK response carrying `sdp_body` captured at `ts`.
    fn make_200_with_sdp(sdp_body: &[u8], ts: DateTime<Utc>) -> Result<SipMessage, TestError> {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: sdp-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", sdp_body.len()),
            ],
            sdp_body,
        );
        Ok(parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// Build an ACK request carrying `sdp_body` captured at `ts`.
    fn make_ack_with_sdp(sdp_body: &[u8], ts: DateTime<Utc>) -> Result<SipMessage, TestError> {
        let raw = build_sip(
            "ACK sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: sdp-test@example.com",
                "CSeq: 1 ACK",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", sdp_body.len()),
            ],
            sdp_body,
        );
        Ok(parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// Build an INVITE with no message body (no SDP) captured at `ts`.
    fn make_invite_no_sdp(ts: DateTime<Utc>) -> Result<SipMessage, TestError> {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: sdp-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        Ok(parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// Build a sendrecv audio SDP body with the given codec, address, and port.
    fn sendrecv_sdp(codec: &str, addr: &str, port: u16) -> Vec<u8> {
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 {codec}/8000\r\n\
             a=sendrecv\r\n"
        )
        .into_bytes()
    }

    /// Build an audio SDP body carrying only static payload numbers, with no
    /// `a=rtpmap` at all. RFC 3551 assigns these numbers permanently, so this
    /// is a complete and legal offer — it is what Cisco, Avaya and most SBCs
    /// emit for plain G.711.
    fn static_pt_sdp(formats: &str, addr: &str, port: u16) -> Vec<u8> {
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP {formats}\r\n\
             a=sendrecv\r\n"
        )
        .into_bytes()
    }

    /// Each exchange records whether a request or a response carried it.
    ///
    /// Offer and answer cannot say this: in a delayed offer the 2xx (a
    /// response) is the offer and the ACK (a request) the answer, so a relay's
    /// rewritten address in the forwarded 2xx and the forwarded ACK reads
    /// "answer" both times. Engine selection from SDP needs the direction of
    /// travel, which is request or response.
    #[test]
    fn each_exchange_records_whether_a_request_carried_it() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        track_sdp(&mut timeline, &make_invite_no_sdp(base_ts()?)?);
        let sdp = sendrecv_sdp("PCMU", "192.0.2.20", 6000);
        track_sdp(&mut timeline, &make_200_with_sdp(&sdp, base_ts()?)?);
        let sdp = sendrecv_sdp("PCMU", "192.0.2.21", 6000);
        track_sdp(&mut timeline, &make_ack_with_sdp(&sdp, base_ts()?)?);

        assert_eq!(timeline.len(), 2, "the offerless INVITE leaves no exchange");
        assert_eq!(
            timeline[0].direction,
            OfferAnswer::Offer,
            "each exchange records whether a request carried it"
        );
        assert!(!timeline[0].from_request, "the 2xx is a response");
        assert_eq!(
            timeline[1].direction,
            OfferAnswer::Answer,
            "each exchange records whether a request carried it"
        );
        assert!(timeline[1].from_request, "the ACK is a request");
        Ok(())
    }

    /// An SDP with no `a=rtpmap` still names its codecs. RFC 3551 Table 4
    /// assigns 0, 8 and 18 permanently, so an offer carrying only payload
    /// numbers is complete — the rtpmap is what DYNAMIC types (96-127) need,
    /// not static ones.
    ///
    /// Reading codecs from `a=rtpmap` alone reported no codecs for these, and
    /// an empty list is not a neutral answer: `check_codec_negotiation` turns
    /// it into "sdp_present_but_no_codecs", which tells an operator the far end
    /// offered nothing when it offered G.711 both ways.
    #[test]
    fn static_payload_types_are_named_without_an_rtpmap() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let sdp = static_pt_sdp("0 8 18", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, base_ts()?)?;
        track_sdp(&mut timeline, &invite);

        assert_eq!(timeline.len(), 1);
        assert_eq!(
            timeline[0].codecs,
            vec!["PCMU", "PCMA", "G729"],
            "RFC 3551 static payload types must be named from the m= line when \
             no a=rtpmap is present; got {:?}",
            timeline[0].codecs
        );
        Ok(())
    }

    /// A dynamic payload type with no `a=rtpmap` is genuinely unnameable —
    /// 96-127 mean nothing without the map. It must not be guessed at, and it
    /// must not suppress the static entries beside it.
    #[test]
    fn dynamic_payload_types_without_an_rtpmap_are_not_invented() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let sdp = static_pt_sdp("0 96 97", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, base_ts()?)?;
        track_sdp(&mut timeline, &invite);

        assert_eq!(
            timeline[0].codecs,
            vec!["PCMU"],
            "dynamic types carry no registry meaning without a=rtpmap and must \
             be omitted, not named; got {:?}",
            timeline[0].codecs
        );
        Ok(())
    }

    /// An explicit `a=rtpmap` wins over the static table. RFC 3551 permits
    /// re-binding a static number, and the wire spelling is the evidence.
    #[test]
    fn an_explicit_rtpmap_overrides_the_static_table() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let sdp = sendrecv_sdp("SomethingElse", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, base_ts()?)?;
        track_sdp(&mut timeline, &invite);

        assert_eq!(
            timeline[0].codecs,
            vec!["SomethingElse"],
            "payload type 0 was explicitly mapped; the static default must not \
             override what the wire said"
        );
        Ok(())
    }

    /// Build an audio SDP body with an explicit direction attribute
    /// (`sendonly`, `inactive`, ...).
    fn directional_sdp(codec: &str, addr: &str, port: u16, direction: &str) -> Vec<u8> {
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 {codec}/8000\r\n\
             a={direction}\r\n"
        )
        .into_bytes()
    }

    /// Build a T.38 fax SDP body (`m=image ... udptl t38`).
    fn t38_sdp(addr: &str, port: u16) -> Vec<u8> {
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=image {port} udptl t38\r\n"
        )
        .into_bytes()
    }

    /// First offer records no event, and neither does the answer: the answer
    /// is the callee's first SDP, at the callee's own address, so there is no
    /// earlier callee anchor for it to have moved from.
    #[test]
    fn initial_offer_and_answer() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::milliseconds(500);

        let sdp = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, t0)?;
        track_sdp(&mut timeline, &invite);

        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].direction, OfferAnswer::Offer);
        assert_eq!(timeline[0].codecs, vec!["PCMU"]);
        assert_eq!(timeline[0].media_addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(timeline[0].media_port, Some(20000));
        assert_eq!(timeline[0].mode, "sendrecv");
        assert!(timeline[0].event.is_none()); // No previous → no event

        let answer_sdp = sendrecv_sdp("PCMU", "10.0.0.2", 30000);
        let ok = make_200_with_sdp(&answer_sdp, t1)?;
        track_sdp(&mut timeline, &ok);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].direction, OfferAnswer::Answer);
        assert_eq!(
            timeline[1].sender.tag.as_deref(),
            Some("t2"),
            "the 200 OK is the callee's, by its To tag"
        );
        // Different IP and port from the OFFER, but the offer is the caller's:
        // the callee has no earlier anchor, so nothing moved.
        assert_eq!(
            timeline[1].event, None,
            "the answer is the callee's first SDP, not an anchor change"
        );
        Ok(())
    }

    /// A re-INVITE switching sendrecv to sendonly is detected as Hold.
    #[test]
    fn hold_detection() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::seconds(5);

        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0)?;
        track_sdp(&mut timeline, &invite);

        // Re-INVITE with sendonly → hold
        let sdp2 = directional_sdp("PCMU", "10.0.0.1", 20000, "sendonly");
        let reinvite = make_invite_with_sdp(&sdp2, t1)?;
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::Hold));
        Ok(())
    }

    /// Returning to sendrecv after a hold is detected as Resume.
    #[test]
    fn resume_detection() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::seconds(5);
        let t2 = t0 + TimeDelta::seconds(10);

        // Initial sendrecv
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0)?;
        track_sdp(&mut timeline, &invite);

        // Hold (sendonly)
        let sdp2 = directional_sdp("PCMU", "10.0.0.1", 20000, "sendonly");
        let hold = make_invite_with_sdp(&sdp2, t1)?;
        track_sdp(&mut timeline, &hold);
        assert_eq!(timeline[1].event, Some(SdpEvent::Hold));

        // Resume (sendrecv)
        let sdp3 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let resume = make_invite_with_sdp(&sdp3, t2)?;
        track_sdp(&mut timeline, &resume);

        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[2].event, Some(SdpEvent::Resume));
        Ok(())
    }

    /// A re-INVITE swapping PCMU for opus is detected as CodecChange.
    #[test]
    fn codec_change_detection() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::seconds(5);

        // Initial with PCMU
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0)?;
        track_sdp(&mut timeline, &invite);

        // Re-INVITE with opus
        let sdp2 = sendrecv_sdp("opus", "10.0.0.1", 20000);
        let reinvite = make_invite_with_sdp(&sdp2, t1)?;
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::CodecChange));
        Ok(())
    }

    /// A re-INVITE moving audio to `m=image` is detected as T38Switch.
    #[test]
    fn t38_switch_detection() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::seconds(5);

        // Initial audio
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0)?;
        track_sdp(&mut timeline, &invite);

        // Switch to T.38
        let sdp2 = t38_sdp("10.0.0.1", 20000);
        let reinvite = make_invite_with_sdp(&sdp2, t1)?;
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::T38Switch));
        Ok(())
    }

    /// Repeated T.38 re-INVITE offer/answer exchanges (e.g. session refresh
    /// while faxing) emit T38Switch exactly once, at the audio→T.38 transition.
    #[test]
    fn repeated_t38_reinvites_emit_single_switch() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;

        // Initial audio offer/answer
        let audio = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        track_sdp(&mut timeline, &make_invite_with_sdp(&audio, t0)?);
        track_sdp(
            &mut timeline,
            &make_200_with_sdp(&audio, t0 + TimeDelta::seconds(1))?,
        );

        // Three consecutive T.38 offer/answer exchanges
        let t38 = t38_sdp("10.0.0.1", 20000);
        for i in 0..3 {
            let ts = t0 + TimeDelta::seconds(10 * (i + 1));
            track_sdp(&mut timeline, &make_invite_with_sdp(&t38, ts)?);
            track_sdp(
                &mut timeline,
                &make_200_with_sdp(&t38, ts + TimeDelta::seconds(1))?,
            );
        }

        let switches = timeline
            .iter()
            .filter(|e| e.event == Some(SdpEvent::T38Switch))
            .count();
        assert_eq!(
            switches,
            1,
            "T38Switch must fire once for a call that stays in T.38, got timeline {:?}",
            timeline.iter().map(|e| &e.event).collect::<Vec<_>>()
        );
        Ok(())
    }

    /// A genuine T.38 → audio → T.38 sequence emits a new T38Switch for the
    /// second audio→T.38 transition.
    #[test]
    fn t38_after_return_to_audio_emits_new_switch() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;

        let audio = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let t38 = t38_sdp("10.0.0.1", 20000);

        track_sdp(&mut timeline, &make_invite_with_sdp(&audio, t0)?);
        track_sdp(
            &mut timeline,
            &make_invite_with_sdp(&t38, t0 + TimeDelta::seconds(10))?,
        );
        track_sdp(
            &mut timeline,
            &make_invite_with_sdp(&audio, t0 + TimeDelta::seconds(20))?,
        );
        track_sdp(
            &mut timeline,
            &make_invite_with_sdp(&t38, t0 + TimeDelta::seconds(30))?,
        );

        assert_eq!(timeline[1].event, Some(SdpEvent::T38Switch));
        assert_ne!(
            timeline[2].event,
            Some(SdpEvent::T38Switch),
            "returning to audio is not a T.38 switch"
        );
        assert_eq!(
            timeline[3].event,
            Some(SdpEvent::T38Switch),
            "second audio→T.38 transition must emit a new switch"
        );
        Ok(())
    }

    /// A port change with identical codec/mode is a MediaAnchorChange.
    #[test]
    fn media_anchor_change_detection() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::seconds(5);

        // Initial
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0)?;
        track_sdp(&mut timeline, &invite);

        // Same codec/mode but different port
        let sdp2 = sendrecv_sdp("PCMU", "10.0.0.1", 30000);
        let reinvite = make_invite_with_sdp(&sdp2, t1)?;
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::MediaAnchorChange));
        Ok(())
    }

    /// An audio+video offer records codecs from every m= line, not just the first.
    #[test]
    fn multi_mline_timeline_includes_video_codec() -> Result<(), TestError> {
        // An audio+video offer must not drop the video codec from the
        // timeline (it previously recorded only the first m= line).
        let sdp = b"v=0\r\n\
o=- 0 0 IN IP4 10.0.0.1\r\n\
s=-\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 20000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n\
m=video 20002 RTP/AVP 96\r\n\
a=rtpmap:96 H264/90000\r\n\
a=sendrecv\r\n";
        let mut timeline = Vec::new();
        let invite = make_invite_with_sdp(sdp, base_ts()?)?;
        track_sdp(&mut timeline, &invite);

        assert_eq!(timeline.len(), 1);
        let codecs = &timeline[0].codecs;
        assert!(codecs.iter().any(|c| c == "PCMU"), "audio codec present");
        assert!(
            codecs.iter().any(|c| c == "H264"),
            "video codec must appear in the timeline, got {codecs:?}"
        );
        Ok(())
    }

    /// Delayed-offer INVITE: the offerless INVITE creates no exchange, the
    /// SDP first appears in the 200 OK (the offer), and the ACK carries the
    /// answer. Roles must be labeled by offer/answer position, not by the
    /// request/response type of the carrying message.
    #[test]
    fn delayed_offer_roles_labeled_by_position() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::milliseconds(200);
        let t2 = t0 + TimeDelta::milliseconds(400);

        // Offerless INVITE — no SDP, so no timeline entry.
        let invite = make_invite_no_sdp(t0)?;
        track_sdp(&mut timeline, &invite);
        assert!(timeline.is_empty(), "offerless INVITE adds no exchange");

        // 200 OK carries the delayed offer.
        let offer_sdp = sendrecv_sdp("PCMU", "10.0.0.2", 30000);
        let ok = make_200_with_sdp(&offer_sdp, t1)?;
        track_sdp(&mut timeline, &ok);

        assert_eq!(timeline.len(), 1);
        assert_eq!(
            timeline[0].direction,
            OfferAnswer::Offer,
            "the SDP in the 200 OK is the delayed offer, not an answer"
        );
        assert!(
            timeline[0].event.is_none(),
            "first SDP in the dialog has no predecessor → no event"
        );

        // ACK carries the answer, matching the offer's anchor/codecs.
        let answer_sdp = sendrecv_sdp("PCMU", "10.0.0.2", 30000);
        let ack = make_ack_with_sdp(&answer_sdp, t2)?;
        track_sdp(&mut timeline, &ack);

        assert_eq!(timeline.len(), 2);
        assert_eq!(
            timeline[1].direction,
            OfferAnswer::Answer,
            "the SDP in the ACK is the answer to the delayed offer"
        );
        assert!(
            timeline[1].event.is_none(),
            "answer matching the offer's anchor/codecs is not a mid-call event"
        );
        Ok(())
    }

    // ── Per-party comparison ─────────────────────────────────────────
    //
    // Each party's SDP describes that party's own receive address, mode and
    // codecs. An exchange is compared with the previous exchange FROM THE SAME
    // PARTY, never with the other party's. The fixtures below give the caller
    // and the callee distinct signaling and media addresses (RFC 5737), as a
    // real two-party call has.

    /// One party of the test dialog.
    struct Party {
        /// URI user part.
        user: &'static str,
        /// The party's own dialog tag.
        tag: &'static str,
        /// Signaling address the party sends from.
        ip: IpAddr,
    }

    /// The caller: sends the initial INVITE, From tag `caller-tag`.
    const CALLER: Party = Party {
        user: "alice",
        tag: "caller-tag",
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
    };

    /// The callee: answers the initial INVITE, To tag `callee-tag`.
    const CALLEE: Party = Party {
        user: "bob",
        tag: "callee-tag",
        ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
    };

    /// Caller media address used in party fixtures.
    const CALLER_MEDIA: &str = "192.0.2.11";
    /// Callee media address used in party fixtures.
    const CALLEE_MEDIA: &str = "198.51.100.21";

    /// Parse `raw` as sent from `src` to `dst` at `ts`.
    fn parse_between(
        raw: &[u8],
        ts: DateTime<Utc>,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<SipMessage, TestError> {
        Ok(parse_sip(
            raw,
            ts,
            src,
            dst,
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// Build a request `method` sent by `sender` to `peer`, carrying `sdp`.
    ///
    /// `peer_tagged` is false only for the initial INVITE, whose `To` has no
    /// tag yet. An empty `sdp` produces a body-less request.
    fn request(
        method: &str,
        sender: &Party,
        peer: &Party,
        peer_tagged: bool,
        cseq: u32,
        sdp: &[u8],
        ts: DateTime<Utc>,
    ) -> Result<SipMessage, TestError> {
        let to_tag = if peer_tagged {
            format!(";tag={}", peer.tag)
        } else {
            String::new()
        };
        let mut headers = vec![
            format!("From: <sip:{}@example.com>;tag={}", sender.user, sender.tag),
            format!("To: <sip:{}@example.com>{to_tag}", peer.user),
            "Call-ID: party-test@example.com".to_string(),
            format!("CSeq: {cseq} {method}"),
        ];
        if !sdp.is_empty() {
            headers.push("Content-Type: application/sdp".to_string());
        }
        headers.push(format!("Content-Length: {}", sdp.len()));
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        let raw = build_sip(
            &format!("{method} sip:{}@example.com SIP/2.0", peer.user),
            &refs,
            sdp,
        );
        parse_between(&raw, ts, sender.ip, peer.ip)
    }

    /// Build a response `status` sent by `sender` to a `method` request that
    /// `requester` sent, carrying `sdp`.
    fn response(
        status: &str,
        sender: &Party,
        requester: &Party,
        method: &str,
        cseq: u32,
        sdp: &[u8],
        ts: DateTime<Utc>,
    ) -> Result<SipMessage, TestError> {
        let headers = [
            format!(
                "From: <sip:{}@example.com>;tag={}",
                requester.user, requester.tag
            ),
            format!("To: <sip:{}@example.com>;tag={}", sender.user, sender.tag),
            "Call-ID: party-test@example.com".to_string(),
            format!("CSeq: {cseq} {method}"),
            "Content-Type: application/sdp".to_string(),
            format!("Content-Length: {}", sdp.len()),
        ];
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        let raw = build_sip(&format!("SIP/2.0 {status}"), &refs, sdp);
        parse_between(&raw, ts, sender.ip, requester.ip)
    }

    /// The events of `timeline`, oldest first.
    fn events(timeline: &[SdpExchange]) -> Vec<Option<SdpEvent>> {
        timeline.iter().map(|e| e.event.clone()).collect()
    }

    /// SUCCESS. A plain offer/answer with no anchor change is not labeled
    /// moved: the answer describes the callee's own address, which differs
    /// from the caller's because they are two parties, not because anything
    /// moved.
    #[test]
    fn plain_offer_answer_is_not_labeled_anchor_moved() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let answer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 1, &answer, t0)?,
        );

        assert_eq!(timeline.len(), 2, "an offer and an answer are recorded");
        assert_eq!(
            timeline[1].direction,
            OfferAnswer::Answer,
            "the 200 OK answers the INVITE"
        );
        assert_eq!(
            events(&timeline),
            vec![None, None],
            "a plain offer/answer with no anchor change is not labeled moved"
        );
        Ok(())
    }

    /// Build an audio+video SDP body: the audio leg first, then video.
    fn audio_video_sdp(addr: &str, audio_port: u16, video_port: u16) -> Vec<u8> {
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {audio_port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=sendrecv\r\n\
             m=video {video_port} RTP/AVP 96\r\n\
             a=rtpmap:96 H264/90000\r\n\
             a=sendrecv\r\n"
        )
        .into_bytes()
    }

    /// Track the initial INVITE (caller) and its 200 OK (callee), both
    /// sendrecv PCMU at each party's own media address.
    fn established_call(t0: DateTime<Utc>) -> Result<Vec<SdpExchange>, TestError> {
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let answer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response(
                "200 OK",
                &CALLEE,
                &CALLER,
                "INVITE",
                1,
                &answer,
                t0 + TimeDelta::milliseconds(100),
            )?,
        );
        Ok(timeline)
    }

    /// The tag the exchange at `index` is attributed to.
    fn sender_tag(timeline: &[SdpExchange], index: usize) -> Option<&str> {
        timeline.get(index).and_then(|e| e.sender.tag.as_deref())
    }

    /// SUCCESS. Delayed offer with the two parties at different addresses:
    /// the callee's 2xx offers, the caller's ACK answers, and neither is an
    /// anchor change.
    #[test]
    fn delayed_offer_answer_is_not_labeled_anchor_moved() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = Vec::new();
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, b"", t0)?,
        );
        let offer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 1, &offer, t0)?,
        );
        let answer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("ACK", &CALLER, &CALLEE, true, 1, &answer, t0)?,
        );

        assert_eq!(timeline.len(), 2, "the offerless INVITE adds no exchange");
        assert_eq!(
            timeline[0].direction,
            OfferAnswer::Offer,
            "the 2xx carries the delayed offer"
        );
        assert_eq!(
            timeline[1].direction,
            OfferAnswer::Answer,
            "the ACK carries the answer"
        );
        assert_eq!(
            sender_tag(&timeline, 0),
            Some(CALLEE.tag),
            "2xx is the callee's"
        );
        assert_eq!(
            sender_tag(&timeline, 1),
            Some(CALLER.tag),
            "ACK is the caller's"
        );
        assert_eq!(
            events(&timeline),
            vec![None, None],
            "a delayed offer/answer with no anchor change is not labeled moved"
        );
        Ok(())
    }

    /// SUCCESS. A re-INVITE from the caller with a new port is an anchor
    /// change, attributed to the caller; the callee's unchanged answer is not.
    #[test]
    fn caller_reinvite_with_new_port_is_an_anchor_change_by_the_caller() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20002);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::MediaAnchorChange), None],
            "only the caller's re-INVITE moved an anchor"
        );
        assert_eq!(
            sender_tag(&timeline, 2),
            Some(CALLER.tag),
            "the re-INVITE is the caller's"
        );
        assert_eq!(
            timeline[2].sender.addr, CALLER.ip,
            "the move is attributed to the caller's signaling address"
        );
        Ok(())
    }

    /// SUCCESS (neighbor). A caller re-INVITE repeating its own SDP (a session
    /// refresh) is no event, although the previous exchange in the timeline is
    /// the callee's answer at another address.
    #[test]
    fn caller_session_refresh_is_not_an_anchor_change() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, None, None],
            "a refresh that changes nothing records no event"
        );
        Ok(())
    }

    /// SUCCESS. A re-INVITE from the callee with a new media IP is an anchor
    /// change attributed to the callee, compared with the callee's own 200 OK;
    /// the caller's unchanged answer is not.
    #[test]
    fn callee_reinvite_with_new_ip_is_an_anchor_change_by_the_callee() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", "198.51.100.22", 30000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLEE, &CALLER, true, 1, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLER, &CALLEE, "INVITE", 1, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::MediaAnchorChange), None],
            "only the callee's re-INVITE moved an anchor"
        );
        assert_eq!(
            sender_tag(&timeline, 2),
            Some(CALLEE.tag),
            "the re-INVITE is the callee's"
        );
        assert_eq!(
            sender_tag(&timeline, 3),
            Some(CALLER.tag),
            "the answer is the caller's"
        );
        Ok(())
    }

    /// SUCCESS. The answer to a re-INVITE that moves the ANSWERER's own port
    /// is an anchor change; the unchanged re-INVITE is not.
    #[test]
    fn answer_moving_its_own_anchor_is_an_anchor_change() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30002);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, None, Some(SdpEvent::MediaAnchorChange)],
            "the callee's answer moved the callee's anchor"
        );
        assert_eq!(
            sender_tag(&timeline, 3),
            Some(CALLEE.tag),
            "the moving answer is the callee's"
        );
        Ok(())
    }

    /// EDGE. Both parties move in one exchange: the offer and the answer each
    /// report their own anchor change. An anchor is each party's own address,
    /// so the answer's move is not the offer's move repeated.
    #[test]
    fn both_parties_moving_report_two_anchor_changes() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20002);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30002);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![
                None,
                None,
                Some(SdpEvent::MediaAnchorChange),
                Some(SdpEvent::MediaAnchorChange)
            ],
            "each party's own move is reported once"
        );
        Ok(())
    }

    /// FAILURE (cross-party mode). A `sendonly` answer to a `sendrecv` offer
    /// is the callee's first SDP, not a hold: there is no earlier callee state
    /// for it to have changed from.
    #[test]
    fn sendonly_answer_to_the_initial_offer_is_not_hold() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let answer = directional_sdp("PCMU", CALLEE_MEDIA, 30000, "sendonly");
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 1, &answer, t0)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None],
            "the other party's sendrecv offer is not the answerer's prior state"
        );
        Ok(())
    }

    /// SUCCESS. Hold and resume by the caller with the callee answering each:
    /// the caller's `sendonly` is Hold, the callee's `recvonly` answer is no
    /// event, and the caller's return to `sendrecv` is Resume, compared with
    /// the caller's own `sendonly`, not the callee's `recvonly`.
    #[test]
    fn caller_hold_and_resume_with_answers_between() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let steps: [(bool, &str, u32); 4] = [
            (true, "sendonly", 2),
            (false, "recvonly", 2),
            (true, "sendrecv", 3),
            (false, "sendrecv", 3),
        ];
        for (i, (from_caller, mode, cseq)) in steps.into_iter().enumerate() {
            let ts = t0 + TimeDelta::seconds(5 * (i as i64 + 1));
            if from_caller {
                let sdp = directional_sdp("PCMU", CALLER_MEDIA, 20000, mode);
                track_sdp(
                    &mut timeline,
                    &request("INVITE", &CALLER, &CALLEE, true, cseq, &sdp, ts)?,
                );
            } else {
                let sdp = directional_sdp("PCMU", CALLEE_MEDIA, 30000, mode);
                track_sdp(
                    &mut timeline,
                    &response("200 OK", &CALLEE, &CALLER, "INVITE", cseq, &sdp, ts)?,
                );
            }
        }

        assert_eq!(
            events(&timeline),
            vec![
                None,
                None,
                Some(SdpEvent::Hold),
                None,
                Some(SdpEvent::Resume),
                None
            ],
            "hold and resume are the caller's, the callee only answers"
        );
        Ok(())
    }

    /// SUCCESS (boundary). An `inactive` hold answered `inactive`: the
    /// answerer accepts the hold its offer reported, so the hold is reported
    /// once, on the offer.
    #[test]
    fn inactive_hold_answered_inactive_reports_one_hold() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let hold = directional_sdp("PCMU", CALLER_MEDIA, 20000, "inactive");
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &hold, t1)?,
        );
        let answer = directional_sdp("PCMU", CALLEE_MEDIA, 30000, "inactive");
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &answer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::Hold), None],
            "one hold, reported on the offer that placed it"
        );
        Ok(())
    }

    /// SUCCESS. A hold placed by the callee is the callee's Hold, compared
    /// with the callee's own 200 OK.
    #[test]
    fn callee_hold_is_attributed_to_the_callee() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let hold = directional_sdp("PCMU", CALLEE_MEDIA, 30000, "sendonly");
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLEE, &CALLER, true, 1, &hold, t1)?,
        );
        let answer = directional_sdp("PCMU", CALLER_MEDIA, 20000, "recvonly");
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLER, &CALLEE, "INVITE", 1, &answer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::Hold), None],
            "the callee held; the caller answered"
        );
        assert_eq!(
            sender_tag(&timeline, 2),
            Some(CALLEE.tag),
            "the hold is the callee's"
        );
        Ok(())
    }

    /// FAILURE (cross-party codec). An answer choosing a different codec from
    /// the offer is the answerer's first SDP, not a codec change, even when
    /// both parties use one media address (a B2BUA anchoring both).
    #[test]
    fn answer_choosing_another_codec_is_not_a_codec_change() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", "203.0.113.30", 40000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let answer = sendrecv_sdp("PCMA", "203.0.113.30", 40000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 1, &answer, t0)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None],
            "the offerer's codec list is not the answerer's prior state"
        );
        Ok(())
    }

    /// SUCCESS. A caller re-INVITE switching to opus is CodecChange; the
    /// callee's opus answer accepts it and records no second event.
    #[test]
    fn codec_change_offer_and_its_answer_report_one_change() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("opus", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("opus", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::CodecChange), None],
            "one codec change, reported on the offer"
        );
        Ok(())
    }

    /// SUCCESS (neighbor). An unchanged re-offer answered with a new codec:
    /// the answerer changed its own codec, so the answer is CodecChange.
    #[test]
    fn answer_changing_its_own_codec_is_a_codec_change() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("opus", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, None, Some(SdpEvent::CodecChange)],
            "the callee changed its codec; the caller did not"
        );
        Ok(())
    }

    /// SUCCESS. A caller T.38 re-INVITE is T38Switch; the callee's T.38
    /// answer on a new port accepts it and records no second event.
    #[test]
    fn t38_offer_and_its_answer_report_one_switch() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = t38_sdp(CALLER_MEDIA, 20004);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = t38_sdp(CALLEE_MEDIA, 30004);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::T38Switch), None],
            "one T.38 switch, reported on the offer"
        );
        Ok(())
    }

    /// SUCCESS (neighbor). A T.38 switch the callee initiates is the callee's,
    /// and the caller's T.38 answer records no second event.
    #[test]
    fn callee_initiated_t38_switch_is_reported_once() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = t38_sdp(CALLEE_MEDIA, 30004);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLEE, &CALLER, true, 1, &reoffer, t1)?,
        );
        let reanswer = t38_sdp(CALLER_MEDIA, 20004);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLER, &CALLEE, "INVITE", 1, &reanswer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::T38Switch), None],
            "the callee switched to T.38; the caller accepted"
        );
        assert_eq!(
            sender_tag(&timeline, 2),
            Some(CALLEE.tag),
            "the switch is the callee's"
        );
        Ok(())
    }

    /// SUCCESS. Audio+video offer and answer at two parties' addresses is no
    /// event; a later caller re-INVITE moving the first (audio) port is an
    /// anchor change.
    #[test]
    fn multi_mline_offer_answer_then_audio_move() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = Vec::new();
        let offer = audio_video_sdp(CALLER_MEDIA, 20000, 20002);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let answer = audio_video_sdp(CALLEE_MEDIA, 30000, 30002);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 1, &answer, t0)?,
        );
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = audio_video_sdp(CALLER_MEDIA, 20010, 20002);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::MediaAnchorChange)],
            "only the caller's audio move is an anchor change"
        );
        Ok(())
    }

    /// SUCCESS. An UPDATE from the caller with a new port is an anchor change;
    /// the callee's unchanged 200 OK to the UPDATE is not.
    #[test]
    fn update_with_new_port_is_an_anchor_change_and_its_answer_is_not() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20008);
        track_sdp(
            &mut timeline,
            &request("UPDATE", &CALLER, &CALLEE, true, 2, &reoffer, t1)?,
        );
        let reanswer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "UPDATE", 2, &reanswer, t1)?,
        );

        assert_eq!(
            timeline[2].direction,
            OfferAnswer::Offer,
            "the UPDATE carries an offer"
        );
        assert_eq!(
            timeline[3].direction,
            OfferAnswer::Answer,
            "the 200 OK to the UPDATE carries the answer"
        );
        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::MediaAnchorChange), None],
            "the UPDATE moved the caller's anchor; the answer moved nothing"
        );
        Ok(())
    }

    /// EDGE. A REFER entry carries no media and is no party's SDP state: a
    /// re-INVITE after it is compared with the caller's own last SDP, not with
    /// the transfer marker's absent address.
    #[test]
    fn exchange_after_refer_is_not_compared_with_the_transfer_marker() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let mut timeline = established_call(t0)?;
        let t1 = t0 + TimeDelta::seconds(5);
        track_transfer(
            &mut timeline,
            &request("REFER", &CALLER, &CALLEE, true, 2, b"", t1)?,
        );
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, true, 3, &reoffer, t1)?,
        );

        assert_eq!(timeline.len(), 4, "offer, answer, transfer, re-INVITE");
        assert_eq!(
            timeline[3].event, None,
            "the caller's unchanged SDP is no event after a REFER"
        );
        Ok(())
    }

    /// EDGE. Two copies of the callee's answer, one on each leg of a media
    /// relay: the relay rewrites the address on its leg. Each copy is the
    /// first SDP on its leg, so neither is an anchor change; a later change on
    /// the relay's leg still is.
    #[test]
    fn relay_leg_copies_are_tracked_per_signaling_address() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let relay = Party {
            user: "bob",
            tag: CALLEE.tag,
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        };
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let raw_answer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response(
                "183 Session Progress",
                &CALLEE,
                &CALLER,
                "INVITE",
                1,
                &raw_answer,
                t0,
            )?,
        );
        let relayed = sendrecv_sdp("PCMU", "203.0.113.6", 40000);
        track_sdp(
            &mut timeline,
            &response(
                "183 Session Progress",
                &relay,
                &CALLER,
                "INVITE",
                1,
                &relayed,
                t0,
            )?,
        );
        track_sdp(
            &mut timeline,
            &response("200 OK", &CALLEE, &CALLER, "INVITE", 1, &raw_answer, t0)?,
        );
        track_sdp(
            &mut timeline,
            &response("200 OK", &relay, &CALLER, "INVITE", 1, &relayed, t0)?,
        );
        let moved = sendrecv_sdp("PCMU", "203.0.113.6", 40002);
        track_sdp(
            &mut timeline,
            &response("200 OK", &relay, &CALLER, "INVITE", 1, &moved, t0)?,
        );

        assert_eq!(
            events(&timeline),
            vec![
                None,
                None,
                None,
                None,
                None,
                Some(SdpEvent::MediaAnchorChange)
            ],
            "the relay's rewrite is not a move; a move on the relay's leg is"
        );
        Ok(())
    }

    /// EDGE. Forked early dialogs: two 183s with different `To` tags are two
    /// parties, so neither is compared with the other.
    #[test]
    fn forked_early_answers_are_separate_parties() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let fork = Party {
            user: "bob",
            tag: "fork-tag",
            ip: CALLEE.ip,
        };
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        track_sdp(
            &mut timeline,
            &request("INVITE", &CALLER, &CALLEE, false, 1, &offer, t0)?,
        );
        let first = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        track_sdp(
            &mut timeline,
            &response(
                "183 Session Progress",
                &CALLEE,
                &CALLER,
                "INVITE",
                1,
                &first,
                t0,
            )?,
        );
        let second = sendrecv_sdp("PCMU", "198.51.100.23", 32000);
        track_sdp(
            &mut timeline,
            &response(
                "183 Session Progress",
                &fork,
                &CALLER,
                "INVITE",
                1,
                &second,
                t0,
            )?,
        );

        assert_eq!(
            events(&timeline),
            vec![None, None, None],
            "each fork's first SDP has no predecessor"
        );
        Ok(())
    }

    /// EDGE. Messages without a dialog tag fall back to the signaling address:
    /// a tagless answer from another address is no event, and a tagless
    /// re-offer from the offerer's address with a new port is an anchor
    /// change.
    #[test]
    fn tagless_messages_fall_back_to_the_signaling_address() -> Result<(), TestError> {
        let t0 = base_ts()?;
        let untagged = |first_line: &str, cseq: &str, sdp: &[u8]| {
            build_sip(
                first_line,
                &[
                    "From: <sip:alice@example.com>",
                    "To: <sip:bob@example.com>",
                    "Call-ID: tagless@example.com",
                    cseq,
                    "Content-Type: application/sdp",
                    &format!("Content-Length: {}", sdp.len()),
                ],
                sdp,
            )
        };
        let mut timeline = Vec::new();
        let offer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20000);
        let raw = untagged(
            "INVITE sip:bob@example.com SIP/2.0",
            "CSeq: 1 INVITE",
            &offer,
        );
        track_sdp(
            &mut timeline,
            &parse_between(&raw, t0, CALLER.ip, CALLEE.ip)?,
        );
        let answer = sendrecv_sdp("PCMU", CALLEE_MEDIA, 30000);
        let raw = untagged("SIP/2.0 200 OK", "CSeq: 1 INVITE", &answer);
        track_sdp(
            &mut timeline,
            &parse_between(&raw, t0, CALLEE.ip, CALLER.ip)?,
        );
        let reoffer = sendrecv_sdp("PCMU", CALLER_MEDIA, 20002);
        let raw = untagged(
            "INVITE sip:bob@example.com SIP/2.0",
            "CSeq: 2 INVITE",
            &reoffer,
        );
        track_sdp(
            &mut timeline,
            &parse_between(&raw, t0, CALLER.ip, CALLEE.ip)?,
        );

        assert_eq!(timeline[1].sender.tag, None, "no tag was on the wire");
        assert_eq!(
            events(&timeline),
            vec![None, None, Some(SdpEvent::MediaAnchorChange)],
            "the signaling address separates the parties when no tag does"
        );
        Ok(())
    }

    /// A message without an SDP body leaves the timeline untouched.
    #[test]
    fn no_sdp_body_ignored() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: nosdp@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;

        track_sdp(&mut timeline, &msg);
        assert!(timeline.is_empty());
        Ok(())
    }

    /// `a=inactive` is also detected as Hold (not just sendonly).
    #[test]
    fn inactive_hold_detection() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;
        let t1 = t0 + TimeDelta::seconds(5);

        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0)?;
        track_sdp(&mut timeline, &invite);

        // Hold with inactive mode
        let sdp2 = directional_sdp("PCMU", "10.0.0.1", 20000, "inactive");
        let reinvite = make_invite_with_sdp(&sdp2, t1)?;
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline[1].event, Some(SdpEvent::Hold));
        Ok(())
    }

    /// A REFER request records a Transfer event with the Refer-To target.
    #[test]
    fn track_transfer_creates_event() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;

        let raw = build_sip(
            "REFER sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: transfer-test@example.com",
                "CSeq: 3 REFER",
                "Refer-To: <sip:carol@example.com>",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            t0,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;

        track_transfer(&mut timeline, &msg);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].mode, "transfer");
        assert_eq!(
            timeline[0].event,
            Some(SdpEvent::Transfer {
                target: Some("<sip:carol@example.com>".to_string()),
            })
        );
        Ok(())
    }

    /// A REFER with no `Refer-To` records `None`, not a fabricated target.
    ///
    /// It used to record the literal `"unknown"`, which a call-flow export
    /// renders as a transfer to a party of that name — indistinguishable from a
    /// real one, and not a URI. A malformed REFER should read as malformed.
    #[test]
    fn track_transfer_records_no_target_when_refer_to_is_absent() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;

        // Same REFER as the test above, minus the Refer-To header.
        let raw = build_sip(
            "REFER sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: transfer-no-target@example.com",
                "CSeq: 3 REFER",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            t0,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;

        track_transfer(&mut timeline, &msg);
        assert_eq!(timeline.len(), 1, "the REFER itself is still recorded");
        assert_eq!(
            timeline[0].event,
            Some(SdpEvent::Transfer { target: None }),
            "an absent Refer-To must not become a target string"
        );
        Ok(())
    }

    /// A non-REFER request is ignored by track_transfer.
    #[test]
    fn track_transfer_ignores_non_refer() -> Result<(), TestError> {
        let mut timeline = Vec::new();
        let t0 = base_ts()?;

        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: noref@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            t0,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;

        track_transfer(&mut timeline, &msg);
        assert!(timeline.is_empty());
        Ok(())
    }
}
