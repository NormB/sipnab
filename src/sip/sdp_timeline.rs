// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDP negotiation timeline tracking for SIP dialogs.
//!
//! Records each SDP offer and answer as messages flow through a dialog,
//! detecting mid-call events such as hold, resume, codec changes, T.38
//! fax switchover, and media anchor (IP:port) changes.

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
    /// Detected mid-call event, if any, compared to the previous exchange.
    pub event: Option<SdpEvent>,
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
/// an [`SdpExchange`] entry. Compares with the previous entry in the timeline
/// to detect mid-call events (hold, resume, codec change, T.38, anchor change).
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

    let event = detect_event(
        timeline,
        &codecs,
        &media_addr,
        media_port,
        mode.as_str(),
        is_t38,
    );

    timeline.push(SdpExchange {
        timestamp: msg.timestamp,
        direction,
        codecs,
        media_addr,
        media_port,
        mode: mode.as_str().to_string(),
        is_t38,
        event,
    });
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
/// Two delayed-offer exceptions (RFC 3261 §13.2.1) override the type-based
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

/// Compare the current SDP exchange against the previous one to detect events.
///
/// Priority order (first match wins):
/// 1. T.38 switch (media type changed to image)
/// 2. Hold (sendrecv → sendonly/inactive)
/// 3. Resume (sendonly/inactive → sendrecv)
/// 4. Media anchor change (IP or port changed)
/// 5. Codec change (different codec set)
///
/// # Arguments
///
/// * `timeline` — prior exchanges; only the last entry is compared against.
/// * `codecs` — de-duplicated codec names of the current exchange.
/// * `media_addr` / `media_port` — current media anchor.
/// * `mode` — current direction mode string (`"sendrecv"` etc.).
/// * `is_t38` — whether the current first media description is `m=image`.
///
/// # Returns
///
/// The highest-priority detected event, or `None` when the timeline is
/// empty or nothing changed.
fn detect_event(
    timeline: &[SdpExchange],
    codecs: &[String],
    media_addr: &Option<String>,
    media_port: Option<u16>,
    mode: &str,
    is_t38: bool,
) -> Option<SdpEvent> {
    let prev = timeline.last()?;

    // T.38 switch takes priority. Compare against the previous exchange's
    // media *state*, not its event: repeated T.38 re-INVITEs (session
    // refresh) leave `prev.event` as None, which must not re-trigger.
    if is_t38 && !prev.is_t38 {
        return Some(SdpEvent::T38Switch);
    }

    // Hold detection: was sendrecv, now sendonly or inactive
    let prev_active = prev.mode == "sendrecv";
    let now_held = mode == "sendonly" || mode == "inactive";
    if prev_active && now_held {
        return Some(SdpEvent::Hold);
    }

    // Resume detection: was sendonly/inactive, now sendrecv
    let prev_held = prev.mode == "sendonly" || prev.mode == "inactive";
    let now_active = mode == "sendrecv";
    if prev_held && now_active {
        return Some(SdpEvent::Resume);
    }

    // Media anchor change: IP or port changed
    if media_addr != &prev.media_addr || media_port != prev.media_port {
        return Some(SdpEvent::MediaAnchorChange);
    }

    // Codec change: different codec set
    if codecs != prev.codecs {
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

    /// Fixed 127.0.0.1 address used for all test messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) tests offset from.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build an INVITE carrying `sdp_body` captured at `ts`.
    fn make_invite_with_sdp(sdp_body: &[u8], ts: DateTime<Utc>) -> SipMessage {
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE with SDP")
    }

    /// Build a 200 OK response carrying `sdp_body` captured at `ts`.
    fn make_200_with_sdp(sdp_body: &[u8], ts: DateTime<Utc>) -> SipMessage {
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse 200 OK with SDP")
    }

    /// Build an ACK request carrying `sdp_body` captured at `ts`.
    fn make_ack_with_sdp(sdp_body: &[u8], ts: DateTime<Utc>) -> SipMessage {
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse ACK with SDP")
    }

    /// Build an INVITE with no message body (no SDP) captured at `ts`.
    fn make_invite_no_sdp(ts: DateTime<Utc>) -> SipMessage {
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE without SDP")
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
    fn static_payload_types_are_named_without_an_rtpmap() {
        let mut timeline = Vec::new();
        let sdp = static_pt_sdp("0 8 18", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, base_ts());
        track_sdp(&mut timeline, &invite);

        assert_eq!(timeline.len(), 1);
        assert_eq!(
            timeline[0].codecs,
            vec!["PCMU", "PCMA", "G729"],
            "RFC 3551 static payload types must be named from the m= line when \
             no a=rtpmap is present; got {:?}",
            timeline[0].codecs
        );
    }

    /// A dynamic payload type with no `a=rtpmap` is genuinely unnameable —
    /// 96-127 mean nothing without the map. It must not be guessed at, and it
    /// must not suppress the static entries beside it.
    #[test]
    fn dynamic_payload_types_without_an_rtpmap_are_not_invented() {
        let mut timeline = Vec::new();
        let sdp = static_pt_sdp("0 96 97", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, base_ts());
        track_sdp(&mut timeline, &invite);

        assert_eq!(
            timeline[0].codecs,
            vec!["PCMU"],
            "dynamic types carry no registry meaning without a=rtpmap and must \
             be omitted, not named; got {:?}",
            timeline[0].codecs
        );
    }

    /// An explicit `a=rtpmap` wins over the static table. RFC 3551 permits
    /// re-binding a static number, and the wire spelling is the evidence.
    #[test]
    fn an_explicit_rtpmap_overrides_the_static_table() {
        let mut timeline = Vec::new();
        let sdp = sendrecv_sdp("SomethingElse", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, base_ts());
        track_sdp(&mut timeline, &invite);

        assert_eq!(
            timeline[0].codecs,
            vec!["SomethingElse"],
            "payload type 0 was explicitly mapped; the static default must not \
             override what the wire said"
        );
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

    /// First offer records no event; the answer from a different anchor
    /// records a MediaAnchorChange.
    #[test]
    fn initial_offer_and_answer() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(500);

        let sdp = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp, t0);
        track_sdp(&mut timeline, &invite);

        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].direction, OfferAnswer::Offer);
        assert_eq!(timeline[0].codecs, vec!["PCMU"]);
        assert_eq!(timeline[0].media_addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(timeline[0].media_port, Some(20000));
        assert_eq!(timeline[0].mode, "sendrecv");
        assert!(timeline[0].event.is_none()); // No previous → no event

        let answer_sdp = sendrecv_sdp("PCMU", "10.0.0.2", 30000);
        let ok = make_200_with_sdp(&answer_sdp, t1);
        track_sdp(&mut timeline, &ok);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].direction, OfferAnswer::Answer);
        // Different IP and port → anchor change
        assert_eq!(timeline[1].event, Some(SdpEvent::MediaAnchorChange));
    }

    /// A re-INVITE switching sendrecv to sendonly is detected as Hold.
    #[test]
    fn hold_detection() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);

        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0);
        track_sdp(&mut timeline, &invite);

        // Re-INVITE with sendonly → hold
        let sdp2 = directional_sdp("PCMU", "10.0.0.1", 20000, "sendonly");
        let reinvite = make_invite_with_sdp(&sdp2, t1);
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::Hold));
    }

    /// Returning to sendrecv after a hold is detected as Resume.
    #[test]
    fn resume_detection() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);
        let t2 = t0 + TimeDelta::seconds(10);

        // Initial sendrecv
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0);
        track_sdp(&mut timeline, &invite);

        // Hold (sendonly)
        let sdp2 = directional_sdp("PCMU", "10.0.0.1", 20000, "sendonly");
        let hold = make_invite_with_sdp(&sdp2, t1);
        track_sdp(&mut timeline, &hold);
        assert_eq!(timeline[1].event, Some(SdpEvent::Hold));

        // Resume (sendrecv)
        let sdp3 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let resume = make_invite_with_sdp(&sdp3, t2);
        track_sdp(&mut timeline, &resume);

        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[2].event, Some(SdpEvent::Resume));
    }

    /// A re-INVITE swapping PCMU for opus is detected as CodecChange.
    #[test]
    fn codec_change_detection() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);

        // Initial with PCMU
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0);
        track_sdp(&mut timeline, &invite);

        // Re-INVITE with opus
        let sdp2 = sendrecv_sdp("opus", "10.0.0.1", 20000);
        let reinvite = make_invite_with_sdp(&sdp2, t1);
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::CodecChange));
    }

    /// A re-INVITE moving audio to `m=image` is detected as T38Switch.
    #[test]
    fn t38_switch_detection() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);

        // Initial audio
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0);
        track_sdp(&mut timeline, &invite);

        // Switch to T.38
        let sdp2 = t38_sdp("10.0.0.1", 20000);
        let reinvite = make_invite_with_sdp(&sdp2, t1);
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::T38Switch));
    }

    /// Repeated T.38 re-INVITE offer/answer exchanges (e.g. session refresh
    /// while faxing) emit T38Switch exactly once, at the audio→T.38 transition.
    #[test]
    fn repeated_t38_reinvites_emit_single_switch() {
        let mut timeline = Vec::new();
        let t0 = base_ts();

        // Initial audio offer/answer
        let audio = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        track_sdp(&mut timeline, &make_invite_with_sdp(&audio, t0));
        track_sdp(
            &mut timeline,
            &make_200_with_sdp(&audio, t0 + TimeDelta::seconds(1)),
        );

        // Three consecutive T.38 offer/answer exchanges
        let t38 = t38_sdp("10.0.0.1", 20000);
        for i in 0..3 {
            let ts = t0 + TimeDelta::seconds(10 * (i + 1));
            track_sdp(&mut timeline, &make_invite_with_sdp(&t38, ts));
            track_sdp(
                &mut timeline,
                &make_200_with_sdp(&t38, ts + TimeDelta::seconds(1)),
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
    }

    /// A genuine T.38 → audio → T.38 sequence emits a new T38Switch for the
    /// second audio→T.38 transition.
    #[test]
    fn t38_after_return_to_audio_emits_new_switch() {
        let mut timeline = Vec::new();
        let t0 = base_ts();

        let audio = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let t38 = t38_sdp("10.0.0.1", 20000);

        track_sdp(&mut timeline, &make_invite_with_sdp(&audio, t0));
        track_sdp(
            &mut timeline,
            &make_invite_with_sdp(&t38, t0 + TimeDelta::seconds(10)),
        );
        track_sdp(
            &mut timeline,
            &make_invite_with_sdp(&audio, t0 + TimeDelta::seconds(20)),
        );
        track_sdp(
            &mut timeline,
            &make_invite_with_sdp(&t38, t0 + TimeDelta::seconds(30)),
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
    }

    /// A port change with identical codec/mode is a MediaAnchorChange.
    #[test]
    fn media_anchor_change_detection() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);

        // Initial
        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0);
        track_sdp(&mut timeline, &invite);

        // Same codec/mode but different port
        let sdp2 = sendrecv_sdp("PCMU", "10.0.0.1", 30000);
        let reinvite = make_invite_with_sdp(&sdp2, t1);
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].event, Some(SdpEvent::MediaAnchorChange));
    }

    /// An audio+video offer records codecs from every m= line, not just the first.
    #[test]
    fn multi_mline_timeline_includes_video_codec() {
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
        let invite = make_invite_with_sdp(sdp, base_ts());
        track_sdp(&mut timeline, &invite);

        assert_eq!(timeline.len(), 1);
        let codecs = &timeline[0].codecs;
        assert!(codecs.iter().any(|c| c == "PCMU"), "audio codec present");
        assert!(
            codecs.iter().any(|c| c == "H264"),
            "video codec must appear in the timeline, got {codecs:?}"
        );
    }

    /// Delayed-offer INVITE: the offerless INVITE creates no exchange, the
    /// SDP first appears in the 200 OK (the offer), and the ACK carries the
    /// answer. Roles must be labeled by offer/answer position, not by the
    /// request/response type of the carrying message.
    #[test]
    fn delayed_offer_roles_labeled_by_position() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(200);
        let t2 = t0 + TimeDelta::milliseconds(400);

        // Offerless INVITE — no SDP, so no timeline entry.
        let invite = make_invite_no_sdp(t0);
        track_sdp(&mut timeline, &invite);
        assert!(timeline.is_empty(), "offerless INVITE adds no exchange");

        // 200 OK carries the delayed offer.
        let offer_sdp = sendrecv_sdp("PCMU", "10.0.0.2", 30000);
        let ok = make_200_with_sdp(&offer_sdp, t1);
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
        let ack = make_ack_with_sdp(&answer_sdp, t2);
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
    }

    /// A message without an SDP body leaves the timeline untouched.
    #[test]
    fn no_sdp_body_ignored() {
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
            base_ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        track_sdp(&mut timeline, &msg);
        assert!(timeline.is_empty());
    }

    /// `a=inactive` is also detected as Hold (not just sendonly).
    #[test]
    fn inactive_hold_detection() {
        let mut timeline = Vec::new();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);

        let sdp1 = sendrecv_sdp("PCMU", "10.0.0.1", 20000);
        let invite = make_invite_with_sdp(&sdp1, t0);
        track_sdp(&mut timeline, &invite);

        // Hold with inactive mode
        let sdp2 = directional_sdp("PCMU", "10.0.0.1", 20000, "inactive");
        let reinvite = make_invite_with_sdp(&sdp2, t1);
        track_sdp(&mut timeline, &reinvite);

        assert_eq!(timeline[1].event, Some(SdpEvent::Hold));
    }

    /// A REFER request records a Transfer event with the Refer-To target.
    #[test]
    fn track_transfer_creates_event() {
        let mut timeline = Vec::new();
        let t0 = base_ts();

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
        )
        .expect("should parse REFER");

        track_transfer(&mut timeline, &msg);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].mode, "transfer");
        assert_eq!(
            timeline[0].event,
            Some(SdpEvent::Transfer {
                target: Some("<sip:carol@example.com>".to_string()),
            })
        );
    }

    /// A REFER with no `Refer-To` records `None`, not a fabricated target.
    ///
    /// It used to record the literal `"unknown"`, which a call-flow export
    /// renders as a transfer to a party of that name — indistinguishable from a
    /// real one, and not a URI. A malformed REFER should read as malformed.
    #[test]
    fn track_transfer_records_no_target_when_refer_to_is_absent() {
        let mut timeline = Vec::new();
        let t0 = base_ts();

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
        )
        .expect("should parse REFER");

        track_transfer(&mut timeline, &msg);
        assert_eq!(timeline.len(), 1, "the REFER itself is still recorded");
        assert_eq!(
            timeline[0].event,
            Some(SdpEvent::Transfer { target: None }),
            "an absent Refer-To must not become a target string"
        );
    }

    /// A non-REFER request is ignored by track_transfer.
    #[test]
    fn track_transfer_ignores_non_refer() {
        let mut timeline = Vec::new();
        let t0 = base_ts();

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
        )
        .expect("should parse INVITE");

        track_transfer(&mut timeline, &msg);
        assert!(timeline.is_empty());
    }
}
