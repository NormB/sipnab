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
    /// Codec names from the first audio media description's rtpmap entries.
    pub codecs: Vec<String>,
    /// Media IP address (effective address from session or media level `c=`).
    pub media_addr: Option<String>,
    /// Media port from the first audio media description.
    pub media_port: Option<u16>,
    /// Stream directionality: `"sendrecv"`, `"sendonly"`, `"recvonly"`, or `"inactive"`.
    pub mode: String,
    /// Detected mid-call event, if any, compared to the previous exchange.
    pub event: Option<SdpEvent>,
}

/// Mid-call SDP event detected by comparing successive exchanges.
#[derive(Debug, Clone, PartialEq)]
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
}

/// Whether an SDP body is an offer or an answer in the offer/answer model.
#[derive(Debug, Clone, PartialEq)]
pub enum OfferAnswer {
    /// SDP offer (typically in INVITE or re-INVITE requests).
    Offer,
    /// SDP answer (typically in 200 OK responses to INVITE).
    Answer,
}

/// Track SDP from a SIP message and append to the timeline.
///
/// If the message contains an `application/sdp` body, parses it and creates
/// an [`SdpExchange`] entry. Compares with the previous entry in the timeline
/// to detect mid-call events (hold, resume, codec change, T.38, anchor change).
///
/// Messages without SDP bodies are silently ignored.
pub fn track_sdp(timeline: &mut Vec<SdpExchange>, msg: &SipMessage) {
    let sdp = match msg.sdp() {
        Some(s) => s,
        None => return,
    };

    let direction = determine_offer_answer(msg);
    let (codecs, media_addr, media_port, mode, is_t38) = extract_media_info(&sdp);

    let event = detect_event(timeline, &codecs, &media_addr, media_port, &mode, is_t38);

    timeline.push(SdpExchange {
        timestamp: msg.timestamp,
        direction,
        codecs,
        media_addr,
        media_port,
        mode,
        event,
    });
}

/// Determine whether an SDP body is an offer or answer based on the SIP message type.
///
/// - Requests (INVITE, UPDATE) carry offers
/// - Responses (200 OK, 183, etc.) carry answers
fn determine_offer_answer(msg: &SipMessage) -> OfferAnswer {
    if msg.is_request {
        OfferAnswer::Offer
    } else {
        OfferAnswer::Answer
    }
}

/// Extract codec list, media address, port, direction mode, and T.38 flag
/// from the first media description in the SDP session.
fn extract_media_info(
    sdp: &SdpSession,
) -> (Vec<String>, Option<String>, Option<u16>, String, bool) {
    let first_media = match sdp.media.first() {
        Some(m) => m,
        None => return (Vec::new(), None, None, "sendrecv".to_string(), false),
    };

    let codecs: Vec<String> = first_media
        .rtpmap
        .iter()
        .map(|r| r.encoding.clone())
        .collect();

    let media_addr = sdp::effective_address(first_media, sdp);
    let media_port = Some(first_media.port);

    let mode = match first_media.direction {
        MediaDirection::SendRecv => "sendrecv",
        MediaDirection::SendOnly => "sendonly",
        MediaDirection::RecvOnly => "recvonly",
        MediaDirection::Inactive => "inactive",
    }
    .to_string();

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
fn detect_event(
    timeline: &[SdpExchange],
    codecs: &[String],
    media_addr: &Option<String>,
    media_port: Option<u16>,
    mode: &str,
    is_t38: bool,
) -> Option<SdpEvent> {
    let prev = timeline.last()?;

    // T.38 switch takes priority
    if is_t38 {
        // Only emit if previous was not already T.38
        let prev_not_t38 = prev.event.as_ref() != Some(&SdpEvent::T38Switch);
        if prev_not_t38 {
            return Some(SdpEvent::T38Switch);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

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
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse INVITE with SDP")
    }

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
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse 200 OK with SDP")
    }

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
        let msg = parse_sip(&raw, base_ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        track_sdp(&mut timeline, &msg);
        assert!(timeline.is_empty());
    }

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
}
