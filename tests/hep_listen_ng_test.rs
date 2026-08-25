//! rtpengine `ng` delivered to `--hep-listen`, not sniffed off the wire.
//!
//! sipnab documents three ways to see a relay's control plane, and one of them
//! is "point rtpengine's own HEP export at sipnab". That method decoded
//! NOTHING: the listener unwraps HEP before the parser runs, so by the time the
//! pipeline looked for `ng` there was no HEP header left to find, and the
//! correlation id — the only thing naming the call on a REPLY — had been
//! dropped on the floor.
//!
//! The failure was silent and expensive in the one direction that matters:
//! rtpengine has a single `homer` destination, so an operator following the
//! page repointed production at sipnab, LOST their Homer collector, and got no
//! relay visibility in exchange.
#![cfg(all(feature = "hep", feature = "native"))]

use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use sipnab::capture::packet::{HepOrigin, Packet, PreParsed};
use sipnab::capture::parse::parse_packet;
use sipnab::pipeline::{self, PacketAction, PipelineOptions};
use sipnab::rtp::heuristic::RtpHeuristic;

/// rtpengine's own capture protocol for a mirrored `ng` datagram.
const NG_PROTO: u8 = 0x3d;

/// An `ng` OFFER, shaped like the one in the committed live fixture.
fn offer_body() -> Vec<u8> {
    let sdp = "v=0\r\nc=IN IP4 10.0.0.60\r\nm=audio 40001 RTP/AVP 0";
    format!(
        "cookie1 d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp{}:{sdp}e",
        sdp.len()
    )
    .into_bytes()
}

/// The offer REPLY as rtpengine really sends it: no `call-id`, no `command`.
fn offer_reply_body() -> Vec<u8> {
    let sdp = "v=0\r\nc=IN IP4 10.0.0.40\r\nm=audio 38664 RTP/AVP 0";
    format!("cookie1 d3:sdp{}:{sdp}6:result2:oke", sdp.len()).into_bytes()
}

/// One datagram as the HEP LISTENER hands it on: wrapper already stripped, so
/// the payload is the bare body and everything the wrapper said travels in
/// `PreParsed`.
fn delivered_by_the_listener(body: Vec<u8>, correlation_id: Option<&str>) -> Packet {
    Packet::with_pre_parsed(
        Utc::now(),
        body,
        Some("hep:198.51.100.7:9060".to_string()),
        PreParsed {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 41)),
            src_port: 22222,
            dst_port: 2223,
            ip_protocol: 17,
            hep: Some(HepOrigin {
                protocol: NG_PROTO,
                correlation_id: correlation_id.map(str::to_owned),
            }),
        },
    )
}

fn classify(packet: &Packet) -> PacketAction {
    let parsed = parse_packet(packet).expect("a pre-parsed datagram parses");
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    let mut decrypt = pipeline::MediaDecrypt::default();
    pipeline::classify_packet(&parsed, &mut heuristic, &opts, &mut decrypt)
}

/// SUCCESS: a request delivered over HEP is claimed as relay control, and its
/// media endpoint is read.
#[test]
fn an_ng_request_delivered_over_hep_names_its_media_endpoint() {
    let action = classify(&delivered_by_the_listener(offer_body(), None));
    let PacketAction::RelayControl { sdp_links } = action else {
        panic!("an ng offer over --hep-listen must be claimed as relay control");
    };
    assert_eq!(
        sdp_links.len(),
        1,
        "the offer names one media endpoint: {sdp_links:?}"
    );
    let (addr, port, call_id, _) = &sdp_links[0];
    assert_eq!(addr.to_string(), "10.0.0.60");
    assert_eq!(*port, 40001);
    assert_eq!(call_id, "km-670bd208@sipnab");
}

/// SUCCESS, and the half that only the correlation id can carry: a REPLY names
/// no call in its body, so the wrapper's correlation id is the sole route from
/// the relay's allocated port back to the call it belongs to.
#[test]
fn an_ng_reply_is_attributed_by_the_hep_correlation_id() {
    let action = classify(&delivered_by_the_listener(
        offer_reply_body(),
        Some("km-670bd208@sipnab"),
    ));
    let PacketAction::RelayControl { sdp_links } = action else {
        panic!("an ng reply over --hep-listen must be claimed as relay control");
    };
    assert_eq!(sdp_links.len(), 1, "the reply rewrites one endpoint");
    let (addr, port, call_id, _) = &sdp_links[0];
    assert_eq!(addr.to_string(), "10.0.0.40");
    assert_eq!(*port, 38664);
    assert_eq!(
        call_id, "km-670bd208@sipnab",
        "a reply carries no call-id of its own; drop the correlation id and \
         the relay's allocated port belongs to no call"
    );
}

/// FAILURE: a reply with NO correlation id names no call, and sipnab must not
/// invent one.
///
/// The endpoint is real and the call is unknown. Attributing it to a guess
/// would put a relay port on the wrong conversation, which is worse than
/// leaving it unattributed.
#[test]
fn an_ng_reply_without_a_correlation_id_attributes_nothing() {
    let action = classify(&delivered_by_the_listener(offer_reply_body(), None));
    let PacketAction::RelayControl { sdp_links } = action else {
        panic!("the datagram is still relay control");
    };
    assert!(
        sdp_links.is_empty(),
        "nothing names this call, so nothing may be attributed: {sdp_links:?}"
    );
}

/// FAILURE: a datagram the listener delivers that is NOT ng is left alone.
///
/// The listener carries ordinary SIP too — that is what it is for — and a
/// claim here would eat every SIP message an operator sent over HEP.
#[test]
fn sip_delivered_over_hep_is_not_claimed_as_relay_control() {
    let sip = b"INVITE sip:bob@example.net SIP/2.0\r\nCall-ID: x@y\r\n\r\n".to_vec();
    let packet = Packet::with_pre_parsed(
        Utc::now(),
        sip,
        Some("hep:198.51.100.7:9060".to_string()),
        PreParsed {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 41)),
            src_port: 5060,
            dst_port: 5060,
            ip_protocol: 17,
            // Capture protocol 1: SIP, which is what a Homer feed carries.
            hep: Some(HepOrigin {
                protocol: 1,
                correlation_id: Some("x@y".to_string()),
            }),
        },
    );
    assert!(
        !matches!(classify(&packet), PacketAction::RelayControl { .. }),
        "a SIP message over HEP must reach the SIP path, not the relay path"
    );
}

/// The relay's own declaration is honored even when sipnab cannot decode the
/// body.
///
/// `is_ng_over_hep` accepts on EITHER the capture protocol or a body that
/// parses, and a well-formed `ng` body is self-identifying — so every test
/// above passes on the body alone and none of them proves the protocol byte is
/// read at all. Mutation said exactly that: forcing the carried protocol to
/// SIP left them green.
///
/// This is the case that separates them. rtpengine says `0x3d`, the body is
/// something this version cannot parse — truncated, or a command added after
/// this build — and the datagram must STILL be claimed as control traffic.
/// Falling through would hand a control datagram to the RTP heuristic, which
/// is the one outcome the whole block is ordered to prevent.
#[test]
fn a_body_sipnab_cannot_parse_is_still_control_when_the_relay_says_so() {
    let undecodable = b"d7:command9:some-verb".to_vec();
    let packet = delivered_by_the_listener(undecodable, Some("km-670bd208@sipnab"));

    let action = classify(&packet);
    let PacketAction::RelayControl { sdp_links } = action else {
        panic!(
            "rtpengine declared this ng; an undecodable body is not a reason \
             to reconsider it as media"
        );
    };
    assert!(
        sdp_links.is_empty(),
        "nothing was decoded, so nothing may be attributed: {sdp_links:?}"
    );
}
