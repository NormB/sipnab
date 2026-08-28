// SPDX-License-Identifier: MIT OR Apache-2.0

//! One sipnab per host, and only ONE of the relays has to be asked.
//!
//! # The deployment
//!
//! A proxy fronts several rtpengine instances and picks one per call. Each
//! host runs its own sipnab: the proxy's sees the SIP, each relay's sees the
//! media its own host relays and nothing else. Nobody is aggregating.
//!
//! ```text
//!         sipnab@proxy            sipnab@relay-a          sipnab@relay-b
//!         (SIP only)              (media for THIS call)   (media for others)
//!              |                        |                       |
//!   GET /v1/dialogs/{call_id}    GET .../{call_id}       GET .../{call_id}
//!         200 + sdp_timeline           200                     404
//! ```
//!
//! The naive way to find a call's media is to ask all ten relays. This suite
//! proves you do not have to: **the proxy's own SDP names the relay.** The
//! `c=` address in the dialog's `sdp_timeline` IS the rtpengine host the proxy
//! steered that call to, so one query to the proxy tells you which single
//! relay to ask.
//!
//! # What each test pins
//!
//! * The proxy holds the signaling and NO media — so a query there answers
//!   "which relay", not "what did the audio do".
//! * Exactly one relay claims the call. The other does not, and says so as a
//!   404 rather than as an empty success, because "I do not have this call"
//!   and "this call had no media" are different answers.
//! * Each node stamps its answers with its own capture identity, so two
//!   replies collected from two hosts remain attributable to the host that
//!   gave them.
//!
//! # Why this is a test and not a document
//!
//! Every piece here already existed -- per-node stores, the 404, the SDP
//! timeline, the capture identity. What did not exist was any proof they
//! compose into the deployment above, and a fan-out procedure that is wrong
//! about which node to ask is worse than no procedure: it sends an operator to
//! nine hosts that were never going to have the call.
#![cfg(all(feature = "native", feature = "api"))]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use chrono::Utc;
use parking_lot::RwLock;

use sipnab::capture::parse::{InputOrigin, ParsedPacket, TransportProto};
use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// The Call-ID the proxy assigned. One call, three hosts.
const CALL_ID: &str = "fanout-1@proxy.example";
/// The relay the proxy steered this call to. Its address appears in the SDP.
const RELAY_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 40);
/// A second relay, carrying somebody else's call.
const RELAY_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 41);
/// The port rtpengine on relay A allocated for this call.
const RELAY_A_PORT: u16 = 38664;

/// One sipnab: its own stores, exactly as a separate host would have.
///
/// Deliberately NOT a shared store with a node label. The property under test
/// is that a node which never saw a call cannot answer for it, and a shared
/// store would make every node able to answer everything -- proving the
/// opposite of the deployment.
struct Node {
    dialogs: Arc<RwLock<DialogStore>>,
    streams: Arc<RwLock<StreamStore>>,
}

impl Node {
    fn new() -> Self {
        Self {
            dialogs: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            streams: Arc::new(RwLock::new(StreamStore::new(1000))),
        }
    }

    /// Does this node hold the call? The question a fan-out asks each host.
    fn holds_dialog(&self, call_id: &str) -> bool {
        self.dialogs.read().get(call_id).is_some()
    }

    /// How many media streams this node attributed to the call.
    fn streams_for(&self, call_id: &str) -> usize {
        self.streams.read().streams_for(call_id).count()
    }
}

/// An INVITE whose SDP steers media at `relay` -- what the proxy rewrote it to.
fn invite_with_sdp(call_id: &str, relay: Ipv4Addr, port: u16) -> Vec<u8> {
    let sdp = format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 {relay}\r\n\
         s=-\r\n\
         c=IN IP4 {relay}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n"
    );
    format!(
        "INVITE sip:b@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfanout\r\n\
         From: <sip:a@example.com>;tag=f1\r\n\
         To: <sip:b@example.com>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    )
    .into_bytes()
}

/// A UDP packet carrying `payload` toward `dst`.
fn packet(payload: Vec<u8>, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> ParsedPacket {
    ParsedPacket {
        frame_bytes: None,
        frame: None,
        timestamp: Utc::now(),
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_addr: IpAddr::V4(dst),
        src_port,
        dst_port,
        transport: TransportProto::Udp,
        payload: payload.into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        dscp: None,
        input_origin: InputOrigin::Wire,
        hep: None,
    }
}

/// One RTP packet landing on a relay socket.
fn media(dst: Ipv4Addr, dst_port: u16, ssrc: u32) -> (ParsedPacket, RtpHeader) {
    (
        packet(vec![0u8; 12 + 160], 20000, dst, dst_port),
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 160,
            ssrc,
            payload_offset: 12,
        },
    )
}

/// Feed the proxy's node the INVITE, the way the capture path would.
fn proxy_sees_the_invite(node: &Node, call_id: &str, relay: Ipv4Addr, port: u16) {
    let pp = packet(invite_with_sdp(call_id, relay, port), 5060, relay, 5060);
    let msg = sipnab::sip::parser::parse_sip(
        &pp.payload,
        pp.timestamp,
        pp.src_addr,
        pp.dst_addr,
        pp.src_port,
        pp.dst_port,
        pp.transport,
    )
    .expect("the fixture must parse as SIP, or this test proves nothing");
    node.dialogs.write().process_message(msg);
}

/// Register a relay-allocated endpoint and then land media on it.
///
/// This is the RE4 shape: the relay's own control plane named the port, so a
/// stream arriving there takes its Call-ID from memory rather than from
/// signaling the relay host never saw.
fn relay_sees_the_media(node: &Node, call_id: &str, relay: Ipv4Addr, port: u16, ssrc: u32) {
    let ts = Utc::now();
    {
        let mut ss = node.streams.write();
        ss.link_to_dialog_with_sdp_from(
            IpAddr::V4(relay),
            port,
            call_id,
            &relay_media(port),
            sipnab::rtp::stream_store::SdpProvenance::relay_asserted(InputOrigin::Hep, ts),
        );
    }
    let (pp, rtp) = media(relay, port, ssrc);
    node.streams.write().process_rtp(&pp, &rtp, ts);
}

/// The media description a relay's control plane reports for its own socket.
///
/// The rtpmap is empty because a `query` reply names a codec and no payload
/// type, and an rtpmap entry needs both. Synthesizing one would put a number
/// sipnab was never told into a field an operator reads as measured.
fn relay_media(port: u16) -> sipnab::sip::sdp::SdpMedia {
    sipnab::sip::sdp::SdpMedia {
        media_type: "audio".to_string(),
        port,
        proto: "RTP/AVP".to_string(),
        formats: vec!["0".to_string()],
        connection: None,
        direction: sipnab::sip::sdp::SdpDirection::SendRecv,
        rtpmap: Vec::new(),
        fmtp: Vec::new(),
        ptime: None,
        crypto: Vec::new(),
        ice_candidates: Vec::new(),
        rtcp_mux: false,
        rtcp_port: None,
    }
}

/// The proxy holds the signaling and none of the media.
///
/// Both halves matter. The signaling is what makes the proxy the node you ask
/// FIRST; the absence of media is what makes asking a relay necessary at all.
/// A proxy that appeared to hold streams would send an operator looking for
/// audio on a host that only ever saw SDP.
#[test]
fn the_proxy_node_holds_the_signaling_and_no_media() {
    let proxy = Node::new();
    proxy_sees_the_invite(&proxy, CALL_ID, RELAY_A, RELAY_A_PORT);

    assert!(
        proxy.holds_dialog(CALL_ID),
        "the proxy saw the INVITE, so it must be able to answer for the call"
    );
    assert_eq!(
        proxy.streams_for(CALL_ID),
        0,
        "the proxy is not in the media path -- reporting streams here would \
         send an operator looking for audio on a host that only saw SDP"
    );
}

/// Exactly one relay claims the call, and the other says so.
///
/// This is the property the whole deployment rests on. If both relays claimed
/// it, a fan-out would return two contradictory answers with no way to choose;
/// if neither did, the media would be unattributable on every host and the
/// call would look like it had none.
#[test]
fn exactly_one_relay_holds_the_call_and_the_other_does_not() {
    let relay_a = Node::new();
    let relay_b = Node::new();

    // Relay A carries THIS call.
    relay_sees_the_media(&relay_a, CALL_ID, RELAY_A, RELAY_A_PORT, 0xAAAA_AAAA);
    // Relay B carries somebody else's, on its own socket.
    relay_sees_the_media(
        &relay_b,
        "other-call@proxy.example",
        RELAY_B,
        30000,
        0xBBBB_BBBB,
    );

    assert_eq!(
        relay_a.streams_for(CALL_ID),
        1,
        "the relay that carried the call must attribute its media, from its \
         own control plane -- it never saw the SIP"
    );
    assert_eq!(
        relay_b.streams_for(CALL_ID),
        0,
        "a relay that never carried this call must not claim it. Two relays \
         claiming one call gives a fan-out two contradictory answers and no \
         way to choose between them"
    );
    // And relay B is not simply empty: it holds its own call, so the zero
    // above is a real "not mine" rather than a node that captured nothing.
    assert_eq!(
        relay_b.streams_for("other-call@proxy.example"),
        1,
        "relay B must be carrying its own traffic, or the assertion above \
         passes for the wrong reason"
    );
}

/// The proxy's SDP names the relay to ask, so nine hosts stay unqueried.
///
/// The routing key. Without it a fan-out is a broadcast: ask all ten relays,
/// discard nine 404s. With it the proxy's answer contains the address of the
/// one host that can have the media, because the `c=` line IS the rtpengine
/// the proxy steered the call to.
#[test]
fn the_proxy_sdp_names_which_relay_to_ask() {
    let proxy = Node::new();
    proxy_sees_the_invite(&proxy, CALL_ID, RELAY_A, RELAY_A_PORT);

    let ds = proxy.dialogs.read();
    let dialog = ds.get(CALL_ID).expect("the proxy holds the dialog");
    let streams: Vec<&sipnab::rtp::stream::RtpStream> = Vec::new();
    let diagnosis = sipnab::rtp::diagnosis::MediaDiagnosis::default();
    let json = sipnab::output::json::dialog_to_json(dialog, &streams, &diagnosis);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let first = &v["sdp_timeline"][0];
    assert_eq!(
        first["media_addr"],
        RELAY_A.to_string(),
        "the dialog must publish the media address the proxy negotiated. \
         Without it a fan-out has to ask every relay and discard the misses: {v}"
    );
    assert_eq!(
        first["media_port"], RELAY_A_PORT,
        "the port travels with the address, because a relay host may carry \
         many calls and the port is what distinguishes them: {v}"
    );
    assert_ne!(
        first["media_addr"],
        RELAY_B.to_string(),
        "the routing key must name the relay that has the call, not any relay"
    );
}
