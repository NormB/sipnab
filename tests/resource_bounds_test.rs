//! Resource-exhaustion bounds: a remote attacker who invents unlimited
//! unique Call-IDs (dialog table) or SSRCs (RTP stream table) must not
//! be able to grow sipnab's memory without bound. Both stores cap +
//! evict; these tests prove the cap holds under a large hostile flood,
//! driving the SAME public entry points the live pipeline uses
//! (`parse_sip` -> `DialogStore::process_message`, `parse_rtp_header`
//! -> `StreamStore::process_rtp`).
//!
//! Companion to the audit in docs/fault-model.md. The stores were
//! already bounded in code; these are the missing behavioural
//! regression guards for the #1 ranked DoS surface.

use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};

use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::rtp::parser::parse_rtp_header;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::parser::parse_sip;

const FLOOD: usize = 50_000;
const CAP: usize = 1_000;

fn invite_bytes(call_id: &str) -> Vec<u8> {
    format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}\r\n\
         From: <sip:alice@example.com>;tag=a{call_id}\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {call_id}@10.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn parse_invite(call_id: &str) -> sipnab::sip::SipMessage {
    parse_sip(
        &invite_bytes(call_id),
        Utc::now(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("crafted INVITE must parse")
}

/// rotate=true (LRU eviction): a unique-Call-ID flood is capped at
/// `max_dialogs`; the table never exceeds the cap.
#[test]
fn dialog_flood_bounded_with_rotate() {
    let mut store = DialogStore::new(CAP, true);
    for i in 0..FLOOD {
        store.process_message(parse_invite(&format!("flood-{i}")));
        // Invariant must hold at EVERY step, not just at the end.
        assert!(
            store.len() <= CAP,
            "dialog store exceeded cap: len={} cap={} at i={}",
            store.len(),
            CAP,
            i
        );
    }
    // The security property is the UPPER bound, asserted at every step
    // above. Rotate-mode eviction is batched (cap/100 at a time) for
    // amortized O(1) inserts under flood, so the final length may sit up
    // to one batch below the cap (drop-new mode stays exactly at it).
    assert!(
        store.len() > CAP - CAP / 100 - 1 && store.len() <= CAP,
        "store should be saturated to within one eviction batch of the cap: len={}",
        store.len()
    );
}

/// rotate=false (drop-new): a unique-Call-ID flood is still bounded —
/// new dialogs are dropped at capacity rather than evicting, but memory
/// never grows past the cap.
#[test]
fn dialog_flood_bounded_without_rotate() {
    let mut store = DialogStore::new(CAP, false);
    for i in 0..FLOOD {
        store.process_message(parse_invite(&format!("flood-{i}")));
        assert!(
            store.len() <= CAP,
            "dialog store exceeded cap: len={} cap={} at i={}",
            store.len(),
            CAP,
            i
        );
    }
    // The security property is the UPPER bound, asserted at every step
    // above. Rotate-mode eviction is batched (cap/100 at a time) for
    // amortized O(1) inserts under flood, so the final length may sit up
    // to one batch below the cap (drop-new mode stays exactly at it).
    assert!(
        store.len() > CAP - CAP / 100 - 1 && store.len() <= CAP,
        "store should be saturated to within one eviction batch of the cap: len={}",
        store.len()
    );
}

fn rtp_packet(ssrc: u32, seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00]; // V=2, PT=0
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1]); // timestamp
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xaa; 160]); // G.711 payload
    p
}

fn parsed_for(ssrc: u32, payload: Vec<u8>) -> ParsedPacket {
    // Vary the 4-tuple per SSRC too, so the StreamKey is genuinely
    // unique (an attacker controls all of it).
    ParsedPacket {
        timestamp: Utc::now(),
        src_addr: IpAddr::V4(Ipv4Addr::new(
            10,
            0,
            ((ssrc >> 8) & 0xff) as u8,
            (ssrc & 0xff) as u8,
        )),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 10000 + (ssrc & 0x7fff) as u16,
        dst_port: 4000,
        transport: TransportProto::Udp,
        payload: payload.into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
    }
}

/// A unique-SSRC flood is capped at `max_streams`; the RTP stream table
/// never exceeds the cap (always-evict policy).
#[test]
fn rtp_stream_flood_bounded() {
    let mut store = StreamStore::new(CAP);
    for i in 0..FLOOD as u32 {
        let pkt = rtp_packet(i, (i & 0xffff) as u16);
        let parsed = parsed_for(i, pkt.clone());
        let hdr = parse_rtp_header(&pkt).expect("crafted RTP must parse");
        store.process_rtp(&parsed, &hdr, parsed.timestamp);
        assert!(
            store.len() <= CAP,
            "stream store exceeded cap: len={} cap={} at i={}",
            store.len(),
            CAP,
            i
        );
    }
    assert_eq!(
        store.len(),
        CAP,
        "stream store should be saturated at the cap"
    );
}
