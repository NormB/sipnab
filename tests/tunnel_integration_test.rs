// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunneled SIP, end to end through the public API.
//!
//! The unit tests in `capture::parse` prove each decapsulator is wired to the
//! walk. This file proves the thing an operator actually cares about: a call
//! that crossed a carrier core, a mobile core or a data-center fabric comes
//! out of `sipnab` as a SIP **message**, not as a `ParsedPacket` that happens
//! to hold the right bytes — and that the frames it must refuse produce a
//! named refusal rather than an invented dialog.
//!
//! sipnab's failure mode for an encapsulation it did not understand was a
//! confident zero: "No SIP traffic found" over a capture full of INVITEs. Each
//! case below is one wrapper that used to produce that answer.

use chrono::{TimeZone, Utc};
use sipnab::CaptureError;
use sipnab::capture::packet::Packet;
use sipnab::capture::parse::{parse_packet, peek_host_pair};
use sipnab::net::TransportProto;
use sipnab::sip::method::SipMethod;

/// Pcap link type for Ethernet II (DLT_EN10MB).
const EN10MB: i32 = 1;

/// The INVITE every case recovers. Complete enough to parse as SIP: a start
/// line, the headers a dialog is keyed on, and a terminating blank line.
fn invite() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"INVITE sip:bob@example.com SIP/2.0\r\n");
    m.extend_from_slice(b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKtunnel\r\n");
    m.extend_from_slice(b"From: <sip:alice@example.com>;tag=t1\r\n");
    m.extend_from_slice(b"To: <sip:bob@example.com>\r\n");
    m.extend_from_slice(b"Call-ID: tunneled-call-1@example.com\r\n");
    m.extend_from_slice(b"CSeq: 1 INVITE\r\n");
    m.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    m
}

/// Build an Ethernet/IPv4/UDP frame from 10.0.0.1:5060 to 10.0.0.2:5060.
fn eth_ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut ip = Vec::new();
    ip.extend_from_slice(&sport.to_be_bytes());
    ip.extend_from_slice(&dport.to_be_bytes());
    ip.extend_from_slice(&udp_len.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
    ip.extend_from_slice(payload);
    eth(&ipv4(&ip, 17, src, dst), 0x0800)
}

/// Wrap `payload` in an IPv4 header carrying `protocol`.
fn ipv4(payload: &[u8], protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&[0x00, 0x11]); // identification
    h.extend_from_slice(&[0x40, 0x00]); // DF, fragment offset 0
    h.push(64); // TTL
    h.push(protocol);
    h.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(payload);
    h
}

/// Wrap `payload` in an Ethernet II header.
///
/// The source MAC's Group bit is clear: IEEE 802.3 clause 3.2.3 reserves it in
/// the Source Address field, and the inner-Ethernet decoders use it as a
/// plausibility gate, so a frame with it set is not a legal encapsulated
/// frame.
fn eth(payload: &[u8], ethertype: u16) -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBA; 6]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Replace a frame's EtherType and splice `header` in ahead of its payload.
fn splice(base: &[u8], ethertype: u16, header: &[u8]) -> Vec<u8> {
    let mut f = base[0..12].to_vec();
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(header);
    f.extend_from_slice(&base[14..]);
    f
}

/// One MPLS label stack entry (RFC 3032 §2.1).
fn mpls_label(label: u32, bottom: bool) -> [u8; 4] {
    ((label << 12) | (u32::from(bottom) << 8) | 64).to_be_bytes()
}

/// A VXLAN header (RFC 7348 §5): I flag set, reserved fields zero.
fn vxlan_header() -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = 0x08;
    h[4..7].copy_from_slice(&[0x00, 0x12, 0x34]);
    h
}

/// A GTP-U G-PDU header (3GPP TS 29.281 §5.1).
fn gtpu_header(payload_len: usize) -> Vec<u8> {
    let mut h = vec![0x30, 255];
    h.extend_from_slice(&(payload_len as u16).to_be_bytes());
    h.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    h
}

/// The INVITE-bearing frame, and the bare IP packet inside it.
fn invite_frame() -> Vec<u8> {
    eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, &invite())
}

fn invite_packet() -> Vec<u8> {
    invite_frame()[14..].to_vec()
}

fn packet(data: Vec<u8>) -> Packet {
    let len = data.len();
    Packet::new(
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
        data,
        len,
        len,
        None,
        EN10MB,
    )
}

/// Parse a frame all the way to a SIP message and assert it is the INVITE,
/// carried between the endpoints the *inner* headers name.
#[track_caller]
fn assert_invite_through(what: &str, frame: Vec<u8>) {
    let parsed = parse_packet(&packet(frame)).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    assert_eq!(parsed.src_addr.to_string(), "10.0.0.1", "{what}: source");
    assert_eq!(parsed.dst_addr.to_string(), "10.0.0.2", "{what}: dest");
    assert_eq!(parsed.src_port, 5060, "{what}: source port");
    assert_eq!(parsed.dst_port, 5060, "{what}: dest port");

    let msg = sipnab::sip::parser::parse_sip_bytes(
        &parsed.payload,
        parsed.timestamp,
        parsed.src_addr,
        parsed.dst_addr,
        parsed.src_port,
        parsed.dst_port,
        TransportProto::Udp,
    )
    .unwrap_or_else(|e| panic!("{what}: not SIP: {e:?}"));

    assert!(msg.is_request, "{what}: should be a request");
    assert_eq!(msg.method, Some(SipMethod::Invite), "{what}: method");
    assert_eq!(
        msg.call_id(),
        Some("tunneled-call-1@example.com"),
        "{what}: Call-ID"
    );
}

/// MPLS is the carrier core, and a capture taken on a labeled segment is
/// often the only place the problem is visible.
#[test]
fn mpls_labelled_invite_reaches_the_sip_parser() {
    assert_invite_through(
        "MPLS",
        splice(&invite_frame(), 0x8847, &mpls_label(16_000, true)),
    );
}

/// MPLS-in-IP (RFC 4023), IP protocol 137.
#[test]
fn mpls_in_ip_invite_reaches_the_sip_parser() {
    let mut stack = mpls_label(16_000, true).to_vec();
    stack.extend_from_slice(&invite_packet());
    assert_invite_through(
        "MPLS-in-IP",
        eth(&ipv4(&stack, 137, [192, 0, 2, 1], [192, 0, 2, 2]), 0x0800),
    );
}

/// NSH (RFC 8300) — the service-chain header a firewall or SBC sits behind.
#[test]
fn nsh_encapsulated_invite_reaches_the_sip_parser() {
    let mut nsh = vec![0x00, 0x06, 0x01, 0x01]; // Ver 0, Length 6, MD Type 1, IPv4
    nsh.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF]); // SPI / SI
    nsh.extend_from_slice(&[0u8; 16]); // fixed context headers
    assert_invite_through("NSH", splice(&invite_frame(), 0x894F, &nsh));
}

/// A Provider Backbone Bridge I-TAG (IEEE Std 802.1Q-2014 §9.7) carries a
/// whole customer frame, addresses and all.
#[test]
fn pbb_encapsulated_invite_reaches_the_sip_parser() {
    let mut f = vec![0xCC; 6]; // B-DA
    f.extend_from_slice(&[0xDD; 6]); // B-SA
    f.extend_from_slice(&0x88E7u16.to_be_bytes());
    f.push(0x00); // flags: Res2 clear
    f.extend_from_slice(&[0x00, 0x00, 0x64]); // I-SID 100
    f.extend_from_slice(&invite_frame());
    assert_invite_through("PBB I-TAG", f);
}

/// MACsec with E and C clear is integrity-only: the User Data is plaintext,
/// and throwing it away would lose a call that is legible in the capture.
#[test]
fn macsec_integrity_only_invite_reaches_the_sip_parser() {
    let base = invite_frame();
    let mut f = base[0..12].to_vec();
    f.extend_from_slice(&0x88E5u16.to_be_bytes());
    f.push(0x00); // TCI / AN: V, ES, SC, SCB, E, C all clear
    f.push(0x00); // SL
    f.extend_from_slice(&1u32.to_be_bytes()); // PN
    f.extend_from_slice(&base[12..]);
    assert_invite_through("MACsec", f);
}

/// VXLAN (RFC 7348) — the data-center fabric.
#[test]
fn vxlan_encapsulated_invite_reaches_the_sip_parser() {
    let mut vx = vxlan_header().to_vec();
    vx.extend_from_slice(&invite_frame());
    assert_invite_through(
        "VXLAN",
        eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 32_768, 4789, &vx),
    );
}

/// GTP-U (3GPP TS 29.281) — VoLTE/VoNR signaling on S1-U, S5/S8 or N3.
#[test]
fn gtpu_encapsulated_invite_reaches_the_sip_parser() {
    let inner = invite_packet();
    let mut gtp = gtpu_header(inner.len());
    gtp.extend_from_slice(&inner);
    assert_invite_through(
        "GTP-U",
        eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 2152, 2152, &gtp),
    );
}

/// GRE with Protocol Type 0x6558, Transparent Ethernet Bridging (RFC 7637
/// §3.2).
#[test]
fn gre_teb_encapsulated_invite_reaches_the_sip_parser() {
    let mut gre = vec![0x00, 0x00]; // no optional fields
    gre.extend_from_slice(&0x6558u16.to_be_bytes());
    gre.extend_from_slice(&invite_frame());
    assert_invite_through(
        "GRE-TEB",
        eth(&ipv4(&gre, 47, [192, 0, 2, 1], [192, 0, 2, 2]), 0x0800),
    );
}

/// AH authenticates without encrypting (RFC 4302 §1), so the datagram it
/// protects is in the clear and reachable.
#[test]
fn ah_protected_invite_reaches_the_sip_parser() {
    // 24-octet AH: 12 fixed octets plus a 96-bit ICV. Payload Len is in
    // 4-octet units minus 2, so it reads 4.
    let mut ah = vec![4u8, 4, 0x00, 0x00]; // Next Header 4 (IPv4), Payload Len 4
    ah.extend_from_slice(&0x1122_3344u32.to_be_bytes()); // SPI
    ah.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
    ah.extend_from_slice(&[0xEE; 12]); // ICV
    ah.extend_from_slice(&invite_packet());
    assert_invite_through(
        "AH tunnel mode",
        eth(&ipv4(&ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]), 0x0800),
    );
}

/// Attacker-controlled nesting terminates. Six encapsulations of four
/// different kinds share one budget, so alternating them buys no extra depth,
/// and the frame is refused rather than walked.
#[test]
fn over_nested_frame_is_refused_not_walked() {
    // MACsec → MPLS → GTP-U → IP-in-IP → IP-in-IP → the INVITE: six layers
    // against a limit of five.
    let mut inner = invite_packet();
    for _ in 0..2 {
        inner = ipv4(&inner, 4, [172, 16, 0, 1], [172, 16, 0, 2]);
    }
    let mut gtp = gtpu_header(inner.len());
    gtp.extend_from_slice(&inner);
    let udp = eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 2152, 2152, &gtp);
    let mpls = splice(&udp, 0x8847, &mpls_label(16_000, true));
    let base = mpls;
    let mut f = base[0..12].to_vec();
    f.extend_from_slice(&0x88E5u16.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]); // TCI / AN, SL
    f.extend_from_slice(&1u32.to_be_bytes()); // PN
    f.extend_from_slice(&base[12..]);

    let err = parse_packet(&packet(f)).expect_err("an over-nested frame must be refused");
    assert!(
        matches!(err, CaptureError::EncapTooDeep { limit: 5, .. }),
        "expected the shared depth limit, got {err:?}"
    );
}

/// An encrypted MACsec frame is named, not silently dropped and not turned
/// into a flow. "MACsec-encrypted frame" is something an operator can act on;
/// a frame that merely vanished is not.
#[test]
fn encrypted_macsec_is_named_rather_than_invented() {
    let base = invite_frame();
    let mut f = base[0..12].to_vec();
    f.extend_from_slice(&0x88E5u16.to_be_bytes());
    f.push(0x0C); // TCI: E and C set — confidentiality
    f.push(0x00); // SL
    f.extend_from_slice(&1u32.to_be_bytes()); // PN
    f.extend_from_slice(&base[12..]);

    let err = parse_packet(&packet(f)).expect_err("encrypted MACsec carries no readable flow");
    assert!(
        matches!(err, CaptureError::NotIp { what } if what.contains("MACsec")),
        "the refusal must name MACsec, got {err:?}"
    );
}

/// `--cores` shards on the outer host pair for network- and transport-layer
/// tunnels, and on the inner one for link-layer encapsulation. Both halves
/// are deliberate: see `peek_host_pair`.
#[test]
fn core_sharding_follows_link_layer_and_stops_at_udp_tunnels() {
    let mpls = splice(&invite_frame(), 0x8847, &mpls_label(16_000, true));
    let p = packet(mpls);
    let parsed = parse_packet(&p).expect("MPLS");
    assert_eq!(
        peek_host_pair(&p),
        Some((parsed.src_addr, parsed.dst_addr)),
        "a link-layer encapsulation is on every frame of a flow, so the peek \
         and the full parse must not disagree"
    );

    let mut vx = vxlan_header().to_vec();
    vx.extend_from_slice(&invite_frame());
    let p = packet(eth_ipv4_udp(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        32_768,
        4789,
        &vx,
    ));
    let parsed = parse_packet(&p).expect("VXLAN");
    assert_eq!(parsed.src_addr.to_string(), "10.0.0.1");
    let (src, dst) = peek_host_pair(&p).expect("a shard key");
    assert_eq!(
        (src.to_string(), dst.to_string()),
        ("192.0.2.1".to_string(), "192.0.2.2".to_string()),
        "a tunnel header appears only in the first fragment, so the peek must \
         key on the tunnel endpoints"
    );
}
