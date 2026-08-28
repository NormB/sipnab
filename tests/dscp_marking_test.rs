// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DSCP an operator marked a packet with survives the parse.
//!
//! Every IP header sipnab reads carries six bits saying which queue the
//! network was asked to put the packet in. Until this file existed sipnab
//! discarded them at `extract_parsed_packet` and no surface could report
//! them — so "the audio is choppy and my SBC marks EF" and "the audio is
//! choppy and nothing is marked at all" produced byte-identical output.
//! The second is a configuration fault an operator can fix in a minute; the
//! first is a network problem. Telling them apart needs the byte.
//!
//! The evidence here is a REAL capture rather than a hand-built packet.
//! `metasploit-sip-invite-spoof.pcap` carries a two-message dialog whose two
//! halves are marked DIFFERENTLY — the INVITE at DSCP 0 (best effort) and the
//! `180 Ringing` at DSCP 24 (CS3) — which is the asymmetry an operator hunts
//! and the one thing a hardcoded constant cannot fake. A capture where every
//! packet is unmarked would let `dscp: 0` pass while reading nothing.
//!
//! The capture's own SIP is spoofed junk, which is why it ships: nothing here
//! asserts on a header value, only on the marking of the frames that carried
//! them.

#![cfg(feature = "native")]

use std::process::Command;

use chrono::{TimeZone, Utc};
use sipnab::capture::packet::Packet;
use sipnab::capture::parse::parse_packet;

/// The one capture in the tree whose two dialog halves are marked differently.
const SPOOF: &str = "tests/pcap-samples/metasploit-sip-invite-spoof.pcap";

/// DSCP 24, class selector 3 — what the `180 Ringing` in [`SPOOF`] carries.
const CS3: u64 = 24;

/// Run sipnab over a capture and return its per-message JSON objects.
///
/// The wide port range is required rather than cosmetic: [`SPOOF`]'s INVITE
/// travels between two ephemeral ports, so the shipped 5060-5061 default sees
/// only the response and the asymmetry this file exists to check disappears.
fn messages(pcap: &str) -> Vec<serde_json::Value> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-N",
            "-I",
            pcap,
            "--portrange",
            "1-65535",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("spawn sipnab");
    assert!(
        out.status.success(),
        "sipnab failed on {pcap}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("message line is JSON"))
        .collect()
}

/// The per-message JSON reports the DSCP the frame was marked with.
#[test]
fn message_json_reports_the_dscp_the_frame_carried() {
    let msgs = messages(SPOOF);

    // A scan that found nothing would make every assertion below vacuous.
    assert_eq!(
        msgs.len(),
        2,
        "{SPOOF} holds one INVITE and one 180 Ringing; got {} message(s)",
        msgs.len()
    );

    let invite = msgs
        .iter()
        .find(|m| m["method"] == "INVITE" && m["is_request"] == true)
        .unwrap_or_else(|| panic!("no INVITE in {SPOOF}: {msgs:?}"));
    let ringing = msgs
        .iter()
        .find(|m| m["status_code"] == 180)
        .unwrap_or_else(|| panic!("no 180 in {SPOOF}: {msgs:?}"));

    assert_eq!(
        invite["dscp"], 0,
        "the INVITE frame's TOS byte is 0x00, so DSCP is 0 (best effort)"
    );
    assert_eq!(
        ringing["dscp"], CS3,
        "the 180 Ringing frame's TOS byte is 0x60, so DSCP is 24 (CS3). \
         Getting 0 here means the parser is reporting a default rather than \
         reading the header"
    );
}

/// A capture where nothing is marked reports 0, not absence.
///
/// The counterpart to the test above and the reason it is not enough on its
/// own: 0 is a real DSCP value (best effort, the default PHB of
/// [RFC 2474](https://www.rfc-editor.org/rfc/rfc2474)), so a surface that
/// omits the key when the marking is 0 tells an agent "unknown" for a call
/// whose marking is known and is the fault.
#[test]
fn an_unmarked_capture_reports_zero_rather_than_omitting_the_field() {
    let msgs = messages("tests/pcap-samples/sip-rtp-g711.pcap");
    assert!(
        !msgs.is_empty(),
        "no messages parsed — this test would assert nothing"
    );
    for m in &msgs {
        assert_eq!(
            m["dscp"], 0,
            "every frame in sip-rtp-g711.pcap is unmarked, and 0 is the value \
             for that — not a missing key: {m}"
        );
    }
}

// ── Encapsulation: the inner marking is the operator's own ───────────

/// Pcap link type for Ethernet II (DLT_EN10MB).
const EN10MB: i32 = 1;

/// Wrap `payload` in an IPv4 header carrying `protocol`, marked `dscp`.
fn ipv4(payload: &[u8], protocol: u8, src: [u8; 4], dst: [u8; 4], dscp: u8) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    // The TOS byte is DSCP in the top six bits and ECN in the bottom two.
    let mut h = vec![0x45, dscp << 2];
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

/// Wrap `payload` in an Ethernet II header carrying IPv4.
fn eth(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBA; 6]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(payload);
    f
}

/// A UDP datagram carrying `payload`.
fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut d = Vec::new();
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
    d.extend_from_slice(payload);
    d
}

/// A tunneled packet reports the marking its own operator set.
///
/// IP-in-IP with the outer header at `EF` (46) and the inner at `CS3` (24).
/// The outer marking belongs to whoever runs the tunnel; the inner one is the
/// fact the operator whose call this is can act on. Reporting the outer value
/// would tell them their signaling is expedited when their own SBC marked it
/// CS3, and no amount of staring at the SBC would explain the number.
///
/// This case also stands in for every other encapsulation sipnab decodes:
/// each nested layer re-enters the same extraction with the innermost network
/// slice, so a parser that gets this one right gets GRE, MPLS-in-IP, VXLAN,
/// GTP-U and the rest right for the same reason.
#[test]
fn a_tunnelled_packet_reports_the_inner_marking_not_the_carriers() {
    const OUTER_EF: u8 = 46;
    const INNER_CS3: u8 = 24;

    let sip = b"OPTIONS sip:probe@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKdscp\r\n\
        From: <sip:a@example.com>;tag=t1\r\n\
        To: <sip:b@example.com>\r\n\
        Call-ID: dscp-tunnel@example.com\r\n\
        CSeq: 1 OPTIONS\r\n\
        Content-Length: 0\r\n\r\n";

    let inner = ipv4(
        &udp(5060, 5060, sip),
        17,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        INNER_CS3,
    );
    // Protocol 4 is IPv4-in-IPv4.
    let outer = ipv4(&inner, 4, [192, 0, 2, 1], [192, 0, 2, 2], OUTER_EF);
    let frame = eth(&outer);

    let len = frame.len();
    let packet = Packet::new(
        Utc.timestamp_opt(0, 0).single().expect("epoch"),
        frame,
        len,
        len,
        None,
        EN10MB,
    );
    let parsed = parse_packet(&packet).expect("IP-in-IP SIP parses");

    assert_eq!(
        parsed.dscp,
        Some(INNER_CS3),
        "the inner header is marked CS3 and the outer EF; reporting {:?} means \
         the parse read the carrier's marking instead of the operator's",
        parsed.dscp
    );
}

// ── Media: a stream keeps its first marking and notices a re-marking ──

/// Feed one RTP packet of a stream, marked `dscp`.
fn push_rtp(store: &mut sipnab::rtp::stream_store::StreamStore, seq: u16, dscp: u8) {
    let parsed = sipnab::capture::ParsedPacket {
        frame_bytes: None,
        frame: None,
        timestamp: Utc
            .timestamp_opt(1_700_000_000 + i64::from(seq), 0)
            .single()
            .expect("ts"),
        src_addr: "10.0.0.1".parse().expect("addr"),
        dst_addr: "10.0.0.2".parse().expect("addr"),
        src_port: 20000,
        dst_port: 30000,
        transport: sipnab::net::TransportProto::Udp,
        payload: vec![0u8; 172].into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        dscp: Some(dscp),
        input_origin: sipnab::capture::parse::InputOrigin::Wire,
        hep: None,
    };
    let rtp = sipnab::rtp::parser::RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 0,
        sequence: seq,
        timestamp: u32::from(seq) * 160,
        ssrc: 0xAAAA_BBBB,
        payload_offset: 12,
    };
    let ts = parsed.timestamp;
    store.process_rtp(&parsed, &rtp, ts);
}

/// A stream re-marked in flight keeps its ORIGINAL marking and says it changed.
///
/// The failure this prevents is the obvious implementation: overwrite the
/// stored value on every packet. That reports the LAST marking as though it
/// were the stream's, so a bearer that left the SBC as `EF` and was bleached to
/// best effort two hops later reads as an unmarked stream — and the operator
/// goes to configure the SBC that was already right.
#[test]
fn a_stream_remarked_in_flight_keeps_its_first_marking_and_reports_the_change() {
    const EF: u8 = 46;
    const BLEACHED: u8 = 0;

    let mut store = sipnab::rtp::stream_store::StreamStore::new(16);
    push_rtp(&mut store, 1, EF);
    push_rtp(&mut store, 2, BLEACHED);

    let stream = store.iter().next().expect("one stream");
    assert_eq!(
        stream.dscp_first,
        Some(EF),
        "the stream's first packet was EF; the first marking is the one the \
         sender chose and must not be overwritten by a later hop's"
    );
    assert_eq!(stream.dscp_last, Some(BLEACHED));
    assert!(
        stream.dscp_remarked(),
        "EF then best-effort is a re-marking, and it is the whole finding"
    );
}

/// A steady stream reports one marking and does NOT claim a change.
///
/// The mirror of the test above, and the reason it is not enough alone: an
/// implementation that reported every stream as re-marked would pass that one.
#[test]
fn a_steady_stream_does_not_claim_it_was_remarked() {
    const EF: u8 = 46;

    let mut store = sipnab::rtp::stream_store::StreamStore::new(16);
    push_rtp(&mut store, 1, EF);
    push_rtp(&mut store, 2, EF);

    let stream = store.iter().next().expect("one stream");
    assert_eq!(stream.dscp_first, Some(EF));
    assert!(
        !stream.dscp_remarked(),
        "both packets carry EF, so nothing was re-marked"
    );
    assert_eq!(
        stream.dscp_is_expedited(),
        Some(true),
        "EF is the expedited-forwarding codepoint voice is conventionally \
         marked with"
    );
}

/// A stream whose marking was never observed says so rather than guessing.
///
/// `dscp_is_expedited()` returning `Some(false)` for a HEP-fed stream would
/// read as "this bearer is marked wrongly" about a stream sipnab never saw an
/// IP header for.
#[test]
fn an_unobserved_marking_is_not_reported_as_a_wrong_one() {
    let mut store = sipnab::rtp::stream_store::StreamStore::new(16);
    let parsed = sipnab::capture::ParsedPacket {
        frame_bytes: None,
        frame: None,
        timestamp: Utc.timestamp_opt(1_700_000_000, 0).single().expect("ts"),
        src_addr: "10.0.0.1".parse().expect("addr"),
        dst_addr: "10.0.0.2".parse().expect("addr"),
        src_port: 20000,
        dst_port: 30000,
        transport: sipnab::net::TransportProto::Udp,
        payload: vec![0u8; 172].into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        dscp: None,
        input_origin: sipnab::capture::parse::InputOrigin::Hep,
        hep: None,
    };
    let rtp = sipnab::rtp::parser::RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 0,
        sequence: 1,
        timestamp: 160,
        ssrc: 0xCCCC_DDDD,
        payload_offset: 12,
    };
    let ts = parsed.timestamp;
    store.process_rtp(&parsed, &rtp, ts);

    let stream = store.iter().next().expect("one stream");
    assert_eq!(stream.dscp_first, None);
    assert_eq!(
        stream.dscp_is_expedited(),
        None,
        "no IP header was observed, so 'is it marked EF?' has no answer — \
         Some(false) would accuse a correctly-marked trunk"
    );
    assert!(
        !stream.dscp_remarked(),
        "one unobserved marking cannot differ from another"
    );
}
