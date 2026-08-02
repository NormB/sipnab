// SPDX-License-Identifier: MIT OR Apache-2.0

//! ICMP errors that quote a SIP request.
//!
//! An ICMP port-unreachable quoting an `INVITE` is the most diagnostic packet
//! a SIP capture can hold: it is categorical evidence that the far end was not
//! listening, which is the exact question an operator opens a capture to
//! answer. sipnab used to drop every ICMP packet at the transport switch, so
//! the capture contained the answer and the report said "unanswered".
//!
//! Three properties are load-bearing and each has a test here:
//!
//! 1. **The quote is truncated by design.** RFC 792 guarantees only the
//!    original IP header plus 8 bytes. A partial request is EVIDENCE about a
//!    message, never a message: it must not parse as SIP, must not be counted,
//!    and must not join a dialog's message ladder.
//! 2. **Two addresses, two meanings.** The ICMP source is the router or host
//!    *reporting* the failure. The quoted datagram's destination is the
//!    endpoint that *did not answer*. Attributing the failure to the wrong one
//!    is worse than not reporting it at all.
//! 3. **Nothing is dropped silently.** A quote too short to carry a `Call-ID`
//!    cannot be attributed to a dialog — so it is counted as unattributed and
//!    reported, not discarded.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{TimeZone, Utc};
use sipnab::capture::Packet;
use sipnab::capture::parse::{IcmpErrorKind, TransportProto, parse_icmp_error, parse_packet};
use sipnab::pipeline;

#[path = "support/mod.rs"]
mod support;

// ── Fixtures ─────────────────────────────────────────────────────────

/// Ethernet link type (DLT_EN10MB).
const DLT_EN10MB: i32 = 1;

/// A realistic `OPTIONS` keepalive — the request that actually draws ICMP
/// errors in production, because it is what a proxy sends at a peer that has
/// gone away.
fn options_keepalive(call_id: &str) -> Vec<u8> {
    format!(
        "OPTIONS sip:peer@198.51.100.20:5080 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5080;branch=z9hG4bK-icmp-1\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:probe@192.0.2.10>;tag=icmp1\r\n\
         To: <sip:peer@198.51.100.20>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 42 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// Build the IPv4 datagram an ICMP error quotes: header + UDP + `payload`.
///
/// `declared_len` is what the IPv4 `Total Length` field claims, which is the
/// only record of how long the original datagram was. Truncating the returned
/// vector without changing it is exactly what a router does when it obeys RFC
/// 792's 8-byte minimum instead of RFC 1812's advice to send more.
fn quoted_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut d = Vec::with_capacity(total_len as usize);
    d.push(0x45); // IPv4, IHL 5
    d.push(0x00);
    d.extend_from_slice(&total_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x07]); // identification
    d.extend_from_slice(&[0x40, 0x00]); // DF
    d.push(64); // TTL
    d.push(17); // protocol: UDP
    d.extend_from_slice(&[0x00, 0x00]); // checksum (unverified)
    d.extend_from_slice(&src.octets());
    d.extend_from_slice(&dst.octets());
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&udp_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]); // UDP checksum
    d.extend_from_slice(payload);
    d
}

/// Wrap `quoted` in an ICMPv4 error from `reporter` to `reported_to`.
fn icmpv4_error(
    reporter: Ipv4Addr,
    reported_to: Ipv4Addr,
    icmp_type: u8,
    icmp_code: u8,
    quoted: &[u8],
) -> Packet {
    let mut icmp = Vec::with_capacity(8 + quoted.len());
    icmp.push(icmp_type);
    icmp.push(icmp_code);
    icmp.extend_from_slice(&[0x00, 0x00]); // checksum (unverified)
    icmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // unused / MTU
    icmp.extend_from_slice(quoted);

    let total_len = (20 + icmp.len()) as u16;
    let mut pkt = Vec::with_capacity(14 + total_len as usize);
    pkt.extend_from_slice(&[0xAA; 6]);
    pkt.extend_from_slice(&[0xBB; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x09]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(1); // protocol: ICMP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&reporter.octets());
    pkt.extend_from_slice(&reported_to.octets());
    pkt.extend_from_slice(&icmp);
    make_packet(pkt)
}

/// Build the IPv6 datagram an ICMPv6 error quotes: header + UDP + `payload`.
fn quoted_ipv6_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut d = Vec::with_capacity(40 + udp_len as usize);
    d.push(0x60);
    d.extend_from_slice(&[0x00, 0x00, 0x00]);
    d.extend_from_slice(&udp_len.to_be_bytes()); // payload length
    d.push(17); // next header: UDP
    d.push(64); // hop limit
    d.extend_from_slice(&src.octets());
    d.extend_from_slice(&dst.octets());
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&udp_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d.extend_from_slice(payload);
    d
}

/// Wrap `quoted` in an ICMPv6 error from `reporter` to `reported_to`.
fn icmpv6_error(
    reporter: Ipv6Addr,
    reported_to: Ipv6Addr,
    icmp_type: u8,
    icmp_code: u8,
    quoted: &[u8],
) -> Packet {
    let mut icmp = Vec::with_capacity(8 + quoted.len());
    icmp.push(icmp_type);
    icmp.push(icmp_code);
    icmp.extend_from_slice(&[0x00, 0x00]);
    icmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    icmp.extend_from_slice(quoted);

    let mut pkt = Vec::with_capacity(14 + 40 + icmp.len());
    pkt.extend_from_slice(&[0xAA; 6]);
    pkt.extend_from_slice(&[0xBB; 6]);
    pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6
    pkt.push(0x60);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    pkt.push(58); // next header: ICMPv6
    pkt.push(64);
    pkt.extend_from_slice(&reporter.octets());
    pkt.extend_from_slice(&reported_to.octets());
    pkt.extend_from_slice(&icmp);
    make_packet(pkt)
}

/// A [`Packet`] over Ethernet with a fixed capture timestamp.
fn make_packet(data: Vec<u8>) -> Packet {
    let len = data.len();
    Packet::new(
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
        data,
        len,
        len,
        None,
        DLT_EN10MB,
    )
}

/// The proxy that sent the request that failed.
fn sender() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 10)
}

/// The peer that did not answer — the address the failure is *about*.
fn dead_peer() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 20)
}

/// The router that reported the failure — NOT the peer.
fn router() -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, 1)
}

// ── Parsing ──────────────────────────────────────────────────────────

/// An ICMPv4 port-unreachable quoting an `OPTIONS` yields the quoted request's
/// method, `Call-ID`, and the socket that did not answer.
#[test]
fn icmpv4_port_unreachable_quoting_sip_is_parsed() {
    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive("icmp-parse-1@test"),
    );
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);

    let q = parse_icmp_error(&pkt).expect("an ICMP destination-unreachable must yield a quote");
    assert_eq!(q.kind, IcmpErrorKind::DestinationUnreachable);
    assert_eq!((q.icmp_type, q.icmp_code), (3, 3));
    assert_eq!(q.quoted_src, IpAddr::V4(sender()));
    assert_eq!(q.quoted_dst, IpAddr::V4(dead_peer()));
    assert_eq!(q.quoted_src_port, Some(5080));
    assert_eq!(q.quoted_dst_port, Some(5080));
    assert_eq!(q.quoted_transport, Some(TransportProto::Udp));
    assert!(
        q.quoted_payload.starts_with(b"OPTIONS sip:"),
        "the quoted payload must be the original request's bytes"
    );
    assert!(
        !q.quoted_truncated,
        "this quote carries the whole datagram the IP header declares"
    );
}

/// The ICMP source is the *reporter*; the quoted destination is the endpoint
/// that did not answer. Conflating them blames the wrong address, which is
/// worse than saying nothing.
#[test]
fn the_reporter_is_never_the_unreachable_endpoint() {
    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive("icmp-attrib-1@test"),
    );
    let pkt = icmpv4_error(router(), sender(), 3, 1, &quoted);
    let q = parse_icmp_error(&pkt).expect("parses");

    assert_eq!(q.reporter, IpAddr::V4(router()));
    assert_eq!(q.reported_to, IpAddr::V4(sender()));
    assert_eq!(q.quoted_dst, IpAddr::V4(dead_peer()));
    assert_ne!(
        q.reporter, q.quoted_dst,
        "the router that reported the failure is not the host that failed"
    );
}

/// RFC 792's minimum: the IP header plus 8 bytes. The quote then holds the UDP
/// header and NOT ONE BYTE of SIP — so there is no method, no `Call-ID`, and
/// the truncation must be reported rather than guessed around.
#[test]
fn an_rfc792_minimum_quote_is_reported_as_truncated() {
    let full = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive("icmp-trunc-1@test"),
    );
    // IP header + 8 bytes, with Total Length still declaring the whole thing.
    let minimal = &full[..28];
    let pkt = icmpv4_error(router(), sender(), 3, 3, minimal);

    let q = parse_icmp_error(&pkt).expect("a minimal quote is still a quote");
    assert_eq!(q.quoted_dst, IpAddr::V4(dead_peer()));
    assert_eq!(q.quoted_dst_port, Some(5080));
    assert!(
        q.quoted_payload.is_empty(),
        "8 bytes past the IP header is the UDP header and nothing else"
    );
    assert!(
        q.quoted_truncated,
        "the datagram declared more than the quote carries; saying otherwise \
         would present a header prefix as a whole message"
    );
}

/// A quote that stops mid-header is a prefix, not a message: it must be
/// flagged truncated and must not be fed to the SIP parser as a message.
#[test]
fn a_mid_header_quote_is_a_prefix_not_a_message() {
    let sip = options_keepalive("icmp-trunc-2@test");
    let full = quoted_ipv4_udp(sender(), dead_peer(), 5080, 5080, &sip);
    let cut = &full[..28 + 60]; // request line + start of Via
    let pkt = icmpv4_error(router(), sender(), 3, 3, cut);

    let q = parse_icmp_error(&pkt).expect("parses");
    assert!(q.quoted_truncated);
    assert_eq!(q.quoted_payload.len(), 60);

    // The start line survived, so the method is known — and the headers did
    // not, so nothing further may be claimed. Reading the prefix must stop
    // where the quote stopped rather than inventing the rest.
    let prefix = pipeline::quoted_sip_prefix(&q.quoted_payload).expect("a request prefix");
    assert_eq!(prefix.method, "OPTIONS");
    assert_eq!(
        prefix.call_id, None,
        "the quote ended before Call-ID; claiming one would file this evidence \
         under a dialog it does not belong to"
    );
    assert_eq!(prefix.cseq, None);
}

/// A quote cut in the MIDDLE of the `Call-ID` value must yield no `Call-ID`.
///
/// This is the dangerous truncation. A quote that stops before the header is
/// obviously unattributable; a quote that stops halfway through the value
/// looks like a shorter, perfectly plausible `Call-ID` — which would file this
/// dialog's evidence under a dialog that does not exist, or worse, under one
/// that does. The header's own terminator is what makes the value trustworthy,
/// so a value without one is not read at all.
#[test]
fn a_call_id_cut_mid_value_is_not_a_call_id() {
    let sip = options_keepalive("a-long-call-id-that-gets-cut@example.net");
    let full = quoted_ipv4_udp(sender(), dead_peer(), 5080, 5080, &sip);
    // Everything up to and including "Call-ID: a-long-call-id" and no further.
    let cut_at = 28
        + sip
            .windows(23)
            .position(|w| w == b"Call-ID: a-long-call-id")
            .expect("fixture contains the header")
        + 23;
    let pkt = icmpv4_error(router(), sender(), 3, 3, &full[..cut_at]);

    let q = parse_icmp_error(&pkt).expect("parses");
    let prefix = pipeline::quoted_sip_prefix(&q.quoted_payload).expect("a request prefix");
    assert_eq!(prefix.method, "OPTIONS");
    assert_eq!(
        prefix.call_id, None,
        "an unterminated Call-ID line is a partial value; reading it would \
         attribute this evidence to a Call-ID that was never sent"
    );
}

/// A header present but empty carries no value, and an empty `Call-ID` is not
/// a dialog. It must not be attributed to one.
#[test]
fn an_empty_call_id_header_is_not_a_call_id() {
    let sip = b"OPTIONS sip:peer@198.51.100.20:5080 SIP/2.0\r\n\
                Via: SIP/2.0/UDP 192.0.2.10:5080;branch=z9hG4bK-icmp-9\r\n\
                Call-ID: \r\n\
                CSeq: 42 OPTIONS\r\n\r\n";
    let full = quoted_ipv4_udp(sender(), dead_peer(), 5080, 5080, sip);
    let pkt = icmpv4_error(router(), sender(), 3, 3, &full);

    let q = parse_icmp_error(&pkt).expect("parses");
    let prefix = pipeline::quoted_sip_prefix(&q.quoted_payload).expect("a request prefix");
    assert_eq!(
        prefix.call_id, None,
        "an empty Call-ID names no dialog; returning Some(\"\") would collect \
         every such quote under one imaginary call"
    );
}

/// ICMPv6 (RFC 4443) carries the same evidence and must be parsed too.
#[test]
fn icmpv6_destination_unreachable_quoting_sip_is_parsed() {
    let src: Ipv6Addr = "2001:db8::10".parse().expect("v6 literal");
    let dst: Ipv6Addr = "2001:db8::20".parse().expect("v6 literal");
    let rtr: Ipv6Addr = "2001:db8::1".parse().expect("v6 literal");

    let quoted = quoted_ipv6_udp(src, dst, 5060, 5060, &options_keepalive("icmp-v6-1@test"));
    let pkt = icmpv6_error(rtr, src, 1, 4, &quoted); // 1/4 = port unreachable

    let q = parse_icmp_error(&pkt).expect("ICMPv6 errors must yield a quote too");
    assert_eq!(q.kind, IcmpErrorKind::DestinationUnreachable);
    assert_eq!(q.reporter, IpAddr::V6(rtr));
    assert_eq!(q.quoted_src, IpAddr::V6(src));
    assert_eq!(q.quoted_dst, IpAddr::V6(dst));
    assert_eq!(q.quoted_dst_port, Some(5060));
    assert!(q.quoted_payload.starts_with(b"OPTIONS sip:"));
    assert!(!q.quoted_truncated);
}

/// ICMPv6 Packet Too Big (type 2) is a PMTU black hole — the reason a large
/// `INVITE` with SDP vanishes while small requests succeed. It quotes the
/// datagram like any other error and must be read.
#[test]
fn icmpv6_packet_too_big_is_an_error_that_quotes() {
    let src: Ipv6Addr = "2001:db8::10".parse().expect("v6 literal");
    let dst: Ipv6Addr = "2001:db8::20".parse().expect("v6 literal");
    let rtr: Ipv6Addr = "2001:db8::1".parse().expect("v6 literal");
    let quoted = quoted_ipv6_udp(src, dst, 5060, 5060, &options_keepalive("icmp-v6-2@test"));
    let pkt = icmpv6_error(rtr, src, 2, 0, &quoted);

    let q = parse_icmp_error(&pkt).expect("Packet Too Big quotes the datagram");
    assert_eq!(q.kind, IcmpErrorKind::PacketTooBig);
}

/// An ICMP message that is not an error must yield nothing — even when its
/// payload would parse perfectly as a quoted datagram.
///
/// The adversarial case, and the only one that proves anything: the payload of
/// an echo request is arbitrary bytes chosen by whoever sent the ping, so it
/// can be made byte-identical to a quoted IPv4/UDP datagram carrying a SIP
/// request. Nothing but the ICMP type distinguishes them. A short, obviously
/// non-IP ping payload would pass this test through the length check alone and
/// prove nothing about the type check — which is how the first version of this
/// test passed with the type check removed.
///
/// Redirect (type 5) gets the same treatment: it does quote the datagram, but
/// it reports a better route rather than a failure, and reading it as one
/// would report a fault on a path that is working.
#[test]
fn only_errors_quote_and_a_ping_payload_cannot_forge_one() {
    let forged = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive("icmp-forged-1@test"),
    );

    for (icmp_type, what) in [
        (8u8, "echo request"),
        (0, "echo reply"),
        (5, "redirect"),
        (13, "timestamp request"),
    ] {
        assert!(
            parse_icmp_error(&icmpv4_error(router(), sender(), icmp_type, 0, &forged)).is_none(),
            "an ICMP {what} (type {icmp_type}) is not a delivery failure; reading \
             its payload as a quoted datagram would report an endpoint as \
             unreachable on the word of a ping"
        );
    }

    // ICMPv6 echo (128) and neighbour discovery (135) are likewise not errors.
    let src: Ipv6Addr = "2001:db8::10".parse().expect("v6 literal");
    let dst: Ipv6Addr = "2001:db8::20".parse().expect("v6 literal");
    let rtr: Ipv6Addr = "2001:db8::1".parse().expect("v6 literal");
    let forged6 = quoted_ipv6_udp(
        src,
        dst,
        5060,
        5060,
        &options_keepalive("icmp-forged-2@test"),
    );
    for (icmp_type, what) in [(128u8, "echo request"), (135, "neighbour solicitation")] {
        assert!(
            parse_icmp_error(&icmpv6_error(rtr, src, icmp_type, 0, &forged6)).is_none(),
            "an ICMPv6 {what} (type {icmp_type}) is not a delivery failure"
        );
    }

    // …and the control: the same bytes under an error type ARE read.
    let real = icmpv4_error(router(), sender(), 3, 3, &forged);
    assert!(
        parse_icmp_error(&real).is_some(),
        "precondition: the payload really is a well-formed quote, so the \
         rejections above came from the type check and nothing else"
    );
}

/// A destination-unreachable quoting RTP (not SIP) still parses at the packet
/// layer — it is real evidence about media — but must never be attributed to a
/// dialog, because there is no `Call-ID` in an RTP packet to attribute it by.
#[test]
fn a_quote_of_non_sip_traffic_is_not_attributed_to_a_dialog() {
    let mut rtp = vec![0x80u8, 0x00, 0x00, 0x01];
    rtp.extend_from_slice(&[0x00; 8]);
    rtp.extend_from_slice(&[0xAB; 160]);
    let quoted = quoted_ipv4_udp(sender(), dead_peer(), 20000, 20002, &rtp);
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);

    let q = parse_icmp_error(&pkt).expect("still a parseable ICMP error");
    assert_eq!(q.quoted_dst_port, Some(20002));
    assert!(
        pipeline::quoted_sip_prefix(&q.quoted_payload).is_none(),
        "an RTP payload must not be read as a SIP request prefix"
    );
}

// ── Accounting ───────────────────────────────────────────────────────

/// `parse_packet` still rejects ICMP, so an ICMP error can never reach the SIP
/// counters. The quote is evidence *about* a message, and counting it as one
/// would inflate every message total sipnab prints.
#[test]
fn an_icmp_error_is_never_a_parsed_packet() {
    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive("icmp-count-1@test"),
    );
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);
    assert!(
        parse_packet(&pkt).is_err(),
        "an ICMP error must not become a ParsedPacket: it would be classified, \
         counted, and could reach a dialog's message list as an ordinary rung"
    );
}

// ── Evidence association ─────────────────────────────────────────────

/// A quote that reaches the `Call-ID` is attributed to that dialog, with the
/// unreachable endpoint (not the reporter) recorded against it.
#[test]
#[serial_test::serial(icmp_evidence)]
fn evidence_is_attributed_by_the_quoted_call_id() {
    pipeline::reset_icmp_evidence();

    let call_id = "icmp-evidence-1@test";
    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive(call_id),
    );
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);
    assert!(parse_packet(&pkt).is_err());

    let ev = pipeline::icmp_evidence_for(call_id);
    assert_eq!(ev.errors, 1, "the quote names this Call-ID");
    assert_eq!(ev.samples.len(), 1);
    assert_eq!(ev.samples[0].unreachable_addr, IpAddr::V4(dead_peer()));
    assert_eq!(ev.samples[0].unreachable_port, Some(5080));
    assert_eq!(ev.samples[0].reported_by, IpAddr::V4(router()));
    assert_eq!(ev.samples[0].method.as_deref(), Some("OPTIONS"));

    let report = pipeline::icmp_evidence_report();
    assert_eq!(report.errors, 1);
    assert_eq!(report.attributed, 1);
    assert_eq!(report.unattributed, 0);

    pipeline::reset_icmp_evidence();
}

/// A quote too short to reach the `Call-ID` cannot be attributed — and is
/// counted as unattributed rather than dropped, so the operator learns that
/// the network said something sipnab could not place.
#[test]
#[serial_test::serial(icmp_evidence)]
fn an_unattributable_quote_is_counted_not_dropped() {
    pipeline::reset_icmp_evidence();

    let full = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive("icmp-evidence-2@test"),
    );
    // Request line only: enough to know it was an OPTIONS, not enough for a
    // Call-ID.
    let pkt = icmpv4_error(router(), sender(), 3, 3, &full[..28 + 30]);
    assert!(parse_packet(&pkt).is_err());

    assert_eq!(
        pipeline::icmp_evidence_for("icmp-evidence-2@test"),
        Default::default(),
        "no Call-ID was quoted, so nothing may be attributed to that dialog"
    );
    let report = pipeline::icmp_evidence_report();
    assert_eq!(report.errors, 1);
    assert_eq!(report.attributed, 0);
    assert_eq!(
        report.unattributed, 1,
        "the evidence exists and must be reported even when unplaceable"
    );
    assert_eq!(
        report.endpoints.len(),
        1,
        "the unreachable endpoint is known even when the dialog is not"
    );
    assert_eq!(report.endpoints[0].addr, IpAddr::V4(dead_peer()));

    pipeline::reset_icmp_evidence();
}

/// An ICMP error about media (no SIP in the quote) is not SIP evidence and
/// must not enter the SIP evidence report at all.
#[test]
#[serial_test::serial(icmp_evidence)]
fn media_icmp_does_not_enter_the_sip_evidence_report() {
    pipeline::reset_icmp_evidence();

    let mut rtp = vec![0x80u8, 0x00, 0x00, 0x01];
    rtp.extend_from_slice(&[0x00; 8]);
    rtp.extend_from_slice(&[0xAB; 160]);
    let quoted = quoted_ipv4_udp(sender(), dead_peer(), 20000, 20002, &rtp);
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);
    assert!(parse_packet(&pkt).is_err());

    assert_eq!(
        pipeline::icmp_evidence_report().errors,
        0,
        "an ICMP error about an RTP packet is not evidence about a SIP message"
    );

    pipeline::reset_icmp_evidence();
}

// ── Diagnosis ────────────────────────────────────────────────────────

/// Retransmitting an `OPTIONS` into silence reads as "no response" today. With
/// an ICMP quote it reads as a fact: that socket was not listening. The claim
/// must name the endpoint that failed, never the router that said so.
#[test]
#[serial_test::serial(icmp_evidence)]
fn icmp_evidence_turns_silence_into_a_stated_cause() {
    use sipnab::sip::parser::parse_sip_bytes;

    pipeline::reset_icmp_evidence();

    let call_id = "icmp-diagnosis-1@test";
    let sip: bytes::Bytes = options_keepalive(call_id).into();
    let mut messages = Vec::new();
    for i in 0..3 {
        messages.push(
            parse_sip_bytes(
                &sip,
                Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, i)
                    .single()
                    .expect("ts"),
                IpAddr::V4(sender()),
                IpAddr::V4(dead_peer()),
                5080,
                5080,
                TransportProto::Udp,
            )
            .expect("fixture parses"),
        );
    }

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), 5080, 5080, &sip);
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);
    assert!(parse_packet(&pkt).is_err());

    let diag = sipnab::sip::diagnosis::diagnose_signaling(&messages);
    let icmp = diag
        .icmp_unreachable
        .as_ref()
        .expect("an ICMP quote for this Call-ID must reach the diagnosis");
    assert_eq!(icmp.unreachable_endpoint, format!("{}:5080", dead_peer()));
    assert_eq!(icmp.reported_by, router().to_string());
    assert_eq!(icmp.errors, 1);

    // Specifically the ICMP hint. The retransmission detection already offers
    // "a one-way path or an unreachable peer" — an inference over the same
    // silence — so a looser selector here would pass on the guess this
    // detection exists to replace with a fact.
    let hint = diag
        .hints
        .iter()
        .find(|h| h.starts_with("ICMP "))
        .expect("the finding must reach the plain-language hints");
    assert!(
        hint.contains(&dead_peer().to_string()),
        "the hint must name the endpoint that did not answer: {hint}"
    );
    assert!(
        !hint.contains(&router().to_string()) || hint.contains("reported by"),
        "the router may only appear as the reporter, never as the failure: {hint}"
    );

    pipeline::reset_icmp_evidence();
}

/// With no ICMP evidence recorded, diagnosis is byte-identical to what it was
/// before this feature existed — the detection is additive, never a new claim
/// drawn from the same old silence.
#[test]
#[serial_test::serial(icmp_evidence)]
fn without_evidence_the_diagnosis_is_unchanged() {
    use sipnab::sip::parser::parse_sip_bytes;

    pipeline::reset_icmp_evidence();

    let sip: bytes::Bytes = options_keepalive("icmp-diagnosis-2@test").into();
    let msg = parse_sip_bytes(
        &sip,
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
            .single()
            .expect("ts"),
        IpAddr::V4(sender()),
        IpAddr::V4(dead_peer()),
        5080,
        5080,
        TransportProto::Udp,
    )
    .expect("fixture parses");

    let diag = sipnab::sip::diagnosis::diagnose_signaling(&[msg]);
    assert!(
        diag.icmp_unreachable.is_none(),
        "no ICMP was seen, so no ICMP claim may be made"
    );
}

/// The published JSON schema must describe the field, not merely tolerate its
/// absence.
///
/// `signaling_diagnosis` is declared `additionalProperties: false`, and
/// `icmp_unreachable` is skipped when absent — so every existing fixture keeps
/// validating whether or not the schema knows about the field. That is exactly
/// the shape of an under-declared contract: green on the test corpus, invalid
/// on the first real capture that contains ICMP. This validates a diagnosis
/// that actually carries the field.
#[test]
fn the_schema_declares_the_icmp_finding() {
    use serde_json::Value;
    use sipnab::sip::diagnosis::{IcmpUnreachable, SignalingDiagnosis};

    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(support::schema::schema_path("call_report.schema.json"))
            .expect("read call_report.schema.json"),
    )
    .expect("parse schema");
    let subschema = schema
        .get("$defs")
        .and_then(|d| d.get("signaling_diagnosis"))
        .expect("call_report.schema.json must define signaling_diagnosis")
        .clone();
    let validator = jsonschema::validator_for(&subschema).expect("compile signaling_diagnosis");

    let diag = SignalingDiagnosis {
        icmp_unreachable: Some(IcmpUnreachable {
            description: "port unreachable".to_string(),
            icmp_type: 3,
            icmp_code: 3,
            unreachable_endpoint: "198.51.100.20:5080".to_string(),
            reported_by: "203.0.113.1".to_string(),
            method: Some("OPTIONS".to_string()),
            errors: 2,
            truncated: true,
            evidence: vec![0, 1],
        }),
        hints: vec!["ICMP port unreachable".to_string()],
        ..Default::default()
    };
    let instance = serde_json::to_value(&diag).expect("serialize");
    support::schema::assert_valid(
        &validator,
        &instance,
        "a diagnosis carrying icmp_unreachable",
    );

    // …and absence still serializes to nothing at all, so a capture with no
    // ICMP produces the same object it always did.
    let clean = serde_json::to_value(SignalingDiagnosis::default()).expect("serialize");
    assert!(
        clean.get("icmp_unreachable").is_none(),
        "a diagnosis with no ICMP evidence must omit the field, not emit null: \
         null would claim the check ran on a capture that held no ICMP"
    );
}

// ── Bounded retention, exact counts ──────────────────────────────────

/// Past the per-dialog sample cap, the COUNT is still exact.
///
/// Found by running against the corpus: 720 of 3,232 real ICMP errors fell
/// past the cap, and a finding drawn from the retained samples would have told
/// an operator a peer failed eight times when it failed thirty. The samples
/// are how many quotes are shown; `errors` is how many there were, and only
/// one of those two numbers is a fact about the network.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_dialog_past_the_sample_cap_still_reports_the_exact_count() {
    pipeline::reset_icmp_evidence();

    let call_id = "icmp-cap-1@test";
    let over = pipeline::MAX_ICMP_PER_CALL_ID + 5;
    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        5080,
        5080,
        &options_keepalive(call_id),
    );
    for _ in 0..over {
        assert!(parse_packet(&icmpv4_error(router(), sender(), 3, 1, &quoted)).is_err());
    }

    let ev = pipeline::icmp_evidence_for(call_id);
    assert_eq!(
        ev.errors, over as u64,
        "the count must be exact past the retention cap"
    );
    assert_eq!(
        ev.samples.len(),
        pipeline::MAX_ICMP_PER_CALL_ID,
        "retention is capped; only the detail stops, not the count"
    );

    // And the finding an operator reads must carry the exact number.
    let sip: bytes::Bytes = options_keepalive(call_id).into();
    let msg = sipnab::sip::parser::parse_sip_bytes(
        &sip,
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
            .single()
            .expect("ts"),
        IpAddr::V4(sender()),
        IpAddr::V4(dead_peer()),
        5080,
        5080,
        TransportProto::Udp,
    )
    .expect("fixture parses");
    let diag = sipnab::sip::diagnosis::diagnose_signaling(&[msg]);
    let finding = diag.icmp_unreachable.as_ref().expect("a finding");
    assert_eq!(
        finding.errors, over,
        "the finding must report every error, not just the retained ones"
    );

    pipeline::reset_icmp_evidence();
}

/// Past the endpoint cap, errors are counted as untallied rather than
/// forgotten — so `endpoints` plus `untallied_endpoints` always reconciles to
/// `errors`, and a reader can tell a complete endpoint list from a partial
/// one.
#[test]
#[serial_test::serial(icmp_evidence)]
fn endpoint_overflow_is_counted_not_forgotten() {
    pipeline::reset_icmp_evidence();

    // One more distinct unreachable endpoint than the store retains.
    let over = pipeline::MAX_ICMP_ENDPOINTS + 1;
    for i in 0..over {
        // 198.51.100.0/24 is the documentation range; vary the last two octets
        // so every error names a different endpoint.
        let peer = Ipv4Addr::new(198, 51, (i / 256) as u8, (i % 256) as u8);
        let quoted = quoted_ipv4_udp(
            sender(),
            peer,
            5080,
            5080,
            &options_keepalive("icmp-cap-2@test"),
        );
        assert!(parse_packet(&icmpv4_error(router(), sender(), 3, 1, &quoted)).is_err());
    }

    let report = pipeline::icmp_evidence_report();
    assert_eq!(report.errors, over as u64);
    assert_eq!(report.endpoints.len(), pipeline::MAX_ICMP_ENDPOINTS);
    assert_eq!(
        report.untallied_endpoints, 1,
        "the endpoint past the cap must be counted as untallied, not dropped"
    );
    assert_eq!(
        report.endpoints.iter().map(|e| e.errors).sum::<u64>() + report.untallied_endpoints,
        report.errors,
        "endpoints plus untallied must reconcile to the total, or the report \
         quietly under-counts what the network said"
    );

    pipeline::reset_icmp_evidence();
}
