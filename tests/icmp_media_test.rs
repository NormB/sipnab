// SPDX-License-Identifier: MIT OR Apache-2.0

//! ICMP errors that quote MEDIA rather than signalling.
//!
//! An ICMP port-unreachable quoting an RTP packet is the direct answer to the
//! commonest complaint this tool exists to explain: "the call connected and
//! nobody could hear anything." It says, from the network itself, that the
//! audio was sent to a host that was not listening. sipnab parsed these and
//! then dropped them: in one real corpus 544 of 3,776 ICMP errors quoted a
//! non-SIP port and reached no output at all.
//!
//! The hard part is the association key, and it is not the SIP one. A media
//! datagram carries no `Call-ID`, so a quote of one cannot name a dialog by
//! reading it. What it does carry is the failed datagram's own 5-tuple, and —
//! when the router quoted more than RFC 792's 8-byte minimum — an RTP or RTCP
//! header with an SSRC. Those are matched against the streams sipnab tracked.
//!
//! Four properties are load-bearing and each has a test here:
//!
//! 1. **The quote is matched on the 5-tuple, not guessed.** An exact directed
//!    match against a tracked stream is the strongest tie available and is
//!    tried first.
//! 2. **A quote that matches nothing is counted, never dropped.** It is real
//!    evidence about a real endpoint; only the stream is unknown, and the
//!    report says which of the two it is missing.
//! 3. **A quote is evidence, never a thing.** It must not create a stream,
//!    move a stream count, or enter the SIP evidence report.
//! 4. **RTCP is one port above RTP.** Media errors in the real corpus are
//!    predominantly about the RTCP port, which no RTP stream is ever keyed on,
//!    so the companion-port rule (RFC 3550 §11) is what stops the commonest
//!    case falling out.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use chrono::{TimeZone, Utc};
use sipnab::capture::Packet;
use sipnab::capture::parse::{ParsedPacket, TransportProto, parse_packet};
use sipnab::pipeline::{self, MediaMatch, QuotedMediaKind};
use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::stream_store::StreamStore;

// ── Fixtures ─────────────────────────────────────────────────────────

/// Ethernet link type (DLT_EN10MB).
const DLT_EN10MB: i32 = 1;

/// The endpoint whose media failed to arrive — the one sending audio.
fn sender() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 10)
}

/// The endpoint that did not answer on its media port.
fn dead_peer() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 20)
}

/// The router that reported the failure — never the fault.
fn router() -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, 1)
}

/// The sender's RTP port. Even, per RFC 3550 §11, so RTCP is one above.
const RTP_SRC: u16 = 40000;
/// The unreachable RTP port.
const RTP_DST: u16 = 20000;
/// The SSRC of the stream under test.
const SSRC: u32 = 0x0BAD_F00D;

/// A minimal RTP packet: version 2, PCMU, with `ssrc` and a G.711 payload.
fn rtp_datagram(ssrc: u32) -> Vec<u8> {
    let mut d = vec![0x80u8, 0x00]; // V=2, PT=0 (PCMU)
    d.extend_from_slice(&1u16.to_be_bytes()); // sequence
    d.extend_from_slice(&160u32.to_be_bytes()); // timestamp
    d.extend_from_slice(&ssrc.to_be_bytes());
    d.extend_from_slice(&[0xAB; 160]);
    d
}

/// A minimal RTCP receiver report (PT 201) from `ssrc`, with no report blocks.
fn rtcp_datagram(ssrc: u32) -> Vec<u8> {
    let mut d = vec![0x80u8, 201]; // V=2, RC=0, PT=201 (RR)
    d.extend_from_slice(&1u16.to_be_bytes()); // length: 1 => 8 bytes total
    d.extend_from_slice(&ssrc.to_be_bytes());
    d
}

/// Build the IPv4/UDP datagram an ICMP error quotes.
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
    d.push(0x45);
    d.push(0x00);
    d.extend_from_slice(&total_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x07]);
    d.extend_from_slice(&[0x40, 0x00]);
    d.push(64);
    d.push(17); // UDP
    d.extend_from_slice(&[0x00, 0x00]);
    d.extend_from_slice(&src.octets());
    d.extend_from_slice(&dst.octets());
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&udp_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
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
    icmp.extend_from_slice(&[0x00, 0x00]);
    icmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    icmp.extend_from_slice(quoted);

    let total_len = (20 + icmp.len()) as u16;
    let mut pkt = Vec::with_capacity(14 + total_len as usize);
    pkt.extend_from_slice(&[0xAA; 6]);
    pkt.extend_from_slice(&[0xBB; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x09]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(1); // ICMP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&reporter.octets());
    pkt.extend_from_slice(&reported_to.octets());
    pkt.extend_from_slice(&icmp);

    let len = pkt.len();
    Packet::new(
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
            .single()
            .expect("fixture timestamp"),
        pkt,
        len,
        len,
        None,
        DLT_EN10MB,
    )
}

/// Feed one ICMP error through the real parser, which is where evidence is
/// filed. Driving `parse_packet` rather than the recorder directly is the
/// point: every capture path funnels through it.
fn feed(pkt: &Packet) {
    assert!(
        parse_packet(pkt).is_err(),
        "an ICMP error must never become a ParsedPacket"
    );
}

/// A tracked RTP stream from `sender():src_port` to `dead_peer():dst_port`.
fn store_with_stream(
    src_port: u16,
    dst_port: u16,
    ssrc: u32,
    call_id: Option<&str>,
) -> StreamStore {
    let mut store = StreamStore::new(64);
    if let Some(call_id) = call_id {
        store.link_endpoint(IpAddr::V4(dead_peer()), dst_port, call_id, &[]);
    }
    let parsed = ParsedPacket {
        timestamp: Utc
            .with_ymd_and_hms(2024, 1, 15, 11, 59, 0)
            .single()
            .expect("fixture timestamp"),
        tcp_seq: None,
        tcp_flags: None,
        src_addr: IpAddr::V4(sender()),
        dst_addr: IpAddr::V4(dead_peer()),
        src_port,
        dst_port,
        transport: TransportProto::Udp,
        payload: bytes::Bytes::from_static(&[0u8; 172]),
        ip_id: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        from_hep: false,
    };
    let rtp = RtpHeader {
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
    };
    store.process_rtp(
        &parsed,
        &rtp,
        Utc.with_ymd_and_hms(2024, 1, 15, 11, 59, 0)
            .single()
            .expect("fixture timestamp"),
    );
    store
}

// ── Recording ────────────────────────────────────────────────────────

/// An ICMP error quoting RTP is recorded. Before this it was parsed, found not
/// to be SIP, and thrown away — the capture held the answer to "why is there
/// no audio" and every surface said nothing.
#[test]
#[serial_test::serial(icmp_evidence)]
fn an_icmp_error_quoting_rtp_is_recorded_not_dropped() {
    pipeline::reset_icmp_evidence();

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.errors, 1, "the error must reach a report");
    assert_eq!(
        report.endpoints.len(),
        1,
        "the socket that did not answer is known even when the stream is not"
    );
    assert_eq!(report.endpoints[0].addr, IpAddr::V4(dead_peer()));
    assert_eq!(report.endpoints[0].port, Some(RTP_DST));

    pipeline::reset_icmp_evidence();
}

/// The quoted payload is read for what it is. An RTP header in the quote is
/// how sipnab can say "your audio" rather than "a datagram", and the SSRC it
/// carries is a second, independent key onto a tracked stream.
#[test]
#[serial_test::serial(icmp_evidence)]
fn the_quoted_payload_is_recognised_as_rtp() {
    pipeline::reset_icmp_evidence();

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    let f = report.flows.first().expect("one flow");
    assert_eq!(
        f.payload,
        QuotedMediaKind::Rtp {
            ssrc: SSRC,
            payload_type: 0
        }
    );
    assert_eq!(report.media, 1, "an RTP quote is media whatever it matched");

    pipeline::reset_icmp_evidence();
}

/// A quote of something that is neither SIP nor media is still recorded and
/// still named — but it is not claimed as media. Reporting a failed DNS query
/// as a media blackhole would be a fabricated diagnosis.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_non_media_quote_is_recorded_but_not_claimed_as_media() {
    pipeline::reset_icmp_evidence();

    // A DNS query: not SIP, not RTP, not RTCP.
    let dns = [
        0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let quoted = quoted_ipv4_udp(sender(), dead_peer(), 53000, 53, &dns);
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.errors, 1, "still recorded — the endpoint is real");
    assert_eq!(report.media, 0, "and not reported as a media failure");
    assert_eq!(
        report.flows.first().expect("one flow").payload,
        QuotedMediaKind::NotMedia
    );

    pipeline::reset_icmp_evidence();
}

// ── Association ──────────────────────────────────────────────────────

/// The strongest tie available: the quoted datagram's own directed 5-tuple is
/// exactly a stream sipnab tracked. The finding then names the call.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_media_quote_is_matched_to_the_stream_whose_five_tuple_it_carries() {
    pipeline::reset_icmp_evidence();

    let store = store_with_stream(RTP_SRC, RTP_DST, SSRC, Some("media-icmp-1@test"));
    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&store);
    assert_eq!(report.attributed, 1);
    assert_eq!(report.unattributed, 0);
    let f = report.flows.first().expect("one flow");
    assert_eq!(f.matched, MediaMatch::Flow);
    assert_eq!(f.call_ids, vec!["media-icmp-1@test".to_string()]);
    assert!(
        f.hint.contains("audio"),
        "a matched media blackhole must say what it costs the call: {}",
        f.hint
    );

    pipeline::reset_icmp_evidence();
}

/// RTCP runs one port above RTP, so an ICMP error about RTCP can never match a
/// stream's 5-tuple — the stream is keyed on the RTP port. The SSRC in the
/// quoted RTCP header is the tie that survives, and in the real corpus the
/// media errors are predominantly RTCP.
#[test]
#[serial_test::serial(icmp_evidence)]
fn an_rtcp_quote_is_matched_by_the_ssrc_it_carries() {
    pipeline::reset_icmp_evidence();

    let store = store_with_stream(RTP_SRC, RTP_DST, SSRC, Some("media-icmp-2@test"));
    // RTCP: source and destination ports are both one above the RTP pair, so
    // neither the 5-tuple nor either socket is a stream endpoint.
    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        RTP_SRC + 1,
        RTP_DST + 1,
        &rtcp_datagram(SSRC),
    );
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&store);
    let f = report.flows.first().expect("one flow");
    assert_eq!(
        f.matched,
        MediaMatch::Ssrc,
        "the SSRC is the only key an RTCP quote shares with an RTP stream"
    );
    assert_eq!(f.call_ids, vec!["media-icmp-2@test".to_string()]);
    assert_eq!(report.attributed, 1);

    pipeline::reset_icmp_evidence();
}

/// When no RTP was captured at all — a one-sided capture, or media that never
/// started — an RTCP quote still lands on the call, through the SDP-advertised
/// media port one below it (RFC 3550 §11).
#[test]
#[serial_test::serial(icmp_evidence)]
fn an_rtcp_quote_falls_back_to_the_sdp_media_port_one_below() {
    pipeline::reset_icmp_evidence();

    let mut store = StreamStore::new(64);
    store.link_endpoint(
        IpAddr::V4(dead_peer()),
        RTP_DST,
        "media-icmp-3@test",
        &[(0, "PCMU".to_string(), 8000)],
    );
    assert_eq!(store.len(), 0, "an SDP link creates no stream");

    let quoted = quoted_ipv4_udp(
        sender(),
        dead_peer(),
        RTP_SRC + 1,
        RTP_DST + 1,
        // Truncated to the RFC 792 minimum: no payload, so no SSRC either.
        &[],
    );
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&store);
    let f = report.flows.first().expect("one flow");
    assert_eq!(f.matched, MediaMatch::SdpEndpoint);
    assert_eq!(f.call_ids, vec!["media-icmp-3@test".to_string()]);
    assert_eq!(
        f.payload,
        QuotedMediaKind::Unread,
        "RFC 792's minimum quote carries no payload to read"
    );

    pipeline::reset_icmp_evidence();
}

/// A quote that matches nothing is counted as unattributed and reported with
/// the endpoint it names. Dropping it would hide the fact that the network
/// answered — the exact defect this whole feature exists to remove.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_quote_matching_no_stream_is_unattributed_not_dropped() {
    pipeline::reset_icmp_evidence();

    // A store with an unrelated stream, so "no match" is a real decision
    // rather than an empty store trivially matching nothing.
    let store = store_with_stream(41000, 21000, 0xFEED_FACE, Some("other-call@test"));
    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&store);
    assert_eq!(report.errors, 1);
    assert_eq!(report.attributed, 0);
    assert_eq!(
        report.unattributed, 1,
        "attributed + unattributed must always equal errors"
    );
    let f = report.flows.first().expect("one flow");
    assert_eq!(f.matched, MediaMatch::None);
    assert!(f.call_ids.is_empty());
    assert!(
        f.hint.contains("no stream"),
        "the report must say which half is missing: {}",
        f.hint
    );

    pipeline::reset_icmp_evidence();
}

/// Repeated errors against one flow collapse to one finding with an exact
/// count. Thirty blackholed packets is a different picture from one.
#[test]
#[serial_test::serial(icmp_evidence)]
fn repeated_errors_on_one_flow_are_one_finding_with_an_exact_count() {
    pipeline::reset_icmp_evidence();

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    let pkt = icmpv4_error(router(), sender(), 3, 3, &quoted);
    for _ in 0..30 {
        feed(&pkt);
    }

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.errors, 30);
    assert_eq!(report.flows.len(), 1, "one flow, not thirty");
    assert_eq!(
        report.flows[0].errors, 30,
        "the count is exact past the sample retention cap"
    );

    pipeline::reset_icmp_evidence();
}

/// Routers on one path do not all quote the same number of bytes. One quote
/// that reached the RTP header is enough to know what the flow carries, so
/// reading only the newest sample would lose it to whichever router quoted
/// least.
#[test]
#[serial_test::serial(icmp_evidence)]
fn one_generous_quote_settles_what_the_flow_carries() {
    pipeline::reset_icmp_evidence();

    // First: a full RTP header. Then two RFC 792 minimum quotes of the same
    // flow, which carry no payload at all.
    let full = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 3, &full));
    let bare = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &[]);
    feed(&icmpv4_error(router(), sender(), 3, 3, &bare));
    feed(&icmpv4_error(router(), sender(), 3, 3, &bare));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.flows.len(), 1, "one flow");
    assert_eq!(
        report.flows[0].payload,
        QuotedMediaKind::Rtp {
            ssrc: SSRC,
            payload_type: 0
        },
        "the generous quote settles it for the flow"
    );
    assert_eq!(report.media, 3, "every error on the flow is media");

    pipeline::reset_icmp_evidence();
}

/// A quote that stopped before the transport header names no flow at all —
/// there are no ports in it to key on. That is a third outcome, distinct from
/// "matched nothing", and it is counted separately so a reader can tell a
/// router that quotes too little from media this capture does not hold.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_quote_stopping_before_the_ports_is_counted_as_unkeyed() {
    pipeline::reset_icmp_evidence();

    let full = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    // The IPv4 header and nothing else: both addresses are readable, neither
    // port is.
    feed(&icmpv4_error(router(), sender(), 3, 1, &full[..20]));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.errors, 1);
    assert_eq!(
        report.unkeyed, 1,
        "no ports in the quote means no flow to match, and that must be visible"
    );
    assert_eq!(report.flows.len(), 0, "there is no flow to report");
    assert_eq!(
        report.unattributed, 1,
        "unkeyed is a subset of unattributed, never a third bucket outside the total"
    );
    assert_eq!(
        report.endpoints.len(),
        1,
        "the host that did not answer is known even with no port"
    );
    assert_eq!(report.endpoints[0].port, None);

    pipeline::reset_icmp_evidence();
}

// ── Accounting ───────────────────────────────────────────────────────

/// A quote is evidence ABOUT media, never media. It must not create a stream,
/// move a stream count, or enter the SIP evidence report — the same line the
/// signalling side holds, on the media side.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_media_quote_never_becomes_a_stream_or_a_sip_message() {
    pipeline::reset_icmp_evidence();

    let store = store_with_stream(RTP_SRC, RTP_DST, SSRC, None);
    let before = store.len();

    for payload in [rtp_datagram(SSRC), rtcp_datagram(SSRC)] {
        let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &payload);
        feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));
    }

    assert_eq!(
        store.len(),
        before,
        "an ICMP quote of RTP must not add a stream: it is one packet that never arrived"
    );
    assert_eq!(
        pipeline::icmp_evidence_report().errors,
        0,
        "a media quote is not evidence about a SIP message"
    );
    assert_eq!(pipeline::icmp_media_report(&store).errors, 2);

    pipeline::reset_icmp_evidence();
}

/// The reporter is the device that noticed, not the device that failed. Naming
/// it as the fault sends an operator to debug a working router.
#[test]
#[serial_test::serial(icmp_evidence)]
fn the_reporter_is_never_reported_as_the_failure() {
    pipeline::reset_icmp_evidence();

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    let f = report.flows.first().expect("one flow");
    assert_eq!(
        f.unreachable_endpoint,
        SocketAddr::new(IpAddr::V4(dead_peer()), RTP_DST).to_string()
    );
    assert_eq!(f.reported_by, router().to_string());
    assert_ne!(
        f.unreachable_endpoint, f.reported_by,
        "the two addresses mean opposite things"
    );
    assert_eq!(
        report.endpoints[0].addr,
        IpAddr::V4(dead_peer()),
        "the endpoint tally names the failure, never the reporter"
    );

    pipeline::reset_icmp_evidence();
}

/// Two routers reporting the same dead socket is one broken endpoint, not two.
/// The tally is keyed on the socket that failed; keying it on the reporter
/// would split one fault across however many devices happened to notice, and
/// under-state every one of them.
#[test]
#[serial_test::serial(icmp_evidence)]
fn two_reporters_naming_one_dead_socket_are_one_endpoint() {
    pipeline::reset_icmp_evidence();

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 1, &quoted));
    feed(&icmpv4_error(
        Ipv4Addr::new(203, 0, 113, 2),
        sender(),
        3,
        1,
        &quoted,
    ));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.errors, 2);
    assert_eq!(
        report.endpoints.len(),
        1,
        "one socket failed, however many devices said so"
    );
    assert_eq!(report.endpoints[0].addr, IpAddr::V4(dead_peer()));
    assert_eq!(report.endpoints[0].errors, 2);

    pipeline::reset_icmp_evidence();
}

/// Administratively prohibited is a firewall, not a dead media port, and it
/// changes who the operator calls.
#[test]
#[serial_test::serial(icmp_evidence)]
fn an_administratively_prohibited_media_error_names_the_filter() {
    pipeline::reset_icmp_evidence();

    let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, RTP_DST, &rtp_datagram(SSRC));
    feed(&icmpv4_error(router(), sender(), 3, 13, &quoted));

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    let f = report.flows.first().expect("one flow");
    assert_eq!(f.description, "communication administratively prohibited");
    assert!(
        f.hint.contains("filtering") || f.hint.contains("firewall"),
        "a prohibition is a policy decision and the fix is the filter: {}",
        f.hint
    );

    pipeline::reset_icmp_evidence();
}

/// The flow map is keyed by addresses and ports a remote party chooses, so it
/// is bounded and says what it did at the bound (invariant 4). Past the cap the
/// exact error total still rises and the excess is counted as untracked, so a
/// flood costs memory nothing and costs the report only detail it names.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_flood_of_unique_flows_is_bounded_and_says_so() {
    pipeline::reset_icmp_evidence();

    let over = pipeline::MAX_ICMP_MEDIA_FLOWS + 64;
    for i in 0..over {
        // A distinct destination port per error, which is a distinct flow.
        let port = 1024u16.wrapping_add(i as u16);
        let quoted = quoted_ipv4_udp(sender(), dead_peer(), RTP_SRC, port, &rtp_datagram(SSRC));
        feed(&icmpv4_error(router(), sender(), 3, 3, &quoted));
    }

    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report.errors, over as u64, "the total stays exact");
    assert!(
        report.flows.len() <= pipeline::MAX_ICMP_MEDIA_FLOWS,
        "the flow map must not grow past its cap: {} flows",
        report.flows.len()
    );
    assert!(
        report.untracked_flows > 0,
        "the errors past the cap must be counted, not dropped in silence"
    );
    assert_eq!(
        report.flows.iter().map(|f| f.errors).sum::<u64>()
            + report.untracked_flows
            + report.unkeyed,
        report.errors,
        "every error reaches a flow or one of the two named overflow counters"
    );

    pipeline::reset_icmp_evidence();
}

/// With no ICMP recorded the report is empty and costs nothing — the common
/// case for a healthy capture.
#[test]
#[serial_test::serial(icmp_evidence)]
fn a_capture_without_icmp_reports_nothing() {
    pipeline::reset_icmp_evidence();
    let report = pipeline::icmp_media_report(&StreamStore::new(8));
    assert_eq!(report, Default::default());
}
