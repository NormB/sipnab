// SPDX-License-Identifier: MIT OR Apache-2.0

//! The media diagnosis must reach the surfaces that publish it.
//!
//! `no_media` and `nat_mismatch` were computed only when `diagnose_media`
//! was handed an SDP session, and every production caller handed it `None`:
//! the filter DSL, batch output, the REST API and the MCP server alike. Both
//! flags were therefore always `false`, so `--nat-issues` selected nothing on
//! any capture and `NOT nat_mismatch` selected everything. Unit tests passed
//! because they alone supplied the SDP the callers withheld.
//!
//! These tests drive [`select_dialogs`] — the entry point the CLI, the REST
//! API and the MCP tools all funnel through — so a diagnosis that is computed
//! but never delivered still fails. They also pin the two false positives the
//! wiring could introduce: a healthy bidirectional call whose two legs
//! legitimately source RTP from two different advertised addresses, and a call
//! whose media was negotiated inactive (hold) and so was never expected to
//! carry RTP at all.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::rtp::parser::parse_rtp_header;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::dsl::{FilterExpr, select_dialogs};
use sipnab::sip::parser::parse_sip;

// ── Fixtures ────────────────────────────────────────────────────────────

/// Deterministic timestamp `secs` seconds after a fixed base.
fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
}

/// An IPv4 address from four octets.
fn ip(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

/// Build raw SIP bytes from a start line, header lines and a body.
///
/// The crate's own `test_utils` builder is `#[cfg(test)]`, so it is invisible
/// from an integration test; this is the same three-line assembly.
fn build_sip_message(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(first_line.as_bytes());
    msg.extend_from_slice(b"\r\n");
    for h in headers {
        msg.extend_from_slice(h.as_bytes());
        msg.extend_from_slice(b"\r\n");
    }
    msg.extend_from_slice(b"\r\n");
    msg.extend_from_slice(body);
    msg
}

/// An SDP body advertising one audio stream at `addr:port` with `direction`.
fn sdp_body(addr: &str, port: u16, direction: &str) -> String {
    format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 {addr}\r\n\
         s=-\r\n\
         c=IN IP4 {addr}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a={direction}\r\n"
    )
}

/// Feed an INVITE carrying `body` into `store` under `call_id`.
fn offer(store: &mut DialogStore, call_id: &str, body: &str, at: DateTime<Utc>) {
    let raw = build_sip_message(
        "INVITE sip:b@example.net SIP/2.0",
        &[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-offer",
            "From: <sip:a@example.net>;tag=aaa",
            "To: <sip:b@example.net>",
            &format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
            &format!("Content-Length: {}", body.len()),
        ],
        body.as_bytes(),
    );
    let msg = parse_sip(
        &raw,
        at,
        ip([10, 0, 0, 1]),
        ip([10, 0, 0, 2]),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("INVITE should parse");
    store.process_message(msg);
}

/// Feed a 200 OK carrying `body` into `store` under `call_id`.
fn answer(store: &mut DialogStore, call_id: &str, body: &str, at: DateTime<Utc>) {
    let raw = build_sip_message(
        "SIP/2.0 200 OK",
        &[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-offer",
            "From: <sip:a@example.net>;tag=aaa",
            "To: <sip:b@example.net>;tag=bbb",
            &format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
            &format!("Content-Length: {}", body.len()),
        ],
        body.as_bytes(),
    );
    let msg = parse_sip(
        &raw,
        at,
        ip([10, 0, 0, 2]),
        ip([10, 0, 0, 1]),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("200 OK should parse");
    store.process_message(msg);
}

/// Feed a bodiless 200 OK into `store` under `call_id`.
///
/// The call is answered, but the offer in the INVITE never got its answer.
fn answer_without_sdp(store: &mut DialogStore, call_id: &str, at: DateTime<Utc>) {
    let raw = build_sip_message(
        "SIP/2.0 200 OK",
        &[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-offer",
            "From: <sip:a@example.net>;tag=aaa",
            "To: <sip:b@example.net>;tag=bbb",
            &format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = parse_sip(
        &raw,
        at,
        ip([10, 0, 0, 2]),
        ip([10, 0, 0, 1]),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("200 OK should parse");
    store.process_message(msg);
}

/// Feed a re-INVITE (CSeq 2) carrying `body` into `store` under `call_id`.
fn reoffer(store: &mut DialogStore, call_id: &str, body: &str, at: DateTime<Utc>) {
    let raw = build_sip_message(
        "INVITE sip:b@example.net SIP/2.0",
        &[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reoffer",
            "From: <sip:a@example.net>;tag=aaa",
            "To: <sip:b@example.net>;tag=bbb",
            &format!("Call-ID: {call_id}"),
            "CSeq: 2 INVITE",
            "Content-Type: application/sdp",
            &format!("Content-Length: {}", body.len()),
        ],
        body.as_bytes(),
    );
    let msg = parse_sip(
        &raw,
        at,
        ip([10, 0, 0, 1]),
        ip([10, 0, 0, 2]),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("re-INVITE should parse");
    store.process_message(msg);
}

/// One synthetic PCMU packet on the given 4-tuple.
fn rtp_packet(
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    ssrc: u32,
    seq: u16,
) -> ParsedPacket {
    let mut payload = Vec::with_capacity(172);
    payload.push(0x80);
    payload.push(0x00); // PT 0, PCMU
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    payload.extend_from_slice(&ssrc.to_be_bytes());
    payload.extend_from_slice(&[0x7F; 160]);

    ParsedPacket {
        frame: None,
        timestamp: ts(0),
        src_addr: src,
        dst_addr: dst,
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
        input_origin: sipnab::capture::parse::InputOrigin::Wire,
    }
}

/// Record ten RTP packets on the given 4-tuple into `store`.
fn record_stream(
    store: &mut StreamStore,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    ssrc: u32,
) {
    for i in 0..10u16 {
        let parsed = rtp_packet(src, src_port, dst, dst_port, ssrc, 100 + i);
        let hdr = parse_rtp_header(&parsed.payload).expect("synthetic RTP header");
        store.process_rtp(&parsed, &hdr, ts(i as i64));
    }
}

/// Call-IDs selected by `expr` over the two stores.
fn selected(expr: &str, ds: &DialogStore, ss: &StreamStore) -> Vec<String> {
    let filter = FilterExpr::parse(expr).expect("filter should parse");
    select_dialogs(Some(&filter), ds, ss)
        .dialogs
        .iter()
        .map(|(d, _)| d.call_id.clone())
        .collect()
}

// ── nat_mismatch ────────────────────────────────────────────────────────

/// RTP arriving from an address no SDP in the dialog advertised is a NAT
/// mismatch, and `--nat-issues` (`nat_mismatch == true`) must select it.
///
/// The offer advertises the caller's PRIVATE media address; its RTP actually
/// leaves a public one because a NAT rewrote the source. This is the single
/// most common media fault on a SIP trunk, and it is the case the unwired
/// diagnosis could never report.
#[test]
fn nat_rewritten_rtp_source_is_selected_by_nat_mismatch() {
    let call_id = "nat-rewrite@example.net";
    let mut ds = DialogStore::new(64, false);
    // Caller advertises 192.168.1.10 (pre-NAT); callee advertises 203.0.113.9.
    offer(
        &mut ds,
        call_id,
        &sdp_body("192.168.1.10", 20000, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.9", 30000, "sendrecv"),
        ts(1),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([192, 168, 1, 10]), 20000, call_id, &[]);
    ss.link_endpoint(ip([203, 0, 113, 9]), 30000, call_id, &[]);
    // Callee → caller: sourced from the advertised 203.0.113.9. Fine.
    record_stream(
        &mut ss,
        ip([203, 0, 113, 9]),
        30000,
        ip([198, 51, 100, 7]),
        20000,
        0x2222,
    );
    // Caller → callee: sourced from 198.51.100.7, which NO SDP advertised.
    record_stream(
        &mut ss,
        ip([198, 51, 100, 7]),
        20000,
        ip([203, 0, 113, 9]),
        30000,
        0x1111,
    );

    assert_eq!(
        selected("nat_mismatch == true", &ds, &ss),
        vec![call_id.to_string()],
        "RTP from an address no SDP advertised is the NAT mismatch --nat-issues exists to find"
    );
}

/// A healthy bidirectional call is NOT a NAT mismatch.
///
/// Each leg sources RTP from the address its own side advertised. Comparing
/// every stream source against a single `c=` line would flag one direction of
/// every two-way call ever captured, so the check compares against the
/// addresses the dialog advertised as a set.
#[test]
fn healthy_bidirectional_call_is_not_a_nat_mismatch() {
    let call_id = "healthy@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.1", 20000, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.2", 30000, "sendrecv"),
        ts(1),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 1]), 20000, call_id, &[]);
    ss.link_endpoint(ip([203, 0, 113, 2]), 30000, call_id, &[]);
    record_stream(
        &mut ss,
        ip([203, 0, 113, 1]),
        20000,
        ip([203, 0, 113, 2]),
        30000,
        0x1111,
    );
    record_stream(
        &mut ss,
        ip([203, 0, 113, 2]),
        30000,
        ip([203, 0, 113, 1]),
        20000,
        0x2222,
    );

    assert!(
        selected("nat_mismatch == true", &ds, &ss).is_empty(),
        "both legs sourced RTP from an address their own SDP advertised"
    );
}

/// A re-INVITE that moves the media anchor is not a NAT mismatch.
///
/// RTP captured before the move is legitimately sourced from the OLD anchor.
/// A diagnosis reading only the latest exchange would report every hold,
/// resume and codec renegotiation as a NAT fault, so every exchange in the
/// dialog contributes to the advertised set.
#[test]
fn re_invite_anchor_change_does_not_invalidate_earlier_rtp() {
    let call_id = "anchor-move@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.1", 20000, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.2", 30000, "sendrecv"),
        ts(1),
    );
    // Mid-call the caller re-anchors onto a different address.
    reoffer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.5", 21000, "sendrecv"),
        ts(30),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 1]), 20000, call_id, &[]);
    ss.link_endpoint(ip([203, 0, 113, 2]), 30000, call_id, &[]);
    ss.link_endpoint(ip([203, 0, 113, 5]), 21000, call_id, &[]);
    // Media from before the move, still sourced from the original anchor.
    record_stream(
        &mut ss,
        ip([203, 0, 113, 1]),
        20000,
        ip([203, 0, 113, 2]),
        30000,
        0x1111,
    );
    // Media from after the move.
    record_stream(
        &mut ss,
        ip([203, 0, 113, 5]),
        21000,
        ip([203, 0, 113, 2]),
        30000,
        0x3333,
    );
    record_stream(
        &mut ss,
        ip([203, 0, 113, 2]),
        30000,
        ip([203, 0, 113, 5]),
        21000,
        0x2222,
    );

    assert!(
        selected("nat_mismatch == true", &ds, &ss).is_empty(),
        "RTP from an anchor a re-INVITE replaced was advertised while it flowed"
    );
}

// ── no_media ────────────────────────────────────────────────────────────

/// An answered call that negotiated active media and carried no RTP is
/// `no_media`, and the filter must select it.
#[test]
fn answered_call_with_no_rtp_is_selected_by_no_media() {
    let silent = "silent@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        silent,
        &sdp_body("203.0.113.1", 20000, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        silent,
        &sdp_body("203.0.113.2", 30000, "sendrecv"),
        ts(1),
    );

    // A second call in the same capture DID carry media, so the capture is
    // demonstrably on a media path and the silence of the first is evidence.
    let noisy = "noisy@example.net";
    offer(
        &mut ds,
        noisy,
        &sdp_body("203.0.113.3", 22000, "sendrecv"),
        ts(2),
    );
    answer(
        &mut ds,
        noisy,
        &sdp_body("203.0.113.4", 32000, "sendrecv"),
        ts(3),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 3]), 22000, noisy, &[]);
    ss.link_endpoint(ip([203, 0, 113, 4]), 32000, noisy, &[]);
    record_stream(
        &mut ss,
        ip([203, 0, 113, 3]),
        22000,
        ip([203, 0, 113, 4]),
        32000,
        0x4444,
    );
    record_stream(
        &mut ss,
        ip([203, 0, 113, 4]),
        32000,
        ip([203, 0, 113, 3]),
        22000,
        0x5555,
    );

    assert_eq!(
        selected("no_media == true", &ds, &ss),
        vec![silent.to_string()],
        "the answered call that carried no RTP is the one with no media"
    );
}

/// A call whose media was negotiated `a=inactive` for its whole life is NOT
/// `no_media`.
///
/// Held media legitimately carries no RTP. Reporting it as a media failure
/// would be a new false positive of exactly the kind this diagnosis exists to
/// avoid, so `no_media` requires that some exchange in the dialog described
/// media that was actually expected to flow.
#[test]
fn call_held_inactive_throughout_is_not_no_media() {
    let held = "held@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        held,
        &sdp_body("203.0.113.1", 20000, "inactive"),
        ts(0),
    );
    answer(
        &mut ds,
        held,
        &sdp_body("203.0.113.2", 30000, "inactive"),
        ts(1),
    );

    let carrier = "carrier@example.net";
    offer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.3", 22000, "sendrecv"),
        ts(2),
    );
    answer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.4", 32000, "sendrecv"),
        ts(3),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 3]), 22000, carrier, &[]);
    record_stream(
        &mut ss,
        ip([203, 0, 113, 3]),
        22000,
        ip([203, 0, 113, 4]),
        32000,
        0x4444,
    );

    assert!(
        !selected("no_media == true", &ds, &ss).contains(&held.to_string()),
        "media negotiated inactive was never expected to flow"
    );
}

/// A hold offer that black-holes the connection address (`c=0.0.0.0`, the
/// RFC 2543 hold form still emitted by older gateways) is not `no_media`
/// either.
#[test]
fn call_held_with_black_holed_address_is_not_no_media() {
    let held = "blackhole@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        held,
        &sdp_body("0.0.0.0", 20000, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        held,
        &sdp_body("0.0.0.0", 30000, "sendrecv"),
        ts(1),
    );

    let carrier = "carrier2@example.net";
    offer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.3", 22000, "sendrecv"),
        ts(2),
    );
    answer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.4", 32000, "sendrecv"),
        ts(3),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 3]), 22000, carrier, &[]);
    record_stream(
        &mut ss,
        ip([203, 0, 113, 3]),
        22000,
        ip([203, 0, 113, 4]),
        32000,
        0x4444,
    );

    assert!(
        !selected("no_media == true", &ds, &ss).contains(&held.to_string()),
        "a black-holed connection address asks for no RTP"
    );
}

/// An offer that was never answered did not negotiate media, so its silence
/// is not a media failure.
#[test]
fn unanswered_offer_is_not_no_media() {
    let ringing = "ringing@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        ringing,
        &sdp_body("203.0.113.1", 20000, "sendrecv"),
        ts(0),
    );

    let carrier = "carrier3@example.net";
    offer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.3", 22000, "sendrecv"),
        ts(2),
    );
    answer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.4", 32000, "sendrecv"),
        ts(3),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 3]), 22000, carrier, &[]);
    record_stream(
        &mut ss,
        ip([203, 0, 113, 3]),
        22000,
        ip([203, 0, 113, 4]),
        32000,
        0x4444,
    );

    assert!(
        !selected("no_media == true", &ds, &ss).contains(&ringing.to_string()),
        "an unanswered INVITE never completed an offer/answer"
    );
}

/// A call answered with a bodiless 200 is not `no_media`.
///
/// The INVITE offered media and the call was answered, but the 2xx carried no
/// answer, so nothing was ever negotiated — RFC 3261 puts the answer in the
/// 2xx, and without it the two sides never agreed on a media path to fail.
/// `no_media` claims a negotiated path carried nothing; here there is no
/// negotiated path, and the real fault ("the 200 carried no SDP") belongs to
/// the signaling diagnosis. Counting SDP bodies instead of requiring one in a
/// request AND one in a response would report this as a media failure, and
/// would also let an INVITE plus its own retransmission look like an
/// offer/answer.
#[test]
fn call_answered_without_an_sdp_answer_is_not_no_media() {
    let unanswered_offer = "no-answer-sdp@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        unanswered_offer,
        &sdp_body("203.0.113.1", 20000, "sendrecv"),
        ts(0),
    );
    answer_without_sdp(&mut ds, unanswered_offer, ts(1));

    let carrier = "carrier4@example.net";
    offer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.3", 22000, "sendrecv"),
        ts(2),
    );
    answer(
        &mut ds,
        carrier,
        &sdp_body("203.0.113.4", 32000, "sendrecv"),
        ts(3),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 3]), 22000, carrier, &[]);
    record_stream(
        &mut ss,
        ip([203, 0, 113, 3]),
        22000,
        ip([203, 0, 113, 4]),
        32000,
        0x4444,
    );

    assert!(
        !selected("no_media == true", &ds, &ss).contains(&unanswered_offer.to_string()),
        "an offer the 2xx never answered did not negotiate a media path"
    );
}

/// On a capture that carried no RTP at all, `no_media` stays silent.
///
/// A signaling-only capture — a proxy tap, a HEP feed, `--no-rtp` — cannot
/// answer a question about RTP. Without this guard the flag reports the
/// capture's vantage point rather than the call, and selects every answered
/// call in the file.
#[test]
fn signalling_only_capture_reports_no_no_media() {
    let mut ds = DialogStore::new(64, false);
    for n in 0..3 {
        let call_id = format!("sig-only-{n}@example.net");
        offer(
            &mut ds,
            &call_id,
            &sdp_body("203.0.113.1", 20000, "sendrecv"),
            ts(n),
        );
        answer(
            &mut ds,
            &call_id,
            &sdp_body("203.0.113.2", 30000, "sendrecv"),
            ts(n + 1),
        );
    }
    let ss = StreamStore::new(64);

    assert!(
        selected("no_media == true", &ds, &ss).is_empty(),
        "a capture holding no RTP cannot show that a particular call had none"
    );
}

// ── The alias operators actually type ───────────────────────────────────

/// `--nat-issues` expands to `nat_mismatch == true`, so the alias must select
/// the NAT-rewritten call too. The flag is the surface operators reach for.
#[test]
fn the_nat_issues_alias_selects_the_rewritten_call() {
    let call_id = "alias-nat@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        call_id,
        &sdp_body("192.168.1.10", 20000, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        call_id,
        &sdp_body("203.0.113.9", 30000, "sendrecv"),
        ts(1),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([203, 0, 113, 9]), 30000, call_id, &[]);
    record_stream(
        &mut ss,
        ip([198, 51, 100, 7]),
        20000,
        ip([203, 0, 113, 9]),
        30000,
        0x1111,
    );

    let expr =
        sipnab::sip::dsl::expand_alias("nat-issues", &sipnab::sip::dsl::AliasThresholds::default())
            .expect("alias exists");
    assert_eq!(
        selected(&expr, &ds, &ss),
        vec![call_id.to_string()],
        "the --nat-issues alias must find what nat_mismatch finds"
    );
}

// ── The port evidence must reach the surfaces, not just the MCP tool ─────

/// The one-way hint's ports reach the text call report.
///
/// The hints are produced once, in `rtp::diagnosis`, and rendered by four
/// separate surfaces — the text and Markdown call reports, `--json-dialogs`,
/// the REST layer and the MCP tools. Formatting the ports inside any one
/// renderer would improve that surface and leave the other three emitting the
/// weaker sentence, so this test asserts the improved text arriving through a
/// NON-MCP surface: if the ports were added to a renderer rather than to the
/// producer, this fails.
///
/// The capture is the fault the ports exist to explain: the caller advertises
/// 16384, a NAT rewrote its source port to 41002, and the callee's reply goes
/// to 16384 where nothing is sending.
///
/// Gated on `native` at the call site because that is where the dependency is:
/// `sipnab::output` is compiled only under that feature, while everything else
/// in this file builds without it. The rest of the file must keep compiling
/// under `--no-default-features --features tls`, which is one of the
/// combinations CI builds and `--features full` cannot see.
#[cfg(feature = "native")]
#[test]
fn the_text_call_report_carries_the_port_evidence() {
    let call_id = "one-way-ports@example.net";
    let mut ds = DialogStore::new(64, false);
    offer(
        &mut ds,
        call_id,
        &sdp_body("10.0.2.15", 16384, "sendrecv"),
        ts(0),
    );
    answer(
        &mut ds,
        call_id,
        &sdp_body("10.0.2.20", 16386, "sendrecv"),
        ts(1),
    );

    let mut ss = StreamStore::new(64);
    ss.link_endpoint(ip([10, 0, 2, 20]), 16386, call_id, &[]);
    record_stream(
        &mut ss,
        ip([10, 0, 2, 15]),
        41002,
        ip([10, 0, 2, 20]),
        16386,
        0x343d_a99b,
    );

    let dialog = ds.get(call_id).expect("dialog was stored");
    let streams: Vec<&sipnab::rtp::stream::RtpStream> = ss.streams_for(call_id).collect();
    assert_eq!(streams.len(), 1, "one direction only, by construction");
    let ctx = sipnab::rtp::diagnosis::MediaContext::for_dialog(
        dialog,
        sipnab::rtp::diagnosis::CaptureMedia::of_store(&ss),
    );
    let diagnosis = sipnab::rtp::diagnosis::diagnose_media(&streams, &ctx);

    let report = sipnab::output::generate_call_report(
        dialog,
        &streams,
        &diagnosis,
        sipnab::output::ReportFormat::Text,
    );

    assert!(
        report.contains("10.0.2.15:41002 -> 10.0.2.20:16386"),
        "the report's issues section must name both ports of the flow:\n{report}"
    );
    assert!(
        report.contains("10.0.2.15 advertised 16384") && report.contains("sends from 41002"),
        "the report must carry the advertised-versus-actual comparison:\n{report}"
    );
    assert!(
        report.contains("10.0.2.20 replies to 16384"),
        "the report must name the port the reply goes to, where the pinhole is \
         missing:\n{report}"
    );
}
