// SPDX-License-Identifier: MIT OR Apache-2.0

//! The process-wide counters behind `/metrics`, at their increment sites.
//!
//! `sipnab_capture_packets_total` and `sipnab_reassembly_timeouts_total` were
//! written into every scrape as a literal `0` because nothing incremented
//! them. These tests drive the data-plane sites directly — a packet through
//! `PacketProcessor::process`, an entry aged past the reassembly TTL — and
//! assert the counter moved, then that the movement reaches the exposition
//! through `PrometheusMetrics::for_scrape`.
//!
//! Every assertion is a DELTA. The counters are process-global by design (one
//! capture, many scrape surfaces), so integration tests sharing this binary
//! also move them; an absolute value would be flaky where a delta is exact.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use sipnab::capture::parse::{ParsedPacket, TcpFlags, TransportProto};
use sipnab::capture::reassembly::{FragmentReassembler, TcpReassembler, reassembly_timeouts};
use sipnab::capture::{Packet, PacketProcessor, captured_packets};
use sipnab::output::prometheus::{PrometheusMetrics, format_metrics};

/// An IP fragment that is never completed: offset 0 with More-Fragments set.
///
/// # Arguments
/// * `ip_id` — the IP identification the entry is keyed under.
///
/// # Returns
/// A parsed packet the fragment reassembler will buffer and never release.
fn incomplete_fragment(ip_id: u32) -> ParsedPacket {
    ParsedPacket {
        timestamp: chrono::Utc::now(),
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 0,
        dst_port: 0,
        transport: TransportProto::Udp,
        payload: bytes::Bytes::from_static(&[0xAA; 8]),
        ip_id: Some(ip_id),
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: Some(0),
        more_fragments: true,
        ip_protocol: 17,
        from_hep: false,
    }
}

/// A plain ACK TCP segment carrying `payload`, so the reassembler opens a
/// stream that then goes idle.
///
/// # Arguments
/// * `src_port` — source port, which keys the stream.
///
/// # Returns
/// A parsed TCP packet with a partial SIP message that never completes.
fn idle_tcp_segment(src_port: u16) -> ParsedPacket {
    ParsedPacket {
        timestamp: chrono::Utc::now(),
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port,
        dst_port: 5060,
        transport: TransportProto::Tcp,
        payload: bytes::Bytes::from_static(b"INVITE sip:a@b SIP/2.0\r\n"),
        ip_id: None,
        tcp_seq: Some(100),
        tcp_flags: Some(TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        }),
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 6,
        from_hep: false,
    }
}

/// Every packet handed to the processor counts, including one that does not
/// parse — an unparseable frame was still captured, and a counter that
/// dropped it would understate a capture full of junk.
#[test]
fn processing_a_packet_moves_the_capture_counter() {
    let before = captured_packets();

    let mut processor = PacketProcessor::new();
    let packet = Packet::new(
        chrono::Utc::now(),
        vec![0x00; 14],
        14,
        14,
        None,
        1, // DLT_EN10MB
    );
    let _ = processor.process(&packet);

    assert!(
        captured_packets() > before,
        "PacketProcessor::process must count the packet: {before} -> {}",
        captured_packets()
    );
}

/// An IP fragment aged past the reassembly TTL and swept is a reassembly
/// timeout, and moves the counter by exactly the number of entries dropped.
#[test]
fn fragment_ttl_sweep_moves_the_reassembly_counter() {
    let mut r = FragmentReassembler::with_limits(100, Duration::from_millis(20));
    assert!(r.insert(&incomplete_fragment(0x4242)).is_none());
    assert!(r.insert(&incomplete_fragment(0x4343)).is_none());

    std::thread::sleep(Duration::from_millis(40));
    let before = reassembly_timeouts();
    r.sweep();

    assert!(r.is_empty(), "both stale entries should have been swept");
    assert_eq!(
        reassembly_timeouts(),
        before + 2,
        "two entries aged out, so the timeout counter moves by two"
    );
}

/// A sweep that drops nothing must not move the counter — otherwise the
/// metric would climb on every idle sweep tick and mean nothing.
#[test]
fn sweep_with_nothing_stale_leaves_the_counter_alone() {
    let mut r = FragmentReassembler::with_limits(100, Duration::from_secs(300));
    assert!(r.insert(&incomplete_fragment(0x5151)).is_none());

    let before = reassembly_timeouts();
    r.sweep();

    assert_eq!(r.len(), 1, "the entry is far from its TTL");
    assert_eq!(
        reassembly_timeouts(),
        before,
        "a sweep that evicted nothing must not count a timeout"
    );
}

/// An idle TCP stream swept past the TTL counts as a reassembly timeout too:
/// the metric names reassembly, not IP fragments alone.
#[test]
fn tcp_ttl_sweep_moves_the_reassembly_counter() {
    let mut r = TcpReassembler::with_limits(100, Duration::from_millis(20));
    r.insert(&idle_tcp_segment(41001));

    std::thread::sleep(Duration::from_millis(40));
    let before = reassembly_timeouts();
    r.sweep();

    assert!(r.is_empty(), "the idle stream should have been swept");
    assert_eq!(
        reassembly_timeouts(),
        before + 1,
        "one stream aged out, so the timeout counter moves by one"
    );
}

/// The scrape reads the live counters: what the data plane recorded is what
/// the exposition prints. A collector that built its metrics from
/// `PrometheusMetrics::default` printed `0` here forever.
#[test]
fn scrape_carries_the_process_counters_into_the_exposition() {
    let mut processor = PacketProcessor::new();
    let packet = Packet::new(chrono::Utc::now(), vec![0x00; 14], 14, 14, None, 1);
    let _ = processor.process(&packet);

    let metrics = PrometheusMetrics::for_scrape();
    assert!(
        metrics.capture_packets_total > 0,
        "for_scrape must load the capture counter, not leave it at zero"
    );

    let body = format_metrics(&metrics);
    let line = format!(
        "sipnab_capture_packets_total {}",
        metrics.capture_packets_total
    );
    assert!(
        body.contains(&line),
        "exposition should carry `{line}`; body was:\n{body}"
    );
}

/// A scrape initializes the closed label sets, so a rule over a class the
/// capture has not seen reads `0` instead of no-data. This is the difference
/// between "no 5xx responses" and "the metric does not exist".
#[test]
fn scrape_initialises_closed_label_sets() {
    let body = format_metrics(&PrometheusMetrics::for_scrape());

    for class in ["1xx", "2xx", "3xx", "4xx", "5xx", "6xx"] {
        assert!(
            body.contains(&format!(r#"sipnab_responses_total{{code="{class}"}}"#)),
            "response class {class} must be present even at zero"
        );
    }
    for kind in ["one_way_audio", "nat_mismatch", "no_media"] {
        assert!(
            body.contains(&format!(r#"sipnab_diagnosis_total{{type="{kind}"}}"#)),
            "diagnosis type {kind} must be present even at zero"
        );
    }
}

/// Recording a security alert moves the family the alert engine feeds, keyed
/// by the rule that fired.
#[test]
fn recording_a_security_alert_moves_the_family() {
    // A rule name no other test uses, so the delta is this test's alone.
    let kind = "metrics_counters_test_rule";
    let before = sipnab::security::alerts_by_type()
        .into_iter()
        .find(|(k, _)| k == kind)
        .map(|(_, v)| v)
        .unwrap_or(0);

    sipnab::security::record_alert(kind);

    let metrics = PrometheusMetrics::for_scrape();
    assert_eq!(
        metrics.security_alerts_total.get(kind).copied(),
        Some(before + 1),
        "the scrape must carry the recorded alert under its rule name"
    );
    let body = format_metrics(&metrics);
    assert!(
        body.contains(&format!(
            r#"sipnab_security_alerts_total{{type="{kind}"}} {}"#,
            before + 1
        )),
        "exposition should carry the recorded alert; body was:\n{body}"
    );
}
