// SPDX-License-Identifier: MIT OR Apache-2.0

//! The standalone `--metrics` server must publish the same wired counters as
//! the REST API's `/metrics`.
//!
//! Both surfaces build their exposition from `PrometheusMetrics`, and both
//! used to start from `Default` — so both published `sipnab_capture_packets_total 0`
//! against a running capture and dropped the labelled families entirely. The
//! REST API side is covered in `metrics_wiring_test.rs`; this drives the
//! standalone server, which has no HTTP framework and a separate collector.
#![cfg(feature = "metrics")]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use sipnab::capture::{Packet, PacketProcessor};
use sipnab::output::prometheus_server::start_metrics_server;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// A free loopback address: bind to port 0, read the assignment, release it.
///
/// # Returns
/// An address the metrics server can claim.
fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local addr")
}

/// Issue one raw HTTP/1.1 request and read the response to EOF.
///
/// # Arguments
/// * `addr` — the metrics server's address.
/// * `raw` — the full request text.
///
/// # Returns
/// The response, status line and headers included.
fn http_request(addr: SocketAddr, raw: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream.write_all(raw.as_bytes()).expect("write request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    resp
}

/// Parse one SIP message and fold it into `store`.
///
/// # Arguments
/// * `store` — the dialog store to populate.
/// * `raw` — the message bytes.
fn feed(store: &mut DialogStore, raw: &'static [u8]) {
    let data = bytes::Bytes::from_static(raw);
    let msg = sipnab::sip::parser::parse_sip_bytes(
        &data,
        chrono::Utc::now(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect("fixture message parses");
    store.process_message(msg);
}

/// One INVITE answered by a `200 OK` — a dialog with a 2xx response in it.
///
/// # Returns
/// A shared dialog store holding that dialog.
fn answered_call() -> Arc<RwLock<DialogStore>> {
    let mut ds = DialogStore::new(100, false);
    feed(
        &mut ds,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\
          From: Alice <sip:alice@example.com>;tag=a1\r\n\
          To: Bob <sip:bob@example.com>\r\n\
          Call-ID: metrics-scrape-1@example.com\r\n\
          CSeq: 1 INVITE\r\n\
          Max-Forwards: 70\r\n\
          Contact: <sip:alice@10.0.0.1:5060>\r\n\
          Content-Length: 0\r\n\r\n",
    );
    feed(
        &mut ds,
        b"SIP/2.0 200 OK\r\n\
          Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\
          From: Alice <sip:alice@example.com>;tag=a1\r\n\
          To: Bob <sip:bob@example.com>;tag=b1\r\n\
          Call-ID: metrics-scrape-1@example.com\r\n\
          CSeq: 1 INVITE\r\n\
          Contact: <sip:bob@10.0.0.2:5060>\r\n\
          Content-Length: 0\r\n\r\n",
    );
    Arc::new(RwLock::new(ds))
}

/// The standalone server's scrape carries the live capture counter and the
/// zero-initialized label sets, not the zeros of a `Default` collector.
#[test]
fn standalone_scrape_publishes_wired_counters() {
    // Move the process-wide capture counter, exactly as a capture would.
    let mut processor = PacketProcessor::new();
    let packet = Packet::new(chrono::Utc::now(), vec![0x00; 14], 14, 14, None, 1);
    let _ = processor.process(&packet);

    let addr = free_addr();
    let _handle = start_metrics_server(
        addr,
        answered_call(),
        Arc::new(RwLock::new(StreamStore::new(100))),
        None,
        None,
        sipnab::output::prometheus_server::DEFAULT_MAX_CONCURRENT_CONNECTIONS,
    )
    .expect("metrics server binds");

    let resp = http_request(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp:?}");

    let packets = resp
        .lines()
        .find_map(|l| l.strip_prefix("sipnab_capture_packets_total "))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .expect("scrape must expose sipnab_capture_packets_total");
    assert!(
        packets > 0,
        "the standalone collector must read the live capture counter, got {packets}"
    );

    assert!(
        resp.contains(r#"sipnab_responses_total{code="2xx"} 1"#),
        "the answered call's 200 must be counted by class; body was:\n{resp}"
    );
    for class in ["1xx", "3xx", "4xx", "5xx", "6xx"] {
        assert!(
            resp.contains(&format!(r#"sipnab_responses_total{{code="{class}"}} 0"#)),
            "class {class} must be present at zero rather than absent"
        );
    }
    for kind in ["one_way_audio", "nat_mismatch", "no_media"] {
        assert!(
            resp.contains(&format!(r#"sipnab_diagnosis_total{{type="{kind}"}}"#)),
            "diagnosis type {kind} must be present even at zero"
        );
    }
}

/// The undecodable-frame series must be readable HERE, on the standalone
/// server, and not only on the REST API's `/metrics`.
///
/// This is the claim that has to be proved rather than assumed. This repo
/// already carries series that exist on one scrape surface and not the other
/// — `sipnab_rtp_streams_total{status}` is `--api` only, so a panel built on
/// it against `--metrics` stays permanently blank — and the docs page for
/// this feature states "both". A test that read the formatter instead of the
/// socket could not tell those apart.
///
/// The counter is process-global, so this asserts only that the series is
/// PRESENT and that the fraction is emitted even when nothing failed: another
/// test in this binary moves the same counter, and pinning an exact total
/// here would make the two order-dependent.
#[test]
fn standalone_scrape_publishes_the_undecodable_series() {
    // A link type with no decoder, driven through the real swallow site.
    let mut processor = PacketProcessor::new();
    let packet = Packet::new(chrono::Utc::now(), vec![0x00; 64], 64, 64, None, 147);
    let _ = processor.process(&packet);

    let addr = free_addr();
    let _handle = start_metrics_server(
        addr,
        answered_call(),
        Arc::new(RwLock::new(StreamStore::new(100))),
        None,
        None,
        sipnab::output::prometheus_server::DEFAULT_MAX_CONCURRENT_CONNECTIONS,
    )
    .expect("metrics server binds");

    let resp = http_request(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp:?}");

    let frames = resp
        .lines()
        .find_map(|l| {
            l.strip_prefix(
                r#"sipnab_capture_undecodable_frames_total{reason="unsupported_link_type_147"} "#,
            )
        })
        .and_then(|v| v.trim().parse::<u64>().ok())
        .expect("the standalone scrape must carry the per-reason series, with its DLT number");
    assert!(
        frames >= 1,
        "the reason series must count the frame this test fed, got {frames}"
    );

    assert!(
        resp.lines()
            .any(|l| l.starts_with("sipnab_capture_undecoded_fraction ")),
        "the fraction gauge must be on this surface too; body was:\n{resp}"
    );
}
