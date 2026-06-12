//! The per-packet protocol-routing pipeline must be a testable library
//! API, not code buried in main.rs. These tests drive
//! `sipnab::pipeline::process_packet` directly: SIP packets land in the
//! dialog store, RTP/RTCP in the stream store, and the opt-out flags are
//! honored — without spawning the binary.
#![cfg(feature = "native")]

use chrono::Utc;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::pipeline::{self, PipelineOptions};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

fn parsed(payload: Vec<u8>, src_port: u16, dst_port: u16) -> ParsedPacket {
    ParsedPacket {
        timestamp: Utc::now(),
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port,
        dst_port,
        transport: TransportProto::Udp,
        payload,
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
    }
}

fn invite() -> Vec<u8> {
    b"INVITE sip:bob@example.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpipe\r\n\
      From: <sip:alice@example.com>;tag=p1\r\n\
      To: <sip:bob@example.com>\r\n\
      Call-ID: pipeline-1@test\r\n\
      CSeq: 1 INVITE\r\n\
      Content-Length: 0\r\n\r\n"
        .to_vec()
}

fn rtp_packet(ssrc: u32, seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1]);
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xaa; 160]);
    p
}

struct Harness {
    ds: Arc<RwLock<DialogStore>>,
    ss: Arc<RwLock<StreamStore>>,
    heuristic: RtpHeuristic,
}

impl Harness {
    fn new() -> Self {
        Self {
            ds: Arc::new(RwLock::new(DialogStore::new(100, false))),
            ss: Arc::new(RwLock::new(StreamStore::new(100))),
            heuristic: RtpHeuristic::new(),
        }
    }

    fn run(&mut self, pp: &ParsedPacket, opts: &PipelineOptions) {
        pipeline::process_packet(pp, &self.ds, &self.ss, &mut self.heuristic, opts);
    }
}

#[test]
fn sip_invite_lands_in_dialog_store() {
    let mut h = Harness::new();
    h.run(&parsed(invite(), 5060, 5060), &PipelineOptions::default());
    assert_eq!(h.ds.read().len(), 1, "INVITE must create a dialog");
    assert!(h.ds.read().get("pipeline-1@test").is_some());
    assert!(h.ss.read().is_empty(), "no RTP yet");
}

#[test]
fn rtp_lands_in_stream_store() {
    let mut h = Harness::new();
    h.run(
        &parsed(rtp_packet(0xABCD, 1), 20000, 30000),
        &PipelineOptions::default(),
    );
    assert_eq!(h.ss.read().len(), 1, "RTP must create a stream");
    assert!(h.ds.read().is_empty());
}

#[test]
fn no_rtp_option_skips_media() {
    let mut h = Harness::new();
    let opts = PipelineOptions {
        no_rtp: true,
        ..Default::default()
    };
    h.run(&parsed(rtp_packet(0xABCD, 1), 20000, 30000), &opts);
    assert!(h.ss.read().is_empty(), "no_rtp must skip RTP tracking");
}

#[test]
fn no_dialog_option_skips_sip_tracking() {
    let mut h = Harness::new();
    let opts = PipelineOptions {
        no_dialog: true,
        ..Default::default()
    };
    h.run(&parsed(invite(), 5060, 5060), &opts);
    assert!(
        h.ds.read().is_empty(),
        "no_dialog must skip dialog tracking"
    );
}

#[test]
fn port_in_range_is_inclusive_and_either_direction() {
    assert!(pipeline::port_in_range(5060, 9999, (5060, 5061)));
    assert!(pipeline::port_in_range(9999, 5061, (5060, 5061)));
    assert!(!pipeline::port_in_range(5059, 5062, (5060, 5061)));
    // Degenerate single-port range
    assert!(pipeline::port_in_range(5060, 1, (5060, 5060)));
}

#[test]
fn rtcp_detection_requires_odd_port_and_valid_header() {
    // Valid RTCP SR header (V=2, PT=200) on an odd port
    let rtcp = vec![0x80, 200, 0, 6, 0, 0, 0, 1];
    assert!(pipeline::is_rtcp_packet(&rtcp, 30001));
    assert!(
        !pipeline::is_rtcp_packet(&rtcp, 30000),
        "even dst port is RTP, not RTCP"
    );
    assert!(!pipeline::is_rtcp_packet(&[0x80, 200], 30001), "too short");
}
