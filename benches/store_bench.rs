//! Throughput benchmarks for the per-packet store layer
//! (`DialogStore`, `StreamStore`).
//!
//! The parser benchmarks cover the parse half of the hot path; these
//! cover the store half, so that store optimizations (lock scope,
//! lookup allocation, eviction cost, RTCP indexing) are measurable
//! instead of asserted. Baselines and deltas belong in the PR
//! descriptions of changes touching these paths.

use chrono::Utc;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::net::{IpAddr, Ipv4Addr};

use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::rtp::parser::parse_rtp_header;
use sipnab::rtp::rtcp::{ReceiverReport, ReceptionReport, RtcpPacket};
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::SipMessage;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::parser::parse_sip;

// ── Constructors (mirror tests/resource_bounds_test.rs) ─────────────

fn invite_bytes(call_id: &str, cseq: u32) -> Vec<u8> {
    format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}-{cseq}\r\n\
         From: <sip:alice@example.com>;tag=a{call_id}\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {call_id}@10.0.0.1\r\n\
         CSeq: {cseq} INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn parse_invite(call_id: &str, cseq: u32) -> SipMessage {
    parse_sip(
        &invite_bytes(call_id, cseq),
        Utc::now(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("crafted INVITE must parse")
}

fn rtp_packet(ssrc: u32, seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00]; // V=2, PT=0 (G.711 PCMU)
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1]); // timestamp
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xaa; 160]); // 20ms G.711 frame
    p
}

fn parsed_for(ssrc: u32, payload: Vec<u8>) -> ParsedPacket {
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

// ── DialogStore ──────────────────────────────────────────────────────

fn bench_dialog_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("dialog_store");
    group.throughput(Throughput::Elements(1));

    // Hot path: message for an EXISTING dialog (the common case during a
    // call). Exercises the Call-ID lookup; today that allocates a String
    // per message before the IndexMap probe.
    group.bench_function("message_existing_dialog", |b| {
        let mut store = DialogStore::new(10_000, true);
        store.process_message(parse_invite("bench-hot", 1));
        let mut cseq = 1u32;
        b.iter_batched(
            || {
                cseq += 1;
                parse_invite("bench-hot", cseq)
            },
            |msg| store.process_message(msg),
            BatchSize::SmallInput,
        );
    });

    // Eviction path: store saturated at the cap with rotate=true, every
    // new Call-ID evicts the oldest dialog. Today eviction is
    // shift_remove_index(0): O(n) element moves per eviction.
    group.bench_function("new_dialog_at_cap_10k_rotate", |b| {
        let mut store = DialogStore::new(10_000, true);
        for i in 0..10_000 {
            store.process_message(parse_invite(&format!("warm-{i}"), 1));
        }
        let mut n = 0u64;
        b.iter_batched(
            || {
                n += 1;
                parse_invite(&format!("evict-{n}"), 1)
            },
            |msg| store.process_message(msg),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── StreamStore ──────────────────────────────────────────────────────

fn bench_stream_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_store");
    group.throughput(Throughput::Elements(1));

    // Hot path: RTP packet for an EXISTING stream (50 pps per call leg —
    // by far the highest-frequency store operation in the pipeline).
    group.bench_function("rtp_existing_stream", |b| {
        let mut store = StreamStore::new(10_000);
        let pkt = rtp_packet(0x1111, 0);
        let parsed = parsed_for(0x1111, pkt.clone());
        let hdr = parse_rtp_header(&pkt).expect("rtp parses");
        store.process_rtp(&parsed, &hdr, parsed.timestamp);
        let mut seq = 0u16;
        b.iter(|| {
            seq = seq.wrapping_add(1);
            let pkt = rtp_packet(0x1111, seq);
            let hdr = parse_rtp_header(&pkt).expect("rtp parses");
            store.process_rtp(&parsed, &hdr, parsed.timestamp);
        });
    });

    // RTCP report matching against a store with 1000 active streams.
    // Today this is a linear scan over all streams per report block;
    // worst case is a report for the most-recently-inserted SSRC.
    group.bench_function("rtcp_match_1000_streams", |b| {
        let mut store = StreamStore::new(10_000);
        for i in 0..1000u32 {
            let pkt = rtp_packet(i, 0);
            let parsed = parsed_for(i, pkt.clone());
            let hdr = parse_rtp_header(&pkt).expect("rtp parses");
            store.process_rtp(&parsed, &hdr, parsed.timestamp);
        }
        let rtcp = vec![RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 0xfeed,
            reports: vec![ReceptionReport {
                ssrc: 999, // last-inserted stream: worst case for the scan
                fraction_lost: 0,
                cumulative_lost: 7,
                highest_seq: 100,
                jitter: 42,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        })];
        b.iter(|| store.process_rtcp(&rtcp));
    });

    group.finish();
}

criterion_group!(benches, bench_dialog_store, bench_stream_store);
criterion_main!(benches);
