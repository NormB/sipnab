// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end pipeline benchmarks: `PacketProcessor::process` (the full
//! link → IP → transport decap every captured frame walks, including the
//! per-packet `Vec` return) and parse → `DialogStore::process_message`
//! (with explicit clone-then-insert vs move-insert variants quantifying
//! the batch-path clone).

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use sipnab::capture::{Packet, PacketProcessor};
use sipnab::sip::dialog_store::DialogStore;

// ── Frame builders ─────────────────────────────────────────────────

/// Ethernet + IPv4 + UDP frame carrying `payload` between the given ports.
fn build_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, // eth
    ];
    let total_len = (20 + 8 + payload.len()) as u16;
    let mut ip: [u8; 20] = [
        0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ];
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&ip);
    let udp_len = (8 + payload.len()) as u16;
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (unverified)
    frame.extend_from_slice(payload);
    frame
}

/// Ethernet + IPv4 + TCP (PSH|ACK, seq 1) frame carrying `payload`.
fn build_tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, // eth
    ];
    let total_len = (20 + 20 + payload.len()) as u16;
    let mut ip: [u8; 20] = [
        0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ];
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&ip);
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes()); // seq
    tcp[12] = 0x50; // data offset 5
    tcp[13] = 0x18; // PSH|ACK
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
    frame.extend_from_slice(&tcp);
    frame.extend_from_slice(payload);
    frame
}

fn build_rtp_payload() -> Vec<u8> {
    let mut pkt = vec![0u8; 172]; // 12-byte header + 160 bytes G.711 20ms
    pkt[0] = 0x80; // V=2
    pkt[1] = 0x00; // PT=0 (PCMU)
    pkt[3] = 0x01; // seq=1
    pkt
}

fn build_sip_invite(call_id: &str) -> Vec<u8> {
    format!(
        "INVITE sip:1002@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:1002@example.com>\r\n\
         From: \"Alice\" <sip:1001@example.com>;tag=1928301774\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 314159 INVITE\r\n\
         Contact: <sip:1001@10.0.0.1:5060>\r\n\
         User-Agent: sipnab-bench/1.0\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
    .into_bytes()
}

fn make_packet(frame: Vec<u8>) -> Packet {
    let len = frame.len();
    Packet::new(fixed_ts(), frame, len, len, None, 1 /* DLT_EN10MB */)
}

fn fixed_ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
}

// ── PacketProcessor::process end-to-end ────────────────────────────

fn bench_packet_process(c: &mut Criterion) {
    let udp_rtp = make_packet(build_udp_frame(20000, 30000, &build_rtp_payload()));
    let udp_sip = make_packet(build_udp_frame(
        5060,
        5060,
        &build_sip_invite("bench@10.0.0.1"),
    ));
    let tcp_sip = make_packet(build_tcp_frame(
        5060,
        5060,
        &build_sip_invite("bench@10.0.0.1"),
    ));

    let mut group = c.benchmark_group("packet_process");
    group.throughput(Throughput::Elements(1));

    // UDP is stateless in the processor: one long-lived processor, hot loop.
    let mut processor = PacketProcessor::new();
    group.bench_function("udp_rtp_160b", |b| b.iter(|| processor.process(&udp_rtp)));
    group.bench_function("udp_sip_invite", |b| b.iter(|| processor.process(&udp_sip)));

    // TCP goes through per-flow reassembly state; a fresh processor per
    // iteration (setup excluded from timing) measures session-create +
    // single-segment framing rather than the retransmission-dedup path
    // that reprocessing one segment forever would hit.
    group.bench_function("tcp_sip_single_segment", |b| {
        b.iter_batched(
            PacketProcessor::new,
            |mut p| {
                let out = p.process(&tcp_sip);
                (out, p) // drop outside the timed region
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ── parse → DialogStore::process_message ───────────────────────────

fn bench_msg_pipeline(c: &mut Criterion) {
    let invite: bytes::Bytes = build_sip_invite("bench@10.0.0.1").into();
    let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
    let ts = fixed_ts();
    let parsed = sipnab::sip::parser::parse_sip_bytes(
        &invite,
        ts,
        src,
        dst,
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect("bench INVITE parses");

    let mut group = c.benchmark_group("msg_pipeline");
    group.throughput(Throughput::Elements(1));

    // Full per-message cost: parse + insert into a store (fresh store per
    // iteration, excluded from timing; returned so drop is untimed too).
    group.bench_function("parse_and_insert", |b| {
        b.iter_batched(
            || DialogStore::new(64, false),
            |mut ds| {
                let msg = sipnab::sip::parser::parse_sip_bytes(
                    &invite,
                    ts,
                    src,
                    dst,
                    5060,
                    5060,
                    sipnab::capture::parse::TransportProto::Udp,
                )
                .expect("bench INVITE parses");
                ds.process_message(msg);
                ds
            },
            BatchSize::SmallInput,
        )
    });

    // Isolate the batch-path clone: identical insert, with vs without a
    // deep clone of the parsed message. The delta is the per-SIP-message
    // cost the batch/--jobs paths pay(paid) at main.rs/parallel.rs.
    group.bench_function("insert_move", |b| {
        b.iter_batched(
            || (DialogStore::new(64, false), parsed.clone()),
            |(mut ds, msg)| {
                ds.process_message(msg);
                ds
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("insert_clone", |b| {
        b.iter_batched(
            || (DialogStore::new(64, false), parsed.clone()),
            |(mut ds, msg)| {
                ds.process_message(msg.clone());
                (ds, msg)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_packet_process, bench_msg_pipeline);
criterion_main!(benches);
