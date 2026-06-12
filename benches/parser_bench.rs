use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// ── SIP parser benchmarks ──────────────────────────────────────────

fn bench_sip_parser(c: &mut Criterion) {
    let invite = build_sip_invite();
    let ok_200 = build_sip_200ok();

    let mut group = c.benchmark_group("sip_parser");
    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_invite", |b| {
        b.iter(|| {
            sipnab::sip::parser::parse_sip(
                &invite,
                chrono::Utc::now(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                5060,
                5060,
                sipnab::capture::parse::TransportProto::Udp,
            )
            .unwrap()
        })
    });

    group.bench_function("parse_200ok", |b| {
        b.iter(|| {
            sipnab::sip::parser::parse_sip(
                &ok_200,
                chrono::Utc::now(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                5060,
                5060,
                sipnab::capture::parse::TransportProto::Udp,
            )
            .unwrap()
        })
    });

    group.finish();
}

// ── SIP message size scaling ───────────────────────────────────────

fn bench_sip_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("sip_scaling");

    // Bench with varying numbers of Via headers to show scaling behavior
    for via_count in [1, 5, 10, 20] {
        let msg = build_sip_with_via_count(via_count);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("via_headers", via_count),
            &msg,
            |b, msg| {
                b.iter(|| {
                    sipnab::sip::parser::parse_sip(
                        msg,
                        chrono::Utc::now(),
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                        5060,
                        5060,
                        sipnab::capture::parse::TransportProto::Udp,
                    )
                    .unwrap()
                })
            },
        );
    }

    group.finish();
}

// ── RTP parser benchmarks ──────────────────────────────────────────

fn bench_rtp_parser(c: &mut Criterion) {
    let rtp = build_rtp_packet();

    let mut group = c.benchmark_group("rtp_parser");
    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_rtp_header", |b| {
        b.iter(|| sipnab::rtp::parser::parse_rtp_header(&rtp).unwrap())
    });

    group.finish();
}

// ── SDP parser benchmarks ──────────────────────────────────────────

fn bench_sdp_parser(c: &mut Criterion) {
    let sdp = SDP_BODY.as_bytes();

    let mut group = c.benchmark_group("sdp_parser");
    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_sdp", |b| {
        b.iter(|| sipnab::sip::sdp::parse_sdp(sdp).unwrap())
    });

    group.finish();
}

// ── Filter DSL benchmarks ──────────────────────────────────────────

fn bench_filter_dsl(c: &mut Criterion) {
    let mut group = c.benchmark_group("filter_dsl");

    group.bench_function("parse_complex_filter", |b| {
        b.iter(|| {
            sipnab::sip::dsl::FilterExpr::parse(
                "from.user =~ '100[0-9]' AND rtp.mos < 3.0 AND NOT state == 'Failed'",
            )
            .unwrap()
        })
    });

    group.finish();
}

// ── SIP/RTP detection benchmarks ───────────────────────────────────

fn bench_sip_detection(c: &mut Criterion) {
    let invite = build_sip_invite();
    let non_sip = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut group = c.benchmark_group("sip_detection");
    group.throughput(Throughput::Elements(1));

    group.bench_function("is_sip_message_true", |b| {
        b.iter(|| sipnab::sip::is_sip_message(&invite))
    });

    group.bench_function("is_sip_message_false", |b| {
        b.iter(|| sipnab::sip::is_sip_message(non_sip))
    });

    group.finish();
}

fn bench_rtp_detection(c: &mut Criterion) {
    let rtp = build_rtp_packet();
    let non_rtp = [0x00u8; 12]; // V=0, not RTP

    let mut group = c.benchmark_group("rtp_detection");
    group.throughput(Throughput::Elements(1));

    group.bench_function("is_rtp_packet_true", |b| {
        b.iter(|| sipnab::rtp::is_rtp_packet(&rtp))
    });

    group.bench_function("is_rtp_packet_false", |b| {
        b.iter(|| sipnab::rtp::is_rtp_packet(&non_rtp))
    });

    group.finish();
}

// ── Test data builders ─────────────────────────────────────────────

const SDP_BODY: &str = "\
v=0\r\n\
o=- 1234 5678 IN IP4 10.0.0.1\r\n\
s=SIP Call\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 20000 RTP/AVP 0 8 18 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:18 G729/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n";

fn build_sip_invite() -> Vec<u8> {
    format!(
        "INVITE sip:1002@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:1002@example.com>\r\n\
         From: \"Alice\" <sip:1001@example.com>;tag=1928301774\r\n\
         Call-ID: a84b4c76e66710@10.0.0.1\r\n\
         CSeq: 314159 INVITE\r\n\
         Contact: <sip:1001@10.0.0.1:5060>\r\n\
         User-Agent: sipnab-bench/1.0\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        SDP_BODY.len(),
        SDP_BODY
    )
    .into_bytes()
}

fn build_sip_200ok() -> Vec<u8> {
    b"SIP/2.0 200 OK\r\n\
      Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
      To: <sip:1002@example.com>;tag=9fxced76sl\r\n\
      From: \"Alice\" <sip:1001@example.com>;tag=1928301774\r\n\
      Call-ID: a84b4c76e66710@10.0.0.1\r\n\
      CSeq: 314159 INVITE\r\n\
      Contact: <sip:1002@10.0.0.2:5060>\r\n\
      Content-Length: 0\r\n\
      \r\n"
        .to_vec()
}

fn build_sip_with_via_count(count: usize) -> Vec<u8> {
    let mut msg = String::from("INVITE sip:1002@example.com SIP/2.0\r\n");
    for i in 0..count {
        msg.push_str(&format!(
            "Via: SIP/2.0/UDP proxy{i}.example.com:5060;branch=z9hG4bK{i:04}\r\n"
        ));
    }
    msg.push_str("Max-Forwards: 70\r\n");
    msg.push_str("To: <sip:1002@example.com>\r\n");
    msg.push_str("From: \"Alice\" <sip:1001@example.com>;tag=1928301774\r\n");
    msg.push_str("Call-ID: scaling-bench@10.0.0.1\r\n");
    msg.push_str("CSeq: 1 INVITE\r\n");
    msg.push_str("Content-Length: 0\r\n");
    msg.push_str("\r\n");
    msg.into_bytes()
}

fn build_rtp_packet() -> Vec<u8> {
    let mut pkt = vec![0u8; 172]; // 12-byte header + 160 bytes payload (G.711 20ms)
    pkt[0] = 0x80; // V=2, P=0, X=0, CC=0
    pkt[1] = 0x00; // M=0, PT=0 (PCMU)
    pkt[2] = 0x00;
    pkt[3] = 0x01; // seq=1
    // timestamp and SSRC can stay zero for the benchmark
    pkt
}

// ── Full decap chain (link → IP → UDP → payload extraction) ─────────

fn bench_packet_decap(c: &mut Criterion) {
    // Ethernet + IPv4 + UDP + a 160-byte payload: the per-packet path
    // every captured frame walks, including payload extraction into
    // ParsedPacket.
    let mut frame = vec![
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, // eth
    ];
    let ip: [u8; 20] = [
        0x45, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ];
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&[0x4e, 0x20, 0x75, 0x30, 0x00, 0xa8, 0x00, 0x00]); // udp 20000->30000
    frame.extend_from_slice(&[0xaa; 160]);

    let packet = sipnab::capture::Packet::new(
        chrono::Utc::now(),
        frame,
        202,
        202,
        None,
        1, // DLT_EN10MB
    );

    let mut group = c.benchmark_group("packet_decap");
    group.throughput(Throughput::Elements(1));
    group.bench_function("eth_ipv4_udp_160b", |b| {
        b.iter(|| sipnab::capture::parse::parse_packet(&packet).unwrap())
    });

    // Isolate the changed operation: refcounted slice vs heap copy of the
    // same 160-byte payload, measured in the same run (same noise floor).
    let data = bytes::Bytes::from(vec![0xaau8; 202]);
    group.bench_function("payload_slice_zero_copy", |b| {
        b.iter(|| data.slice(42..202))
    });
    group.bench_function("payload_copy_to_vec", |b| b.iter(|| data[42..202].to_vec()));
    group.finish();
}

criterion_group!(
    benches,
    bench_sip_parser,
    bench_sip_scaling,
    bench_rtp_parser,
    bench_sdp_parser,
    bench_filter_dsl,
    bench_sip_detection,
    bench_rtp_detection,
    bench_packet_decap,
);
criterion_main!(benches);
