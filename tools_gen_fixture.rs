//! One-shot binary to generate test fixture pcap files.
//!
//! Run with: cargo run --bin gen_fixture
//! Creates tests/fixtures/udp_5060.pcap and tests/fixtures/sip_call.pcap
//! with synthetic SIP packets suitable for integration testing.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let fixture_dir = std::path::PathBuf::from(&manifest_dir)
        .join("tests")
        .join("fixtures");
    std::fs::create_dir_all(&fixture_dir).expect("create fixtures dir");

    // Original fixture: 10 minimal 200 OK responses
    generate_udp_5060(&fixture_dir);

    // New fixture: realistic INVITE dialog with Call-ID/From/To
    generate_sip_call(&fixture_dir);
}

/// Generate the original minimal 200 OK fixture (backward compatible).
fn generate_udp_5060(fixture_dir: &std::path::Path) {
    let output_path = fixture_dir.join("udp_5060.pcap");
    let cap = pcap::Capture::dead(pcap::Linktype(1)).expect("dead capture");
    let mut savefile = cap.savefile(&output_path).expect("create savefile");

    for i in 0u8..10 {
        let payload = format!("SIP/2.0 200 OK\r\nSeq: {i}\r\n\r\n");
        let packet_data = build_udp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, i.wrapping_add(2)],
            5060,
            5060,
            payload.as_bytes(),
        );
        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: (1_700_000_000 + i as i64) as libc::time_t,
                tv_usec: 0 as libc::suseconds_t,
            },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };
        savefile.write(&pcap::Packet {
            header: &header,
            data: &packet_data,
        });
    }

    drop(savefile);
    println!("Wrote 10 packets to {}", output_path.display());
}

/// Generate a realistic SIP call fixture with INVITE, 100, 180, 200, ACK, BYE, 200.
fn generate_sip_call(fixture_dir: &std::path::Path) {
    let output_path = fixture_dir.join("sip_call.pcap");
    let cap = pcap::Capture::dead(pcap::Linktype(1)).expect("dead capture");
    let mut savefile = cap.savefile(&output_path).expect("create savefile");

    let call_id = "test-call-1@10.0.0.1";
    let src_ip = [10, 0, 0, 1];
    let dst_ip = [10, 0, 0, 2];
    let base_ts: i64 = 1_700_000_000;

    let messages: Vec<(i64, [u8; 4], [u8; 4], String)> = vec![
        // 0: INVITE (caller -> callee)
        (
            0,
            src_ip,
            dst_ip,
            format!(
                "INVITE sip:1002@10.0.0.2 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
                 Max-Forwards: 70\r\n\
                 To: <sip:1002@10.0.0.2>\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 INVITE\r\n\
                 Contact: <sip:1001@10.0.0.1:5060>\r\n\
                 User-Agent: sipnab-test/1.0\r\n\
                 Content-Type: application/sdp\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        // 1: 100 Trying (callee -> caller)
        (
            100,
            dst_ip,
            src_ip,
            format!(
                "SIP/2.0 100 Trying\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
                 To: <sip:1002@10.0.0.2>\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 INVITE\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        // 2: 180 Ringing (callee -> caller)
        (
            500,
            dst_ip,
            src_ip,
            format!(
                "SIP/2.0 180 Ringing\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
                 To: <sip:1002@10.0.0.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 INVITE\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        // 3: 200 OK (callee -> caller)
        (
            2000,
            dst_ip,
            src_ip,
            format!(
                "SIP/2.0 200 OK\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
                 To: <sip:1002@10.0.0.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 INVITE\r\n\
                 Contact: <sip:1002@10.0.0.2:5060>\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        // 4: ACK (caller -> callee)
        (
            2050,
            src_ip,
            dst_ip,
            format!(
                "ACK sip:1002@10.0.0.2 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdack\r\n\
                 Max-Forwards: 70\r\n\
                 To: <sip:1002@10.0.0.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 ACK\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        // 5: BYE (caller -> callee)
        (
            60_000,
            src_ip,
            dst_ip,
            format!(
                "BYE sip:1002@10.0.0.2 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdbye\r\n\
                 Max-Forwards: 70\r\n\
                 To: <sip:1002@10.0.0.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 2 BYE\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        // 6: 200 OK to BYE (callee -> caller)
        (
            60_100,
            dst_ip,
            src_ip,
            format!(
                "SIP/2.0 200 OK\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdbye\r\n\
                 To: <sip:1002@10.0.0.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@10.0.0.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 2 BYE\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
    ];

    for (offset_ms, src, dst, payload) in &messages {
        let packet_data = build_udp_packet(*src, *dst, 5060, 5060, payload.as_bytes());
        let secs = base_ts + offset_ms / 1000;
        let usecs = (offset_ms % 1000) * 1000;
        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: secs as libc::time_t,
                tv_usec: usecs as libc::suseconds_t,
            },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };
        savefile.write(&pcap::Packet {
            header: &header,
            data: &packet_data,
        });
    }

    drop(savefile);
    println!(
        "Wrote {} packets to {}",
        messages.len(),
        output_path.display()
    );
}

/// Build a minimal Ethernet + IPv4 + UDP packet.
fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len: u16 = 8 + payload.len() as u16;
    let ip_total_len: u16 = 20 + udp_len;

    let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes, no options)
    pkt.push(0x45); // version + IHL
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset (DF)
    pkt.push(64); // TTL
    pkt.push(17); // protocol: UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // UDP header (8 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)

    // Payload
    pkt.extend_from_slice(payload);

    pkt
}
