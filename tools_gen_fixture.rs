//! One-shot binary to generate the test fixture pcap file.
//!
//! Run with: cargo run --bin gen_fixture
//! Creates tests/fixtures/udp_5060.pcap with 10 synthetic UDP packets on port 5060.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let fixture_dir = std::path::PathBuf::from(&manifest_dir)
        .join("tests")
        .join("fixtures");
    std::fs::create_dir_all(&fixture_dir).expect("create fixtures dir");

    let output_path = fixture_dir.join("udp_5060.pcap");

    // Create a dead capture with Ethernet link type (DLT_EN10MB = 1)
    let cap = pcap::Capture::dead(pcap::Linktype(1)).expect("dead capture");
    let mut savefile = cap.savefile(&output_path).expect("create savefile");

    // Generate 10 synthetic Ethernet/IP/UDP packets on port 5060
    for i in 0u8..10 {
        let packet_data = build_udp_packet(i);
        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: (1700000000 + i as i64) as libc::time_t,
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

/// Build a minimal Ethernet + IPv4 + UDP packet targeting port 5060.
fn build_udp_packet(seq: u8) -> Vec<u8> {
    let payload = format!("SIP/2.0 200 OK\r\nSeq: {seq}\r\n\r\n");
    let payload_bytes = payload.as_bytes();

    let udp_len: u16 = 8 + payload_bytes.len() as u16;
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
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
    pkt.extend_from_slice(&[10, 0, 0, seq.wrapping_add(2)]); // dst IP

    // UDP header (8 bytes)
    pkt.extend_from_slice(&5060u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&5060u16.to_be_bytes()); // dst port
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)

    // Payload
    pkt.extend_from_slice(payload_bytes);

    pkt
}
