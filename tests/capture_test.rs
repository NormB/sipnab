//! Integration tests for the capture subsystem.
//!
//! These tests exercise pcap file reading, packet count limits, BPF filtering,
//! and the pcap writer roundtrip. All tests use file-based capture (no root
//! privileges required).
#![cfg(feature = "native")]

use std::path::PathBuf;

use crossbeam_channel::unbounded;
use sipnab::capture::file::capture_file;
use sipnab::capture::packet::Packet;
use sipnab::capture::parse::{TransportProto, parse_packet};
use sipnab::capture::writer::PcapWriter;
use sipnab::capture::{CaptureConfig, PacketProcessor, PcapExportMode};

/// Path to the test fixture pcap.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("udp_5060.pcap")
}

/// Collect all packets from a file capture with the given config.
fn collect_packets(config: CaptureConfig) -> Vec<Packet> {
    let (tx, rx) = unbounded();
    capture_file(&fixture_path(), &config, tx, None).expect("capture_file should succeed");
    rx.try_iter().collect()
}

// ── Reading ────────────────────────────────────────────────────────────

#[test]
fn read_fixture_all_packets() {
    let packets = collect_packets(CaptureConfig::default());
    assert_eq!(packets.len(), 10, "Fixture contains exactly 10 packets");
}

#[test]
fn packets_have_valid_metadata() {
    let packets = collect_packets(CaptureConfig::default());
    for pkt in &packets {
        assert!(!pkt.data.is_empty(), "Packet data must not be empty");
        assert!(pkt.caplen > 0, "caplen must be positive");
        assert!(pkt.origlen > 0, "origlen must be positive");
        assert_eq!(pkt.caplen, pkt.origlen, "Fixture packets are not truncated");
        assert!(pkt.interface.is_none(), "File captures have no interface");
        assert_eq!(pkt.link_type, 1, "Fixture uses DLT_EN10MB (1)");
    }
}

// ── Count limit ────────────────────────────────────────────────────────

#[test]
fn count_limit_stops_early() {
    let config = CaptureConfig {
        count: Some(5),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 5, "Should stop after exactly 5 packets");
}

#[test]
fn count_limit_one() {
    let config = CaptureConfig {
        count: Some(1),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 1);
}

#[test]
fn count_limit_exceeds_file() {
    let config = CaptureConfig {
        count: Some(100),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 10, "Count > file size yields all packets");
}

// ── BPF filter ─────────────────────────────────────────────────────────

#[test]
fn bpf_filter_udp_5060() {
    let config = CaptureConfig {
        bpf_filter: Some("udp port 5060".to_string()),
        ..Default::default()
    };
    let packets = collect_packets(config);
    // All 10 fixture packets are UDP port 5060
    assert_eq!(
        packets.len(),
        10,
        "All fixture packets match 'udp port 5060'"
    );
}

#[test]
fn bpf_filter_no_match() {
    let config = CaptureConfig {
        bpf_filter: Some("tcp port 80".to_string()),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 0, "No packets should match 'tcp port 80'");
}

#[test]
fn bpf_filter_with_count() {
    let config = CaptureConfig {
        bpf_filter: Some("udp port 5060".to_string()),
        count: Some(3),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 3, "Filter + count should give exactly 3");
}

// ── Writer roundtrip ───────────────────────────────────────────────────

#[test]
fn writer_roundtrip() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let output_path = dir.path().join("roundtrip.pcap");

    // Read all packets from fixture
    let packets = collect_packets(CaptureConfig::default());
    assert_eq!(packets.len(), 10);

    // Write them to a new file
    {
        let mut writer =
            PcapWriter::new(&output_path, packets[0].link_type, None, None).expect("create writer");
        for pkt in &packets {
            writer.write(pkt).expect("write packet");
        }
    }

    // Re-read the written file
    let (tx, rx) = unbounded();
    capture_file(&output_path, &CaptureConfig::default(), tx, None).expect("re-read");
    let reread: Vec<Packet> = rx.try_iter().collect();

    assert_eq!(
        reread.len(),
        packets.len(),
        "Roundtrip should preserve packet count"
    );

    // Verify data integrity
    for (orig, copy) in packets.iter().zip(reread.iter()) {
        assert_eq!(orig.data, copy.data, "Packet data must survive roundtrip");
        assert_eq!(orig.caplen, copy.caplen);
        assert_eq!(orig.origlen, copy.origlen);
    }
}

#[test]
fn writer_with_count_limit() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let output_path = dir.path().join("limited.pcap");

    // Read 5 packets
    let config = CaptureConfig {
        count: Some(5),
        ..Default::default()
    };
    let packets = collect_packets(config);

    // Write them
    {
        let mut writer =
            PcapWriter::new(&output_path, packets[0].link_type, None, None).expect("create writer");
        for pkt in &packets {
            writer.write(pkt).expect("write packet");
        }
    }

    // Re-read
    let (tx, rx) = unbounded();
    capture_file(&output_path, &CaptureConfig::default(), tx, None).expect("re-read");
    let reread: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(
        reread.len(),
        5,
        "Written file should have exactly 5 packets"
    );
}

// ── format roundtrip (M2 — T2.6) ─────────────────────────────────────────

/// Read the first `n` bytes of a file (for magic-number assertions).
fn read_magic(path: &std::path::Path, n: usize) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read output file");
    assert!(bytes.len() >= n, "file too short for magic check");
    bytes[..n].to_vec()
}

/// Classic pcap roundtrip must preserve the **link type** (not just the count):
/// a wrong linktype silently corrupts every reread packet's framing.
#[test]
fn pcap_roundtrip_preserves_linktype_and_magic() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let output_path = dir.path().join("rt.pcap");
    let packets = collect_packets(CaptureConfig::default());
    let src_link = packets[0].link_type;

    {
        let mut writer =
            PcapWriter::new(&output_path, src_link, None, None).expect("create writer");
        for pkt in &packets {
            writer.write(pkt).expect("write packet");
        }
    }

    // Classic pcap magic: micro/nano-second, little/big-endian variants.
    let magic = read_magic(&output_path, 4);
    let known = [
        [0xd4, 0xc3, 0xb2, 0xa1], // microsec LE
        [0xa1, 0xb2, 0xc3, 0xd4], // microsec BE
        [0x4d, 0x3c, 0xb2, 0xa1], // nanosec LE
        [0xa1, 0xb2, 0x3c, 0x4d], // nanosec BE
    ];
    assert!(
        known.iter().any(|m| m == magic.as_slice()),
        "unexpected pcap magic: {magic:02x?}"
    );

    let (tx, rx) = unbounded();
    capture_file(&output_path, &CaptureConfig::default(), tx, None).expect("re-read");
    let reread: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(reread.len(), packets.len(), "count must survive roundtrip");
    for pkt in &reread {
        assert_eq!(pkt.link_type, src_link, "link type must survive roundtrip");
    }
}

/// PCAP-NG output must carry the Section Header Block magic and roundtrip.
#[test]
fn pcapng_roundtrip_and_magic() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let output_path = dir.path().join("rt.pcapng");
    let packets = collect_packets(CaptureConfig::default());
    let src_link = packets[0].link_type;

    {
        let mut writer = PcapWriter::with_format(
            &output_path,
            src_link,
            None,
            None,
            true, // pcapng
            PcapExportMode::Decrypted,
        )
        .expect("create pcapng writer");
        for pkt in &packets {
            writer.write(pkt).expect("write packet");
        }
    }

    // pcapng begins with a Section Header Block: type 0x0A0D0D0A.
    assert_eq!(
        read_magic(&output_path, 4),
        vec![0x0a, 0x0d, 0x0d, 0x0a],
        "pcapng Section Header Block magic missing"
    );

    let (tx, rx) = unbounded();
    capture_file(&output_path, &CaptureConfig::default(), tx, None).expect("re-read pcapng");
    let reread: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(
        reread.len(),
        packets.len(),
        "pcapng roundtrip must preserve packet count"
    );
}

// ── start_capture integration ──────────────────────────────────────────

#[test]
fn start_capture_file_source() {
    use sipnab::capture::{CaptureSource, start_capture};

    let (tx, rx) = unbounded();
    let source = CaptureSource::File {
        path: fixture_path(),
    };
    let handle = start_capture(source, CaptureConfig::default(), tx, None).expect("start_capture");

    // Wait for the thread to finish
    handle.thread.join().expect("join").expect("capture result");

    let packets: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(packets.len(), 10);
}

// ── Packet parsing integration ────────────────────────────────────────

#[test]
fn fixture_packets_parse_to_valid_udp() {
    let packets = collect_packets(CaptureConfig::default());
    assert_eq!(packets.len(), 10);

    for (i, pkt) in packets.iter().enumerate() {
        let parsed =
            parse_packet(pkt).unwrap_or_else(|e| panic!("Packet {i} failed to parse: {e}"));

        // All fixture packets are UDP on port 5060
        assert_eq!(
            parsed.transport,
            TransportProto::Udp,
            "Packet {i} should be UDP"
        );
        assert_eq!(parsed.src_port, 5060, "Packet {i} src_port");
        assert_eq!(parsed.dst_port, 5060, "Packet {i} dst_port");

        // Source IP should be 10.0.0.1 (from the gen_fixture tool)
        assert_eq!(
            parsed.src_addr,
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap(),
            "Packet {i} src_addr"
        );

        // Payload should be non-empty and contain SIP-like content
        assert!(!parsed.payload.is_empty(), "Packet {i} payload empty");
        let payload_str = String::from_utf8_lossy(&parsed.payload);
        assert!(
            payload_str.contains("SIP/2.0"),
            "Packet {i} payload should contain SIP content, got: {payload_str}"
        );
    }
}

#[test]
fn packet_processor_handles_fixture() {
    let packets = collect_packets(CaptureConfig::default());
    let mut processor = PacketProcessor::new();
    let mut parsed_total = 0;

    for pkt in &packets {
        let results = processor.process(pkt);
        for pp in &results {
            assert_eq!(pp.transport, TransportProto::Udp);
            assert_eq!(pp.src_port, 5060);
            assert!(!pp.payload.is_empty());
        }
        parsed_total += results.len();
    }

    assert_eq!(
        parsed_total, 10,
        "All 10 UDP packets should pass through processor immediately"
    );
}

/// Zero-copy contract: a parsed packet's payload must be a VIEW into the
/// captured frame's buffer (refcounted slice), not a fresh allocation —
/// per-packet payload copies were the top hot-path cost.
#[test]
fn parsed_payload_shares_packet_buffer() {
    // Ethernet + IPv4 + UDP + 160-byte payload
    let mut frame = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ]);
    frame.extend_from_slice(&[0x4e, 0x20, 0x75, 0x30, 0x00, 0xa8, 0x00, 0x00]);
    frame.extend_from_slice(&[0xaa; 160]);

    let packet = Packet::new(chrono::Utc::now(), frame, 202, 202, None, 1);
    let pp = parse_packet(&packet).expect("frame parses");

    assert_eq!(pp.payload.len(), 160);
    let buf = packet.data.as_ptr_range();
    assert!(
        buf.contains(&pp.payload.as_ptr()),
        "payload must point into the packet buffer (zero-copy), not a new allocation"
    );
}
