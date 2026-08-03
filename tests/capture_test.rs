// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the capture subsystem.
//!
//! These tests exercise pcap file reading, packet count limits, BPF filtering,
//! and the pcap writer roundtrip. All tests use file-based capture (no root
//! privileges required).
#![cfg(feature = "native")]

use std::path::PathBuf;

use sipnab::capture::channel::packet_channel;
use sipnab::capture::file::capture_file;
use sipnab::capture::packet::Packet;
use sipnab::capture::parse::{TransportProto, parse_packet};
use sipnab::capture::writer::PcapWriter;
use sipnab::capture::{CaptureConfig, PacketProcessor, PcapExportMode};

/// Path to the test fixture pcap (`tests/fixtures/udp_5060.pcap`, 10 UDP
/// SIP packets on port 5060).
///
/// # Returns
/// Absolute path rooted at `CARGO_MANIFEST_DIR`.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("udp_5060.pcap")
}

/// Runs `capture_file` on the fixture pcap with the given config and drains
/// every captured packet from the channel.
///
/// # Arguments
/// * `config` — capture options (count limit, BPF filter, …) to apply.
///
/// # Returns
/// All packets the capture emitted, in file order.
fn collect_packets(config: CaptureConfig) -> Vec<Packet> {
    let (tx, rx) = packet_channel(1 << 20);
    capture_file(&fixture_path(), &config, tx, None).expect("capture_file should succeed");
    rx.try_iter().collect()
}

// ── Reading ────────────────────────────────────────────────────────────

/// A default (unfiltered, unlimited) file capture yields all 10 fixture packets.
#[test]
fn read_fixture_all_packets() {
    let packets = collect_packets(CaptureConfig::default());
    assert_eq!(packets.len(), 10, "Fixture contains exactly 10 packets");
}

/// Every captured packet has non-empty data, positive caplen/origlen with no
/// truncation, the source file it was read from, and link type DLT_EN10MB.
#[test]
fn packets_have_valid_metadata() {
    let packets = collect_packets(CaptureConfig::default());
    let source = fixture_path().display().to_string();
    for pkt in &packets {
        assert!(!pkt.data.is_empty(), "Packet data must not be empty");
        assert!(pkt.caplen > 0, "caplen must be positive");
        assert!(pkt.origlen > 0, "origlen must be positive");
        assert_eq!(pkt.caplen, pkt.origlen, "Fixture packets are not truncated");
        // A replayed packet names the file it came from. Downstream — the
        // pcapng export above all — this is the only thing that tells the
        // members of a multi-file input set apart.
        assert_eq!(
            pkt.interface.as_deref(),
            Some(source.as_str()),
            "a file capture stamps its source file"
        );
        assert_eq!(pkt.link_type, 1, "Fixture uses DLT_EN10MB (1)");
    }
}

// ── Count limit ────────────────────────────────────────────────────────

/// `count: Some(5)` stops the capture after exactly 5 of the 10 packets.
#[test]
fn count_limit_stops_early() {
    let config = CaptureConfig {
        count: Some(5),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 5, "Should stop after exactly 5 packets");
}

/// The boundary case `count: Some(1)` yields exactly one packet.
#[test]
fn count_limit_one() {
    let config = CaptureConfig {
        count: Some(1),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 1);
}

/// A count limit larger than the file (100 > 10) yields all packets without error.
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

/// The BPF filter `udp port 5060` matches all 10 fixture packets.
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

/// A non-matching BPF filter (`tcp port 80`) yields zero packets.
#[test]
fn bpf_filter_no_match() {
    let config = CaptureConfig {
        bpf_filter: Some("tcp port 80".to_string()),
        ..Default::default()
    };
    let packets = collect_packets(config);
    assert_eq!(packets.len(), 0, "No packets should match 'tcp port 80'");
}

/// BPF filter and count limit compose: matching filter plus `count: 3` yields
/// exactly 3 packets.
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

// ── Immediate mode / ring format (CT7) ─────────────────────────────────

/// The library default keeps immediate mode, i.e. exactly what every capture
/// asked for before the setting existed. Only `app::bootstrap`, which knows
/// whether a human is watching, turns it off — an embedder building a
/// `CaptureConfig::default()` must not have its ring format changed under it.
#[test]
fn default_config_keeps_immediate_mode() {
    assert!(CaptureConfig::default().immediate_mode);
}

/// Immediate mode is a live-device concern: it decides the kernel ring format
/// (TPACKET_V2 vs V3), and a file has no ring. Reading the fixture with the
/// flag off must therefore be byte-identical to reading it with the flag on —
/// proving the new field cannot disturb offline analysis.
#[test]
fn immediate_mode_does_not_affect_file_capture() {
    let batched = collect_packets(CaptureConfig {
        immediate_mode: false,
        ..Default::default()
    });
    let interactive = collect_packets(CaptureConfig {
        immediate_mode: true,
        ..Default::default()
    });
    assert_eq!(batched.len(), 10, "the fixture still reads in full");
    assert_eq!(batched.len(), interactive.len());
    for (b, i) in batched.iter().zip(interactive.iter()) {
        assert_eq!(b.data, i.data, "file capture must ignore immediate mode");
        assert_eq!(b.timestamp, i.timestamp);
    }
}

// ── Writer roundtrip ───────────────────────────────────────────────────

/// Writing all fixture packets with `PcapWriter` and re-reading the file
/// preserves packet count, data bytes, caplen, and origlen.
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
    let (tx, rx) = packet_channel(1 << 20);
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

/// Writing a count-limited capture (5 packets) produces a file that re-reads
/// as exactly 5 packets.
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
    let (tx, rx) = packet_channel(1 << 20);
    capture_file(&output_path, &CaptureConfig::default(), tx, None).expect("re-read");
    let reread: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(
        reread.len(),
        5,
        "Written file should have exactly 5 packets"
    );
}

// ── format roundtrip (M2 — T2.6) ─────────────────────────────────────────

/// Reads the first `n` bytes of a file (for magic-number assertions).
///
/// # Arguments
/// * `path` — file to inspect.
/// * `n` — number of leading bytes to return; panics if the file is shorter.
///
/// # Returns
/// The first `n` bytes.
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

    let (tx, rx) = packet_channel(1 << 20);
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

    let (tx, rx) = packet_channel(1 << 20);
    capture_file(&output_path, &CaptureConfig::default(), tx, None).expect("re-read pcapng");
    let reread: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(
        reread.len(),
        packets.len(),
        "pcapng roundtrip must preserve packet count"
    );
}

// ── start_capture integration ──────────────────────────────────────────

/// `start_capture` with a `CaptureSource::File` spawns a thread that reads the
/// fixture to completion and delivers all 10 packets over the channel.
#[test]
fn start_capture_file_source() {
    use sipnab::capture::{CaptureSource, start_capture};

    let (tx, rx) = packet_channel(1 << 20);
    let source = CaptureSource::File {
        paths: vec![fixture_path()],
    };
    let handle = start_capture(source, CaptureConfig::default(), tx, None).expect("start_capture");

    // Wait for the thread to finish
    handle.thread.join().expect("join").expect("capture result");

    let packets: Vec<Packet> = rx.try_iter().collect();
    assert_eq!(packets.len(), 10);
}

// ── Packet parsing integration ────────────────────────────────────────

/// `parse_packet` on every fixture packet yields UDP 5060→5060 from 10.0.0.1
/// with a non-empty payload containing `SIP/2.0`.
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

/// `PacketProcessor::process` passes all 10 UDP fixture packets straight
/// through (no reassembly buffering), each parsed as UDP port 5060.
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
