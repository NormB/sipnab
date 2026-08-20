//! A merged pcapng — interfaces that disagree — must still be readable.
//!
//! `mergecap`, and any capture spanning interfaces with different snaplens or
//! link types, produces a file libpcap refuses outright. Measured against a
//! real one (The Ultimate PCAP, 313 interface description blocks): libpcap
//! rejects first on snaplen —
//!
//! ```text
//! an interface has a snapshot length 8192 different from the snapshot length
//! of the first interface
//! ```
//!
//! and then, once every snaplen is normalised to one value, on link type:
//!
//! ```text
//! an interface has a type 274 different from the type of the first interface
//! ```
//!
//! Per-packet encapsulation is the *point* of a merged capture, so no
//! normalisation makes libpcap read one. The fix is a reader that takes the
//! link type from each packet's own interface, which the parser already
//! supports: `Packet::from_bytes` has always taken `link_type` per packet, and
//! only the readers treated it as one value for a whole file.
//!
//! The fixture is built here rather than taken from the corpus. The corpus is
//! never committed, so a test that depended on one would prove nothing in CI.
#![cfg(feature = "native")]

use std::path::Path;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// Read `path` headlessly and return combined output.
fn read_capture(path: &Path) -> (String, String, Option<i32>) {
    run_support::run(
        &[
            "-N",
            "-I",
            path.to_str().unwrap(),
            "--portrange",
            "1-65535",
            "--no-cli-print",
            "--report",
        ],
        Some("info"),
    )
}

/// Both interfaces' packets must be read, not just the first interface's.
///
/// Interface 0 is Ethernet at snaplen 65535; interface 1 is raw IP at snaplen
/// 2048. Each carries one SIP message, and a run that reads only one of them
/// has silently discarded half the capture.
#[test]
fn a_merged_pcapng_yields_packets_from_every_interface() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("merged.pcapng");

    let eth = pcap_build::udp_frame(
        [10, 1, 0, 1],
        [10, 2, 0, 1],
        5060,
        5060,
        b"OPTIONS sip:eth@example.net SIP/2.0\r\nCall-ID: merged-eth\r\n\
          CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    );
    let raw = pcap_build::strip_ethernet(&pcap_build::udp_frame(
        [10, 3, 0, 1],
        [10, 4, 0, 1],
        5060,
        5060,
        b"OPTIONS sip:raw@example.net SIP/2.0\r\nCall-ID: merged-raw\r\n\
          CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    ));

    pcap_build::write_pcapng_multi_iface(&path, &[(0, eth), (1, raw)]);

    let (stdout, stderr, code) = read_capture(&path);
    let all = format!("{stdout}{stderr}");

    assert_eq!(
        code,
        Some(0),
        "a merged pcapng must be readable, not refused at open:\n{all}"
    );
    assert!(
        all.contains("merged-eth"),
        "the Ethernet interface's SIP must be read:\n{all}"
    );
    assert!(
        all.contains("merged-raw"),
        "the raw-IP interface's SIP must be read too — reading only the first \
         interface silently discards the rest of the capture:\n{all}"
    );
}

/// A single-interface pcapng must keep working exactly as before.
///
/// The negative control for the change: adding a reader for the awkward case
/// must not alter the ordinary one, which is the overwhelming majority of
/// captures.
#[test]
fn an_ordinary_single_interface_capture_still_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.pcap");

    let frame = pcap_build::udp_frame(
        [10, 1, 0, 1],
        [10, 2, 0, 1],
        5060,
        5060,
        b"OPTIONS sip:plain@example.net SIP/2.0\r\nCall-ID: plain-one\r\n\
          CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    );
    pcap_build::write_pcap(&path, &[frame]);

    let (stdout, stderr, code) = read_capture(&path);
    let all = format!("{stdout}{stderr}");
    assert_eq!(code, Some(0), "an ordinary capture must still read:\n{all}");
    assert!(
        all.contains("plain-one"),
        "the ordinary path must be untouched:\n{all}"
    );
}
