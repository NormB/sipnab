// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP over TCP survives a capture that missed part of the connection.
//!
//! A tap that drops a packet, or a capture that joins a long-lived
//! proxy-to-proxy connection part way, leaves a hole in the sequence space no
//! later packet fills. sipnab used to hold everything behind such a hole until
//! the buffer ceiling, a FIN or eviction, so every message on that direction
//! was lost. These tests run the binary, through both readers, over a capture
//! built here with exactly that hole: the messages after it must be reported,
//! including one that is the last packet its direction ever sends.
//!
//! A connection joined part way also has no SYN to anchor its sequence
//! numbers, and sipnab used to report every retransmission on such a
//! connection as the message again.
#![cfg(feature = "native")]

use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;

const A: [u8; 4] = [10, 30, 0, 1];
const B: [u8; 4] = [10, 30, 0, 2];

fn message(first_line: &str, call_id: &str) -> String {
    format!(
        "{first_line}\r\nVia: SIP/2.0/TCP 10.30.0.1:40001;branch=z9hG4bK{call_id}\r\n\
         From: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: {call_id}\r\n\
         CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    )
}

/// A -> B: the head of a message, a hole of 500 bytes, then two whole
/// messages. B -> A: a hole, then one whole message that is the last packet
/// on that direction.
fn frames() -> Vec<Vec<u8>> {
    let head = b"OPTIONS sip:b@x SIP/2.0\r\nCall-ID: never-whole\r\n";
    let second = message("OPTIONS sip:b@x SIP/2.0", "hole-after-1");
    let third = message("OPTIONS sip:b@x SIP/2.0", "hole-after-2");
    let reply = message("SIP/2.0 200 OK", "hole-reply");
    let a_after = 5_001 + head.len() as u32 + 500;
    vec![
        pcap_build::tcp_frame(A, B, 40_001, 5060, 5_000, 0x02, b""),
        pcap_build::tcp_frame(B, A, 5060, 40_001, 9_000, 0x12, b""),
        pcap_build::tcp_frame(A, B, 40_001, 5060, 5_001, 0x18, head),
        pcap_build::tcp_frame(A, B, 40_001, 5060, a_after, 0x18, second.as_bytes()),
        pcap_build::tcp_frame(
            A,
            B,
            40_001,
            5060,
            a_after + second.len() as u32,
            0x18,
            third.as_bytes(),
        ),
        pcap_build::tcp_frame(B, A, 5060, 40_001, 9_001 + 700, 0x18, reply.as_bytes()),
    ]
}

fn call_ids(cores: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hole.pcap");
    pcap_build::write_pcap(&path, &frames());
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I"])
        .arg(&path)
        // Dialogs rather than messages: `--cores` has no per-message stream.
        .args(["--json-dialogs", "--no-cli-print", "--cores", cores])
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    let mut ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["call_id"].as_str().map(str::to_string))
        .filter(|id| !id.is_empty())
        .collect();
    ids.sort();
    ids
}

/// Both messages after the hole, and the reply that ends its direction; never
/// the half message before the hole.
#[test]
fn messages_after_a_hole_are_reported_by_both_readers() {
    let want = vec!["hole-after-1", "hole-after-2", "hole-reply"];
    assert_eq!(call_ids("1"), want, "the single-threaded reader");
    assert_eq!(call_ids("2"), want, "the --cores reader");
}

/// A skipped hole is data the capture never held, so the run says so where
/// it reports every other loss: in the capture-quality line, with how many
/// holes and how much sequence space they spanned (500 bytes one way, 700
/// the other).
#[test]
fn skipped_holes_are_reported_as_capture_loss_by_both_readers() {
    for cores in ["1", "2"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hole.pcap");
        pcap_build::write_pcap(&path, &frames());
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "-I"])
            .arg(&path)
            .args(["--no-cli-print", "--cores", cores])
            .env("NO_COLOR", "1")
            .output()
            .expect("spawn sipnab");
        let stderr = String::from_utf8_lossy(&out.stderr);
        let line = stderr
            .lines()
            .find(|l| l.contains("capture quality:"))
            .unwrap_or_else(|| panic!("--cores {cores}: no capture-quality line:\n{stderr}"));
        assert!(
            line.contains("2 hole(s)") && line.contains("1200 byte(s)"),
            "--cores {cores}: the line must count both holes and their span: {line}"
        );
    }
}

/// A connection the capture joined part way (no SYN): one message, sent,
/// then retransmitted twice, the second copy after the next message.
fn retransmitted_frames() -> Vec<Vec<u8>> {
    let first = message("OPTIONS sip:b@x SIP/2.0", "sent-once");
    let second = message("OPTIONS sip:b@x SIP/2.0", "sent-after");
    let next = 70_000 + first.len() as u32;
    let copy = || pcap_build::tcp_frame(A, B, 40_002, 5060, 70_000, 0x18, first.as_bytes());
    vec![
        copy(),
        copy(),
        pcap_build::tcp_frame(A, B, 40_002, 5060, next, 0x18, second.as_bytes()),
        copy(),
    ]
}

/// Each message once, however often TCP carried it.
#[test]
fn a_retransmission_on_a_connection_joined_part_way_is_reported_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("retransmitted.pcap");
    pcap_build::write_pcap(&path, &retransmitted_frames());
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I"])
        .arg(&path)
        .args(["--json"])
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    let mut ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["call_id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    assert_eq!(ids, vec!["sent-after", "sent-once"]);
}
