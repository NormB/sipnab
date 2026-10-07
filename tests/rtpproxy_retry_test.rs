// SPDX-License-Identifier: MIT OR Apache-2.0

//! A retried rtpproxy command is counted and named (RP4).
//!
//! rtpproxy's datagram control protocol starts every command with a cookie,
//! and the cookie exists for retransmission: the relay keeps a reply cache
//! and answers a repeated cookie with the cached reply. So a capture shows a
//! retry as the same cookie sent twice. A retry usually means the proxy did
//! not hear the answer, and from the SIP side a control channel losing
//! answers looks only like a proxy that is sometimes slow.
//!
//! Two shapes are told apart, because they point at different halves of the
//! path. A retry sent AFTER the relay's answer was on the wire means the answer
//! was lost or late on its way back to the proxy. A retry sent before any
//! answer means the command, or the relay, was slow.

#![cfg(all(feature = "native", feature = "mcp"))]

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/pcap_build.rs"]
mod pcap_build;

use mcp::McpSession;
use pcap_build::{udp_frame, write_pcap_or_panic};
use std::process::Command;

const PROXY: [u8; 4] = [192, 0, 2, 10];
const RELAY: [u8; 4] = [192, 0, 2, 40];
const CONTROL: u16 = 7722;

fn command(cookie: &str, call: &str) -> Vec<u8> {
    let text = format!("{cookie} Uc8 {call} 192.0.2.60 40000 ftag\n");
    udp_frame(PROXY, RELAY, 43000, CONTROL, text.as_bytes())
}

fn reply(cookie: &str, port: u16) -> Vec<u8> {
    let text = format!("{cookie} {port} 192.0.2.40\n");
    udp_frame(RELAY, PROXY, CONTROL, 43000, text.as_bytes())
}

/// c1: answered, then sent again (the answer did not reach the proxy).
/// c2: sent twice before any answer, then answered once.
/// c3: one command, one answer.
fn capture(dir: &std::path::Path) -> String {
    let frames = vec![
        command("c1", "call-1"),
        reply("c1", 31000),
        command("c1", "call-1"),
        reply("c1", 31000),
        command("c2", "call-2"),
        command("c2", "call-2"),
        reply("c2", 31002),
        command("c3", "call-3"),
        reply("c3", 31004),
    ];
    let path = dir.join("retries.pcap");
    write_pcap_or_panic(&path, &frames);
    path.to_str().expect("utf-8 path").to_string()
}

/// The `relay_control` rows `reconcile_orphans` returns.
fn relay_control(session: &mut McpSession) -> Vec<serde_json::Value> {
    let msg = session.call_or_panic("reconcile_orphans", serde_json::json!({}));
    assert!(
        msg.get("error").is_none(),
        "reconcile_orphans must answer: {msg}"
    );
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .expect("text payload")
        .to_string();
    let value: serde_json::Value = serde_json::from_str(&text).expect("payload is JSON");
    value["relay_control"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("no relay_control in {value}"))
}

/// MCP: one row for the relay's control socket, with the counts.
#[test]
fn reconcile_orphans_counts_retried_relay_commands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let mut session = McpSession::start_or_panic(
        &pcap,
        &["--no-config", "--rtpproxy-control", "192.0.2.40:7722"],
    );
    let rows = relay_control(&mut session);
    assert_eq!(rows.len(), 1, "one control socket: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["relay"], "192.0.2.40:7722", "{row}");
    assert_eq!(row["implementation"], "rtpproxy", "{row}");
    assert_eq!(row["commands"], 5, "{row}");
    assert_eq!(row["retried_commands"], 2, "{row}");
    assert_eq!(row["retried_after_answer"], 1, "{row}");
}

/// No control socket named: nothing is read as control, so nothing is counted.
#[test]
fn without_a_control_socket_there_is_no_relay_control_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let mut session = McpSession::start_or_panic(&pcap, &["--no-config"]);
    assert!(relay_control(&mut session).is_empty());
}

/// The headless run says it at the end, with the same numbers.
#[test]
fn a_headless_run_reports_retried_relay_commands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap,
            "--no-config",
            "--rtpproxy-control",
            "192.0.2.40:7722",
        ])
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    assert!(out.status.success(), "sipnab failed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("rtpproxy at 192.0.2.40:7722: 2 of 5 control commands were retried"),
        "no retry line:\n{stderr}"
    );
    assert!(
        stderr.contains("1 after the relay's answer was already on the wire"),
        "the retry after an answer must be named:\n{stderr}"
    );
}

/// A capture with no retries prints no retry line.
#[test]
fn a_clean_control_channel_prints_no_retry_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("clean.pcap");
    write_pcap_or_panic(&path, &[command("c9", "call-9"), reply("c9", 31010)]);
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            path.to_str().expect("utf-8"),
            "--no-config",
            "--rtpproxy-control",
            "192.0.2.40:7722",
        ])
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    assert!(out.status.success(), "sipnab failed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("retried"),
        "retry line on a clean channel:\n{stderr}"
    );
}

/// `--cores` reads the capture on several workers and merges their stores;
/// the counts survive the merge.
#[test]
fn the_parallel_reader_reports_the_same_retries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap,
            "--no-config",
            "--cores",
            "2",
            "--rtpproxy-control",
            "192.0.2.40:7722",
        ])
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    assert!(out.status.success(), "sipnab failed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("rtpproxy at 192.0.2.40:7722: 2 of 5 control commands were retried"),
        "no retry line from --cores:\n{stderr}"
    );
}
