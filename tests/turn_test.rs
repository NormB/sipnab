// SPDX-License-Identifier: MIT OR Apache-2.0

//! TURN decoding must survive the whole path from pcap to printed report.
//!
//! The unit tests cover the ChannelData framing, the attribute decoding and
//! the tracker; these drive the binary, because the defect that motivated the
//! work was not a wrong answer. It was every packet of media that crossed a
//! TURN relay being counted as nothing at all: a ChannelData frame carries no
//! magic cookie, so it is not STUN, and its version bits are `01`, so it is not
//! RTP either. sipnab read those frames and reported an empty media path.
//!
//! The fixture `turn_relay.pcap` is fabricated end to end and uses RFC 5737
//! documentation addresses throughout:
//!
//! ```text
//!   192.0.2.10:50000     the TURN client
//!   198.51.100.20:3478   the TURN server
//!   198.51.100.77:49160  the relayed address the server allocates
//!   203.0.113.9:16000    the peer on the far side of the relay
//!   203.0.113.5:12262    the client's reflexive address
//! ```
//!
//! It holds an Allocate that succeeds with `XOR-RELAYED-ADDRESS` and a
//! 60-second `LIFETIME`, a CreatePermission, a ChannelBind on channel
//! `0x4001`, one Send indication relaying an RTP packet in its `DATA`
//! attribute, and 152 ChannelData frames carrying RTP and RTCP. No Refresh
//! appears anywhere, and the last talk spurt begins a minute in — so the
//! allocation had already lapsed under the media still crossing it.
//!
//! # One deliberate gap
//!
//! The RTP inside the Send indication's `DATA` attribute is NOT unwrapped.
//! The attribute is decoded — `StunMessage::data` locates it — but the
//! pipeline consumes only the ChannelData form, so the fixture's relayed media
//! counts 150 packets rather than 151. Unwrapping the pre-channel form is a
//! pipeline change of its own and is not claimed here.
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::process::Command;

fn turn_fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("turn_relay.pcap")
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("failed to execute sipnab");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// `--stun` on the TURN fixture, stdout only.
fn turn_report() -> String {
    let (stdout, stderr, code) = run(&["-N", "-I", &turn_fixture(), "--stun", "--no-cli-print"]);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");
    stdout
}

// ── The relayed media ────────────────────────────────────────────────

/// The whole point. 150 ChannelData frames carry RTP in both directions, and
/// every one of them must reach the stream store as media rather than be
/// discarded as an unrecognised datagram.
#[test]
fn relayed_media_reaches_the_stream_store_as_rtp() {
    let (stdout, stderr, code) = run(&["-N", "-I", &turn_fixture(), "--no-cli-print"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("150 RTP packets across 2 stream(s) were parsed"),
        "relayed RTP must be counted and streamed, got:\n{combined}"
    );
}

/// The two relayed streams must be attributable — an operator has to be able
/// to see the SSRCs and the endpoints the frames were observed between. The
/// endpoints are the client and the TURN server on purpose: that is where
/// these packets were seen, and what a follow-up capture filter has to match.
#[test]
fn the_relayed_streams_are_attributable_to_their_endpoints() {
    let (stdout, stderr, code) = run(&["-N", "-I", &turn_fixture(), "--report", "--no-cli-print"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let up = stdout
        .lines()
        .find(|l| l.contains("0x11223344"))
        .unwrap_or_else(|| panic!("the client-to-server stream must exist, got:\n{stdout}"));
    assert!(up.contains("192.0.2.10:50000"), "{up}");
    assert!(up.contains("198.51.100.20:3478"), "{up}");
    let down = stdout
        .lines()
        .find(|l| l.contains("0x55667788"))
        .unwrap_or_else(|| panic!("the server-to-client stream must exist, got:\n{stdout}"));
    assert!(down.contains("198.51.100.20:3478"), "{down}");
}

// ── The TURN report ──────────────────────────────────────────────────

/// The method has to be on the row, or an Allocate is indistinguishable from
/// a connectivity check.
#[test]
fn the_transaction_table_names_each_turn_method() {
    let out = turn_report();
    for method in ["Allocate", "CreatePermission", "ChannelBind"] {
        assert!(out.contains(method), "{method} must be named, got:\n{out}");
    }
}

/// The relayed address is what the client should be advertising, and it is the
/// direct analogue of the mapped address beside it.
#[test]
fn the_transaction_table_carries_the_relayed_address() {
    let out = turn_report();
    assert!(out.contains("Relayed Address"), "{out}");
    assert!(
        out.contains("198.51.100.77:49160"),
        "the XOR-RELAYED-ADDRESS must be reported, got:\n{out}"
    );
    assert!(
        out.contains("203.0.113.5:12262"),
        "and it must not have displaced the mapped address, got:\n{out}"
    );
}

/// The relayed frames are the proof the media is no longer invisible, and the
/// report has to say so beside the allocation they crossed.
#[test]
fn the_allocation_section_accounts_for_the_relayed_frames() {
    let out = turn_report();
    assert!(
        out.contains("152 relayed ChannelData frame(s)"),
        "150 RTP + 2 RTCP frames crossed the relay, got:\n{out}"
    );
}

/// The operational finding LIFETIME exists for: the server granted 60 seconds,
/// no Refresh was ever sent, and media kept crossing the relay a minute later.
#[test]
fn an_allocation_that_outlived_its_lifetime_is_reported() {
    let out = turn_report();
    assert!(out.contains("TURN Allocations (1)"), "{out}");
    assert!(out.contains("60s"), "the granted lifetime, got:\n{out}");
    assert!(out.contains("LAPSED"), "{out}");
    assert!(
        out.contains("1 allocation(s) were still carrying traffic"),
        "the finding must be stated in prose, not implied by a cell, got:\n{out}"
    );
}

/// The run summary must name the lapsed allocation on stderr, so a capture
/// read WITHOUT `--stun` still says the relay was torn down under the media.
/// That is the whole reason this finding is not confined to one flag: it has
/// no other symptom anywhere — no SIP message says the audio stopped.
#[test]
fn the_run_summary_names_the_lapsed_allocation() {
    let (_, stderr, code) = run(&["-N", "-I", &turn_fixture(), "--no-cli-print"]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("TURN: 1 allocation(s) were still carrying traffic"),
        "got:\n{stderr}"
    );
    assert!(
        stderr.contains("192.0.2.10:50000 -> 198.51.100.20:3478"),
        "the summary must name which allocation, got:\n{stderr}"
    );
}

// ── NDJSON ───────────────────────────────────────────────────────────

/// `--json-stun` carries both record shapes, each tagged, so a consumer never
/// has to guess which it is looking at.
#[test]
fn json_stun_emits_tagged_transactions_and_allocations() {
    let (stdout, stderr, code) =
        run(&["-N", "-I", &turn_fixture(), "--json-stun", "--no-cli-print"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let records: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("each line must be valid JSON"))
        .collect();

    let allocate = records
        .iter()
        .find(|r| r["method_name"] == "Allocate")
        .unwrap_or_else(|| panic!("the Allocate transaction must be present, got:\n{stdout}"));
    assert_eq!(allocate["record"], "transaction");
    assert_eq!(allocate["method"], 3);
    assert_eq!(allocate["relayed_address"], "198.51.100.77:49160");
    assert_eq!(allocate["lifetime_secs"], 60);

    let bind = records
        .iter()
        .find(|r| r["method_name"] == "ChannelBind")
        .expect("the ChannelBind transaction must be present");
    assert_eq!(bind["channel_number"], 0x4001);
    assert_eq!(bind["peer_address"], "203.0.113.9:16000");

    let alloc = records
        .iter()
        .find(|r| r["record"] == "turn_allocation")
        .unwrap_or_else(|| panic!("the allocation must be present, got:\n{stdout}"));
    assert_eq!(alloc["relayed_address"], "198.51.100.77:49160");
    assert_eq!(alloc["refreshes"], 0);
    assert_eq!(alloc["released"], false);
    assert_eq!(
        alloc["lapsed"], true,
        "the derived verdict must ride along, or a consumer has to reimplement \
         the lifetime arithmetic: {alloc}"
    );
}

// ── --analyze ────────────────────────────────────────────────────────

/// A lapsed allocation is a capture-level finding, and `--analyze` is where an
/// operator looks for those.
#[test]
fn analyze_ranks_the_lapsed_allocation() {
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &turn_fixture(),
        "--json-analyze",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let value: serde_json::Value = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("valid JSON"))
        .unwrap_or_else(|| panic!("--json-analyze must emit an object, got:\n{stdout}"));
    let findings = value["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("findings must be an array, got:\n{stdout}"));
    let lapsed = findings
        .iter()
        .find(|f| f["kind"] == "turn_allocation_lapsed")
        .unwrap_or_else(|| panic!("the lapsed allocation must be a finding, got:\n{stdout}"));
    assert_eq!(lapsed["severity"], "major");
    assert_eq!(lapsed["occurrences"], 1);
}

// ── The quiet-run guarantee ──────────────────────────────────────────

/// A capture with no TURN in it must render exactly as it did before any of
/// this existed: no TURN sections, no TURN summary lines.
#[test]
fn a_capture_without_turn_gains_no_turn_output() {
    let sip = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap");
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &sip.to_string_lossy(),
        "--stun",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    for needle in ["TURN Allocations", "Relayed Address"] {
        assert!(
            !stdout.contains(needle),
            "'{needle}' must not appear for a capture without TURN, got:\n{stdout}"
        );
    }
    assert!(
        !stderr.contains("TURN:"),
        "no TURN summary either, got:\n{stderr}"
    );
}

/// And a capture that holds STUN but no relay must keep its STUN report free
/// of relay columns and sections.
#[test]
fn a_stun_only_capture_gains_no_turn_sections() {
    let stun = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("stun_nat_probe.pcap");
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &stun.to_string_lossy(),
        "--stun",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(stdout.contains("STUN Transactions"), "{stdout}");
    assert!(!stdout.contains("Relayed Address"), "{stdout}");
    assert!(!stdout.contains("TURN Allocations"), "{stdout}");
}
