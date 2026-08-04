// SPDX-License-Identifier: MIT OR Apache-2.0

//! A capture sipnab cannot decode must not report as an empty one.
//!
//! The defect, end to end: given a capture on a link type sipnab had no
//! decoder for, the run printed
//!
//! ```text
//! sipnab: 49 packets captured, 0 SIP messages, 0 RTP packets across 0 streams
//! No SIP traffic found. Check that the capture contains SIP packets ...
//! ```
//!
//! and exited 0 — character for character what a *perfect* read of a capture
//! containing no SIP produces. Every frame had failed to parse; the only trace
//! was a `debug!` line that is off by default. An operator had no way to tell
//! "there is no SIP here" from "I could not read one single frame of this",
//! and neither did a script reading `$?`.
//!
//! These tests drive the real binary over captures this file builds, so the
//! link type is chosen here rather than inherited from a checked-in sample.
//! That matters for more than hygiene: sipnab's decoder coverage is actively
//! growing, so a test pinned to whichever sample happens to be undecodable
//! today would flip to green-for-the-wrong-reason the moment that gap closed.
//! DLT 147 is `DLT_USER0`, reserved by libpcap for private use and therefore
//! never something sipnab will decode.
#![cfg(feature = "native")]

use std::path::Path;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// A pcap link type reserved for private use, so no future decoder claims it.
const DLT_USER0: u32 = 147;

/// Frames in the undecodable fixture. Small and exact: every assertion below
/// names this number, and `> 0` would pass on a run that read one frame.
const UNDECODABLE_FRAMES: usize = 5;

/// Run the binary under the shared test baseline with quiet logs.
fn run(args: &[&str]) -> (String, String, Option<i32>) {
    run_support::run(args, Some("error"))
}

/// Write a capture whose link type sipnab has no decoder for, carrying bytes
/// that *would* be a SIP INVITE if anything could reach them.
///
/// The payload matters: this is the "capture full of SIP that sipnab reports
/// as empty" case, not a capture that is genuinely empty.
fn write_undecodable(path: &Path) {
    let sip = b"INVITE sip:auto@localhost SIP/2.0\r\nCall-ID: undecodable-1\r\n\r\n";
    let frames: Vec<Vec<u8>> = (0..UNDECODABLE_FRAMES)
        .map(|_| {
            let mut f = vec![0u8; 4]; // an opaque private-use link header
            f.extend_from_slice(sip);
            f
        })
        .collect();
    pcap_build::write_pcap_with_linktype(path, &frames, DLT_USER0);
}

/// The summary must state, with numbers, that nothing was decoded — and must
/// name the DLT, because "unsupported link type" without its number names no
/// capture format an operator can convert.
#[test]
fn an_undecodable_capture_says_so_with_its_numbers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("undecodable.pcap");
    write_undecodable(&path);

    let (_, stderr, code) = run(&["-N", "-I", path.to_str().expect("utf-8 path")]);
    assert_eq!(
        code,
        Some(0),
        "a readable file is not a failed run: {stderr}"
    );

    assert!(
        stderr.contains(&format!(
            "NOT DECODED: {UNDECODABLE_FRAMES} of {UNDECODABLE_FRAMES} frame(s) (100.0%)"
        )),
        "the exact count and share must be stated:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "unsupported link type {DLT_USER0} ({UNDECODABLE_FRAMES})"
        )),
        "the DLT number and its frame count must be named:\n{stderr}"
    );
    assert!(
        stderr.contains("not evidence of absence"),
        "a wholly unread capture must refuse to let a zero read as a finding:\n{stderr}"
    );
}

/// The unqualified "No SIP traffic found." is a claim about the wire. A run
/// that decoded nothing has no basis for it, and this is the last mile of the
/// defect — the point where an unread capture was finally reported to the
/// operator as an empty one.
#[test]
fn no_sip_traffic_found_is_never_stated_after_a_failed_decode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("undecodable.pcap");
    write_undecodable(&path);

    let (_, stderr, _) = run(&["-N", "-I", path.to_str().expect("utf-8 path")]);

    assert!(
        !stderr.contains("No SIP traffic found."),
        "the unqualified finding must not appear:\n{stderr}"
    );
    assert!(
        stderr.contains("not a finding that the capture contains no SIP"),
        "the run must disclaim its own zero:\n{stderr}"
    );
}

/// The other half of the contract, and the one that gives the first half its
/// value: a capture sipnab reads perfectly must stay silent about decoding.
/// A notice that fires on every run is one operators learn to skim past.
#[test]
fn a_capture_that_decodes_cleanly_prints_no_notice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("clean.pcap");
    let frames: Vec<Vec<u8>> = pcap_build::sip_call("clean-1", "z9hG4bK-clean", "alice", "bob")
        .iter()
        .map(|msg| pcap_build::udp_frame([10, 1, 0, 1], [10, 1, 0, 2], 5060, 5060, msg.as_bytes()))
        .collect();
    pcap_build::write_pcap(&path, &frames);

    let (_, stderr, code) = run(&["-N", "-I", path.to_str().expect("utf-8 path")]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        !stderr.contains("NOT DECODED"),
        "a clean read must print no undecodable notice:\n{stderr}"
    );
}

/// A capture that decodes fine but holds no SIP keeps the plain finding —
/// that IS the answer, and softening it everywhere would trade one useless
/// message for another.
#[test]
fn a_clean_capture_with_no_sip_still_states_it_plainly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("no-sip.pcap");
    // Well-formed UDP on a port carrying nothing that parses as SIP.
    let frames: Vec<Vec<u8>> = (0..4)
        .map(|_| pcap_build::udp_frame([10, 1, 0, 1], [10, 1, 0, 2], 5060, 5060, b"not-sip-at-all"))
        .collect();
    pcap_build::write_pcap(&path, &frames);

    let (_, stderr, code) = run(&["-N", "-I", path.to_str().expect("utf-8 path")]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        !stderr.contains("NOT DECODED"),
        "these frames decoded; they simply were not SIP:\n{stderr}"
    );
    assert!(
        stderr.contains("No SIP traffic found."),
        "a clean read with no SIP must say so plainly:\n{stderr}"
    );
}

/// `--report` is the surface an operator reads to answer "what is in this
/// capture". An empty dialog table answers that question when the capture was
/// read; when it was not, the empty table is not an answer at all — and the
/// two rendered as the same blank report.
#[test]
fn the_report_carries_a_not_decoded_section() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("undecodable.pcap");
    write_undecodable(&path);

    let (stdout, _, code) = run(&["-N", "-I", path.to_str().expect("utf-8 path"), "--report"]);
    assert_eq!(code, Some(0));
    assert!(
        stdout.contains("NOT DECODED (capture-wide):"),
        "the report must carry the section:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "{UNDECODABLE_FRAMES} frame(s) produced no packet at all"
        )),
        "with the exact count:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("unsupported link type {DLT_USER0}")),
        "and the DLT number:\n{stdout}"
    );

    // The other half: a clean capture's report is unchanged.
    let clean = dir.path().join("clean.pcap");
    let frames: Vec<Vec<u8>> = pcap_build::sip_call("rep-1", "z9hG4bK-rep", "alice", "bob")
        .iter()
        .map(|msg| pcap_build::udp_frame([10, 1, 0, 1], [10, 1, 0, 2], 5060, 5060, msg.as_bytes()))
        .collect();
    pcap_build::write_pcap(&clean, &frames);
    let (stdout, _, _) = run(&["-N", "-I", clean.to_str().expect("utf-8 path"), "--report"]);
    assert!(
        !stdout.contains("NOT DECODED"),
        "a clean report gains no section:\n{stdout}"
    );
}

/// `--cores N` must reach the same conclusion as `--cores 1` about the same
/// capture. The parallel path had no ICMP summary at all for a long time for
/// exactly this reason: a notice wired into one summary site and not the
/// others makes the two paths disagree about the same bytes.
#[test]
fn the_parallel_path_reports_the_same_undecodable_frames() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("undecodable.pcap");
    write_undecodable(&path);
    let file = path.to_str().expect("utf-8 path");

    let (_, single, _) = run(&["-N", "-I", file]);
    let (_, parallel, _) = run(&["-N", "-I", file, "--cores", "2"]);

    for stderr in [&single, &parallel] {
        assert!(
            stderr.contains(&format!(
                "unsupported link type {DLT_USER0} ({UNDECODABLE_FRAMES})"
            )),
            "both paths must name the DLT and its count:\n{stderr}"
        );
    }
}
