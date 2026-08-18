// SPDX-License-Identifier: MIT OR Apache-2.0

//! STUN decoding must survive the whole path from pcap to printed report.
//!
//! The unit tests cover the parser, the tracker and the renderer; these drive
//! the binary, because the failure that motivated the feature was not a wrong
//! answer. It was sipnab reading a capture full of STUN, counting the packets
//! as nothing at all, and printing "No SIP traffic found." — a claim about the
//! wire that the capture contradicts.
//!
//! The fixture uses RFC 5737 documentation addresses throughout: 192.0.2.10
//! retransmits a Binding Request that nothing answers, and 192.0.2.11 gets a
//! success response carrying XOR-MAPPED-ADDRESS 203.0.113.5:12262.
//!
//! A second fixture, `stun_sdp_mismatch.pcap`, carries the payoff: the same
//! unanswered probe followed by the SIP call the client then placed, whose SDP
//! advertises the LAN address it never learned to replace. Everything routable
//! in it is RFC 5737; the LAN side is RFC 1918, which the finding requires by
//! definition.
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::process::Command;

fn stun_fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("stun_nat_probe.pcap")
        .to_string_lossy()
        .into_owned()
}

/// The STUN + SIP fixture: an unanswered probe from 192.168.10.50, then that
/// client's call advertising 192.168.10.50 in its SDP, with the far end's media
/// anchored on 203.0.113.7 — an address no SDP in the dialog named.
fn mismatch_fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("stun_sdp_mismatch.pcap")
        .to_string_lossy()
        .into_owned()
}

/// The Call-ID of the single dialog in `stun_sdp_mismatch.pcap`.
const MISMATCH_CALL_ID: &str = "stun-sdp-mismatch-1@192.168.10.50";

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

/// `--stun` on the fixture, stdout only.
fn stun_report() -> String {
    let (stdout, stderr, code) = run(&["-N", "-I", &stun_fixture(), "--stun", "--no-cli-print"]);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");
    stdout
}

#[test]
fn report_lists_stun_transactions() {
    let out = stun_report();
    assert!(
        out.contains("STUN Transactions"),
        "the report needs a STUN section, got:\n{out}"
    );
    assert!(
        out.contains("198.51.100.20:3478"),
        "the report must name the STUN server, got:\n{out}"
    );
    assert!(
        out.contains("2 transaction(s)"),
        "two distinct transaction IDs, not four packets, got:\n{out}"
    );
}

/// The signature the whole feature exists to surface: a request retransmitted
/// under one transaction ID with nothing ever answering. RFC 5389 §7.2.1
/// retransmits only on timeout, so the second request is itself proof the
/// first went unanswered.
#[test]
fn report_flags_the_unanswered_retransmitted_probe() {
    let out = stun_report();
    let line = out
        .lines()
        .find(|l| l.contains("192.0.2.10:5060"))
        .unwrap_or_else(|| panic!("no row for the failing client, got:\n{out}"));
    assert!(
        line.contains("NONE"),
        "an unanswered probe must say so in its row: {line}"
    );
    assert!(
        out.contains("1 transaction(s) drew no response"),
        "the unanswered probe must be called out in prose, got:\n{out}"
    );
    assert!(
        out.contains("retransmitted"),
        "the retransmit is the proof, and must be named, got:\n{out}"
    );
}

#[test]
fn report_shows_the_discovered_public_address() {
    let out = stun_report();
    assert!(
        out.contains("203.0.113.5:12262"),
        "the XOR-MAPPED-ADDRESS the client learned must be reported, got:\n{out}"
    );
}

/// A capture holding only STUN is not an empty capture. Reporting "No SIP
/// traffic found." and nothing else is the defect: it is the sentence that
/// sends an operator back to tcpdump to rediscover what sipnab already held.
#[test]
fn stun_only_capture_is_not_reported_as_empty() {
    let (stdout, stderr, code) = run(&["-N", "-I", &stun_fixture()]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("No SIP traffic found."),
        "a STUN-only capture is not an empty one, got:\n{combined}"
    );
    assert!(
        combined.contains("1 of 2 STUN/TURN transaction(s) went unanswered"),
        "the guidance must state what the capture held instead, got:\n{combined}"
    );
    assert!(
        combined.contains("192.0.2.10:5060 sent Binding to 198.51.100.20:3478"),
        "and it must name who asked what of whom, got:\n{combined}"
    );
}

/// A capture with no STUN must render exactly as it did before this feature —
/// no empty section, no zero line. The "a clean run stays quiet" rule.
#[test]
fn a_capture_without_stun_gains_no_stun_output() {
    let sip = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap");
    let (stdout, stderr, _) = run(&[
        "-N",
        "-I",
        &sip.to_string_lossy(),
        "--stun",
        "--no-cli-print",
    ]);
    assert!(
        !stdout.contains("STUN Transactions"),
        "a capture without STUN must print no STUN table, got:\n{stdout}"
    );
    assert!(
        !stderr.contains("STUN/TURN:"),
        "a capture without STUN must print no STUN summary, got:\n{stderr}"
    );
}

#[test]
fn json_stun_emits_one_object_per_transaction() {
    let (stdout, stderr, code) =
        run(&["-N", "-I", &stun_fixture(), "--json-stun", "--no-cli-print"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(
        lines.len(),
        2,
        "one JSON object per transaction, got:\n{stdout}"
    );

    let parsed: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("each line must be valid JSON"))
        .collect();

    assert!(
        parsed.iter().all(|v| v["record"] == "transaction"),
        "every record must name its kind, got:\n{stdout}"
    );

    let failing = parsed
        .iter()
        .find(|v| v["client"].as_str() == Some("192.0.2.10:5060"))
        .expect("the failing transaction must be present");
    assert_eq!(failing["request_count"], 2);
    assert!(
        failing["responded_at"].is_null(),
        "nothing answered it: {failing}"
    );
    assert_eq!(failing["software"], "traversal-2.1.0 45");

    let answered = parsed
        .iter()
        .find(|v| v["client"].as_str() == Some("192.0.2.11:5062"))
        .expect("the answered transaction must be present");
    assert_eq!(answered["mapped_address"], "203.0.113.5:12262");
    assert!(!answered["responded_at"].is_null());
}

// ── STUN mapped address versus the advertised SDP address ──────────────
//
// The finding the decoder exists to reach: STUN is on record failing (or
// disagreeing), the SDP carries an unroutable address, and the one-way audio
// that follows now has a stated cause instead of a symptom.
//
// It is carried as `stun_sdp_mismatch` INSIDE the diagnosis that already
// raises `private_media_address`, never as a finding of its own — one address,
// one problem, with STUN as the evidence that settles it.

/// The diagnosis block of the single dialog in the mismatch fixture, as JSON,
/// selected through `alias`.
fn mismatch_diagnosis(alias: &str) -> serde_json::Value {
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &mismatch_fixture(),
        alias,
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .unwrap_or_else(|| panic!("{alias} must select the dialog, got:\n{stdout}"));
    let dialog: serde_json::Value =
        serde_json::from_str(line).expect("the dialog line must be valid JSON");
    assert_eq!(dialog["call_id"], MISMATCH_CALL_ID);
    dialog["diagnosis"].clone()
}

/// `--one-way` selects the call, and the diagnosis it prints names the STUN
/// failure that caused it — not just the missing reverse flow.
#[test]
fn one_way_output_carries_the_stun_versus_sdp_finding() {
    let diagnosis = mismatch_diagnosis("--one-way");
    assert_eq!(diagnosis["one_way_audio"], true);

    let finding = &diagnosis["stun_sdp_mismatch"];
    assert_eq!(finding["reason"], "unanswered");
    assert_eq!(finding["client"], "192.168.10.50:5060");
    assert_eq!(finding["advertised"], "192.168.10.50");
    assert_eq!(finding["request_count"], 2);
    assert!(
        finding["mapped_address"].is_null(),
        "nothing answered, so there is no public address to name: {finding}"
    );
}

/// The evidence never stands alone: it is attached to the finding it
/// corroborates, so one capture cannot report two independent-looking problems
/// about one address.
#[test]
fn the_stun_evidence_rides_on_the_private_address_finding() {
    let diagnosis = mismatch_diagnosis("--one-way");
    assert_eq!(
        diagnosis["private_media_address"], true,
        "the STUN evidence is evidence FOR this flag, so it cannot be raised \
         without it: {diagnosis}"
    );
}

/// The same finding is present when the call is reached through `--nat-issues`:
/// the diagnosis does not depend on which alias selected the dialog.
#[test]
fn nat_issues_output_carries_the_stun_versus_sdp_finding() {
    let diagnosis = mismatch_diagnosis("--nat-issues");
    assert_eq!(diagnosis["nat_mismatch"], true);
    assert_eq!(diagnosis["stun_sdp_mismatch"]["reason"], "unanswered");
}

/// The hint has to say what an operator should do next: which host, which
/// address it advertised, and that the probe drew nothing.
#[test]
fn the_hint_names_the_client_the_silence_and_the_advertised_address() {
    let diagnosis = mismatch_diagnosis("--one-way");
    let hints = diagnosis["hints"]
        .as_array()
        .expect("hints must be an array");
    let hint = hints
        .iter()
        .filter_map(|h| h.as_str())
        .find(|h| h.contains("STUN request drew no response"))
        .unwrap_or_else(|| panic!("no STUN hint among {hints:?}"));
    assert!(hint.contains("192.168.10.50:5060"), "{hint}");
    assert!(hint.contains("retransmitted"), "{hint}");
    assert!(hint.contains("advertised 192.168.10.50"), "{hint}");
    // One hint about this address, not two. The uncorroborated wording is what
    // `private_media_address` says on its own, and printing both would read as
    // two problems.
    assert!(
        !hints
            .iter()
            .filter_map(|h| h.as_str())
            .any(|h| h.contains("This is correct only if something downstream rewrites")),
        "the corroborated hint REPLACES the check-this-yourself one: {hints:?}"
    );
}

/// The text `--call-report` carries it too, in the issues section alongside
/// the symptom it explains.
#[test]
fn call_report_lists_the_stun_finding_among_the_issues() {
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &mismatch_fixture(),
        "--call-report",
        MISMATCH_CALL_ID,
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(
        stdout.contains("Issues Detected:"),
        "the report needs an issues section, got:\n{stdout}"
    );
    assert!(
        stdout.contains("STUN request drew no response"),
        "the STUN cause must appear beside the one-way symptom, got:\n{stdout}"
    );
}

/// The absolute requirement: a capture with no STUN in it must diagnose
/// exactly as it did before this finding existed. No field, no hint, no
/// mention of STUN anywhere in the dialog JSON.
#[test]
fn a_capture_without_stun_gains_no_diagnosis_field() {
    let sip = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap");
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &sip.to_string_lossy(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(
        !stdout.contains("stun_sdp_mismatch"),
        "a capture without STUN must carry no STUN finding, got:\n{stdout}"
    );
    for line in stdout.lines().filter(|l| l.starts_with('{')) {
        let dialog: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        assert!(
            dialog["diagnosis"]["stun_sdp_mismatch"].is_null(),
            "no STUN, no finding: {line}"
        );
    }
}
