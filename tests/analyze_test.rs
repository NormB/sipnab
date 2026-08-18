// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--analyze` must survive the whole path from pcap to ranked report.
//!
//! The unit tests in `src/analysis.rs` cover the ladder, the tie-break and the
//! honesty rules against constructed facts; these drive the binary, because
//! what this feature adds is not a new answer. Every finding it prints was
//! already computed (design decision D20) and was already reachable one dialog
//! at a time. What was missing was the aggregate — an operator handed a
//! capture could ask "is call X broken?" and never "what is broken in here?"
//! — so the thing worth testing end to end is that the aggregate comes out of
//! a real file, worst first, with evidence attached.
//!
//! Fixtures used, all RFC 5737 documentation addresses on the routable side
//! and RFC 1918 on the LAN side:
//!
//! * `tests/fixtures/stun_nat_probe.pcap` — STUN only, no SIP at all. A real
//!   input shape, and the one that proves the analyzer does not need dialogs.
//! * `tests/fixtures/stun_sdp_mismatch.pcap` — the payoff capture: an
//!   unanswered Binding Request, then the call that client placed advertising
//!   the private address it never learned to replace, with media anchored
//!   somewhere the far end could not reach.
//! * `tests/pcap-samples/sip-problem-call.pcap` — ordinary failed calls, for
//!   the 4xx/5xx split.
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a file under `tests/`.
fn fixture(dir: &str, name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(dir)
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// The STUN-only capture: no SIP, one unanswered retransmitted probe.
fn stun_only() -> String {
    fixture("fixtures", "stun_nat_probe.pcap")
}

/// The STUN + SIP capture whose SDP advertises what STUN never confirmed.
fn mismatch() -> String {
    fixture("fixtures", "stun_sdp_mismatch.pcap")
}

/// Ordinary failed calls: a 486, a 404, a 603 and a 503.
fn problem_calls() -> String {
    fixture("pcap-samples", "sip-problem-call.pcap")
}

/// A clean single call with no findings in it.
fn clean_call() -> String {
    fixture("fixtures", "sip_call.pcap")
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

/// `--analyze` on a capture, stdout only.
fn analyze(path: &str, extra: &[&str]) -> String {
    let mut args = vec!["-N", "-I", path, "--analyze", "--no-cli-print"];
    args.extend_from_slice(extra);
    let (stdout, stderr, code) = run(&args);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");
    stdout
}

/// The `--json-analyze` object for a capture.
fn analyze_json(path: &str, extra: &[&str]) -> serde_json::Value {
    let mut args = vec!["-N", "-I", path, "--json-analyze", "--no-cli-print"];
    args.extend_from_slice(extra);
    let (stdout, stderr, code) = run(&args);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .unwrap_or_else(|| panic!("--json-analyze must emit one object, got:\n{stdout}"));
    serde_json::from_str(line).expect("the analysis must be valid JSON")
}

/// The kinds in a JSON analysis, in the order they were ranked.
fn kinds(analysis: &serde_json::Value) -> Vec<String> {
    analysis["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .map(|f| f["kind"].as_str().unwrap_or_default().to_string())
        .collect()
}

// ── The user's question: what is wrong with this file? ─────────────────

/// The motivating case. One-way audio has to appear, has to be CRITICAL, and
/// has to be at the top — a ranked list that buries the fault the operator
/// called about is a list nobody reads twice.
#[test]
fn one_way_audio_is_reported_first_and_as_critical() {
    let out = analyze(&mismatch(), &[]);
    assert!(out.contains("One-way audio"), "{out}");
    let first = out
        .lines()
        .find(|l| l.starts_with("1. "))
        .unwrap_or_else(|| panic!("no ranked findings in:\n{out}"));
    assert!(first.contains("[CRITICAL]"), "{first}");
    assert!(first.contains("One-way audio"), "{first}");
}

/// The finding must carry the cause beside the symptom. STUN failing is what
/// made the SDP wrong, and both belong in the same ranked list.
#[test]
fn the_stun_versus_sdp_cause_is_ranked_beside_the_one_way_audio() {
    let json = analyze_json(&mismatch(), &[]);
    let ranked = kinds(&json);
    assert!(
        ranked.contains(&"one_way_audio".to_string()),
        "expected one-way audio in {ranked:?}"
    );
    assert!(
        ranked.contains(&"stun_sdp_mismatch".to_string()),
        "expected the STUN/SDP cause in {ranked:?}"
    );
    // Both are Critical, so they sit above the NAT mismatch and the probe.
    let critical: Vec<&str> = json["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .filter(|f| f["severity"] == "critical")
        .map(|f| f["kind"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(critical, vec!["one_way_audio", "stun_sdp_mismatch"]);
}

/// Requirement: a finding an operator cannot verify against the pcap is
/// worthless. Every finding must name the call, the addresses and the counts.
#[test]
fn every_finding_carries_evidence_that_points_back_at_the_capture() {
    let json = analyze_json(&mismatch(), &[]);
    let findings = json["findings"].as_array().expect("findings is an array");
    assert!(!findings.is_empty(), "{json}");
    for f in findings {
        let evidence = f["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("{} has no evidence array", f["kind"]));
        assert!(
            !evidence.is_empty(),
            "{} has no evidence at all: {f}",
            f["kind"]
        );
        let first = &evidence[0];
        let has_anchor = first.get("call_id").is_some() || first.get("endpoints").is_some();
        assert!(has_anchor, "{} evidence names nothing: {first}", f["kind"]);
    }

    let text = analyze(&mismatch(), &[]);
    assert!(
        text.contains("Call-ID stun-sdp-mismatch-1@192.168.10.50"),
        "the text report must name the call: {text}"
    );
    assert!(
        text.contains("203.0.113.7"),
        "the text report must name the address media actually came from: {text}"
    );
    assert!(
        text.contains("rtp_packets="),
        "the text report must carry packet counts: {text}"
    );
}

// ── A capture with no SIP in it at all ─────────────────────────────────

/// STUN-only, ICMP-only and media-only captures are all real inputs. The
/// analyzer must work without a single dialog — this is the same defect class
/// as reporting a STUN-only file as "No SIP traffic found."
#[test]
fn a_capture_with_no_sip_at_all_still_reports() {
    let out = analyze(&stun_only(), &[]);
    assert!(
        out.contains("STUN Binding Request unanswered"),
        "a STUN-only capture holds a real finding: {out}"
    );
    assert!(
        out.contains("0 dialog(s)"),
        "and must say it examined no dialogs: {out}"
    );
    assert!(
        out.contains("198.51.100.20:3478"),
        "the evidence must name the server that stayed silent: {out}"
    );
    assert!(
        !out.contains("No problems found"),
        "an unanswered probe is a problem: {out}"
    );
}

// ── Honesty: what sipnab did not read ──────────────────────────────────

/// A clean capture gets one line, and that line names its own denominators.
/// "No problems found." alone is a claim about the traffic that sipnab is not
/// entitled to make.
#[test]
fn a_clean_capture_gets_one_line_naming_its_denominators() {
    let out = analyze(&clean_call(), &[]);
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "one honest line, not a scaffold:\n{out}");
    assert!(lines[0].contains("No problems found"), "{out}");
    assert!(lines[0].contains("frame(s)"), "{out}");
    assert!(lines[0].contains("dialog(s)"), "{out}");
}

/// The rule this repo enforces: sipnab's totals describe what it UNDERSTOOD.
/// A port gate that discarded real SIP must make "no problems found"
/// unreachable, because the messages it threw away are in no count below.
#[test]
fn sip_thrown_away_by_a_port_gate_prevents_a_clean_verdict() {
    let out = analyze(&problem_calls(), &["--portrange", "6000-6001"]);
    assert!(
        !out.contains("No problems found"),
        "a capture whose SIP was gated away is not a clean one:\n{out}"
    );
    assert!(out.contains("THIS ANALYSIS IS INCOMPLETE"), "{out}");
    assert!(
        out.contains("[BLIND] SIP discarded by --portrange"),
        "{out}"
    );
    assert!(
        out.contains("port 5060"),
        "the evidence must name the port that was gated out: {out}"
    );
}

/// The machine-readable form has to carry the same verdict, or a pipeline and
/// a human reading the same capture disagree about it.
#[test]
fn the_json_form_marks_an_incomplete_read_as_incomplete() {
    let json = analyze_json(&problem_calls(), &["--portrange", "6000-6001"]);
    assert_eq!(json["complete"], false, "{json}");
    assert_eq!(
        json["findings"][0]["severity"], "blind",
        "the incompleteness must rank first: {json}"
    );
    assert_eq!(json["findings"][0]["kind"], "sip_discarded_by_portrange");

    let clean = analyze_json(&clean_call(), &[]);
    assert_eq!(clean["complete"], true, "{clean}");
    assert!(
        clean["findings"]
            .as_array()
            .expect("findings is an array")
            .is_empty(),
        "{clean}"
    );
    assert!(
        clean["frames_read"].as_u64().unwrap_or(0) > 0,
        "a clean verdict must still state its denominator: {clean}"
    );
}

// ── Ranking ────────────────────────────────────────────────────────────

/// A 5xx is never an ordinary call outcome and a 4xx routinely is, so they get
/// different severities and the 5xx sorts above.
#[test]
fn server_failures_outrank_request_failures() {
    let json = analyze_json(&problem_calls(), &[]);
    let ranked = kinds(&json);
    let server = ranked
        .iter()
        .position(|k| k == "server_failure")
        .unwrap_or_else(|| panic!("expected a 5xx/6xx finding in {ranked:?}"));
    let request = ranked
        .iter()
        .position(|k| k == "request_failure")
        .unwrap_or_else(|| panic!("expected a 4xx finding in {ranked:?}"));
    assert!(server < request, "5xx must rank above 4xx: {ranked:?}");
}

/// The order must be byte-stable across runs, or two analyses of the same
/// capture cannot be diffed and a count that moved is invisible.
#[test]
fn the_ranked_output_is_identical_across_runs() {
    let first = analyze(&mismatch(), &[]);
    let second = analyze(&mismatch(), &[]);
    assert_eq!(first, second, "the report must be deterministic");
}

// ── Flag plumbing ──────────────────────────────────────────────────────

/// Both flags write to stdout, so both belong in the output-flag tally that
/// requires `-N`. A flag missing from it produces a report the TUI then
/// scribbles over — silently, because the report was still generated.
#[test]
fn the_analyze_flags_require_non_interactive_mode() {
    for flag in ["--analyze", "--json-analyze"] {
        let (_, stderr, code) = run(&["-I", &clean_call(), flag]);
        assert_ne!(code, 0, "{flag} without -N must be refused");
        assert!(
            stderr.contains(flag),
            "the error must name {flag}: {stderr}"
        );
        assert!(
            stderr.contains("require -N/--no-tui"),
            "and must say why: {stderr}"
        );
    }
}

/// MCP owns stdout for the JSON-RPC wire, so both flags must also be in the
/// `--mcp` stdout guard — the second of the two lists in `Cli::validate`. A
/// flag in one list and not the other corrupts the JSON-RPC stream instead of
/// being refused.
#[cfg(feature = "mcp")]
#[test]
fn the_analyze_flags_are_refused_under_mcp() {
    for flag in ["--analyze", "--json-analyze"] {
        let (_, stderr, code) = run(&["-N", "--mcp", "-I", &clean_call(), flag]);
        assert_ne!(code, 0, "{flag} under --mcp must be refused");
        assert!(
            stderr.contains(flag),
            "the error must name {flag}: {stderr}"
        );
    }
}

/// Both forms can be asked for at once and must describe the same capture.
#[test]
fn text_and_json_forms_agree_about_the_same_capture() {
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        &mismatch(),
        "--analyze",
        "--json-analyze",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON object in:\n{stdout}"));
    let json: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
    let count = json["findings"]
        .as_array()
        .expect("findings is an array")
        .len();
    assert!(
        stdout.contains(&format!("{count} finding(s)")),
        "the text header must agree with the JSON array: {count} vs\n{stdout}"
    );
}

/// `--markdown` must actually change the shape — the defect #89 recorded for
/// `--report`, where the flag was read, documented and ignored.
#[test]
fn markdown_changes_the_rendering() {
    let text = analyze(&mismatch(), &[]);
    let md = analyze(&mismatch(), &["--markdown"]);
    assert_ne!(text, md, "--markdown must not be a no-op");
    assert!(md.contains("## Capture analysis"), "{md}");
    assert!(md.contains("### 1. [CRITICAL]"), "{md}");
}

/// `--filter` narrows the dialogs and nothing else: a NAT-discovery probe
/// belongs to no dialog, so narrowing it away would delete the evidence that
/// explains why the selected dialogs are broken.
#[test]
fn a_filter_narrows_dialogs_without_deleting_capture_level_evidence() {
    let json = analyze_json(&mismatch(), &["--filter", "call_id == 'nothing-matches'"]);
    assert_eq!(
        json["dialogs_examined"], 0,
        "the filter must select no dialogs: {json}"
    );
    let ranked = kinds(&json);
    assert!(
        ranked.contains(&"unanswered_stun_probe".to_string()),
        "the STUN evidence must survive a dialog filter: {ranked:?}"
    );
    assert!(
        !ranked.contains(&"one_way_audio".to_string()),
        "the filtered-out dialog's findings must be gone: {ranked:?}"
    );
}
