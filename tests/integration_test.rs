//! Integration tests for the full sipnab capture-to-output pipeline.
//!
//! These tests exercise the binary end-to-end using file capture mode,
//! verifying that SIP messages are detected, parsed, tracked into dialogs,
//! and output in the requested format.

use std::path::PathBuf;
use std::process::Command;

/// Path to the SIP call fixture (INVITE/100/180/200/ACK/BYE/200).
fn sip_call_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap")
}

/// Path to the original minimal fixture (10 bare 200 OK packets).
fn udp_5060_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("udp_5060.pcap")
}

/// Run sipnab with the given arguments and return (stdout, stderr, exit_code).
/// Log level defaults to "warn" to suppress noise; use `run_sipnab_with_log`
/// for explicit control.
fn run_sipnab(args: &[&str]) -> (String, String, i32) {
    run_sipnab_with_log(args, "warn")
}

/// Run sipnab with explicit log level control.
fn run_sipnab_with_log(args: &[&str], log_level: &str) -> (String, String, i32) {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let output = Command::new(binary)
        .args(args)
        .env("SIPNAB_LOG", log_level)
        .output()
        .expect("failed to execute sipnab");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    (stdout, stderr, code)
}

// ── SIP detection and JSON output ───────────────────────────────────

#[test]
fn sip_messages_detected_and_output_as_json() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) = run_sipnab(&["-N", "-I", fixture.to_str().unwrap(), "--json"]);

    assert_eq!(code, 0, "should exit successfully");

    // Each line should be valid JSON with a schema_version field
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 7, "fixture has 7 SIP messages");

    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {i} is not valid JSON: {e}"));
        assert_eq!(
            parsed["schema_version"], 1,
            "line {i} should have schema_version=1"
        );
        assert!(
            parsed["call_id"].is_string(),
            "line {i} should have a call_id"
        );
    }

    // First message should be an INVITE
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["method"], "INVITE");
    assert_eq!(first["is_request"], true);
    assert_eq!(first["call_id"], "test-call-1@10.0.0.1");

    // Fourth message should be a 200 OK response
    let fourth: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(fourth["status_code"], 200);
    assert_eq!(fourth["is_request"], false);
}

// ── Dialog report ───────────────────────────────────────────────────

#[test]
fn report_contains_dialog_info() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) = run_sipnab(&["-N", "-I", fixture.to_str().unwrap(), "--report"]);

    assert_eq!(code, 0);

    // Report should contain the Call-ID
    assert!(
        stdout.contains("test-call-1@10.0.0.1"),
        "report should contain the Call-ID"
    );

    // Report should show from/to users
    assert!(stdout.contains("1001"), "report should contain From user");
    assert!(stdout.contains("1002"), "report should contain To user");

    // Report should show Completed state (INVITE -> 200 OK -> BYE -> 200 OK)
    assert!(
        stdout.contains("Completed"),
        "report should show Completed state"
    );

    // Report should show PDD (time from INVITE to 180 Ringing = 0.5s)
    assert!(stdout.contains("0.5s"), "report should contain PDD of 0.5s");
}

// ── Count limit ─────────────────────────────────────────────────────

#[test]
fn count_limit_stops_after_n_packets() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) =
        run_sipnab(&["-N", "-I", fixture.to_str().unwrap(), "--json", "-n", "3"]);

    assert_eq!(code, 0);

    let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(json_lines.len(), 3, "should output exactly 3 JSON messages");
}

// ── From filter ─────────────────────────────────────────────────────

#[test]
fn from_filter_selects_matching_messages() {
    let fixture = sip_call_fixture();

    // All messages have From: sip:1001@... so --from 1001 matches everything
    let (stdout, _stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json",
        "--from",
        "1001",
    ]);

    assert_eq!(code, 0);
    let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(json_lines.len(), 7, "all messages match --from 1001");
}

#[test]
fn from_filter_rejects_nonmatching_messages() {
    let fixture = sip_call_fixture();

    // --from 9999 matches nothing
    let (stdout, _stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json",
        "--from",
        "9999",
    ]);

    assert_eq!(code, 0);
    let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(json_lines.len(), 0, "no messages should match --from 9999");
}

// ── Calls-only filter ───────────────────────────────────────────────

#[test]
fn calls_only_shows_invite_only() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) =
        run_sipnab(&["-N", "-I", fixture.to_str().unwrap(), "--json", "-c"]);

    assert_eq!(code, 0);
    let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(json_lines.len(), 1, "calls-only should show 1 INVITE");

    let parsed: serde_json::Value = serde_json::from_str(json_lines[0]).unwrap();
    assert_eq!(parsed["method"], "INVITE");
}

// ── Summary line ────────────────────────────────────────────────────

#[test]
fn summary_reports_packet_counts() {
    let fixture = sip_call_fixture();
    let (stdout, stderr, code) =
        run_sipnab_with_log(&["-N", "-I", fixture.to_str().unwrap()], "info");

    assert_eq!(code, 0);

    // The summary line goes to stderr (via log::info!)
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("7 packets captured"),
        "should report 7 packets captured: got:\n{combined}"
    );
    assert!(
        combined.contains("7 SIP messages"),
        "should report 7 SIP messages: got:\n{combined}"
    );
}

// ── Hexdump ─────────────────────────────────────────────────────────

#[test]
fn hexdump_shows_hex_output() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--hexdump",
        "-n",
        "1",
    ]);

    assert_eq!(code, 0);
    // Hexdump output should contain hex offset markers
    assert!(
        stdout.contains("00000000"),
        "hexdump should contain offset markers"
    );
    // Should contain pipe delimiters for ASCII column
    assert!(stdout.contains('|'), "hexdump should contain ASCII column");
}

// ── No capture source ───────────────────────────────────────────────

#[test]
fn no_source_exits_cleanly() {
    let (_stdout, _stderr, code) = run_sipnab(&["-N", "-F"]);
    // Should exit 0 with info message, not crash
    assert_eq!(code, 0);
}

// ── Original fixture backward compat ────────────────────────────────

#[test]
fn original_fixture_still_works() {
    let fixture = udp_5060_fixture();
    let (stdout, stderr, code) =
        run_sipnab_with_log(&["-N", "-I", fixture.to_str().unwrap()], "info");

    assert_eq!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("10 packets captured"),
        "should report 10 packets: got:\n{combined}"
    );
    // Messages are SIP (200 OK) but have no Call-ID, so SIP count should still be 10
    assert!(
        combined.contains("10 SIP messages"),
        "should detect 10 SIP messages: got:\n{combined}"
    );
}

// ── Text dump mode ──────────────────────────────────────────────────

#[test]
fn text_dump_shows_raw_sip() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) =
        run_sipnab(&["-N", "-I", fixture.to_str().unwrap(), "-T", "-n", "1"]);

    assert_eq!(code, 0);
    assert!(
        stdout.contains("INVITE sip:"),
        "text dump should contain raw INVITE line"
    );
    assert!(
        stdout.contains("Call-ID:"),
        "text dump should contain Call-ID header"
    );
}
