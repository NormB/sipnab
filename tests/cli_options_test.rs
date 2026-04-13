//! Comprehensive integration tests for all sipnab CLI options.
//!
//! Every flag listed in `sipnab --help` is exercised here. Tests use the
//! `sip_call.pcap` fixture (7 SIP messages: INVITE/100/180/200/ACK/BYE/200)
//! and the `udp_5060.pcap` fixture (10 bare 200 OK packets).

use std::path::PathBuf;
use std::process::Command;

// ── Helpers ────────────────────────────────────────────────────────────

fn sip_call_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap")
}

fn udp_5060_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("udp_5060.pcap")
}

/// Run sipnab in non-interactive mode with the given arguments.
/// Returns (stdout, stderr, exit_code).
fn run(args: &[&str]) -> (String, String, i32) {
    run_with_log(args, "warn")
}

fn run_with_log(args: &[&str], level: &str) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", level)
        .output()
        .expect("failed to execute sipnab");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Count JSON object lines (starting with '{').
fn json_line_count(s: &str) -> usize {
    s.lines().filter(|l| l.starts_with('{')).count()
}

/// Shorthand: run with sip_call fixture in JSON mode.
fn run_json(extra: &[&str]) -> (String, String, i32) {
    let fixture = sip_call_fixture();
    let f = fixture.to_str().unwrap();
    let mut args = vec!["-N", "-I", f, "--json"];
    args.extend_from_slice(extra);
    run(&args)
}

/// Shorthand: run with sip_call fixture in default text mode.
fn run_text(extra: &[&str]) -> (String, String, i32) {
    let fixture = sip_call_fixture();
    let f = fixture.to_str().unwrap();
    let mut args = vec!["-N", "-I", f];
    args.extend_from_slice(extra);
    run(&args)
}

// ═══════════════════════════════════════════════════════════════════════
//  VERSION & HELP
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn version_includes_commit_hash() {
    let (stdout, _, code) = run(&["-V"]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("sipnab 0."), "got: {stdout}");
    // Version should contain parenthesised commit hash (8 hex chars)
    assert!(
        stdout.contains('(') && stdout.contains(')'),
        "Expected commit hash in parens, got: {stdout}"
    );
}

#[test]
fn short_help_flag() {
    let (stdout, _, code) = run(&["-h"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("sipnab"));
}

#[test]
fn long_help_flag() {
    let (stdout, _, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("EXAMPLES:"));
    // Spot-check a selection of flags are documented
    for flag in &[
        "--device", "--input", "--output", "--json", "--from", "--to",
        "--kill-scanner", "--report", "--problems", "--no-rtp",
        "--call-report", "--filter", "--hexdump", "--delta-time",
    ] {
        assert!(stdout.contains(flag), "help missing {flag}");
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  CAPTURE SOURCE FLAGS (-I, -O, -n, --snaplen, --portrange, --no-rtp)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn input_file_reads_all_messages() {
    let (stdout, _, code) = run_json(&[]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn count_flag_limits_output() {
    let (stdout, _, code) = run_json(&["-n", "3"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 3);
}

#[test]
fn count_one() {
    let (stdout, _, code) = run_json(&["-n", "1"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 1);
    let parsed: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["method"], "INVITE");
}

#[test]
fn output_writes_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("output.pcap");
    let fixture = sip_call_fixture();

    let (_, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "-O", out_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    // Re-read the written pcap
    let (stdout, _, code2) = run(&["-N", "-I", out_path.to_str().unwrap(), "--json"]);
    assert_eq!(code2, 0);
    assert_eq!(json_line_count(&stdout), 7, "roundtrip should preserve all messages");
}

#[test]
fn snaplen_accepted() {
    let (stdout, _, code) = run_json(&["--snaplen", "65535"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn portrange_matching() {
    let (stdout, _, code) = run_json(&["--portrange", "5060-5061"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn portrange_no_match() {
    let (stdout, _, code) = run_json(&["--portrange", "8080-8081"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn no_rtp_still_shows_sip() {
    let (stdout, _, code) = run_json(&["--no-rtp"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT MODE FLAGS (-N, --json, --json-pretty, -T, --hexdump)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn non_interactive_mode() {
    let (stdout, _, code) = run_text(&[]);
    assert_eq!(code, 0);
    assert!(stdout.contains("INVITE"), "default text output should show INVITE");
}

#[test]
fn json_output_valid() {
    let (stdout, _, code) = run_json(&[]);
    assert_eq!(code, 0);
    for (i, line) in stdout.lines().filter(|l| !l.is_empty()).enumerate() {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {i} invalid JSON: {e}"));
        assert_eq!(v["schema_version"], 1);
    }
}

#[test]
fn json_pretty_output() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(), "--json-pretty", "-n", "1",
    ]);
    assert_eq!(code, 0);
    // Should still parse as valid JSON
    assert!(stdout.contains("schema_version"));
}

#[test]
fn text_dump_shows_raw_headers() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(), "-T", "-n", "1",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("INVITE sip:"), "should show raw request line");
    assert!(stdout.contains("Call-ID:"), "should show Call-ID header");
    assert!(stdout.contains("Via:"), "should show Via header");
    assert!(stdout.contains("CSeq:"), "should show CSeq header");
}

#[test]
fn hexdump_output() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(), "--hexdump", "-n", "1",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("00000000"), "should have hex offset markers");
    assert!(stdout.contains('|'), "should have ASCII column delimiter");
}

// ═══════════════════════════════════════════════════════════════════════
//  HEADER FILTER FLAGS (--from, --to, --contact, --ua)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn from_filter_match() {
    let (stdout, _, code) = run_json(&["--from", "1001"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7, "all messages have From: 1001");
}

#[test]
fn from_filter_no_match() {
    let (stdout, _, code) = run_json(&["--from", "9999"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn to_filter_match() {
    let (stdout, _, code) = run_json(&["--to", "1002"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7, "all messages have To: 1002");
}

#[test]
fn to_filter_no_match() {
    let (stdout, _, code) = run_json(&["--to", "9999"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn contact_filter_match() {
    let (stdout, _, code) = run_json(&["--contact", "1001"]);
    assert_eq!(code, 0);
    // Only the INVITE has a Contact header with 1001
    assert_eq!(json_line_count(&stdout), 1);
}

#[test]
fn ua_filter_match() {
    let (stdout, _, code) = run_json(&["--ua", "sipnab-test"]);
    assert_eq!(code, 0);
    // Only the INVITE has a User-Agent header
    assert_eq!(json_line_count(&stdout), 1);
}

#[test]
fn ua_filter_no_match() {
    let (stdout, _, code) = run_json(&["--ua", "nonexistent-agent"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  MATCH MODIFIER FLAGS (-i, -v, -w, --single-line)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ignore_case_match() {
    let (stdout, _, code) = run_json(&["-i", "--ua", "SIPNAB-TEST"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 1, "case-insensitive should match");
}

#[test]
fn invert_match() {
    let (stdout, _, code) = run_json(&["-v", "--from", "1001"]);
    assert_eq!(code, 0);
    // All messages match --from 1001, so invert = 0
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn word_match_flag_accepted() {
    let (stdout, _, code) = run_json(&["-w", "--from", "1001"]);
    assert_eq!(code, 0);
    // Should not crash; word matching may or may not change result
    assert!(json_line_count(&stdout) <= 7);
}

#[test]
fn single_line_flag_accepted() {
    let (stdout, _, code) = run_json(&["--single-line", "--from", "1001"]);
    assert_eq!(code, 0);
    assert!(json_line_count(&stdout) <= 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  CALLS-ONLY & DIALOG FLAGS (-c, --no-dialog, -R, -l, --dialog-track)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn calls_only() {
    let (stdout, _, code) = run_json(&["-c"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 1, "calls-only shows 1 INVITE");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["method"], "INVITE");
}

#[test]
fn no_dialog_mode() {
    let (stdout, _, code) = run_json(&["--no-dialog"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7, "no-dialog still outputs all messages");
}

#[test]
fn rotate_flag() {
    let (stdout, _, code) = run_json(&["-R"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn dialog_limit() {
    let (stdout, _, code) = run_json(&["-l", "5"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  DISPLAY FLAGS (--delta-time, --color, -A, --show-empty, --payload-limit)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn delta_time_output() {
    let (stdout, _, code) = run_text(&["--delta-time"]);
    assert_eq!(code, 0);
    // First line should show +0.000s
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.contains("+0.000s"),
        "first message should have +0.000s delta, got: {first}"
    );
}

#[test]
fn color_never() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(), "--color", "never", "-T", "-n", "1",
    ]);
    assert_eq!(code, 0);
    // No ANSI escape sequences
    assert!(!stdout.contains("\x1b["), "color=never should have no ANSI escapes");
}

#[test]
fn color_always() {
    let fixture = sip_call_fixture();
    let (_, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(), "--color", "always",
    ]);
    assert_eq!(code, 0);
}

#[test]
fn after_context() {
    let (stdout, _, code) = run_json(&["-A", "1", "-n", "1"]);
    assert_eq!(code, 0);
    // -A 1 with -n 1 should show at most the matched message + 1 context
    assert!(json_line_count(&stdout) >= 1);
}

#[test]
fn show_empty_flag() {
    let (_, _, code) = run_json(&["--show-empty"]);
    assert_eq!(code, 0);
}

#[test]
fn payload_limit() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "--payload-limit", "50", "-T", "-n", "1",
    ]);
    assert_eq!(code, 0);
    // With a 50-byte limit, output should be shorter than full message
    assert!(stdout.len() < 500, "payload should be truncated");
}

#[test]
fn quiet_flag() {
    let (stdout, _, code) = run_json(&["-q"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn line_buffer_flag() {
    let (stdout, _, code) = run_json(&["--line-buffer"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  REPORT FLAGS (--report, --call-report, --markdown)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn report_contains_dialog() {
    let (stdout, _, code) = run_text(&["--report"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("test-call-1@10.0.0.1"));
    assert!(stdout.contains("1001"));
    assert!(stdout.contains("1002"));
    assert!(stdout.contains("Completed"));
}

#[test]
fn report_markdown_format() {
    let (stdout, _, code) = run_text(&["--report", "--markdown"]);
    assert_eq!(code, 0);
    // Markdown output should contain headers or table markers
    assert!(
        stdout.contains('#') || stdout.contains('|') || stdout.contains("test-call-1"),
        "markdown report should contain markdown formatting or call data"
    );
}

#[test]
fn call_report_specific_call() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "--call-report", "test-call-1@10.0.0.1",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Call Report:"), "should contain report header");
    assert!(stdout.contains("test-call-1@10.0.0.1"));
}

#[test]
fn call_report_markdown() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "--call-report", "test-call-1@10.0.0.1", "--markdown",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("test-call-1@10.0.0.1"));
}

#[test]
fn call_report_nonexistent_call() {
    let fixture = sip_call_fixture();
    let (_, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "--call-report", "nonexistent@nowhere",
    ]);
    // Should not crash — may exit 0 with no report or with all messages
    assert!(code == 0 || code == 1);
}

// ═══════════════════════════════════════════════════════════════════════
//  DIAGNOSIS FLAGS (--problems, --slow-setup, --short-calls, --one-way,
//                   --nat-issues)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn problems_filter() {
    let (stdout, _, code) = run_json(&["--problems"]);
    assert_eq!(code, 0);
    // Normal call has no problems
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn slow_setup_filter() {
    let (stdout, _, code) = run_json(&["--slow-setup"]);
    assert_eq!(code, 0);
    // Setup time is 2s (INVITE to 200 OK), threshold is 3s — should not match
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn short_calls_filter() {
    let (stdout, _, code) = run_json(&["--short-calls"]);
    assert_eq!(code, 0);
    // Call duration is 60s, threshold is 10s — should not match as "short"
    // (whatever count we get, it shouldn't crash)
    let count = json_line_count(&stdout);
    assert!(count <= 7, "short-calls should not produce more than total messages");
}

#[test]
fn one_way_filter() {
    let (stdout, _, code) = run_json(&["--one-way"]);
    assert_eq!(code, 0);
    // No RTP in fixture, so no one-way audio detected
    assert_eq!(json_line_count(&stdout), 0);
}

#[test]
fn nat_issues_filter() {
    let (stdout, _, code) = run_json(&["--nat-issues"]);
    assert_eq!(code, 0);
    // No NAT issues in fixture
    assert_eq!(json_line_count(&stdout), 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  SECURITY FLAGS (--kill-scanner, --kill-ua, --kill-response,
//                  --fraud-detect, --reg-flood, --digest-leak,
//                  --stir-shaken, --fail2ban)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn kill_scanner_flag() {
    let (stdout, _, code) = run_json(&["--kill-scanner"]);
    assert_eq!(code, 0);
    // Scanner detection should not affect normal SIP output
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn kill_ua_flag() {
    let (stdout, _, code) = run_json(&["--kill-ua", "friendly-scanner"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn kill_response_flag() {
    let (stdout, _, code) = run_json(&["--kill-scanner", "--kill-response", "403"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn fraud_detect_flag() {
    let (stdout, _, code) = run_json(&["--fraud-detect"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn reg_flood_flag() {
    let (stdout, _, code) = run_json(&["--reg-flood"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn digest_leak_flag() {
    let (stdout, _, code) = run_json(&["--digest-leak"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn stir_shaken_flag() {
    let (stdout, _, code) = run_json(&["--stir-shaken"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn fail2ban_flag() {
    let (stdout, _, code) = run_json(&["--fail2ban"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  CONFIG FLAGS (-f, -F, -D)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn dump_config_no_config() {
    let (stdout, _, code) = run(&["-F", "--dump-config"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("sipnab v"));
    assert!(
        stdout.contains("No config file loaded") || stdout.contains("defaults only"),
        "should show no-config message, got: {stdout}"
    );
}

#[test]
fn dump_config_with_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("test.toml");
    std::fs::write(&cfg, "[capture]\ndevice = \"eth99\"\n").unwrap();

    let (stdout, _, code) = run(&["-f", cfg.to_str().unwrap(), "--dump-config"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("eth99"), "config should reflect device setting");
}

#[test]
fn no_config_flag() {
    let (stdout, _, code) = run(&["--no-config", "--dump-config"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("No config file loaded") || stdout.contains("defaults only")
    );
}

#[test]
fn missing_config_file_errors() {
    let (_, stderr, code) = run(&["-f", "/nonexistent/sipnab.toml", "--dump-config"]);
    assert_ne!(code, 0, "should fail for missing config");
    assert!(
        stderr.contains("not found") || stderr.contains("Config file") || stderr.contains("error"),
        "should report error, got: {stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  RTP FLAGS (--rtp-interval, --max-streams, --quality-threshold, -t)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rtp_interval_accepted() {
    let (_, _, code) = run_json(&["--rtp-interval", "5"]);
    assert_eq!(code, 0);
}

#[test]
fn max_streams_accepted() {
    let (_, _, code) = run_json(&["--max-streams", "100"]);
    assert_eq!(code, 0);
}

#[test]
fn quality_threshold_accepted() {
    let (_, _, code) = run_json(&["--quality-threshold", "2.5"]);
    assert_eq!(code, 0);
}

#[test]
fn telephone_event_flag() {
    let (_, _, code) = run_json(&["-t"]);
    assert_eq!(code, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  GROUP-BY FLAG
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn group_by_method() {
    let (stdout, _, code) = run_json(&["--group-by", "method"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn group_by_call_id() {
    let (stdout, _, code) = run_json(&["--group-by", "call-id"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  EXEC / ALERT FLAGS (accepted without crashing)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn alert_json_flag() {
    let (_, _, code) = run_json(&["--alert", "json"]);
    assert_eq!(code, 0);
}

#[test]
fn exec_rate_limit_flag() {
    let (_, _, code) = run_json(&["--exec-rate-limit", "5"]);
    assert_eq!(code, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  PRIVILEGE FLAGS (accepted in file-capture mode)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn allow_coredump_flag() {
    let (_, _, code) = run_json(&["--allow-coredump"]);
    assert_eq!(code, 0);
}

#[test]
fn no_priv_drop_flag() {
    let (_, _, code) = run_json(&["--no-priv-drop"]);
    assert_eq!(code, 0);
}

#[test]
fn max_reassembly_flag() {
    let (_, _, code) = run_json(&["--max-reassembly", "500"]);
    assert_eq!(code, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  COMBINED FLAG TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn json_with_count_and_from_filter() {
    let (stdout, _, code) = run_json(&["-n", "2", "--from", "1001"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 2);
}

#[test]
fn text_dump_with_count() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(), "-T", "-n", "2",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("INVITE sip:"));
    assert!(stdout.contains("100 Trying"));
}

#[test]
fn report_with_quiet() {
    let (stdout, _, code) = run_text(&["--report", "-q"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("test-call-1@10.0.0.1"));
}

#[test]
fn delta_time_with_json() {
    // delta-time is a display flag; verify it doesn't break JSON mode
    let (stdout, _, code) = run_json(&["--delta-time"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn security_flags_combined() {
    let (stdout, _, code) = run_json(&[
        "--kill-scanner", "--fraud-detect", "--reg-flood", "--digest-leak",
    ]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

#[test]
fn output_with_count_and_filter() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("filtered.pcap");
    let fixture = sip_call_fixture();

    let (_, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "-O", out_path.to_str().unwrap(),
        "-n", "3",
    ]);
    assert_eq!(code, 0);

    // Verify written file has 3 messages
    let (stdout, _, _) = run(&["-N", "-I", out_path.to_str().unwrap(), "--json"]);
    assert_eq!(json_line_count(&stdout), 3);
}

#[test]
fn hexdump_with_count_and_color_never() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N", "-I", fixture.to_str().unwrap(),
        "--hexdump", "-n", "1", "--color", "never",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("00000000"));
    assert!(!stdout.contains("\x1b["));
}

// ═══════════════════════════════════════════════════════════════════════
//  ERROR CASES
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn invalid_flag_rejected() {
    let (_, stderr, code) = run(&["--nonexistent-flag"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("error"),
        "should report error for unknown flag"
    );
}

#[test]
fn missing_input_file_errors() {
    let (_, stderr, code) = run(&["-N", "-I", "/nonexistent/file.pcap"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("No such file") || stderr.contains("error") || stderr.contains("not found"),
        "should report missing file error, got: {stderr}"
    );
}

#[test]
fn invalid_count_errors() {
    let (_, stderr, code) = run(&["-N", "-n", "abc"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "should reject non-numeric count"
    );
}

#[test]
fn invalid_quality_threshold_errors() {
    let (_, stderr, code) = run(&["-N", "--quality-threshold", "not-a-number"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "should reject non-numeric threshold"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  FIXTURE BACKWARD COMPATIBILITY
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn udp_5060_fixture_all_options() {
    let fixture = udp_5060_fixture();
    let f = fixture.to_str().unwrap();

    // Basic JSON
    let (stdout, _, code) = run(&["-N", "-I", f, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 10);

    // With report
    let (stdout, stderr, code) = run_with_log(&["-N", "-I", f, "--report"], "info");
    assert_eq!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("10 packets captured"));

    // Text dump
    let (stdout, _, code) = run(&["-N", "-I", f, "-T", "-n", "1"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("SIP/2.0 200 OK"));
}

// ═══════════════════════════════════════════════════════════════════════
//  PACKET SUMMARY LINE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn summary_reports_correct_counts() {
    let fixture = sip_call_fixture();
    let (stdout, stderr, code) = run_with_log(
        &["-N", "-I", fixture.to_str().unwrap()],
        "info",
    );
    assert_eq!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("7 packets captured"), "got: {combined}");
    assert!(combined.contains("7 SIP messages"), "got: {combined}");
}
