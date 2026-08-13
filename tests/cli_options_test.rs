// SPDX-License-Identifier: MIT OR Apache-2.0

//! Comprehensive integration tests for all sipnab CLI options.
//!
//! Every flag listed in `sipnab --help` is exercised here. Tests use the
//! `sip_call.pcap` fixture (7 SIP messages: INVITE/100/180/200/ACK/BYE/200)
//! and the `udp_5060.pcap` fixture (10 bare 200 OK packets).

use std::path::PathBuf;

#[path = "support/run.rs"]
mod run_support;

// Builds the pcapng-with-Decryption-Secrets-Block fixtures the
// `--strip-secrets` tests at the end of this file need; no checked-in sample
// carries a DSB.
#[path = "support/pcap_build.rs"]
mod pcap_build;

// ── Helpers ────────────────────────────────────────────────────────────

/// Absolute path to `tests/fixtures/sip_call.pcap` (7-message complete call:
/// INVITE/100/180/200/ACK/BYE/200).
fn sip_call_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap")
}

/// Absolute path to `tests/fixtures/udp_5060.pcap` (10 bare 200 OK packets).
fn udp_5060_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("udp_5060.pcap")
}

/// Run sipnab in non-interactive mode with the given arguments.
/// Returns (stdout, stderr, exit_code). Logs are set to `warn`.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary as a subprocess.
fn run(args: &[&str]) -> (String, String, i32) {
    run_with_log(args, "warn")
}

/// Runs the `sipnab` binary under the shared test baseline (see
/// [`run_support::run`]) with an explicit `SIPNAB_LOG` level.
///
/// # Arguments
/// * `args` — CLI arguments to pass.
/// * `level` — value for the `SIPNAB_LOG` env var (e.g. `warn`, `info`).
///
/// # Returns
/// `(stdout, stderr, exit_code)`; exit code is -1 if killed by a signal.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary as a subprocess.
fn run_with_log(args: &[&str], level: &str) -> (String, String, i32) {
    let (stdout, stderr, code) = run_support::run(args, Some(level));
    (stdout, stderr, code.unwrap_or(-1))
}

/// Count JSON object lines (starting with '{').
fn json_line_count(s: &str) -> usize {
    s.lines().filter(|l| l.starts_with('{')).count()
}

/// Shorthand: run with the sip_call fixture in JSON mode (`-N -I <fixture>
/// --json` plus `extra` args); returns `(stdout, stderr, exit_code)`.
fn run_json(extra: &[&str]) -> (String, String, i32) {
    let fixture = sip_call_fixture();
    let f = fixture.to_str().unwrap();
    let mut args = vec!["-N", "-I", f, "--json"];
    args.extend_from_slice(extra);
    run(&args)
}

/// Shorthand: run with the sip_call fixture in default text mode (`-N -I
/// <fixture>` plus `extra` args); returns `(stdout, stderr, exit_code)`.
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

/// `-V` exits 0 with `sipnab 0.` plus a parenthesised commit hash.
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

/// `-h` exits 0 and shows a `Usage:` line naming sipnab.
#[test]
fn short_help_flag() {
    let (stdout, _, code) = run(&["-h"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("sipnab"));
}

/// `--help` exits 0, has an `EXAMPLES:` section, and documents a spot-check set of flags.
#[test]
fn long_help_flag() {
    let (stdout, _, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("EXAMPLES:"));
    // Spot-check a selection of flags are documented
    for flag in &[
        "--device",
        "--input",
        "--output",
        "--json",
        "--from",
        "--to",
        "--kill-scanner",
        "--report",
        "--problems",
        "--no-rtp",
        "--call-report",
        "--filter",
        "--hexdump",
        "--delta-time",
    ] {
        assert!(stdout.contains(flag), "help missing {flag}");
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  CAPTURE SOURCE FLAGS (-I, -O, -n, --snaplen, --portrange, --no-rtp)
// ═══════════════════════════════════════════════════════════════════════

/// `-I sip_call.pcap --json` emits all 7 SIP messages.
#[test]
fn input_file_reads_all_messages() {
    let (stdout, _, code) = run_json(&[]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `-n 3` limits JSON output to exactly 3 messages.
#[test]
fn count_flag_limits_output() {
    let (stdout, _, code) = run_json(&["-n", "3"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 3);
}

/// `-n 1` emits exactly one message and it is the INVITE.
#[test]
fn count_one() {
    let (stdout, _, code) = run_json(&["-n", "1"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 1);
    let parsed: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["method"], "INVITE");
}

/// `-O <file>` writes a pcap that re-reads to the same 7 messages.
#[test]
fn output_writes_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("output.pcap");
    let fixture = sip_call_fixture();

    let (_, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "-O",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    // Re-read the written pcap
    let (stdout, _, code2) = run(&["-N", "-I", out_path.to_str().unwrap(), "--json"]);
    assert_eq!(code2, 0);
    assert_eq!(
        json_line_count(&stdout),
        7,
        "roundtrip should preserve all messages"
    );
}

/// `--snaplen 65535` is accepted and all 7 messages still parse.
#[test]
fn snaplen_accepted() {
    let (stdout, _, code) = run_json(&["--snaplen", "65535"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--portrange 5060-5061` (the fixture's ports) passes all 7 messages.
#[test]
fn portrange_matching() {
    let (stdout, _, code) = run_json(&["--portrange", "5060-5061"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// A non-matching `--portrange 8080-8081` yields zero messages.
#[test]
fn portrange_no_match() {
    let (stdout, _, code) = run_json(&["--portrange", "8080-8081"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

/// `--no-rtp` still emits all 7 SIP messages (only RTP analysis is disabled).
#[test]
fn no_rtp_still_shows_sip() {
    let (stdout, _, code) = run_json(&["--no-rtp"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT MODE FLAGS (-N, --json, --json-pretty, -T, --hexdump)
// ═══════════════════════════════════════════════════════════════════════

/// Default `-N` text output includes the INVITE method.
#[test]
fn non_interactive_mode() {
    let (stdout, _, code) = run_text(&[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("INVITE"),
        "default text output should show INVITE"
    );
}

/// Every `--json` line parses as JSON and carries `schema_version` 1.
#[test]
fn json_output_valid() {
    let (stdout, _, code) = run_json(&[]);
    assert_eq!(code, 0);
    for (i, line) in stdout.lines().filter(|l| !l.is_empty()).enumerate() {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i} invalid JSON: {e}"));
        assert_eq!(v["schema_version"], 1);
    }
}

/// `--json-pretty` exits 0 and the output still contains `schema_version`.
#[test]
fn json_pretty_output() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json-pretty",
        "-n",
        "1",
    ]);
    assert_eq!(code, 0);
    // Should still parse as valid JSON
    assert!(stdout.contains("schema_version"));
}

/// `-T` shows the raw request line plus Call-ID, Via, and CSeq headers.
#[test]
fn text_dump_shows_raw_headers() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&["-N", "-I", fixture.to_str().unwrap(), "-T", "-n", "1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("INVITE sip:"),
        "should show raw request line"
    );
    assert!(stdout.contains("Call-ID:"), "should show Call-ID header");
    assert!(stdout.contains("Via:"), "should show Via header");
    assert!(stdout.contains("CSeq:"), "should show CSeq header");
}

/// `--hexdump` output has hex offset markers and the ASCII column delimiter.
#[test]
fn hexdump_output() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--hexdump",
        "-n",
        "1",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("00000000"),
        "should have hex offset markers"
    );
    assert!(stdout.contains('|'), "should have ASCII column delimiter");
}

// ═══════════════════════════════════════════════════════════════════════
//  HEADER FILTER FLAGS (--from, --to, --contact, --ua)
// ═══════════════════════════════════════════════════════════════════════

/// `--from 1001` matches all 7 messages (shared From header).
#[test]
fn from_filter_match() {
    let (stdout, _, code) = run_json(&["--from", "1001"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7, "all messages have From: 1001");
}

/// A non-matching `--from 9999` yields zero messages.
#[test]
fn from_filter_no_match() {
    let (stdout, _, code) = run_json(&["--from", "9999"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

/// `--to 1002` matches all 7 messages (shared To header).
#[test]
fn to_filter_match() {
    let (stdout, _, code) = run_json(&["--to", "1002"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7, "all messages have To: 1002");
}

/// A non-matching `--to 9999` yields zero messages.
#[test]
fn to_filter_no_match() {
    let (stdout, _, code) = run_json(&["--to", "9999"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

/// `--contact 1001` matches only the INVITE (the sole message with Contact).
#[test]
fn contact_filter_match() {
    let (stdout, _, code) = run_json(&["--contact", "1001"]);
    assert_eq!(code, 0);
    // Only the INVITE has a Contact header with 1001
    assert_eq!(json_line_count(&stdout), 1);
}

/// `--ua sipnab-test` matches only the INVITE (the sole message with User-Agent).
#[test]
fn ua_filter_match() {
    let (stdout, _, code) = run_json(&["--ua", "sipnab-test"]);
    assert_eq!(code, 0);
    // Only the INVITE has a User-Agent header
    assert_eq!(json_line_count(&stdout), 1);
}

/// A non-matching `--ua` pattern yields zero messages.
#[test]
fn ua_filter_no_match() {
    let (stdout, _, code) = run_json(&["--ua", "nonexistent-agent"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  MATCH MODIFIER FLAGS (-i, -v, -w, --single-line)
// ═══════════════════════════════════════════════════════════════════════

/// `-i` makes the upper-cased `--ua SIPNAB-TEST` match the one UA-bearing message.
#[test]
fn ignore_case_match() {
    let (stdout, _, code) = run_json(&["-i", "--ua", "SIPNAB-TEST"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 1, "case-insensitive should match");
}

/// `-v --from 1001` inverts an all-match filter to zero messages.
#[test]
fn invert_match() {
    let (stdout, _, code) = run_json(&["-v", "--from", "1001"]);
    assert_eq!(code, 0);
    // All messages match --from 1001, so invert = 0
    assert_eq!(json_line_count(&stdout), 0);
}

/// `-w` enforces whole-word matching: `--from 100` matches as a substring of
/// every `1001` From header without it, but `-w` demands a word boundary and
/// so rejects `100` inside `1001`.
#[test]
fn word_match_restricts_to_whole_words() {
    // Substring semantics (default): "100" is inside every "1001".
    let (loose, _, code) = run_json(&["--from", "100"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&loose),
        7,
        "without -w, substring '100' matches all 7 From: 1001 headers"
    );
    // Whole-word semantics: "100" is not a word inside "1001", so no match.
    let (strict, _, code) = run_json(&["-w", "--from", "100"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&strict),
        0,
        "-w requires a word boundary, so '100' no longer matches '1001' \
         (this fails if -w is a no-op — it would still report 7)"
    );
}

/// `--single-line` stops `.` in a match pattern from spanning header lines.
/// A pattern crossing the request line and the User-Agent header matches by
/// default (dot matches newline) but not under `--single-line`.
#[test]
fn single_line_stops_dot_matching_newline() {
    // "INVITE" is on the request line; "sipnab" is in the User-Agent header a
    // few lines below. Matching the INVITE follows its dialog → all 7 messages.
    let (spanning, _, code) = run_json(&["-e", "INVITE.*sipnab"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&spanning),
        7,
        "by default '.' matches newlines, so the cross-line pattern hits the INVITE"
    );
    // With --single-line, '.' no longer crosses the newline between the
    // request line and the User-Agent header, so the pattern misses entirely.
    let (restricted, _, code) = run_json(&["--single-line", "-e", "INVITE.*sipnab"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&restricted),
        0,
        "--single-line makes '.' stop at newlines (this fails if the flag is a \
         no-op — the cross-line pattern would still match all 7)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  CALLS-ONLY & DIALOG FLAGS (-c, --no-dialog, -R, -l)
// ═══════════════════════════════════════════════════════════════════════

/// `-c` (calls-only) emits exactly one message and it is the INVITE.
#[test]
fn calls_only() {
    let (stdout, _, code) = run_json(&["-c"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 1, "calls-only shows 1 INVITE");
    let parsed: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["method"], "INVITE");
}

/// `--no-dialog` still emits all 7 messages (dialog tracking off, output unchanged).
#[test]
fn no_dialog_mode() {
    let (stdout, _, code) = run_json(&["--no-dialog"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&stdout),
        7,
        "no-dialog still outputs all messages"
    );
}

/// `-R` (rotate) is accepted and all 7 messages are still emitted.
#[test]
fn rotate_flag() {
    let (stdout, _, code) = run_json(&["-R"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `-l 5` (dialog limit above the fixture's 1 dialog) leaves all 7 messages.
#[test]
fn dialog_limit() {
    let (stdout, _, code) = run_json(&["-l", "5"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  DISPLAY FLAGS (--delta-time, --color, -A, --show-empty, --payload-limit)
// ═══════════════════════════════════════════════════════════════════════

/// With `--delta-time`, the first message line shows a `+0.000s` delta.
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

/// `--color never` output contains no ANSI escape sequences.
#[test]
fn color_never() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--color",
        "never",
        "-T",
        "-n",
        "1",
    ]);
    assert_eq!(code, 0);
    // No ANSI escape sequences
    assert!(
        !stdout.contains("\x1b["),
        "color=never should have no ANSI escapes"
    );
}

/// `--color always` emits ANSI escape sequences — the counterpart to the
/// `color_never` test, which asserts their absence. `--color` overrides TTY
/// detection (and `NO_COLOR`), so this holds even when stdout is a pipe.
#[test]
fn color_always_emits_ansi() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&["-N", "-I", fixture.to_str().unwrap(), "--color", "always"]);
    assert_eq!(code, 0);
    // Fails if --color always is ignored (default piped output has no escapes).
    assert!(
        stdout.contains("\x1b["),
        "color=always must emit ANSI escape sequences, got: {stdout:?}"
    );
}

/// `-A 2` includes the two messages that follow each match. `--ua sipnab-test`
/// matches only the INVITE; adding `-A 2` pulls in the following 100 and 180,
/// which would not appear otherwise.
#[test]
fn after_context_includes_following_messages() {
    // Baseline: the UA filter matches exactly the INVITE (only message with a UA).
    let (base, _, code) = run_json(&["--ua", "sipnab-test"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&base),
        1,
        "only the INVITE carries the sipnab-test User-Agent"
    );
    // -A 2 appends the next two messages (100 Trying, 180 Ringing).
    let (ctx, _, code) = run_json(&["--ua", "sipnab-test", "-A", "2"]);
    assert_eq!(code, 0);
    assert_eq!(
        json_line_count(&ctx),
        3,
        "-A 2 must add the two following messages to the single match \
         (this fails if -A is a no-op — it would still report 1)"
    );
}

/// `--show-empty` prints the full header block of bodyless messages; without
/// it they collapse to a one-line summary. The `Via:` header line only appears
/// in the expanded form, so its presence is a direct effect check.
#[test]
fn show_empty_expands_bodyless_messages() {
    let fixture = sip_call_fixture();
    let f = fixture.to_str().unwrap();
    // Default text output is one line per message — no header block, no Via.
    let (compact, _, code) = run(&["-N", "-I", f]);
    assert_eq!(code, 0);
    assert!(
        !compact.contains("Via:"),
        "default output shows one-line summaries, not header blocks:\n{compact}"
    );
    // --show-empty expands every message to its full header block.
    let (full, _, code) = run(&["-N", "-I", f, "--show-empty"]);
    assert_eq!(code, 0);
    assert!(
        full.contains("Via:"),
        "--show-empty must reveal the full header block (Via: header); \
         fails if the flag is a no-op:\n{full}"
    );
    assert!(
        full.len() > compact.len(),
        "expanded output must be larger than the one-line summaries"
    );
}

/// `--payload-limit N` truncates the printed raw message at N bytes and marks
/// it `[truncated]`. `--show-empty` forces the raw block to print (the fixture
/// messages have empty bodies), so a 50-byte limit cuts off every header past
/// the first two lines — the late User-Agent header vanishes.
#[test]
fn payload_limit_truncates_raw_dump() {
    let fixture = sip_call_fixture();
    let f = fixture.to_str().unwrap();
    // Baseline: --show-empty prints the whole INVITE, including the User-Agent
    // header well past byte 50, and no truncation marker.
    let (full, _, code) = run(&["-N", "-I", f, "--show-empty", "-n", "1"]);
    assert_eq!(code, 0);
    assert!(
        full.contains("User-Agent"),
        "full dump must include the late User-Agent header:\n{full}"
    );
    assert!(
        !full.contains("[truncated]"),
        "no truncation marker without a limit:\n{full}"
    );
    // A 50-byte limit cuts the dump short: late headers gone, marker appended.
    let (limited, _, code) = run(&[
        "-N",
        "-I",
        f,
        "--show-empty",
        "--payload-limit",
        "50",
        "-n",
        "1",
    ]);
    assert_eq!(code, 0);
    assert!(
        limited.contains("[truncated]"),
        "--payload-limit must append a [truncated] marker:\n{limited}"
    );
    assert!(
        !limited.contains("User-Agent"),
        "--payload-limit 50 must cut off headers past byte 50 (fails if the \
         flag is a no-op — the full message would still contain User-Agent):\n{limited}"
    );
    assert!(
        limited.len() < full.len(),
        "truncated dump must be shorter than the full one"
    );
}

/// `-q` still emits all 7 JSON messages (quiet only affects logs).
#[test]
fn quiet_flag() {
    let (stdout, _, code) = run_json(&["-q"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--line-buffer` still emits all 7 JSON messages.
#[test]
fn line_buffer_flag() {
    let (stdout, _, code) = run_json(&["--line-buffer"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  REPORT FLAGS (--report, --call-report, --markdown)
// ═══════════════════════════════════════════════════════════════════════

/// `--report` names the fixture Call-ID, both parties, and the Completed state.
#[test]
fn report_contains_dialog() {
    let (stdout, _, code) = run_text(&["--report"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("test-call-1@10.0.0.1"));
    assert!(stdout.contains("1001"));
    assert!(stdout.contains("1002"));
    assert!(stdout.contains("Completed"));
}

/// `--report --markdown` exits 0 and contains markdown markers or the call data.
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

/// `--call-report <call-id>` prints a `Call Report:` header for the fixture call.
#[test]
fn call_report_specific_call() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--call-report",
        "test-call-1@10.0.0.1",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Call Report:"),
        "should contain report header"
    );
    assert!(stdout.contains("test-call-1@10.0.0.1"));
}

/// `--call-report --markdown` exits 0 and includes the Call-ID.
#[test]
fn call_report_markdown() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--call-report",
        "test-call-1@10.0.0.1",
        "--markdown",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("test-call-1@10.0.0.1"));
}

/// `--call-report` for an unknown Call-ID exits 1 and explains the failure on
/// stderr. Scripts checking a specific call must be able to trust the code, so
/// the exit is pinned to 1 (not the looser 0|1) — consistent with
/// `output_behavior_test::call_report_unknown_call_id_exits_nonzero`. The
/// missing Call-ID path is `generate_reports` returning `false` →
/// `std::process::exit(1)` (src/app/batch.rs).
#[test]
fn call_report_nonexistent_call() {
    let fixture = sip_call_fixture();
    let (_, stderr, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--call-report",
        "nonexistent@nowhere",
    ]);
    assert_eq!(code, 1, "unknown Call-ID must exit 1; stderr:\n{stderr}");
    assert!(
        stderr.contains("not found"),
        "stderr must explain the missing Call-ID, got: {stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  DIAGNOSIS FLAGS (--problems, --slow-setup, --short-calls, --one-way,
//                   --nat-issues)
// ═══════════════════════════════════════════════════════════════════════

/// `--problems` on a clean call emits zero messages.
#[test]
fn problems_filter() {
    let (stdout, _, code) = run_json(&["--problems"]);
    assert_eq!(code, 0);
    // Normal call has no problems
    assert_eq!(json_line_count(&stdout), 0);
}

/// `--slow-setup` (3s threshold vs the fixture's 2s setup) emits zero messages.
#[test]
fn slow_setup_filter() {
    let (stdout, _, code) = run_json(&["--slow-setup"]);
    assert_eq!(code, 0);
    // Setup time is 2s (INVITE to 200 OK), threshold is 3s — should not match
    assert_eq!(json_line_count(&stdout), 0);
}

/// `--short-calls` is accepted and never emits more than the 7 total messages.
#[test]
fn short_calls_filter() {
    let (stdout, _, code) = run_json(&["--short-calls"]);
    assert_eq!(code, 0);
    // Call duration is 60s, threshold is 10s — should not match as "short"
    // (whatever count we get, it shouldn't crash)
    let count = json_line_count(&stdout);
    assert!(
        count <= 7,
        "short-calls should not produce more than total messages"
    );
}

/// `--one-way` on an RTP-free fixture emits zero messages.
#[test]
fn one_way_filter() {
    let (stdout, _, code) = run_json(&["--one-way"]);
    assert_eq!(code, 0);
    // No RTP in fixture, so no one-way audio detected
    assert_eq!(json_line_count(&stdout), 0);
}

/// `--nat-issues` on a clean fixture emits zero messages.
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

/// `--kill-scanner` leaves normal SIP output untouched (all 7 messages).
#[test]
fn kill_scanner_flag() {
    let (stdout, _, code) = run_json(&["--kill-scanner"]);
    assert_eq!(code, 0);
    // Scanner detection should not affect normal SIP output
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--kill-ua` with a non-matching UA leaves all 7 messages.
#[test]
fn kill_ua_flag() {
    let (stdout, _, code) = run_json(&["--kill-ua", "friendly-scanner"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--kill-scanner --kill-response 403` leaves all 7 messages.
#[test]
fn kill_response_flag() {
    let (stdout, _, code) = run_json(&["--kill-scanner", "--kill-response", "403"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--fraud-detect` leaves all 7 messages on a clean fixture.
#[test]
fn fraud_detect_flag() {
    let (stdout, _, code) = run_json(&["--fraud-detect"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--reg-flood` leaves all 7 messages on a clean fixture.
#[test]
fn reg_flood_flag() {
    let (stdout, _, code) = run_json(&["--reg-flood"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--digest-leak` leaves all 7 messages on a clean fixture.
#[test]
fn digest_leak_flag() {
    let (stdout, _, code) = run_json(&["--digest-leak"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--stir-shaken` leaves all 7 messages on a clean fixture.
#[test]
fn stir_shaken_flag() {
    let (stdout, _, code) = run_json(&["--stir-shaken"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--fail2ban` leaves all 7 JSON messages.
#[test]
fn fail2ban_flag() {
    let (stdout, _, code) = run_json(&["--fail2ban"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  CONFIG FLAGS (-f, -F, -D)
// ═══════════════════════════════════════════════════════════════════════

/// `-F --dump-config` exits 0 and reports that no config file was loaded.
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

/// `-f <file> --dump-config` echoes the file's `device = "eth99"` value.
#[test]
fn dump_config_with_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("test.toml");
    std::fs::write(&cfg, "[capture]\ndevice = \"eth99\"\n").unwrap();

    let (stdout, _, code) = run(&["-f", cfg.to_str().unwrap(), "--dump-config"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("eth99"),
        "config should reflect device setting"
    );
}

/// `--no-config --dump-config` reports defaults-only (no file loaded).
#[test]
fn no_config_flag() {
    let (stdout, _, code) = run(&["--no-config", "--dump-config"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("No config file loaded") || stdout.contains("defaults only"));
}

/// `-f /nonexistent/...` exits non-zero and reports the missing config file.
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
//  RTP FLAGS (--max-streams, --quality-threshold, -t)
// ═══════════════════════════════════════════════════════════════════════

/// `--rtp-interval` is refused outright, not accepted and ignored.
///
/// It parsed, defaulted, documented itself and reached nothing for the whole
/// of its life; the interval report it named was never built. An accepted
/// value is the worse failure of the two, because a runbook reads as
/// configured and reports nothing. clap now names the flag it does not know,
/// which is an answer an operator can act on.
#[test]
fn rtp_interval_is_refused_rather_than_accepted_and_ignored() {
    let (_, stderr, code) = run_json(&["--rtp-interval", "5"]);
    assert_ne!(code, 0, "a flag sipnab does not implement must not exit 0");
    assert!(
        stderr.contains("--rtp-interval"),
        "the refusal must name the flag; got: {stderr}"
    );
}

/// `--max-streams 100` is accepted and exits 0.
#[test]
fn max_streams_accepted() {
    let (_, _, code) = run_json(&["--max-streams", "100"]);
    assert_eq!(code, 0);
}

/// `--quality-threshold 2.5` is accepted and exits 0.
#[test]
fn quality_threshold_accepted() {
    let (_, _, code) = run_json(&["--quality-threshold", "2.5"]);
    assert_eq!(code, 0);
}

/// `-t` (telephone-event) is accepted and exits 0.
#[test]
fn telephone_event_flag() {
    let (_, _, code) = run_json(&["-t"]);
    assert_eq!(code, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  GROUP-BY FLAG
// ═══════════════════════════════════════════════════════════════════════

/// `--group-by method` still emits all 7 JSON messages.
#[test]
fn group_by_method() {
    let (stdout, _, code) = run_json(&["--group-by", "method"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `--group-by call-id` still emits all 7 JSON messages.
#[test]
fn group_by_call_id() {
    let (stdout, _, code) = run_json(&["--group-by", "call-id"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

// ═══════════════════════════════════════════════════════════════════════
//  EXEC / ALERT FLAGS (accepted without crashing)
// ═══════════════════════════════════════════════════════════════════════

/// `--alert json` is accepted and exits 0.
#[test]
fn alert_json_flag() {
    let (_, _, code) = run_json(&["--alert", "json"]);
    assert_eq!(code, 0);
}

/// `--alert-json` (structured alert channel) is accepted and exits 0.
#[test]
fn alert_json_output_flag() {
    // structured JSON alert channel (--alert-json) is accepted without crashing
    let (_, _, code) = run_json(&["--alert-json"]);
    assert_eq!(code, 0);
}

/// `--exec-rate-limit 5` is accepted and exits 0.
#[test]
fn exec_rate_limit_flag() {
    let (_, _, code) = run_json(&["--exec-rate-limit", "5"]);
    assert_eq!(code, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  PRIVILEGE FLAGS (accepted in file-capture mode)
// ═══════════════════════════════════════════════════════════════════════

/// `--allow-coredump` is accepted in file-capture mode and exits 0.
#[test]
fn allow_coredump_flag() {
    let (_, _, code) = run_json(&["--allow-coredump"]);
    assert_eq!(code, 0);
}

/// `--no-priv-drop` is accepted in file-capture mode and exits 0.
#[test]
fn no_priv_drop_flag() {
    let (_, _, code) = run_json(&["--no-priv-drop"]);
    assert_eq!(code, 0);
}

/// `--max-reassembly 500` is accepted and exits 0.
#[test]
fn max_reassembly_flag() {
    let (_, _, code) = run_json(&["--max-reassembly", "500"]);
    assert_eq!(code, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  COMBINED FLAG TESTS
// ═══════════════════════════════════════════════════════════════════════

/// `-n 2 --from 1001` composes: exactly 2 messages are emitted.
#[test]
fn json_with_count_and_from_filter() {
    let (stdout, _, code) = run_json(&["-n", "2", "--from", "1001"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 2);
}

/// `-T -n 2` shows the raw INVITE and the 100 Trying.
#[test]
fn text_dump_with_count() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&["-N", "-I", fixture.to_str().unwrap(), "-T", "-n", "2"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("INVITE sip:"));
    assert!(stdout.contains("100 Trying"));
}

/// `--report -q` still prints the report with the fixture Call-ID.
#[test]
fn report_with_quiet() {
    let (stdout, _, code) = run_text(&["--report", "-q"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("test-call-1@10.0.0.1"));
}

/// `--delta-time` does not break JSON mode: all 7 messages emitted.
#[test]
fn delta_time_with_json() {
    // delta-time is a display flag; verify it doesn't break JSON mode
    let (stdout, _, code) = run_json(&["--delta-time"]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// All four security flags together leave the 7 messages untouched.
#[test]
fn security_flags_combined() {
    let (stdout, _, code) = run_json(&[
        "--kill-scanner",
        "--fraud-detect",
        "--reg-flood",
        "--digest-leak",
    ]);
    assert_eq!(code, 0);
    assert_eq!(json_line_count(&stdout), 7);
}

/// `-O` with `-n 3` writes a pcap that re-reads as exactly 3 messages.
#[test]
fn output_with_count_and_filter() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("filtered.pcap");
    let fixture = sip_call_fixture();

    let (_, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "-O",
        out_path.to_str().unwrap(),
        "-n",
        "3",
    ]);
    assert_eq!(code, 0);

    // Verify written file has 3 messages
    let (stdout, _, _) = run(&["-N", "-I", out_path.to_str().unwrap(), "--json"]);
    assert_eq!(json_line_count(&stdout), 3);
}

/// `--hexdump --color never` shows hex offsets with no ANSI escapes.
#[test]
fn hexdump_with_count_and_color_never() {
    let fixture = sip_call_fixture();
    let (stdout, _, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--hexdump",
        "-n",
        "1",
        "--color",
        "never",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("00000000"));
    assert!(!stdout.contains("\x1b["));
}

// ═══════════════════════════════════════════════════════════════════════
//  --cores ON A SOURCE THAT CANNOT USE IT (G6)
// ═══════════════════════════════════════════════════════════════════════

/// `--cores N` with a live device runs single-threaded — parallel
/// reconstruction shards a saved capture and has no streaming equivalent. That
/// used to happen in silence: the operator asked for N cores, got one, and
/// nothing in the run said so. The device name is deliberately bogus so the
/// test needs no interface and no capture privileges; the warning is emitted
/// while planning, before anything is opened.
#[test]
fn cores_with_a_live_device_warns_that_it_is_ignored() {
    let (_stdout, stderr, _code) = run(&["-N", "--cores", "8", "-d", "sipnab-no-such-dev0"]);
    assert!(
        stderr.contains("--cores 8 is ignored"),
        "a discarded --cores request must be reported, got: {stderr}"
    );
    assert!(
        stderr.contains("-I"),
        "the warning must name the flag that would honour it, got: {stderr}"
    );
}

/// The mirror image: `--cores N -I <file>` is exactly what the parallel reader
/// is for, so it must run without the warning. A warning that fired here would
/// be noise on the one invocation that does use every core.
#[test]
fn cores_with_an_input_file_does_not_warn() {
    let fixture = sip_call_fixture();
    let (_stdout, stderr, code) = run(&[
        "-N",
        "--cores",
        "2",
        "-I",
        fixture.to_str().unwrap(),
        "--report",
    ]);
    assert_eq!(code, 0, "parallel offline reconstruction must succeed");
    assert!(
        !stderr.contains("is ignored"),
        "the honoured case must stay quiet, got: {stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  ERROR CASES
// ═══════════════════════════════════════════════════════════════════════

/// An unknown flag exits non-zero with an error on stderr.
#[test]
fn invalid_flag_rejected() {
    let (_, stderr, code) = run(&["--nonexistent-flag"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("error"),
        "should report error for unknown flag"
    );
}

/// `-I` with a nonexistent path exits non-zero and reports the missing file.
#[test]
fn missing_input_file_errors() {
    let (_, stderr, code) = run(&["-N", "-I", "/nonexistent/file.pcap"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("does not exist"),
        "should name the missing path, got: {stderr}"
    );
}

/// A non-numeric `-n abc` exits non-zero with an invalid-value error.
#[test]
fn invalid_count_errors() {
    let (_, stderr, code) = run(&["-N", "-n", "abc"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "should reject non-numeric count"
    );
}

/// A non-numeric `--quality-threshold` exits non-zero with an error.
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

/// The udp_5060 fixture works across JSON (10 messages), `--report` (packet count), and `-T` modes.
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

/// The end-of-run summary reports `7 packets captured` and `7 SIP messages`.
#[test]
fn summary_reports_correct_counts() {
    let fixture = sip_call_fixture();
    let (stdout, stderr, code) = run_with_log(&["-N", "-I", fixture.to_str().unwrap()], "info");
    assert_eq!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("7 packets captured"), "got: {combined}");
    assert!(combined.contains("7 SIP messages"), "got: {combined}");
}

// ═══════════════════════════════════════════════════════════════════════
//  --strip-secrets INPUT RESOLUTION
// ═══════════════════════════════════════════════════════════════════════
//
// `--strip-secrets` is a privacy control: it exists so an operator can hand a
// capture to a vendor without handing over the TLS keys embedded in it. It
// used to act on `cli.primary_input()` — the FIRST `-I` *argument* — while `-I`
// is repeatable and expands directories and globs. Every file past the first
// kept its Decryption Secrets Block, the command exited 0, and nothing said so.
// A partial sanitisation that reports success is worse than a refusal, so these
// tests pin both halves: one resolved file gets stripped, anything else is
// rejected loudly with the input untouched.

/// pcapng block type of a Decryption Secrets Block.
const DSB_BLOCK_TYPE: u32 = 0x0000_000a;

/// Write a one-packet pcapng carrying a TLS key-log Decryption Secrets Block.
///
/// No checked-in sample carries a DSB, so the fixtures are built here — the
/// same approach `strip_secrets_removes_the_dsb_and_preserves_the_input` in
/// `cli_flag_behavior_test.rs` takes.
///
/// # Arguments
/// * `path` — file to write.
/// * `call_id` — Call-ID of the single SIP message, so fixtures stay distinct.
///
/// # Side effects
/// Writes `path`.
fn write_pcapng_with_secrets(path: &std::path::Path, call_id: &str) {
    let payload = format!(
        "OPTIONS sip:a@b SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    );
    let frame = pcap_build::udp_frame([10, 1, 0, 1], [10, 2, 0, 1], 5060, 5060, payload.as_bytes());
    pcap_build::write_pcapng_with_dsb(path, "CLIENT_RANDOM 0011 22334455\n", &frame);
    assert_eq!(
        pcap_build::count_pcapng_blocks(path, DSB_BLOCK_TYPE),
        1,
        "fixture must start with exactly one DSB"
    );
}

/// Two `-I` arguments must be refused outright: one output path cannot hold two
/// sanitised captures, and stripping only the first ships the operator's live
/// keys to whoever receives the rest.
#[test]
fn strip_secrets_refuses_two_input_files() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.pcapng");
    let second = dir.path().join("second.pcapng");
    write_pcapng_with_secrets(&first, "strip-multi-1");
    write_pcapng_with_secrets(&second, "strip-multi-2");
    let out = dir.path().join("stripped.pcapng");

    let (_stdout, stderr, code) = run_with_log(
        &[
            "-N",
            "-I",
            first.to_str().unwrap(),
            "-I",
            second.to_str().unwrap(),
            "--strip-secrets",
            out.to_str().unwrap(),
            "--no-cli-print",
        ],
        "error",
    );

    assert_ne!(
        code, 0,
        "--strip-secrets must refuse a two-file input set instead of sanitising \
         one of them and reporting success:\n{stderr}"
    );
    assert!(
        !out.exists(),
        "a refused --strip-secrets must leave no output file behind"
    );
    for input in [&first, &second] {
        assert_eq!(
            pcap_build::count_pcapng_blocks(input, DSB_BLOCK_TYPE),
            1,
            "--strip-secrets must never modify its input ({})",
            input.display()
        );
    }
    assert!(
        stderr.contains("first.pcapng") && stderr.contains("second.pcapng"),
        "the refusal must name every file the operator pointed at, so nobody \
         assumes the unnamed ones were handled:\n{stderr}"
    );
}

/// A single `-I` naming a directory that holds several captures must be
/// refused the same way. This is the sneakier shape: the operator typed one
/// `-I`, so nothing on the command line hints that more than one file is in
/// play.
#[test]
fn strip_secrets_refuses_a_directory_of_captures() {
    let dir = tempfile::tempdir().unwrap();
    write_pcapng_with_secrets(&dir.path().join("ring-0.pcapng"), "strip-dir-0");
    write_pcapng_with_secrets(&dir.path().join("ring-1.pcapng"), "strip-dir-1");
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("stripped.pcapng");

    let (_stdout, stderr, code) = run_with_log(
        &[
            "-N",
            "-I",
            dir.path().to_str().unwrap(),
            "--strip-secrets",
            out.to_str().unwrap(),
            "--no-cli-print",
        ],
        "error",
    );

    assert_ne!(
        code, 0,
        "a directory of captures must be refused:\n{stderr}"
    );
    assert!(
        !out.exists(),
        "a refused --strip-secrets must leave no output file behind"
    );
    assert!(
        stderr.contains("ring-0.pcapng") && stderr.contains("ring-1.pcapng"),
        "the refusal must name the resolved files, not just the directory — \
         otherwise the operator cannot tell what went unsanitised:\n{stderr}"
    );
}

/// `-I <directory>` holding exactly one capture must work: the resolved file
/// is what gets stripped, not the `-I` argument as typed. Handing a directory
/// path straight to the pcapng writer fails with an unhelpful I/O error.
#[test]
fn strip_secrets_accepts_a_directory_holding_one_capture() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("only.pcapng");
    write_pcapng_with_secrets(&input, "strip-dir-single");
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("stripped.pcapng");

    let (_stdout, stderr, code) = run_with_log(
        &[
            "-N",
            "-I",
            dir.path().to_str().unwrap(),
            "--strip-secrets",
            out.to_str().unwrap(),
            "--no-cli-print",
        ],
        "error",
    );

    assert_eq!(
        code, 0,
        "a directory naming exactly one capture must be stripped:\n{stderr}"
    );
    assert_eq!(
        pcap_build::count_pcapng_blocks(&out, DSB_BLOCK_TYPE),
        0,
        "the stripped copy must contain no Decryption Secrets Block"
    );
    assert_eq!(
        pcap_build::count_pcapng_blocks(&input, DSB_BLOCK_TYPE),
        1,
        "--strip-secrets must never modify its input"
    );
}

/// `--lint` runs the conformance linter from the CLI, and `--lint-fail-on`
/// makes it a gate that exits 3 (#147).
///
/// The linter shipped reachable only over MCP, which put the project's most
/// distinctive capability out of reach of a pipeline gating a proxy config
/// change — the place it matters most.
///
/// Exit 3 is asserted specifically, not merely "non-zero". A pipeline has to
/// tell "sipnab broke" (1) from "you invoked it wrong" (2) from "the capture
/// is non-conformant" (3); the usual response to each differs completely, and
/// a gate that reports 1 is indistinguishable from a crashed tool.
#[test]
fn lint_reports_from_the_cli_and_fail_on_exits_three() {
    let cap = sip_call_fixture();
    let path = cap.to_string_lossy().into_owned();

    // Informational on its own: findings print, exit code untouched.
    let (out, err, code) = run_support::run(&["-N", "-I", &path, "--no-cli-print", "--lint"], None);
    assert_eq!(
        code,
        Some(0),
        "--lint alone must not change the exit code; it is a report, not a \
         gate:\nstdout={out}\nstderr={err}"
    );
    assert!(
        err.contains("Lint:") && err.contains("dialog(s)"),
        "the summary must name the DENOMINATOR -- '0 findings' over 0 dialogs \
         and over 900 are different answers:\n{err}"
    );

    // The gate itself. `info` is the floor, so anything the linter found at
    // all trips it — which makes this assert the WIRING rather than depending
    // on this fixture happening to contain an error-severity defect.
    let (_o2, e2, c2) = run_support::run(
        &[
            "-N",
            "-I",
            &path,
            "--no-cli-print",
            "--lint",
            "--lint-fail-on",
            "info",
        ],
        None,
    );
    let findings: u32 = e2
        .split("Lint: ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    if findings > 0 {
        assert_eq!(
            c2,
            Some(3),
            "findings at or above the threshold must exit 3, not 1 or 2:\n{e2}"
        );
    } else {
        assert_eq!(c2, Some(0), "no findings must not trip the gate:\n{e2}");
    }

    // A threshold nothing can reach must not fail the build. Guards against a
    // gate wired to "any findings at all" regardless of severity.
    let (_o3, _e3, c3) = run_support::run(
        &[
            "-N",
            "-I",
            &path,
            "--no-cli-print",
            "--lint",
            "--lint-fail-on",
            "nonsense-severity",
        ],
        None,
    );
    assert_eq!(
        c3,
        Some(0),
        "an unparseable severity must not silently become 'fail on everything'"
    );
}

/// `--cores` runs the same linter and the same gate as the batch path (#147).
///
/// A gate that silently passes under `--cores` is worse than no gate: a
/// pipeline adding `--cores 8` for speed would stop failing on non-conformant
/// captures and nothing would say so. This tree has been bitten by one input
/// getting two answers depending on the path repeatedly — the BPF refusal, the
/// post-merge sweep, the range-overlap warning — so the two paths call one
/// function rather than carrying two copies.
///
/// Asserted as EQUALITY between the paths, not as a fixed expectation. What
/// this fixture happens to contain is beside the point; that the two agree is
/// the whole property.
#[test]
fn cores_runs_the_same_lint_gate_as_the_batch_path() {
    let cap = sip_call_fixture();
    let path = cap.to_string_lossy().into_owned();
    let args = |cores: &str| {
        vec![
            "-N".to_string(),
            "-I".to_string(),
            path.clone(),
            "--no-cli-print".to_string(),
            "--lint".to_string(),
            "--lint-fail-on".to_string(),
            "info".to_string(),
            "--cores".to_string(),
            cores.to_string(),
        ]
    };
    let one_args = args("1");
    let many_args = args("4");
    let one_refs: Vec<&str> = one_args.iter().map(String::as_str).collect();
    let many_refs: Vec<&str> = many_args.iter().map(String::as_str).collect();
    let one = run_support::run(&one_refs, None);
    let many = run_support::run(&many_refs, None);

    assert_eq!(
        one.2, many.2,
        "one input must not get two exit codes depending on --cores.\n\
         cores=1 stderr:\n{}\ncores=4 stderr:\n{}",
        one.1, many.1
    );
    for (label, err) in [("cores=1", &one.1), ("cores=4", &many.1)] {
        assert!(
            err.contains("Lint:") && err.contains("dialog(s)"),
            "{label} must print the lint summary with its denominator:\n{err}"
        );
    }
}

/// `--lint-fail-on` without `--lint` is refused by clap, not silently ignored.
#[test]
fn lint_fail_on_requires_lint() {
    let cap = sip_call_fixture();
    let (_o, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            &cap.to_string_lossy(),
            "--lint-fail-on",
            "error",
        ],
        None,
    );
    assert_eq!(
        code,
        Some(2),
        "a gate threshold with no linter running is a usage error -- silently \
         ignoring it would let a pipeline believe it had a gate:\n{err}"
    );
}

/// `--markdown` changes what `--report` emits (#89).
///
/// It was accepted, documented as "Format report output as Markdown", and did
/// NOTHING here: `cmp` on the two outputs was clean. A flag that is parsed,
/// documented and ignored is the same defect class as a config key that
/// validates and never applies.
///
/// Asserted as INEQUALITY plus a markdown-shape check, rather than against a
/// fixed rendering: pinning exact bytes would make every future column change
/// a test edit, and the property that matters is that the flag does something
/// and that the something is markdown.
#[test]
fn markdown_actually_changes_the_report() {
    let cap = sip_call_fixture();
    let path = cap.to_string_lossy().into_owned();
    let plain = run_support::run(&["-N", "-I", &path, "--report", "--no-cli-print"], None);
    let md = run_support::run(
        &[
            "-N",
            "-I",
            &path,
            "--report",
            "--markdown",
            "--no-cli-print",
        ],
        None,
    );

    assert_ne!(
        plain.0, md.0,
        "--markdown must change the report; byte-identical output is the \
         defect this test exists for"
    );
    assert!(
        md.0.contains("| Call-ID |") && md.0.contains("|---|"),
        "the markdown form must be a markdown table -- header row and rule:\n{}",
        md.0
    );
    assert!(
        !plain.0.contains("|---|"),
        "the text form must stay fixed-width, not quietly become markdown too"
    );
}
