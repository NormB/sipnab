// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for config-wiring and schema-drift bugs.
//!
//! Verifies that config file values are properly used as fallbacks for CLI flags,
//! that JSON output schema is complete, and that DialogState Display/Debug stay
//! consistent (which CSV export relies on).
//!
//! The `[limits]` section carries its own gate at the bottom of this file:
//! every documented key must move an observation the binary produces, so a
//! key cannot be parsed, validated and documented while doing nothing.

use std::io::Write;
use std::path::PathBuf;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// The HEP probe spawns a listener it later kills, which corrupts the child's
/// coverage profile; `support::discard_coverage_profile` sends that profile
/// somewhere the merge will not read it.
#[cfg(all(unix, feature = "hep"))]
#[path = "support/mod.rs"]
mod support;

/// The `api_max_rows` and `api_rate_limit_per_peer` probes drive a real
/// `--api` listener, which is what this harness spawns and reaps.
#[cfg(feature = "api")]
#[path = "support/server.rs"]
mod server;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Absolute path to `tests/fixtures/sip_call.pcap` (7-message complete call).
fn sip_call_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap")
}

/// Run sipnab under the shared test baseline (see [`run_support::run`]) with
/// `SIPNAB_LOG=warn`, mapping the exit code to `i32` (`-1` on signal death).
///
/// # Side effects
/// Spawns the compiled `sipnab` binary as a subprocess.
fn run(args: &[&str]) -> (String, String, i32) {
    let (stdout, stderr, code) = run_support::run(args, Some("warn"));
    (stdout, stderr, code.unwrap_or(-1))
}

/// Write a temporary config file and return its path (kept alive by the tempdir).
///
/// # Arguments
/// * `dir` — tempdir that owns the file's lifetime.
/// * `content` — TOML text to write.
///
/// # Returns
/// Path to the written `sipnab.toml`.
///
/// # Side effects
/// Creates `sipnab.toml` inside `dir`.
fn write_config(dir: &tempfile::TempDir, content: &str) -> PathBuf {
    let path = dir.path().join("sipnab.toml");
    let mut f = std::fs::File::create(&path).unwrap();
    write!(f, "{}", content).unwrap();
    path
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 1: json_output_schema_is_complete
// ═══════════════════════════════════════════════════════════════════════════

/// The first JSON output line carries every required field (src/dst/ports/
/// transport/is_request/call_id/schema_version) with the correct JSON types.
#[test]
fn json_output_schema_is_complete() {
    let fixture = sip_call_fixture();
    let (stdout, _stderr, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json",
        "--no-config",
    ]);
    assert_eq!(code, 0, "sipnab should exit cleanly");

    // Parse the first JSON line
    let first_line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("should have at least one JSON line");
    let parsed: serde_json::Value =
        serde_json::from_str(first_line).expect("first line should be valid JSON");

    // Verify all required fields are present
    let required_fields = [
        "src",
        "dst",
        "src_port",
        "dst_port",
        "transport",
        "is_request",
        "call_id",
        "schema_version",
    ];
    for field in &required_fields {
        assert!(
            parsed.get(field).is_some(),
            "JSON output missing required field '{}'. Got: {}",
            field,
            first_line
        );
    }

    // Verify schema_version is 1
    assert_eq!(parsed["schema_version"], 1, "schema_version should be 1");

    // Verify types
    assert!(parsed["src"].is_string(), "src should be a string");
    assert!(parsed["dst"].is_string(), "dst should be a string");
    assert!(
        parsed["src_port"].is_number(),
        "src_port should be a number"
    );
    assert!(
        parsed["dst_port"].is_number(),
        "dst_port should be a number"
    );
    assert!(
        parsed["transport"].is_string(),
        "transport should be a string"
    );
    assert!(
        parsed["is_request"].is_boolean(),
        "is_request should be a boolean"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 2: dialog_state_display_matches_debug
// ═══════════════════════════════════════════════════════════════════════════

/// For all 13 `DialogState` variants, `Display` output equals `Debug` output —
/// CSV export depends on this equivalence.
#[test]
fn dialog_state_display_matches_debug() {
    use sipnab::sip::dialog::DialogState;

    let all_states = [
        DialogState::Trying,
        DialogState::Ringing,
        DialogState::InCall,
        DialogState::Completed,
        DialogState::Canceled,
        DialogState::Failed,
        DialogState::Redirected,
        DialogState::Registered,
        DialogState::Expired,
        DialogState::Pending,
        DialogState::Active,
        DialogState::Terminated,
        DialogState::Transferring,
    ];

    for state in &all_states {
        let display = format!("{}", state);
        let debug = format!("{:?}", state);
        assert_eq!(
            display, debug,
            "DialogState::{display} has divergent Display ({display:?}) and Debug ({debug:?}). \
             CSV export depends on these being identical."
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 3: config_filter_expression_applied
// ═══════════════════════════════════════════════════════════════════════════

/// A `[filter] expression` from the config file is applied: a REGISTER-only
/// filter drops all 7 INVITE-flow messages, while `--no-config` emits them.
#[test]
fn config_filter_expression_applied() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write_config(
        &dir,
        r#"
[filter]
expression = "method == 'REGISTER'"
"#,
    );
    let fixture = sip_call_fixture();

    // Run with the config that filters to REGISTER only.
    // sip_call.pcap has INVITE/100/180/200/ACK/BYE/200 — no REGISTER.
    // With method == 'REGISTER' filter, output should be empty.
    let (stdout, _stderr, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json",
        "-f",
        config_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "sipnab should exit cleanly");

    let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(
        json_lines.len(),
        0,
        "Config filter 'method == REGISTER' should exclude all messages from sip_call.pcap \
         (which contains INVITE flow). Got {} JSON lines.",
        json_lines.len()
    );

    // Now verify that without the filter config, we get messages
    let (stdout_unfiltered, _stderr, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json",
        "--no-config",
    ]);
    assert_eq!(code, 0);
    let unfiltered_count = stdout_unfiltered
        .lines()
        .filter(|l| l.starts_with('{'))
        .count();
    assert!(
        unfiltered_count > 0,
        "Without filter, sip_call.pcap should produce JSON output"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 4: stir_shaken_without_tls_is_gated
// ═══════════════════════════════════════════════════════════════════════════

/// When the `tls` feature is NOT active (which is the default build),
/// --stir-shaken should be accepted but produce no STIR/SHAKEN output.
/// The flag must not cause a crash or error.
#[cfg(not(feature = "tls"))]
#[test]
fn stir_shaken_without_tls_is_gated() {
    let fixture = sip_call_fixture();
    let (stdout, stderr, code) = run(&[
        "-N",
        "-I",
        fixture.to_str().unwrap(),
        "--json",
        "--stir-shaken",
        "--no-config",
    ]);

    // Should exit cleanly — the flag is accepted but silently ignored
    assert_eq!(
        code, 0,
        "--stir-shaken without tls feature should not error. stderr: {stderr}"
    );

    // Verify we still get normal SIP output
    let json_lines = stdout.lines().filter(|l| l.starts_with('{')).count();
    assert!(
        json_lines > 0,
        "--stir-shaken should not suppress normal SIP output"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 5: config_visible_columns_round_trip
// ═══════════════════════════════════════════════════════════════════════════

/// A `[display] visible_columns` list in the config survives a load +
/// `--dump-config` round trip: the key and every column name appear in the dump.
#[test]
fn config_visible_columns_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let columns = ["#", "Method", "From", "To", "State"];
    let config_content = format!("[display]\nvisible_columns = {:?}\n", columns.as_slice());
    let config_path = write_config(&dir, &config_content);

    // Load and dump the config
    let (stdout, _stderr, code) = run(&["-f", config_path.to_str().unwrap(), "--dump-config"]);
    assert_eq!(code, 0, "dump-config should succeed");

    // Verify every column name appears in the dumped output
    for col in &columns {
        assert!(
            stdout.contains(col),
            "Dumped config should contain column '{}'. Got:\n{}",
            col,
            stdout
        );
    }

    // Verify the visible_columns key itself is present
    assert!(
        stdout.contains("visible_columns"),
        "Dumped config should contain 'visible_columns' key. Got:\n{}",
        stdout
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 6: wasm_export_csv_state_format
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that DialogState Display output matches what the CSV export should
/// produce. Since the WASM export_csv uses `{}` (Display), and we want human-
/// readable state names (not Debug-wrapped quotes), this test ensures all
/// variants produce clean, unquoted names suitable for CSV.
#[test]
fn wasm_export_csv_state_format() {
    use sipnab::sip::dialog::DialogState;

    let expected: &[(DialogState, &str)] = &[
        (DialogState::Trying, "Trying"),
        (DialogState::Ringing, "Ringing"),
        (DialogState::InCall, "InCall"),
        (DialogState::Completed, "Completed"),
        (DialogState::Canceled, "Canceled"),
        (DialogState::Failed, "Failed"),
        (DialogState::Registered, "Registered"),
        (DialogState::Expired, "Expired"),
        (DialogState::Pending, "Pending"),
        (DialogState::Active, "Active"),
        (DialogState::Terminated, "Terminated"),
        (DialogState::Transferring, "Transferring"),
    ];

    for (state, name) in expected {
        let display = format!("{}", state);
        assert_eq!(
            display, *name,
            "DialogState Display for {:?} should be '{}', got '{}'",
            state, name, display
        );

        // CSV format check: no quotes, no commas, no newlines
        assert!(
            !display.contains('"') && !display.contains(',') && !display.contains('\n'),
            "DialogState Display '{}' contains CSV-unsafe characters",
            display
        );
    }
}

// ── Non-exhaustive enum compliance tests ────────────────────────────

/// Verify DialogState has Display (not just Debug) for stable serialization
#[test]
fn dialog_state_all_variants_have_display() {
    use sipnab::sip::dialog::DialogState;
    let states = [
        DialogState::Trying,
        DialogState::Ringing,
        DialogState::InCall,
        DialogState::Completed,
        DialogState::Canceled,
        DialogState::Failed,
        DialogState::Registered,
        DialogState::Expired,
        DialogState::Pending,
        DialogState::Active,
        DialogState::Terminated,
        DialogState::Transferring,
    ];
    for state in &states {
        let display = state.to_string();
        assert!(
            !display.is_empty(),
            "Display for {:?} should not be empty",
            state
        );
        assert!(
            !display.contains("::"),
            "Display should not contain :: (Debug format), got: {display}"
        );
    }
}

/// Verify SipMethod has Display for all standard variants
#[test]
fn sip_method_all_variants_have_display() {
    use sipnab::sip::SipMethod;
    let methods = [
        SipMethod::Invite,
        SipMethod::Ack,
        SipMethod::Bye,
        SipMethod::Cancel,
        SipMethod::Register,
        SipMethod::Options,
        SipMethod::Subscribe,
        SipMethod::Notify,
        SipMethod::Publish,
        SipMethod::Info,
        SipMethod::Refer,
        SipMethod::Message,
        SipMethod::Update,
        SipMethod::Prack,
    ];
    for method in &methods {
        let display = method.to_string();
        assert!(!display.is_empty());
        assert_eq!(
            display,
            display.to_uppercase(),
            "SIP methods should be uppercase: {display}"
        );
    }
    // Custom variant
    let custom = SipMethod::Custom("XMETHOD".into());
    assert_eq!(custom.to_string(), "XMETHOD");
}

/// Verify PcapExportMode parse round-trips all variants
#[cfg(feature = "native")]
#[test]
fn pcap_export_mode_all_variants_round_trip() {
    use sipnab::capture::PcapExportMode;
    let modes = ["decrypted", "raw", "encrypted+dsb"];
    for mode_str in &modes {
        let parsed = PcapExportMode::parse_mode(mode_str);
        assert!(
            parsed.is_some(),
            "parse_mode({mode_str}) should return Some"
        );
    }
}

/// Verify release profile has panic=abort and strip=true
#[test]
fn cargo_toml_release_profile_optimized() {
    let cargo = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    assert!(
        cargo.contains("panic = \"abort\""),
        "Release profile should have panic = abort"
    );
    assert!(
        cargo.contains("lto = true"),
        "Release profile should have LTO enabled"
    );
    assert!(
        cargo.contains("strip = true"),
        "Release profile should strip symbols"
    );
    assert!(
        cargo.contains("codegen-units = 1"),
        "Release profile should use single codegen unit"
    );
}

/// contrib/sipnabrc.example is the shipped starter config: it must stay
/// parseable by the real loader and its values must land, or the first
/// thing a new user copies breaks.
#[test]
fn contrib_example_config_parses_with_real_loader() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/contrib/sipnabrc.example");
    // skip_default=false: with `true` the loader returns defaults without
    // reading even the explicit path.
    let loaded = sipnab::config::Config::load(Some(path), false)
        .expect("contrib/sipnabrc.example must parse with the real config loader");
    // Spot-check a value from each section so a renamed key can't slip by
    // as silently-ignored TOML.
    assert_eq!(
        loaded.config.capture.portrange.as_deref(),
        Some("5060-5080"),
        "capture.portrange from the example must land"
    );
    assert_eq!(
        loaded.config.display.color.as_deref(),
        Some("auto"),
        "display.color from the example must land"
    );
    assert_eq!(
        loaded.config.limits.max_streams,
        Some(4096),
        "limits.max_streams from the example must land"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  [limits]: every documented key must change what the binary does
// ═══════════════════════════════════════════════════════════════════════════
//
// `dialog_limit`, `max_streams`, `max_reassembly` and `hep_rate_limit` were
// parsed, validated (`LimitsConfig::validate` rejects 0 by name) and
// documented as the way to bound sipnab's footprint — and read nowhere. A
// config capping dialogs at 100 loaded cleanly and the run still retained
// 18,948 of them. Validation made that worse than an absent key: sipnab
// confirmed the setting, so the operator believed the cap was real.
//
// The tests below drive the shipped binary over inputs that overrun each cap
// and assert the output is bounded. Parsing assertions cannot replace them —
// parsing is exactly what already passed.
//
// PRECEDENCE (documented in docs/config-reference.md and enforced here):
//
//     explicit CLI flag  >  config file  >  built-in default
//
// the same order every other CLI-vs-config pair in this repo resolves in
// (`cli.capture_args.portrange.or(config.capture.portrange)` in `bootstrap::plan`,
// `cli.capture_args.snaplen.or(config.capture.snaplen)`, `cli.matching_args.from.or(config.filter.from)`).

/// Run sipnab with owned arguments, adapting to the `&[&str]` [`run`] takes.
fn run_owned(args: &[String]) -> (String, String, i32) {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

/// Count the dialog objects on `--json-dialogs` stdout.
fn dialog_count(stdout: &str) -> usize {
    stdout.lines().filter(|l| l.starts_with('{')).count()
}

/// Count the RTP stream rows in a `--report` table (each starts with its SSRC).
fn stream_row_count(stdout: &str) -> usize {
    stdout.lines().filter(|l| l.starts_with("0x")).count()
}

/// Write a pcap of `calls` complete SIP calls, each with its own Call-ID.
fn write_multi_call_pcap(dir: &tempfile::TempDir, calls: usize) -> PathBuf {
    let path = dir.path().join("calls.pcap");
    let mut frames = Vec::new();
    for i in 0..calls {
        frames.extend(pcap_build::sip_call_frames(
            &format!("cap-call-{i}@10.1.0.1"),
            &format!("br{i}"),
            "alice",
            "bob",
        ));
    }
    pcap_build::write_pcap(&path, &frames);
    path
}

/// A long dialog that then goes quiet, which is what idle compaction needs.
///
/// Two conditions have to hold at once before compaction touches anything, and
/// no existing fixture satisfies either: the dialog must hold MORE messages
/// than the keep-limit, and it must have been silent longer than the idle
/// window when the final sweep runs. `sip_call.pcap` is seven messages spanning
/// milliseconds, so a probe built on it observes no compaction under any
/// setting and would report "this key changes nothing" for a key that works.
///
/// So: `exchanges` complete calls sharing one Call-ID, differing by transaction
/// branch (the re-INVITE shape `sip_call_frames` already supports), followed by
/// one unrelated call `quiet_secs` later. That trailing call is what moves the
/// capture's final timestamp forward — the sweep measures idleness against the
/// last packet READ, so without it the long dialog is the newest thing in the
/// capture and is never idle.
fn write_idle_dialog_pcap(
    dir: &tempfile::TempDir,
    exchanges: usize,
    quiet_secs: u64,
) -> (PathBuf, usize) {
    let path = dir.path().join("idle.pcap");
    let mut timed: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut usec = 0u64;
    for i in 0..exchanges {
        for f in
            pcap_build::sip_call_frames("idle-dialog@10.1.0.1", &format!("br{i}"), "alice", "bob")
        {
            timed.push((f, usec));
            usec += 1_000;
        }
    }
    let messages = timed.len();

    let later = usec + quiet_secs * 1_000_000;
    for f in pcap_build::sip_call_frames("late-call@10.1.0.1", "late", "carol", "dave") {
        timed.push((f, later));
    }
    pcap_build::write_pcap_at(&path, &timed, 1);
    (path, messages)
}

/// The four-stream RTP fixture the `max_streams` probes bound.
fn rtp_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pcap-samples")
        .join("codec-negotiation.pcap")
}

// ── dialog_limit ──────────────────────────────────────────────────────────

/// `[limits] dialog_limit` bounds the dialogs a run retains.
///
/// This is the reported defect, reduced to a fixture: eight distinct calls
/// against `dialog_limit = 3`. Before the fix the capped run returned all
/// eight.
#[test]
fn config_dialog_limit_bounds_retained_dialogs() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    let cfg = write_config(&dir, "[limits]\ndialog_limit = 3\n");
    let pcap = pcap.to_str().unwrap().to_string();

    let (uncapped, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.clone(),
        "--json-dialogs".into(),
        "--no-config".into(),
    ]);
    assert_eq!(code, 0, "uncapped run should exit cleanly");
    assert_eq!(
        dialog_count(&uncapped),
        8,
        "the fixture must overrun the cap, or the test proves nothing"
    );

    let (capped, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap,
        "--json-dialogs".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
    ]);
    assert_eq!(code, 0, "capped run should exit cleanly");
    assert_eq!(
        dialog_count(&capped),
        3,
        "[limits] dialog_limit = 3 must bound the run to 3 dialogs; got {} \
         — the key is parsed and validated but not enforced",
        dialog_count(&capped)
    );
}

/// An explicit `--limit` beats `[limits] dialog_limit`.
#[test]
fn cli_limit_overrides_config_dialog_limit() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    let cfg = write_config(&dir, "[limits]\ndialog_limit = 3\n");

    let (out, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.to_str().unwrap().into(),
        "--json-dialogs".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
        "--limit".into(),
        "6".into(),
    ]);
    assert_eq!(code, 0, "run should exit cleanly");
    assert_eq!(
        dialog_count(&out),
        6,
        "an explicit --limit must win over [limits] dialog_limit"
    );
}

/// `--limit` typed at its default value still beats the config key.
///
/// The precedence rule is "the operator typed it", not "the value differs
/// from the default": `--limit 100000` is an explicit instruction to track
/// 100,000 dialogs and must not be silently narrowed by a config file.
#[test]
fn cli_limit_at_its_default_value_still_overrides_config() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    let cfg = write_config(&dir, "[limits]\ndialog_limit = 3\n");

    let (out, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.to_str().unwrap().into(),
        "--json-dialogs".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
        "--limit".into(),
        "100000".into(),
    ]);
    assert_eq!(code, 0, "run should exit cleanly");
    assert_eq!(
        dialog_count(&out),
        8,
        "--limit 100000 is explicit even though it equals the default, so \
         the config cap must not apply"
    );
}

// ── max_streams ───────────────────────────────────────────────────────────

/// `[limits] max_streams` bounds the RTP stream table.
#[test]
fn config_max_streams_bounds_rtp_stream_table() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nmax_streams = 1\n");
    let pcap = rtp_fixture().to_str().unwrap().to_string();

    let (uncapped, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.clone(),
        "--report".into(),
        "--no-config".into(),
    ]);
    assert_eq!(code, 0, "uncapped run should exit cleanly");
    assert!(
        stream_row_count(&uncapped) > 1,
        "the fixture must carry more streams than the cap; got {}",
        stream_row_count(&uncapped)
    );

    let (capped, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap,
        "--report".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
    ]);
    assert_eq!(code, 0, "capped run should exit cleanly");
    assert_eq!(
        stream_row_count(&capped),
        1,
        "[limits] max_streams = 1 must bound the stream table to 1 row"
    );
}

/// An explicit `--max-streams` beats `[limits] max_streams`.
#[test]
fn cli_max_streams_overrides_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nmax_streams = 1\n");

    let (out, _, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        rtp_fixture().to_str().unwrap().into(),
        "--report".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
        "--max-streams".into(),
        "3".into(),
    ]);
    assert_eq!(code, 0, "run should exit cleanly");
    assert_eq!(
        stream_row_count(&out),
        3,
        "an explicit --max-streams must win over [limits] max_streams"
    );
}

// ── max_reassembly ────────────────────────────────────────────────────────

/// Write a pcap holding `flows` partial SIP messages open over TCP.
fn write_tcp_flow_pcap(dir: &tempfile::TempDir, flows: usize) -> PathBuf {
    let path = dir.path().join("tcp-flows.pcap");
    pcap_build::write_pcap(&path, &pcap_build::partial_tcp_sip_flows(flows));
    path
}

/// The warning a reassembler at capacity logs, with the cap it enforced.
const TCP_AT_CAPACITY: &str = "TCP reassembler at capacity (1)";

/// `[limits] max_reassembly` bounds concurrent TCP reassembly sessions.
///
/// The eviction warning names the cap it enforced, so a run that reports
/// `at capacity (1)` proves the configured `1` reached the reassembler
/// rather than merely that some eviction happened.
#[test]
fn config_max_reassembly_bounds_tcp_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_tcp_flow_pcap(&dir, 4);
    let cfg = write_config(&dir, "[limits]\nmax_reassembly = 1\n");
    let pcap = pcap.to_str().unwrap().to_string();

    let (_, uncapped_err, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.clone(),
        "--json".into(),
        "--no-config".into(),
    ]);
    assert_eq!(code, 0, "uncapped run should exit cleanly");
    assert!(
        !uncapped_err.contains("TCP reassembler at capacity"),
        "the default cap must not bind on a 4-flow fixture:\n{uncapped_err}"
    );

    let (_, capped_err, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap,
        "--json".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
    ]);
    assert_eq!(code, 0, "capped run should exit cleanly");
    assert!(
        capped_err.contains(TCP_AT_CAPACITY),
        "[limits] max_reassembly = 1 must reach the TCP reassembler; \
         expected {TCP_AT_CAPACITY:?} on stderr, got:\n{capped_err}"
    );
}

/// An explicit `--max-reassembly` beats `[limits] max_reassembly`.
///
/// Asserting the *presence* of `at capacity (2)` rather than the absence of
/// any warning keeps this test honest: an unwired key also produces no
/// warning, so an absence assertion would pass against the very defect this
/// file exists to catch.
#[test]
fn cli_max_reassembly_overrides_config() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_tcp_flow_pcap(&dir, 4);
    let cfg = write_config(&dir, "[limits]\nmax_reassembly = 1\n");

    let (_, stderr, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.to_str().unwrap().into(),
        "--json".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
        "--max-reassembly".into(),
        "2".into(),
    ]);
    assert_eq!(code, 0, "run should exit cleanly");
    assert!(
        stderr.contains("TCP reassembler at capacity (2)"),
        "an explicit --max-reassembly 2 must win over [limits] \
         max_reassembly = 1, so the reassembler reports the cap it enforced \
         as 2:\n{stderr}"
    );
    assert!(
        !stderr.contains(TCP_AT_CAPACITY),
        "the config's max_reassembly = 1 must not reach the reassembler when \
         --max-reassembly was typed:\n{stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  The gate: no [limits] key may be added dead
// ═══════════════════════════════════════════════════════════════════════════
//
// Four keys shipped parsed, validated and documented while reading nowhere.
// The gate below makes that state unreachable for the next key: it derives
// the key set from `LimitsConfig` itself, checks the loader and the reference
// documentation agree with it, and then demands that every key carry a probe
// which runs sipnab twice — once without the key, once with it — and returns
// two DIFFERENT observations. A registered probe that changes nothing fails
// as loudly as a missing one, so a parsing assertion cannot satisfy this.

/// Fail loudly when a burst probe's PREMISE did not hold.
///
/// The rate-limit probes send a burst and read the refusals. That reading only
/// means something if the whole burst landed inside ONE limiter window: if it
/// spilled over, the window reset mid-burst, the limiter allowed its quota
/// again, and `refused == 0` describes the machine rather than the key.
///
/// The bound is [`sipnab::rate_limit::WINDOW`], read from the limiter itself
/// rather than restated here — a second copy of `1s` would agree today and
/// drift the moment the limiter changes.
///
/// Measured on this tree, this has ~70x of headroom and has never fired: the
/// 40-request API burst takes 13.7 ms idle and 14.8 ms at three times CPU
/// oversubscription (load average 19), against a 1 s window. It exists because
/// of what the failure would SAY, not because it is likely — without it, a
/// machine slow enough to spill the burst makes both observations agree, and
/// the gate below then tells the reader to delete a key that works perfectly.
/// A gate must not give advice it cannot support.
///
/// Gated where `sipnab::rate_limit` is compiled (`hep` or `mcp`), because that
/// is where the bound lives and reading it from anywhere else would mean
/// copying the value. `api` implies neither, so an api-only build gets the
/// no-op placeholder below and simply goes unguarded — the guard is insurance
/// against a machine slow enough to spill a 14 ms burst past 1 s, not something
/// the probe depends on.
///
/// `allow(dead_code)`: whether anything CALLS this depends on the feature
/// combination, not on whether it can compile. Its two callers are the `api`
/// burst probe and the unix-only `hep` one, so the matrix builds combinations
/// -- `tls`, `native`, `metrics`, `mcp` alone -- where the function is
/// perfectly valid and simply unused. CI denies warnings, so that is an error
/// there and not here; spelling the caller set out as a `cfg` expression would
/// be longer than this comment and wrong the next time a probe moves.
#[allow(dead_code)]
#[cfg(any(feature = "hep", feature = "mcp"))]
fn assert_premise_inside_window(which: &str, elapsed: std::time::Duration, refused: usize) {
    if refused > 0 {
        return; // the limiter did refuse, so the window plainly held
    }
    assert!(
        elapsed < sipnab::rate_limit::WINDOW,
        "the {which} burst took {elapsed:?}, which is not inside the \
         {:?} rate-limit window, so `refused == 0` is not evidence about the \
         key -- the window reset mid-burst and the limiter allowed its quota \
         again. This machine was too slow to OBSERVE the key; that is not the \
         same as the key being dead, and the {which} limit must not be deleted \
         on the strength of it.",
        sipnab::rate_limit::WINDOW
    );
}

/// Placeholder for builds without `sipnab::rate_limit` (neither `hep` nor
/// `mcp`). The bound it would check lives in that module, so there is nothing
/// to check against; the probes still run, they just go unguarded.
#[allow(dead_code)]
#[cfg(not(any(feature = "hep", feature = "mcp")))]
fn assert_premise_inside_window(_which: &str, _elapsed: std::time::Duration, _refused: usize) {}

/// One documented `[limits]` key and the pair of runs that proves it bites.
struct LimitProbe {
    /// The key name, exactly as it appears in TOML and in the reference.
    key: &'static str,
    /// Whether this build compiled the feature the probe needs. A probe is
    /// only skipped when its whole subsystem is absent; `--all-features`
    /// runs every one.
    enabled: bool,
    /// Returns `(observed_without_the_key, observed_with_the_key)`.
    observe: fn() -> (String, String),
}

/// Every field name of [`sipnab::config::LimitsConfig`], read off the struct.
///
/// Serializing the all-`None` default through serde_json keeps each field as
/// a `null` entry, so this follows the struct automatically: a new field
/// appears here the moment it is added, and the gate then demands a probe
/// for it. Deriving the list from the struct rather than from a hand-written
/// constant is the point — a hand-written list is the thing that drifts.
fn limits_struct_keys() -> Vec<String> {
    let value = serde_json::to_value(sipnab::config::LimitsConfig::default())
        .expect("LimitsConfig serializes");
    value
        .as_object()
        .expect("LimitsConfig serializes as a map")
        .keys()
        .cloned()
        .collect()
}

/// The keys the `[limits]` table of `docs/config-reference.md` documents.
fn documented_limits_keys() -> Vec<String> {
    const REFERENCE: &str = include_str!("../docs/config-reference.md");
    let mut keys = Vec::new();
    let mut inside = false;
    for line in REFERENCE.lines() {
        if let Some(heading) = line.strip_prefix("### ") {
            inside = heading.trim() == "[limits]";
            continue;
        }
        if inside
            && let Some(rest) = line.strip_prefix("| `")
            && let Some(key) = rest.split('`').next()
        {
            keys.push(key.to_string());
        }
    }
    keys
}

/// Every probe, one per documented key.
fn limit_probes() -> Vec<LimitProbe> {
    vec![
        LimitProbe {
            key: "dialog_limit",
            enabled: true,
            observe: probe_dialog_limit,
        },
        LimitProbe {
            key: "mcp_max_rows",
            enabled: cfg!(feature = "mcp"),
            observe: probe_mcp_max_rows,
        },
        LimitProbe {
            key: "max_streams",
            enabled: true,
            observe: probe_max_streams,
        },
        LimitProbe {
            key: "max_reassembly",
            enabled: true,
            observe: probe_max_reassembly,
        },
        LimitProbe {
            key: "hep_rate_limit",
            enabled: cfg!(all(unix, feature = "hep")),
            observe: probe_hep_rate_limit,
        },
        LimitProbe {
            key: "max_header_line",
            enabled: true,
            observe: probe_max_header_line,
        },
        LimitProbe {
            key: "max_headers_per_message",
            enabled: true,
            observe: probe_max_headers_per_message,
        },
        LimitProbe {
            key: "max_messages_per_dialog",
            enabled: true,
            observe: probe_max_messages_per_dialog,
        },
        LimitProbe {
            key: "idle_compact_after_secs",
            enabled: true,
            observe: probe_idle_compact_after_secs,
        },
        LimitProbe {
            key: "keep_messages_per_idle_dialog",
            enabled: true,
            observe: probe_keep_messages_per_idle_dialog,
        },
        LimitProbe {
            key: "max_audio_frames",
            enabled: true,
            observe: probe_max_audio_frames,
        },
        LimitProbe {
            key: "lint_max_per_rule",
            enabled: true,
            observe: probe_lint_max_per_rule,
        },
        LimitProbe {
            key: "exec_queue_depth",
            enabled: true,
            observe: probe_exec_queue_depth,
        },
        LimitProbe {
            key: "mcp_max_body_bytes",
            enabled: cfg!(feature = "mcp"),
            observe: probe_mcp_max_body_bytes,
        },
        LimitProbe {
            key: "mcp_max_wait_seconds",
            enabled: cfg!(feature = "mcp"),
            observe: probe_mcp_max_wait_seconds,
        },
        LimitProbe {
            key: "max_lost_sequences",
            enabled: true,
            observe: probe_max_lost_sequences,
        },
        LimitProbe {
            key: "max_groups",
            enabled: true,
            observe: probe_max_groups,
        },
        LimitProbe {
            key: "max_grouped_messages",
            enabled: true,
            observe: probe_max_grouped_messages,
        },
        LimitProbe {
            key: "max_metadata_file_bytes",
            enabled: true,
            observe: probe_max_metadata_file_bytes,
        },
        LimitProbe {
            key: "max_gunzip_bytes",
            enabled: true,
            observe: probe_max_gunzip_bytes,
        },
        LimitProbe {
            key: "max_tcp_buffer",
            enabled: true,
            observe: probe_max_tcp_buffer,
        },
        LimitProbe {
            key: "api_max_rows",
            enabled: cfg!(feature = "api"),
            observe: probe_api_max_rows,
        },
        LimitProbe {
            key: "api_rate_limit_per_peer",
            enabled: cfg!(feature = "api"),
            observe: probe_api_rate_limit_per_peer,
        },
        LimitProbe {
            key: "mcp_max_findings",
            enabled: cfg!(feature = "mcp"),
            observe: probe_mcp_max_findings,
        },
        LimitProbe {
            key: "reassembly_ttl_secs",
            // The KEY is wired on every build; the probe needs a command line
            // to walk the resolver half, and `crate::cli` is native-only.
            enabled: cfg!(feature = "native"),
            observe: probe_reassembly_ttl_secs,
        },
        LimitProbe {
            key: "metrics_max_conn",
            enabled: cfg!(feature = "metrics"),
            observe: probe_metrics_max_conn,
        },
        LimitProbe {
            key: "max_tracked_peers",
            // Linux-only, and not because the key is: the probe needs THREE
            // distinct source addresses to fill a tracking map, and only Linux
            // routes the whole of 127.0.0.0/8 to loopback without an interface
            // alias. The key itself is wired on every platform — `hep.rs` and
            // `mcp/server.rs` read it from one resolver — and the resolver half
            // is pinned in `cli.rs` everywhere.
            enabled: cfg!(all(target_os = "linux", feature = "hep")),
            observe: probe_max_tracked_peers,
        },
    ]
}

/// Run sipnab over `pcap` with and without `toml`, returning both stdouts
/// reduced by `measure`.
fn observe_stdout(
    pcap: &std::path::Path,
    toml: &str,
    extra: &[&str],
    measure: fn(&str) -> String,
) -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, toml);
    let pcap = pcap.to_str().unwrap().to_string();

    let mut base: Vec<String> = vec!["-N".into(), "-I".into(), pcap];
    base.extend(extra.iter().map(|s| (*s).to_string()));

    let mut without = base.clone();
    without.push("--no-config".into());
    let (plain, _, code) = run_owned(&without);
    assert_eq!(code, 0, "uncapped run should exit cleanly");

    let mut with = base;
    with.push("--config".into());
    with.push(cfg.to_str().unwrap().into());
    let (limited, _, code) = run_owned(&with);
    assert_eq!(code, 0, "capped run should exit cleanly");

    (measure(&plain), measure(&limited))
}

/// `dialog_limit`: eight calls against a cap of three.
fn probe_dialog_limit() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    observe_stdout(
        &pcap,
        "[limits]\ndialog_limit = 3\n",
        &["--json-dialogs"],
        |out| format!("dialogs={}", dialog_count(out)),
    )
}

/// `mcp_max_rows`: eight dialogs asked for at once, against a cap of two.
///
/// This probe drives the MCP stdio server rather than stdout, because the key
/// is observable on no other surface. That is the point of the gate it
/// satisfies: a limit that only exists in a resolver is not wired, and this
/// tree already carries six thresholds accepted as parameters that no
/// production caller supplies.
fn probe_mcp_max_rows() -> (String, String) {
    fn rows_with(cfg: Option<&std::path::Path>, pcap: &std::path::Path) -> usize {
        use std::io::{BufRead, BufReader, Write};
        let mut args: Vec<String> = vec![
            "--mcp".into(),
            "-N".into(),
            "-I".into(),
            pcap.to_str().unwrap().into(),
            "--quiet".into(),
        ];
        match cfg {
            Some(c) => {
                args.push("--config".into());
                args.push(c.to_str().unwrap().into());
            }
            None => args.push("--no-config".into()),
        }
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn mcp server");
        let mut stdin = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));

        let send = |w: &mut std::process::ChildStdin, v: serde_json::Value| {
            writeln!(w, "{v}").expect("write");
            w.flush().expect("flush");
        };
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"probe","version":"0"}}}),
        );
        let mut line = String::new();
        out.read_line(&mut line).expect("initialize reply");
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        // Ask for far more than either cap allows, so the cap is what bounds it.
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"list_dialogs","arguments":{"limit":500}}}),
        );

        let mut rows = 0usize;
        for _ in 0..40 {
            line.clear();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v["id"] != serde_json::json!(2) {
                continue;
            }
            let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            rows = parsed["dialogs"].as_array().map(Vec::len).unwrap_or(0);
            break;
        }
        let _ = child.kill();
        let _ = child.wait();
        rows
    }

    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    let cfg = write_config(&dir, "[limits]\nmcp_max_rows = 2\n");
    (
        format!("rows={}", rows_with(None, &pcap)),
        format!("rows={}", rows_with(Some(&cfg), &pcap)),
    )
}

/// `mcp_max_findings`: what one accepted write says is left after it.
///
/// The budget is reported to the agent in every `save_findings` reply, as
/// `remaining`, so the observation is that number after a single write — the
/// same figure the refusal at the end of the budget is counted against. A
/// probe that wrote until it was refused would prove the same thing far more
/// slowly and would not distinguish a cap of 1000 from no cap at all inside a
/// test's patience.
#[cfg(feature = "mcp")]
fn probe_mcp_max_findings() -> (String, String) {
    fn remaining_after_one_write(cfg: Option<&std::path::Path>, pcap: &std::path::Path) -> i64 {
        use std::io::{BufRead, BufReader, Write};
        let mut args: Vec<String> = vec![
            "--mcp".into(),
            "--mcp-allow-save-findings".into(),
            "-N".into(),
            "-I".into(),
            pcap.to_str().unwrap().into(),
            "--quiet".into(),
        ];
        match cfg {
            Some(c) => {
                args.push("--config".into());
                args.push(c.to_str().unwrap().into());
            }
            None => args.push("--no-config".into()),
        }
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn mcp server");
        let mut stdin = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));

        let send = |w: &mut std::process::ChildStdin, v: serde_json::Value| {
            writeln!(w, "{v}").expect("write");
            w.flush().expect("flush");
        };
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"probe","version":"0"}}}),
        );
        let mut line = String::new();
        out.read_line(&mut line).expect("initialize reply");
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"save_findings",
                      "arguments":{"summary":"probing the findings budget"}}}),
        );

        let mut remaining = -1i64;
        for _ in 0..40 {
            line.clear();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v["id"] != serde_json::json!(2) {
                continue;
            }
            let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            remaining = parsed["remaining"].as_i64().unwrap_or(-1);
            break;
        }
        let _ = child.kill();
        let _ = child.wait();
        remaining
    }

    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 2);
    let cfg = write_config(&dir, "[limits]\nmcp_max_findings = 3\n");
    (
        format!("remaining={}", remaining_after_one_write(None, &pcap)),
        format!("remaining={}", remaining_after_one_write(Some(&cfg), &pcap)),
    )
}

/// Placeholder for builds without MCP; the gate never calls it.
#[cfg(not(feature = "mcp"))]
fn probe_mcp_max_findings() -> (String, String) {
    unreachable!("the mcp_max_findings probe only runs in an `mcp` build")
}

/// `lint_max_per_rule`: forty repeats of one rule against a cap of five.
///
/// One dialog, forty `INVITE`s, none with a `Max-Forwards` header, so exactly
/// one rule fires forty times. The cap is per rule per DIALOG, which is why
/// the repeats share a Call-ID and differ only by `CSeq`.
fn probe_lint_max_per_rule() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let frames: Vec<Vec<u8>> = (0..40u32)
        .map(|i| pcap_build::invite_without_max_forwards("lint-probe", &format!("l{i}"), i + 1))
        .collect();
    let pcap = dir.path().join("lint.pcap");
    pcap_build::write_pcap(&pcap, &frames);
    observe_stdout(
        &pcap,
        "[limits]\nlint_max_per_rule = 5\n",
        &["--lint"],
        |out| {
            format!(
                "findings={}",
                out.lines()
                    .filter(|l| l.contains("MAX-FORWARDS-MISSING"))
                    .count()
            )
        },
    )
}

/// `exec_queue_depth`: eight calls firing a hook that outlives the run,
/// against a depth of one.
///
/// The observation is how many events were DROPPED, which is the only thing
/// the depth decides. The hook sleeps so that every child is still live when
/// the next event arrives — a hook that returned immediately would be reaped
/// between events and the queue would never fill, whatever the depth.
///
/// Observed on stderr rather than stdout: the drop is a warning, because an
/// event whose command never ran is the thing an operator has to be told
/// about.
fn probe_exec_queue_depth() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&cfg_dir, "[limits]\nexec_queue_depth = 1\n");
    let pcap = pcap.to_str().unwrap().to_string();

    let count = |err: &str| {
        format!(
            "dropped={}",
            err.lines().filter(|l| l.contains("dropping event")).count()
        )
    };

    let (_, plain, code) = run(&[
        "-N",
        "-I",
        &pcap,
        "--on-dialog-exec",
        "sleep 5",
        "--no-config",
    ]);
    assert_eq!(code, 0, "uncapped run should exit cleanly");

    let (_, limited, code) = run(&[
        "-N",
        "-I",
        &pcap,
        "--on-dialog-exec",
        "sleep 5",
        "--config",
        cfg.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "capped run should exit cleanly");

    (count(&plain), count(&limited))
}

/// `max_lost_sequences`: 1200 losses retained against a cap of 100.
///
/// The observation is the BURST COUNT the burst/gap analysis reports, not the
/// length of any log: the retained log is the only window that analysis can
/// reason over, so shrinking it is visible as bursts that stop being counted.
/// A capture losing three of every ten packets over 4000 sequence numbers
/// holds 400 bursts; the shipped 1000-loss retention sees 333 of them and a
/// 100-loss retention sees 33.
fn probe_max_lost_sequences() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("lossy-call.pcap");
    pcap_build::write_pcap(
        &pcap,
        &pcap_build::sdp_call_with_lossy_rtp("loss-probe", 4000, 3),
    );
    observe_stdout(
        &pcap,
        "[limits]\nmax_lost_sequences = 100\n",
        &["--json-dialogs"],
        |out| format!("bursts={}", first_stream_burst_count(out)),
    )
}

/// Bursts the first dialog's first stream reported, off `--json-dialogs`.
fn first_stream_burst_count(stdout: &str) -> i64 {
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("the probe capture must produce one dialog");
    let v: serde_json::Value = serde_json::from_str(line).expect("valid dialog JSON");
    v["streams"][0]["burst_gap"]["burst_count"]
        .as_i64()
        .expect("the linked stream must carry a burst/gap analysis")
}

/// `max_groups`: eight Call-IDs grouped against a cap of two.
fn probe_max_groups() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    observe_stdout(
        &pcap,
        "[limits]\nmax_groups = 2\n",
        &["--group-by", "call-id"],
        |out| format!("groups={}", out.matches("── call-id ").count()),
    )
}

/// `max_grouped_messages`: a 56-message grouped run against a cap of three.
///
/// Distinct from `max_groups` above: the group cap bounds how many groups
/// exist, this one how much rendered output they hold between them, so the
/// observation is the MESSAGE count under an unrestricted number of groups.
fn probe_max_grouped_messages() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    observe_stdout(
        &pcap,
        "[limits]\nmax_grouped_messages = 3\n",
        &["--group-by", "call-id"],
        |out| {
            format!(
                "messages={}",
                out.lines().filter(|l| l.contains(" -> ")).count()
            )
        },
    )
}

/// `max_metadata_file_bytes`: a pcapng stripped of its secrets, against a
/// ceiling of ten bytes.
///
/// `--strip-secrets` is the command that reads a whole pcapng into memory, so
/// it is where the ceiling bites. It also runs BEFORE the ordinary config
/// load, which is why this probe is worth having: the key reaching it is not
/// something the other paths prove.
fn probe_max_metadata_file_bytes() -> (String, String) {
    fn strip_with(extra: &[&str]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("secrets.pcapng");
        let dst = dir.path().join("stripped.pcapng");
        pcap_build::write_pcapng_with_dsb(
            &src,
            "CLIENT_RANDOM abcd 0123\n",
            &pcap_build::udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, b"OPTIONS\r\n\r\n"),
        );
        let mut args: Vec<String> = vec![
            "-N".into(),
            "-I".into(),
            src.to_str().unwrap().into(),
            "--strip-secrets".into(),
            dst.to_str().unwrap().into(),
            "--no-cli-print".into(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_string()));
        let (_out, _err, code) = run_owned(&args);
        if code == 0 && dst.exists() {
            "stripped".into()
        } else {
            "refused".into()
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nmax_metadata_file_bytes = 10\n");
    (
        strip_with(&["--no-config"]),
        strip_with(&["--config", cfg.to_str().unwrap()]),
    )
}

/// `max_gunzip_bytes`: a gzip-compressed pcapng against a 100-byte inflation
/// ceiling.
///
/// Driven through `--strip-secrets`, because that is a path where sipnab does
/// the inflating. The packet stream of a `-I capture.pcap.gz` is decompressed
/// by libpcap itself and this ceiling never sees it; what sipnab inflates is
/// the pcapng it reads for embedded names and TLS secrets, and the copy
/// `--strip-secrets` rewrites.
fn probe_max_gunzip_bytes() -> (String, String) {
    fn strip_gzipped_with(extra: &[&str]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("secrets.pcapng");
        let gz = dir.path().join("secrets.pcapng.gz");
        let dst = dir.path().join("stripped.pcapng");
        pcap_build::write_pcapng_with_dsb(
            &plain,
            "CLIENT_RANDOM abcd 0123\n",
            &pcap_build::udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, b"OPTIONS\r\n\r\n"),
        );
        std::fs::write(
            &gz,
            pcap_build::gzip_stored(&std::fs::read(&plain).expect("read the plain pcapng")),
        )
        .expect("write the gzip member");
        let mut args: Vec<String> = vec![
            "-N".into(),
            "-I".into(),
            gz.to_str().unwrap().into(),
            "--strip-secrets".into(),
            dst.to_str().unwrap().into(),
            "--no-cli-print".into(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_string()));
        let (_out, _err, code) = run_owned(&args);
        if code == 0 && dst.exists() {
            "stripped".into()
        } else {
            "refused".into()
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nmax_gunzip_bytes = 100\n");
    (
        strip_gzipped_with(&["--no-config"]),
        strip_gzipped_with(&["--config", cfg.to_str().unwrap()]),
    )
}

/// `max_tcp_buffer`: a 100 KiB SIP/TCP INVITE against the shipped 64 KiB.
///
/// The one cap in this registry that DESTROYS data. At the shipped ceiling the
/// reassembler flushes the INVITE in half and both halves parse as malformed,
/// so the dialog holds only the `200 OK` that answered a request sipnab never
/// reported; at 256 KiB the same bytes produce both messages.
///
/// The observation is the dialog's MESSAGE count, not the dialog count: the
/// answer alone still opens a dialog, so counting dialogs would report `1` in
/// both runs and this probe would pass while the INVITE was being destroyed —
/// which is exactly the shape of failure this registry exists to catch.
fn probe_max_tcp_buffer() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("big-tcp-invite.pcap");
    pcap_build::write_pcap(
        &pcap,
        &pcap_build::tcp_sip_call_with_body("big-tcp-probe", 100_000, false),
    );
    observe_stdout(
        &pcap,
        "[limits]\nmax_tcp_buffer = 262144\n",
        &["--json-dialogs"],
        |out| format!("messages={}", first_dialog_msg_count(out)),
    )
}

/// Messages the first reported dialog carried, off `--json-dialogs`.
fn first_dialog_msg_count(stdout: &str) -> i64 {
    let Some(line) = stdout.lines().find(|l| l.starts_with('{')) else {
        return 0;
    };
    let v: serde_json::Value = serde_json::from_str(line).expect("valid dialog JSON");
    v["msg_count"].as_i64().expect("a dialog carries msg_count")
}

/// `mcp_max_body_bytes`: one `search_messages` snippet against a 64-byte
/// ceiling.
///
/// Driven over the MCP stdio server for the same reason `mcp_max_rows` is:
/// there is no other surface this key is visible on, and a cap that only
/// exists in a resolver is not wired.
#[cfg(feature = "mcp")]
fn probe_mcp_max_body_bytes() -> (String, String) {
    fn snippet_len(cfg: Option<&std::path::Path>, pcap: &std::path::Path) -> usize {
        use std::io::{BufRead, BufReader, Write};
        let mut args: Vec<String> = vec![
            "--mcp".into(),
            "-N".into(),
            "-I".into(),
            pcap.to_str().unwrap().into(),
            "--quiet".into(),
        ];
        match cfg {
            Some(c) => {
                args.push("--config".into());
                args.push(c.to_str().unwrap().into());
            }
            None => args.push("--no-config".into()),
        }
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn mcp server");
        let mut stdin = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));

        let send = |w: &mut std::process::ChildStdin, v: serde_json::Value| {
            writeln!(w, "{v}").expect("write");
            w.flush().expect("flush");
        };
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"probe","version":"0"}}}),
        );
        let mut line = String::new();
        out.read_line(&mut line).expect("initialize reply");
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"search_messages","arguments":{"query":"INVITE","limit":1}}}),
        );

        let mut len = 0usize;
        for _ in 0..40 {
            line.clear();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v["id"] != serde_json::json!(2) {
                continue;
            }
            let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            len = parsed[0]["snippet"]
                .as_str()
                .map(str::len)
                .or_else(|| parsed["hits"][0]["snippet"].as_str().map(str::len))
                .unwrap_or(0);
            break;
        }
        let _ = child.kill();
        let _ = child.wait();
        len
    }

    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 1);
    let cfg = write_config(&dir, "[limits]\nmcp_max_body_bytes = 64\n");
    (
        format!("snippet={}", snippet_len(None, &pcap)),
        format!("snippet={}", snippet_len(Some(&cfg), &pcap)),
    )
}

/// Placeholder for a build without the `mcp` feature; the registry marks the
/// probe disabled, so it is never called.
#[cfg(not(feature = "mcp"))]
fn probe_mcp_max_body_bytes() -> (String, String) {
    (String::new(), String::new())
}

/// `mcp_max_wait_seconds`: an hour asked for against a one-second ceiling.
///
/// Driven over the MCP stdio server for the same reason `mcp_max_body_bytes`
/// is: there is no other surface this key is visible on.
///
/// The observation is the EFFECTIVE deadline `await_condition` reports, which
/// is the value it actually waited to, not a copy of the setting: the tool
/// computes it as `min(requested, ceiling)` and answers with it. Asking for an
/// hour makes the ceiling the only thing that can decide the answer.
#[cfg(feature = "mcp")]
fn probe_mcp_max_wait_seconds() -> (String, String) {
    fn effective_timeout(cfg: Option<&std::path::Path>, pcap: &std::path::Path) -> u64 {
        use std::io::{BufRead, BufReader, Write};
        let mut args: Vec<String> = vec![
            "--mcp".into(),
            "-N".into(),
            "-I".into(),
            pcap.to_str().unwrap().into(),
            "--quiet".into(),
        ];
        match cfg {
            Some(c) => {
                args.push("--config".into());
                args.push(c.to_str().unwrap().into());
            }
            None => args.push("--no-config".into()),
        }
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn mcp server");
        let mut stdin = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));

        let send = |w: &mut std::process::ChildStdin, v: serde_json::Value| {
            writeln!(w, "{v}").expect("write");
            w.flush().expect("flush");
        };
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"probe","version":"0"}}}),
        );
        let mut line = String::new();
        out.read_line(&mut line).expect("initialize reply");
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        // A filter every capture with one INVITE satisfies, so the wait ends on
        // its first look and the probe measures the ceiling rather than the
        // clock.
        send(
            &mut stdin,
            serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"await_condition","arguments":{
                "filter":"method == 'INVITE'","timeout_seconds":3600}}}),
        );

        let mut seconds = 0u64;
        for _ in 0..40 {
            line.clear();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v["id"] != serde_json::json!(2) {
                continue;
            }
            let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            seconds = parsed["timeout_seconds"].as_u64().unwrap_or(0);
            break;
        }
        let _ = child.kill();
        let _ = child.wait();
        seconds
    }

    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 1);
    let cfg = write_config(&dir, "[limits]\nmcp_max_wait_seconds = 1\n");
    (
        format!("timeout={}", effective_timeout(None, &pcap)),
        format!("timeout={}", effective_timeout(Some(&cfg), &pcap)),
    )
}

/// Placeholder for a build without the `mcp` feature; the registry marks the
/// probe disabled, so it is never called.
#[cfg(not(feature = "mcp"))]
fn probe_mcp_max_wait_seconds() -> (String, String) {
    (String::new(), String::new())
}

/// `max_streams`: a four-stream capture against a cap of one.
fn probe_max_streams() -> (String, String) {
    observe_stdout(
        &rtp_fixture(),
        "[limits]\nmax_streams = 1\n",
        &["--report"],
        |out| format!("streams={}", stream_row_count(out)),
    )
}

/// `max_reassembly`: four open TCP flows against a cap of one.
///
/// The observation is the eviction warning, which names the cap it enforced,
/// so the capped run proves the configured value reached the reassembler.
fn probe_max_reassembly() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = write_tcp_flow_pcap(&dir, 4);
    let cfg = write_config(&dir, "[limits]\nmax_reassembly = 1\n");
    let pcap = pcap.to_str().unwrap().to_string();

    let (_, plain, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap.clone(),
        "--json".into(),
        "--no-config".into(),
    ]);
    assert_eq!(code, 0, "uncapped run should exit cleanly");
    let (_, limited, code) = run_owned(&[
        "-N".into(),
        "-I".into(),
        pcap,
        "--json".into(),
        "--config".into(),
        cfg.to_str().unwrap().into(),
    ]);
    assert_eq!(code, 0, "capped run should exit cleanly");

    let seen = |err: &str| {
        if err.contains(TCP_AT_CAPACITY) {
            "tcp-reassembler-at-capacity(1)".to_string()
        } else {
            "no-eviction".to_string()
        }
    };
    (seen(&plain), seen(&limited))
}

/// `max_header_line`: a `From` line padded past a 256-byte cap.
fn probe_max_header_line() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("long-header.pcap");
    pcap_build::write_pcap(
        &pcap,
        &[pcap_build::invite_with_long_from("long-header-1", 300)],
    );
    observe_stdout(
        &pcap,
        "[limits]\nmax_header_line = 256\n",
        &["--json"],
        |out| format!("from-present={}", out.contains("\"from\":\"<sip:alice")),
    )
}

/// `max_headers_per_message`: `From` pushed past a five-header cap.
fn probe_max_headers_per_message() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("many-headers.pcap");
    pcap_build::write_pcap(
        &pcap,
        &[pcap_build::invite_with_padded_headers("many-headers-1", 40)],
    );
    observe_stdout(
        &pcap,
        "[limits]\nmax_headers_per_message = 5\n",
        &["--json"],
        |out| format!("from-present={}", out.contains("\"from\":\"<sip:alice")),
    )
}

/// `max_messages_per_dialog`: a seven-message call against a cap of two.
fn probe_max_messages_per_dialog() -> (String, String) {
    observe_stdout(
        &sip_call_fixture(),
        "[limits]\nmax_messages_per_dialog = 2\n",
        &["--json-dialogs"],
        |out| {
            let line = out
                .lines()
                .find(|l| l.starts_with('{'))
                .expect("a dialog object");
            let dialog: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            format!("msg_count={}", dialog["msg_count"])
        },
    )
}

/// The stored-message count of the long dialog in [`write_idle_dialog_pcap`].
///
/// Named rather than positional: the fixture holds a second, late call, and a
/// probe that read `dialogs[0]` would be measuring whichever one the store
/// happened to emit first.
fn idle_dialog_msg_count(out: &str) -> String {
    let dialog = out
        .lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|d| d["call_id"] == "idle-dialog@10.1.0.1")
        .expect("the long dialog must appear in --json-dialogs output");
    format!("msg_count={}", dialog["msg_count"])
}

/// `keep_messages_per_idle_dialog`: how much of a quiet ladder survives.
///
/// The uncapped run already compacts — the fixture is idle by 700s against the
/// 600s default window — so this measures the KEEP limit alone, not the
/// difference between compacting and not. The window probe below is the one
/// that measures whether compaction runs at all.
fn probe_keep_messages_per_idle_dialog() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (pcap, _) = write_idle_dialog_pcap(&dir, 5, 700);
    observe_stdout(
        &pcap,
        "[limits]\nkeep_messages_per_idle_dialog = 2\n",
        &["--json-dialogs"],
        idle_dialog_msg_count,
    )
}

/// `idle_compact_after_secs`: whether a 700-second silence counts as idle.
///
/// Under the 600s default it does, and the ladder is cut to the keep-limit.
/// Widened to an hour it does not, and every captured message survives. Same
/// capture, same sweep, opposite outcome — which is the operator-facing point
/// of the key: a call parked on hold outlives the default window while still
/// being the thing under investigation.
fn probe_idle_compact_after_secs() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (pcap, _) = write_idle_dialog_pcap(&dir, 5, 700);
    observe_stdout(
        &pcap,
        "[limits]\nidle_compact_after_secs = 3600\n",
        &["--json-dialogs"],
        idle_dialog_msg_count,
    )
}

/// `max_audio_frames`: a G.711 capture exported to WAV under two caps.
///
/// This probe drives the library rather than the binary, because no headless
/// path reaches the audio ring buffer: `app::batch` turns audio capture off
/// outright (`ss.set_audio_capture(false)`), leaving the interactive TUI —
/// which calls exactly the [`sipnab::StreamStore::set_max_audio_frames`] used
/// here — as the only consumer. The observation is still behavioral: bytes
/// of exported WAV, from the real fixture, decoder and writer.
fn probe_max_audio_frames() -> (String, String) {
    (
        exported_wav_bytes(1500).to_string(),
        exported_wav_bytes(4).to_string(),
    )
}

/// Bytes of WAV exported from the G.711 fixture with `max_audio_frames` set
/// to `cap`, through the same store API `app::tui_mode` calls.
fn exported_wav_bytes(cap: usize) -> u64 {
    use sipnab::capture::packet::Packet;
    use sipnab::capture::parse::parse_packet;
    use sipnab::capture::pcap_reader::PcapReader;
    use sipnab::rtp::audio_export::export_dialog_to_wav;
    use sipnab::rtp::parser::parse_rtp_header;
    use sipnab::rtp::stream::RtpStream;
    use sipnab::rtp::stream_store::StreamStore;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pcap-samples")
        .join("sip-rtp-g711.pcap");
    let data = std::fs::read(&path).expect("read the G.711 fixture");
    let reader = PcapReader::new(&data).expect("parse the G.711 fixture");
    let link_type = reader.link_type as i32;

    let mut store = StreamStore::new(1000);
    store.set_max_audio_frames(cap);
    for pkt in reader {
        let ts = chrono::DateTime::from_timestamp(
            pkt.timestamp_secs as i64,
            (pkt.timestamp_usecs as u64 * 1000).min(999_999_999) as u32,
        )
        .unwrap_or_default();
        let caplen = pkt.data.len();
        let origlen = pkt.orig_len as usize;
        let packet = Packet::new(ts, pkt.data, caplen, origlen, None, link_type);
        if let Ok(parsed) = parse_packet(&packet)
            && sipnab::rtp::is_rtp_packet(&parsed.payload)
            && let Ok(header) = parse_rtp_header(&parsed.payload)
        {
            store.process_rtp(&parsed, &header, ts);
        }
    }

    let streams: Vec<&RtpStream> = store
        .iter()
        .filter(|s| !s.payload_buffer.is_empty())
        .collect();
    assert!(
        !streams.is_empty(),
        "the G.711 fixture must yield buffered audio"
    );
    let dir = tempfile::tempdir().unwrap();
    let wav = dir.path().join("cap.wav");
    export_dialog_to_wav(&streams, &wav).expect("WAV export");
    std::fs::metadata(&wav).expect("WAV written").len()
}

/// `api_max_rows`: eight dialogs asked for at once, against a ceiling of two.
///
/// Observed on the ROWS the endpoint returns, not on the `limit` it echoes: a
/// wiring that moved only the echo would still hand a batch consumer a
/// thousand rows, which is the defect this key exists to fix.
#[cfg(feature = "api")]
fn probe_api_max_rows() -> (String, String) {
    fn rows_with(pcap: &std::path::Path, extra: &[&str]) -> String {
        let srv = server::ApiServer::spawn_with_pcap(pcap.to_str().unwrap(), extra);
        let resp = srv.get("/v1/dialogs?limit=1000");
        let rows = resp
            .json()
            .get("dialogs")
            .and_then(|d| d.as_array())
            .map_or(0, Vec::len);
        format!("rows={rows}")
    }

    let dir = tempfile::tempdir().unwrap();
    let pcap = write_multi_call_pcap(&dir, 8);
    let cfg = write_config(&dir, "[limits]\napi_max_rows = 2\n");
    (
        rows_with(&pcap, &["--no-config"]),
        rows_with(&pcap, &["--config", cfg.to_str().unwrap()]),
    )
}

/// Placeholder for builds without the REST API; the gate never calls it.
#[cfg(not(feature = "api"))]
fn probe_api_max_rows() -> (String, String) {
    unreachable!("the api_max_rows probe only runs in an `api` build")
}

/// `api_rate_limit_per_peer`: a burst of forty requests from one address
/// against a three-per-second ceiling.
///
/// The observation is whether any request was refused, so it does not depend
/// on exactly where the window boundary falls inside the burst.
#[cfg(feature = "api")]
fn probe_api_rate_limit_per_peer() -> (String, String) {
    fn burst_verdict(extra: &[&str]) -> String {
        let srv = server::ApiServer::spawn(extra);
        let started = std::time::Instant::now();
        let refused = (0..40)
            // 503, not 429: the limiter runs BEFORE auth, so a refusal here
            // says nothing about the credential — see `guard_scoped`.
            .filter(|_| srv.get("/v1/stats").status == 503)
            .count();
        assert_premise_inside_window("api", started.elapsed(), refused);
        if refused > 0 {
            "burst-refused".into()
        } else {
            "burst-served".into()
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\napi_rate_limit_per_peer = 3\n");
    (
        burst_verdict(&["--no-config"]),
        burst_verdict(&["--config", cfg.to_str().unwrap()]),
    )
}

/// Placeholder for builds without the REST API; the gate never calls it.
#[cfg(not(feature = "api"))]
fn probe_api_rate_limit_per_peer() -> (String, String) {
    unreachable!("the api_rate_limit_per_peer probe only runs in an `api` build")
}

/// `max_tracked_peers`: three HEP sources against a two-peer tracking map.
///
/// The refusal this key governs is `Refusal::TrackingFull`, which turns away a
/// peer that is inside every rate limit, so the observation is the warning that
/// says so — the only surface on which the condition is visible at all.
#[cfg(all(target_os = "linux", feature = "hep"))]
fn probe_max_tracked_peers() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nmax_tracked_peers = 2\n");
    (
        hep_three_peer_verdict(&["--no-config"]),
        hep_three_peer_verdict(&["--config", cfg.to_str().unwrap()]),
    )
}

/// Placeholder for builds the probe cannot run on; the gate never calls it.
#[cfg(not(all(target_os = "linux", feature = "hep")))]
fn probe_max_tracked_peers() -> (String, String) {
    unreachable!("the max_tracked_peers probe only runs on Linux `hep` builds")
}

/// `reassembly_ttl_secs`: four half-sent SIP/TCP flows left to go quiet.
///
/// This probe drives the LIBRARY rather than the binary, for a reason the
/// mechanism forces. The sweep is paced by CAPTURE time — every five seconds of
/// packet timestamps — while the TTL is measured on the wall clock, so a
/// headless file run reads the whole capture in about twenty milliseconds and
/// no entry can ever reach any TTL. There is no observation to make from the
/// outside, which is exactly why nobody noticed the TTL was unsettable. The
/// observation is still behavioral: the real fixture frames, the real
/// `PacketProcessor` constructor a capture uses, and the eviction counter every
/// `/metrics` scrape publishes.
///
/// The whole chain from the FILE is covered as well: the key is read through
/// the real loader and the real resolver, and the value that reaches the setter
/// is the one `crate::app::bootstrap` would pass.
///
/// Gated on `native` because that resolver lives on `Cli`, and `crate::cli` is
/// compiled only for a native build — a `--no-default-features --features tls`
/// check has a reassembler and no command line at all. The reassembly TTL
/// itself is wired on every build; it is the RESOLVER half this probe walks
/// that needs the feature.
#[cfg(feature = "native")]
fn probe_reassembly_ttl_secs() -> (String, String) {
    use sipnab::capture::packet::Packet;
    use sipnab::capture::reassembly::{reassembly_timeouts, set_reassembly_ttl_secs};

    fn verdict(toml: Option<&str>) -> String {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config = match toml {
            Some(t) => {
                let path = write_config(&dir, t);
                sipnab::config::Config::load(path.to_str(), false)
                    .expect("the sample config loads")
                    .config
            }
            None => sipnab::config::Config::default(),
        };
        let cli = sipnab::cli::Cli::try_parse_from(["sipnab"]).expect("parse");
        set_reassembly_ttl_secs(cli.reassembly_ttl_secs(&config));

        let mut processor = sipnab::capture::PacketProcessor::with_max_sessions(100);
        for frame in pcap_build::partial_tcp_sip_flows(4) {
            let len = frame.len();
            let _ = processor.process(&Packet::new(chrono::Utc::now(), frame, len, len, None, 1));
        }

        let before = reassembly_timeouts();
        // Past a one-second TTL and nowhere near the shipped thirty.
        std::thread::sleep(std::time::Duration::from_millis(1_400));
        processor.sweep();
        let verdict = if reassembly_timeouts() > before {
            "half-sent-flows-swept"
        } else {
            "half-sent-flows-held"
        };
        set_reassembly_ttl_secs(sipnab::capture::reassembly::DEFAULT_TTL.as_secs().max(1));
        verdict.to_string()
    }

    (
        verdict(None),
        verdict(Some("[limits]\nreassembly_ttl_secs = 1\n")),
    )
}

/// Placeholder for a build with no command line; the gate never calls it.
#[cfg(not(feature = "native"))]
fn probe_reassembly_ttl_secs() -> (String, String) {
    unreachable!("the reassembly_ttl_secs probe only runs in a `native` build")
}

/// `metrics_max_conn`: one connection parked against a one-slot gate.
///
/// The refusal is what the key governs, so the observation is whether a second
/// scrape is served or answered `503`. It is made deterministic by what an
/// UNSENT request does: the accept loop takes a permit and hands the socket to
/// a handler that blocks reading the request line for five seconds, so an idle
/// connection holds its slot for as long as the probe needs and nothing has to
/// race a real scrape.
///
/// Driven against `--hep-listen` rather than a file for the reason
/// `tests/metrics_headless_test.rs` records: a headless FILE run lives about
/// 20 ms, so any connect races a process that has already exited.
#[cfg(feature = "metrics")]
fn probe_metrics_max_conn() -> (String, String) {
    use std::io::{BufRead, BufReader, Read, Write};

    /// What `handle_metrics_connection` gives a client to send its request
    /// line, and therefore how long a parked connection holds its slot.
    /// Mirrors the `set_read_timeout` in `src/output/prometheus_server.rs`.
    const METRICS_HANDLER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Bind an ephemeral port and release it, so the probe knows the number.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let p = l.local_addr().expect("read it back").port();
        drop(l);
        p
    }

    fn second_scrape_verdict(extra: &[&str]) -> String {
        let hep = free_port();
        let metrics = free_port();
        let addr = format!("127.0.0.1:{metrics}");
        let mut args = vec![
            "-N".to_string(),
            "--hep-listen".to_string(),
            format!("127.0.0.1:{hep}"),
            "--metrics".to_string(),
            addr.clone(),
            "--quiet".to_string(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_string()));
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sipnab");

        // Wait until the server actually SERVES, not merely until a connect
        // succeeds. A bare connect takes a permit and its handler holds it for
        // as long as the read blocks, so under `metrics_max_conn = 1` the
        // readiness probe itself can still own the only slot when the parked
        // connection arrives -- the parked one is then refused, holds nothing,
        // and the measurement below reads "served" while the key works fine.
        // A completed scrape proves both that the server is up and that a
        // permit is free again.
        let ready_by = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut up = false;
        while std::time::Instant::now() < ready_by {
            if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = write!(
                    s,
                    "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                );
                let mut line = String::new();
                if BufReader::new(&s).read_line(&mut line).unwrap_or(0) > 0
                    && !line.contains(" 503 ")
                {
                    up = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(up, "the metrics server never served a scrape on {addr}");

        // Park a connection and PROVE it holds a slot, rather than sleeping and
        // assuming the accept loop got to it. The two outcomes are
        // distinguishable on the wire: a REFUSED connection is answered `503`
        // and closed, while a HELD one receives nothing at all, because its
        // handler is blocked reading a request line this probe never sends. So
        // an empty read IS the proof, and a 503 means this attempt took no slot
        // and must be retried.
        let parked_by = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let parked = loop {
            assert!(
                std::time::Instant::now() < parked_by,
                "no connection ever held a metrics slot on {addr}, so the \
                 premise this probe rests on was never established. That is a \
                 statement about this machine, not about the key."
            );
            let s = std::net::TcpStream::connect(&addr).expect("park a connection");
            let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(250)));
            let mut buf = [0u8; 32];
            match (&s).read(&mut buf) {
                // Timed out with no bytes: a handler owns this socket and is
                // blocked on the request line. The slot is held.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break s;
                }
                // Anything else -- a `503`, or a close -- means no slot was
                // taken. Drop it and try again.
                _ => {}
            }
        };
        // Every measurement below must land inside the handler's read timeout,
        // or the parked connection releases its slot mid-probe.
        let held_since = std::time::Instant::now();

        let mut status = String::from("no-answer");
        if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let _ = write!(
                s,
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            );
            let mut line = String::new();
            if BufReader::new(&s).read_line(&mut line).unwrap_or(0) > 0 {
                status = if line.contains(" 503 ") {
                    "second-scrape-refused".into()
                } else {
                    "second-scrape-served".into()
                };
            }
        }

        // A "served" verdict is only evidence about the key if the parked
        // connection still held its slot throughout. Past the handler's read
        // timeout it does not, and "served" would then say nothing -- exactly
        // the reading that would get a working key deleted.
        let elapsed = held_since.elapsed();
        assert!(
            status == "second-scrape-refused" || elapsed < METRICS_HANDLER_READ_TIMEOUT,
            "the second scrape took {elapsed:?}, past the {:?} the parked \
             connection holds its slot for, so `{status}` is not evidence \
             about metrics_max_conn -- the slot was released mid-probe. This \
             machine was too slow to OBSERVE the key; that is not the same as \
             the key being dead, and the limit must not be deleted on the \
             strength of it.",
            METRICS_HANDLER_READ_TIMEOUT
        );

        drop(parked);
        let _ = child.kill();
        let _ = child.wait();
        status
    }

    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nmetrics_max_conn = 1\n");
    (
        second_scrape_verdict(&["--no-config"]),
        second_scrape_verdict(&["--config", cfg.to_str().unwrap()]),
    )
}

/// Placeholder for builds without the metrics server; the gate never calls it.
#[cfg(not(feature = "metrics"))]
fn probe_metrics_max_conn() -> (String, String) {
    unreachable!("the metrics_max_conn probe only runs in a `metrics` build")
}

/// `hep_rate_limit`: a burst well above a one-packet-per-second ceiling.
#[cfg(all(unix, feature = "hep"))]
fn probe_hep_rate_limit() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(&dir, "[limits]\nhep_rate_limit = 1\n");
    (
        hep_burst_verdict(&["--no-config"]),
        hep_burst_verdict(&["--config", cfg.to_str().unwrap()]),
    )
}

/// Placeholder for builds without the HEP subsystem; the gate never calls it.
#[cfg(not(all(unix, feature = "hep")))]
fn probe_hep_rate_limit() -> (String, String) {
    unreachable!("the hep_rate_limit probe only runs in a `hep` build")
}

/// A spawned `--hep-listen` process, its bound port, and its stderr as a
/// stream of lines.
///
/// Extracted because two probes need the same three things — a listener on an
/// ephemeral port, the port it chose, and the log line that says what it did
/// with a packet — and differ only in what they send and which line they wait
/// for. Written twice, the copies drift on the parts that are fiddly rather
/// than interesting: reaping the child on panic, and telling "the listener has
/// not logged yet" from "the listener died".
///
/// A purpose-built spawn rather than `hep_test`'s `HepListener`: these probes
/// need only the bound port and stderr, never the JSON stdout stream that
/// harness exists to scrape.
#[cfg(all(unix, feature = "hep"))]
struct HepProbeListener {
    /// The running process. Killed on drop, however the probe leaves.
    child: std::process::Child,
    /// Stderr, one line per message, fed by a reader thread.
    lines: std::sync::mpsc::Receiver<String>,
    /// The ephemeral port the listener reported binding.
    port: u16,
}

#[cfg(all(unix, feature = "hep"))]
impl Drop for HepProbeListener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(all(unix, feature = "hep"))]
impl HepProbeListener {
    /// Spawn `sipnab -N --hep-listen 127.0.0.1:0 --json --quiet` with
    /// `extra_args`, and block until it reports the port it bound.
    fn spawn(extra_args: &[&str]) -> Self {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        support::discard_coverage_profile(&mut cmd);
        cmd.args(["-N", "--hep-listen", "127.0.0.1:0", "--json", "--quiet"])
            .args(extra_args)
            .env("SIPNAB_LOG", "debug")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn sipnab --hep-listen");
        let stderr = child.stderr.take().expect("stderr pipe");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        // Scrape the ephemeral port the listener bound.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut port = None;
        let mut drained = Vec::new();
        while Instant::now() < deadline && port.is_none() {
            match lines.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    if let Some(rest) = line.split("HEP listener started on ").nth(1)
                        && let Some(p) = rest.trim().rsplit(':').next()
                        && let Ok(p) = p.parse::<u16>()
                    {
                        port = Some(p);
                    }
                    drained.push(line);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Ok(Some(status)) = child.try_wait() {
                        let _ = child.wait();
                        panic!("sipnab --hep-listen exited early: {status}\n{drained:#?}");
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let Some(port) = port else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the listener must report its bound port within 20s: {drained:#?}");
        };
        Self { child, lines, port }
    }

    /// Wait up to ten seconds for a stderr line containing `needle`.
    ///
    /// A window rather than a sleep-then-look: the listener logs as it decides,
    /// so the answer usually arrives in milliseconds and a fixed sleep would
    /// pay for the worst case on every run.
    fn saw(&self, needle: &str) -> bool {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match self.lines.recv_timeout(Duration::from_millis(200)) {
                Ok(line) if line.contains(needle) => return true,
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        false
    }
}

/// Send one HEP3 INVITE to `port` from a socket bound to `src`, so the OUTER
/// UDP source is the peer the rate limiter keys on — which is the whole point
/// of the peer probes.
#[cfg(all(unix, feature = "hep"))]
fn send_hep_invite(src: &str, port: u16, tag: &str) {
    use std::net::UdpSocket;

    let socket = UdpSocket::bind((src, 0)).expect("bind a loopback sender");
    let endpoint = sipnab::capture::hep::HepEndpoint {
        src_addr: src.parse().expect("a literal source address"),
        dst_addr: "127.0.0.1".parse().unwrap(),
        src_port: 5060,
        dst_port: 5062,
        transport: sipnab::net::TransportProto::Udp,
    };
    let invite = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{tag}\r\n\
         From: <sip:alice@example.com>;tag=1\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: limits-{tag}@127.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let datagram = sipnab::capture::hep::build_hep_v3(
        &endpoint,
        chrono::Utc::now(),
        sipnab::capture::hep::HepProtocol::Sip,
        0,
        None,
        invite.as_bytes(),
    );
    socket
        .send_to(&datagram, ("127.0.0.1", port))
        .expect("send HEP");
}

/// Fire 40 HEP3 INVITEs from one source at a freshly spawned listener and
/// report whether it logged a rate-limit drop.
#[cfg(all(unix, feature = "hep"))]
fn hep_burst_verdict(extra_args: &[&str]) -> String {
    let mut args = vec!["--hep-allow", "127.0.0.1/32"];
    args.extend_from_slice(extra_args);
    let listener = HepProbeListener::spawn(&args);
    let started = std::time::Instant::now();
    for _ in 0..40 {
        send_hep_invite("127.0.0.1", listener.port, "hep1");
    }
    let sent_in = started.elapsed();
    let dropped = listener.saw("rate limit exceeded");
    assert_premise_inside_window("hep", sent_in, usize::from(dropped));
    if dropped {
        "burst-dropped".into()
    } else {
        "burst-accepted".into()
    }
}

/// Send one HEP3 INVITE from each of three loopback addresses and report
/// whether the listener said its peer-tracking map filled.
///
/// Three, because the floor on the map is two: a run configured at the floor
/// has room for the first two senders and must turn away the third. Linux
/// routes all of 127.0.0.0/8 to loopback, which is what makes three distinct
/// sources available without touching interface configuration — and is why the
/// probe registry marks this one Linux-only.
#[cfg(all(target_os = "linux", feature = "hep"))]
fn hep_three_peer_verdict(extra_args: &[&str]) -> String {
    let mut args = vec![
        "--hep-allow",
        "127.0.0.0/8",
        // The tracking map is only consulted when the per-peer half is ON, and
        // that half ships `off`. A generous cap keeps the map the only thing
        // that can refuse: every peer here sends one packet.
        "--hep-rate-limit-per-peer",
        "1000",
    ];
    args.extend_from_slice(extra_args);
    let listener = HepProbeListener::spawn(&args);
    // One packet from each of three sources, inside one window: the map is
    // what refuses the third, not any rate.
    for src in ["127.0.0.1", "127.0.0.2", "127.0.0.3"] {
        send_hep_invite(src, listener.port, "peers");
    }
    if listener.saw("peer tracking is full") {
        "tracking-full".into()
    } else {
        "tracking-has-room".into()
    }
}

/// Every documented `[limits]` key is known to the loader, documented once,
/// probed, and observably changes what sipnab does.
///
/// The four assertions are one contract in four parts. The key set comes from
/// `LimitsConfig` itself, so adding a field to the struct immediately fails
/// this test until the loader, the reference and the probe registry all catch
/// up — and the probe has to produce two different observations from the real
/// binary, which is precisely what `dialog_limit`, `max_streams`,
/// `max_reassembly` and `hep_rate_limit` could not do.
#[test]
fn every_documented_limits_key_changes_observable_behaviour() {
    let mut expected = limits_struct_keys();
    expected.sort();
    assert!(
        !expected.is_empty(),
        "LimitsConfig must expose its fields to serde, or this gate is blind"
    );

    // 1. The loader accepts every field; a field missing from KNOWN_KEYS
    //    would warn the operator that a real key is unknown.
    let mut toml = String::from("[limits]\n");
    for key in &expected {
        toml.push_str(&format!("{key} = 1\n"));
    }
    let unknown = sipnab::config::Config::unknown_keys(&toml).expect("the sample parses");
    assert!(
        unknown.is_empty(),
        "the loader does not know these [limits] keys: {unknown:?}"
    );

    // 2. docs/config-reference.md documents exactly those keys.
    let mut documented = documented_limits_keys();
    documented.sort();
    assert_eq!(
        documented, expected,
        "docs/config-reference.md's [limits] table and LimitsConfig disagree"
    );

    // 3. Every key carries a probe, and no probe is orphaned.
    let probes = limit_probes();
    let mut probed: Vec<String> = probes.iter().map(|p| p.key.to_string()).collect();
    probed.sort();
    assert_eq!(
        probed, expected,
        "every [limits] key needs a probe proving it changes behavior; \
         add one to limit_probes() rather than removing it from this list"
    );

    // 4. Each probe moves its observation. A key that parses, validates and
    //    documents cleanly while changing nothing fails here.
    for probe in &probes {
        if !probe.enabled {
            continue;
        }
        let (without, with) = (probe.observe)();
        assert_ne!(
            without, with,
            "[limits] {} did not change what sipnab reported: {without:?} \
             without it and {with:?} with it. The key is parsed, validated and \
             documented, so operators believe it works.\n\
             \n\
             Two different things produce this, and they need opposite fixes. \
             Either the key reaches no enforcement point -- then wire it up, or \
             remove it and its documentation -- or this probe cannot see the \
             effect it is looking for, in which case the key may be perfectly \
             sound and the PROBE is what needs fixing. Establish which before \
             deleting anything: the probes that spawn a server and time a burst \
             have a premise about the machine, and `assert_premise_inside_window` \
             guards the one that is checkable.",
            probe.key
        );
    }
}

// ── Keys outside [limits] that were silently ignored ────────────────────

/// `[display] color` reaches the output, and `--color` still beats it.
///
/// This key parsed, validated and was documented while changing nothing, for
/// the reason named on `Cli::color`: the flag carried a clap `default_value`,
/// so the field was already populated and the key had nothing to override.
///
/// Observed on real output rather than through the resolver, because the
/// resolver is exactly what a broken wiring would still satisfy. stdout here
/// is a pipe, so `auto` must produce no escapes and `always` must produce
/// some — the difference IS the wiring.
#[test]
#[cfg(feature = "native")]
fn display_color_reaches_the_output_and_the_flag_still_wins() {
    fn escapes(args: &[&str]) -> usize {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "-I", "tests/pcap-samples/sip-rtp-g711.pcap"])
            .args(args)
            .output()
            .expect("run sipnab");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains('\u{1b}'))
            .count()
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let always = dir.path().join("always.toml");
    std::fs::write(&always, "[display]\ncolor = \"always\"\n").expect("write");
    let always = always.to_str().expect("utf8");

    assert_eq!(
        escapes(&["--no-config"]),
        0,
        "piped output with no color setting must carry no escapes"
    );
    assert!(
        escapes(&["--no-config", "--color", "always"]) > 0,
        "--color always must color piped output, or this test cannot detect color at all"
    );
    assert!(
        escapes(&["--config", always]) > 0,
        "[display] color must reach the output; it was parsed and ignored before"
    );
    assert_eq!(
        escapes(&["--config", always, "--color", "never"]),
        0,
        "--color must beat the config key"
    );
}

/// `[security] kill_response` reaches the bytes put on the wire.
///
/// The response is sent from a socket, so the observable end of it is the
/// frame `build_scanner_response` produces. Asserting the resolver alone would
/// prove the value was computed, not that it is what a scanner receives.
#[test]
#[cfg(feature = "native")]
fn security_kill_response_reaches_the_wire_bytes() {
    use clap::Parser;
    let raw = b"OPTIONS sip:x@example.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKscan\r\n\
                From: <sip:scan@example.com>;tag=s1\r\n\
                To: <sip:x@example.com>\r\n\
                Call-ID: kill-response-wiring@example.com\r\n\
                CSeq: 1 OPTIONS\r\n\
                Content-Length: 0\r\n\r\n";
    let msg = sipnab::sip::parse_sip(
        raw,
        chrono::Utc::now(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        5060,
        5060,
        sipnab::net::TransportProto::Udp,
    )
    .expect("parse OPTIONS");

    let mut cfg = sipnab::config::Config::default();
    cfg.security.kill_response = Some(486);
    let cli = sipnab::cli::Cli::try_parse_from(["sipnab"]).expect("parse");

    let bytes =
        sipnab::security::scanner_kill::build_scanner_response(&msg, cli.kill_response_code(&cfg))
            .expect("response built");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.starts_with("SIP/2.0 486"),
        "[security] kill_response must reach the wire; got {:?}",
        text.lines().next()
    );

    // And the flag still wins over the key.
    let cli =
        sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "603"]).expect("parse");
    let bytes =
        sipnab::security::scanner_kill::build_scanner_response(&msg, cli.kill_response_code(&cfg))
            .expect("response built");
    assert!(
        String::from_utf8_lossy(&bytes).starts_with("SIP/2.0 603"),
        "--kill-response must beat the config key on the wire"
    );
}

/// A config `kill_response` outside 100-699 is refused, as the flag is.
///
/// Without this the file was the lenient way in: clap range-checks
/// `--kill-response`, so a value it rejects must not be accepted from TOML and
/// then written onto the network as a malformed status line.
#[test]
#[cfg(feature = "native")]
fn an_out_of_range_kill_response_is_refused_from_the_config_file() {
    let mut cfg = sipnab::config::SecurityConfig::default();
    for bad in [0u16, 99, 700, 9999] {
        cfg.kill_response = Some(bad);
        let err = cfg
            .validate()
            .expect_err("out-of-range kill_response must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("kill_response") && msg.contains(&bad.to_string()),
            "the error must name the key and the offending value; got {msg:?}"
        );
    }
    for ok in [100u16, 200, 486, 699] {
        cfg.kill_response = Some(ok);
        assert!(cfg.validate().is_ok(), "{ok} is a valid SIP status");
    }
}

/// `max_tcp_buffer` also raises the ceiling on a HELD PARTIAL, so a peer that
/// sets `PSH` on every segment is fixed by the same key.
///
/// The two ceilings shipped as separate spellings of 65536 that happened to
/// agree, and they bound the same message from opposite ends. Without a push
/// the reassembler accumulates and its own buffer decides; with one it
/// delivers each segment on arrival, the framer holds the incomplete message
/// between flushes, and the leftover ceiling decides instead. Raising only the
/// first would leave every PSH-per-write stack — which is most of them —
/// chopped at 64 KiB anyway, and from the outside that is a setting that does
/// nothing.
#[test]
#[cfg(feature = "native")]
fn the_tcp_buffer_ceiling_also_bounds_a_message_held_across_pushes() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("pushed-big-tcp-invite.pcap");
    pcap_build::write_pcap(
        &pcap,
        &pcap_build::tcp_sip_call_with_body("pushed-probe", 100_000, true),
    );
    let (shipped, raised) = observe_stdout(
        &pcap,
        "[limits]\nmax_tcp_buffer = 262144\n",
        &["--json-dialogs"],
        |out| format!("messages={}", first_dialog_msg_count(out)),
    );
    assert_ne!(
        shipped, raised,
        "a message pushed segment by segment must be bounded by the same key: \
         sipnab reported {shipped} at the shipped ceiling and {raised} at \
         256 KiB. Equal figures mean the held-partial ceiling is still a \
         separate 64 KiB constant, so the key fixes half the trunks it claims to"
    );
}

/// `[capture] ws_ports` reaches the WebSocket unwrap, `--ws-portrange` beats
/// it, and what falls outside is REPORTED instead of vanishing.
///
/// The capture is one answered call carried as SIP-over-WebSocket on 8081 —
/// where a WSS listener behind a reverse proxy commonly lands, and where
/// Kamailio, OpenSIPS and Janus all sit outside sipnab's shipped set of 80,
/// 443, 8080 and 8443. Before this the run printed a clean, complete-looking
/// zero: no dialog, no message count, and no notice of any kind. `--portrange`
/// at least says what it skipped; this said nothing at all, which is why the
/// tally is asserted here alongside the analysis it replaces.
#[test]
#[cfg(feature = "native")]
fn ws_ports_reaches_the_unwrap_and_the_skip_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("wss-8081.pcap");
    pcap_build::write_pcap(&pcap, &pcap_build::ws_sip_call("wss-probe", 8081));
    let pcap = pcap.to_str().unwrap().to_string();
    // `--portrange` is widened in every run: the WebSocket set and the
    // signaling port range are different gates, and leaving the default
    // 5060-5061 in place would let the second one claim the traffic the first
    // one just unwrapped.
    let base: Vec<String> = [
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--portrange",
        "1-65535",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    let mut shipped = base.clone();
    shipped.push("--no-config".into());
    let (out, err, code) = run_owned(&shipped);
    assert_eq!(code, 0, "the run must exit cleanly:\n{err}");
    assert_eq!(
        dialog_count(&out),
        0,
        "8081 is outside the shipped WebSocket set, so the leg is not analyzed \
         — this is the state the key exists to change:\n{out}"
    );
    assert!(
        err.contains("NOT ANALYZED") && err.contains("SIP-over-WebSocket") && err.contains("8081"),
        "the run must SAY what it skipped and name the port, or the operator is \
         told nothing whatsoever about their entire WebRTC signaling leg:\n{err}"
    );

    let cfg = write_config(&dir, "[capture]\nws_ports = \"8081-8081\"\n");
    let mut declared = base.clone();
    declared.push("--config".into());
    declared.push(cfg.to_str().unwrap().into());
    let (out, err, code) = run_owned(&declared);
    assert_eq!(code, 0, "the run must exit cleanly:\n{err}");
    assert_eq!(
        dialog_count(&out),
        1,
        "[capture] ws_ports = \"8081-8081\" must reach the unwrap:\n{out}"
    );
    assert!(
        !err.contains("SIP-over-WebSocket"),
        "nothing was skipped, so nothing may be reported as skipped:\n{err}"
    );

    // The flag beats the key, pointed somewhere the traffic is not: the leg
    // goes back to being skipped, and the report says so again.
    let mut overridden = base;
    overridden.push("--ws-portrange".into());
    overridden.push("9443-9443".into());
    overridden.push("--config".into());
    overridden.push(cfg.to_str().unwrap().into());
    let (out, err, code) = run_owned(&overridden);
    assert_eq!(code, 0, "the run must exit cleanly:\n{err}");
    assert_eq!(
        dialog_count(&out),
        0,
        "--ws-portrange must outrank the [capture] ws_ports it shadows:\n{out}"
    );
    assert!(
        err.contains("SIP-over-WebSocket") && err.contains("8081"),
        "and the traffic the narrower range excluded must be reported:\n{err}"
    );
}

// ── [names] dns_cache_entries ──────────────────────────────────────────

/// `[names] dns_cache_entries` reaches the resolver a RUN builds, and the flag
/// beats it.
///
/// Read off the constructed resolver rather than off the config, because the
/// link this covers is the one a resolved-value assertion cannot see: a key
/// that is parsed, validated, documented and then never handed to
/// `NameResolver::with_limits` produces exactly the same resolved number as a
/// wired one. What the cap then DOES — evict at the configured size rather
/// than at 4096 — is proved against the cache itself in
/// `names::tests::the_configured_cache_cap_is_the_one_the_cache_enforces`,
/// which is where the eviction is reachable.
#[test]
#[cfg(feature = "native")]
fn names_dns_cache_entries_reaches_the_resolver() {
    use clap::Parser;

    fn built_with(args: &[&str], cfg: &sipnab::config::Config) -> usize {
        let cli = sipnab::cli::Cli::try_parse_from(args).expect("parse");
        // Reverse DNS stays off in every case here, so no lookup leaves the
        // box: the cap is a property of the resolver, not of the worker.
        let (resolver, _mode) = sipnab::app::build_resolver(&cli, cfg);
        resolver.dns_cache_capacity()
    }

    let shipped = sipnab::names::MAX_DNS_CACHE_ENTRIES;
    assert_eq!(
        built_with(&["sipnab"], &sipnab::config::Config::default()),
        shipped,
        "with nothing set the run must build the cache at its own constant"
    );

    let mut tuned = sipnab::config::Config::default();
    tuned.names.dns_cache_entries = Some(9);
    assert_ne!(9, shipped, "the case value must differ from the default");
    assert_eq!(
        built_with(&["sipnab"], &tuned),
        9,
        "[names] dns_cache_entries must reach the resolver the run builds"
    );
    assert_eq!(
        built_with(&["sipnab", "--dns-cache-entries", "77"], &tuned),
        77,
        "--dns-cache-entries must outrank the key it shadows"
    );
}

// ── [sip] active_idle_window_secs ──────────────────────────────────────

/// An `InCall` dialog whose only messages are an INVITE and its 200 OK at `t0`.
///
/// Built through the public store API rather than from a fixture file so the
/// dialog reaches `InCall` the way a captured call does. The store's idea of
/// "now" is supplied per call, which is what makes the window observable
/// without waiting out one.
#[cfg(feature = "native")]
fn answered_call_store(
    t0: chrono::DateTime<chrono::Utc>,
) -> sipnab::sip::dialog_store::DialogStore {
    use sipnab::net::TransportProto;
    use sipnab::sip::parse_sip;
    let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let msg = |raw: &str, ts| {
        parse_sip(
            raw.as_bytes(),
            ts,
            loopback,
            loopback,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("the fixture message parses")
    };
    let mut store = sipnab::sip::dialog_store::DialogStore::new(100, false);
    store.process_message(msg(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKidle\r\n\
         From: <sip:alice@example.com>;tag=t1\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: idle-window@example.com\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n",
        t0,
    ));
    store.process_message(msg(
        "SIP/2.0 200 OK\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKidle\r\n\
         From: <sip:alice@example.com>;tag=t1\r\n\
         To: <sip:bob@example.com>;tag=t2\r\n\
         Call-ID: idle-window@example.com\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n",
        t0 + chrono::TimeDelta::seconds(1),
    ));
    store
}

/// `[sip] active_idle_window_secs` moves the active-call gauge.
///
/// The observation is the count itself, at one fixed instant, under two
/// windows: a call parked on hold for ninety minutes is zero channels in use
/// under the shipped hour and one under a contact center's two. Asserting the
/// resolved number instead would pass against a store that ignored it, which
/// is the state this key exists to make unreachable.
///
/// This test owns the process-wide window for the whole binary. Nothing else
/// in it reads an active count, and it restores the shipped value on the way
/// out so a later addition cannot inherit a narrowed one.
#[test]
#[cfg(feature = "native")]
fn sip_active_idle_window_reaches_the_active_call_gauge() {
    use sipnab::sip::dialog_store::{
        DEFAULT_ACTIVE_IDLE_WINDOW, active_idle_window, set_active_idle_window_secs,
    };

    let t0 = chrono::DateTime::parse_from_rfc3339("2026-08-14T12:00:00Z")
        .map(|d| d.with_timezone(&chrono::Utc))
        .expect("the fixture timestamp parses");
    let store = answered_call_store(t0);
    // Ninety minutes of silence: outside the shipped hour, inside a wider one.
    let now = t0 + chrono::TimeDelta::minutes(90);

    set_active_idle_window_secs(DEFAULT_ACTIVE_IDLE_WINDOW.num_seconds());
    assert_eq!(
        store.active_call_count_at(now),
        0,
        "under the shipped window a call silent for ninety minutes is not counted"
    );

    set_active_idle_window_secs(7200);
    assert_eq!(
        active_idle_window(),
        chrono::TimeDelta::seconds(7200),
        "the setter must be what the store reads"
    );
    assert_eq!(
        store.active_call_count_at(now),
        1,
        "[sip] active_idle_window_secs must reach the gauge: at two hours the \
         same parked call is a channel in use"
    );
    assert_eq!(
        store.active_dialog_count_at(now),
        1,
        "the wider window must reach active_dialog_count too — it shares the \
         same predicate, and a key honored by one gauge and not the other is \
         worse than none"
    );

    set_active_idle_window_secs(DEFAULT_ACTIVE_IDLE_WINDOW.num_seconds());
}

/// `--active-idle-window` outranks the `[sip]` key, which outranks the default.
#[test]
#[cfg(feature = "native")]
fn active_idle_window_precedence_is_flag_then_key_then_default() {
    use clap::Parser;
    use sipnab::sip::dialog_store::DEFAULT_ACTIVE_IDLE_WINDOW;

    let bare = sipnab::cli::Cli::try_parse_from(["sipnab"]).expect("parse");
    let shipped = DEFAULT_ACTIVE_IDLE_WINDOW.num_seconds() as u64;
    assert_eq!(
        bare.active_idle_window_secs(&sipnab::config::Config::default()),
        shipped,
        "with nothing set the resolver must report the store's own constant"
    );

    let mut tuned = sipnab::config::Config::default();
    tuned.sip.active_idle_window_secs = Some(7200);
    assert_ne!(7200, shipped, "the case value must differ from the default");
    assert_eq!(
        bare.active_idle_window_secs(&tuned),
        7200,
        "[sip] active_idle_window_secs must reach the resolver"
    );

    let flagged =
        sipnab::cli::Cli::try_parse_from(["sipnab", "--active-idle-window", "300"]).expect("parse");
    assert_eq!(
        flagged.active_idle_window_secs(&tuned),
        300,
        "--active-idle-window must outrank the key it shadows"
    );
}
