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
        DialogState::Cancelled,
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
        (DialogState::Cancelled, "Cancelled"),
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
        DialogState::Cancelled,
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
// (`cli.portrange.or(config.capture.portrange)` in `bootstrap::plan`,
// `cli.snaplen.or(config.capture.snaplen)`, `cli.from.or(config.filter.from)`).

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
            key: "max_audio_frames",
            enabled: true,
            observe: probe_max_audio_frames,
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

/// `max_audio_frames`: a G.711 capture exported to WAV under two caps.
///
/// This probe drives the library rather than the binary, because no headless
/// path reaches the audio ring buffer: `app::batch` turns audio capture off
/// outright (`ss.set_audio_capture(false)`), leaving the interactive TUI —
/// which calls exactly the [`sipnab::StreamStore::set_max_audio_frames`] used
/// here — as the only consumer. The observation is still behavioural: bytes
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

/// Fire 40 HEP3 INVITEs at a freshly spawned listener and report whether it
/// logged a rate-limit drop.
///
/// A purpose-built spawn rather than `hep_test`'s `HepListener`: this probe
/// needs only the bound port and stderr, never the JSON stdout stream that
/// harness exists to scrape.
#[cfg(all(unix, feature = "hep"))]
fn hep_burst_verdict(extra_args: &[&str]) -> String {
    use std::io::{BufRead, BufReader};
    use std::net::UdpSocket;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Kills the listener however the probe leaves, including on panic.
    struct Reaper(Child);
    impl Drop for Reaper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    support::discard_coverage_profile(&mut cmd);
    cmd.args([
        "-N",
        "--hep-listen",
        "127.0.0.1:0",
        "--json",
        "--quiet",
        "--hep-allow",
        "127.0.0.1/32",
    ])
    .args(extra_args)
    .env("SIPNAB_LOG", "debug")
    .env("NO_COLOR", "1")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sipnab --hep-listen");
    let stderr = child.stderr.take().expect("stderr pipe");
    let mut reaper = Reaper(child);
    let (tx, rx) = mpsc::channel();
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
        match rx.recv_timeout(Duration::from_millis(200)) {
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
                if let Ok(Some(status)) = reaper.0.try_wait() {
                    panic!("sipnab --hep-listen exited early: {status}\n{drained:#?}");
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let port = port.expect("the listener must report its bound port within 20s");

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let endpoint = sipnab::capture::hep::HepEndpoint {
        src_addr: "127.0.0.1".parse().unwrap(),
        dst_addr: "127.0.0.1".parse().unwrap(),
        src_port: 5060,
        dst_port: 5062,
    };
    let invite = b"INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKlimits\r\n\
         From: <sip:alice@example.com>;tag=1\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: limits-hep-1@127.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n";
    for _ in 0..40 {
        let datagram = sipnab::capture::hep::build_hep_v3(
            &endpoint,
            chrono::Utc::now(),
            sipnab::capture::hep::HepProtocol::Sip,
            0,
            None,
            invite,
        );
        socket
            .send_to(&datagram, ("127.0.0.1", port))
            .expect("send HEP");
    }

    // A drop is logged as it happens; give the listener a bounded window.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) if line.contains("rate limit exceeded") => return "burst-dropped".into(),
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    "burst-accepted".into()
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
        "every [limits] key needs a probe proving it changes behaviour; \
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
            "[limits] {} does not change observable behaviour: sipnab \
             reported {without:?} without it and {with:?} with it. The key \
             is parsed, validated and documented, so operators believe it \
             works — wire it to its enforcement point or delete it.",
            probe.key
        );
    }
}
