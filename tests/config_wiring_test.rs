//! Integration tests for config-wiring and schema-drift bugs.
//!
//! Verifies that config file values are properly used as fallbacks for CLI flags,
//! that JSON output schema is complete, and that DialogState Display/Debug stay
//! consistent (which CSV export relies on).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

// ── Helpers ──────────────────────────────────────────────────────────────

fn sip_call_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sip_call.pcap")
}

/// Run sipnab with the given arguments and return (stdout, stderr, exit_code).
fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("failed to execute sipnab");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Write a temporary config file and return its path (kept alive by the tempdir).
fn write_config(dir: &tempfile::TempDir, content: &str) -> PathBuf {
    let path = dir.path().join("sipnab.toml");
    let mut f = std::fs::File::create(&path).unwrap();
    write!(f, "{}", content).unwrap();
    path
}

// ═══════════════════════════════════════════════════════════════════════════
//  Test 1: json_output_schema_is_complete
// ═══════════════════════════════════════════════════════════════════════════

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
