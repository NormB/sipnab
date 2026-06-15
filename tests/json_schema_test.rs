//! JSON-Schema contract tests (verification plan M1 — T1.3).
//!
//! Validates sipnab's machine-readable output against versioned schemas in
//! `tests/schemas/`. Two surfaces are reachable from the CLI today and are
//! validated against *real* output here:
//!   * `message.schema.json`  ← `--json` NDJSON lines
//!   * `call_report.schema.json` ← `--call-report --json`
//!
//! `dialog.schema.json` (REST list summary) and `stream.schema.json` (full RTP
//! stream) are only emitted by the REST API; their live-output validation lands
//! in M3 (T3.2/T3.5, which depend on T1.3). Until then `all_schemas_compile`
//! proves every schema is well-formed.
//!
//! Per spec §13.3 every schema validated here also has a NEGATIVE test: a
//! schema that accepts anything is worthless, so we prove each one rejects a
//! wrong-typed field, a missing required field, and an unexpected field.

use std::process::Command;

use serde_json::Value;

#[path = "support/mod.rs"]
mod support;

use support::schema::{assert_valid, load_validator};

/// Run the built binary with the determinism contract and return stdout.
fn run_sipnab(args: &[&str]) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(manifest).args(args);
    support::deterministic_env(&mut cmd);
    let out = cmd.output().expect("spawn sipnab");
    assert!(
        out.status.success(),
        "sipnab {args:?} exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

#[test]
fn message_schema_validates_ndjson_output() {
    let v = load_validator("message.schema.json");
    let out = run_sipnab(&["-N", "-I", "tests/fixtures/sip_call.pcap", "--json"]);
    let mut n = 0;
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let inst: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("NDJSON line {n} not JSON: {e}\n{line}"));
        assert_valid(&v, &inst, &format!("message line {n}"));
        n += 1;
    }
    assert!(
        n >= 5,
        "expected several SIP messages from sip_call.pcap, got {n}"
    );
}

#[test]
fn message_schema_rejects_malformed() {
    let v = load_validator("message.schema.json");
    // Ground the negative test in a REAL good line, then corrupt it.
    let out = run_sipnab(&["-N", "-I", "tests/fixtures/sip_call.pcap", "--json"]);
    let good: Value = serde_json::from_str(out.lines().next().expect("≥1 message")).unwrap();
    assert!(v.is_valid(&good), "sanity: real message must validate");

    // (a) wrong type for a required field
    let mut bad = good.clone();
    bad["src_port"] = Value::String("not-a-port".into());
    assert!(!v.is_valid(&bad), "must reject src_port as string");

    // (b) missing required field
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("schema_version");
    assert!(!v.is_valid(&bad), "must reject missing schema_version");

    // (c) wrong schema_version value
    let mut bad = good.clone();
    bad["schema_version"] = Value::from(2);
    assert!(!v.is_valid(&bad), "must reject schema_version != 1");

    // (d) unexpected extra field (additionalProperties:false)
    let mut bad = good.clone();
    bad["surprise"] = Value::Bool(true);
    assert!(!v.is_valid(&bad), "must reject unknown field");
}

#[test]
fn call_report_schema_validates_output() {
    let v = load_validator("call_report.schema.json");

    // No-RTP call: exercises the base shape with empty sdp_timeline/streams.
    let out = run_sipnab(&[
        "-N",
        "-I",
        "tests/fixtures/sip_call.pcap",
        "--call-report",
        "test-call-1@10.0.0.1",
        "--json",
        "--no-cli-print",
    ]);
    let inst: Value = serde_json::from_str(out.trim()).expect("call-report JSON parses");
    assert_valid(&v, &inst, "call_report (sip_call)");

    // RTP call: exercises sdp_timeline entries + from_display/to_display.
    let out = run_sipnab(&[
        "-N",
        "-I",
        "tests/pcap-samples/sip-rtp-g711.pcap",
        "--call-report",
        "1-1966@10.0.2.20",
        "--json",
        "--no-cli-print",
    ]);
    let inst: Value = serde_json::from_str(out.trim()).expect("RTP call-report JSON parses");
    assert_valid(&v, &inst, "call_report (rtp g711)");
}

#[test]
fn call_report_schema_rejects_malformed() {
    let v = load_validator("call_report.schema.json");
    let out = run_sipnab(&[
        "-N",
        "-I",
        "tests/fixtures/sip_call.pcap",
        "--call-report",
        "test-call-1@10.0.0.1",
        "--json",
        "--no-cli-print",
    ]);
    let good: Value = serde_json::from_str(out.trim()).unwrap();
    assert!(v.is_valid(&good), "sanity: real call report must validate");

    // (a) missing required nested object
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("diagnosis");
    assert!(!v.is_valid(&bad), "must reject missing diagnosis");

    // (b) wrong type on a nested required field
    let mut bad = good.clone();
    bad["timing"]["retransmits"] = Value::String("lots".into());
    assert!(!v.is_valid(&bad), "must reject non-integer retransmits");

    // (c) unexpected extra field
    let mut bad = good.clone();
    bad["unexpected"] = Value::from(1);
    assert!(!v.is_valid(&bad), "must reject unknown top-level field");
}

#[test]
fn all_schemas_compile() {
    // dialog + stream get live-output validation in M3; prove well-formed now.
    for name in [
        "message.schema.json",
        "dialog.schema.json",
        "stream.schema.json",
        "call_report.schema.json",
    ] {
        let _ = load_validator(name);
    }
}
