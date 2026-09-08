// SPDX-License-Identifier: MIT OR Apache-2.0

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
///
/// # Arguments
/// * `args` — CLI arguments to pass.
///
/// # Returns
/// The process's stdout as UTF-8; panics on a non-zero exit.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary with the deterministic env applied.
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

/// Every `--json` NDJSON line from the fixture validates against
/// `message.schema.json`, and at least 5 messages are produced.
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

/// Negative test (spec §13.3): corrupting a real message line — wrong-typed
/// src_port, missing/wrong schema_version, extra field — makes validation fail.
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

/// `--call-report --json` output validates against `call_report.schema.json`
/// for both a no-RTP call (empty timeline/streams) and an RTP G.711 call.
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

    // A call that actually went wrong, which is the shape the other two cannot
    // reach: both are healthy, so neither emits `signaling_diagnosis` at all.
    // The schema declared every other field with `additionalProperties: false`
    // and simply never mentioned this one, so real diagnosed output failed
    // validation while the suite stayed green — for as long as every fixture
    // here was a call with nothing wrong with it.
    let out = run_sipnab(&[
        "-N",
        "-I",
        "tests/pcap-samples/sip-488-codec-reject.pcapng",
        "--call-report",
        "codec-reject-synth",
        "--json",
        "--no-cli-print",
    ]);
    let inst: Value = serde_json::from_str(out.trim()).expect("failed-call report JSON parses");
    assert!(
        inst.get("signaling_diagnosis")
            .is_some_and(|d| !d.is_null()),
        "fixture must actually carry a diagnosis or this case proves nothing"
    );
    assert_valid(&v, &inst, "call_report (diagnosed failure)");
}

/// `--json-dialogs` emits the same per-dialog document the call report does,
/// one compact line per call, so it answers to the same schema.
///
/// Worth its own case because the flag is the newest way into that document
/// and the only one that emits many of them unattended: a shape that only
/// appears on the tenth call of a capture is exactly what a single
/// `--call-report` invocation cannot reach.
#[test]
fn json_dialogs_lines_validate_against_the_call_report_schema() {
    let v = load_validator("call_report.schema.json");
    let out = run_sipnab(&[
        "-N",
        "-I",
        "tests/pcap-samples/sip-auth-failure.pcapng",
        "--json-dialogs",
        "--no-cli-print",
    ]);

    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "fixture produced no dialogs, so this test proves nothing"
    );
    let mut diagnosed = 0;
    for (i, line) in lines.iter().enumerate() {
        let inst: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i} parses: {e}"));
        if inst
            .get("signaling_diagnosis")
            .is_some_and(|d| !d.is_null())
        {
            diagnosed += 1;
        }
        assert_valid(&v, &inst, &format!("json-dialogs line {i}"));
    }
    assert!(
        diagnosed > 0,
        "this fixture is chosen for carrying diagnoses; without one the \
         signaling_diagnosis shape goes unvalidated again"
    );
}

/// Negative test: removing `diagnosis`, mistyping `timing.retransmits`, or
/// adding an unknown top-level field makes the call-report schema reject.
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

/// `--json` (7 NDJSON lines) and `--json-pretty` (7-value concatenated JSON
/// stream) both validate per message and agree on the message count.
#[test]
fn json_and_json_pretty_streams_validate(/* M2 — T2.2 */) {
    // --json emits compact NDJSON (one object per line); --json-pretty emits
    // the same objects pretty-printed (multi-line, still a parseable
    // concatenated-JSON stream). Every value of each must validate, and both
    // must yield the same message count as the fixture.
    let v = load_validator("message.schema.json");

    let out = run_sipnab(&["-N", "-I", "tests/fixtures/sip_call.pcap", "--json"]);
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 7, "--json: expected 7 NDJSON messages");
    for (i, line) in lines.iter().enumerate() {
        let inst: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("--json line {i} not JSON: {e}"));
        assert_valid(&v, &inst, &format!("--json msg {i}"));
    }

    let out = run_sipnab(&["-N", "-I", "tests/fixtures/sip_call.pcap", "--json-pretty"]);
    let values: Vec<Value> = serde_json::Deserializer::from_str(&out)
        .into_iter::<Value>()
        .collect::<Result<_, _>>()
        .expect("--json-pretty must stay a parseable JSON stream");
    assert_eq!(values.len(), 7, "--json-pretty: expected 7 messages");
    for (i, inst) in values.iter().enumerate() {
        assert_valid(&v, inst, &format!("--json-pretty msg {i}"));
    }
}

/// Every schema in `tests/schemas/` compiles into a validator (well-formed),
/// including the ones whose live-output validation lives in the API tests.
///
/// This enumerates the directory rather than listing filenames. The list form
/// could not see a schema that was added but never registered: a deliberately
/// malformed `zzz_gate_probe.schema.json` dropped into `tests/schemas/` left
/// this suite at 6 passed / 0 failed, because nothing ever opened it.
#[test]
fn all_schemas_compile() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/schemas");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        // load_validator panics with the path on read/parse/compile failure.
        let _ = load_validator(&name);
        seen += 1;
    }
    // Anti-vacuity: a broken path or an empty directory must fail, not pass.
    assert!(
        seen >= 4,
        "expected at least the 4 known schemas in tests/schemas/, found {seen}"
    );
}

/// Every `InputOrigin` sipnab can report is a value the message and dialog
/// schemas accept.
///
/// The origin name is a fact written in three places — `InputOrigin::as_str`,
/// `message.schema.json` and `dialog.schema.json` — and a consumer validating
/// against a schema that omits one gets a *validation failure* on honest
/// output, which reads as sipnab emitting something wrong. The match below is
/// exhaustive by construction: a fourth variant stops this file compiling
/// until somebody adds it to both schemas.
#[test]
fn every_capture_origin_is_a_value_both_schemas_accept() {
    use sipnab::capture::parse::InputOrigin;

    let all = [InputOrigin::Wire, InputOrigin::Hep, InputOrigin::Uprobe];
    for origin in all {
        match origin {
            InputOrigin::Wire | InputOrigin::Hep | InputOrigin::Uprobe => {}
        }
    }

    for schema in ["message.schema.json", "dialog.schema.json"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/schemas")
            .join(schema);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let doc: Value = serde_json::from_str(&text).expect("schema is JSON");
        let listed = doc["properties"]["input_origin"]["enum"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("{schema} declares no input_origin enum, so it cannot validate an origin")
            });
        for origin in all {
            assert!(
                listed.iter().any(|v| v.as_str() == Some(origin.as_str())),
                "{schema} rejects `{}`, an origin sipnab really emits",
                origin.as_str()
            );
        }
        assert_eq!(
            listed.len(),
            all.len(),
            "{schema} lists {} origin(s) against {} sipnab can report, so one \
             side has a name the other does not",
            listed.len(),
            all.len()
        );
    }
}

// ── The schema and the struct are one fact written twice ────────────────
//
// Eight tests owed for the four schema gates 0.5.159 turned red. Every one of
// those four failed the same way: a field was added to a Rust projection and
// the published schema's `additionalProperties: false` refused the output.
//
// That is the gate working, and it is also the gate arriving LATE. It fires
// only when a sample happens to carry the new field — so a field the fixtures
// never exercise can be missing from the schema indefinitely, and a schema
// entry for a field the code stopped emitting can sit there forever telling a
// consumer to expect something that will never arrive. The rules below compare
// the two declarations directly, in both directions.

/// The serde field names of one struct, read out of the source.
///
/// Reading the source rather than serializing an instance, because a field
/// that is `skip_serializing_if` absent on every fixture is exactly the field
/// this is looking for — serializing one would find only the fields the
/// fixture happened to populate, which is the weakness being paid for.
fn struct_fields(file: &str, name: &str) -> Vec<String> {
    let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file))
        .unwrap_or_else(|e| panic!("read {file}: {e}"));
    let decl = format!("struct {name}");
    let start = src
        .find(&decl)
        .unwrap_or_else(|| panic!("{file} declares no `{decl}`"));
    let body = &src[start..];
    let end = body
        .find("\n}")
        .unwrap_or_else(|| panic!("`{decl}` has no closing brace"));
    let body = &body[..end];

    let field = regex::Regex::new(r"(?m)^\s{4}(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:").expect("pattern");
    let renamed = regex::Regex::new(r#"rename\s*=\s*"([^"]+)""#).expect("rename pattern");
    let mut out = Vec::new();
    for line in body.lines() {
        if let Some(c) = renamed.captures(line) {
            out.push(c[1].to_string());
            continue;
        }
        if let Some(c) = field.captures(line) {
            out.push(c[1].to_string());
        }
    }
    assert!(
        out.len() >= 5,
        "only {} field(s) parsed out of `{decl}` in {file}; the pattern has \
         stopped matching and every census below would pass vacuously",
        out.len()
    );
    out
}

/// The `properties` keys of one schema.
fn schema_properties(schema: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/schemas")
        .join(schema);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {schema}: {e}"));
    let doc: Value = serde_json::from_str(&text).expect("schema is JSON");
    doc["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("{schema} declares no properties object"))
        .keys()
        .cloned()
        .collect()
}

/// The two sides of one census, as `(in code only, in schema only)`.
fn census(fields: &[String], properties: &[String]) -> (Vec<String>, Vec<String>) {
    let code: std::collections::BTreeSet<&String> = fields.iter().collect();
    let schema: std::collections::BTreeSet<&String> = properties.iter().collect();
    (
        code.difference(&schema).map(|s| (*s).clone()).collect(),
        schema.difference(&code).map(|s| (*s).clone()).collect(),
    )
}

/// **First of eight.** Every field of the per-message projection is declared
/// in `message.schema.json`.
///
/// `extension_headers` is why this exists: it was added to `MessageJson`, the
/// schema said `additionalProperties: false`, and the first thing to notice
/// was a fixture that happened to carry it.
#[test]
fn every_message_json_field_is_declared_in_the_message_schema() {
    let (missing, _) = census(
        &struct_fields("src/output/json.rs", "MessageJson"),
        &schema_properties("message.schema.json"),
    );
    assert!(
        missing.is_empty(),
        "message.schema.json declares no {missing:?}. The schema says \
         `additionalProperties: false`, so every consumer validating sipnab's \
         output rejects a message carrying one of these."
    );
}

/// **Second of eight.** The same, for the per-dialog report.
#[test]
fn every_dialog_json_field_is_declared_in_the_call_report_schema() {
    let (missing, _) = census(
        &struct_fields("src/output/json.rs", "DialogJson"),
        &schema_properties("call_report.schema.json"),
    );
    assert!(
        missing.is_empty(),
        "call_report.schema.json declares no {missing:?}, and it refuses \
         additional properties."
    );
}

/// **Third of eight.** No schema promises a field the code cannot emit.
///
/// The other direction, and the one no runtime validation can ever catch: a
/// consumer reads the schema, writes code expecting the key, and the key never
/// arrives. Nothing fails anywhere.
#[test]
fn no_schema_promises_a_field_the_code_does_not_emit() {
    for (file, name, schema) in [
        ("src/output/json.rs", "MessageJson", "message.schema.json"),
        (
            "src/output/json.rs",
            "DialogJson",
            "call_report.schema.json",
        ),
    ] {
        let (_, phantom) = census(&struct_fields(file, name), &schema_properties(schema));
        assert!(
            phantom.is_empty(),
            "{schema} promises {phantom:?}, which `{name}` cannot emit. A \
             consumer written against the schema waits for a key that never \
             arrives, and no validation run anywhere would notice."
        );
    }
}

/// **Fourth of eight.** The census can fail, in both directions.
#[test]
fn the_schema_census_fires_on_a_disagreement() {
    let code: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
    let schema: Vec<String> = ["b", "c", "d"].iter().map(|s| (*s).to_string()).collect();
    let (missing, phantom) = census(&code, &schema);
    assert_eq!(
        missing,
        vec!["a".to_string()],
        "a code-only field is missing"
    );
    assert_eq!(
        phantom,
        vec!["d".to_string()],
        "a schema-only field is a phantom"
    );

    let (none, also_none) = census(&code, &code);
    assert!(
        none.is_empty() && also_none.is_empty(),
        "agreement is silent"
    );
}

/// **Fifth of eight.** Both schemas refuse an undeclared field.
///
/// That refusal is what turned these four gates red, and it is a feature: a
/// key sipnab has never documented reaching a consumer is how a debugging
/// field becomes an accidental contract. Pinned so nobody relaxes it to make a
/// census like the ones above go away.
#[test]
fn both_schemas_refuse_an_undeclared_field() {
    for schema in ["message.schema.json", "call_report.schema.json"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/schemas")
            .join(schema);
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(
            doc["additionalProperties"],
            Value::Bool(false),
            "{schema} accepts undeclared properties, so a field that reaches a \
             consumer without ever being documented validates cleanly"
        );
    }
}

/// **Sixth of eight.** A real termination block validates.
#[test]
fn a_termination_block_validates_against_the_call_report_schema() {
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
    let mut report: Value = serde_json::from_str(out.trim()).expect("call-report JSON parses");
    report["termination"] = serde_json::json!({
        "cause_code": 38,
        "cause_text": "Network out of order",
        "protocol": "Q.850",
        "source_header": "Reason",
        "frame_ref": 7,
    });
    assert_valid(&v, &report, "call_report with a termination block");
}

/// **Seventh of eight.** A termination block missing what it must carry is
/// refused. `source_header` and `frame_ref` are always knowable — a cause was
/// read from SOME header on SOME message — so a block without them is not a
/// sparser answer, it is a broken one.
#[test]
fn a_termination_block_without_its_required_fields_is_refused() {
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
    let base: Value = serde_json::from_str(out.trim()).expect("call-report JSON parses");

    for bad in [
        serde_json::json!({ "cause_code": 16 }),
        serde_json::json!({ "source_header": "Reason" }),
        serde_json::json!({ "frame_ref": 2 }),
        serde_json::json!({ "source_header": "Reason", "frame_ref": 2, "extra": 1 }),
    ] {
        let mut report = base.clone();
        report["termination"] = bad.clone();
        assert!(
            v.validate(&report).is_err(),
            "the schema accepted a malformed termination block: {bad}"
        );
    }
}

/// **Eighth of eight.** An extension-header list validates, and a wrongly
/// typed one does not.
#[test]
fn an_extension_header_list_validates_against_the_message_schema() {
    let v = load_validator("message.schema.json");
    let out = run_sipnab(&["-N", "-I", "tests/fixtures/sip_call.pcap", "--json"]);
    let base: Value = serde_json::from_str(out.lines().next().expect("a message")).unwrap();

    let mut good = base.clone();
    good["extension_headers"] = serde_json::json!([
        "Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1",
        "Diversion: <sip:1003@example.com>;reason=user-busy",
    ]);
    assert_valid(&v, &good, "message with extension headers");

    // The name/value OBJECT shape, which the vCon exporter's credential filter
    // could not police and which this field deliberately does not use.
    let mut bad = base;
    bad["extension_headers"] = serde_json::json!([{ "name": "Via", "value": "x" }]);
    assert!(
        v.validate(&bad).is_err(),
        "the schema accepted a name/value object list; the field is wire-form \
         strings, and the object shape is the one a name-keyed filter cannot \
         reach"
    );
}

// ── The other two schemas, and every object inside all of them ──────────
//
// Two more tests owed for `siprec`, which was in the Rust projection and in
// neither the published schema nor the OpenAPI document for several releases.
// The census written for it compared two of the four schemas; these cover the
// rest, and then the same question one level down.

/// **Seventh of ten tests owed for the five defects 0.5.159 uncovered.** The
/// two schemas the census did not reach.
///
/// `dialog.schema.json` and `stream.schema.json` describe the REST list
/// summary and the full RTP stream. Neither is validated against live output
/// here — that lands with T3.2/T3.5 — so until this, nothing in the tree
/// compared them to the Rust types they describe at all. A `siprec` in either
/// would have sat undetected exactly as the first one did, and for longer:
/// there is not even a sample to trip over it.
#[test]
fn every_remaining_schema_agrees_with_the_projection_it_describes() {
    for (file, name, schema) in [
        ("src/output/model.rs", "DialogSummary", "dialog.schema.json"),
        ("src/output/json.rs", "StreamJson", "stream.schema.json"),
    ] {
        let (missing, phantom) = census(&struct_fields(file, name), &schema_properties(schema));
        assert!(
            missing.is_empty(),
            "{schema} declares no {missing:?}, and `{name}` emits them. Every \
             schema here refuses additional properties, so a consumer \
             validating sipnab's output rejects the answer outright."
        );
        assert!(
            phantom.is_empty(),
            "{schema} promises {phantom:?}, which `{name}` cannot emit. \
             Nothing fails at runtime for this one — a consumer simply waits \
             for a key that never arrives."
        );
    }
}

/// **Eighth of ten.** Every object sipnab publishes is closed, at every depth.
///
/// `additionalProperties: false` at the root is what turned four gates red and
/// caught `siprec`. It says nothing about the objects INSIDE — and `siprec` is
/// itself a nested object with nested objects of its own, so a schema closed
/// only at the top would have accepted any shape one level down and the census
/// above would still pass.
///
/// **`vcon.schema.json` is exempt, and the exemption is paired with its
/// evidence.** It is the vCon draft's own schema, vendored: its `$id` is
/// `ietf.org`, not sipnab's. Tightening a publisher's schema means validating
/// against a document nobody publishes, so a container that passed here would
/// still be refused by every other implementation. The test asserts the file
/// really is the publisher's, so the exemption cannot be borrowed by a schema
/// sipnab owns.
#[test]
fn every_object_in_a_sipnab_schema_is_closed_at_every_depth() {
    /// Paths of every `type: object` with `properties` that admits extras.
    fn open_objects(node: &Value, path: &str, out: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                if map.get("type") == Some(&Value::String("object".into()))
                    && map.contains_key("properties")
                    && map.get("additionalProperties") != Some(&Value::Bool(false))
                {
                    out.push(if path.is_empty() {
                        "<root>".to_string()
                    } else {
                        path.to_string()
                    });
                }
                for (k, v) in map {
                    let child = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}/{k}")
                    };
                    open_objects(v, &child, out);
                }
            }
            Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    open_objects(v, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }

    let dir = repo_schemas();
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir)
        .expect("read tests/schemas")
        .flatten()
    {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !file.ends_with(".schema.json") {
            continue;
        }
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
            .expect("schema is JSON");

        if file == "vcon.schema.json" {
            // The exemption, paired with what justifies it.
            assert_eq!(
                doc["$id"].as_str(),
                Some("https://ietf.org/vcon/schemas/unsigned-vcon.json"),
                "vcon.schema.json is exempt because it is the vCon draft's own \
                 schema, vendored unchanged. Its `$id` no longer says so, which \
                 means either it was edited — and a vendored publisher schema \
                 must not be — or a schema sipnab owns has taken its name and \
                 inherited an exemption it has no claim to."
            );
            continue;
        }

        checked += 1;
        let mut open = Vec::new();
        open_objects(&doc, "", &mut open);
        assert!(
            open.is_empty(),
            "{file} leaves {} object(s) open: {open:?}\nThe root being closed \
             is what caught `siprec`; an open object one level down accepts a \
             shape nobody documented, and the field census cannot see inside \
             one.",
            open.len()
        );
    }
    assert_eq!(
        checked, 4,
        "expected sipnab's four own schemas; found {checked}. A schema added \
         without being checked here is one whose nested objects nothing closes"
    );
}

/// The directory holding the schemas this repository publishes.
fn repo_schemas() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/schemas")
}
