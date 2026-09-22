// SPDX-License-Identifier: MIT OR Apache-2.0

//! One analysis, two encodings, three doors.
//!
//! The capture analysis is served plain (`--json-analyze`, `GET /v1/report`,
//! MCP `get_capture_report`) and RFC 7951-encoded against the YANG module
//! `sipnab-diagnosis` (`--yang-analyze`, `GET /v1/report?format=yang-json`,
//! `get_capture_report {"format": "yang-json"}`). The claim this file tests is
//! the one that makes the second encoding worth having: it is the SAME value.
//! Each door is asked for both encodings of one run, the RFC 7951 document is
//! decoded back with the strict decoder, and the two must be equal.
//!
//! # What this file cannot check, and who does
//!
//! Whether the documents are valid YANG data is a question for a YANG
//! implementation, not for the code that wrote them. With
//! `SIPNAB_YANG_EXPORT_DIR` set, every RFC 7951 document below is also written
//! there, one file per door and fixture, and `scripts/check-yang.py` hands
//! each to libyang's `yanglint -t data`. The pre-push hook runs that, and CI
//! runs it with the tools installed. Unset, nothing is written and the
//! equality checks still run.

#![cfg(all(feature = "api", feature = "mcp", feature = "native"))]

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use sipnab::analysis::yang;

#[path = "support/server.rs"]
mod server;

#[path = "support/mcp.rs"]
mod mcp;

/// The captures `tests/analyze_test.rs` drives: every severity, a clean
/// capture, a capture with no SIP at all, and a port-gate run that is blind.
const CASES: &[(&str, &str, &[&str])] = &[
    ("stun_nat_probe", "tests/fixtures/stun_nat_probe.pcap", &[]),
    (
        "stun_sdp_mismatch",
        "tests/fixtures/stun_sdp_mismatch.pcap",
        &[],
    ),
    (
        "sip_problem_call",
        "tests/pcap-samples/sip-problem-call.pcap",
        &[],
    ),
    (
        "sip_problem_call_portrange",
        "tests/pcap-samples/sip-problem-call.pcap",
        &["--portrange", "6000-6001"],
    ),
    ("sip_call", "tests/fixtures/sip_call.pcap", &[]),
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Write one export for `scripts/check-yang.py`, when it asked for them.
fn export(door: &str, case: &str, doc: &Value) {
    let Some(dir) = std::env::var_os("SIPNAB_YANG_EXPORT_DIR").filter(|d| !d.is_empty()) else {
        return;
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("create the export directory");
    let path = dir.join(format!("{door}-{case}.json"));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(doc).expect("serializes"),
    )
    .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Decode an RFC 7951 document, or fail naming the door that wrote it.
fn decoded(door: &str, case: &str, doc: &Value) -> Value {
    yang::decode(doc).unwrap_or_else(|e| panic!("{door} {case}: not a valid document: {e}\n{doc}"))
}

/// `--json-analyze --yang-analyze` in ONE run: both lines describe the same
/// analysis, computed once.
#[test]
fn the_cli_prints_one_analysis_in_both_encodings() {
    for (case, path, extra) in CASES {
        let mut args = vec![
            "-N",
            "-I",
            path,
            "--json-analyze",
            "--yang-analyze",
            "--no-cli-print",
        ];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(repo())
            .args(&args)
            .env("SIPNAB_LOG", "warn")
            .output()
            .expect("spawn sipnab");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{case}: sipnab exited {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
        assert_eq!(lines.len(), 2, "{case}: expected two objects:\n{stdout}");
        let plain: Value = serde_json::from_str(lines[0]).expect("the plain line is JSON");
        let doc: Value = serde_json::from_str(lines[1]).expect("the RFC 7951 line is JSON");
        assert!(
            doc.get("sipnab-diagnosis:capture-analysis").is_some(),
            "{case}: the second line is not the RFC 7951 document: {doc}"
        );
        assert_eq!(
            decoded("cli", case, &doc),
            plain,
            "{case}: the two encodings of one run disagree"
        );
        export("cli", case, &doc);
    }
}

/// `--yang-analyze` alone prints the document and nothing else.
#[test]
fn the_cli_prints_the_document_alone() {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(repo())
        .args([
            "-N",
            "-I",
            "tests/fixtures/stun_sdp_mismatch.pcap",
            "--yang-analyze",
            "--no-cli-print",
        ])
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("spawn sipnab");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "one document, one line:\n{stdout}");
    let doc: Value = serde_json::from_str(lines[0]).expect("JSON");
    decoded("cli", "stun_sdp_mismatch", &doc);
}

/// `GET /v1/report?format=yang-json` is the same analysis as `GET /v1/report`,
/// under the media type RFC 8040 section 11.3.2 registers for it.
#[test]
fn rest_serves_one_analysis_in_both_encodings() {
    for (case, path, extra) in CASES {
        let srv = server::ApiServer::spawn_with_pcap(path, extra);
        let plain = srv.get("/v1/report");
        assert_eq!(plain.status, 200, "{case}: {}", plain.body);
        let yang_resp = srv.get("/v1/report?format=yang-json");
        assert_eq!(yang_resp.status, 200, "{case}: {}", yang_resp.body);
        assert_eq!(
            yang_resp.content_type.as_deref(),
            Some("application/yang-data+json"),
            "{case}: the RFC 7951 body must say what it is"
        );
        let doc: Value = serde_json::from_str(&yang_resp.body).expect("JSON");
        assert_eq!(
            decoded("rest", case, &doc),
            plain.json(),
            "{case}: the two encodings disagree"
        );
        // `json` is the default spelled out, and answers exactly as the default.
        assert_eq!(srv.get("/v1/report?format=json").json(), plain.json());
        export("rest", case, &doc);
    }
}

/// A format REST does not serve is refused, not silently answered in JSON.
#[test]
fn rest_refuses_a_format_it_does_not_serve() {
    let srv = server::ApiServer::spawn(&[]);
    for bad in ["xml", "yang-xml", "markdown", "YANG-JSON", ""] {
        let resp = srv.get(&format!("/v1/report?format={bad}"));
        assert_eq!(resp.status, 400, "format={bad:?} answered {}", resp.status);
        assert!(
            resp.body.contains("yang-json"),
            "the refusal must name what is accepted: {}",
            resp.body
        );
    }
}

/// `get_capture_report {"format": "yang-json"}` is the same analysis as the
/// default `json` answer, and the completeness envelope MCP stamps on every
/// JSON answer arrives beside the document rather than inside it: RFC 7951
/// section 4 admits no unqualified member at the top of an instance document.
#[test]
fn mcp_answers_one_analysis_in_both_encodings() {
    for (case, path, extra) in CASES {
        let mut session = mcp::McpSession::start(path, extra);
        let mut plain = session.ok("get_capture_report", serde_json::json!({}));
        let msg = session.call(
            "get_capture_report",
            serde_json::json!({"format": "yang-json"}),
        );
        let doc = mcp::ok_payload(&msg);
        let obj = doc.as_object().expect("the document is an object");
        assert!(
            obj.keys().all(|k| k.contains(':')),
            "{case}: every top-level member must be module-qualified: {doc}"
        );
        let envelope: Value = serde_json::from_str(
            msg["result"]["content"][1]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("{case}: no envelope block beside the document: {msg}")),
        )
        .expect("the envelope is JSON");
        assert_eq!(envelope["source_exhausted"], true, "{case}: {envelope}");
        for key in ["source_exhausted", "source_stopped_early"] {
            assert_eq!(
                plain[key], envelope[key],
                "{case}: the two answers disagree about `{key}`"
            );
            plain.as_object_mut().expect("object").remove(key);
        }
        assert_eq!(
            decoded("mcp", case, &doc),
            plain,
            "{case}: the two encodings disagree"
        );
        export("mcp", case, &doc);
    }
}
