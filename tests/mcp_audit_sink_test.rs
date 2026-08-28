// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(unix, feature = "mcp"))]
//! PB10 — the append-only tool-call audit sink, end to end over real stdio.
//!
//! The unit tests in `src/mcp/audit.rs` prove the sink's own properties:
//! reopening does not truncate, a hostile argument cannot forge a record,
//! concurrent appends lose no sequence number, a failed write is reported.
//! What they cannot prove is that `--mcp-audit-file` is WIRED to them — a
//! server that never calls `append` passes every one of those tests while the
//! file stays empty.
//!
//! So this runs the real binary and reads the real file.
//!
//! The one property that only exists at this level is the reason PB10 stayed
//! open: the tracing line is suppressed by `--quiet` unless the operator also
//! sets `SIPNAB_LOG`, and a record kept for a legal-hold question cannot be
//! conditional on a log level chosen months earlier. Every test here runs with
//! `--quiet` and NO `SIPNAB_LOG`, which is the configuration under which the
//! old record did not exist.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

include!("support/timeout.rs");

/// Absolute path to a file under `tests/fixtures/`.
fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

/// One JSON-RPC line to the child.
fn send(child: &mut std::process::Child, msg: &serde_json::Value) {
    let stdin = child.stdin.as_mut().expect("stdin");
    writeln!(stdin, "{}", serde_json::to_string(msg).expect("serialize")).expect("write");
    stdin.flush().expect("flush");
}

/// Read until the response with `id` arrives.
fn read_response(
    reader: &mut BufReader<&mut std::process::ChildStdout>,
    id: i64,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(trimmed)
                    .unwrap_or_else(|e| panic!("stdout is the JSON-RPC wire: {e}\n{trimmed}"));
                if v.get("id").and_then(serde_json::Value::as_i64) == Some(id) {
                    return Some(v);
                }
            }
            Err(_) => return None,
        }
    }
    None
}

/// Run one MCP session against `audit_path`, calling each `(tool, arguments)`
/// in turn, and return the responses.
///
/// Deliberately `--quiet` with no `SIPNAB_LOG`: the configuration in which the
/// tracing audit line does not exist.
fn session(
    audit_path: &std::path::Path,
    calls: &[(&str, serde_json::Value)],
) -> Vec<serde_json::Value> {
    let pcap = fixture("sip_call.pcap");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap.to_string_lossy(),
            "--mcp",
            "--mcp-transport",
            "stdio",
            "--mcp-audit-file",
            &audit_path.to_string_lossy(),
            "--quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --mcp");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut responses = Vec::new();
    {
        let mut reader = BufReader::new(&mut stdout);
        send(
            &mut child,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "pb10-test", "version": "0"}
                }
            }),
        );
        read_response(&mut reader, 1, test_timeout(10)).expect("initialize");
        send(
            &mut child,
            &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        );
        for (i, (tool, args)) in calls.iter().enumerate() {
            let id = 2 + i as i64;
            send(
                &mut child,
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": tool, "arguments": args}
                }),
            );
            responses.push(
                read_response(&mut reader, id, test_timeout(10))
                    .unwrap_or_else(|| panic!("no response for {tool}")),
            );
        }
    }
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
    responses
}

/// Parse the audit file into one JSON value per line, failing loudly on a
/// line that does not parse — a split line is the concurrency defect, and it
/// must not be quietly skipped.
fn records(path: &std::path::Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("the audit file was never created: {e}"));
    text.lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("audit line is not JSON: {e}\n{l}"))
        })
        .collect()
}

/// The whole point of the sink: the record exists under `--quiet` with no
/// `SIPNAB_LOG`, which is exactly where the tracing line does not.
#[test]
fn every_call_is_recorded_even_with_the_log_suppressed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    session(
        &path,
        &[
            ("capture_status", serde_json::json!({})),
            ("list_dialogs", serde_json::json!({"limit": 5})),
        ],
    );

    let recs = records(&path);
    assert_eq!(
        recs.len(),
        2,
        "one record per call, and only the calls: {recs:#?}"
    );
    let tools: Vec<&str> = recs
        .iter()
        .map(|r| r["tool"].as_str().expect("tool"))
        .collect();
    assert_eq!(tools, vec!["capture_status", "list_dialogs"]);

    for (i, r) in recs.iter().enumerate() {
        assert_eq!(
            r["seq"].as_u64(),
            Some(i as u64 + 1),
            "sequence numbers must run 1..N so a gap is visible: {r}"
        );
        assert_eq!(r["outcome"], "ok");
        assert_eq!(r["caller"], "stdio", "stdio names the boundary honestly");
        assert!(r["ts"].as_str().expect("ts").contains('T'));
        assert!(r["elapsed_ms"].is_u64());
        assert!(r["error"].is_null());
    }
    assert!(
        recs[1]["args"]
            .as_str()
            .expect("args")
            .contains("\"limit\":5"),
        "\"read dialog X\" and \"read something\" answer different questions \
         later, so the arguments are the record: {}",
        recs[1]
    );
}

/// A refused call is recorded, with its reason.
///
/// An agent probing for tools a server does not serve is the traffic the
/// record is kept for, and an audit that only kept successes would answer the
/// opposite question.
#[test]
fn a_refused_call_is_recorded_with_its_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    let responses = session(
        &path,
        &[
            ("capture_status", serde_json::json!({})),
            ("no_such_tool", serde_json::json!({})),
        ],
    );
    assert!(
        responses[1]["error"].is_object(),
        "the unknown tool must be refused on the wire: {}",
        responses[1]
    );

    let recs = records(&path);
    let refused = recs
        .iter()
        .find(|r| r["tool"] == "no_such_tool")
        .unwrap_or_else(|| panic!("the probe left no record: {recs:#?}"));
    assert_eq!(refused["outcome"], "refused");
    assert!(
        !refused["error"]
            .as_str()
            .expect("a refusal must say why")
            .is_empty()
    );
}

/// A second run APPENDS. The first run's records are still there, first, and
/// the file has not been rewritten.
///
/// This is the property that makes the file an audit trail rather than a
/// scratch pad, and it is one `OpenOptions` flag away from being false.
#[test]
fn a_second_run_appends_rather_than_replacing_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    session(&path, &[("capture_status", serde_json::json!({}))]);
    let after_first = records(&path);
    assert_eq!(after_first.len(), 1);

    session(&path, &[("list_dialogs", serde_json::json!({}))]);
    let after_second = records(&path);

    assert_eq!(
        after_second.len(),
        2,
        "the second run replaced the first run's record instead of appending \
         to it: {after_second:#?}"
    );
    assert_eq!(
        after_second[0]["tool"], "capture_status",
        "the earlier run's record must still be FIRST and intact"
    );
    assert_eq!(after_second[1]["tool"], "list_dialogs");
}

/// A call that cannot be written to the audit file is REFUSED, not answered.
///
/// `/dev/full` is a real `ENOSPC` on every write — the full-disk condition
/// itself rather than a mock of it. The invariant being proved is the reason
/// to pass the flag at all: no result leaves the server that is not in the
/// file, so an operator who finds no record can conclude nothing happened
/// rather than that the recording failed.
#[cfg(target_os = "linux")]
#[test]
fn a_call_that_cannot_be_recorded_is_refused_rather_than_answered() {
    let dev_full = std::path::Path::new("/dev/full");
    if !dev_full.exists() {
        return;
    }
    let responses = session(dev_full, &[("capture_status", serde_json::json!({}))]);
    let resp = &responses[0];

    assert!(
        resp["error"].is_object(),
        "the call was ANSWERED while its record could not be written, so the \
         run is now serving a capture it has no account of: {resp}"
    );
    let message = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("audit"),
        "the caller has to be told WHY, or a full disk reads as a broken \
         tool: {resp}"
    );
}

/// Without the flag, nothing changes: no file, and the calls still answer.
///
/// The guard against a fix that makes every existing deployment depend on a
/// file it never asked for.
#[test]
fn without_the_flag_no_file_is_written_and_calls_still_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("never-created.jsonl");
    let pcap = fixture("sip_call.pcap");

    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap.to_string_lossy(),
            "--mcp",
            "--mcp-transport",
            "stdio",
            "--quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --mcp");
    let mut stdout = child.stdout.take().expect("stdout");
    {
        let mut reader = BufReader::new(&mut stdout);
        send(
            &mut child,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "pb10-test", "version": "0"}
                }
            }),
        );
        read_response(&mut reader, 1, test_timeout(10)).expect("initialize");
        send(
            &mut child,
            &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        );
        send(
            &mut child,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "capture_status", "arguments": {}}
            }),
        );
        let resp = read_response(&mut reader, 2, test_timeout(10)).expect("response");
        assert!(
            resp["result"].is_object(),
            "an unflagged run must answer exactly as before: {resp}"
        );
    }
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();

    assert!(
        !path.exists(),
        "a file nobody asked for was created at {}",
        path.display()
    );
}

/// An audit file that cannot be opened stops the run at STARTUP.
///
/// Not at the first tool call, and not silently: an operator who passed
/// `--mcp-audit-file` and got a run that recorded nothing would find out when
/// they went looking for the record, which is the one moment it cannot be
/// recreated.
#[test]
fn an_unopenable_audit_path_fails_the_run_at_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("no-such-dir").join("audit.jsonl");
    let pcap = fixture("sip_call.pcap");

    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap.to_string_lossy(),
            "--mcp",
            "--mcp-transport",
            "stdio",
            "--mcp-audit-file",
            &path.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run sipnab");

    assert!(
        !out.status.success(),
        "sipnab served MCP without the audit trail it was asked for"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mcp-audit-file"),
        "the failure must name the flag that caused it: {stderr}"
    );
}
