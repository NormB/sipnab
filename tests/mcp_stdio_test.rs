#![cfg(all(unix, feature = "mcp"))]
//! Phase 8.1 — end-to-end stdio MCP integration test.
//!
//! Spawns `sipnab --mcp -I <pcap> --no-tui` with the stdio transport,
//! sends a JSON-RPC `initialize` request followed by `tools/list` and a
//! `tools/call` for `find_problems`, and asserts every line on stdout
//! parses as valid JSON-RPC with no log lines bleeding in.
//!
//! This is the regression test for Gotcha 1 (stdio mode: stdout is the
//! JSON-RPC wire). If the tracing-subscriber initializer ever drifts back
//! to stdout, this test fails.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

/// Send a single JSON-RPC line to the child's stdin.
fn send(child: &mut std::process::Child, msg: &serde_json::Value) {
    let stdin = child.stdin.as_mut().expect("stdin");
    let line = serde_json::to_string(msg).expect("serialize");
    writeln!(stdin, "{line}").expect("write");
    stdin.flush().expect("flush");
}

/// Read JSON-RPC response lines from the child up to `timeout`. Each line
/// must parse as JSON; if any line fails to parse, the test fails (that's
/// the Gotcha 1 regression signal). Returns the response with the matching
/// `id`, or `None` on timeout.
fn read_response_with_id(
    reader: &mut BufReader<&mut std::process::ChildStdout>,
    target_id: i64,
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
                let v: serde_json::Value = serde_json::from_str(trimmed).unwrap_or_else(|e| {
                    panic!(
                        "stdout line did not parse as JSON-RPC (Gotcha 1 regression?): \
                         {e}\nline: {trimmed}"
                    )
                });
                if v.get("id").and_then(|i| i.as_i64()) == Some(target_id) {
                    return Some(v);
                }
                // Notification or other id — keep reading.
            }
            Err(_) => return None,
        }
    }
    None
}

/// Spawn `sipnab --mcp` with the given pcap and verify the stdio JSON-RPC
/// session round-trips correctly for all three v0.4 tools.
#[test]
fn stdio_mcp_round_trips_three_tools() {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let pcap = fixture("sip_call.pcap");
    let pcap_str = pcap.to_string_lossy().to_string();

    let mut child = Command::new(binary)
        .args([
            "-N",
            "-I",
            &pcap_str,
            "--mcp",
            "--mcp-transport",
            "stdio",
            "--quiet",
        ])
        // Force INFO logging so any subscriber misconfiguration leaks visibly.
        .env("SIPNAB_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --mcp");

    // Take stdout out of the child for buffered reading.
    let mut stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(&mut stdout);

    // 1. initialize
    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "sipnab-test", "version": "0"}
        }
    });
    send(&mut child, &init);

    let init_resp = read_response_with_id(&mut reader, 1, Duration::from_secs(5))
        .expect("initialize response within 5s");
    assert!(
        init_resp.get("result").is_some(),
        "initialize must succeed; got: {init_resp}"
    );

    // notifications/initialized (no id) — required to complete handshake
    let initd = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    send(&mut child, &initd);

    // 2. tools/list — verify the three tools are advertised
    let list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    send(&mut child, &list);

    let list_resp = read_response_with_id(&mut reader, 2, Duration::from_secs(5))
        .expect("tools/list response within 5s");
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names.contains(&"list_dialogs"),
        "list_dialogs must be advertised; got: {names:?}"
    );
    assert!(
        names.contains(&"get_dialog_report"),
        "get_dialog_report must be advertised; got: {names:?}"
    );
    assert!(
        names.contains(&"find_problems"),
        "find_problems must be advertised; got: {names:?}"
    );

    // 3. tools/call list_dialogs with no filter — should return some dialogs
    //    from the pcap (sip_call.pcap has 1 dialog).
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "list_dialogs",
            "arguments": {}
        }
    });
    send(&mut child, &call);

    let call_resp = read_response_with_id(&mut reader, 3, Duration::from_secs(5))
        .expect("list_dialogs response within 5s");
    let result = &call_resp["result"];
    assert!(result.is_object(), "result must be present: {call_resp}");
    // The result.content[0].text is a JSON-encoded array of summaries.
    let content = &result["content"][0];
    let body = content["text"].as_str().expect("text content");
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("inner JSON parses");
    let arr = parsed.as_array().expect("dialog summaries array");
    assert!(
        !arr.is_empty(),
        "fixture pcap has at least 1 dialog; expected non-empty list"
    );

    // 4. tools/call get_dialog_report with the call_id from the list — round-trip
    let call_id = arr[0]["call_id"].as_str().expect("call_id field");
    let call_report = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_dialog_report",
            "arguments": {"call_id": call_id, "format": "json"}
        }
    });
    send(&mut child, &call_report);

    let report_resp = read_response_with_id(&mut reader, 4, Duration::from_secs(5))
        .expect("get_dialog_report response within 5s");
    assert!(
        report_resp["result"].is_object(),
        "get_dialog_report must succeed: {report_resp}"
    );

    // 5. tools/call get_dialog_report with unknown call_id — must error,
    //    not panic, with code -32602 (invalid params).
    let call_unknown = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "get_dialog_report",
            "arguments": {"call_id": "does-not-exist@nowhere", "format": "json"}
        }
    });
    send(&mut child, &call_unknown);

    let err_resp = read_response_with_id(&mut reader, 5, Duration::from_secs(5))
        .expect("error response within 5s");
    assert!(
        err_resp["error"].is_object(),
        "unknown call_id must return error: {err_resp}"
    );
    assert_eq!(
        err_resp["error"]["code"].as_i64(),
        Some(-32602),
        "expected invalid_params (-32602): {err_resp}"
    );

    // Clean shutdown.
    drop(reader);
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}
