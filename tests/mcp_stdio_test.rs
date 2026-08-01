// SPDX-License-Identifier: MIT OR Apache-2.0

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

include!("support/timeout.rs");

/// Absolute path to a file under `tests/fixtures/`.
///
/// # Arguments
/// * `path` — filename relative to the fixtures directory.
fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

/// Send a single JSON-RPC line to the child's stdin.
///
/// # Arguments
/// * `child` — the spawned `sipnab --mcp` process.
/// * `msg` — the JSON-RPC message; serialized onto one line and flushed.
///
/// # Side effects
/// Writes to the child process's stdin.
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
///
/// # Arguments
/// * `reader` — buffered reader over the child's stdout.
/// * `target_id` — JSON-RPC id whose response is awaited.
/// * `timeout` — overall deadline for finding the matching response.
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

/// Call `list_dialogs` repeatedly (reusing `id`) until it returns a
/// non-empty summaries array, or fail once `timeout` elapses. Replay
/// ingestion runs asynchronously to the MCP server loop, so the first
/// call after `initialize` can legitimately observe zero dialogs on a
/// slow runner; every reply must still be well-formed.
///
/// # Returns
/// The `dialogs` array out of the `list_dialogs` page (non-empty); panics on
/// timeout or a malformed reply.
///
/// The tool answers with a page object — `{dialogs, returned, total_matched,
/// truncated, next_cursor}` — rather than a bare array, so that a caller can
/// tell 50 dialogs from the first 50 of 2311. This helper hands back the
/// `dialogs` array so its callers keep indexing rows.
///
/// # Side effects
/// Sends repeated `tools/call` requests on the child's stdin.
fn list_dialogs_until_nonempty(
    child: &mut std::process::Child,
    reader: &mut BufReader<&mut std::process::ChildStdout>,
    id: i64,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        send(
            child,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": "list_dialogs", "arguments": {}}
            }),
        );
        let resp = read_response_with_id(reader, id, test_timeout(5))
            .expect("list_dialogs response within 5s");
        assert!(
            resp["result"].is_object(),
            "list_dialogs must succeed: {resp}"
        );
        let body = resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let parsed: serde_json::Value = serde_json::from_str(body).expect("inner JSON parses");
        let dialogs = parsed["dialogs"]
            .as_array()
            .unwrap_or_else(|| panic!("list_dialogs page must carry `dialogs`: {parsed}"));
        // The count that makes a short page readable has to be there too.
        assert!(
            parsed["total_matched"].is_u64(),
            "a page without total_matched is a silently truncated answer: {parsed}"
        );
        if !dialogs.is_empty() {
            return parsed["dialogs"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "list_dialogs still empty after {timeout:?}; \
             fixture replay never surfaced a dialog"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

    let init_resp = read_response_with_id(&mut reader, 1, test_timeout(5))
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

    let list_resp = read_response_with_id(&mut reader, 2, test_timeout(5))
        .expect("tools/list response within 5s");
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
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

    // 3. tools/call list_dialogs with no filter — poll until the fixture
    //    pcap's dialog appears (sip_call.pcap has 1 dialog; ingestion is
    //    asynchronous, so the first reply may be empty on a slow runner).
    let parsed = list_dialogs_until_nonempty(&mut child, &mut reader, 3, test_timeout(10));
    let arr = parsed.as_array().expect("dialog summaries array");

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

    let report_resp = read_response_with_id(&mut reader, 4, test_timeout(5))
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

    let err_resp =
        read_response_with_id(&mut reader, 5, test_timeout(5)).expect("error response within 5s");
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
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

/// Phase 8.3 — verify the seven new tools are advertised and round-trip.
#[test]
fn stdio_mcp_phase_8_3_tools_round_trip() {
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
        .env("SIPNAB_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --mcp");

    let mut stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(&mut stdout);

    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "sipnab-test", "version": "0"}}
        }),
    );
    let _ = read_response_with_id(&mut reader, 1, test_timeout(5)).expect("initialize response");
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // tools/list — verify all 10 tools
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let list_resp =
        read_response_with_id(&mut reader, 2, test_timeout(5)).expect("tools/list response");
    let names: Vec<String> = list_resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str().map(|s| s.to_string()))
        .collect();
    for tool in [
        "list_dialogs",
        "get_dialog_report",
        "find_problems",
        "get_dialog",
        "get_message",
        "render_ladder",
        "rtp_stats",
        "search_messages",
        "tail_dialogs",
        "stats",
    ] {
        assert!(
            names.contains(&tool.to_string()),
            "expected tool {tool} to be advertised; got {names:?}"
        );
    }

    // Get the call_id we'll use for tool calls. Poll: replay ingestion is
    // asynchronous, so the dialog may not be visible yet (macOS CI flake,
    // run 29791219683: dialogs[0] was None on the first call).
    let dialogs = list_dialogs_until_nonempty(&mut child, &mut reader, 3, test_timeout(10));
    let call_id = dialogs[0]["call_id"].as_str().unwrap().to_string();

    // get_dialog
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "get_dialog",
                       "arguments": {"call_id": call_id, "max_messages": 100}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 4, test_timeout(5)).expect("get_dialog response");
    let payload_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let payload: serde_json::Value = serde_json::from_str(payload_text).unwrap();
    assert!(
        payload["messages"].is_array(),
        "get_dialog must return messages: {payload}"
    );
    assert!(payload["complete"].as_bool().unwrap_or(false));

    // get_message at index 0
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "get_message",
                       "arguments": {"call_id": call_id, "index": 0}}
        }),
    );
    let resp =
        read_response_with_id(&mut reader, 5, test_timeout(5)).expect("get_message response");
    let msg_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let msg: serde_json::Value = serde_json::from_str(msg_text).unwrap();
    assert_eq!(msg["call_id"].as_str(), Some(call_id.as_str()));

    // get_message out-of-range index → error
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "get_message",
                       "arguments": {"call_id": call_id, "index": 9999}}
        }),
    );
    let resp =
        read_response_with_id(&mut reader, 6, test_timeout(5)).expect("get_message OOR response");
    assert_eq!(resp["error"]["code"].as_i64(), Some(-32602));

    // render_ladder markdown
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "render_ladder",
                       "arguments": {"call_id": call_id, "format": "markdown"}}
        }),
    );
    let resp =
        read_response_with_id(&mut reader, 7, test_timeout(5)).expect("render_ladder response");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.is_empty(), "ladder must not be empty");

    // rtp_stats
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "rtp_stats",
                       "arguments": {"call_id": call_id}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 8, test_timeout(5)).expect("rtp_stats response");
    let body_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(body_text).unwrap();
    assert!(body["streams"].is_array());

    // search_messages with a known token from the fixture
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "search_messages",
                       "arguments": {"query": "INVITE"}}
        }),
    );
    let resp =
        read_response_with_id(&mut reader, 9, test_timeout(5)).expect("search_messages response");
    let hits_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let hits: serde_json::Value = serde_json::from_str(hits_text).unwrap();
    assert!(hits.as_array().map(|a| !a.is_empty()).unwrap_or(false));

    // tail_dialogs without cursor
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "tail_dialogs", "arguments": {}}
        }),
    );
    let resp =
        read_response_with_id(&mut reader, 10, test_timeout(5)).expect("tail_dialogs response");
    let body_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(body_text).unwrap();
    assert!(
        body["dialogs"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    );
    let next_cursor = body["next_cursor"].as_str().unwrap_or("").to_string();
    // tail again with the cursor — should produce an empty list
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "tail_dialogs",
                       "arguments": {"cursor": next_cursor}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 11, test_timeout(5))
        .expect("tail_dialogs cursor response");
    let body_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(body_text).unwrap();
    assert_eq!(
        body["dialogs"].as_array().map(|a| a.len()),
        Some(0),
        "tail with last cursor must return 0 dialogs"
    );

    // stats
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": {"name": "stats", "arguments": {}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 12, test_timeout(5)).expect("stats response");
    let body_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(body_text).unwrap();
    assert!(body["dialog_count"].as_u64().unwrap_or(0) >= 1);

    // Clean shutdown
    drop(reader);
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

/// `tail_dialogs.source_exhausted` must flip to true once the pcap replay
/// drains — a polling client (typically an LLM) relies on it to know the
/// replay is complete and stop polling. It was a hardcoded `false` stub.
#[test]
fn stdio_mcp_tail_dialogs_reports_source_exhausted_after_replay() {
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
        .env("SIPNAB_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --mcp");

    let mut stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(&mut stdout);

    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "sipnab-test", "version": "0"}}
        }),
    );
    read_response_with_id(&mut reader, 1, test_timeout(5)).expect("initialize");
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // Poll tail_dialogs until the tiny fixture replay drains. The contract
    // is polling-shaped, so the test polls exactly like a real client.
    let deadline = Instant::now() + test_timeout(10);
    let mut id: i64 = 1;
    let exhausted = loop {
        assert!(
            Instant::now() < deadline,
            "source_exhausted never became true within 10s of a tiny pcap replay"
        );
        id += 1;
        send(
            &mut child,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": "tail_dialogs", "arguments": {}}
            }),
        );
        let resp =
            read_response_with_id(&mut reader, id, test_timeout(5)).expect("tail_dialogs response");
        let body_text = resp["result"]["content"][0]["text"]
            .as_str()
            .expect("tail_dialogs text");
        let body: serde_json::Value = serde_json::from_str(body_text).expect("inner JSON");
        if body["source_exhausted"].as_bool() == Some(true) {
            break true;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(exhausted);

    drop(reader);
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

/// M3 — T3.5: assert the COMPLETE MCP tool set (count + exact names) and
/// exercise the two tools the other tests don't call (`find_problems`,
/// `security_findings`). The plan referred to "12 tools"; the server actually
/// exposes 11 — this test pins that exact set so adding/removing a tool (drift)
/// fails loudly and the plan stays honest.
#[test]
fn stdio_mcp_full_tool_set_and_remaining_tools() {
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
        .env("SIPNAB_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --mcp");

    let mut stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(&mut stdout);

    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "sipnab-test", "version": "0"}}
        }),
    );
    read_response_with_id(&mut reader, 1, test_timeout(5)).expect("initialize");
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // tools/list — assert the EXACT advertised set (catches missing AND extra).
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let list_resp = read_response_with_id(&mut reader, 2, test_timeout(5)).expect("tools/list");
    let mut names: Vec<String> = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    names.sort();
    let mut expected = vec![
        "capture_status",
        "check_codec_negotiation",
        "compare_dialogs",
        "diagnose_registration",
        "explain_response_code",
        "export_audio",
        "export_capture",
        "find_problems",
        "get_sdp_timeline",
        "list_captures",
        "get_dialog",
        "get_dialog_report",
        "get_message",
        "list_dialogs",
        "render_ladder",
        "rtp_stats",
        "search_by_time",
        "search_messages",
        "security_findings",
        "server_capabilities",
        "shutdown_server",
        "stats",
        "tail_dialogs",
        "triage_call",
    ];
    expected.sort();
    assert_eq!(names, expected, "MCP tool set drifted");
    assert_eq!(names.len(), 24, "expected exactly 24 MCP tools");

    // find_problems with default kinds (['problems']) → JSON array, no error.
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "find_problems", "arguments": {}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 3, test_timeout(5)).expect("find_problems");
    assert!(resp.get("error").is_none(), "find_problems errored: {resp}");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("find_problems text");
    let page: serde_json::Value = serde_json::from_str(text).expect("find_problems JSON");
    assert!(
        page["dialogs"].is_array(),
        "find_problems must return a page object carrying `dialogs`: {page}"
    );
    assert!(
        page["total_matched"].is_u64() && page["truncated"].is_boolean(),
        "the page must say how many matched and whether it withheld any — a \
         bare array lets an agent count its rows and answer with them: {page}"
    );

    // security_findings with no AlertEngine attached → empty JSON array, no error.
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "security_findings", "arguments": {}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 4, test_timeout(5)).expect("security_findings");
    assert!(
        resp.get("error").is_none(),
        "security_findings errored: {resp}"
    );
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("security_findings text");
    let arr = serde_json::from_str::<serde_json::Value>(text).expect("security_findings JSON");
    assert_eq!(
        arr.as_array().map(Vec::len),
        Some(0),
        "security_findings must be an empty array without an AlertEngine"
    );

    drop(reader);
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}
