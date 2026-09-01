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

/// The payload text block of a `tools/call` response.
///
/// Tools that return capture-derived data lead with a provenance note
/// (`shape::untrusted_note`), so `content[0]` is the note for those and the
/// payload for the rest. This finds the first text block that is not the note.
///
/// Worth stating plainly, because this file is the closest thing in the tree to
/// a real client: `resp["result"]["content"][0]["text"]` is exactly what an
/// external consumer would write, and it is exactly what the note broke. Any
/// client outside this repo that indexes block 0 needs the same change.
fn payload_text(resp: &serde_json::Value) -> String {
    let note = sipnab::mcp::shape::untrusted_note();
    resp["result"]["content"]
        .as_array()
        .unwrap_or_else(|| panic!("tool result must carry content: {resp}"))
        .iter()
        .filter_map(|c| c["text"].as_str())
        .find(|t| *t != note)
        .unwrap_or_else(|| panic!("no payload block besides the provenance note: {resp}"))
        .to_string()
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
        let body = payload_text(&resp);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("inner JSON parses");
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
        "capture_status",
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
    let dialog_text = payload_text(&resp);
    let payload: serde_json::Value = serde_json::from_str(&dialog_text).unwrap();
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
    let msg_text = payload_text(&resp);
    let msg: serde_json::Value = serde_json::from_str(&msg_text).unwrap();
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
    let text = payload_text(&resp);
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
    let body_text = payload_text(&resp);
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
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
    let hits_text = payload_text(&resp);
    let page: serde_json::Value = serde_json::from_str(&hits_text).unwrap();
    assert!(
        page["hits"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "search_messages must return a page object carrying `hits`: {page}"
    );
    assert!(
        page["total_matched"].is_u64() && page["truncated"].is_boolean(),
        "the page must say how many matched and whether it withheld any — a \
         bare array lets an agent count its rows and answer with them: {page}"
    );

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
    let body_text = payload_text(&resp);
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
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
    let body_text = payload_text(&resp);
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
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
            "params": {"name": "capture_status", "arguments": {}}
        }),
    );
    let resp = read_response_with_id(&mut reader, 12, test_timeout(5)).expect("stats response");
    let body_text = payload_text(&resp);
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
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
        let body_text = payload_text(&resp);
        let body: serde_json::Value = serde_json::from_str(&body_text).expect("inner JSON");
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
        "aggregate_dialogs",
        "await_condition",
        "build_evidence_package",
        "capture_health",
        "capture_status",
        "check_codec_negotiation",
        "compare_captures",
        "compare_dialogs",
        "decode_evidence",
        "decode_ng",
        "describe_endpoint",
        "diagnose_registration",
        "evaluate_expectations",
        "explain_attribution",
        "explain_response_code",
        "explain_rule",
        "export_audio",
        "export_capture",
        "find_correlated",
        "find_problems",
        "generate_fail2ban_rule",
        "generate_repro",
        "generate_wireshark_filter",
        "get_call_tree",
        "get_capture_report",
        "get_dialog",
        "get_dialog_report",
        "get_message",
        "get_sdp_timeline",
        "group_dialogs",
        "lint_dialog",
        "list_captures",
        "list_dialogs",
        "list_tls_libraries",
        "media_diagnostics",
        "open_capture",
        "reconcile_orphans",
        "query_relay",
        "render_ladder",
        "rtp_stats",
        "save_findings",
        "search_by_time",
        "search_messages",
        "security_findings",
        "server_capabilities",
        "show_evidence",
        "shutdown_server",
        "start_tls_capture",
        "stop_tls_capture",
        "tail_dialogs",
        "timeline",
        "top_talkers",
        "triage_call",
        "validate_filter",
        "validate_message",
    ];
    // The vCon pair is registered only where the exporter exists, so this
    // build's expectation has to say so too. A list that names them
    // unconditionally asserts a tool set no `mcp`-without-`vcon` build has --
    // and the two are advertised exactly when they can run, which
    // `mcp_capability_agreement_test` is what gates.
    if cfg!(feature = "vcon") {
        expected.extend_from_slice(&["export_vcon", "validate_vcon"]);
    }
    expected.sort();
    assert_eq!(names, expected, "MCP tool set drifted");
    let want = if cfg!(feature = "vcon") { 57 } else { 55 };
    assert_eq!(names.len(), want, "expected exactly {want} MCP tools");

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
    let text = payload_text(&resp);
    let page: serde_json::Value = serde_json::from_str(&text).expect("find_problems JSON");
    assert!(
        page["dialogs"].is_array(),
        "find_problems must return a page object carrying `dialogs`: {page}"
    );
    assert!(
        page["total_matched"].is_u64() && page["truncated"].is_boolean(),
        "the page must say how many matched and whether it withheld any — a \
         bare array lets an agent count its rows and answer with them: {page}"
    );

    // security_findings with nothing armed → an empty page that SAYS nothing
    // was armed, no error.
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
    let text = payload_text(&resp);
    let page = serde_json::from_str::<serde_json::Value>(&text).expect("security_findings JSON");
    assert_eq!(
        page["findings"].as_array().map(Vec::len),
        Some(0),
        "no detector was armed, so there can be no findings: {page}"
    );
    assert_eq!(
        page["detection_armed"],
        serde_json::json!(false),
        "an agent must be able to tell 'nothing was watching' from 'the \
         traffic was clean', and this server was watching for nothing: {page}"
    );

    // An unknown `kinds` value is refused by name rather than answering with
    // the same empty page a quiet capture produces.
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "security_findings", "arguments": {"kinds": ["reg-flood"]}}
        }),
    );
    let resp =
        read_response_with_id(&mut reader, 5, test_timeout(5)).expect("security_findings refusal");
    assert_eq!(
        resp["error"]["code"], -32602,
        "the hyphenated spelling --alert uses must be an error, not an empty \
         list: {resp}"
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

/// Every tool call leaves an audit line on stderr — success and refusal alike.
///
/// The `#[tool_handler]` macro used to generate the dispatch, so there was no
/// hand-written point a call passed through and nothing recorded who called
/// what. The manual `call_tool` wrapper is that point now, and this test pins
/// its EFFECT end to end: the line a real operator would grep out of a real
/// server's stderr, not the presence of a `tracing::info!` in the source.
///
/// Three properties:
/// 1. A successful call is audited with its tool name, outcome `ok`, and the
///    stdio caller identity.
/// 2. A REFUSED call (unknown tool) is audited too — probing for tools that
///    do not exist is exactly the traffic an audit log exists to show, and an
///    implementation that only logged successes would hide it.
/// 3. One line per call, not two — double-logging would make every count an
///    operator derives from this log wrong.
#[test]
fn every_tool_call_leaves_an_audit_line_on_stderr() {
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
        // The audit line is emitted at info under the `mcp_audit` target;
        // SIPNAB_LOG=info is how an operator would switch it on past --quiet.
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
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sipnab-test", "version": "0"}
            }
        }),
    );
    read_response_with_id(&mut reader, 1, test_timeout(5)).expect("initialize response");
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // One call that succeeds…
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "capture_status", "arguments": {}}
        }),
    );
    let ok_resp = read_response_with_id(&mut reader, 2, test_timeout(5)).expect("stats response");
    assert!(
        ok_resp["result"].is_object(),
        "stats must succeed: {ok_resp}"
    );

    // …and one the router refuses.
    send(
        &mut child,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}}
        }),
    );
    let err_resp =
        read_response_with_id(&mut reader, 3, test_timeout(5)).expect("refusal response");
    assert!(
        err_resp["error"].is_object(),
        "an unknown tool must be refused on the wire too: {err_resp}"
    );

    // Tear down, then read the WHOLE stderr: the audit trail as an operator
    // would find it after the fact.
    drop(reader);
    drop(stdout);
    if let Some(stdin) = child.stdin.take() {
        drop(stdin);
    }
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let mut stderr_text = String::new();
    {
        use std::io::Read;
        let mut stderr = child.stderr.take().expect("stderr");
        stderr
            .read_to_string(&mut stderr_text)
            .expect("read child stderr");
    }
    let _ = child.wait();

    let audit_lines: Vec<&str> = stderr_text
        .lines()
        .filter(|l| l.contains("mcp_audit"))
        .collect();

    let stats_lines: Vec<&&str> = audit_lines
        .iter()
        .filter(|l| l.contains("tool=capture_status "))
        .collect();
    assert_eq!(
        stats_lines.len(),
        1,
        "exactly one audit line for the one stats call; stderr was:\n{stderr_text}"
    );
    let stats_line = stats_lines[0];
    assert!(
        stats_line.contains("outcome=ok"),
        "the successful call must be audited as ok: {stats_line}"
    );
    assert!(
        stats_line.contains("caller=\"stdio\""),
        "a stdio call must be attributed to the stdio boundary: {stats_line}"
    );
    // Absence recorded as absence. An HTTP call that presents a verified token
    // carries `token=<id>` in the caller field; stdio has no bearer token at
    // all, so it must carry no such key rather than an empty or placeholder
    // one — `token=` or `token=-` would be indistinguishable from a real token
    // whose id is blank, and would put stdio into a `token=` grep.
    assert!(
        !stats_line.contains("token="),
        "stdio presents no token, so the audit line must name none — an empty \
         or placeholder id would read as a real credential: {stats_line}"
    );
    assert!(
        stats_line.contains("id=2"),
        "the audit line must carry the JSON-RPC request id: {stats_line}"
    );

    let refused_lines: Vec<&&str> = audit_lines
        .iter()
        .filter(|l| l.contains("tool=no_such_tool "))
        .collect();
    assert_eq!(
        refused_lines.len(),
        1,
        "the refused call must be audited exactly once — probing for tools that \
         do not exist is what an audit log is FOR; stderr was:\n{stderr_text}"
    );
    assert!(
        refused_lines[0].contains("outcome=refused"),
        "a refusal must be distinguishable from a success in the record: {}",
        refused_lines[0]
    );
}

/// `--mcp-rate-limit-per-peer` refuses a looping caller, on the wire and in
/// the audit trail.
///
/// The end-to-end gate for the flag: it proves the whole chain an operator
/// depends on — the flag reaches the server, `call_tool` meters the call, the
/// refusal is a retryable JSON-RPC error rather than a hang or a dropped
/// connection, and the refusal lands on the `mcp_audit` line with a running
/// total. The unit tests in `mcp::server` drive the limiter directly; nothing
/// but this proves the wiring between them.
///
/// Five calls against a cap of one, sequentially. The assertion is "at least
/// three refused" rather than "exactly four" on purpose: the window is a wall
/// clock, so a boundary crossing during the run can hand back one extra
/// allowance. It cannot hand back three, so the gate is both tight enough to
/// fail if the limiter is not wired and loose enough never to flake on it.
#[test]
fn a_looping_caller_is_rate_limited_on_the_wire_and_in_the_audit_line() {
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
            "--mcp-rate-limit-per-peer",
            "1",
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
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sipnab-test", "version": "0"}
            }
        }),
    );
    read_response_with_id(&mut reader, 1, test_timeout(5)).expect("initialize response");
    send(
        &mut child,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    let mut admitted = 0;
    let mut refused = 0;
    for id in 2..=6 {
        send(
            &mut child,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": "capture_status", "arguments": {}}
            }),
        );
        let resp = read_response_with_id(&mut reader, id, test_timeout(5)).unwrap_or_else(|| {
            panic!("no response to call {id} — a rate limit must REFUSE, not hang")
        });
        if let Some(error) = resp.get("error") {
            refused += 1;
            assert_eq!(
                error["code"].as_i64(),
                Some(-32000),
                "a rate-limit refusal must carry the retryable server-error code: {resp}"
            );
            let message = error["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("rate limit") && message.contains("retry"),
                "the refusal must tell the caller to retry shortly: {message}"
            );
        } else {
            admitted += 1;
            assert!(
                resp["result"].is_object(),
                "an admitted call must carry a result: {resp}"
            );
        }
    }
    assert!(admitted >= 1, "the first call is inside the allowance");
    assert!(
        refused >= 3,
        "five calls against a 1/s cap must be refused at least three times; \
         admitted {admitted}, refused {refused}"
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
    let mut stderr_text = String::new();
    {
        use std::io::Read;
        let mut stderr = child.stderr.take().expect("stderr");
        stderr
            .read_to_string(&mut stderr_text)
            .expect("read child stderr");
    }
    let _ = child.wait();

    let limited: Vec<&str> = stderr_text
        .lines()
        .filter(|l| l.contains("mcp_audit") && l.contains("error=rate limited"))
        .collect();
    assert!(
        limited.len() >= 3,
        "every rate-limited call must leave an audit line saying so; found \
         {} in:\n{stderr_text}",
        limited.len()
    );
    assert!(
        limited.iter().all(|l| l.contains("outcome=refused")),
        "a rate-limit refusal must be audited as a refusal like any other \
         outcome:\n{}",
        limited.join("\n")
    );
    assert!(
        limited.iter().any(|l| l.contains("refused since start")),
        "the audit line must carry the running refusal count, or a flood and a \
         confused client read identically:\n{}",
        limited.join("\n")
    );
}
