// SPDX-License-Identifier: MIT OR Apache-2.0

//! An MCP tool call must reach the Prometheus exposition.
//!
//! The counters themselves are unit-tested where they are counted. What no
//! unit test can see is the wiring: `call_tool` is the one place every tool
//! call passes through, it is not reachable without fabricating a
//! `RequestContext`, and a build where the recording line was removed from it
//! would keep every one of those unit tests green while publishing zeros for a
//! server answering thousands of calls. That is the same failure the audit
//! line had before it existed — a surface that reads as wired and measures
//! nothing.
//!
//! So this drives the REAL binary: a stdio MCP session against a fixture pcap,
//! with `--metrics` bound beside it, and then scrapes the exposition over TCP.
//! Every assertion is about a series in the scrape, not about a counter in
//! process memory.

#![cfg(all(unix, feature = "mcp", feature = "metrics"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

include!("support/timeout.rs");

/// A tool name no router answers to, used to prove a refusal is counted.
///
/// Deliberately shaped like a tool rather than like junk: the point is that
/// probing shows up in the metric, and a name an operator might mistype is the
/// realistic case.
const UNKNOWN_TOOL: &str = "list_dialogs_v2";

/// A spawned `sipnab --mcp --metrics`, killed on drop so a panicking test
/// leaks neither the process nor the port.
struct McpWithMetrics {
    /// The child, held so `Drop` can reap it.
    child: Child,
    /// `host:port` the metrics server actually bound to.
    metrics_addr: String,
}

impl Drop for McpWithMetrics {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the binary with an MCP stdio server and a metrics server beside it.
///
/// # Returns
///
/// The running child and the ephemeral address the metrics server reported.
fn spawn() -> McpWithMetrics {
    let pcap = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sip_call.pcap")
        .to_string_lossy()
        .into_owned();

    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap,
            "--mcp",
            "--mcp-transport",
            "stdio",
            "--metrics",
            "127.0.0.1:0",
            "--quiet",
        ])
        // `--quiet` drops the default level to warn, and the bind line that
        // carries the ephemeral port is at info.
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --mcp --metrics");

    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let budget = test_timeout(20);
    let deadline = Instant::now() + budget;
    let mut addr = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(rest) = line.split("metrics server listening on ").nth(1) {
                    addr = Some(rest.trim().to_string());
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("sipnab exited before binding the metrics server: {status}");
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let metrics_addr = addr.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("the metrics server did not report a listening address within {budget:?}")
    });

    McpWithMetrics {
        child,
        metrics_addr,
    }
}

/// Send one JSON-RPC message on the child's stdin.
fn send(child: &mut Child, msg: &serde_json::Value) {
    let stdin = child.stdin.as_mut().expect("stdin");
    writeln!(stdin, "{}", serde_json::to_string(msg).expect("serialize")).expect("write");
    stdin.flush().expect("flush");
}

/// Read lines until one carries `id`, or the deadline passes.
fn await_id(
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

/// `GET /metrics` over a raw socket, returning the body.
fn scrape(addr: &str) -> String {
    let mut sock = TcpStream::connect(addr).expect("connect to the metrics server");
    sock.set_read_timeout(Some(test_timeout(10)))
        .expect("read timeout");
    write!(
        sock,
        "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut raw = String::new();
    sock.read_to_string(&mut raw).expect("read response");
    raw.split_once("\r\n\r\n")
        .map_or(raw.clone(), |(_, body)| body.to_string())
}

/// A tool call, and a call to a name no tool answers to, both reach the
/// exposition — with the right tool label, the right outcome, a timed
/// histogram and a byte count.
#[test]
fn a_tool_call_reaches_the_prometheus_exposition() {
    let mut server = spawn();
    let mut stdout = server.child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(&mut stdout);
    let budget = test_timeout(20);

    send(
        &mut server.child,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "metrics-wiring-test", "version": "0"}
            }
        }),
    );
    await_id(&mut reader, 1, budget).expect("initialize is answered");
    send(
        &mut server.child,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // `capture_status` takes no arguments and needs no ingested data, so its
    // outcome cannot depend on how far the replay has got.
    send(
        &mut server.child,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "capture_status", "arguments": {}}
        }),
    );
    let ok = await_id(&mut reader, 2, budget).expect("capture_status is answered");
    assert!(
        ok.get("error").is_none(),
        "capture_status must succeed for this test to be about the metric: {ok}"
    );

    send(
        &mut server.child,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": UNKNOWN_TOOL, "arguments": {}}
        }),
    );
    await_id(&mut reader, 3, budget).expect("the unknown tool is answered, with an error");

    let body = scrape(&server.metrics_addr);

    assert!(
        body.contains(r#"sipnab_mcp_tool_calls_total{tool="capture_status",outcome="ok"} 1"#),
        "the call counter did not reach the scrape — call_tool is not \
         recording:\n{body}"
    );
    assert!(
        body.contains(r#"sipnab_mcp_tool_duration_seconds_count{tool="capture_status"} 1"#),
        "the latency histogram did not reach the scrape:\n{body}"
    );
    assert!(
        body.contains(&format!(
            r#"sipnab_mcp_tool_calls_total{{tool="{UNKNOWN_TOOL}",outcome="refused"}} 1"#
        )),
        "a refusal must be counted too — probing is what this counter is for:\n{body}"
    );

    let bytes = body
        .lines()
        .find_map(|l| {
            l.strip_prefix(r#"sipnab_mcp_tool_response_bytes_total{tool="capture_status"} "#)
        })
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(|| panic!("no response-byte series for capture_status:\n{body}"));
    assert!(
        bytes > 0,
        "capture_status returned a payload, so its byte counter must have \
         moved: {bytes}"
    );

    // A refusal returns no payload, so it must NOT have invented one.
    let refused_bytes = body.lines().find_map(|l| {
        l.strip_prefix(&format!(
            r#"sipnab_mcp_tool_response_bytes_total{{tool="{UNKNOWN_TOOL}"}} "#
        ))
        .and_then(|v| v.trim().parse::<u64>().ok())
    });
    assert_eq!(
        refused_bytes,
        Some(0),
        "a refused call carries no content, so its byte counter stays at \
         zero:\n{body}"
    );
}

/// A scrape taken before any tool call publishes no MCP series at all.
///
/// The other direction of the same wiring: a formatter that emitted the
/// families unconditionally would make the assertions above pass on a build
/// where nothing was ever counted.
#[test]
fn a_server_that_has_answered_nothing_publishes_no_mcp_series() {
    let server = spawn();
    let body = scrape(&server.metrics_addr);
    assert!(
        body.contains("sipnab_"),
        "the scrape must carry the ordinary families, or this proves \
         nothing:\n{body}"
    );
    assert!(
        !body.contains("sipnab_mcp_tool"),
        "no tool call has been made, so no per-tool series may exist:\n{body}"
    );
}
