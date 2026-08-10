// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end per-tool token scoping over HTTP MCP (#141).
//!
//! Spawns `sipnab --mcp --mcp-transport http --mcp-signing-key …`, mints a
//! `read`-scoped token in-process with the same key, and drives real
//! `tools/call` requests through the streamable-HTTP transport to prove the
//! GATE in both directions:
//!
//! - a read token is ACCEPTED by a read-only tool (`capture_status` answers), and
//! - a read token is REFUSED by a non-read-only tool (`shutdown_server`),
//!   with a refusal that names the tool and the scope — BEFORE the tool's
//!   own gating, so the server is provably not relying on `shutdown_server`
//!   being unarmed.
//!
//! Unlike the other MCP HTTP suites this one keeps the child's stderr, so it
//! can also assert the scope refusal lands on the `mcp_audit` line as
//! `outcome=refused` — the record an operator would grep for after the fact.
//!
//! The transport plumbing is deliberately local: the shared harness
//! (`support/mcp.rs`) only does sessionless `initialize` probes, whereas
//! `tools/call` needs the `Mcp-Session-Id` handshake and an SSE body parse.
#![cfg(all(unix, feature = "mcp-http"))]

#[path = "support/mcp.rs"]
mod mcp;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

include!("support/timeout.rs");

/// A long, deterministic signing key shared between the spawned server and
/// in-test minting.
const SIGNING_KEY: &str = "e2e-scope-signing-key-0123456789abcdef";

/// Mint a token bound to the MCP audience with the given id and scope, one
/// hour out.
fn mint_with_id(id: &str, scope: &str) -> String {
    sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        id,
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_MCP,
        scope,
    )
}

/// Mint a token bound to the MCP audience with the given scope, one hour out.
fn mint(scope: &str) -> String {
    mint_with_id(&format!("scope-test-{scope}"), scope)
}

/// Like `support/mcp.rs`'s `spawn_http`, but KEEPS the stderr channel so the
/// test can read the audit trail after the calls. The shared helper drops its
/// receiver once the listen line appears, which is fine for status-code
/// probes and useless for asserting what was audited.
fn spawn_with_stderr() -> (Child, String, mpsc::Receiver<String>) {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let pcap = mcp::fixture("sip_call.pcap");
    let pcap_str = pcap.to_string_lossy().to_string();

    let mut child = Command::new(binary)
        .args([
            "-N",
            "-I",
            &pcap_str,
            "--mcp",
            "--mcp-transport",
            "http",
            "--mcp-bind",
            "127.0.0.1:0",
            "--mcp-signing-key",
            SIGNING_KEY,
            "--quiet",
        ])
        // The audit line is emitted at info under the `mcp_audit` target.
        .env("SIPNAB_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --mcp http");

    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + test_timeout(5);
    let mut addr = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(a) = line.split("listening on ").nth(1) {
                    addr = Some(a.trim().to_string());
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let addr = addr.unwrap_or_else(|| {
        // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let _ = child.wait();
        panic!("server never reported a listening address");
    });
    (child, addr, rx)
}

/// One parsed HTTP reply: status, headers (lower-cased names), decoded body.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    /// The value of `name` (case-insensitive), if present.
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// POST `body` to `http://{addr}/mcp` with a bearer token and optional
/// `Mcp-Session-Id`, and return the parsed reply with its body de-chunked.
///
/// Raw `TcpStream` like the rest of the MCP HTTP suites, plus the two things
/// they do not need: response headers survive (the session id rides in one)
/// and `Transfer-Encoding: chunked` is decoded (SSE responses arrive that
/// way). Reads until EOF or the read timeout — request-scoped SSE streams
/// close once the response event is sent, so EOF is the normal end.
fn post_mcp(addr: &str, bearer: &str, session: Option<&str>, body: &serde_json::Value) -> Reply {
    let (host, port_str) = addr.rsplit_once(':').expect("host:port");
    let port: u16 = port_str.parse().expect("port");
    let mut stream = TcpStream::connect((host, port)).expect("connect");
    stream
        .set_read_timeout(Some(test_timeout(5)))
        .expect("read timeout");

    let body_str = serde_json::to_string(body).expect("serialize");
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Authorization: Bearer {bearer}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body_str.len(),
    );
    if let Some(sid) = session {
        req.push_str(&format!("Mcp-Session-Id: {sid}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body_str);
    stream.write_all(req.as_bytes()).expect("write");

    // Read to EOF; a timeout mid-stream keeps whatever arrived, which is
    // enough as long as the response event was flushed (asserted by the
    // JSON parse downstream, not silently accepted).
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();

    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();

    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        dechunk(rest)
    } else {
        rest.to_string()
    };
    Reply {
        status,
        headers,
        body,
    }
}

/// Decode an HTTP/1.1 chunked body (sizes in hex, CRLF-framed). Tolerant of a
/// missing terminal chunk — a read timeout can cut the tail — because the
/// caller's JSON parse is the arbiter of whether enough arrived.
fn dechunk(raw: &str) -> String {
    let mut out = String::new();
    let mut rest = raw;
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            break;
        };
        if size == 0 || after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        // Skip the chunk's trailing CRLF if present.
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

/// Extract the LAST JSON-RPC message from a response body that is either
/// plain JSON or an SSE stream of `data:` lines.
fn last_json_message(body: &str) -> serde_json::Value {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body.trim()) {
        return v;
    }
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<serde_json::Value>(d.trim()).ok())
        .next_back()
        .unwrap_or_else(|| panic!("no JSON-RPC message in body: {body:?}"))
}

/// Handshake as `bearer` and return the session id for `tools/call`s.
fn establish_session(addr: &str, bearer: &str) -> String {
    let init = post_mcp(addr, bearer, None, &mcp::initialize_payload());
    assert_eq!(init.status, 200, "initialize failed: {}", init.body);
    let session = init
        .header("mcp-session-id")
        .expect("initialize reply carries a session id")
        .to_string();
    let notify = post_mcp(
        addr,
        bearer,
        Some(&session),
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    assert!(
        notify.status == 202 || notify.status == 200,
        "initialized notification rejected: {} {}",
        notify.status,
        notify.body
    );
    session
}

/// Issue one `tools/call` in `session` and return the raw JSON-RPC reply.
fn call_tool(
    addr: &str,
    bearer: &str,
    session: &str,
    id: i64,
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let reply = post_mcp(
        addr,
        bearer,
        Some(session),
        &serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        }),
    );
    assert_eq!(
        reply.status, 200,
        "tools/call {tool} transport-level failure: {}",
        reply.body
    );
    last_json_message(&reply.body)
}

/// The GATE, over the wire: a read token reaches a read-only tool and is
/// refused by a non-read-only one, and the refusal is audited.
///
/// Both directions live in ONE test on ONE server on purpose: a build that
/// refuses everything fails the `capture_status` half, a build that accepts
/// everything fails the `shutdown_server` half, and neither can pass by the
/// other's success. A full-scope control call then proves the refusal was
/// the SCOPE's — not the tool being generally broken — because the same
/// request under a full token gets past the scope check to the tool's own
/// unarmed-shutdown refusal.
#[test]
fn a_read_token_reaches_read_only_tools_and_nothing_else() {
    let (child, addr, stderr_rx) = spawn_with_stderr();
    let read_token = mint(sipnab::auth::SCOPE_READ);
    let full_token = mint(sipnab::auth::SCOPE_FULL);

    // ── Accept half: a read-only tool answers a read token. ──────────
    let session = establish_session(&addr, &read_token);
    let ok = call_tool(
        &addr,
        &read_token,
        &session,
        2,
        "capture_status",
        serde_json::json!({}),
    );
    assert!(
        ok.get("error").is_none() && ok["result"].is_object(),
        "a read token must be able to call the read-only capture_status tool: {ok}"
    );

    // ── Refuse half: a write tool refuses the same token. ────────────
    let refused = call_tool(
        &addr,
        &read_token,
        &session,
        3,
        "shutdown_server",
        serde_json::json!({}),
    );
    let msg = refused["error"]["message"].as_str().unwrap_or_else(|| {
        panic!("shutdown_server under a read token must be a JSON-RPC error: {refused}")
    });
    assert!(
        msg.contains("shutdown_server") && msg.contains("\"read\""),
        "the refusal must name the tool and the scope: {msg}"
    );

    // ── Control: the same call under a FULL token passes the scope check
    // and reaches the tool's own gate (unarmed shutdown refuses, naming its
    // opt-in flag). This is what proves the read-token refusal above was
    // scope enforcement and not shutdown_server failing for everyone. ──
    let full_session = establish_session(&addr, &full_token);
    let gated = call_tool(
        &addr,
        &full_token,
        &full_session,
        4,
        "shutdown_server",
        serde_json::json!({}),
    );
    let gated_msg = gated["error"]["message"].as_str().unwrap_or_else(|| {
        panic!("unarmed shutdown_server must still refuse a full token: {gated}")
    });
    assert!(
        gated_msg.contains("--mcp-allow-shutdown"),
        "a full token must get past scope to the tool's own gate: {gated_msg}"
    );

    // ── The audit trail names the scope refusal. ─────────────────────
    // Tear down first so stderr is complete.
    mcp::shutdown(child);
    let mut audit = Vec::new();
    while let Ok(line) = stderr_rx.recv_timeout(Duration::from_millis(200)) {
        if line.contains("mcp_audit") {
            audit.push(line);
        }
    }
    let scope_refusals: Vec<&String> = audit
        .iter()
        .filter(|l| {
            l.contains("tool=shutdown_server ")
                && l.contains("outcome=refused")
                && l.contains("scope=read")
        })
        .collect();
    assert_eq!(
        scope_refusals.len(),
        1,
        "exactly one audited scope refusal for shutdown_server under \
         scope=read; audit lines were:\n{audit:#?}"
    );
    assert!(
        audit
            .iter()
            .any(|l| l.contains("tool=capture_status ") && l.contains("outcome=ok")),
        "the accepted read-scope capture_status call must be audited ok:\n{audit:#?}"
    );
}

/// The audit line names WHICH token made the call (PB10).
///
/// Everything else on the caller field describes the connection — the peer
/// socket, and that *a* credential verified. Under a legal hold that is not
/// enough: two agents sharing a host present two different tokens from the
/// same address, and "somebody with a valid token read this capture" does not
/// answer whose. The id is what closes that, because it is the same string the
/// operator passed to `--token-id` and the same string they would write into
/// `--mcp-revoked-file`.
///
/// Driven end to end on purpose. Every hop between the minted payload and the
/// log line is a place the id can be dropped — `verify_claims` returning it,
/// the auth middleware stamping it, the extensions carrying it into dispatch —
/// and a unit test on any one hop passes while the next one throws it away.
/// The assertion is on the byte sequence an operator would grep for, inside
/// the quoted caller field, so a build that logs the id somewhere else on the
/// line does not pass either.
#[test]
fn the_audit_line_names_the_token_that_made_the_call() {
    // Distinctive enough that it cannot match anything else on the line.
    const TOKEN_ID: &str = "pb10-audit-e2e-token";

    let (child, addr, stderr_rx) = spawn_with_stderr();
    let token = mint_with_id(TOKEN_ID, sipnab::auth::SCOPE_FULL);

    let session = establish_session(&addr, &token);
    let ok = call_tool(
        &addr,
        &token,
        &session,
        2,
        "capture_status",
        serde_json::json!({}),
    );
    assert!(
        ok.get("error").is_none() && ok["result"].is_object(),
        "the call must succeed, so the audit line below describes a real \
         answered call rather than a refusal: {ok}"
    );

    // Tear down first so stderr is complete.
    mcp::shutdown(child);
    let mut audit = Vec::new();
    while let Ok(line) = stderr_rx.recv_timeout(Duration::from_millis(200)) {
        if line.contains("mcp_audit") {
            audit.push(line);
        }
    }
    let calls: Vec<&String> = audit
        .iter()
        .filter(|l| l.contains("tool=capture_status "))
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "exactly one audited capture_status call; audit lines were:\n{audit:#?}"
    );
    let line = calls[0];
    assert!(
        line.contains(&format!(" bearer-verified scope=full token={TOKEN_ID}\"")),
        "the audit line must name the token that made the call, as the last \
         field inside the quoted caller — a token named outside those quotes \
         is not attributed to this caller: {line}"
    );
}
