#![cfg(all(unix, feature = "mcp-http"))]
//! Phase 8.2 — end-to-end HTTP MCP integration test.
//!
//! Spawns `sipnab --mcp --mcp-transport http --mcp-bind 127.0.0.1:0` against
//! a fixture pcap, then issues HTTP JSON-RPC requests to verify:
//! - non-loopback bind without token is refused
//! - missing/invalid bearer token returns 401
//! - valid token round-trips initialize → tools/list

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

/// Spawn sipnab with HTTP MCP and return the child + the bind address it
/// actually started on (since we use port 0). Reads stderr for the
/// "MCP HTTP server listening on" log line.
fn spawn_http(extra_args: &[&str]) -> Option<(std::process::Child, String)> {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let pcap = fixture("sip_call.pcap");
    let pcap_str = pcap.to_string_lossy().to_string();

    let mut cmd = Command::new(binary);
    cmd.args([
        "-N",
        "-I",
        &pcap_str,
        "--mcp",
        "--mcp-transport",
        "http",
        "--quiet",
    ]);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.env("SIPNAB_LOG", "info");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sipnab");
    let stderr = child.stderr.take().expect("stderr");

    // Stream stderr in a background thread so we can capture the bind line
    // before the test issues requests.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(addr) = line.split("listening on ").nth(1) {
                return Some((child, addr.trim().to_string()));
            }
            if line.contains("refuses to start") {
                // Process won't exit on its own (capture loop holds it open);
                // SIGTERM it so wait() returns.
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGTERM);
                }
                let _ = child.wait();
                return None;
            }
        } else if let Ok(Some(_)) = child.try_wait() {
            return None;
        }
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
    None
}

fn shutdown(mut child: std::process::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

#[test]
fn http_mcp_non_loopback_without_token_refuses_to_start() {
    let result = spawn_http(&["--mcp-bind", "0.0.0.0:0"]);
    assert!(
        result.is_none(),
        "non-loopback bind without --mcp-token must refuse to start (D18)"
    );
}

#[test]
fn http_mcp_loopback_no_auth_initialize_succeeds() {
    let (child, addr) = match spawn_http(&["--mcp-bind", "127.0.0.1:0"]) {
        Some(p) => p,
        None => panic!("failed to start MCP HTTP server"),
    };
    let url = format!("http://{addr}/mcp");

    // Send an initialize request with no auth header — loopback + no token
    // configured = no auth required.
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    });
    let resp = ureq_post(&url, None, &payload);
    assert_eq!(
        resp.status, 200,
        "initialize should succeed; body: {}",
        resp.body
    );

    shutdown(child);
}

#[test]
fn http_mcp_with_token_rejects_missing_and_wrong_tokens() {
    let token = "supersecret-test-token";
    let (child, addr) = match spawn_http(&["--mcp-bind", "127.0.0.1:0", "--mcp-token", token]) {
        Some(p) => p,
        None => panic!("failed to start MCP HTTP server with token"),
    };
    let url = format!("http://{addr}/mcp");

    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    });

    // No auth header → 401
    let resp = ureq_post(&url, None, &payload);
    assert_eq!(resp.status, 401, "missing token must be 401");

    // Wrong token → 401
    let resp = ureq_post(&url, Some("wrong-token-value"), &payload);
    assert_eq!(resp.status, 401, "wrong token must be 401");

    // Right token → 200
    let resp = ureq_post(&url, Some(token), &payload);
    assert_eq!(
        resp.status, 200,
        "correct token must succeed; body: {}",
        resp.body
    );

    shutdown(child);
}

// ── Minimal HTTP client (no extra dep) ───────────────────────────────

struct HttpResponse {
    status: u16,
    body: String,
}

fn ureq_post(url: &str, bearer: Option<&str>, body: &serde_json::Value) -> HttpResponse {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let parsed = url::ParsedUrl::parse(url).expect("parse url");
    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let body_str = serde_json::to_string(body).expect("serialize body");
    let mut req = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        parsed.path,
        parsed.host,
        parsed.port,
        body_str.len(),
    );
    if let Some(b) = bearer {
        req.push_str(&format!("Authorization: Bearer {b}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body_str);
    stream.write_all(req.as_bytes()).expect("write request");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .expect("read response");
    let s = String::from_utf8_lossy(&response_bytes).to_string();
    let mut parts = s.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    HttpResponse { status, body }
}

mod url {
    pub struct ParsedUrl {
        pub host: String,
        pub port: u16,
        pub path: String,
    }
    impl ParsedUrl {
        pub fn parse(s: &str) -> Option<Self> {
            let s = s.strip_prefix("http://")?;
            let (authority, path) = s.split_once('/').unwrap_or((s, ""));
            let (host, port_str) = authority.rsplit_once(':')?;
            let port: u16 = port_str.parse().ok()?;
            Some(Self {
                host: host.to_string(),
                port,
                path: format!("/{path}"),
            })
        }
    }
}
