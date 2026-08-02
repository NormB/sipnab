// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared HTTP-MCP end-to-end test harness.
//!
//! Spawns `sipnab --mcp --mcp-transport http` against a fixture pcap and drives
//! it with a tiny raw-`TcpStream` HTTP/1.1 client (no HTTP-client dependency,
//! matching the API tests). Previously each of `mcp_http_test.rs`,
//! `mcp_token_test.rs`, and `mcp_token_rotation_test.rs` carried its own copy of
//! `spawn_http` / `shutdown` / the POST helper; this is the single shared copy.
//!
//! This file lives in a `tests/` subdirectory, so cargo does not compile it as
//! its own test binary; consumers include it with
//! `#[path = "support/mcp.rs"] mod mcp;`.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

include!("timeout.rs");

/// A minimal HTTP response: status code + body (headers are discarded).
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Absolute path to a file under `tests/fixtures/`.
///
/// # Arguments
/// * `path` — filename relative to the fixtures directory.
pub fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

/// Spawn sipnab with HTTP MCP and the given args; return the child + the bind
/// address it actually started on (with `--mcp-bind …:0` the OS assigns an
/// ephemeral port, so concurrent runs never collide). Reads stderr for the
/// "listening on" log line.
///
/// The base args do NOT include `--mcp-bind`; the caller supplies it (see
/// `spawn_http_loopback` for the common `127.0.0.1:0` case).
///
/// # Returns
/// `Some((child, addr))` once the "listening on" line appears; `None` if the
/// server refuses to start or times out after 5s (child is reaped).
///
/// # Side effects
/// Spawns the sipnab binary (binding an ephemeral HTTP port) plus a stderr
/// reader thread; on failure paths the child is SIGTERMed and waited.
pub fn spawn_http(extra_args: &[&str]) -> Option<(Child, String)> {
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

    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let deadline = Instant::now() + test_timeout(5);
    while Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(addr) = line.split("listening on ").nth(1) {
                return Some((child, addr.trim().to_string()));
            }
            if line.contains("refuses to start") {
                // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
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
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
    None
}

/// `spawn_http` bound to loopback: prepends `--mcp-bind 127.0.0.1:0` to
/// `extra_args`. The common case for tests that don't vary the bind address.
pub fn spawn_http_loopback(extra_args: &[&str]) -> Option<(Child, String)> {
    let mut args: Vec<&str> = vec!["--mcp-bind", "127.0.0.1:0"];
    args.extend_from_slice(extra_args);
    spawn_http(&args)
}

/// SIGTERMs a spawned sipnab child and waits for it to exit.
///
/// # Side effects
/// Sends SIGTERM to the child process and reaps it.
pub fn shutdown(mut child: Child) {
    // SAFETY: kill(2) with the PID of a child we spawned; touches no memory.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

/// The canonical JSON-RPC `initialize` request body.
pub fn initialize_payload() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    })
}

/// POST a JSON-RPC `initialize` to `http://addr/mcp` with an optional bearer
/// token and return the HTTP status code.
pub fn initialize_status(addr: &str, bearer: Option<&str>) -> u16 {
    post_status(&format!("http://{addr}/mcp"), bearer, &initialize_payload())
}

/// Issue a raw-TCP HTTP POST of `body` as JSON and return the status code only
/// (0 if the status line is unparsable).
pub fn post_status(url: &str, bearer: Option<&str>, body: &serde_json::Value) -> u16 {
    post_json(url, bearer, body).status
}

/// Issue a raw-TCP HTTP POST of `body` as JSON and return the parsed status
/// code + response body (status 0 if the status line is unparsable).
///
/// # Arguments
/// * `url` — plain `http://host:port/path` URL.
/// * `bearer` — optional bearer token for the Authorization header.
/// * `body` — JSON payload to serialize and send.
///
/// # Side effects
/// Opens a TCP connection with a 5s read timeout.
pub fn post_json(url: &str, bearer: Option<&str>, body: &serde_json::Value) -> HttpResponse {
    let parsed = url.strip_prefix("http://").expect("http url");
    let (authority, path) = parsed.split_once('/').unwrap_or((parsed, ""));
    let (host, port_str) = authority.rsplit_once(':').expect("host:port");
    let port: u16 = port_str.parse().expect("port");

    let mut stream = TcpStream::connect((host, port)).expect("connect");
    stream
        .set_read_timeout(Some(test_timeout(5)))
        .expect("read timeout");

    let body_str = serde_json::to_string(body).expect("serialize");
    let mut req = format!(
        "POST /{path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body_str.len(),
    );
    if let Some(b) = bearer {
        req.push_str(&format!("Authorization: Bearer {b}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body_str);
    stream.write_all(req.as_bytes()).expect("write");

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).expect("read");
    let s = String::from_utf8_lossy(&resp);
    let (head, body) = s.split_once("\r\n\r\n").unwrap_or((&s, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    HttpResponse {
        status,
        body: body.to_string(),
    }
}

// ── stdio session ───────────────────────────────────────────────────

/// A loaded `sipnab --mcp` process that answers repeated tool calls.
///
/// Pagination cannot be tested one process at a time: each call has to feed the
/// previous response's `next_cursor` back in, and a fresh replay per page both
/// costs a reload and proves nothing about resuming. So the session outlives a
/// single call and the capture loads once.
pub struct McpSession {
    /// The running server. Kept so `stdin` stays open and `Drop` can stop it.
    child: std::process::Child,
    /// Line reader over the server's stdout, which is the JSON-RPC wire.
    reader: BufReader<std::process::ChildStdout>,
    /// Next JSON-RPC request id, so replies are matched rather than assumed.
    next_id: i64,
}

impl McpSession {
    /// Spawn `sipnab --mcp` on `pcap`, handshake, and wait for the replay to drain.
    ///
    /// The wait matters: without it these tests raced the pcap reader and passed
    /// on Linux by luck, while macOS saw an empty store and reported "no messages
    /// are held", "call_id not found" and an empty dialog list. A test that wins a
    /// race on one platform is an unobserved failure, not a pass. Polling
    /// `capture_status` until the file source drains is exactly what that tool is
    /// for.
    pub fn start(pcap: &str, extra: &[&str]) -> Self {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let mut argv: Vec<&str> = vec!["--mcp", "-N", "-I", pcap, "--quiet"];
        argv.extend_from_slice(extra);
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(manifest)
            .args(&argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipnab --mcp");

        {
            let stdin = child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "1"}}
                })
            )
            .expect("write initialize");
            writeln!(
                stdin,
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0", "method": "notifications/initialized"
                })
            )
            .expect("write initialized");
            stdin.flush().expect("flush");
        }

        let stdout = child.stdout.take().expect("stdout");
        let mut session = Self {
            child,
            reader: BufReader::new(stdout),
            next_id: 2,
        };

        // Bounded, so a genuine hang fails the test rather than running forever.
        const MAX_POLLS: usize = 200;
        let mut loaded = false;
        for _ in 0..MAX_POLLS {
            let msg = session.call("capture_status", serde_json::json!({}));
            let text = msg["result"]["content"][0]["text"].as_str().unwrap_or("{}");
            let v: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
            if v["source_exhausted"] == true {
                loaded = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(loaded, "capture never finished loading for {pcap}");
        session
    }

    /// Issue one `tools/call` and return the raw JSON-RPC reply.
    ///
    /// Raw rather than unwrapped, so callers can assert on refusals as well as
    /// results — a tool that must reject an argument combination is tested here
    /// the same way as one that must answer it.
    pub fn call(&mut self, tool: &str, args: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        {
            let stdin = self.child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": tool, "arguments": args}
                })
            )
            .expect("write tool call");
            stdin.flush().expect("flush");
        }
        let mut line = String::new();
        loop {
            line.clear();
            if self.reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for {tool}");
            }
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            if msg["id"] == serde_json::json!(id) {
                return msg;
            }
        }
    }

    /// Issue one `tools/call` and return the parsed payload, failing on a refusal.
    pub fn ok(&mut self, tool: &str, args: serde_json::Value) -> serde_json::Value {
        let msg = self.call(tool, args);
        ok_payload(&msg)
    }

    /// The tool names this server advertises, sorted.
    ///
    /// Registration and permission are separate questions here: a tool the
    /// operator did not enable is still listed and refuses when called, so an
    /// agent can tell "not permitted on this server" from "this build cannot
    /// do it at all".
    pub fn list_tools(&mut self) -> Vec<String> {
        let id = self.next_id;
        self.next_id += 1;
        {
            let stdin = self.child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
            )
            .expect("write tools/list");
            stdin.flush().expect("flush");
        }
        let mut line = String::new();
        loop {
            line.clear();
            if self.reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for tools/list");
            }
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            if msg["id"] == serde_json::json!(id) {
                let mut names: Vec<String> = msg["result"]["tools"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_string))
                    .collect();
                names.sort();
                return names;
            }
        }
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Call a tool with extra CLI args, waiting for the capture to load first.
///
/// Returns the raw JSON-RPC message so callers can assert on errors as well as
/// results.
pub fn call_tool_with_args(
    pcap: &str,
    extra: &[&str],
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    McpSession::start(pcap, extra).call(tool, args)
}

/// Unwrap a successful tool result to its parsed JSON payload.
pub fn ok_payload(msg: &serde_json::Value) -> serde_json::Value {
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected success, got {msg}"));
    serde_json::from_str(text).expect("payload is JSON")
}
