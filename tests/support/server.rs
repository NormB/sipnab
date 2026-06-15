//! REST API spawn harness (verification plan M3 — T3.1).
//!
//! Spawns a real `sipnab --api 127.0.0.1:0` process against the canonical
//! fixture pcap, scrapes its log for the *actual* bound port (port 0 ⇒ the OS
//! assigns an ephemeral one — so CI runs never collide), and drives it with a
//! tiny `TcpStream` HTTP/1.1 client. The child is killed on `Drop`, so a
//! panicking test never leaks the process or the port.
//!
//! A raw socket client (rather than `reqwest`) is deliberate: it matches the
//! existing `mcp_http_test`, needs no TLS backend (API HTTPS is unimplemented —
//! see `tls_flags_fail_fast_and_do_not_serve`), and avoids dragging
//! aws-lc-rs/quinn into the test build.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// A minimal HTTP response: status code + body (headers are discarded).
pub struct Resp {
    pub status: u16,
    pub body: String,
}

impl Resp {
    /// Parse the body as JSON, panicking with context on failure.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON: {e}\n{}", self.body))
    }
}

/// A spawned API server. Holds the child so `Drop` can reap it.
pub struct ApiServer {
    child: Child,
    /// `host:port` the server actually bound to.
    pub addr: String,
}

impl ApiServer {
    /// Spawn against `tests/fixtures/sip_call.pcap` with extra CLI args (e.g.
    /// `--api-key`). Panics if the server doesn't come up.
    pub fn spawn(extra_args: &[&str]) -> ApiServer {
        Self::spawn_with_pcap("tests/fixtures/sip_call.pcap", extra_args)
    }

    /// Spawn against an arbitrary pcap (path relative to the crate root) — e.g.
    /// an RTP fixture so `/v1/streams` returns real streams.
    pub fn spawn_with_pcap(pcap_rel: &str, extra_args: &[&str]) -> ApiServer {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let pcap = format!("{manifest}/{pcap_rel}");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        cmd.args(["-N", "-I", &pcap, "--api", "127.0.0.1:0", "--quiet"]);
        cmd.args(extra_args);
        // --quiet sets the default level to warn; force info so the
        // "REST API listening on" line (which carries the bound port) appears.
        cmd.env("SIPNAB_LOG", "info");
        cmd.env("NO_COLOR", "1");
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn sipnab --api");
        let stderr = child.stderr.take().expect("piped stderr");

        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });

        // First wait for the bind line to learn the ephemeral port.
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut addr = None;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    if let Some(rest) = line.split("REST API listening on ").nth(1) {
                        addr = Some(rest.trim().to_string());
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Ok(Some(status)) = child.try_wait() {
                        panic!("sipnab --api exited early: {status}");
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let addr = addr.unwrap_or_else(|| {
            let _ = child.kill();
            panic!("API server did not report a listening address within 15s");
        });

        // The API serves *concurrently* with offline-pcap processing, so a bound
        // socket does NOT mean the dialog/stream store is fully populated (a real
        // race that flakes under load). Poll /v1/stats until it STABILIZES — two
        // identical consecutive reads — which generically means processing has
        // settled, without assuming any per-fixture counts.
        // Authenticate the readiness poll if the server was started with a key
        // (otherwise /v1/stats would 401 and never look "stable"). Supports
        // both the static `--api-key` and an HMAC `--api-signing-key` (in which
        // case we mint a short-lived token with the same key for the poll).
        let mut bearer = extra_args
            .windows(2)
            .find(|w| w[0] == "--api-key")
            .map(|w| w[1].to_string());
        #[cfg(feature = "api")]
        if bearer.is_none()
            && let Some(w) = extra_args.windows(2).find(|w| w[0] == "--api-signing-key")
        {
            let exp = chrono::Utc::now().timestamp() + 3600;
            bearer = Some(sipnab::auth::mint(w[1].as_bytes(), "readiness-poll", exp));
        }
        let srv = ApiServer { child, addr };
        srv.await_stable(bearer.as_deref());
        srv
    }

    /// Poll `/v1/stats` until two consecutive reads are identical and
    /// non-empty — a generic "capture settled" signal. Gives up after ~10s and
    /// returns anyway (the test's own assertions then surface the problem).
    fn await_stable(&self, api_key: Option<&str>) {
        let auth = api_key.map(|k| format!("Bearer {k}"));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut prev: Option<serde_json::Value> = None;
        while Instant::now() < deadline {
            // Compare PARSED values: equal content is "stable" regardless of any
            // transport framing/whitespace variance in the raw response.
            let raw = http_get(&self.addr, "/v1/stats", auth.as_deref()).body;
            let cur = serde_json::from_str::<serde_json::Value>(&raw).ok();
            if cur.is_some() && cur == prev {
                return;
            }
            prev = cur;
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// `GET path` with no auth header.
    pub fn get(&self, path: &str) -> Resp {
        http_get(&self.addr, path, None)
    }

    /// `GET path` with a bearer token.
    pub fn get_bearer(&self, path: &str, token: &str) -> Resp {
        http_get(&self.addr, path, Some(&format!("Bearer {token}")))
    }

    /// `GET path` with a verbatim `Authorization` header value (e.g. a
    /// non-Bearer scheme, to prove the auth check rejects it).
    pub fn get_with_auth(&self, path: &str, auth_value: &str) -> Resp {
        http_get(&self.addr, path, Some(auth_value))
    }
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Minimal blocking HTTP/1.1 GET over a fresh `Connection: close` socket.
fn http_get(addr: &str, path: &str, auth: Option<&str>) -> Resp {
    let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).expect("write request");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw);

    // Status code from the first line: "HTTP/1.1 <code> <reason>".
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in response:\n{text}"));

    // Body is everything after the first blank line.
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();

    Resp { status, body }
}

/// Spawn `sipnab --api` with the given args, collect stderr for `wait`, then
/// kill the process and return what it logged. For *failure-path* tests (e.g.
/// unimplemented TLS) where the server never reaches a listening state — the
/// capture process keeps running, so it must be reaped.
pub fn run_and_capture_stderr(extra_args: &[&str], wait: Duration) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let pcap = format!("{manifest}/tests/fixtures/sip_call.pcap");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(["-N", "-I", &pcap, "--api", "127.0.0.1:0", "--quiet"]);
    cmd.args(extra_args);
    cmd.env("SIPNAB_LOG", "info");
    cmd.env("NO_COLOR", "1");
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sipnab --api");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let deadline = Instant::now() + wait;
    let mut out = String::new();
    while Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    out
}
