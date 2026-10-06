// SPDX-License-Identifier: MIT OR Apache-2.0

//! REST API spawn harness (verification plan M3 — T3.1).
//!
//! Spawns a real `sipnab --api 127.0.0.1:0` process against the canonical
//! fixture pcap, scrapes its log for the *actual* bound port (port 0 ⇒ the OS
//! assigns an ephemeral one — so CI runs never collide), and drives it with a
//! tiny `TcpStream` HTTP/1.1 client. The child is stopped on `Drop` with
//! SIGTERM (see `teardown.rs`), so a panicking test never leaks the process or
//! the port, and the server's own coverage profile is written.
//!
//! A raw socket client (rather than `reqwest`) is deliberate: it matches the
//! existing `mcp_http_test`, needs no TLS backend, and avoids dragging
//! aws-lc-rs/quinn into the test build. The HTTPS tests in `api_test.rs`
//! bring their own small rustls client and use [`ApiServer::spawn_unsettled`].
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

include!("timeout.rs");
include!("teardown.rs");

/// A minimal HTTP response: status code, body, and the `Content-Type` header.
///
/// Other headers are discarded; `content_type` is kept because a binary route
/// (`GET /v1/dialogs/{id}/audio`) is verified by the type it declares, not only
/// by its bytes.
pub struct Resp {
    pub status: u16,
    pub body: String,
    /// The `Content-Type` response header, lowercased, when present.
    pub content_type: Option<String>,
    /// The `Retry-After` response header, when present: how a refusal for
    /// rate says when to come back.
    pub retry_after: Option<String>,
}

/// The value of header `name` from an HTTP header block, if present.
fn header_of(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        l.split_once(':').and_then(|(k, v)| {
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    })
}

/// The lowercased `Content-Type` value from an HTTP header block, if present.
fn content_type_of(head: &str) -> Option<String> {
    header_of(head, "content-type").map(|v| v.to_lowercase())
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
    /// Everything the server logged up to and including its "REST API
    /// listening on" line: what it said about its own configuration at
    /// startup (the non-loopback warning, for one).
    pub startup_log: String,
}

/// Whether two consecutive `/v1/stats` reads show a capture that has settled:
/// the reader has reached the end of the file (`source_exhausted`) and the
/// store did not change between the reads.
///
/// `cur` is the latest read and `prev` the one before it, if any. Equal reads
/// alone are not enough: a reader that stalls for one poll interval before it
/// stores anything gives two identical reads of an empty store.
pub fn capture_settled(prev: Option<&serde_json::Value>, cur: &serde_json::Value) -> bool {
    cur["source_exhausted"] == true && prev == Some(cur)
}

impl ApiServer {
    /// Spawn against `tests/fixtures/sip_call.pcap` with extra CLI args (e.g.
    /// `--api-key`). Panics if the server doesn't come up.
    pub fn spawn(extra_args: &[&str]) -> ApiServer {
        Self::spawn_with_pcap("tests/fixtures/sip_call.pcap", extra_args)
    }

    /// Spawn against an arbitrary pcap — e.g. an RTP fixture so `/v1/streams`
    /// returns real streams.
    ///
    /// `pcap_rel` is taken relative to the crate root, or used verbatim when
    /// it is already absolute, so a caller that generated a capture into a
    /// tempdir can point at it without inventing a second spawn.
    pub fn spawn_with_pcap(pcap_rel: &str, extra_args: &[&str]) -> ApiServer {
        let srv = Self::launch(pcap_rel, "127.0.0.1:0", extra_args);
        srv.settle(extra_args);
        srv
    }

    /// Spawn and wait only for the "REST API listening on" line, without the
    /// plain-HTTP readiness poll [`Self::spawn`] runs afterwards.
    ///
    /// For a server started with `--api-tls-cert`/`--api-tls-key`: its port
    /// speaks TLS, so the plain-HTTP `/v1/stats` poll would get no status line
    /// and panic. The caller drives the server with its own HTTPS client.
    pub fn spawn_unsettled(extra_args: &[&str]) -> ApiServer {
        Self::spawn_unsettled_on("127.0.0.1:0", extra_args)
    }

    /// [`Self::spawn_unsettled`] with `--api <bind>` rather than
    /// `127.0.0.1:0`, for the tests about what a non-loopback bind logs.
    pub fn spawn_unsettled_on(bind: &str, extra_args: &[&str]) -> ApiServer {
        Self::launch("tests/fixtures/sip_call.pcap", bind, extra_args)
    }

    /// Start the child and wait for its "REST API listening on" line.
    fn launch(pcap_rel: &str, bind: &str, extra_args: &[&str]) -> ApiServer {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let pcap = if std::path::Path::new(pcap_rel).is_absolute() {
            pcap_rel.to_string()
        } else {
            format!("{manifest}/{pcap_rel}")
        };

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        cmd.args(["-N", "-I", &pcap, "--api", bind, "--quiet"]);
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
        let budget = test_timeout(15);
        let start = Instant::now();
        let deadline = start + budget;
        let mut addr = None;
        let mut startup_log = String::new();
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    startup_log.push_str(&line);
                    startup_log.push('\n');
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
                // stderr closed, which means the child is gone -- the deadline
                // has NOT elapsed. This arm used to `break`, and the panic below
                // then named a timeout that never happened: a ThreadSanitizer
                // run whose children were being aborted by `halt_on_error`
                // reported "did not report a listening address within 180s" for
                // a suite that finished in 55s, and the resulting investigation
                // went after runner speed instead of the abort. Report the
                // child's own status, which is the actual cause.
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // stderr usually closes microseconds before the process is
                    // reaped, so give it a moment rather than racing it and
                    // reporting "still running" for a process that is exiting.
                    let grace = Instant::now() + Duration::from_secs(2);
                    let mut exit = None;
                    while Instant::now() < grace {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                exit = Some(status);
                                break;
                            }
                            _ => thread::sleep(Duration::from_millis(50)),
                        }
                    }
                    let status = match exit {
                        Some(status) => format!("exited with {status}"),
                        None => {
                            let _ = child.kill();
                            "still running with stderr closed (killed)".to_string()
                        }
                    };
                    panic!(
                        "sipnab --api closed stderr after {:?} without reporting a \
                         listening address — {status}. This is the process dying, \
                         not a timeout; under a sanitizer, check that build's log \
                         for the abort that killed it.",
                        start.elapsed()
                    );
                }
            }
        }
        let addr = addr.unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "API server did not report a listening address within {budget:?} \
                 (waited {:?})",
                start.elapsed()
            );
        });

        ApiServer {
            child,
            addr,
            startup_log,
        }
    }

    /// Wait until the capture behind a freshly spawned server has settled.
    fn settle(&self, extra_args: &[&str]) {
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
            bearer = Some(sipnab::auth::mint(
                w[1].as_bytes(),
                "readiness-poll",
                exp,
                sipnab::auth::AUDIENCE_API,
                sipnab::auth::SCOPE_FULL,
            ));
        }
        self.await_stable(bearer.as_deref());
    }

    /// Poll `/v1/stats` until two consecutive reads are identical and
    /// non-empty — a generic "capture settled" signal. Gives up after ~10s and
    /// returns anyway (the test's own assertions then surface the problem).
    fn await_stable(&self, api_key: Option<&str>) {
        let auth = api_key.map(|k| format!("Bearer {k}"));
        let deadline = Instant::now() + test_timeout(10);
        let mut prev: Option<serde_json::Value> = None;
        while Instant::now() < deadline {
            // Compare PARSED values: equal content is "stable" regardless of any
            // transport framing/whitespace variance in the raw response.
            let raw = http_get(&self.addr, "/v1/stats", auth.as_deref()).body;
            let cur = serde_json::from_str::<serde_json::Value>(&raw).ok();
            if let Some(read) = &cur
                && capture_settled(prev.as_ref(), read)
            {
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

    /// `POST path` with a JSON body and no auth header.
    pub fn post_json(&self, path: &str, body: &str) -> Resp {
        http_post(&self.addr, path, body, None)
    }

    /// `POST path` with a JSON body and a bearer token.
    pub fn post_json_bearer(&self, path: &str, body: &str, token: &str) -> Resp {
        http_post(&self.addr, path, body, Some(&format!("Bearer {token}")))
    }

    /// `GET path` with no auth header and `host` as the `Host` header.
    pub fn get_as_host(&self, path: &str, host: &str) -> Resp {
        http_get_as(&self.addr, host, path, None)
    }

    /// `POST path` with a JSON body, no auth header, and `host` as the
    /// `Host` header.
    pub fn post_json_as_host(&self, path: &str, body: &str, host: &str) -> Resp {
        http_post_as(&self.addr, host, path, body, None)
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or_else(|| panic!("no port in {}", self.addr))
    }

    /// The server's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Stop the server the way `Drop` does and return how it exited.
    pub fn stop(mut self) -> std::process::ExitStatus {
        terminate(&mut self.child).expect("reap sipnab --api")
    }
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        let _ = terminate(&mut self.child);
    }
}

/// Minimal blocking HTTP/1.1 GET over a fresh `Connection: close` socket.
fn http_get(addr: &str, path: &str, auth: Option<&str>) -> Resp {
    http_get_as(addr, addr, path, auth)
}

/// [`http_get`] sending `host` as the `Host` header instead of the address
/// the socket connects to -- what a browser sends after a DNS-rebinding
/// attacker points its own name at the server.
fn http_get_as(addr: &str, host: &str, path: &str, auth: Option<&str>) -> Resp {
    let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    stream.set_read_timeout(Some(test_timeout(10))).ok();

    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
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

    // Body is everything after the first blank line; the head before it carries
    // the Content-Type.
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map_or((String::new(), String::new()), |(h, b)| {
            (h.to_string(), b.to_string())
        });
    let content_type = content_type_of(&head);
    let retry_after = header_of(&head, "retry-after");

    Resp {
        status,
        body,
        content_type,
        retry_after,
    }
}

/// Minimal blocking HTTP/1.1 POST over a fresh `Connection: close` socket.
///
/// `Content-Length` is computed from the body's BYTE length, not its character
/// count: a body carrying a multi-byte character would otherwise be truncated
/// by the server mid-character, and the request would fail for a reason that
/// has nothing to do with what the test is asking.
fn http_post(addr: &str, path: &str, body: &str, auth: Option<&str>) -> Resp {
    http_post_as(addr, addr, path, body, auth)
}

/// [`http_post`] sending `host` as the `Host` header; see [`http_get_as`].
fn http_post_as(addr: &str, host: &str, path: &str, body: &str, auth: Option<&str>) -> Resp {
    let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    stream.set_read_timeout(Some(test_timeout(10))).ok();

    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).expect("write request");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw);

    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in response:\n{text}"));

    let (head, body) = text
        .split_once("\r\n\r\n")
        .map_or((String::new(), String::new()), |(h, b)| {
            (h.to_string(), b.to_string())
        });
    let content_type = content_type_of(&head);
    let retry_after = header_of(&head, "retry-after");

    Resp {
        status,
        body,
        content_type,
        retry_after,
    }
}

/// Spawn `sipnab --api` with the given args, collect stderr for `wait`, then
/// stop the process and return what it logged. For *failure-path* tests (e.g.
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
    let _ = terminate(&mut child);
    out
}
