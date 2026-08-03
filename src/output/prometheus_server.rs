// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone Prometheus metrics HTTP server.
//!
//! Provides a minimal HTTP/1.1 server that serves the `/metrics` endpoint
//! using a raw TCP listener and plain threads — no axum/tokio runtime is
//! involved (note the module itself is still compiled under the `api`
//! feature gate in `super`).
//!
//! Started when `--metrics <addr:port>` is specified without `--api`.
//! Concurrency is capped at `MAX_CONCURRENT_CONNECTIONS`; optional HTTP
//! Basic auth protects non-loopback binds.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::RwLock;

use crate::output::prometheus::{PrometheusMetrics, format_metrics};
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// Maximum number of metrics connections handled concurrently. Beyond this,
/// new connections are answered `503` and closed immediately, so a burst of
/// slow clients cannot exhaust threads and make monitoring unavailable
/// (SN-02, CWE-770). Prometheus scrapes are infrequent and cheap, so a small
/// ceiling is ample for legitimate use.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Bounds the number of in-flight metrics connections. A permit is taken per
/// accepted connection and released (via `ConnPermit`'s `Drop`) when its
/// handler finishes.
struct ConnGate {
    /// Current in-flight connection count, shared with issued permits.
    active: Arc<AtomicUsize>,
    /// Maximum simultaneous connections before refusals.
    max: usize,
}

/// RAII permit from `ConnGate::try_acquire`; decrements the in-flight count
/// when dropped.
struct ConnPermit {
    /// Shared in-flight counter to decrement on drop.
    active: Arc<AtomicUsize>,
}

impl Drop for ConnPermit {
    /// Release the slot by decrementing the shared in-flight counter.
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConnGate {
    /// Create a gate allowing at most `max` simultaneous connections.
    fn new(max: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Reserve a slot, or `None` if the concurrency cap is already reached.
    /// Increments the shared counter optimistically and backs out on refusal.
    fn try_acquire(&self) -> Option<ConnPermit> {
        let prev = self.active.fetch_add(1, Ordering::SeqCst);
        if prev >= self.max {
            self.active.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(ConnPermit {
                active: Arc::clone(&self.active),
            })
        }
    }
}

/// Start a standalone Prometheus metrics HTTP server in a background thread.
///
/// Serves `/metrics` with Prometheus text exposition format. Any other path
/// returns 404. Optionally requires HTTP Basic authentication when
/// `basic_auth` is `Some("user:pass")`.
///
/// # Arguments
///
/// * `bind_addr` — Address to listen on.
/// * `dialog_store` — Shared dialog store snapshotted per scrape.
/// * `stream_store` — Shared stream store snapshotted per scrape.
/// * `basic_auth` — Expected `user:pass` credential, or `None` to disable
///   auth (loopback binds only).
/// * `capture_meter` — Optional capture-queue meter for queue-depth and
///   backpressure gauges.
///
/// # Returns
///
/// The `JoinHandle` of the detached `metrics-server` accept-loop thread.
///
/// # Errors
///
/// Fails when the bind is non-loopback with no `basic_auth` configured
/// (fail-closed policy, SN-02), when the TCP listener cannot be bound, or
/// when the server thread cannot be spawned.
///
/// # Side effects
///
/// Binds a TCP listener, spawns a long-lived accept-loop thread that in
/// turn spawns one short-lived `metrics-conn` thread per accepted
/// connection (bounded by the connection gate; excess connections get an
/// immediate 503), logs the bound address, and warns when Basic auth is
/// used on a non-loopback bind without TLS. The loop exits on shutdown
/// request.
pub fn start_metrics_server(
    bind_addr: SocketAddr,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    basic_auth: Option<String>,
    capture_meter: Option<crate::capture::channel::CaptureMeter>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    // Fail closed on a non-loopback bind without authentication, matching
    // the REST API and MCP HTTP transports (SN-02). An unauthenticated
    // metrics endpoint on a routable address publishes dialog/message/
    // stream counts and security-event counters to anyone who can reach it.
    if !bind_addr.ip().is_loopback() && basic_auth.is_none() {
        anyhow::bail!(
            "metrics server refuses to start: --metrics {bind_addr} is non-loopback \
             but no --metrics-auth / --metrics-auth-file was supplied. Bind to \
             127.0.0.1, or set credentials to publish on a routable address."
        );
    }
    if !bind_addr.ip().is_loopback() {
        tracing::warn!(
            "metrics server bound non-loopback ({bind_addr}) with Basic auth only — \
             credentials are base64-encoded, not encrypted; terminate TLS upstream."
        );
    }

    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind metrics server on {bind_addr}: {e}"))?;

    // Log the actual bound address: with port 0 the OS assigns an ephemeral
    // port, so logging `bind_addr` would print ":0" (mirrors the REST API/HEP).
    let actual_addr = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!("Prometheus metrics server listening on {actual_addr}");

    let handle = std::thread::Builder::new()
        .name("metrics-server".to_string())
        .spawn(move || {
            let gate = ConnGate::new(MAX_CONCURRENT_CONNECTIONS);
            for stream in listener.incoming() {
                if crate::signals::shutdown_requested() {
                    break;
                }

                let mut stream = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("Metrics server accept error: {e}");
                        continue;
                    }
                };

                // Refuse when at the concurrency cap so one slow client cannot
                // monopolize the server and starve legitimate scrapes.
                let Some(permit) = gate.try_acquire() else {
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                    write_simple(&mut stream, "503 Service Unavailable", "503 Busy\n");
                    continue;
                };

                // Hand off to a short-lived worker so a slow request only
                // occupies one of the bounded slots, not the accept loop.
                let dialog_store = Arc::clone(&dialog_store);
                let stream_store = Arc::clone(&stream_store);
                let basic_auth = basic_auth.clone();
                let capture_meter = capture_meter.clone();
                let spawned = std::thread::Builder::new()
                    .name("metrics-conn".to_string())
                    .spawn(move || {
                        // permit is moved in and dropped when the handler ends.
                        let _permit = permit;
                        handle_metrics_connection(
                            stream,
                            &dialog_store,
                            &stream_store,
                            basic_auth.as_deref(),
                            capture_meter.as_ref(),
                        );
                    });
                if spawned.is_err() {
                    tracing::debug!("Metrics server: failed to spawn connection handler");
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("Failed to spawn metrics server thread: {e}"))?;

    Ok(handle)
}

/// Write a minimal `Connection: close` HTTP response with a plain-text body.
/// Best-effort: write errors are swallowed.
fn write_simple(stream: &mut TcpStream, status_line: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Handle one metrics connection: parse the request line and headers, enforce
/// Basic auth when configured, and serve `/metrics` (or 404). Owns `stream`
/// for the connection's lifetime.
///
/// # Arguments
///
/// * `stream` — The accepted TCP connection.
/// * `dialog_store` / `stream_store` — Stores snapshotted by
///   `collect_metrics` on a `/metrics` hit.
/// * `basic_auth` — Expected `user:pass`, or `None` for no auth.
/// * `capture_meter` — Optional capture-queue meter.
///
/// # Side effects
///
/// Sets 5 s read/write timeouts (slowloris defense), reads the request
/// from the socket, takes store read locks while collecting metrics, and
/// writes a 200/401/404 response. All I/O is best-effort; malformed
/// requests simply end the connection.
fn handle_metrics_connection(
    mut stream: TcpStream,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    basic_auth: Option<&str>,
    capture_meter: Option<&crate::capture::channel::CaptureMeter>,
) {
    // Set a reasonable timeout to prevent slowloris.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

    // Read the HTTP request (just enough to get the path and headers).
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();

    // Read headers (looking for Authorization).
    let mut auth_header = None;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break; // End of headers
                }
                if let Some(value) = strip_authorization(trimmed) {
                    auth_header = Some(value.to_string());
                }
            }
        }
    }

    // Check Basic auth if configured.
    if let Some(expected_creds) = basic_auth {
        let authenticated = auth_header
            .as_deref()
            .is_some_and(|auth| check_basic_auth(auth, expected_creds));
        if !authenticated {
            let body = "401 Unauthorized\n";
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\n\
                 WWW-Authenticate: Basic realm=\"sipnab metrics\"\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
    }

    if path == "/metrics" {
        let metrics = collect_metrics(dialog_store, stream_store, capture_meter);
        let body = format_metrics(&metrics);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    } else {
        write_simple(&mut stream, "404 Not Found", "404 Not Found\n");
    }
}

/// Extract the value of an `Authorization` request header line, or `None`
/// if the line is not an Authorization header.
///
/// Per RFC 7230 the field name is case-insensitive and any amount of optional
/// whitespace (OWS) may surround the field value, so the match is robust to
/// odd-but-valid casings (`AUTHORIZATION:`) and spacing (`authorization:\t…`).
fn strip_authorization(line: &str) -> Option<&str> {
    let (name, value) = line.split_once(':')?;
    if name.eq_ignore_ascii_case("Authorization") {
        Some(value.trim())
    } else {
        None
    }
}

/// Case-insensitively strip an auth-scheme token from a credentials value and
/// return the remaining credentials with surrounding whitespace removed, or
/// `None` if the scheme does not match.
///
/// Per RFC 7235 the scheme is case-insensitive and separated from the
/// credentials by one or more spaces (or tabs); this tolerates arbitrary
/// leading whitespace and multiple separators.
fn strip_auth_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let (found, rest) = value.trim_start().split_once(char::is_whitespace)?;
    if found.eq_ignore_ascii_case(scheme) {
        Some(rest.trim())
    } else {
        None
    }
}

/// Check HTTP Basic authentication.
///
/// `auth_value` is the value of the Authorization header (e.g., "Basic dXNlcjpwYXNz").
/// `expected_creds` is the expected "user:pass" string.
///
/// # Returns
///
/// `true` only when the base64 payload decodes to valid UTF-8 equal to
/// `expected_creds` (compared in constant time); `false` for a missing
/// `Basic` scheme, bad base64, or non-UTF-8.
///
/// Per RFC 7235 the auth-scheme is case-insensitive and separated from the
/// credentials by one or more spaces (or tabs), so `basic`, `BASIC` and extra
/// inter-token whitespace are accepted. The token comparison itself is
/// unchanged: exact and constant-time.
fn check_basic_auth(auth_value: &str, expected_creds: &str) -> bool {
    let Some(encoded) = strip_auth_scheme(auth_value, "Basic") else {
        return false;
    };

    use base64::Engine;
    let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };

    let Ok(decoded) = String::from_utf8(decoded_bytes) else {
        return false;
    };

    // Constant-time comparison to prevent timing attacks
    constant_time_eq(decoded.as_bytes(), expected_creds.as_bytes())
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
/// Returns `true` iff `a` and `b` have equal length and contents; always
/// scans `max(len)` bytes regardless of where they differ.
///
/// `#[inline(never)]` prevents the optimizer from rewriting the loop into
/// a short-circuiting form. `black_box` on the accumulator forces the
/// compiler to materialize it, blocking dead-store elimination.
#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_match = a.len() == b.len();
    let max_len = a.len().max(b.len());
    let mut byte_diff = 0u8;
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        byte_diff |= x ^ y;
    }
    len_match && std::hint::black_box(byte_diff) == 0
}

/// Parse a bind address string into a `SocketAddr`.
///
/// Same logic as the API bind address parser: accepts `:port`, `port`, or
/// `addr:port` (bare/`:port` forms bind loopback).
///
/// # Errors
///
/// Returns `crate::Error::InvalidBindAddr` (carrying the input and a
/// reason string) when no form parses.
pub fn parse_metrics_addr(addr: &str) -> Result<SocketAddr, crate::Error> {
    crate::output::parse_listen_addr(addr, "metrics bind address")
}

/// Collect current metrics from the dialog and stream stores.
///
/// Populates per-state dialog counts, per-method message counts, per-class
/// response counts, per-type media diagnosis counts, the active-stream
/// gauge, and (when a meter is supplied) capture queue depth and
/// backpressure counters — on top of the process-wide counters
/// `PrometheusMetrics::for_scrape` loads (captured packets, reassembly
/// timeouts, security alerts).
///
/// # Side effects
///
/// Takes the dialog- and stream-store read locks (dialog first, matching
/// the REST API; both dropped before returning).
fn collect_metrics(
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    capture_meter: Option<&crate::capture::channel::CaptureMeter>,
) -> PrometheusMetrics {
    // `for_scrape`, never `default`: the two scalar counters and the alert
    // family are fed by the capture path, not by these stores, and a
    // `default()` here published a literal `0` for a live capture.
    let mut metrics = PrometheusMetrics::for_scrape();

    if let Some(meter) = capture_meter {
        metrics.capture_queue_depth_packets = meter.in_flight() as u64;
        metrics.capture_backpressure_blocks_total = meter.backpressure_blocks();
    }

    // Dialog metrics (the stream store is read alongside them: the
    // per-dialog media diagnosis needs both).
    {
        let ds = dialog_store.read();
        let ss = stream_store.read();
        let capture_media = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);
        for dialog in ds.iter() {
            let state_str = dialog.state().to_string();
            *metrics.dialogs_total.entry(state_str).or_insert(0) += 1;

            // Count messages by method
            *metrics
                .messages_total
                .entry(dialog.method.to_string())
                .or_insert(0) += dialog.messages.len() as u64;

            for msg in &dialog.messages {
                if let Some(code) = msg.status_code {
                    metrics.record_response(code);
                }
            }

            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&dialog.call_id).collect();
            let media = crate::rtp::diagnosis::MediaContext::for_dialog(dialog, capture_media);
            metrics.record_media_diagnosis(&crate::rtp::diagnosis::diagnose_media(
                &dialog_streams,
                &media,
            ));
        }
    }

    // Stream metrics
    {
        let ss = stream_store.read();
        let mut active_count: u64 = 0;
        for stream in ss.iter() {
            if stream.is_active() {
                active_count += 1;
            }
        }
        metrics.rtp_streams_active = active_count;
    }

    metrics
}

/// Tests for address parsing, Basic-auth checking, the connection gate,
/// bind policy, and end-to-end HTTP behavior on ephemeral ports.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    /// A bare port string binds to `127.0.0.1:<port>`.
    #[test]
    fn parse_metrics_addr_port_only() {
        let addr = parse_metrics_addr("9100").unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9100));
    }

    /// The `:port` shorthand binds to `127.0.0.1:<port>`.
    #[test]
    fn parse_metrics_addr_colon_port() {
        let addr = parse_metrics_addr(":9100").unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9100));
    }

    /// A full `addr:port` pair parses verbatim.
    #[test]
    fn parse_metrics_addr_full() {
        let addr = parse_metrics_addr("0.0.0.0:9100").unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9100)
        );
    }

    /// A non-address string is rejected.
    #[test]
    fn parse_metrics_addr_invalid() {
        assert!(parse_metrics_addr("not-an-address").is_err());
    }

    /// Correct base64 credentials pass the Basic auth check.
    #[test]
    fn basic_auth_valid() {
        // base64("user:pass") = "dXNlcjpwYXNz"
        assert!(check_basic_auth("Basic dXNlcjpwYXNz", "user:pass"));
    }

    /// Wrong-password credentials fail the Basic auth check.
    #[test]
    fn basic_auth_invalid() {
        assert!(!check_basic_auth("Basic dXNlcjp3cm9uZw==", "user:pass"));
    }

    /// A non-`Basic` scheme fails the Basic auth check.
    #[test]
    fn basic_auth_missing_prefix() {
        assert!(!check_basic_auth("Bearer token", "user:pass"));
    }

    /// Odd-but-valid RFC 7235 scheme casings and inter-token whitespace are
    /// accepted: the auth-scheme is case-insensitive and one-or-more spaces
    /// (or tabs) may separate it from the credentials.
    #[test]
    fn basic_auth_accepts_odd_scheme_casing_and_spacing() {
        // base64("user:pass") = "dXNlcjpwYXNz"
        assert!(check_basic_auth("basic dXNlcjpwYXNz", "user:pass"));
        assert!(check_basic_auth("BASIC dXNlcjpwYXNz", "user:pass"));
        assert!(check_basic_auth("bAsIc dXNlcjpwYXNz", "user:pass"));
        assert!(check_basic_auth("Basic    dXNlcjpwYXNz", "user:pass"));
        assert!(check_basic_auth("Basic\tdXNlcjpwYXNz", "user:pass"));
    }

    /// A wrong token is still rejected even with an odd-but-valid scheme
    /// casing and extra whitespace — the token comparison is not weakened.
    #[test]
    fn basic_auth_wrong_token_rejected_despite_odd_casing() {
        // base64("user:wrong") = "dXNlcjp3cm9uZw=="
        assert!(!check_basic_auth("basic   dXNlcjp3cm9uZw==", "user:pass"));
    }

    /// The Authorization header field name is matched case-insensitively
    /// and tolerates arbitrary optional whitespace (OWS) after the colon.
    #[test]
    fn authorization_header_name_is_case_insensitive_and_ows_tolerant() {
        assert_eq!(
            strip_authorization("Authorization: Basic xyz"),
            Some("Basic xyz")
        );
        assert_eq!(
            strip_authorization("authorization: Basic xyz"),
            Some("Basic xyz")
        );
        assert_eq!(
            strip_authorization("AUTHORIZATION:    Basic xyz"),
            Some("Basic xyz")
        );
        assert_eq!(
            strip_authorization("AuThOrIzAtIoN:\tBasic xyz"),
            Some("Basic xyz")
        );
        assert_eq!(strip_authorization("Content-Type: text/plain"), None);
    }

    // ── End-to-end server tests ────────────────────────────────────────
    //
    // These exercise the spawned accept loop in `start_metrics_server` by
    // binding it to an ephemeral port and issuing raw HTTP/1.1 requests.

    use crate::capture::parse::ParsedPacket;
    use chrono::Utc;
    use std::io::Read;
    use std::net::TcpStream;

    /// Reserve a free localhost port by binding to :0, then release it so the
    /// metrics server can claim it. (Standard small-race test pattern.)
    fn free_addr() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    }

    /// Send a raw HTTP request and return the full response as a string.
    fn http_request(addr: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut resp = String::new();
        // Server sets Connection: close, so read to EOF.
        stream.read_to_string(&mut resp).unwrap();
        resp
    }

    /// A dialog store containing one tracked INVITE dialog.
    fn populated_dialog_store() -> Arc<RwLock<DialogStore>> {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\
                    From: Alice <sip:alice@example.com>;tag=a1\r\n\
                    To: Bob <sip:bob@example.com>\r\n\
                    Call-ID: metrics-1@example.com\r\n\
                    CSeq: 1 INVITE\r\n\
                    Max-Forwards: 70\r\n\
                    Contact: <sip:alice@10.0.0.1:5060>\r\n\
                    Content-Length: 0\r\n\r\n";
        let data = bytes::Bytes::from_static(raw);
        let msg = crate::sip::parser::parse_sip_bytes(
            &data,
            Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .unwrap();
        let mut ds = DialogStore::new(100, false);
        ds.process_message(msg);
        Arc::new(RwLock::new(ds))
    }

    /// A stream store containing one active RTP stream (last_seen ~= now).
    fn populated_stream_store() -> Arc<RwLock<StreamStore>> {
        use crate::capture::parse::TransportProto;
        use crate::rtp::parser::RtpHeader;
        let parsed = ParsedPacket {
            frame: None,
            timestamp: Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 20000,
            dst_port: 30000,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from_static(&[0u8; 172]),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        };
        let rtp = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0, // PCMU
            sequence: 1,
            timestamp: 160,
            ssrc: 0x1234_5678,
            payload_offset: 12,
        };
        let mut ss = StreamStore::new(100);
        ss.process_rtp(&parsed, &rtp, Utc::now());
        Arc::new(RwLock::new(ss))
    }

    /// `GET /metrics` returns 200 with the Prometheus content type and a
    /// `sipnab_` body.
    #[test]
    fn metrics_endpoint_returns_200_with_body() {
        let addr = free_addr();
        let _handle = start_metrics_server(
            addr,
            populated_dialog_store(),
            populated_stream_store(),
            None,
            None,
        )
        .expect("server should bind");

        let resp = http_request(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp:?}");
        assert!(
            resp.contains("version=0.0.4"),
            "should advertise Prometheus content type"
        );
        // Body should carry the exposition text produced by format_metrics.
        assert!(resp.contains("sipnab_"), "metrics body missing: {resp:?}");
    }

    /// Any path other than `/metrics` returns 404.
    #[test]
    fn unknown_path_returns_404() {
        let addr = free_addr();
        let _handle = start_metrics_server(
            addr,
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            None,
            None,
        )
        .expect("server should bind");

        let resp = http_request(addr, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp:?}");
    }

    /// With auth configured: no/wrong credentials get 401 (with a
    /// challenge), correct credentials get 200.
    #[test]
    fn basic_auth_enforced() {
        let addr = free_addr();
        let _handle = start_metrics_server(
            addr,
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            Some("user:pass".to_string()),
            None,
        )
        .expect("server should bind");

        // No credentials -> 401 with a challenge.
        let resp = http_request(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(
            resp.starts_with("HTTP/1.1 401 Unauthorized"),
            "got: {resp:?}"
        );
        assert!(resp.contains("WWW-Authenticate: Basic"), "got: {resp:?}");

        // Wrong credentials -> still 401.
        let resp = http_request(
            addr,
            "GET /metrics HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjp3cm9uZw==\r\n\r\n",
        );
        assert!(
            resp.starts_with("HTTP/1.1 401 Unauthorized"),
            "got: {resp:?}"
        );

        // Correct credentials (base64 "user:pass") -> 200.
        let resp = http_request(
            addr,
            "GET /metrics HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
        );
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp:?}");
    }

    /// The connection gate caps concurrent handlers: acquisitions beyond the
    /// limit are refused (returning `None`) so a burst of slow clients cannot
    /// exhaust threads, and a slot frees when its permit is dropped (SN-02).
    #[test]
    fn conn_gate_caps_and_releases() {
        let gate = ConnGate::new(2);
        let p1 = gate.try_acquire().expect("first permit");
        let _p2 = gate.try_acquire().expect("second permit");
        assert!(
            gate.try_acquire().is_none(),
            "third over the cap is refused"
        );
        drop(p1);
        assert!(gate.try_acquire().is_some(), "a freed slot is reusable");
    }

    /// The standalone metrics server must fail closed on a non-loopback
    /// bind when no Basic-auth credential is configured, matching the
    /// REST API and MCP HTTP transports (SN-02). Otherwise operational
    /// telemetry is published to the network unauthenticated.
    #[test]
    fn refuses_non_loopback_bind_without_auth() {
        let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = start_metrics_server(
            bind,
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            None,
            None,
        )
        .expect_err("non-loopback without auth must be refused");
        assert!(
            err.to_string().contains("non-loopback"),
            "error should explain the bind policy, got: {err}"
        );
    }

    /// A non-loopback bind is allowed once a credential is configured.
    #[test]
    fn allows_non_loopback_bind_with_auth() {
        let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let handle = start_metrics_server(
            bind,
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            Some("user:pass".to_string()),
            None,
        );
        assert!(
            handle.is_ok(),
            "auth-configured non-loopback bind should start"
        );
    }

    /// Loopback binds never require auth (the common local-scrape case).
    #[test]
    fn allows_loopback_bind_without_auth() {
        let handle = start_metrics_server(
            free_addr(),
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            None,
            None,
        );
        assert!(handle.is_ok(), "loopback without auth should start");
    }

    /// Collected metrics count the seeded dialog and the one active stream.
    #[test]
    fn collect_metrics_counts_dialogs_and_active_streams() {
        let metrics = collect_metrics(&populated_dialog_store(), &populated_stream_store(), None);
        // One INVITE dialog was inserted.
        assert!(metrics.messages_total.values().sum::<u64>() >= 1);
        assert!(!metrics.dialogs_total.is_empty());
        // The stream was created with a near-now timestamp, so it counts active.
        assert_eq!(metrics.rtp_streams_active, 1);
    }

    /// A supplied capture meter reports queue depth; without one the gauge
    /// stays 0.
    #[test]
    fn collect_metrics_reports_capture_queue_depth() {
        use crate::capture::channel::packet_channel;
        use crate::capture::packet::Packet;

        let (tx, rx) = packet_channel(8);
        let ts = chrono::DateTime::from_timestamp(0, 0).unwrap();
        tx.send(Packet::new(ts, vec![0u8; 32], 32, 32, None, 1))
            .unwrap();
        tx.send(Packet::new(ts, vec![0u8; 32], 32, 32, None, 1))
            .unwrap();

        let m = collect_metrics(
            &populated_dialog_store(),
            &populated_stream_store(),
            Some(&rx.meter()),
        );
        assert_eq!(m.capture_queue_depth_packets, 2);
        // Without a meter the gauge stays at its default 0.
        let m0 = collect_metrics(&populated_dialog_store(), &populated_stream_store(), None);
        assert_eq!(m0.capture_queue_depth_packets, 0);
    }
}
