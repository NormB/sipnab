//! Standalone Prometheus metrics HTTP server.
//!
//! Provides a minimal HTTP/1.1 server that serves the `/metrics` endpoint
//! using a raw TCP listener. This avoids requiring the `api` feature (axum/tokio)
//! for standalone metrics export.
//!
//! Started when `--metrics <addr:port>` is specified without `--api`.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::output::prometheus::{PrometheusMetrics, format_metrics};
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// Start a standalone Prometheus metrics HTTP server in a background thread.
///
/// Serves `/metrics` with Prometheus text exposition format. Any other path
/// returns 404. Optionally requires HTTP Basic authentication when
/// `basic_auth` is `Some("user:pass")`.
///
/// # Errors
///
/// Returns an error if the TCP listener cannot be bound.
pub fn start_metrics_server(
    bind_addr: SocketAddr,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    basic_auth: Option<String>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind metrics server on {bind_addr}: {e}"))?;

    tracing::info!("Prometheus metrics server listening on {bind_addr}");

    let handle = std::thread::Builder::new()
        .name("metrics-server".to_string())
        .spawn(move || {
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

                // Set a reasonable timeout to prevent slowloris
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

                // Read the HTTP request (just enough to get the path and headers)
                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }

                // Parse request path
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_string();

                // Read headers (looking for Authorization)
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
                            if let Some(value) = trimmed.strip_prefix("Authorization: ") {
                                auth_header = Some(value.to_string());
                            } else if let Some(value) = trimmed.strip_prefix("authorization: ") {
                                auth_header = Some(value.to_string());
                            }
                        }
                    }
                }

                // Check Basic auth if configured
                if let Some(ref expected_creds) = basic_auth {
                    let authenticated = if let Some(ref auth) = auth_header {
                        check_basic_auth(auth, expected_creds)
                    } else {
                        false
                    };

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
                        continue;
                    }
                }

                if path == "/metrics" {
                    let metrics = collect_metrics(&dialog_store, &stream_store);
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
                    let body = "404 Not Found\n";
                    let response = format!(
                        "HTTP/1.1 404 Not Found\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n\
                         {}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("Failed to spawn metrics server thread: {e}"))?;

    Ok(handle)
}

/// Check HTTP Basic authentication.
///
/// `auth_value` is the value of the Authorization header (e.g., "Basic dXNlcjpwYXNz").
/// `expected_creds` is the expected "user:pass" string.
fn check_basic_auth(auth_value: &str, expected_creds: &str) -> bool {
    let Some(encoded) = auth_value.strip_prefix("Basic ") else {
        return false;
    };

    use base64::Engine;
    let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };

    let Ok(decoded) = String::from_utf8(decoded_bytes) else {
        return false;
    };

    // Constant-time comparison to prevent timing attacks
    constant_time_eq(decoded.as_bytes(), expected_creds.as_bytes())
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
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

/// Parse a bind address string into a [`SocketAddr`].
///
/// Same logic as the API bind address parser: accepts `:port`, `port`, or `addr:port`.
pub fn parse_metrics_addr(addr: &str) -> Result<SocketAddr, crate::Error> {
    parse_metrics_addr_inner(addr).map_err(|reason| crate::Error::InvalidBindAddr {
        input: addr.to_string(),
        reason,
    })
}

fn parse_metrics_addr_inner(addr: &str) -> Result<SocketAddr, String> {
    // Just a port number
    if let Ok(port) = addr.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    // ":port" shorthand
    if let Some(stripped) = addr.strip_prefix(':')
        && let Ok(port) = stripped.parse::<u16>()
    {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    // Full addr:port
    addr.parse::<SocketAddr>()
        .map_err(|e| format!("invalid metrics bind address '{addr}': {e}"))
}

/// Collect current metrics from the dialog and stream stores.
fn collect_metrics(
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
) -> PrometheusMetrics {
    let mut metrics = PrometheusMetrics::default();

    // Dialog metrics
    {
        let ds = dialog_store.read();
        for dialog in ds.iter() {
            let state_str = dialog.state().to_string();
            *metrics.dialogs_total.entry(state_str).or_insert(0) += 1;

            // Count messages by method
            *metrics
                .messages_total
                .entry(dialog.method.to_string())
                .or_insert(0) += dialog.messages.len() as u64;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metrics_addr_port_only() {
        let addr = parse_metrics_addr("9100").unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9100));
    }

    #[test]
    fn parse_metrics_addr_colon_port() {
        let addr = parse_metrics_addr(":9100").unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9100));
    }

    #[test]
    fn parse_metrics_addr_full() {
        let addr = parse_metrics_addr("0.0.0.0:9100").unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9100)
        );
    }

    #[test]
    fn parse_metrics_addr_invalid() {
        assert!(parse_metrics_addr("not-an-address").is_err());
    }

    #[test]
    fn basic_auth_valid() {
        // base64("user:pass") = "dXNlcjpwYXNz"
        assert!(check_basic_auth("Basic dXNlcjpwYXNz", "user:pass"));
    }

    #[test]
    fn basic_auth_invalid() {
        assert!(!check_basic_auth("Basic dXNlcjp3cm9uZw==", "user:pass"));
    }

    #[test]
    fn basic_auth_missing_prefix() {
        assert!(!check_basic_auth("Bearer token", "user:pass"));
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

    #[test]
    fn metrics_endpoint_returns_200_with_body() {
        let addr = free_addr();
        let _handle = start_metrics_server(
            addr,
            populated_dialog_store(),
            populated_stream_store(),
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

    #[test]
    fn unknown_path_returns_404() {
        let addr = free_addr();
        let _handle = start_metrics_server(
            addr,
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            None,
        )
        .expect("server should bind");

        let resp = http_request(addr, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp:?}");
    }

    #[test]
    fn basic_auth_enforced() {
        let addr = free_addr();
        let _handle = start_metrics_server(
            addr,
            Arc::new(RwLock::new(DialogStore::new(10, false))),
            Arc::new(RwLock::new(StreamStore::new(10))),
            Some("user:pass".to_string()),
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

    #[test]
    fn collect_metrics_counts_dialogs_and_active_streams() {
        let metrics = collect_metrics(&populated_dialog_store(), &populated_stream_store());
        // One INVITE dialog was inserted.
        assert!(metrics.messages_total.values().sum::<u64>() >= 1);
        assert!(!metrics.dialogs_total.is_empty());
        // The stream was created with a near-now timestamp, so it counts active.
        assert_eq!(metrics.rtp_streams_active, 1);
    }
}
