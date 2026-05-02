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
pub fn parse_metrics_addr(addr: &str) -> Result<SocketAddr, String> {
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
}
