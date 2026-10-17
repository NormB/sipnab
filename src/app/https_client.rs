// SPDX-License-Identifier: MIT OR Apache-2.0
//! A small HTTP/1.1 client over rustls: one request, one answer, then close.
//!
//! The vCon forwarder, the vCon fetcher and `sipnab g729 install` share it.
//! It lives here rather than in the forwarder so that a build with `g729`
//! and without `vcon` (the static musl release builds) can download the
//! ITU-T G.729 package too.

use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Where the forwarder sends a container: scheme, host, port and the path
/// with its query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `https://` rather than `http://`.
    pub tls: bool,
    /// The host as written, without brackets around an IPv6 literal.
    pub host: String,
    /// The port, 80 or 443 when the URL names none.
    pub port: u16,
    /// The path and query, `/` when the URL names none.
    pub target: String,
}

/// Which part of sipnab reads a URL, so that a refusal of the URL names that
/// part and the setting it takes credentials from. One parser serves every
/// surface; each caller says which one it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlUse {
    /// The part that sends the request, as a refusal names it.
    pub client: &'static str,
    /// The setting this surface reads credentials from, or `None` when it
    /// takes none.
    pub credentials: Option<&'static str>,
}

impl UrlUse {
    /// The vCon forwarder's store URL and replace URL.
    pub const FORWARDER: Self = Self {
        client: "the forwarder",
        credentials: Some("--vcon-forward-auth-file"),
    };
    /// The forwarder's transparency service URL.
    pub const FORWARDER_SCITT: Self = Self {
        client: "the forwarder",
        credentials: Some("--vcon-forward-scitt-auth-file"),
    };
    /// The vCon fetcher's store URL.
    pub const FETCHER: Self = Self {
        client: "the fetcher",
        credentials: Some("--vcon-fetch-auth-file"),
    };
    /// A `[[vcon.enrich]]` service URL.
    pub const ENRICHER: Self = Self {
        client: "the enricher",
        credentials: Some("[[vcon.enrich]] auth_file"),
    };
    /// A URL sipnab reads without credentials: one named inside a vCon, a
    /// transparency service's `Location`, or the G.729 package download.
    pub const DOWNLOAD: Self = Self {
        client: "sipnab",
        credentials: None,
    };
}

impl Endpoint {
    /// Parse an `http://` or `https://` URL read by `user`.
    ///
    /// # Errors
    ///
    /// Any other scheme, whitespace, an empty host, a bad port, credentials
    /// in the URL (they would reach the log) or a fragment. The scheme and
    /// credential refusals name `user`.
    pub fn parse(url: &str, user: UrlUse) -> Result<Self, String> {
        // Every refusal below quotes the URL; none may quote its userinfo.
        let shown = crate::app::run_provenance::redact_url_userinfo(url);
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            let client = user.client;
            return Err(format!(
                "'{shown}': {client} speaks http:// and https:// only"
            ));
        };
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("'{shown}': a URL cannot hold whitespace"));
        }
        if url.contains('#') {
            return Err(format!("'{shown}': a URL sent to a store has no fragment"));
        }
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        // Userinfo by the redaction rule, not by `authority`: a password
        // typed with an unescaped `?` ends `authority` early, and its tail
        // would otherwise be read, and quoted, as the port.
        if shown != url {
            let client = user.client;
            return match user.credentials {
                Some(setting) => Err(format!(
                    "'{shown}': put credentials in {setting}, not in the URL"
                )),
                None => Err(format!(
                    "'{shown}': a URL {client} reads cannot hold credentials"
                )),
            };
        }
        let (host, port) = split_authority(authority).map_err(|e| format!("'{shown}': {e}"))?;
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("'{shown}': '{p}' is not a port"))?,
            None if tls => 443,
            None => 80,
        };
        let target = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_string()
        };
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
            target,
        })
    }

    /// The port this scheme uses when the URL names none.
    fn default_port(&self) -> u16 {
        if self.tls { 443 } else { 80 }
    }

    /// The `Host` header's value: the host, bracketed when it is an IPv6
    /// literal, and the port when it is not the scheme's default.
    #[must_use]
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.host_header(), self.target)
    }
}

/// `host[:port]` or `[v6][:port]`, split. The port is `None` when absent.
fn split_authority(authority: &str) -> Result<(&str, Option<&str>), String> {
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (host, tail) = after
            .split_once(']')
            .ok_or("an IPv6 address needs its closing ']'")?;
        match tail {
            "" => (host, None),
            _ => (
                host,
                Some(
                    tail.strip_prefix(':')
                        .ok_or("only a port may follow an IPv6 address")?,
                ),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err("the URL names no host".to_string());
    }
    Ok((host, port))
}

/// Connect to `endpoint`, over TLS with `tls` when it is `https://`, write
/// `request`, and hand the answer to `read`.
///
/// # Errors
///
/// No connection, an `https://` endpoint without `tls`, a host that is not a
/// certificate name, a failed write, or what `read` returns.
pub(crate) fn exchange<T>(
    endpoint: &Endpoint,
    timeout: Duration,
    tls: Option<&Arc<rustls::ClientConfig>>,
    request: &[u8],
    read: impl FnOnce(&mut dyn BufRead) -> Result<T, String>,
) -> Result<T, String> {
    let sock = connect(endpoint, timeout)?;
    if !endpoint.tls {
        return over(sock, request, read);
    }
    let config = tls.cloned().ok_or("no TLS configuration")?;
    let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
        .map_err(|e| format!("'{}' is not a certificate name: {e}", endpoint.host))?;
    let conn = rustls::ClientConnection::new(config, name).map_err(|e| e.to_string())?;
    over(rustls::StreamOwned::new(conn, sock), request, read)
}

/// [`exchange`] over one stream.
fn over<T>(
    stream: impl Read + Write,
    request: &[u8],
    read: impl FnOnce(&mut dyn BufRead) -> Result<T, String>,
) -> Result<T, String> {
    let mut reader = std::io::BufReader::new(stream);
    let out = reader.get_mut();
    out.write_all(request)
        .and_then(|()| out.flush())
        .map_err(|e| format!("sending: {e}"))?;
    read(&mut reader)
}

/// The rustls client configuration: trusting only `ca` when named, else the
/// host's CA bundle.
///
/// `ca_flag` names the setting that names a CA file, for the refusal when
/// the host has no bundle.
pub(crate) fn client_config(
    ca: Option<&Path>,
    extra: Option<&Path>,
    names: &crate::tls_files::TrustNames<'_>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let roots = crate::tls_files::trust_roots(
        ca,
        extra,
        crate::tls_files::host_ca_bundle().as_deref(),
        names,
    )
    .map_err(|e| format!("{e:#}"))?;
    let config = rustls::ClientConfig::builder_with_provider(crate::tls_files::provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Connect to `endpoint`, trying each address it resolves to, and set the
/// read and write timeouts.
pub(crate) fn connect(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<std::net::TcpStream, String> {
    use std::net::ToSocketAddrs;
    let addrs = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve '{}': {e}", endpoint.host))?;
    let mut last = format!("'{}' resolved to no address", endpoint.host);
    for addr in addrs {
        match std::net::TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => {
                sock.set_read_timeout(Some(timeout))
                    .and_then(|()| sock.set_write_timeout(Some(timeout)))
                    .map_err(|e| e.to_string())?;
                return Ok(sock);
            }
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

/// The status line and headers, as lines, refused past `max` bytes.
///
/// `flag` names the setting that sets `max`, for the refusal.
pub(crate) fn read_head(
    reader: &mut (impl BufRead + ?Sized),
    max: usize,
    flag: &str,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let n = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("reading the answer: {e}"))?;
        if n == 0 {
            return Err("the store closed the connection without an answer".into());
        }
        total += n;
        if total > max {
            return Err(format!(
                "the answer's status line and headers are larger than {max} bytes ({flag})"
            ));
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        if text.is_empty() {
            return Ok(lines);
        }
        lines.push(text);
    }
}

/// The status code in a status line.
pub(crate) fn status_of(head: &[String]) -> Result<u16, String> {
    let line = head.first().map(String::as_str).unwrap_or_default();
    let mut words = line.split_whitespace();
    match (
        words.next(),
        words.next().and_then(|c| c.parse::<u16>().ok()),
    ) {
        (Some(v), Some(code)) if v.starts_with("HTTP/") => Ok(code),
        _ => Err("the answer is not HTTP".into()),
    }
}

/// The value of header `name` in `head`, case-insensitively.
pub(crate) fn header_value<'a>(head: &'a [String], name: &str) -> Option<&'a str> {
    head.iter().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

/// At most `keep` bytes of the body, and whether there was more. A body
/// that ends early or fails to read ends where it ended: it is evidence for
/// a person, not data the forwarder acts on.
pub(crate) fn read_body(
    reader: &mut (impl BufRead + ?Sized),
    head: &[String],
    keep: usize,
) -> (Vec<u8>, bool) {
    let chunked = header_value(head, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return read_chunked(reader, keep);
    }
    let length = header_value(head, "content-length").and_then(|v| v.parse::<u64>().ok());
    let limit = length.map_or(keep as u64 + 1, |n| n.min(keep as u64 + 1));
    let mut body = Vec::new();
    let _ = reader.take(limit).read_to_end(&mut body);
    let more = body.len() > keep || length.is_some_and(|n| n > keep as u64);
    body.truncate(keep);
    (body, more)
}

/// [`read_body`] for `Transfer-Encoding: chunked`.
fn read_chunked(reader: &mut (impl BufRead + ?Sized), keep: usize) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).unwrap_or(0) == 0 {
            return (body, false);
        }
        let hex = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(hex, 16) else {
            return (body, false);
        };
        if size == 0 {
            return (body, false);
        }
        let room = keep.saturating_sub(body.len());
        let mut chunk = Vec::new();
        let _ = reader.take(size.min(room) as u64).read_to_end(&mut chunk);
        body.extend_from_slice(&chunk);
        if size > room {
            return (body, true);
        }
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf);
    }
}
