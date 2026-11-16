// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
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

/// The `User-Agent` every request carries. A Cloudflare front refuses some
/// client libraries' default agents with `403 error code: 1010`; an explicit,
/// honest one names the software that sent the request.
///
/// Not a setting: the header names the software that sent the request, and a
/// setting would let the request name other software.
#[cfg(any(feature = "vcon", feature = "api"))]
pub(crate) const USER_AGENT: &str = concat!("sipnab/", env!("CARGO_PKG_VERSION"));

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
    /// An instance URL in a `sipnab fleet` hosts file.
    pub const FLEET: Self = Self {
        client: "sipnab fleet",
        credentials: Some("the host's token_file"),
    };
    /// A fleet member's center URL, `[fleet] report_url`.
    pub const FLEET_REPORT: Self = Self {
        client: "the fleet member",
        credentials: Some("--fleet-report-token-file"),
    };
    /// A URL sipnab reads without credentials: one named inside a vCon, a
    /// transparency service's `Location`, or the G.729 package download.
    pub const DOWNLOAD: Self = Self {
        client: "sipnab",
        credentials: None,
    };
}

impl Endpoint {
    /// Whether the host is this machine: `localhost` or a loopback address.
    ///
    /// The one rule for where plain `http://` crosses no network: the vCon
    /// forwarder warns off it, and a fleet member refuses off it.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

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

/// A body as it was read: at most `keep` bytes, whether there was more, and,
/// when the body did not arrive whole, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Body {
    /// At most `keep` bytes of the body.
    pub(crate) bytes: Vec<u8>,
    /// The body was longer than `keep`; the rest was not read.
    pub(crate) more: bool,
    /// The body ended before its framing said it ends (a `Content-Length`
    /// not reached, a chunked body without its last chunk) or a read failed
    /// (a timeout, a reset): the message names the bytes read.
    pub(crate) short: Option<String>,
}

/// At most `keep` bytes of a body the caller acts on, and whether there was
/// more.
///
/// # Errors
///
/// The body did not arrive whole: it ended before its `Content-Length` or
/// before its last chunk, a chunk size is not hex, or a read failed. The
/// message names the bytes read and, when the answer declared it, the
/// length expected.
pub(crate) fn read_body(
    reader: &mut (impl BufRead + ?Sized),
    head: &[String],
    keep: usize,
) -> Result<(Vec<u8>, bool), String> {
    let body = read_body_parts(reader, head, keep);
    match body.short {
        Some(why) => Err(why),
        None => Ok((body.bytes, body.more)),
    }
}

/// At most `keep` bytes of a body quoted to a person (the text of a refusal),
/// and whether there was more. A body that ends early or fails to read ends
/// where it ended: it is evidence for a person, not data anything acts on.
pub(crate) fn read_quoted_body(
    reader: &mut (impl BufRead + ?Sized),
    head: &[String],
    keep: usize,
) -> (Vec<u8>, bool) {
    let body = read_body_parts(reader, head, keep);
    (body.bytes, body.more)
}

/// The one reading of a body that [`read_body`] and [`read_quoted_body`]
/// share.
pub(crate) fn read_body_parts(
    reader: &mut (impl BufRead + ?Sized),
    head: &[String],
    keep: usize,
) -> Body {
    let chunked = header_value(head, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return read_chunked(reader, keep);
    }
    let length = header_value(head, "content-length").and_then(|v| v.parse::<u64>().ok());
    let limit = length.map_or(keep as u64 + 1, |n| n.min(keep as u64 + 1));
    let mut bytes = Vec::new();
    let failed = reader.take(limit).read_to_end(&mut bytes).err();
    let got = bytes.len();
    // A body is whole when it reached its limit (its length, or one byte
    // past what is kept) or, without a length, when the peer closed.
    let reached = got as u64 == limit;
    let short = match (length, failed) {
        (Some(n), failed) if !reached => Some(match failed {
            Some(e) => format!("the answer ended after {got} of its {n} bytes: {e}"),
            None => format!("the answer ended after {got} of its {n} bytes"),
        }),
        (None, Some(e)) if !reached => Some(format!(
            "reading the answer's body failed after {got} bytes: {e}"
        )),
        _ => None,
    };
    let more = short.is_none() && (got > keep || length.is_some_and(|n| n > keep as u64));
    bytes.truncate(keep);
    Body { bytes, more, short }
}

/// [`read_body_parts`] for `Transfer-Encoding: chunked`.
fn read_chunked(reader: &mut (impl BufRead + ?Sized), keep: usize) -> Body {
    let mut bytes = Vec::new();
    let end = |bytes: Vec<u8>, more: bool, short: Option<String>| Body { bytes, more, short };
    loop {
        let got = bytes.len();
        let mut size_line = String::new();
        match reader.read_line(&mut size_line) {
            Ok(0) => {
                let why =
                    format!("the chunked answer ended after {got} bytes, before its last chunk");
                return end(bytes, false, Some(why));
            }
            Ok(_) => {}
            Err(e) => {
                let why = format!("the chunked answer ended after {got} bytes: {e}");
                return end(bytes, false, Some(why));
            }
        }
        let hex = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(hex, 16) else {
            let why = format!(
                "the chunked answer has a chunk size that is not hex after {got} bytes: {:?}",
                size_line.trim_end()
            );
            return end(bytes, false, Some(why));
        };
        if size == 0 {
            return end(bytes, false, None);
        }
        let room = keep.saturating_sub(got);
        let want = size.min(room);
        let mut chunk = Vec::new();
        let failed = reader.take(want as u64).read_to_end(&mut chunk).err();
        let read = chunk.len();
        bytes.extend_from_slice(&chunk);
        if read < want {
            let why = match failed {
                Some(e) => {
                    format!("a chunk of the answer ended after {read} of its {size} bytes: {e}")
                }
                None => format!("a chunk of the answer ended after {read} of its {size} bytes"),
            };
            return end(bytes, false, Some(why));
        }
        if size > room {
            return end(bytes, true, None);
        }
        let mut crlf = String::new();
        if let Err(e) = reader.read_line(&mut crlf) {
            let why = format!("the chunked answer ended after {} bytes: {e}", bytes.len());
            return end(bytes, false, Some(why));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, ErrorKind};

    /// A connection that hands out `data`, at most `step` bytes a read,
    /// then ends: with `end` as the error of the next read, or at end of
    /// file when `end` is `None`. `fail_once` makes the first read at that
    /// offset fail once with that kind: `Interrupted`, as a signal does, or
    /// a one-time error the connection then reads on after.
    struct Wire {
        data: Vec<u8>,
        at: usize,
        step: usize,
        end: Option<ErrorKind>,
        fail_once: Option<(usize, ErrorKind)>,
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some((at, kind)) = self.fail_once
                && at == self.at
            {
                self.fail_once = None;
                return Err(std::io::Error::new(kind, "the wire failed once"));
            }
            if self.at == self.data.len() {
                return match self.end {
                    Some(kind) => Err(std::io::Error::new(kind, "the wire failed")),
                    None => Ok(0),
                };
            }
            let n = buf.len().min(self.step).min(self.data.len() - self.at);
            buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    /// The wire for `data`, read 7 bytes at a time through a 16-byte buffer
    /// so that a body spans several reads.
    fn wire(data: &[u8], end: Option<ErrorKind>) -> BufReader<Wire> {
        BufReader::with_capacity(
            16,
            Wire {
                data: data.to_vec(),
                at: 0,
                step: 7,
                end,
                fail_once: None,
            },
        )
    }

    /// The wire for `data`, one byte a read, whose read at offset `at`
    /// fails once with `kind`.
    fn wire_failing_once(data: &[u8], at: usize, kind: ErrorKind) -> BufReader<Wire> {
        BufReader::with_capacity(
            16,
            Wire {
                data: data.to_vec(),
                at: 0,
                step: 1,
                end: None,
                fail_once: Some((at, kind)),
            },
        )
    }

    fn head(lines: &[&str]) -> Vec<String> {
        std::iter::once("HTTP/1.1 200 OK")
            .chain(lines.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    fn sized(n: usize) -> Vec<String> {
        head(&[&format!("Content-Length: {n}")])
    }

    fn chunked() -> Vec<String> {
        head(&["Transfer-Encoding: chunked"])
    }

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| b'a' + (i % 26) as u8).collect()
    }

    // SUCCESS

    #[test]
    fn a_body_of_its_content_length_is_read_whole() {
        let body = bytes(100);
        let got = read_body(&mut wire(&body, None), &sized(100), 1000);
        assert_eq!(got, Ok((body, false)), "a whole sized body is the body");
    }

    #[test]
    fn a_body_without_a_length_is_read_to_the_close() {
        let body = bytes(50);
        let got = read_body(&mut wire(&body, None), &head(&[]), 1000);
        assert_eq!(got, Ok((body, false)), "an unsized body ends at the close");
    }

    #[test]
    fn a_chunked_body_is_its_chunks_joined() {
        let got = read_body(
            &mut wire(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", None),
            &chunked(),
            1000,
        );
        assert_eq!(
            got,
            Ok((b"hello world".to_vec(), false)),
            "chunks join in order"
        );
    }

    #[test]
    fn a_chunk_extension_does_not_change_the_size() {
        let got = read_body(
            &mut wire(b"5;name=x\r\nhello\r\n0\r\n\r\n", None),
            &chunked(),
            1000,
        );
        assert_eq!(
            got,
            Ok((b"hello".to_vec(), false)),
            "an extension is not part of the size"
        );
    }

    #[test]
    fn a_sized_body_past_the_limit_is_cut_and_says_more() {
        let body = bytes(100);
        let got = read_body(&mut wire(&body, None), &sized(100), 10);
        assert_eq!(
            got,
            Ok((body[..10].to_vec(), true)),
            "the first 10 bytes, and more"
        );
    }

    #[test]
    fn a_chunked_body_past_the_limit_is_cut_and_says_more() {
        let got = read_body(
            &mut wire(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", None),
            &chunked(),
            8,
        );
        assert_eq!(
            got,
            Ok((b"hello wo".to_vec(), true)),
            "the first 8 bytes, and more"
        );
    }

    #[test]
    fn an_unsized_body_past_the_limit_is_cut_and_says_more() {
        let body = bytes(30);
        let got = read_body(&mut wire(&body, None), &head(&[]), 20);
        assert_eq!(
            got,
            Ok((body[..20].to_vec(), true)),
            "the first 20 bytes, and more"
        );
    }

    #[test]
    fn a_quoted_body_that_arrived_whole_is_the_body() {
        let body = bytes(40);
        let got = read_quoted_body(&mut wire(&body, None), &sized(40), 1000);
        assert_eq!(got, (body, false), "a whole quoted body is the body");
    }

    // FAILURE

    #[test]
    fn a_sized_body_that_closes_early_is_refused_with_both_counts() {
        let got = read_body(&mut wire(&bytes(40), None), &sized(100), 1000);
        let e = got.expect_err("a body 60 bytes short is not the body");
        assert!(
            e.contains("40 of its 100 bytes"),
            "names read and expected: {e}"
        );
    }

    #[test]
    fn a_sized_body_whose_read_times_out_is_refused_with_the_reason() {
        let got = read_body(
            &mut wire(&bytes(40), Some(ErrorKind::TimedOut)),
            &sized(100),
            1000,
        );
        let e = got.expect_err("a timed-out body is not the body");
        assert!(
            e.contains("40 of its 100 bytes"),
            "names read and expected: {e}"
        );
        assert!(e.contains("the wire failed"), "names the read error: {e}");
    }

    #[test]
    fn a_sized_body_whose_connection_resets_is_refused() {
        let got = read_body(
            &mut wire(&bytes(3), Some(ErrorKind::ConnectionReset)),
            &sized(10),
            1000,
        );
        let e = got.expect_err("a reset body is not the body");
        assert!(
            e.contains("3 of its 10 bytes"),
            "names read and expected: {e}"
        );
    }

    #[test]
    fn an_unsized_body_whose_read_fails_is_refused_with_the_count() {
        let got = read_body(
            &mut wire(&bytes(12), Some(ErrorKind::WouldBlock)),
            &head(&[]),
            1000,
        );
        let e = got.expect_err("an unsized body cut by a read error is not the body");
        assert!(e.contains("after 12 bytes"), "names the bytes read: {e}");
        assert!(e.contains("the wire failed"), "names the read error: {e}");
    }

    #[test]
    fn a_chunked_body_that_closes_before_its_last_chunk_is_refused() {
        let got = read_body(&mut wire(b"5\r\nhello\r\n", None), &chunked(), 1000);
        let e = got.expect_err("no last chunk, no whole body");
        assert!(
            e.contains("before its last chunk"),
            "says what is missing: {e}"
        );
        assert!(e.contains("after 5 bytes"), "names the bytes read: {e}");
    }

    #[test]
    fn a_chunked_body_whose_chunk_closes_early_is_refused() {
        let got = read_body(&mut wire(b"a\r\nhel", None), &chunked(), 1000);
        let e = got.expect_err("a chunk 7 bytes short is not the body");
        assert!(
            e.contains("3 of its 10 bytes"),
            "names read and the chunk size: {e}"
        );
    }

    #[test]
    fn a_chunked_body_whose_read_times_out_inside_a_chunk_is_refused() {
        let got = read_body(
            &mut wire(b"a\r\nhel", Some(ErrorKind::TimedOut)),
            &chunked(),
            1000,
        );
        let e = got.expect_err("a timed-out chunk is not the body");
        assert!(e.contains("the wire failed"), "names the read error: {e}");
    }

    #[test]
    fn a_chunked_body_whose_size_line_read_fails_is_refused() {
        let got = read_body(
            &mut wire(b"5\r\nhello\r\n", Some(ErrorKind::TimedOut)),
            &chunked(),
            1000,
        );
        let e = got.expect_err("a failed size line read is not the end of the body");
        assert!(e.contains("the wire failed"), "names the read error: {e}");
        assert!(e.contains("after 5 bytes"), "names the bytes read: {e}");
    }

    #[test]
    fn a_chunk_size_that_is_not_hex_is_refused() {
        let got = read_body(
            &mut wire(b"zz\r\nhello\r\n0\r\n\r\n", None),
            &chunked(),
            1000,
        );
        let e = got.expect_err("a size line that is not hex is not a chunked body");
        assert!(e.contains("\"zz\""), "quotes the size line: {e}");
    }

    #[test]
    fn a_chunked_body_whose_chunk_end_read_fails_is_refused() {
        let got = read_body(
            &mut wire(b"5\r\nhello", Some(ErrorKind::TimedOut)),
            &chunked(),
            1000,
        );
        let e = got.expect_err("a failed read after a chunk is not the end of the body");
        assert!(e.contains("the wire failed"), "names the read error: {e}");
    }

    #[test]
    fn a_short_sized_body_under_the_limit_is_refused_not_cut() {
        let got = read_body(&mut wire(&bytes(5), None), &sized(100), 10);
        let e = got.expect_err("5 bytes of 100 under a 10-byte limit is short, not more");
        assert!(
            e.contains("5 of its 100 bytes"),
            "names read and expected: {e}"
        );
    }

    // EDGE

    #[test]
    fn a_body_of_length_zero_is_empty_and_whole() {
        let got = read_body(&mut wire(b"", Some(ErrorKind::TimedOut)), &sized(0), 1000);
        assert_eq!(
            got,
            Ok((Vec::new(), false)),
            "nothing is read for a length of 0"
        );
    }

    #[test]
    fn a_body_exactly_the_limit_is_whole_and_not_more() {
        let body = bytes(10);
        let got = read_body(&mut wire(&body, None), &sized(10), 10);
        assert_eq!(
            got,
            Ok((body, false)),
            "10 bytes under a 10-byte limit is whole"
        );
    }

    #[test]
    fn a_read_error_after_the_whole_sized_body_does_not_count() {
        let body = bytes(20);
        let got = read_body(
            &mut wire(&body, Some(ErrorKind::TimedOut)),
            &sized(20),
            1000,
        );
        assert_eq!(
            got,
            Ok((body, false)),
            "the body is whole before the failing read"
        );
    }

    #[test]
    fn a_sized_body_one_byte_short_of_the_limit_plus_one_is_refused() {
        let got = read_body(&mut wire(&bytes(10), None), &sized(11), 10);
        let e = got.expect_err("10 of 11 bytes is short even at the limit");
        assert!(
            e.contains("10 of its 11 bytes"),
            "names read and expected: {e}"
        );
    }

    #[test]
    fn a_signal_during_a_body_read_is_read_through() {
        let body = bytes(30);
        let mut reader = wire_failing_once(&body, 14, ErrorKind::Interrupted);
        let got = read_body(&mut reader, &sized(30), 1000);
        assert_eq!(got, Ok((body, false)), "an interrupted read is read again");
    }

    #[test]
    fn a_one_time_error_at_a_chunk_end_is_refused_with_that_error() {
        // "5\r\nhello" is 8 bytes; the read of the chunk's CRLF fails once.
        let mut reader = wire_failing_once(b"5\r\nhello\r\n0\r\n\r\n", 8, ErrorKind::TimedOut);
        let e = read_body(&mut reader, &chunked(), 1000).expect_err("a failed chunk end");
        assert!(
            e.contains("after 5 bytes: the wire failed once"),
            "names the bytes and the read error, not a later parse: {e}"
        );
    }

    #[test]
    fn a_first_chunk_of_size_zero_is_an_empty_whole_body() {
        let got = read_body(&mut wire(b"0\r\n\r\n", None), &chunked(), 1000);
        assert_eq!(
            got,
            Ok((Vec::new(), false)),
            "a lone last chunk is an empty body"
        );
    }

    #[test]
    fn a_chunked_body_with_another_coding_listed_is_chunked() {
        let head = head(&["Transfer-Encoding: gzip, Chunked"]);
        let got = read_body(&mut wire(b"2\r\nhi\r\n0\r\n\r\n", None), &head, 1000);
        assert_eq!(
            got,
            Ok((b"hi".to_vec(), false)),
            "chunked is found in a list, any case"
        );
    }

    #[test]
    fn a_content_length_that_is_not_a_number_reads_to_the_close() {
        let head = head(&["Content-Length: many"]);
        let got = read_body(&mut wire(b"abc", None), &head, 1000);
        assert_eq!(
            got,
            Ok((b"abc".to_vec(), false)),
            "no length means the close ends it"
        );
    }

    #[test]
    fn a_quoted_body_that_closes_early_keeps_what_arrived() {
        let got = read_quoted_body(&mut wire(&bytes(4), None), &sized(100), 1000);
        assert_eq!(got, (bytes(4), false), "evidence keeps the bytes that came");
    }

    #[test]
    fn a_quoted_chunked_body_whose_read_fails_keeps_what_arrived() {
        let got = read_quoted_body(
            &mut wire(b"5\r\nhello\r\n3\r\nab", Some(ErrorKind::TimedOut)),
            &chunked(),
            1000,
        );
        assert_eq!(
            got,
            (b"helloab".to_vec(), false),
            "evidence keeps the bytes that came"
        );
    }

    #[test]
    fn a_short_body_declared_past_the_limit_is_short_not_more() {
        let got = read_body_parts(&mut wire(&bytes(5), None), &sized(100), 10);
        assert!(!got.more, "5 bytes that came are not more than the 10 kept");
        assert!(got.short.is_some(), "5 of 100 bytes is short");
        let quoted = read_quoted_body(&mut wire(&bytes(5), None), &sized(100), 10);
        assert_eq!(
            quoted,
            (bytes(5), false),
            "quoted as far as it came, not as cut"
        );
    }

    #[test]
    fn the_parts_of_a_short_body_carry_both_the_bytes_and_the_reason() {
        let got = read_body_parts(&mut wire(&bytes(6), None), &sized(9), 1000);
        assert_eq!(got.bytes, bytes(6), "the bytes that came");
        assert!(!got.more, "not more: short");
        let reason = got.short.unwrap_or_default();
        assert!(
            reason.contains("6 of its 9 bytes"),
            "the reason names both: {reason}"
        );
    }
}
