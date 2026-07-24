// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core SIP message parser.
//!
//! Parses raw byte slices into [`SipMessage`] structs. Handles request and
//! response first-lines, header folding (RFC 3261 SS7.3.1), compact header
//! form expansion, and body extraction with Content-Length validation.

use std::borrow::Cow;
use std::net::IpAddr;

use crate::error::ParseError;
use chrono::{DateTime, Utc};

use super::message::{SipHeader, SipMessage};
use super::method::SipMethod;
use crate::net::TransportProto;

/// Mapping from single-character compact header names to canonical long
/// forms. RFC 3261 §7.3.3 allows a compact form to substitute for the long
/// name at any time; the authoritative list is the IANA SIP Header Fields
/// registry (19 registered forms) — add new registrations here.
const COMPACT_HEADERS: &[(u8, &str)] = &[
    // RFC 3261 §20 core forms
    (b'i', "Call-ID"),
    (b'f', "From"),
    (b't', "To"),
    (b'v', "Via"),
    (b'm', "Contact"),
    (b'l', "Content-Length"),
    (b'c', "Content-Type"),
    (b'e', "Content-Encoding"),
    (b'k', "Supported"),
    (b's', "Subject"),
    // IANA-registered extension forms
    (b'a', "Accept-Contact"),      // RFC 3841
    (b'b', "Referred-By"),         // RFC 3892
    (b'd', "Request-Disposition"), // RFC 3841
    (b'j', "Reject-Contact"),      // RFC 3841
    (b'o', "Event"),               // RFC 6665
    (b'r', "Refer-To"),            // RFC 3515
    (b'u', "Allow-Events"),        // RFC 6665
    (b'x', "Session-Expires"),     // RFC 4028
    (b'y', "Identity"),            // RFC 8224
];

/// Parse a raw byte slice into a [`SipMessage`].
///
/// The caller supplies network-layer metadata (addresses, ports, transport)
/// obtained from the capture engine. The parser extracts the SIP first-line,
/// all headers (with folding and compact-form expansion), and the body.
///
/// If parsing fails partway through, the returned message will have
/// `parse_error: true` with whatever fields could be extracted.
///
/// # Arguments
///
/// * `data` — raw message bytes; copied once into a fresh `bytes::Bytes`.
/// * `timestamp` — capture time recorded on the returned message.
/// * `src_addr` / `dst_addr` — source and destination IP addresses from
///   the network layer.
/// * `src_port` / `dst_port` — source and destination transport ports.
/// * `transport` — transport protocol the message arrived on.
///
/// # Returns
///
/// A fully populated `SipMessage` (possibly with `parse_error` set for
/// partial input).
///
/// # Errors
///
/// Returns `Err` only when the data is clearly not a SIP message (e.g.,
/// binary garbage, no valid first line). Partial SIP messages produce `Ok`
/// with `parse_error` set.
///
/// # Examples
///
/// ```
/// use sipnab::net::TransportProto;
/// use sipnab::sip::parser::parse_sip;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
///     Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n\
///     From: \"Alice\" <sip:alice@example.com>;tag=a1\r\n\
///     To: <sip:bob@example.com>\r\n\
///     Call-ID: demo@example.com\r\n\
///     CSeq: 1 INVITE\r\n\
///     Content-Length: 0\r\n\r\n";
/// let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
/// let msg = parse_sip(raw, chrono::Utc::now(), ip, ip, 5060, 5060, TransportProto::Udp)?;
/// assert!(msg.is_request);
/// assert_eq!(msg.call_id(), Some("demo@example.com"));
/// assert_eq!(msg.from_user().as_deref(), Some("alice"));
///
/// // Non-SIP input is a matchable ParseError, not message text:
/// use sipnab::ParseError;
/// let err = parse_sip(b"GET / HTTP/1.1\r\n\r\n", chrono::Utc::now(), ip, ip, 80, 80,
///     TransportProto::Tcp).unwrap_err();
/// assert!(matches!(err, ParseError::NotSip { .. }));
/// # Ok::<(), sipnab::ParseError>(())
/// ```
#[must_use = "parsing result must be handled"]
pub fn parse_sip(
    data: &[u8],
    timestamp: DateTime<Utc>,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    transport: TransportProto,
) -> Result<SipMessage, ParseError> {
    // Validate the first line on the borrowed slice before paying for the
    // copy. All hard-`Err` conditions (empty, missing CRLF, non-UTF-8 or
    // non-SIP first line) are decidable without owning the bytes, so garbage
    // and non-SIP inputs return their error with zero allocation; only inputs
    // that will actually yield a message reach `copy_from_slice`.
    precheck_first_line(data)?;
    parse_sip_bytes(
        &bytes::Bytes::copy_from_slice(data),
        timestamp,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        transport,
    )
}

/// Run the cheap, allocation-free first-line validation that gates whether a
/// buffer can become a [`SipMessage`]. Returns the same `Err` variants
/// `parse_sip_bytes` would, so pre-checking the borrowed slice is behaviorally
/// identical to letting `parse_sip_bytes` reject a copy.
fn precheck_first_line(data: &[u8]) -> Result<(), ParseError> {
    if data.is_empty() {
        return Err(ParseError::Empty {
            what: "SIP message",
        });
    }
    let first_crlf = find_crlf(data).ok_or(ParseError::MissingCrlf)?;
    let first_line = &data[..first_crlf];
    let first_line_str = std::str::from_utf8(first_line).map_err(|_| ParseError::InvalidUtf8 {
        what: "SIP first line",
    })?;
    parse_first_line(first_line_str)?;
    Ok(())
}

/// Like [`parse_sip`], but `raw` and `body` of the returned message are
/// zero-copy views of `data`'s buffer (refcount bumps, no allocation).
/// Use this on the capture hot path where the payload is already a
/// [`bytes::Bytes`]; `parse_sip` copies once and delegates here.
///
/// Arguments, return value, and error conditions are identical to
/// `parse_sip` except that `data` is a refcounted buffer rather than a
/// plain slice.
#[must_use = "parsing result must be handled"]
pub fn parse_sip_bytes(
    data: &bytes::Bytes,
    timestamp: DateTime<Utc>,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    transport: TransportProto,
) -> Result<SipMessage, ParseError> {
    if data.is_empty() {
        return Err(ParseError::Empty {
            what: "SIP message",
        });
    }

    // Find the end of the first line
    let first_crlf = find_crlf(data).ok_or(ParseError::MissingCrlf)?;
    let first_line = &data[..first_crlf];

    // Attempt to decode the first line as UTF-8 for parsing
    let first_line_str = std::str::from_utf8(first_line).map_err(|_| ParseError::InvalidUtf8 {
        what: "SIP first line",
    })?;

    // Determine request vs response
    let first = parse_first_line(first_line_str)?;

    // Parse headers and body
    let header_start = first_crlf + 2; // skip past \r\n
    let (headers, body_range, parse_error) = parse_headers_and_body(data, header_start);

    Ok(SipMessage {
        raw: data.clone(),
        is_request: first.is_request,
        method: first.method,
        status_code: first.status_code,
        reason: first.reason,
        request_uri: first.request_uri,
        headers,
        body: body_range.map(|r| data.slice(r)).unwrap_or_default(),
        parse_error,
        timestamp,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        transport,
        is_retransmission: false,
    })
}

/// Parsed components of a SIP first line.
struct FirstLine {
    /// `true` for a request-line, `false` for a status-line.
    is_request: bool,
    /// Request method. `None` for responses.
    method: Option<SipMethod>,
    /// Response status code. `None` for requests.
    status_code: Option<u16>,
    /// Response reason phrase. `None` for requests.
    reason: Option<String>,
    /// Request-URI. `None` for responses.
    request_uri: Option<String>,
}

/// Parse the SIP first line (request-line or status-line).
///
/// # Arguments
///
/// * `line` — the first line of the message, already decoded as UTF-8 and
///   without its trailing CRLF.
///
/// # Returns
///
/// A `FirstLine` with either the response fields (`status_code`, `reason`)
/// or the request fields (`method`, `request_uri`) populated.
///
/// # Errors
///
/// `ParseError::InvalidFirstLine` when a status-line lacks a space after the
/// code or a request-line lacks the expected spaces,
/// `ParseError::InvalidStatusCode` when the status code is not a `u16`, and
/// `ParseError::NotSip` when the line is neither form.
fn parse_first_line(line: &str) -> Result<FirstLine, ParseError> {
    let line = line.trim();

    if let Some(after_version) = line.strip_prefix("SIP/2.0 ") {
        // Response: "SIP/2.0 200 OK"
        let space_pos = after_version
            .find(' ')
            .ok_or_else(|| ParseError::InvalidFirstLine {
                line: line.to_string(),
                reason: "no space after status code",
            })?;
        let code_str = &after_version[..space_pos];
        let code: u16 = code_str
            .parse()
            .map_err(|_| ParseError::InvalidStatusCode {
                code: code_str.to_string(),
            })?;
        let reason = after_version[space_pos + 1..].trim().to_string();

        Ok(FirstLine {
            is_request: false,
            method: None,
            status_code: Some(code),
            reason: Some(reason),
            request_uri: None,
        })
    } else if line.ends_with(" SIP/2.0") {
        // Request: "INVITE sip:bob@example.com SIP/2.0". The version token is
        // anchored to a leading SP so a glued `...ASIP/2.0` is not accepted.
        let first_space = line.find(' ').ok_or_else(|| ParseError::InvalidFirstLine {
            line: line.to_string(),
            reason: "no space in request line",
        })?;
        let method_str = &line[..first_space];

        let rest = &line[first_space + 1..];
        let last_space = rest
            .rfind(' ')
            .ok_or_else(|| ParseError::InvalidFirstLine {
                line: line.to_string(),
                reason: "no space before SIP version",
            })?;
        // RFC 3261 request-line grammar is single-SP-delimited, but tolerate
        // sloppy multi-SP input (e.g. "INVITE  sip:x SIP/2.0") by trimming the
        // extracted URI rather than rejecting the message.
        let uri = rest[..last_space].trim().to_string();

        Ok(FirstLine {
            is_request: true,
            method: Some(SipMethod::parse(method_str)),
            status_code: None,
            reason: None,
            request_uri: Some(uri),
        })
    } else {
        Err(ParseError::NotSip {
            line: line.to_string(),
        })
    }
}

/// Default maximum bytes in a single unfolded header line (D17 defense-in-depth).
pub const DEFAULT_MAX_HEADER_LINE_LEN: usize = 8 * 1024;

/// Default maximum number of headers per SIP message (D17 defense-in-depth).
pub const DEFAULT_MAX_HEADERS_PER_MESSAGE: usize = 200;

/// Runtime-configurable cap on the byte length of a single unfolded header
/// line (set once at startup from config; defaults to
/// `DEFAULT_MAX_HEADER_LINE_LEN`).
static MAX_HEADER_LINE_LEN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_HEADER_LINE_LEN);
/// Runtime-configurable cap on the number of headers retained per message
/// (set once at startup from config; defaults to
/// `DEFAULT_MAX_HEADERS_PER_MESSAGE`).
static MAX_HEADERS_PER_MESSAGE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_HEADERS_PER_MESSAGE);

/// Set parser limits from configuration. Call once at startup.
///
/// # Arguments
///
/// * `max_header_line` — maximum bytes allowed in one unfolded header line.
/// * `max_headers` — maximum number of headers retained per message.
///
/// # Side effects
///
/// Stores both values into the process-global `MAX_HEADER_LINE_LEN` and
/// `MAX_HEADERS_PER_MESSAGE` atomics (relaxed ordering), affecting every
/// subsequent parse on any thread.
pub fn set_parser_limits(max_header_line: usize, max_headers: usize) {
    MAX_HEADER_LINE_LEN.store(max_header_line, std::sync::atomic::Ordering::Relaxed);
    MAX_HEADERS_PER_MESSAGE.store(max_headers, std::sync::atomic::Ordering::Relaxed);
}

/// Parse SIP headers (with folding and compact form expansion) and extract body.
///
/// # Arguments
///
/// * `data` — the full raw message bytes.
/// * `start` — byte offset of the first header line (just past the
///   first-line CRLF).
///
/// # Returns
///
/// Returns `(headers, body byte-range within `data`, parse_error)`. The
/// header list is capped at the configured per-message maximum; the body
/// range is `None` when no blank-line separator was found, and is truncated
/// to the declared `Content-Length` when one is present. `parse_error` is
/// `true` for non-UTF-8 header lines, over-long folded lines, a missing
/// body separator, or a body shorter than the declared `Content-Length`.
fn parse_headers_and_body(
    data: &[u8],
    start: usize,
) -> (Vec<SipHeader>, Option<std::ops::Range<usize>>, bool) {
    /// Push a parsed header unless the per-message cap is reached. Dropping a
    /// header because the cap was hit sets `parse_error` so the truncation is
    /// visible rather than a silent loss.
    fn push_header_capped(
        headers: &mut Vec<SipHeader>,
        hdr: SipHeader,
        max_headers: usize,
        parse_error: &mut bool,
    ) {
        if headers.len() < max_headers {
            headers.push(hdr);
        } else {
            *parse_error = true;
        }
    }

    let max_header_line = MAX_HEADER_LINE_LEN.load(std::sync::atomic::Ordering::Relaxed);
    let max_headers = MAX_HEADERS_PER_MESSAGE.load(std::sync::atomic::Ordering::Relaxed);
    // A typical SIP message carries ~10-15 headers; skip the growth reallocs.
    let mut headers = Vec::with_capacity(16);
    let mut pos = start;
    let mut parse_error = false;

    // The pending (possibly folded) logical header line. Folding is rare in
    // real traffic, so the common case stays a borrow of `data`; only a
    // continuation line promotes it to an owned unfold buffer (`to_mut`).
    let mut current_line: Cow<'_, str> = Cow::Borrowed("");
    let mut found_body_separator = false;

    while pos < data.len() {
        match find_crlf(&data[pos..]) {
            Some(crlf_offset) => {
                let line_bytes = &data[pos..pos + crlf_offset];
                pos = pos + crlf_offset + 2; // advance past \r\n

                // Empty line = end of headers
                if line_bytes.is_empty() {
                    // Flush any pending header
                    if !current_line.is_empty()
                        && let Some(hdr) = parse_header_line(&current_line)
                    {
                        push_header_capped(&mut headers, hdr, max_headers, &mut parse_error);
                    }
                    current_line = Cow::Borrowed("");
                    found_body_separator = true;
                    break;
                }

                // Convert to string; skip malformed lines
                let line_str = match std::str::from_utf8(line_bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        parse_error = true;
                        continue;
                    }
                };

                // RFC 3261 SS7.3.1: continuation lines start with SP or HTAB
                if line_str.starts_with(' ') || line_str.starts_with('\t') {
                    // Header folding: append to current line with a single space
                    // (capped). `to_mut` materializes the unfold buffer only here.
                    if current_line.len() + line_str.len() < max_header_line {
                        let buf = current_line.to_mut();
                        buf.push(' ');
                        buf.push_str(line_str.trim_start());
                    } else {
                        parse_error = true;
                    }
                } else {
                    // New header — flush the previous one
                    if !current_line.is_empty()
                        && let Some(hdr) = parse_header_line(&current_line)
                    {
                        push_header_capped(&mut headers, hdr, max_headers, &mut parse_error);
                    }
                    // Bound the unfolded line too: without this a single
                    // multi-MB header (no continuations) sails past the cap
                    // that only guarded folded growth.
                    if line_str.len() >= max_header_line {
                        parse_error = true;
                        current_line = Cow::Borrowed("");
                    } else {
                        current_line = Cow::Borrowed(line_str);
                    }
                }
            }
            None => {
                // No more CRLFs — treat remainder as a partial header
                if pos < data.len()
                    && let Ok(remainder) = std::str::from_utf8(&data[pos..])
                {
                    if remainder.starts_with(' ') || remainder.starts_with('\t') {
                        if current_line.len() + remainder.len() < max_header_line {
                            let buf = current_line.to_mut();
                            buf.push(' ');
                            buf.push_str(remainder.trim_start());
                        }
                        // parse_error set below in the None→break path
                    } else {
                        if !current_line.is_empty()
                            && let Some(hdr) = parse_header_line(&current_line)
                        {
                            push_header_capped(&mut headers, hdr, max_headers, &mut parse_error);
                        }
                        // Same unfolded-line cap on the no-trailing-CRLF path:
                        // drop an over-long remainder so it is not flushed as a
                        // header. (parse_error is set unconditionally just below
                        // for this truncated-message path.)
                        if remainder.len() < max_header_line {
                            current_line = Cow::Borrowed(remainder);
                        }
                    }
                }
                parse_error = true;
                break;
            }
        }
    }

    // Flush any remaining header
    if !current_line.is_empty()
        && let Some(hdr) = parse_header_line(&current_line)
    {
        push_header_capped(&mut headers, hdr, max_headers, &mut parse_error);
    }

    // No \r\n\r\n found means the message is incomplete
    if !found_body_separator {
        parse_error = true;
    }

    // Extract body
    let body = if found_body_separator && pos < data.len() {
        let body_bytes = &data[pos..];

        // Validate against Content-Length if present. A header that is present
        // but non-numeric must not be silently treated as absent: flag it via
        // parse_error so a garbage length carries a signal.
        let content_length = match headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
        {
            Some(h) => match h.value.trim().parse::<usize>() {
                Ok(len) => Some(len),
                Err(_) => {
                    parse_error = true;
                    None
                }
            },
            None => None,
        };

        if let Some(expected_len) = content_length {
            if body_bytes.len() < expected_len {
                parse_error = true;
            }
            // Take at most expected_len bytes
            Some(pos..pos + body_bytes.len().min(expected_len))
        } else {
            Some(pos..data.len())
        }
    } else {
        None
    };

    (headers, body, parse_error)
}

/// Parse a single unfolded header line into a [`SipHeader`].
///
/// Handles `Name: Value` and compact single-character forms. Returns `None`
/// when the line has no colon or an empty header name.
fn parse_header_line(line: &str) -> Option<SipHeader> {
    let colon_pos = line.find(':')?;
    let raw_name = line[..colon_pos].trim();
    let value = line[colon_pos + 1..].trim().to_string();

    if raw_name.is_empty() {
        return None;
    }

    let name = expand_compact_header(raw_name);

    Some(SipHeader { name, value })
}

/// Expand a compact header name to its canonical long form.
///
/// Single-character names are looked up in the compact header mapping table.
/// Multi-character names in exact canonical casing borrow a static string
/// (real traffic overwhelmingly uses canonical case — this removes one heap
/// allocation per header on the hot path); any other casing is returned
/// as-is, preserving the original (see
/// `non_canonical_case_header_name_is_preserved`).
fn expand_compact_header(name: &str) -> Cow<'static, str> {
    if name.len() == 1 {
        let ch = name.as_bytes()[0].to_ascii_lowercase();
        for &(compact, long) in COMPACT_HEADERS {
            if ch == compact {
                return Cow::Borrowed(long);
            }
        }
    }
    match canonical_header_name(name) {
        Some(canonical) => Cow::Borrowed(canonical),
        None => Cow::Owned(name.to_string()),
    }
}

/// Exact-match (case-sensitive) table of common long-form header names,
/// returning the `'static` canonical string so [`SipHeader::name`] can
/// borrow instead of allocating. Deliberately NOT case-insensitive: a
/// non-canonical casing must round-trip unchanged.
fn canonical_header_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "Via" => "Via",
        "From" => "From",
        "To" => "To",
        "Call-ID" => "Call-ID",
        "CSeq" => "CSeq",
        "Contact" => "Contact",
        "Max-Forwards" => "Max-Forwards",
        "Content-Length" => "Content-Length",
        "Content-Type" => "Content-Type",
        "User-Agent" => "User-Agent",
        "Allow" => "Allow",
        "Supported" => "Supported",
        "Require" => "Require",
        "Expires" => "Expires",
        "Route" => "Route",
        "Record-Route" => "Record-Route",
        "Authorization" => "Authorization",
        "WWW-Authenticate" => "WWW-Authenticate",
        "Proxy-Authorization" => "Proxy-Authorization",
        "Proxy-Authenticate" => "Proxy-Authenticate",
        "P-Asserted-Identity" => "P-Asserted-Identity",
        "Session-Expires" => "Session-Expires",
        "Min-SE" => "Min-SE",
        "Refer-To" => "Refer-To",
        "Referred-By" => "Referred-By",
        "Event" => "Event",
        "Subscription-State" => "Subscription-State",
        "Accept" => "Accept",
        "Accept-Contact" => "Accept-Contact",
        "Reject-Contact" => "Reject-Contact",
        "Request-Disposition" => "Request-Disposition",
        "Allow-Events" => "Allow-Events",
        "Server" => "Server",
        "Subject" => "Subject",
        "Date" => "Date",
        "Reason" => "Reason",
        "Warning" => "Warning",
        "Privacy" => "Privacy",
        "Diversion" => "Diversion",
        "Identity" => "Identity",
        "Timestamp" => "Timestamp",
        "Organization" => "Organization",
        "RSeq" => "RSeq",
        "RAck" => "RAck",
        _ => return None,
    })
}

/// Find the position of the first `\r\n` in `data`, or `None` if absent.
///
/// Canonical CRLF scanner for the `sip` module; also used by the first-line
/// sniffer in [`super::is_sip_message`].
pub(super) fn find_crlf(data: &[u8]) -> Option<usize> {
    // SIMD \r search, then verify the following \n — byte-identical to the old
    // windows(2) scan (bare \r is skipped; a trailing \r returns None).
    let mut start = 0;
    while let Some(i) = memchr::memchr(b'\r', &data[start..]) {
        let abs = start + i;
        if data.get(abs + 1) == Some(&b'\n') {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

/// Parity tests pinning the memchr-based `find_crlf` to a scalar reference.
#[cfg(test)]
mod find_crlf_tests {
    use super::find_crlf;
    // The memchr-based find_crlf must be byte-identical to a scalar windows(2)
    // scan across the adversarial boundary cases.
    /// Reference implementation: naive `windows(2)` scan for `\r\n` in `data`.
    fn scalar(data: &[u8]) -> Option<usize> {
        data.windows(2).position(|w| w == b"\r\n")
    }
    /// `find_crlf` matches the scalar reference on adversarial boundary cases.
    #[test]
    fn parity_with_scalar() {
        let cases: &[&[u8]] = &[
            b"",
            b"\r",
            b"\n",
            b"\r\n",
            b"abc\r\n",
            b"a\rb\r\nc",  // bare \r before the real \r\n
            b"line\r",     // trailing \r, no \n
            b"x\r\ny\r\n", // first match only
            b"\x00\r\n",   // embedded NUL
            b"no crlf here",
            b"a\n\rb\r\n", // \n\r (not \r\n) then \r\n
        ];
        for c in cases {
            assert_eq!(find_crlf(c), scalar(c), "mismatch on {c:?}");
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests covering first-line parsing, header handling (folding, compact
/// forms, duplicates, casing), body extraction, malformed input, and the
/// security caps on header size/count.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Fixed 127.0.0.1 address used for all test messages.
    fn localhost_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed capture timestamp (2024-06-15 12:00:00 UTC) used in tests.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// A full RFC 3261 example INVITE parses with all fields extracted.
    #[test]
    fn parse_invite_request() {
        let msg = build_sip(
            "INVITE sip:bob@biloxi.example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds",
                "Max-Forwards: 70",
                "To: Bob <sip:bob@biloxi.example.com>",
                "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774",
                "Call-ID: a84b4c76e66710@pc33.atlanta.example.com",
                "CSeq: 314159 INVITE",
                "Contact: <sip:alice@pc33.atlanta.example.com>",
                "Content-Type: application/sdp",
                "Content-Length: 4",
            ],
            b"test",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE");

        assert!(sip.is_request);
        assert_eq!(sip.method, Some(SipMethod::Invite));
        assert_eq!(
            sip.request_uri.as_deref(),
            Some("sip:bob@biloxi.example.com")
        );
        assert!(sip.status_code.is_none());
        assert!(sip.reason.is_none());
        assert_eq!(
            sip.call_id(),
            Some("a84b4c76e66710@pc33.atlanta.example.com")
        );
        assert_eq!(
            sip.from_header(),
            Some("Alice <sip:alice@atlanta.example.com>;tag=1928301774")
        );
        assert_eq!(sip.to_header(), Some("Bob <sip:bob@biloxi.example.com>"));
        assert_eq!(sip.contact(), Some("<sip:alice@pc33.atlanta.example.com>"));
        assert_eq!(sip.content_type(), Some("application/sdp"));
        assert_eq!(sip.body[..], b"test"[..]);
        assert!(!sip.parse_error);
    }

    /// A 200 OK status-line parses with code/reason and no request fields.
    #[test]
    fn parse_200_ok_response() {
        let msg = build_sip(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds",
                "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf",
                "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774",
                "Call-ID: a84b4c76e66710@pc33.atlanta.example.com",
                "CSeq: 314159 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse 200 OK");

        assert!(!sip.is_request);
        assert_eq!(sip.status_code, Some(200));
        assert_eq!(sip.reason.as_deref(), Some("OK"));
        assert!(sip.method.is_none());
        assert!(sip.request_uri.is_none());
        assert!(!sip.parse_error);
    }

    /// Core RFC 3261 compact forms (v/f/t/i/m/l) expand to long names.
    #[test]
    fn compact_headers() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "v: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK123",
                "f: Alice <sip:alice@example.com>;tag=abc",
                "t: Bob <sip:bob@example.com>",
                "i: call-id-12345@example.com",
                "m: <sip:alice@10.0.0.1>",
                "l: 0",
            ],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse compact headers");

        assert_eq!(sip.call_id(), Some("call-id-12345@example.com"));
        assert_eq!(
            sip.from_header(),
            Some("Alice <sip:alice@example.com>;tag=abc")
        );
        assert_eq!(sip.to_header(), Some("Bob <sip:bob@example.com>"));
        assert_eq!(sip.contact(), Some("<sip:alice@10.0.0.1>"));

        // Verify internal name expansion
        assert!(sip.headers.iter().any(|h| h.name == "Call-ID"));
        assert!(sip.headers.iter().any(|h| h.name == "Via"));
        assert!(sip.headers.iter().any(|h| h.name == "From"));
        assert!(sip.headers.iter().any(|h| h.name == "To"));
        assert!(sip.headers.iter().any(|h| h.name == "Contact"));
        assert!(sip.headers.iter().any(|h| h.name == "Content-Length"));
    }

    /// All nine IANA extension compact forms expand, case-insensitively.
    #[test]
    fn extension_compact_headers_expand() {
        // All nine IANA-registered extension compact forms (beyond the RFC
        // 3261 core ten), in mixed case to pin case-insensitive matching:
        // a=Accept-Contact, b=Referred-By, d=Request-Disposition,
        // j=Reject-Contact, o=Event, r=Refer-To, u=Allow-Events,
        // x=Session-Expires, y=Identity.
        let msg = build_sip(
            "REFER sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1",
                "From: <sip:alice@example.com>;tag=a",
                "To: <sip:bob@example.com>",
                "Call-ID: compact-ext@test",
                "CSeq: 1 REFER",
                "a: *;require",
                "B: <sip:referrer@example.com>",
                "d: no-fork",
                "j: *;class=\"business\"",
                "o: dialog",
                "R: <sip:target@example.com>",
                "u: dialog, message-summary",
                "X: 1800;refresher=uac",
                "y: dummy.jwt.value",
                "Content-Length: 0",
            ],
            b"",
        );
        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        for name in [
            "Accept-Contact",
            "Referred-By",
            "Request-Disposition",
            "Reject-Contact",
            "Event",
            "Refer-To",
            "Allow-Events",
            "Session-Expires",
            "Identity",
        ] {
            assert!(
                sip.headers.iter().any(|h| h.name == name),
                "compact form for `{name}` not expanded"
            );
        }
        // No single-letter names may remain.
        assert!(
            !sip.headers.iter().any(|h| h.name.len() == 1),
            "unexpanded single-letter header remains"
        );
        assert_eq!(sip.header("Refer-To"), Some("<sip:target@example.com>"));
    }

    /// Single-letter headers with no registered compact form pass through.
    #[test]
    fn unknown_single_letter_headers_keep_their_name() {
        // Letters with no registered compact form must pass through as-is.
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Call-ID: unknown-compact@test",
                "z: mystery",
                "q: 0.7",
                "Content-Length: 0",
            ],
            b"",
        );
        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert!(sip.headers.iter().any(|h| h.name == "z"));
        assert!(sip.headers.iter().any(|h| h.name == "q"));
    }

    /// Mixed long-form and compact duplicates both survive under one name.
    #[test]
    fn mixed_long_and_compact_duplicates_are_both_kept() {
        // RFC 3261 §7.3.3: forms may be mixed freely in one message; both
        // instances of a repeated header must survive under the long name.
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bK1",
                "v: SIP/2.0/UDP proxy2.example.com;branch=z9hG4bK2",
                "Call-ID: mixed-forms@test",
                "Content-Length: 0",
            ],
            b"",
        );
        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        let vias: Vec<_> = sip.headers.iter().filter(|h| h.name == "Via").collect();
        assert_eq!(vias.len(), 2, "both Via instances must be kept");
        assert!(vias[0].value.contains("proxy1"));
        assert!(vias[1].value.contains("proxy2"));
    }

    /// Non-canonical header-name casing (e.g. "VIA") is preserved verbatim.
    #[test]
    fn non_canonical_case_header_name_is_preserved() {
        // Pins WS4.1's canonical-name table to exact-match only: "VIA" must
        // survive as "VIA" (lookups are case-insensitive anyway), never get
        // rewritten to "Via".
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "VIA: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK123",
                "CALL-id: weird-case@example.com",
                "Content-Length: 0",
            ],
            b"",
        );
        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert!(sip.headers.iter().any(|h| h.name == "VIA"));
        assert!(!sip.headers.iter().any(|h| h.name == "Via"));
        assert!(sip.headers.iter().any(|h| h.name == "CALL-id"));
        // Case-insensitive lookup still resolves it.
        assert_eq!(sip.call_id(), Some("weird-case@example.com"));
    }

    /// An orphan continuation line before any header is dropped.
    #[test]
    fn leading_continuation_line_produces_no_header() {
        // A continuation (SP-prefixed) line with no header before it must be
        // dropped, not parsed into a bogus header.
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n \
orphan-continuation\r\n\
Call-ID: orphan-fold@example.com\r\n\
Content-Length: 0\r\n\
\r\n";
        let sip = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert_eq!(sip.call_id(), Some("orphan-fold@example.com"));
        assert!(
            !sip.headers
                .iter()
                .any(|h| h.value.contains("orphan-continuation"))
        );
    }

    /// A truncated trailing continuation still folds, with parse_error set.
    #[test]
    fn trailing_continuation_without_crlf_still_folds() {
        // Message truncated mid-fold: the SP-prefixed remainder (no trailing
        // CRLF) must still fold into the pending header, with parse_error set.
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Call-ID: trunc-fold@example.com\r\n\
Subject: first-part\r\n continued-tail";
        let sip = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert!(sip.parse_error, "truncated message must set parse_error");
        let subject = sip
            .headers
            .iter()
            .find(|h| h.name == "Subject")
            .expect("subject parsed");
        assert_eq!(subject.value, "first-part continued-tail");
    }

    /// A single *unfolded* header line longer than `MAX_HEADER_LINE_LEN` is
    /// rejected (parse_error set, header dropped), not accepted whole — the
    /// cap must bound unfolded lines, not only folded continuations.
    #[test]
    fn oversized_unfolded_header_line_rejected() {
        let big_value = "A".repeat(DEFAULT_MAX_HEADER_LINE_LEN + 100);
        let raw = format!("Subject: {big_value}\r\nCall-ID: ok@example.com\r\n\r\n");
        let (headers, _body, parse_error) = parse_headers_and_body(raw.as_bytes(), 0);
        assert!(
            parse_error,
            "oversized unfolded header must set parse_error"
        );
        assert!(
            !headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("Subject")),
            "oversized unfolded header must not be stored"
        );
        // A normal header after the rejected one still parses.
        assert!(
            headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("Call-ID")),
            "a following normal header must still parse"
        );
    }

    /// A SP-folded Via header (RFC 3261 §7.3.1) is unfolded into one value.
    #[test]
    fn header_folding() {
        // RFC 3261 SS7.3.1: continuation line starts with SP
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP first.example.com\r\n \
;branch=z9hG4bKnashds\r\n\
Call-ID: folding-test@example.com\r\n\
Content-Length: 0\r\n\
\r\n";

        let sip = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse folded headers");

        let via = sip.via_headers();
        assert_eq!(via.len(), 1);
        assert!(
            via[0].contains("first.example.com") && via[0].contains(";branch=z9hG4bKnashds"),
            "Folded Via should be unfolded: got '{}'",
            via[0]
        );
    }

    /// Three Via headers are all kept, in message order.
    #[test]
    fn multiple_via_headers() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP proxy2.example.com;branch=z9hG4bK222",
                "Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bK111",
                "Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK000",
                "Call-ID: multi-via@example.com",
                "Content-Length: 0",
            ],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse multiple Via");

        let vias = sip.via_headers();
        assert_eq!(vias.len(), 3);
        assert!(vias[0].contains("proxy2"));
        assert!(vias[1].contains("proxy1"));
        assert!(vias[2].contains("client"));
    }

    /// `CSeq: 1 INVITE` splits into sequence number and method.
    #[test]
    fn cseq_parsing() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &["CSeq: 1 INVITE", "Content-Length: 0"],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse CSeq");

        let (num, method) = sip.cseq().expect("CSeq should be present");
        assert_eq!(num, 1);
        assert_eq!(method, "INVITE");
    }

    /// A body exactly matching Content-Length parses cleanly.
    #[test]
    fn body_matches_content_length() {
        let body = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n";
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[&format!("Content-Length: {}", body.len())],
            body,
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse body");

        assert_eq!(sip.body[..], body[..]);
        assert!(!sip.parse_error);
    }

    /// The user part is extracted from the From URI.
    #[test]
    fn from_user_extraction() {
        let msg = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &["From: <sip:1001@example.com>;tag=abc", "Content-Length: 0"],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert_eq!(sip.from_user(), Some("1001".to_string()));
    }

    /// The user part is extracted from the To URI.
    #[test]
    fn to_user_extraction() {
        let msg = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &["To: <sip:1002@example.com>", "Content-Length: 0"],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert_eq!(sip.to_user(), Some("1002".to_string()));
    }

    /// A message with no blank-line separator still yields a partial parse
    /// with parse_error set.
    #[test]
    fn malformed_truncated_message() {
        // Has a first line and one header but no \r\n\r\n separator
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x\r\n";

        let sip = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("partial parse should succeed");

        assert!(sip.is_request);
        assert_eq!(sip.method, Some(SipMethod::Invite));
        assert!(sip.parse_error);
        assert!(sip.body.is_empty());
    }

    /// Binary garbage with no SIP first line returns an error.
    #[test]
    fn malformed_binary_garbage() {
        let garbage: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90, 0xA0, 0xB0];
        let result = parse_sip(
            &garbage,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        );
        assert!(result.is_err(), "Binary garbage should return an error");
    }

    /// Headers ending without a blank line parse with an empty body and
    /// parse_error set.
    #[test]
    fn malformed_missing_body_separator() {
        // Headers end with \r\n but no blank line separator
        let msg = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host\r\nContent-Length: 0\r\n";

        let sip = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse with empty body");

        assert!(!sip.is_request);
        assert_eq!(sip.status_code, Some(200));
        assert!(sip.body.is_empty());
        assert!(sip.parse_error);
    }

    /// An HTTP request is rejected as not SIP.
    #[test]
    fn non_sip_data() {
        let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            80,
            80,
            TransportProto::Tcp,
        );
        assert!(result.is_err());
    }

    /// `header()` lookups match regardless of the queried name's casing.
    #[test]
    fn case_insensitive_header_lookup() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &["Call-ID: test-case@example.com", "Content-Length: 0"],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert_eq!(sip.header("call-id"), Some("test-case@example.com"));
        assert_eq!(sip.header("CALL-ID"), Some("test-case@example.com"));
        assert_eq!(sip.header("Call-Id"), Some("test-case@example.com"));
    }

    /// Empty input returns an error rather than a message.
    #[test]
    fn empty_data_returns_error() {
        let result = parse_sip(
            b"",
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        );
        assert!(result.is_err());
    }

    /// From and To `tag` parameters are extracted.
    #[test]
    fn from_tag_extraction() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: Alice <sip:alice@example.com>;tag=from-tag-123",
                "To: Bob <sip:bob@example.com>;tag=to-tag-456",
                "Content-Length: 0",
            ],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert_eq!(sip.from_tag(), Some("from-tag-123"));
        assert_eq!(sip.to_tag(), Some("to-tag-456"));
    }

    /// `user_agent()` falls back to the Server header on responses.
    #[test]
    fn user_agent_fallback_to_server() {
        let msg = build_sip(
            "SIP/2.0 200 OK",
            &["Server: sipnab/0.1", "Content-Length: 0"],
            b"",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert_eq!(sip.user_agent(), Some("sipnab/0.1"));
    }

    /// An HTAB-folded header (RFC 3261 §7.3.1) is unfolded like SP.
    #[test]
    fn header_folding_with_tab() {
        // RFC 3261 SS7.3.1: continuation line starts with HTAB
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host.example.com\r\n\
\t;branch=z9hG4bKtab\r\n\
Content-Length: 0\r\n\
\r\n";

        let sip = parse_sip(
            msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse tab-folded header");

        let via = sip.via_headers();
        assert_eq!(via.len(), 1);
        assert!(via[0].contains(";branch=z9hG4bKtab"));
    }

    /// A body shorter than the declared Content-Length sets parse_error but
    /// keeps the bytes that are present.
    #[test]
    fn body_shorter_than_content_length_sets_parse_error() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &["Content-Length: 100"],
            b"short",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse with error flag");

        assert!(sip.parse_error);
        assert_eq!(sip.body[..], b"short"[..]);
    }

    // ── Security regression tests ────────────────────────────────────

    /// ~50KB of folded continuation lines is capped at the 8KB line limit
    /// with parse_error set (no unbounded allocation).
    #[test]
    fn header_folding_capped_at_8kb() {
        // Construct a Via header followed by 500 continuation lines of ~100
        // bytes each, totalling ~50KB of folded content. The parser must not
        // allocate an unbounded string — the MAX_HEADER_LINE_LEN (8KB) cap
        // should kick in and set parse_error.
        let padding: String = "x".repeat(97); // 97 chars + " " prefix + CRLF overhead ≈ 100 bytes
        let mut raw = Vec::new();
        raw.extend_from_slice(b"INVITE sip:bob@example.com SIP/2.0\r\n");
        raw.extend_from_slice(b"Via: SIP/2.0/UDP host.example.com\r\n");
        for _ in 0..500 {
            raw.extend_from_slice(b" ");
            raw.extend_from_slice(padding.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"Content-Length: 0\r\n");
        raw.extend_from_slice(b"\r\n");

        let sip = parse_sip(
            &raw,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse without panic");

        assert!(
            sip.parse_error,
            "parse_error should be set when folding exceeds 8KB"
        );

        // The Via value must be truncated, not the full ~50KB
        let via = sip.via_headers();
        if !via.is_empty() {
            assert!(
                via[0].len() < DEFAULT_MAX_HEADER_LINE_LEN,
                "Via value should be truncated below {DEFAULT_MAX_HEADER_LINE_LEN} bytes, got {}",
                via[0].len()
            );
        }
    }

    /// 300 headers are truncated to the 200-per-message cap.
    #[test]
    fn header_count_capped_at_200() {
        // Send 300 headers; the parser must stop at MAX_HEADERS_PER_MESSAGE (200).
        let mut headers: Vec<String> = (1..=300)
            .map(|i| format!("X-Junk-{i:03}: value-{i}"))
            .collect();
        headers.push("Content-Length: 0".to_string());

        let header_refs: Vec<&str> = headers.iter().map(|s| s.as_str()).collect();
        let msg = build_sip("INVITE sip:bob@example.com SIP/2.0", &header_refs, b"");

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse with capped headers");

        assert!(
            sip.headers.len() <= DEFAULT_MAX_HEADERS_PER_MESSAGE,
            "headers should be capped at {DEFAULT_MAX_HEADERS_PER_MESSAGE}, got {}",
            sip.headers.len()
        );
    }

    /// CRLF embedded in a header value splits into a separate header instead
    /// of surviving inside the value (log-injection defense).
    #[test]
    fn crlf_injection_in_header_value_no_log_injection() {
        // A malicious User-Agent embeds \r\n to try to inject a fake header.
        // The parser should treat the CRLF as a header boundary, so the
        // User-Agent value must NOT contain a newline.
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
User-Agent: evil\r\n\
fake-header: injected\r\n\
Content-Length: 0\r\n\
\r\n";

        let sip = parse_sip(
            raw,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let ua = sip
            .header("User-Agent")
            .expect("User-Agent header should exist");

        assert!(
            !ua.contains('\n') && !ua.contains('\r'),
            "User-Agent value must not contain newlines, got: {ua:?}"
        );
        assert_eq!(ua, "evil", "User-Agent should be just 'evil'");

        // The CRLF should have been treated as a header boundary, creating
        // "fake-header" as a separate header.
        assert_eq!(
            sip.header("fake-header"),
            Some("injected"),
            "CRLF should split into a separate header, not embed in UA value"
        );
    }

    /// Headers dropped past `MAX_HEADERS_PER_MESSAGE` must set parse_error so
    /// the silent truncation is visible, not swallowed.
    #[test]
    fn header_count_overflow_sets_parse_error() {
        let mut headers: Vec<String> = (1..=300)
            .map(|i| format!("X-Junk-{i:03}: value-{i}"))
            .collect();
        headers.push("Content-Length: 0".to_string());
        let header_refs: Vec<&str> = headers.iter().map(|s| s.as_str()).collect();
        let msg = build_sip("INVITE sip:bob@example.com SIP/2.0", &header_refs, b"");

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert!(sip.headers.len() <= DEFAULT_MAX_HEADERS_PER_MESSAGE);
        assert!(
            sip.parse_error,
            "dropping headers past the cap must set parse_error"
        );
    }

    /// A present-but-non-numeric Content-Length must set parse_error rather
    /// than being silently ignored (treated as absent), so a garbage length
    /// carries a signal. The body bytes present are still retained.
    #[test]
    fn non_numeric_content_length_sets_parse_error() {
        let msg = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &["Content-Length: abc"],
            b"hello",
        );

        let sip = parse_sip(
            &msg,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert!(
            sip.parse_error,
            "non-numeric Content-Length must set parse_error"
        );
        assert_eq!(
            sip.body[..],
            b"hello"[..],
            "present body bytes must be retained, not dropped"
        );
    }

    /// A request line with a double space after the method (RFC 3261 grammar
    /// is single-SP, but sloppy input is tolerated) must yield a trimmed
    /// Request-URI, not one with a leading space.
    #[test]
    fn request_uri_with_double_space_is_trimmed() {
        let raw = b"INVITE  sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let sip = parse_sip(
            raw,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert!(sip.is_request);
        assert_eq!(sip.request_uri.as_deref(), Some("sip:x"));
    }

    /// The version token must be SP-anchored: `ASIP/2.0` glued onto the URI is
    /// not a valid `SIP/2.0` version and the line must be rejected as NotSip,
    /// not accepted as a request via an unanchored `ends_with`.
    #[test]
    fn request_line_requires_space_before_version() {
        let raw = b"INVITE sip:alice ASIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let err = parse_sip(
            raw,
            ts(),
            localhost_v4(),
            localhost_v4(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect_err("ASIP/2.0 must not parse as a SIP request");
        assert!(
            matches!(err, ParseError::NotSip { .. }),
            "expected NotSip, got {err:?}"
        );
    }
}
