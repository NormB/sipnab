//! SIP message type and header accessors.
//!
//! [`SipMessage`] holds a fully parsed SIP message with all headers extracted
//! and normalized. Accessor methods provide convenient typed access to
//! commonly used headers.

use std::borrow::Cow;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::method::SipMethod;
use super::sdp::{self, SdpSession};
use crate::net::TransportProto;

/// A single SIP header: name (normalized to long form) and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHeader {
    /// Header name, normalized to canonical long form (e.g., `"Call-ID"` not `"i"`).
    /// Compact-form headers use `Cow::Borrowed` from static strings; others are owned.
    pub name: Cow<'static, str>,
    /// Header value with leading/trailing whitespace trimmed.
    pub value: String,
}

/// A parsed SIP message with metadata from the capture layer.
///
/// Holds the full raw bytes alongside extracted fields. All headers are
/// eagerly parsed during construction but stored for fast repeated access
/// via the accessor methods.
#[derive(Debug, Clone)]
pub struct SipMessage {
    /// Full raw message bytes as captured (refcounted view of the
    /// packet payload buffer — cloning a SipMessage does not copy it).
    pub raw: bytes::Bytes,
    /// `true` for requests (INVITE, REGISTER, ...), `false` for responses.
    pub is_request: bool,
    /// Request method (e.g., `SipMethod::Invite`). `None` for responses.
    pub method: Option<SipMethod>,
    /// Response status code (e.g., `200`). `None` for requests.
    pub status_code: Option<u16>,
    /// Response reason phrase (e.g., `"OK"`). `None` for requests.
    pub reason: Option<String>,
    /// Request-URI (e.g., `"sip:user@host"`). `None` for responses.
    pub request_uri: Option<String>,
    /// All headers in message order, with compact forms expanded.
    pub headers: Vec<SipHeader>,
    /// Message body (SDP or other payload after the blank line); a
    /// view of the same buffer as `raw`.
    pub body: bytes::Bytes,
    /// `true` if the message was only partially parseable.
    #[allow(dead_code)] // Read in parser tests and available for future use
    pub(crate) parse_error: bool,
    /// Capture timestamp.
    pub timestamp: DateTime<Utc>,
    /// Source IP address from the network layer.
    pub src_addr: IpAddr,
    /// Destination IP address from the network layer.
    pub dst_addr: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// Transport protocol used to carry this message.
    pub transport: TransportProto,
    /// Whether this message is a retransmission of a previously seen message.
    pub(crate) is_retransmission: bool,
}

impl SipMessage {
    /// Return the value of the `Call-ID` header, if present.
    pub fn call_id(&self) -> Option<&str> {
        self.header("Call-ID")
    }

    /// Return the value of the `From` header, if present.
    pub fn from_header(&self) -> Option<&str> {
        self.header("From")
    }

    /// Return the value of the `To` header, if present.
    pub fn to_header(&self) -> Option<&str> {
        self.header("To")
    }

    /// Return values of all `Via` headers in message order.
    pub fn via_headers(&self) -> Vec<&str> {
        self.headers_by_name("Via")
    }

    /// Return the `branch` parameter of the topmost `Via` header, if present.
    ///
    /// This is the RFC 3261 transaction identifier: two messages with the
    /// same Call-ID/CSeq but different top-Via branches belong to distinct
    /// transactions. An empty `branch=` value is treated as absent.
    pub fn top_via_branch(&self) -> Option<&str> {
        let via = *self.via_headers().first()?;
        for param in via.split(';').skip(1) {
            let param = param.trim();
            let (name, value) = match param.split_once('=') {
                Some((n, v)) => (n.trim_end(), v.trim()),
                None => continue,
            };
            if name.eq_ignore_ascii_case("branch") {
                return if value.is_empty() { None } else { Some(value) };
            }
        }
        None
    }

    /// Parse the `CSeq` header into its sequence number and method.
    ///
    /// Returns `None` if the header is missing or malformed.
    /// The method string borrows from the header value (zero allocation).
    pub fn cseq(&self) -> Option<(u32, &str)> {
        let val = self.header("CSeq")?;
        // RFC 3261: CSeq = 1*DIGIT LWS Method, where Method is a single
        // token. Take the first two whitespace-separated tokens and ignore
        // any trailing garbage (e.g. "1 INVITE extra") so method comparisons
        // in timing.rs are not defeated.
        let mut parts = val.split_whitespace();
        let num: u32 = parts.next()?.parse().ok()?;
        let method = parts.next()?;
        Some((num, method))
    }

    /// Return the `User-Agent` header value, falling back to `Server`.
    pub fn user_agent(&self) -> Option<&str> {
        self.header("User-Agent").or_else(|| self.header("Server"))
    }

    /// Return the value of the `Content-Type` header, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.header("Content-Type")
    }

    /// Parse the SDP body, if the `Content-Type` is `application/sdp`.
    ///
    /// Returns `None` if the content type is not SDP or if parsing fails.
    pub fn sdp(&self) -> Option<SdpSession> {
        if self
            .content_type()
            .map(|ct| ct.contains("application/sdp"))
            .unwrap_or(false)
        {
            sdp::parse_sdp(&self.body).ok()
        } else {
            None
        }
    }

    /// Return the value of the `Contact` header, if present.
    pub fn contact(&self) -> Option<&str> {
        self.header("Contact")
    }

    /// Look up a header by name (case-insensitive). Returns the first match.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Return all header values matching `name` (case-insensitive).
    pub fn headers_by_name(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Detect structural malformations (SNB-0003, spec §5.2): defects that make
    /// this a crafted/broken message rather than valid SIP. Returns a list of
    /// human-readable reasons (empty for a well-formed message). The doctrine is
    /// "detect & highlight" — surface the anomaly, never silently accept it.
    ///
    /// Checks: missing mandatory headers (`Call-ID`/`CSeq`/`From`/`To`/`Via`,
    /// RFC 3261 §8.1.1/§8.2), an unparseable `CSeq`, a `Content-Length` larger
    /// than the body actually present (truncated/lying length), and control/NUL
    /// bytes in a header name or value (injection / parser-abuse). Tab (LWS) is
    /// allowed; CR/LF cannot survive line parsing.
    pub fn malformations(&self) -> Vec<String> {
        let mut reasons = Vec::new();

        for (name, present) in [
            ("Call-ID", self.header("Call-ID").is_some()),
            ("CSeq", self.header("CSeq").is_some()),
            ("From", self.header("From").is_some()),
            ("To", self.header("To").is_some()),
            ("Via", !self.via_headers().is_empty()),
        ] {
            if !present {
                reasons.push(format!("missing mandatory header: {name}"));
            }
        }

        if self.header("CSeq").is_some() && self.cseq().is_none() {
            reasons.push("malformed CSeq header (not '<number> <method>')".to_string());
        }

        if let Some(declared) = self
            .header("Content-Length")
            .and_then(|v| v.trim().parse::<usize>().ok())
            && declared > self.body.len()
        {
            reasons.push(format!(
                "content-length mismatch: declared {declared}, body {} bytes present",
                self.body.len()
            ));
        }

        for h in &self.headers {
            if has_control_bytes(&h.name) || has_control_bytes(&h.value) {
                reasons.push(format!("control character in header: {}", h.name));
            }
        }

        reasons
    }

    /// Extract the user part from the `From` URI.
    ///
    /// For `From: "Alice" <sip:1001@example.com>;tag=abc` returns `Some("1001")`.
    pub fn from_user(&self) -> Option<String> {
        extract_uri_user(self.from_header()?)
    }

    /// Extract the user part from the `To` URI.
    ///
    /// For `To: <sip:1002@example.com>` returns `Some("1002")`.
    ///
    /// **Naming note:** the `to_*` accessors (`to_user`, `to_host`,
    /// `to_tag`, `to_display`) read the SIP **`To:` header** — they are
    /// cheap field accessors named for symmetry with `from_user` etc.,
    /// not `to_`-prefixed conversions in the Rust API-guidelines sense.
    pub fn to_user(&self) -> Option<String> {
        extract_uri_user(self.to_header()?)
    }

    /// Extract the host (with optional `:port`) from the `From` URI.
    ///
    /// For `From: <sip:1001@example.com:5060>;tag=abc` returns
    /// `Some("example.com:5060")`. Returns `None` for URIs without a host
    /// (e.g. `tel:`).
    pub fn from_host(&self) -> Option<String> {
        extract_uri_host_port(self.from_header()?)
    }

    /// Extract the host (with optional `:port`) from the `To` URI.
    pub fn to_host(&self) -> Option<String> {
        extract_uri_host_port(self.to_header()?)
    }

    /// Extract the `tag` parameter from the `From` header.
    pub fn from_tag(&self) -> Option<&str> {
        extract_tag(self.from_header()?)
    }

    /// Extract the `tag` parameter from the `To` header.
    pub fn to_tag(&self) -> Option<&str> {
        extract_tag(self.to_header()?)
    }

    /// Extract the display name from the `From` header.
    ///
    /// For `From: "Alice" <sip:1001@example.com>;tag=abc` returns `Some("Alice")`.
    /// For `From: <sip:1001@example.com>;tag=abc` returns `None`.
    pub fn from_display(&self) -> Option<String> {
        extract_display_name(self.from_header()?)
    }

    /// Extract the display name from the `To` header.
    ///
    /// For `To: "Bob" <sip:1002@example.com>` returns `Some("Bob")`.
    pub fn to_display(&self) -> Option<String> {
        extract_display_name(self.to_header()?)
    }
}

/// True if `s` contains a C0 control byte or DEL — excluding tab (`\t`), which
/// is legal linear whitespace in a header value. CR/LF never survive line
/// parsing, so their presence here would also be anomalous.
fn has_control_bytes(s: &str) -> bool {
    s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// Extract the user part from a SIP URI inside a header value.
///
/// Handles both `<sip:user@host>` and bare `sip:user@host` forms (RFC 3261 § 20.20).
/// Returns `None` when no `sip:`/`sips:` URI is found, when the URI has no
/// `@` (host-only), or when the user part is empty.
pub(crate) fn extract_uri_user(header_value: &str) -> Option<String> {
    // The addressable URI is inside <...> for the name-addr form, otherwise
    // the (trimmed) value up to the first header parameter is the bare
    // addr-spec. A quoted/token display name must NEVER be scanned for the
    // user, so a crafted `"sip:evil@x"` display name cannot spoof it.
    let uri = match header_value.find('<') {
        Some(lt) => {
            let rest = &header_value[lt + 1..];
            let gt = rest.find('>')?;
            &rest[..gt]
        }
        None => header_value.trim().split(';').next().unwrap_or("").trim(),
    };

    // The URI must itself be a sip/sips addr-spec (not tel:, etc.).
    let after_scheme = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?;

    // User part ends at '@'.
    let at_pos = after_scheme.find('@')?;
    let user = &after_scheme[..at_pos];

    if user.is_empty() {
        return None;
    }
    Some(user.to_string())
}

/// Extract the host (with optional `:port`) from a SIP URI inside a header value.
///
/// Handles `<sip:user@host:port;params>`, bare `sip:host`, and bracketed IPv6
/// hosts (`sip:user@[2001:db8::1]:5060`). Returns `None` for non-SIP URIs (e.g.
/// `tel:`) or when no host is present (RFC 3261 § 19.1).
fn extract_uri_host_port(header_value: &str) -> Option<String> {
    let scheme_pos = header_value
        .find("<sip:")
        .or_else(|| header_value.find("<sips:"))
        .or_else(|| header_value.find("sip:"))
        .or_else(|| header_value.find("sips:"))?;

    let after_scheme = &header_value[scheme_pos..];
    // Skip past the scheme name to just after its ':'.
    let colon_pos = after_scheme.find(':')?;
    let mut rest = &after_scheme[colon_pos + 1..];

    // Drop the userinfo (everything up to and including the first '@'). Hosts
    // never contain '@', and IPv6 literals are bracketed, so this is safe.
    if let Some(at) = rest.find('@') {
        rest = &rest[at + 1..];
    }

    // host[:port] ends at the first URI delimiter: ';' (uri-parameters), '>'
    // (end of angle form), '?' (headers), ',' (next header value), or
    // whitespace. ':' is left intact so it can carry the port (and IPv6 colons).
    let end = rest
        .find(|c: char| matches!(c, ';' | '>' | '?' | ',') || c.is_whitespace())
        .unwrap_or(rest.len());
    let host_port = rest[..end].trim();

    if host_port.is_empty() {
        return None;
    }
    Some(host_port.to_string())
}

/// Extract the display name from a SIP From/To header value.
///
/// Handles both quoted forms (`"Alice" <sip:...>`) and bare token forms
/// (`Alice <sip:...>`). Returns `None` if no display name is present.
fn extract_display_name(header_value: &str) -> Option<String> {
    let trimmed = header_value.trim();

    // Quoted display name: "Name" <sip:...>
    if let Some(after_quote) = trimmed.strip_prefix('"') {
        let end_quote = after_quote.find('"')?;
        let name = &after_quote[..end_quote];
        if name.is_empty() {
            return None;
        }
        return Some(name.to_string());
    }

    // Bare token display name: Name <sip:...>
    if let Some(angle_pos) = trimmed.find('<') {
        let before_angle = trimmed[..angle_pos].trim();
        if !before_angle.is_empty() {
            return Some(before_angle.to_string());
        }
    }

    None
}

/// Extract the `tag=` parameter from a From/To header value.
///
/// Searches after the closing `>` when present so URI parameters inside the
/// angle brackets are not mistaken for the header-level tag. Returns a
/// borrow of the tag value, or `None` when no non-empty `;tag=` follows.
fn extract_tag(header_value: &str) -> Option<&str> {
    // The tag parameter appears after a semicolon outside angle brackets.
    // Find the closing '>' first (if present), then look for ";tag=".
    let search_from = header_value.find('>').unwrap_or(0);
    let remainder = &header_value[search_from..];

    let tag_prefix = ";tag=";
    let tag_start = remainder.find(tag_prefix)?;
    let value_start = tag_start + tag_prefix.len();
    let value = &remainder[value_start..];

    // Tag value ends at next ';', ',', or end of string
    let end = value.find([';', ',']).unwrap_or(value.len());
    let tag = value[..end].trim();

    if tag.is_empty() {
        return None;
    }
    Some(tag)
}

/// Tests for malformation detection, URI user/host/tag/display extraction,
/// and top-Via branch parsing.
#[cfg(test)]
mod tests {
    use super::*;

    // ── malformation detection (SNB-0003, spec §5.2) ───────────────────
    /// Fixed capture timestamp (2024-06-15 12:00:00 UTC) used in tests.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Build and parse a SIP message from a first line, headers, and body,
    /// with localhost/UDP capture metadata.
    fn parse_msg(first: &str, headers: &[&str], body: &[u8]) -> SipMessage {
        let raw = crate::test_utils::build_sip_message(first, headers, body);
        let lo = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        crate::sip::parser::parse_sip(&raw, ts(), lo, lo, 5060, 5060, TransportProto::Udp)
            .expect("should parse")
    }

    /// A complete, well-formed OPTIONS request.
    fn well_formed() -> SipMessage {
        parse_msg(
            "OPTIONS sip:a@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: ok@example.com",
                "CSeq: 1 OPTIONS",
                "Content-Length: 0",
            ],
            b"",
        )
    }

    /// `cseq()` returns only the single method token per RFC 3261, dropping
    /// any trailing garbage after it (e.g. `1 INVITE extra` → method
    /// `INVITE`), so downstream method comparisons in timing.rs still match.
    #[test]
    fn cseq_method_is_single_token() {
        let msg = parse_msg(
            "INVITE sip:b@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK9",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: cseq@example.com",
                "CSeq: 1 INVITE extra",
                "Content-Length: 0",
            ],
            b"",
        );
        assert_eq!(msg.cseq(), Some((1, "INVITE")));
    }

    /// A complete OPTIONS request reports zero malformations.
    #[test]
    fn well_formed_has_no_malformations() {
        assert!(well_formed().malformations().is_empty());
    }

    /// An INVITE with a correct SDP body triggers no false positives.
    #[test]
    fn well_formed_invite_with_sdp_no_false_positive() {
        let sdp = b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
        let msg = parse_msg(
            "INVITE sip:b@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK2",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: invite@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", sdp.len()),
            ],
            sdp,
        );
        assert!(
            msg.malformations().is_empty(),
            "got {:?}",
            msg.malformations()
        );
    }

    /// Dropping any of the five mandatory headers flags that header by name.
    #[test]
    fn missing_mandatory_headers_flagged() {
        for drop in ["Call-ID", "CSeq", "From", "To", "Via"] {
            let hdrs: Vec<&str> = [
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: x@example.com",
                "CSeq: 1 OPTIONS",
                "Content-Length: 0",
            ]
            .into_iter()
            .filter(|h| !h.starts_with(drop))
            .collect();
            let msg = parse_msg("OPTIONS sip:a@example.com SIP/2.0", &hdrs, b"");
            let m = msg.malformations();
            assert!(
                m.iter().any(|r| r.contains(drop)),
                "dropping {drop} should flag it; got {m:?}"
            );
        }
    }

    /// A Content-Length larger than the actual body is flagged.
    #[test]
    fn lying_content_length_flagged() {
        // declares 500 bytes, datagram carries none → truncated/lying length.
        let msg = parse_msg(
            "OPTIONS sip:a@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: cl@example.com",
                "CSeq: 1 OPTIONS",
                "Content-Length: 500",
            ],
            b"",
        );
        let m = msg.malformations();
        assert!(m.iter().any(|r| r.contains("content-length")), "got {m:?}");
    }

    /// An embedded NUL byte in a header value is flagged as a control char.
    #[test]
    fn nul_in_header_value_flagged() {
        let msg = parse_msg(
            "OPTIONS sip:a@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
                "From: <sip:a@example.com>;tag=1\u{0}BAD",
                "To: <sip:b@example.com>",
                "Call-ID: nul@example.com",
                "CSeq: 1 OPTIONS",
                "Content-Length: 0",
            ],
            b"",
        );
        let m = msg.malformations();
        assert!(
            m.iter().any(|r| r.to_lowercase().contains("control")),
            "embedded NUL must be flagged; got {m:?}"
        );
    }

    /// A non-numeric CSeq sequence number is flagged as malformed.
    #[test]
    fn malformed_cseq_flagged() {
        let msg = parse_msg(
            "OPTIONS sip:a@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: badcseq@example.com",
                "CSeq: not-a-number OPTIONS",
                "Content-Length: 0",
            ],
            b"",
        );
        let m = msg.malformations();
        assert!(
            m.iter().any(|r| r.to_lowercase().contains("cseq")),
            "got {m:?}"
        );
    }

    /// A tab inside a header value is legal LWS and not flagged.
    #[test]
    fn tab_in_header_value_is_not_flagged() {
        // a tab is legal linear whitespace inside a header value (not a control bug)
        let msg = parse_msg(
            "OPTIONS sip:a@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: tab@example.com",
                "CSeq: 1 OPTIONS",
                "User-Agent: my\tagent",
                "Content-Length: 0",
            ],
            b"",
        );
        assert!(
            msg.malformations().is_empty(),
            "tab is LWS, not malformed; got {:?}",
            msg.malformations()
        );
    }

    /// A quoted display name containing a fake `sip:` URI must not be parsed
    /// as the user: the addressable URI here is `tel:`, so there is no SIP
    /// user, and the display name's `sip:evil@…` must be ignored.
    #[test]
    fn extract_user_ignores_spoofed_display_name() {
        assert_eq!(
            extract_uri_user(r#""sip:evil@attacker.com" <tel:+15551234>"#),
            None
        );
        // With a real sip URI present, the angle-bracket URI wins over a
        // spoofed display-name URI.
        assert_eq!(
            extract_uri_user(r#""sip:evil@attacker.com" <sip:real@example.com>"#),
            Some("real".to_string())
        );
    }

    /// User part is extracted despite a quoted display name.
    #[test]
    fn extract_user_with_display_name() {
        assert_eq!(
            extract_uri_user(r#""Alice" <sip:1001@example.com>;tag=abc"#),
            Some("1001".to_string())
        );
    }

    /// User part is extracted from a plain angle-bracket URI.
    #[test]
    fn extract_user_no_display_name() {
        assert_eq!(
            extract_uri_user("<sip:1002@example.com>"),
            Some("1002".to_string())
        );
    }

    /// The `sips:` scheme is handled like `sip:`.
    #[test]
    fn extract_user_sips() {
        assert_eq!(
            extract_uri_user("<sips:secure@example.com>"),
            Some("secure".to_string())
        );
    }

    /// A host-only URI (no `@`) yields no user part.
    #[test]
    fn extract_user_no_at() {
        assert_eq!(extract_uri_user("<sip:example.com>"), None);
    }

    /// A simple `;tag=` parameter after the URI is extracted.
    #[test]
    fn extract_tag_present() {
        assert_eq!(
            extract_tag("<sip:1001@example.com>;tag=abc123"),
            Some("abc123")
        );
    }

    /// The tag value stops at the next `;` when other params follow.
    #[test]
    fn extract_tag_with_other_params() {
        assert_eq!(
            extract_tag("<sip:1001@example.com>;tag=abc;other=xyz"),
            Some("abc")
        );
    }

    /// A header with no `;tag=` yields `None`.
    #[test]
    fn extract_tag_absent() {
        assert_eq!(extract_tag("<sip:1001@example.com>"), None);
    }

    // ── Bare URI extraction (no angle brackets) ────────────────────────

    /// A bare `sip:` URI without angle brackets yields the user part.
    #[test]
    fn extract_user_bare_sip_uri() {
        assert_eq!(
            extract_uri_user("sip:alice@example.com"),
            Some("alice".to_string())
        );
    }

    /// A bare `sips:` URI without angle brackets yields the user part.
    #[test]
    fn extract_user_bare_sips_uri() {
        assert_eq!(
            extract_uri_user("sips:bob@example.com"),
            Some("bob".to_string())
        );
    }

    /// Angle-bracket form continues to work alongside bare-URI support.
    #[test]
    fn extract_user_angle_bracket_still_works() {
        assert_eq!(
            extract_uri_user("<sip:charlie@host>"),
            Some("charlie".to_string())
        );
    }

    /// A bare-token display name before the URI does not confuse extraction.
    #[test]
    fn extract_user_display_name_with_uri() {
        assert_eq!(
            extract_uri_user("Alice <sip:alice@host>"),
            Some("alice".to_string())
        );
    }

    // ── extract_uri_host_port ────────────────────────────────────────

    /// Host and port are extracted past a display name and userinfo.
    #[test]
    fn host_port_with_user_and_port() {
        assert_eq!(
            extract_uri_host_port(r#""Alice" <sip:1001@example.com:5060>;tag=abc"#),
            Some("example.com:5060".to_string())
        );
    }

    /// A URI without a port yields just the host.
    #[test]
    fn host_port_no_port() {
        assert_eq!(
            extract_uri_host_port("<sip:1002@example.com>"),
            Some("example.com".to_string())
        );
    }

    /// A URI without userinfo yields host:port directly.
    #[test]
    fn host_port_no_user() {
        // A URI with no userinfo (e.g. a registrar/domain target).
        assert_eq!(
            extract_uri_host_port("<sip:example.com:5061>"),
            Some("example.com:5061".to_string())
        );
    }

    /// A bracketed IPv6 host with port survives intact.
    #[test]
    fn host_port_ipv6_bracketed_with_port() {
        assert_eq!(
            extract_uri_host_port("<sip:bob@[2001:db8::1]:5060>;transport=udp"),
            Some("[2001:db8::1]:5060".to_string())
        );
    }

    /// A bracketed IPv6 host without a port survives intact.
    #[test]
    fn host_port_ipv6_no_port() {
        assert_eq!(
            extract_uri_host_port("<sip:[2001:db8::1]>"),
            Some("[2001:db8::1]".to_string())
        );
    }

    /// URI parameters (`;transport=...;lr`) are stripped from the host:port.
    #[test]
    fn host_port_strips_uri_params() {
        assert_eq!(
            extract_uri_host_port("<sip:1001@10.0.0.1:5060;transport=tcp;lr>"),
            Some("10.0.0.1:5060".to_string())
        );
    }

    /// Bare `sip:`/`sips:` URIs (no angle brackets) yield host:port.
    #[test]
    fn host_port_bare_uri() {
        assert_eq!(
            extract_uri_host_port("sip:alice@host.example:5070"),
            Some("host.example:5070".to_string())
        );
        assert_eq!(
            extract_uri_host_port("sips:bob@secure.example"),
            Some("secure.example".to_string())
        );
    }

    /// A `tel:` URI has no host and yields `None`.
    #[test]
    fn host_port_tel_uri_has_no_host() {
        // tel: URIs carry no host — fall back to None (caller shows user or '-').
        assert_eq!(extract_uri_host_port("<tel:+15551234567>"), None);
    }

    /// Empty, non-URI, and backslash-laden inputs never panic.
    #[test]
    fn host_port_empty_or_garbage() {
        assert_eq!(extract_uri_host_port(""), None);
        assert_eq!(extract_uri_host_port("not a uri at all"), None);
        // Backslash / odd chars must not panic.
        assert_eq!(
            extract_uri_host_port(r"<sip:a\b@ho\st>"),
            Some(r"ho\st".to_string())
        );
    }

    // ── top_via_branch (RFC 3261 transaction identity) ─────────────────

    /// Build an OPTIONS request carrying the given Via header lines.
    fn msg_with_vias(vias: &[&str]) -> SipMessage {
        let mut headers: Vec<&str> = vias.to_vec();
        headers.extend([
            "From: <sip:a@example.com>;tag=1",
            "To: <sip:b@example.com>",
            "Call-ID: via-branch@test",
            "CSeq: 1 OPTIONS",
            "Content-Length: 0",
        ]);
        parse_msg("OPTIONS sip:b@example.com SIP/2.0", &headers, b"")
    }

    /// A single Via with a branch param yields that branch.
    #[test]
    fn top_via_branch_basic() {
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.abc"]);
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.abc"));
    }

    /// Only the topmost Via's branch is returned when several are present.
    #[test]
    fn top_via_branch_takes_first_via_only() {
        let m = msg_with_vias(&[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.top",
            "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK.below",
        ]);
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.top"));
    }

    /// Extra params and loose spacing around `;` do not break extraction.
    #[test]
    fn top_via_branch_more_params_and_spacing() {
        let m =
            msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060 ; rport ; branch=z9hG4bK.x ; alias"]);
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.x"));
    }

    /// The `branch` parameter name matches case-insensitively.
    #[test]
    fn top_via_branch_param_name_case_insensitive() {
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;BRANCH=z9hG4bK.up"]);
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.up"));
    }

    /// A compact `v:` Via still yields the top branch after expansion.
    #[test]
    fn top_via_branch_compact_form() {
        // Parser expands compact `v:` to `Via`.
        let m = parse_msg(
            "OPTIONS sip:b@example.com SIP/2.0",
            &[
                "v: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.compact",
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: via-compact@test",
                "CSeq: 1 OPTIONS",
                "Content-Length: 0",
            ],
            b"",
        );
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.compact"));
    }

    /// Missing Via, missing/empty branch, prefix params, and adversarial
    /// quoting all behave as specified (None or literal pass-through).
    #[test]
    fn top_via_branch_absent_or_degenerate() {
        // No Via at all.
        let m = parse_msg(
            "OPTIONS sip:b@example.com SIP/2.0",
            &[
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.com>",
                "Call-ID: via-none@test",
                "CSeq: 1 OPTIONS",
                "Content-Length: 0",
            ],
            b"",
        );
        assert_eq!(m.top_via_branch(), None);
        // Via without a branch param (RFC 2543 style).
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060"]);
        assert_eq!(m.top_via_branch(), None);
        // Empty branch value → treated as absent.
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;branch="]);
        assert_eq!(m.top_via_branch(), None);
        // `branch` as a prefix of another param must not match.
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;branchx=nope"]);
        assert_eq!(m.top_via_branch(), None);
        // Adversarial: backslashes and quotes must not panic and pass through.
        let m = msg_with_vias(&[r#"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9\"h4bK"#]);
        assert_eq!(m.top_via_branch(), Some(r#"z9\"h4bK"#));
    }
}
