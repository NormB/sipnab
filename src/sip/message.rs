// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! SIP message type and header accessors.
//!
//! [`SipMessage`] holds a fully parsed SIP message with all headers extracted
//! and normalized. Accessor methods provide convenient typed access to
//! commonly used headers.

use std::borrow::Cow;
use std::net::IpAddr;
use std::ops::Range;

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
    /// Byte range of the logical header line within [`SipMessage::raw`], from
    /// the first byte of the name to the last byte of the value, CRLF
    /// excluded. A folded header spans every line it was folded from, so the
    /// range covers bytes the unfolded `value` does not reproduce verbatim.
    ///
    /// Recorded by the parser as it walks, which is the whole point: a range
    /// derived by a SECOND walk of the same grammar can part company with the
    /// parse — over a line with no colon, a non-UTF-8 line, an over-long one,
    /// or the per-message header cap — and a range pinned one header early
    /// still resolves, so it reads as evidence.
    ///
    /// `None` for a header that came from no bytes: synthesized in a test, or
    /// built by a transform. A range invented for one of those would point at
    /// bytes that never said it.
    pub line_span: Option<Range<u32>>,
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
    pub parse_error: bool,
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
    /// Pointer back to the frame this message was parsed out of.
    ///
    /// This is where provenance stops being an idea about packets and starts
    /// being usable: every dialog, diagnosis, lint finding and report is built
    /// from `SipMessage`, so a message that knows its frame lets each of those
    /// say which bytes it came from. Without it, the pointer that
    /// `ParsedPacket` carries dies at the SIP parse boundary and every fact
    /// downstream is an assertion again.
    ///
    /// `None` for a message that came from no frame — hand-built in a test, or
    /// reassembled from a source that could not number its frames. Downstream
    /// must report the absence rather than substitute a neighboring frame:
    /// naming the wrong bytes is the failure this whole mechanism exists to
    /// prevent.
    pub frame: Option<crate::capture::packet::FrameRef>,
    /// The DSCP the frame carrying this message was marked with.
    ///
    /// Signaling and media are marked separately and frequently disagree —
    /// the classic fault is media marked `EF` while `INVITE`s go out
    /// unmarked, so call setup queues behind bulk traffic on a congested link
    /// and post-dial delay climbs while every media metric stays clean. That
    /// question is unanswerable without the byte, and until this field existed
    /// sipnab discarded it at the parse.
    ///
    /// Attached by the capture pipeline, not by the parser: `parse_sip_bytes`
    /// takes bytes and addressing and has no business knowing about IP
    /// headers, exactly as with [`frame`](Self::frame). `None` means no IP
    /// header was observed (a HEP-fed message, or one built by hand), which is
    /// a different fact from `Some(0)` — 0 is the default PHB, a real and
    /// frequently wrong marking.
    pub dscp: Option<u8>,
    /// Which capture source delivered this message.
    ///
    /// `ParsedPacket` has carried this since scanner-kill needed it, and it
    /// died at the SIP parse boundary: the only consumer was the transmit
    /// gate, and `grep -rn input_origin src/sip/ src/rtp/ src/output/` found
    /// nothing but test fixtures. In a single-source run that cost nothing,
    /// because the answer was the same for every packet.
    ///
    /// It stops being free the moment two sources feed one process. HEP
    /// reports what the proxy BELIEVES it did and the wire reports what
    /// actually left the box; when those disagree the disagreement is the
    /// finding, and a disagreement between two facts is only visible once each
    /// fact knows where it came from. Per MESSAGE rather than per run for the
    /// same reason: a mixed run has no run-level answer.
    ///
    /// `None` for a message that came from no captured packet — hand-built in
    /// a test, or synthesized for a report. Deliberately not defaulted to
    /// `Wire`: "sipnab saw this on a wire" is a claim, and a synthetic message
    /// must not make it.
    pub input_origin: Option<crate::capture::parse::InputOrigin>,
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
        let row = *self.via_headers().first()?;
        // The TOP Via is the first via-parm, not the first ROW. RFC 3261
        // §20.42 makes `Via` a comma-separated list and §7.3.1 lets any number
        // of rows be combined into one, so a single row may hold several hops
        // — and reading the whole row returned a later hop's branch, or a
        // slice running from one branch through the next hop.
        let via = row.split(',').next()?;
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

    /// Whether this message carries an SDP body: the one rule every label and
    /// flag that says "(SDP)" reads.
    ///
    /// - `application/sdp` in any case, with any parameters.
    /// - A `multipart/*` body (SIPREC, SIP-I) with an `application/sdp` part.
    /// - A body with no `Content-Type` at all that starts `v=`. RFC 3261
    ///   section 20.15 requires the header on a body; a peer that omits it on
    ///   SDP is still labeled. A body declared as another type is that type.
    #[must_use]
    pub fn carries_sdp(&self) -> bool {
        match self.content_type() {
            Some(ct) if is_sdp_media_type(ct) => true,
            Some(ct) if is_multipart_media_type(ct) => !sdp_parts(ct, &self.body).is_empty(),
            Some(_) => false,
            None => self.body.starts_with(b"v="),
        }
    }

    /// The message's label on every surface that shows one: the method of a
    /// request, the status code and reason of a response, then ` (SDP)` when
    /// [`Self::carries_sdp`].
    ///
    /// A response with no reason phrase is its code alone; a message whose
    /// method or status code was not parsed is `request` or `response`.
    #[must_use]
    pub fn label(&self) -> String {
        let head = if self.is_request {
            self.method
                .as_ref()
                .map_or_else(|| "request".to_string(), ToString::to_string)
        } else {
            match (self.status_code, self.reason.as_deref()) {
                (Some(code), Some(reason)) if !reason.is_empty() => format!("{code} {reason}"),
                (Some(code), _) => code.to_string(),
                (None, _) => "response".to_string(),
            }
        };
        if self.carries_sdp() {
            format!("{head} (SDP)")
        } else {
            head
        }
    }

    /// Parse the message's SDP: the whole body when the `Content-Type` is
    /// `application/sdp`, or the first `application/sdp` part that parses
    /// when it is `multipart/*`, as in a SIP-I message,
    /// whose SDP sits beside an ISUP part
    /// ([RFC 3204 section 4.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-4.1)),
    /// or a SIPREC one, whose SDP sits beside the recording metadata
    /// ([RFC 7866 section 9.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-9.1)).
    ///
    /// A body with no `Content-Type` that starts `v=` is read as SDP, by the
    /// rule [`Self::carries_sdp`] labels it with, so a message labeled `(SDP)`
    /// is never one whose media is ignored.
    ///
    /// Returns `None` if the body holds no SDP or if parsing fails.
    pub fn sdp(&self) -> Option<SdpSession> {
        match self.content_type() {
            Some(ct) if is_sdp_media_type(ct) => sdp::parse_sdp(&self.body).ok(),
            Some(ct) if is_multipart_media_type(ct) => multipart_sdp(ct, &self.body),
            Some(_) => None,
            None if self.body.starts_with(b"v=") => sdp::parse_sdp(&self.body).ok(),
            None => None,
        }
    }

    /// Whether this message's SDP can set up a media session, by
    /// [`sdp::sdp_sets_up_media`]. A request is judged by its method, a
    /// response by its `CSeq` method and status code. `false` when neither
    /// is known.
    #[must_use]
    pub fn sdp_sets_up_media(&self) -> bool {
        if self.is_request {
            self.method
                .as_ref()
                .is_some_and(|method| sdp::sdp_sets_up_media(method, None))
        } else {
            self.cseq().is_some_and(|(_, method)| {
                sdp::sdp_sets_up_media(&SipMethod::parse(method), self.status_code)
            })
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

    /// Detect structural malformations (backlog item SNB-0003, section 5.2 of
    /// its spec, which is not in this repository): defects that make
    /// this a crafted/broken message rather than valid SIP. Returns a list of
    /// human-readable reasons (empty for a well-formed message). The doctrine is
    /// "detect & highlight" — surface the anomaly, never silently accept it.
    ///
    /// Checks: missing mandatory headers (`Call-ID`/`CSeq`/`From`/`To`/`Via`,
    /// [RFC 3261 section 8.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1)/[RFC 3261 section 8.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.2)), an unparseable `CSeq`, a `Content-Length` larger
    /// than the body actually present (truncated/lying length), and control/NUL
    /// bytes in a header name or value (injection / parser-abuse). Tab (LWS) is
    /// allowed; CR/LF cannot survive line parsing.
    /// The wording is a documented `--json` output format and is unchanged.
    /// The *detection* now lives once, in
    /// [`crate::sip::lint::message`], where the conformance rules read the same
    /// predicates — two detectors for one defect is one detector too many, and
    /// the day they disagreed neither would be trustworthy. For structured
    /// findings with an RFC citation attached, use
    /// [`crate::sip::lint::Linter::lint_message`].
    pub fn malformations(&self) -> Vec<String> {
        super::lint::malformation_reasons(self)
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

    /// The `From` URI as written: the addr-spec without the display name or
    /// the header's own parameters (`tag`), URI parameters kept.
    pub fn from_uri(&self) -> Option<String> {
        non_empty(addr_spec(self.from_header()?))
    }

    /// The `To` URI as written, as [`Self::from_uri`] reads `From`.
    pub fn to_uri(&self) -> Option<String> {
        non_empty(addr_spec(self.to_header()?))
    }

    /// The user part of the `P-Asserted-Identity` URI
    /// ([RFC 3325](https://www.rfc-editor.org/rfc/rfc3325.html)), from its first
    /// value when the header lists several.
    pub fn pai_user(&self) -> Option<String> {
        extract_uri_user(self.header("P-Asserted-Identity")?)
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

/// Strip a leading quoted display name, returning what follows it.
///
/// [RFC 3261 section 25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1): `display-name = *(token LWS) / quoted-string`, and a
/// `quoted-string` may hold any octet except an unescaped `"` — including `<`,
/// `>` and a complete decoy URI, with `\` forming a `quoted-pair`.
///
/// So scanning a raw header value for `<` or `sip:` reads caller-controlled
/// text. `"<sip:evil@attacker.test>" <sip:alice@real.test>` puts a
/// syntactically perfect URI *before* the real one, and a plain `find` returns
/// the decoy: the first textual match is not the addressable URI.
///
/// An unterminated quote yields `""`, not the remainder. A header whose display
/// name never closes has no parseable addr-spec, and returning the tail would
/// resume scanning inside the region this exists to skip.
pub(crate) fn skip_quoted_display_name(header_value: &str) -> &str {
    let trimmed = header_value.trim_start();
    let Some(rest) = trimmed.strip_prefix('"') else {
        return trimmed;
    };
    let mut escaped = false;
    // char_indices, not bytes: a `\` may escape a multi-byte character, and
    // stepping two BYTES past it would slice mid-character and panic — a crash
    // reachable from the same header value this guards.
    for (idx, ch) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            // '"' is one byte, so idx + 1 is always a char boundary.
            '"' => return &rest[idx + 1..],
            _ => {}
        }
    }
    ""
}

/// `s` as an owned string, or `None` when it is empty.
fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Isolate the addr-spec: the URI inside `<...>` for the name-addr form,
/// otherwise the bare addr-spec up to the first header parameter.
///
/// Both [`extract_uri_user`] and [`extract_uri_host_port`] call this. They used
/// to locate the URI two different ways — one anchored on `<`, the other
/// scanning for `sip:` anywhere — and drifted apart exactly as duplicated logic
/// does: the user side was hardened against a decoy and the host side was not,
/// thirty lines below it. One locator is the fix; a second scanner was the bug.
pub(crate) fn addr_spec(header_value: &str) -> &str {
    let value = skip_quoted_display_name(header_value);
    match value.find('<') {
        Some(lt) => {
            let rest = &value[lt + 1..];
            match rest.find('>') {
                Some(gt) => &rest[..gt],
                None => "",
            }
        }
        None => value.trim().split(';').next().unwrap_or("").trim(),
    }
}

/// Extract the user part from a SIP URI inside a header value.
///
/// Handles both `<sip:user@host>` and bare `sip:user@host` forms ([RFC 3261 section 20.20](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.20)).
/// Returns `None` when no `sip:`/`sips:` URI is found, when the URI has no
/// `@` (host-only), or when the user part is empty.
pub(crate) fn extract_uri_user(header_value: &str) -> Option<String> {
    let uri = addr_spec(header_value);

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
/// `tel:`) or when no host is present ([RFC 3261 section 19.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1)).
fn extract_uri_host_port(header_value: &str) -> Option<String> {
    // The SAME isolation extract_uri_user uses. This function used to scan the
    // raw header for a scheme anywhere -- `find("<sip:")`, then three fallbacks
    // ending in a bare `find("sip:")` -- which reads a quoted display name.
    let uri = addr_spec(header_value);

    // The URI must itself be a sip/sips addr-spec (not tel:, etc.).
    let mut rest = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?;

    // Drop the userinfo (everything up to and including the first '@'). Hosts
    // never contain '@', and IPv6 literals are bracketed, so this is safe.
    if let Some(at) = rest.find('@') {
        rest = &rest[at + 1..];
    }

    // host[:port] ends at the first URI delimiter: ';' (uri-parameters, which
    // survive inside the angle form), '?' (headers), ',' (next header value),
    // or whitespace. ':' is left intact so it can carry the port (and IPv6
    // colons). '>' is no longer in this set: `addr_spec` returns what is
    // BETWEEN the brackets, so it cannot appear here.
    let end = rest
        .find(|c: char| matches!(c, ';' | '?' | ',') || c.is_whitespace())
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
        // Scan for the closing quote, honoring `\"` / `\\` quoted-pairs and
        // unescaping them. A naive search for the first `"` truncated a name
        // like "O\"Brien" at the escaped quote (RFC 3261 quoted-string admits
        // `\"` as a literal quote).
        let mut name = String::new();
        let mut chars = after_quote.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        name.push(escaped);
                    }
                }
                '"' => {
                    closed = true;
                    break;
                }
                other => name.push(other),
            }
        }
        if !closed || name.is_empty() {
            return None;
        }
        return Some(name);
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
    // Step over a quoted display name FIRST. RFC 3261 §25.1 puts `>` (%x3E)
    // and `;` (%x3B) inside `qdtext`, so both are legal inside one and neither
    // ends it. Anchoring on the first `>` in the raw value let a sender put
    // `"A>;tag=decoy"` in the display name and choose the tag — and the From
    // tag is half the dialog identifier (§12.1.1), so that is a correlation
    // spoofing primitive rather than a cosmetic miss.
    let after_display = skip_quoted_display_name(header_value);
    // Header parameters begin after the addr-spec. Everything between `<` and
    // `>` is URI parameters (§25.1 `SIP-URI = ... uri-parameters [headers]`),
    // which are not header parameters and must not be searched.
    let remainder = match after_display.find('>') {
        Some(close) => &after_display[close + 1..],
        None => after_display,
    };

    // `SEMI = SWS ";" SWS` and `EQUAL = SWS "=" SWS`, and §7.3.1 makes the
    // parameter NAME case-insensitive — so the literal `";tag="` this used to
    // search for matched only one of the conformant spellings.
    for param in remainder.split(';').skip(1) {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("tag") {
            continue;
        }
        // A value ends at the next COMMA, which separates header values.
        let end = value.find(',').unwrap_or(value.len());
        let tag = value[..end].trim();
        if tag.is_empty() {
            return None;
        }
        return Some(tag);
    }
    None
}

/// Tests for malformation detection, URI user/host/tag/display extraction,
/// and top-Via branch parsing.
/// The media type of a `Content-Type` value: what precedes the first `;`,
/// trimmed.
fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

/// Whether a `Content-Type` value names `application/sdp`. The type and
/// subtype are case-insensitive and parameters do not change the type
/// ([RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1)).
#[must_use]
pub fn is_sdp_media_type(content_type: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case("application/sdp")
}

/// Whether a `Content-Type` value names a `multipart/*` type, in any case
/// ([RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1)).
fn is_multipart_media_type(content_type: &str) -> bool {
    media_type(content_type)
        .get(..10)
        .is_some_and(|t| t.eq_ignore_ascii_case("multipart/"))
}

/// How many levels of `multipart` below a message's own the SDP rule
/// follows. [RFC 5621 section 4.2](https://www.rfc-editor.org/rfc/rfc5621.html#section-4.2)
/// requires parsing nested parts and sets no depth;
/// [section 4.3](https://www.rfc-editor.org/rfc/rfc5621.html#section-4.3) asks a UA to
/// "avoid unnecessarily nesting body parts", and the nested example in
/// [section 4.1](https://www.rfc-editor.org/rfc/rfc5621.html#section-4.1) needs one level. Four is sipnab's
/// bound: room for every shape those sections describe, and a limit on what a
/// hostile body can make the reader do.
pub(crate) const MAX_MULTIPART_DEPTH: usize = 4;

/// The `application/sdp` parts of the multipart `body` under `content_type`,
/// in body order, depth first through nested `multipart` parts to
/// [`MAX_MULTIPART_DEPTH`] levels below this one, split by the same MIME
/// reader the SIPREC metadata uses
/// ([RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1)).
/// Another part may be binary. Empty when the type carries no boundary.
fn sdp_parts(content_type: &str, body: &[u8]) -> Vec<super::siprec::MimePart> {
    let mut found = Vec::new();
    collect_sdp_parts(content_type, body, 0, &mut found);
    found
}

/// [`sdp_parts`] at `depth` levels below the message's own `multipart`.
fn collect_sdp_parts(
    content_type: &str,
    body: &[u8],
    depth: usize,
    found: &mut Vec<super::siprec::MimePart>,
) {
    let Some(boundary) = super::siprec::extract_boundary(content_type) else {
        return;
    };
    for part in super::siprec::split_multipart(body, &boundary) {
        match part.content_type.as_deref() {
            Some(ct) if is_sdp_media_type(ct) => found.push(part),
            Some(ct) if is_multipart_media_type(ct) && depth < MAX_MULTIPART_DEPTH => {
                collect_sdp_parts(ct, &part.body, depth + 1, found);
            }
            _ => {}
        }
    }
}

/// The session description of the multipart `body` under `content_type`: the
/// first `application/sdp` part that parses. The one rule for which part is a
/// multipart message's SDP: [`SipMessage::sdp`] reads it, and so do the
/// SIPREC stream labels ([`super::siprec::labeled_streams`]).
pub(crate) fn multipart_sdp(content_type: &str, body: &[u8]) -> Option<SdpSession> {
    sdp_parts(content_type, body)
        .iter()
        .find_map(|part| sdp::parse_sdp(&part.body).ok())
}

#[cfg(test)]
mod tests {
    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// The TOP Via value is the first via-parm, not the first Via row.
    ///
    /// [RFC 3261 section 20.42](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.42): `Via = ( "Via" / "v" ) HCOLON via-parm *(COMMA
    /// via-parm)`, and §7.3.1 permits multiple rows to be combined into one
    /// comma-separated row without changing the message. So the topmost Via
    /// VALUE may be the first of several inside one row.
    ///
    /// The defect: `top_via_branch` took the whole first row and split it on
    /// `;` only, so on a comma-combined header it returned the SECOND
    /// via-parm's branch — or, when the first carried one, a string running
    /// from the branch through the next via-parm. Everything keyed on the
    /// transaction read that: retransmission detection, scanner and
    /// registration-flood detection, digest-leak detection and three lint
    /// rules.
    #[test]
    fn the_top_via_branch_comes_from_the_first_via_parm() -> Result<(), TestError> {
        // The top via-parm carries no branch; the second one does. Reading the
        // row instead of the value silently borrowed the second's.
        let msg = msg_with_vias(&[
            "Via: SIP/2.0/UDP first.example.com, SIP/2.0/UDP second.example.com;branch=z9hG4bKsecond",
        ])?;
        assert_eq!(
            msg.top_via_branch(),
            None,
            "the top via-parm has no branch, so there is none to report"
        );
        Ok(())
    }

    /// With a branch on the top via-parm, that one is returned whole.
    ///
    /// The other half: splitting on `;` alone also let the returned slice run
    /// past the COMMA into the next via-parm, so the "branch" was not even a
    /// branch value.
    #[test]
    fn the_top_via_branch_stops_at_the_comma() -> Result<(), TestError> {
        let msg = msg_with_vias(&[
            "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bKfirst, SIP/2.0/UDP b.example.com;branch=z9hG4bKsecond",
        ])?;
        assert_eq!(msg.top_via_branch(), Some("z9hG4bKfirst"));
        Ok(())
    }

    /// Separate Via rows are unaffected.
    ///
    /// The regression guard: the ordinary shape, where each hop adds its own
    /// row, must keep returning the first row's branch.
    #[test]
    fn separate_via_rows_still_report_the_first_rows_branch() -> Result<(), TestError> {
        let msg = msg_with_vias(&[
            "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bKtop",
            "Via: SIP/2.0/UDP b.example.com;branch=z9hG4bKnext",
        ])?;
        assert_eq!(msg.top_via_branch(), Some("z9hG4bKtop"));
        Ok(())
    }

    // ── RFC 3261 §7.3.1 / §25.1: the tag parameter ──────────────────────

    /// `; tag = x` is conformant and must yield the tag.
    ///
    /// [RFC 3261 section 25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1): `SEMI = SWS ";" SWS`, `EQUAL = SWS "=" SWS`,
    /// `SWS = [LWS]` — whitespace on either side of both separators is legal
    /// and may be a fold. [RFC 4475 section 3.1.1.1](https://www.rfc-editor.org/rfc/rfc4475.html#section-3.1.1.1) (`wsinv`) carries exactly this
    /// shape and says "All elements should treat this as a well-formed
    /// request".
    ///
    /// The defect: `extract_tag` searched for the byte literal `";tag="`, so
    /// any conformant spacing lost the tag entirely — and the dialog
    /// identifier is Call-ID plus both tags ([RFC 3261 section 12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1)).
    #[test]
    fn a_tag_with_conformant_whitespace_is_found() -> Result<(), TestError> {
        for value in [
            "<sip:alice@example.com>;tag=1928301774",
            "<sip:alice@example.com> ; tag = 1928301774",
            "<sip:alice@example.com>;  tag  =  1928301774",
            "<sip:alice@example.com>;\ttag\t=\t1928301774",
            "<sip:alice@example.com> ;tag= 1928301774",
        ] {
            assert_eq!(
                extract_tag(value),
                Some("1928301774"),
                "SEMI and EQUAL admit SWS: {value:?}"
            );
        }
        Ok(())
    }

    /// The parameter name is case-insensitive.
    ///
    /// [RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1): "field values, parameter names, and parameter values
    /// are case-insensitive", with `ExPiReS` given as the worked example.
    #[test]
    fn the_tag_parameter_name_is_case_insensitive() -> Result<(), TestError> {
        for value in [
            "<sip:alice@example.com>;TAG=abc",
            "<sip:alice@example.com>;Tag=abc",
            "<sip:alice@example.com>;tAg=abc",
        ] {
            assert_eq!(extract_tag(value), Some("abc"), "{value:?}");
        }
        Ok(())
    }

    /// A decoy inside a quoted display name does not become the tag.
    ///
    /// [RFC 3261 section 25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1) puts `>` (%x3E) and `;` (%x3B) inside `qdtext`, so both
    /// are legal within a display name and neither ends it. `extract_tag`
    /// anchored on the first `>` anywhere in the value, including one the
    /// sender wrote inside the quotes — so the caller chose the From tag, and
    /// the From tag is half the dialog identifier. That is a correlation
    /// spoofing primitive, not a cosmetic parse miss.
    ///
    /// `skip_quoted_display_name` already existed for exactly this attack and
    /// was used by `addr_spec`; this function never got it.
    #[test]
    fn a_decoy_in_a_quoted_display_name_is_not_the_tag() -> Result<(), TestError> {
        assert_eq!(
            extract_tag("\"A>;tag=decoy\" <sip:alice@example.com>;tag=realtag"),
            Some("realtag"),
            "the tag after the real addr-spec wins"
        );
        Ok(())
    }

    /// An escaped DQUOTE does not end the display name.
    ///
    /// `quoted-pair = "\\" (%x00-09 / %x0B-0C / %x0E-7F)`, so `\"` is a
    /// literal quote inside the string. [RFC 4475 section 3.1.1.1](https://www.rfc-editor.org/rfc/rfc4475.html#section-3.1.1.1) uses this too.
    #[test]
    fn an_escaped_quote_does_not_end_the_display_name() -> Result<(), TestError> {
        assert_eq!(
            extract_tag("\"J Rosenberg \\\" >;tag=decoy\" <sip:jdrosen@example.com>;tag=98asjd8"),
            Some("98asjd8")
        );
        Ok(())
    }

    /// A parameter merely ENDING in `tag` is not the tag.
    ///
    /// The negative case a substring search gets wrong in the other direction:
    /// `;ttag=` and `;xtag=` contain `tag=` but are different parameters.
    #[test]
    fn a_parameter_whose_name_merely_ends_in_tag_is_not_the_tag() -> Result<(), TestError> {
        assert_eq!(extract_tag("<sip:a@b>;ttag=no"), None);
        assert_eq!(extract_tag("<sip:a@b>;xtag=no;tag=yes"), Some("yes"));
        Ok(())
    }

    /// A bare addr-spec with no angle brackets still yields its tag.
    #[test]
    fn a_bare_addr_spec_still_yields_its_tag() -> Result<(), TestError> {
        assert_eq!(extract_tag("sip:alice@example.com;tag=abc"), Some("abc"));
        Ok(())
    }

    /// No tag means None, not an empty string.
    #[test]
    fn a_header_with_no_tag_has_no_tag() -> Result<(), TestError> {
        assert_eq!(extract_tag("<sip:alice@example.com>"), None);
        assert_eq!(extract_tag("<sip:alice@example.com>;tag="), None);
        Ok(())
    }

    use super::*;

    // ── malformation detection (SNB-0003, spec §5.2) ───────────────────
    /// Fixed capture timestamp (2024-06-15 12:00:00 UTC) used in tests.
    fn ts() -> Result<DateTime<Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
                .single()
                .ok_or("valid fixture timestamp")?,
        )
    }

    /// Build and parse a SIP message from a first line, headers, and body,
    /// with localhost/UDP capture metadata.
    fn parse_msg(first: &str, headers: &[&str], body: &[u8]) -> Result<SipMessage, TestError> {
        let raw = crate::test_utils::build_sip_message(first, headers, body);
        let lo = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        Ok(
            crate::sip::parser::parse_sip(&raw, ts()?, lo, lo, 5060, 5060, TransportProto::Udp)
                .map_err(|e| format!("should parse: {e:?}"))?,
        )
    }

    /// A complete, well-formed OPTIONS request.
    fn well_formed() -> Result<SipMessage, TestError> {
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
    fn cseq_method_is_single_token() -> Result<(), TestError> {
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
        )?;
        assert_eq!(msg.cseq(), Some((1, "INVITE")));
        Ok(())
    }

    /// A complete OPTIONS request reports zero malformations.
    #[test]
    fn well_formed_has_no_malformations() -> Result<(), TestError> {
        assert!(well_formed()?.malformations().is_empty());
        Ok(())
    }

    /// An INVITE with a correct SDP body triggers no false positives.
    #[test]
    fn well_formed_invite_with_sdp_no_false_positive() -> Result<(), TestError> {
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
        )?;
        assert!(
            msg.malformations().is_empty(),
            "got {:?}",
            msg.malformations()
        );
        Ok(())
    }

    /// Dropping any of the five mandatory headers flags that header by name.
    #[test]
    fn missing_mandatory_headers_flagged() -> Result<(), TestError> {
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
            let msg = parse_msg("OPTIONS sip:a@example.com SIP/2.0", &hdrs, b"")?;
            let m = msg.malformations();
            assert!(
                m.iter().any(|r| r.contains(drop)),
                "dropping {drop} should flag it; got {m:?}"
            );
        }
        Ok(())
    }

    /// A Content-Length larger than the actual body is flagged.
    #[test]
    fn lying_content_length_flagged() -> Result<(), TestError> {
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
        )?;
        let m = msg.malformations();
        assert!(m.iter().any(|r| r.contains("content-length")), "got {m:?}");
        Ok(())
    }

    /// An embedded NUL byte in a header value is flagged as a control char.
    #[test]
    fn nul_in_header_value_flagged() -> Result<(), TestError> {
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
        )?;
        let m = msg.malformations();
        assert!(
            m.iter().any(|r| r.to_lowercase().contains("control")),
            "embedded NUL must be flagged; got {m:?}"
        );
        Ok(())
    }

    /// A non-numeric CSeq sequence number is flagged as malformed.
    #[test]
    fn malformed_cseq_flagged() -> Result<(), TestError> {
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
        )?;
        let m = msg.malformations();
        assert!(
            m.iter().any(|r| r.to_lowercase().contains("cseq")),
            "got {m:?}"
        );
        Ok(())
    }

    /// A tab inside a header value is legal LWS and not flagged.
    #[test]
    fn tab_in_header_value_is_not_flagged() -> Result<(), TestError> {
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
        )?;
        assert!(
            msg.malformations().is_empty(),
            "tab is LWS, not malformed; got {:?}",
            msg.malformations()
        );
        Ok(())
    }

    /// A quoted display name containing a fake `sip:` URI must not be parsed
    /// as the user: the addressable URI here is `tel:`, so there is no SIP
    /// user, and the display name's `sip:evil@…` must be ignored.
    #[test]
    fn extract_user_ignores_spoofed_display_name() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user(r#""sip:evil@attacker.test" <tel:+15551234>"#),
            None
        );
        // With a real sip URI present, the angle-bracket URI wins over a
        // spoofed display-name URI.
        assert_eq!(
            extract_uri_user(r#""sip:evil@attacker.test" <sip:real@example.com>"#),
            Some("real".to_string())
        );
        Ok(())
    }

    /// User part is extracted despite a quoted display name.
    #[test]
    fn extract_user_with_display_name() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user(r#""Alice" <sip:1001@example.com>;tag=abc"#),
            Some("1001".to_string())
        );
        Ok(())
    }

    /// A display name with an escaped quote (`\"`) is not truncated at the
    /// escaped quote, and the quoted-pair is unescaped. RFC 3261 quoted-string
    /// admits `\"` as a literal quote inside the name.
    #[test]
    fn extract_display_name_handles_an_escaped_quote() -> Result<(), TestError> {
        assert_eq!(
            extract_display_name(r#""O\"Brien" <sip:ob@example.com>"#),
            Some("O\"Brien".to_string())
        );
        // A plain quoted name is unchanged.
        assert_eq!(
            extract_display_name(r#""Alice" <sip:a@example.com>"#),
            Some("Alice".to_string())
        );
        Ok(())
    }

    /// User part is extracted from a plain angle-bracket URI.
    #[test]
    fn extract_user_no_display_name() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user("<sip:1002@example.com>"),
            Some("1002".to_string())
        );
        Ok(())
    }

    /// The `sips:` scheme is handled like `sip:`.
    #[test]
    fn extract_user_sips() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user("<sips:secure@example.com>"),
            Some("secure".to_string())
        );
        Ok(())
    }

    /// A host-only URI (no `@`) yields no user part.
    #[test]
    fn extract_user_no_at() -> Result<(), TestError> {
        assert_eq!(extract_uri_user("<sip:example.com>"), None);
        Ok(())
    }

    /// A simple `;tag=` parameter after the URI is extracted.
    #[test]
    fn extract_tag_present() -> Result<(), TestError> {
        assert_eq!(
            extract_tag("<sip:1001@example.com>;tag=abc123"),
            Some("abc123")
        );
        Ok(())
    }

    /// The tag value stops at the next `;` when other params follow.
    #[test]
    fn extract_tag_with_other_params() -> Result<(), TestError> {
        assert_eq!(
            extract_tag("<sip:1001@example.com>;tag=abc;other=xyz"),
            Some("abc")
        );
        Ok(())
    }

    /// A header with no `;tag=` yields `None`.
    #[test]
    fn extract_tag_absent() -> Result<(), TestError> {
        assert_eq!(extract_tag("<sip:1001@example.com>"), None);
        Ok(())
    }

    // ── Bare URI extraction (no angle brackets) ────────────────────────

    /// A bare `sip:` URI without angle brackets yields the user part.
    #[test]
    fn extract_user_bare_sip_uri() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user("sip:alice@example.com"),
            Some("alice".to_string())
        );
        Ok(())
    }

    /// A bare `sips:` URI without angle brackets yields the user part.
    #[test]
    fn extract_user_bare_sips_uri() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user("sips:bob@example.com"),
            Some("bob".to_string())
        );
        Ok(())
    }

    /// Angle-bracket form continues to work alongside bare-URI support.
    #[test]
    fn extract_user_angle_bracket_still_works() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user("<sip:charlie@host>"),
            Some("charlie".to_string())
        );
        Ok(())
    }

    /// A bare-token display name before the URI does not confuse extraction.
    #[test]
    fn extract_user_display_name_with_uri() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_user("Alice <sip:alice@host>"),
            Some("alice".to_string())
        );
        Ok(())
    }

    // ── extract_uri_host_port ────────────────────────────────────────

    /// A quoted display name may legally contain a complete URI —
    /// [RFC 3261 section 25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1) lets a `quoted-string` hold any octet except an unescaped `"`,
    /// including `<`, `>` and a scheme. Neither the user nor the host may ever
    /// be read from one, or a caller chooses what it is reported as.
    #[test]
    fn quoted_display_name_cannot_spoof_user_or_host() -> Result<(), TestError> {
        let crafted = r#""<sip:evil@attacker.test>" <sip:alice@real.test>"#;
        assert_eq!(extract_uri_user(crafted), Some("alice".to_string()));
        assert_eq!(
            extract_uri_host_port(crafted),
            Some("real.test".to_string())
        );
        Ok(())
    }

    /// The same attack with a bare scheme rather than a bracketed decoy.
    #[test]
    fn quoted_scheme_in_display_name_is_not_the_uri() -> Result<(), TestError> {
        let crafted = r#""sip:evil@attacker.test" <sip:bob@real.test>"#;
        assert_eq!(extract_uri_user(crafted), Some("bob".to_string()));
        assert_eq!(
            extract_uri_host_port(crafted),
            Some("real.test".to_string())
        );
        Ok(())
    }

    /// `\"` is a quoted-pair and does not close the display name, so a decoy
    /// placed after one is still inside it.
    #[test]
    fn escaped_quote_does_not_end_the_display_name() -> Result<(), TestError> {
        let crafted = r#""he said \"<sip:evil@attacker.test>\"" <sip:carol@real.test>"#;
        assert_eq!(extract_uri_user(crafted), Some("carol".to_string()));
        assert_eq!(
            extract_uri_host_port(crafted),
            Some("real.test".to_string())
        );
        Ok(())
    }

    /// An unterminated display name has no addressable URI. Resuming the scan
    /// past it would read the exact region the quote encloses.
    #[test]
    fn unterminated_display_name_yields_nothing() -> Result<(), TestError> {
        let crafted = r#""<sip:evil@attacker.test> <sip:dave@real.test>"#;
        assert_eq!(extract_uri_user(crafted), None);
        assert_eq!(extract_uri_host_port(crafted), None);
        Ok(())
    }

    /// Host and port are extracted past a display name and userinfo.
    #[test]
    fn host_port_with_user_and_port() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_host_port(r#""Alice" <sip:1001@example.com:5060>;tag=abc"#),
            Some("example.com:5060".to_string())
        );
        Ok(())
    }

    /// A URI without a port yields just the host.
    #[test]
    fn host_port_no_port() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_host_port("<sip:1002@example.com>"),
            Some("example.com".to_string())
        );
        Ok(())
    }

    /// A URI without userinfo yields host:port directly.
    #[test]
    fn host_port_no_user() -> Result<(), TestError> {
        // A URI with no userinfo (e.g. a registrar/domain target).
        assert_eq!(
            extract_uri_host_port("<sip:example.com:5061>"),
            Some("example.com:5061".to_string())
        );
        Ok(())
    }

    /// A bracketed IPv6 host with port survives intact.
    #[test]
    fn host_port_ipv6_bracketed_with_port() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_host_port("<sip:bob@[2001:db8::1]:5060>;transport=udp"),
            Some("[2001:db8::1]:5060".to_string())
        );
        Ok(())
    }

    /// A bracketed IPv6 host without a port survives intact.
    #[test]
    fn host_port_ipv6_no_port() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_host_port("<sip:[2001:db8::1]>"),
            Some("[2001:db8::1]".to_string())
        );
        Ok(())
    }

    /// URI parameters (`;transport=...;lr`) are stripped from the host:port.
    #[test]
    fn host_port_strips_uri_params() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_host_port("<sip:1001@10.0.0.1:5060;transport=tcp;lr>"),
            Some("10.0.0.1:5060".to_string())
        );
        Ok(())
    }

    /// Bare `sip:`/`sips:` URIs (no angle brackets) yield host:port.
    #[test]
    fn host_port_bare_uri() -> Result<(), TestError> {
        assert_eq!(
            extract_uri_host_port("sip:alice@host.example:5070"),
            Some("host.example:5070".to_string())
        );
        assert_eq!(
            extract_uri_host_port("sips:bob@secure.example"),
            Some("secure.example".to_string())
        );
        Ok(())
    }

    /// A `tel:` URI has no host and yields `None`.
    #[test]
    fn host_port_tel_uri_has_no_host() -> Result<(), TestError> {
        // tel: URIs carry no host — fall back to None (caller shows user or '-').
        assert_eq!(extract_uri_host_port("<tel:+15551234567>"), None);
        Ok(())
    }

    /// Empty, non-URI, and backslash-laden inputs never panic.
    #[test]
    fn host_port_empty_or_garbage() -> Result<(), TestError> {
        assert_eq!(extract_uri_host_port(""), None);
        assert_eq!(extract_uri_host_port("not a uri at all"), None);
        // Backslash / odd chars must not panic.
        assert_eq!(
            extract_uri_host_port(r"<sip:a\b@ho\st>"),
            Some(r"ho\st".to_string())
        );
        Ok(())
    }

    // ── top_via_branch (RFC 3261 transaction identity) ─────────────────

    /// Build an OPTIONS request carrying the given Via header lines.
    fn msg_with_vias(vias: &[&str]) -> Result<SipMessage, TestError> {
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
    fn top_via_branch_basic() -> Result<(), TestError> {
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.abc"])?;
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.abc"));
        Ok(())
    }

    /// Only the topmost Via's branch is returned when several are present.
    #[test]
    fn top_via_branch_takes_first_via_only() -> Result<(), TestError> {
        let m = msg_with_vias(&[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.top",
            "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK.below",
        ])?;
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.top"));
        Ok(())
    }

    /// Extra params and loose spacing around `;` do not break extraction.
    #[test]
    fn top_via_branch_more_params_and_spacing() -> Result<(), TestError> {
        let m =
            msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060 ; rport ; branch=z9hG4bK.x ; alias"])?;
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.x"));
        Ok(())
    }

    /// The `branch` parameter name matches case-insensitively.
    #[test]
    fn top_via_branch_param_name_case_insensitive() -> Result<(), TestError> {
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;BRANCH=z9hG4bK.up"])?;
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.up"));
        Ok(())
    }

    /// A compact `v:` Via still yields the top branch after expansion.
    #[test]
    fn top_via_branch_compact_form() -> Result<(), TestError> {
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
        )?;
        assert_eq!(m.top_via_branch(), Some("z9hG4bK.compact"));
        Ok(())
    }

    /// Missing Via, missing/empty branch, prefix params, and adversarial
    /// quoting all behave as specified (None or literal pass-through).
    #[test]
    fn top_via_branch_absent_or_degenerate() -> Result<(), TestError> {
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
        )?;
        assert_eq!(m.top_via_branch(), None);
        // Via without a branch param (RFC 2543 style).
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060"])?;
        assert_eq!(m.top_via_branch(), None);
        // Empty branch value → treated as absent.
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;branch="])?;
        assert_eq!(m.top_via_branch(), None);
        // `branch` as a prefix of another param must not match.
        let m = msg_with_vias(&["Via: SIP/2.0/UDP 10.0.0.1:5060;branchx=nope"])?;
        assert_eq!(m.top_via_branch(), None);
        // Adversarial: backslashes and quotes must not panic and pass through.
        let m = msg_with_vias(&[r#"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9\"h4bK"#])?;
        assert_eq!(m.top_via_branch(), Some(r#"z9\"h4bK"#));
        Ok(())
    }

    // ── SDP-LABEL1: one rule for "this message carries SDP" ────────────

    const SDP_BODY: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
                              t=0 0\r\nm=audio 20000 RTP/AVP 0\r\n";

    fn invite_with(content_type: Option<&str>, body: &[u8]) -> Result<SipMessage, TestError> {
        let ct = content_type.map(|ct| format!("Content-Type: {ct}"));
        let mut headers = vec![
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-sdp",
            "From: <sip:a@example.com>;tag=1",
            "To: <sip:b@example.com>",
            "Call-ID: sdp-rule@example.com",
            "CSeq: 1 INVITE",
        ];
        if let Some(ct) = ct.as_deref() {
            headers.push(ct);
        }
        parse_msg("INVITE sip:b@example.com SIP/2.0", &headers, body)
    }

    fn multipart(sdp_part_type: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"--B\r\nContent-Type: application/rs-metadata+xml\r\n\r\n<x/>\r\n");
        b.extend_from_slice(format!("--B\r\nContent-Type: {sdp_part_type}\r\n\r\n").as_bytes());
        b.extend_from_slice(SDP_BODY);
        b.extend_from_slice(b"\r\n--B--\r\n");
        b
    }

    #[test]
    fn an_application_sdp_body_carries_sdp() -> Result<(), TestError> {
        assert!(invite_with(Some("application/sdp"), SDP_BODY)?.carries_sdp());
        Ok(())
    }

    /// [RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1): the type and subtype are case-insensitive.
    #[test]
    fn the_media_type_is_matched_without_regard_to_case() -> Result<(), TestError> {
        let m = invite_with(Some("Application/SDP"), SDP_BODY)?;
        assert!(m.carries_sdp());
        assert!(m.sdp().is_some(), "sdp() reads an Application/SDP body");
        Ok(())
    }

    /// A body declared as another type is that type, whatever its first bytes.
    #[test]
    fn a_body_declared_as_another_type_does_not_carry_sdp() -> Result<(), TestError> {
        assert!(!invite_with(Some("text/plain"), SDP_BODY)?.carries_sdp());
        Ok(())
    }

    /// [RFC 3261 section 20.15](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.15) requires a Content-Type on a body; a peer that
    /// omits it on an SDP body is still labeled from the body.
    #[test]
    fn an_undeclared_body_that_starts_like_sdp_carries_sdp() -> Result<(), TestError> {
        assert!(invite_with(None, SDP_BODY)?.carries_sdp());
        assert!(!invite_with(None, b"")?.carries_sdp(), "no body, no SDP");
        Ok(())
    }

    /// `sdp()` and `carries_sdp()` are one rule: every body the label calls
    /// SDP is read as SDP, and no other. A body with no `Content-Type` that
    /// starts `v=` is both; one declared as another type, or empty, is
    /// neither.
    #[test]
    fn sdp_reads_exactly_the_bodies_the_label_calls_sdp() -> Result<(), TestError> {
        let multipart_sdp = multipart("application/sdp");
        let multipart_isup = multipart("application/isup");
        let cases: [(Option<&str>, &[u8]); 7] = [
            (None, SDP_BODY),
            (None, b""),
            (None, b"hello"),
            (Some("application/sdp"), SDP_BODY),
            (Some("text/plain"), SDP_BODY),
            (Some("multipart/mixed;boundary=B"), &multipart_sdp),
            (Some("multipart/mixed;boundary=B"), &multipart_isup),
        ];
        for (ct, body) in cases {
            let m = invite_with(ct, body)?;
            assert_eq!(
                m.sdp().is_some(),
                m.carries_sdp(),
                "{ct:?} with {} body bytes",
                body.len()
            );
        }
        assert!(
            invite_with(None, SDP_BODY)?.sdp().is_some(),
            "no Content-Type, starts v="
        );
        Ok(())
    }

    /// A multipart body (SIPREC, SIP-I) carries SDP when one part is SDP.
    #[test]
    fn a_multipart_body_with_an_sdp_part_carries_sdp() -> Result<(), TestError> {
        let ct = Some("multipart/mixed;boundary=B");
        assert!(invite_with(ct, &multipart("application/sdp"))?.carries_sdp());
        assert!(invite_with(ct, &multipart("Application/SDP"))?.carries_sdp());
        assert!(
            !invite_with(ct, &multipart("application/isup"))?.carries_sdp(),
            "no SDP part, no SDP"
        );
        Ok(())
    }

    // ── MULTIPART-SDP-MEDIA: sdp() reads the SDP part of a multipart body ──

    /// A binary ISUP message, as [RFC 3204 section 3.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-3.1)
    /// encodes one ("Encoding scheme: binary"): not UTF-8, and holding a CR LF
    /// pair and a `--` that are part of the message, not framing.
    const ISUP: &[u8] = &[
        0x01, 0x00, 0x60, 0x0d, 0x0a, 0x2d, 0x2d, 0x42, 0x83, 0x90, 0x55, 0x05, 0x01, 0x00, 0xff,
        0xc3, 0x28,
    ];

    /// The [RFC 3204 section 4.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-4.1)
    /// shape: an SDP part typed in capitals with a charset, then a binary ISUP
    /// part whose `Content-Type` is folded.
    fn sip_i(sdp_part: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"--B\r\nContent-Type: application/SDP; charset=ISO-10646\r\n\r\n");
        b.extend_from_slice(sdp_part);
        b.extend_from_slice(
            b"\r\n--B\r\nContent-Type: application/ISUP; version=itu-t;\r\n base=itu-t92+\r\n\
              Content-Disposition: signal; handling=optional\r\n\r\n",
        );
        b.extend_from_slice(ISUP);
        b.extend_from_slice(b"\r\n--B--\r\n");
        b
    }

    /// `sdp()` reads the SDP part of a SIP-I body, beside a binary ISUP part.
    #[test]
    fn sdp_reads_the_sdp_part_of_a_sip_i_body() -> Result<(), TestError> {
        let m = invite_with(Some("multipart/mixed; boundary=B"), &sip_i(SDP_BODY))?;
        let sdp = m.sdp().ok_or("the SDP part is read")?;
        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].port, 20000);
        assert_eq!(
            sdp.connection.as_ref().map(|c| c.addr.as_str()),
            Some("192.0.2.1")
        );
        Ok(())
    }

    /// A binary part does not hide the SDP part from the label rule either.
    #[test]
    fn a_binary_isup_part_does_not_hide_the_sdp_part() -> Result<(), TestError> {
        let m = invite_with(Some("multipart/mixed; boundary=B"), &sip_i(SDP_BODY))?;
        assert!(
            std::str::from_utf8(&m.body).is_err(),
            "the fixture is binary"
        );
        assert!(m.carries_sdp(), "the SDP part is found beside binary ISUP");
        Ok(())
    }

    /// The SIPREC shape: metadata first, SDP second.
    #[test]
    fn sdp_reads_the_sdp_part_after_another_part() -> Result<(), TestError> {
        let m = invite_with(
            Some("multipart/mixed;boundary=B"),
            &multipart("application/sdp"),
        )?;
        let sdp = m.sdp().ok_or("the SDP part is read")?;
        assert_eq!(sdp.media[0].port, 20000);
        Ok(())
    }

    /// [RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1):
    /// the type, the subtype and the parameter name are case-insensitive, so
    /// `Multipart/Mixed; Boundary=B` is read as `multipart/mixed; boundary=B`.
    #[test]
    fn a_multipart_type_is_matched_without_regard_to_case() -> Result<(), TestError> {
        let m = invite_with(Some("Multipart/Mixed; Boundary=B"), &sip_i(SDP_BODY))?;
        assert!(m.sdp().is_some(), "sdp() reads the part");
        assert!(m.carries_sdp(), "and the label rule agrees");
        Ok(())
    }

    // ── MULTIPART-NESTED: an SDP part inside a nested multipart ────────

    /// `body` wrapped `depth` times: each level is a `multipart/mixed` whose one
    /// part is the level inside it, with boundaries `L1`, `L2`, ...; the
    /// innermost level holds `inner_type` with `inner`. Returns the outermost
    /// `Content-Type` and the body.
    fn nested(depth: usize, inner_type: &str, inner: &[u8]) -> (String, Vec<u8>) {
        let mut ct = inner_type.to_string();
        let mut body = inner.to_vec();
        for level in (1..=depth).rev() {
            let boundary = format!("L{level}");
            let mut outer = format!("--{boundary}\r\nContent-Type: {ct}\r\n\r\n").into_bytes();
            outer.extend_from_slice(&body);
            outer.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            ct = format!("multipart/mixed; boundary={boundary}");
            body = outer;
        }
        (ct, body)
    }

    /// [RFC 5621 section 4.2](https://www.rfc-editor.org/rfc/rfc5621.html#section-4.2):
    /// "SIP UAs MUST support parsing 'multipart' MIME bodies, including
    /// nested body parts", and section 4.1 shows a `multipart/alternative`
    /// inside a `multipart/mixed`. The SDP in that inner part is the
    /// message's SDP.
    #[test]
    fn sdp_reads_an_sdp_part_inside_a_nested_multipart() -> Result<(), TestError> {
        let mut alternative = b"--ALT\r\nContent-Type: application/sdp\r\n\r\n".to_vec();
        alternative.extend_from_slice(SDP_BODY);
        alternative
            .extend_from_slice(b"\r\n--ALT\r\nContent-Type: text/plain\r\n\r\nx\r\n--ALT--\r\n");
        let mut body =
            b"--OUT\r\nContent-Type: multipart/alternative; boundary=ALT\r\n\r\n".to_vec();
        body.extend_from_slice(&alternative);
        body.extend_from_slice(
            b"\r\n--OUT\r\nContent-Type: application/ISUP; version=itu-t\r\n\r\n",
        );
        body.extend_from_slice(ISUP);
        body.extend_from_slice(b"\r\n--OUT--\r\n");
        let m = invite_with(Some("multipart/mixed; boundary=OUT"), &body)?;
        let sdp = m.sdp().ok_or("the nested SDP part is read")?;
        assert_eq!(sdp.media[0].port, 20000);
        assert!(m.carries_sdp(), "and the label rule agrees");
        Ok(())
    }

    /// The SDP is the first `application/sdp` part in body order, depth
    /// first: an outer SDP part before a nested one wins, and a nested one
    /// before an outer one wins.
    #[test]
    fn the_first_sdp_part_in_body_order_is_the_sdp() -> Result<(), TestError> {
        let other = String::from_utf8(SDP_BODY.to_vec())?.replace("20000", "30000");
        let (inner_ct, inner) = nested(1, "application/sdp", other.as_bytes());
        let part = |ct: &str, b: &[u8]| {
            let mut v = format!("--OUT\r\nContent-Type: {ct}\r\n\r\n").into_bytes();
            v.extend_from_slice(b);
            v.extend_from_slice(b"\r\n");
            v
        };
        let mut outer_first = part("application/sdp", SDP_BODY);
        outer_first.extend_from_slice(&part(&inner_ct, &inner));
        outer_first.extend_from_slice(b"--OUT--\r\n");
        let mut nested_first = part(&inner_ct, &inner);
        nested_first.extend_from_slice(&part("application/sdp", SDP_BODY));
        nested_first.extend_from_slice(b"--OUT--\r\n");
        let ct = Some("multipart/mixed; boundary=OUT");
        let port = |b: &[u8]| -> Result<u16, TestError> {
            Ok(invite_with(ct, b)?.sdp().ok_or("an SDP part")?.media[0].port)
        };
        assert_eq!(port(&outer_first)?, 20000);
        assert_eq!(port(&nested_first)?, 30000);
        Ok(())
    }

    /// Nesting is followed to [`MAX_MULTIPART_DEPTH`] levels of `multipart`
    /// below the message's own, and no further: a body nested deeper holds no
    /// SDP that sipnab reads, and reading it ends rather than recursing
    /// without bound.
    #[test]
    fn nesting_is_followed_to_a_bounded_depth() -> Result<(), TestError> {
        for (depth, found) in [
            (1, true),
            (MAX_MULTIPART_DEPTH + 1, true),
            (MAX_MULTIPART_DEPTH + 2, false),
            (2_000, false),
        ] {
            let (ct, body) = nested(depth, "application/sdp", SDP_BODY);
            let m = invite_with(Some(&ct), &body)?;
            assert_eq!(m.sdp().is_some(), found, "{depth} levels of multipart");
            assert_eq!(m.carries_sdp(), found, "{depth} levels, label");
        }
        Ok(())
    }

    /// Negative controls: no SDP part, no boundary, or a boundary the body
    /// never uses give no SDP, and a whole `application/sdp` body still does.
    #[test]
    fn sdp_is_none_without_an_sdp_part() -> Result<(), TestError> {
        let ct = Some("multipart/mixed;boundary=B");
        assert!(
            invite_with(ct, &multipart("application/isup"))?
                .sdp()
                .is_none()
        );
        assert!(invite_with(ct, &multipart("text/plain"))?.sdp().is_none());
        assert!(
            invite_with(Some("multipart/mixed"), &multipart("application/sdp"))?
                .sdp()
                .is_none(),
            "no boundary parameter"
        );
        assert!(
            invite_with(
                Some("multipart/mixed;boundary=Z"),
                &multipart("application/sdp")
            )?
            .sdp()
            .is_none(),
            "a boundary the body does not use"
        );
        assert!(
            invite_with(Some("application/sdp"), SDP_BODY)?
                .sdp()
                .is_some()
        );
        Ok(())
    }

    /// [RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1):
    /// the preamble before the first delimiter and the epilogue after the
    /// close delimiter "are to be ignored". SDP-looking text in either is not
    /// the message's SDP.
    #[test]
    fn sdp_ignores_the_preamble_and_the_epilogue() -> Result<(), TestError> {
        let mut body = b"Content-Type: application/sdp\r\n\r\n".to_vec();
        body.extend_from_slice(SDP_BODY);
        body.extend_from_slice(b"\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n");
        body.extend_from_slice(b"--B\r\nContent-Type: application/sdp\r\n\r\n");
        body.extend_from_slice(SDP_BODY);
        let m = invite_with(Some("multipart/mixed;boundary=B"), &body)?;
        assert!(m.sdp().is_none(), "only the preamble and epilogue hold SDP");
        assert!(!m.carries_sdp(), "and the label rule agrees");
        Ok(())
    }

    // ── SDP-LABEL2: one label for every surface ────────────────────────

    fn response_with(
        first: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<SipMessage, TestError> {
        let ct = content_type.map(|ct| format!("Content-Type: {ct}"));
        let mut headers = vec![
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-sdp",
            "From: <sip:a@example.com>;tag=1",
            "To: <sip:b@example.com>;tag=2",
            "Call-ID: sdp-label@example.com",
            "CSeq: 1 INVITE",
        ];
        if let Some(ct) = ct.as_deref() {
            headers.push(ct);
        }
        parse_msg(first, &headers, body)
    }

    #[test]
    fn a_label_names_the_method_or_the_status_and_marks_sdp() -> Result<(), TestError> {
        assert_eq!(
            invite_with(Some("application/sdp"), SDP_BODY)?.label(),
            "INVITE (SDP)"
        );
        assert_eq!(invite_with(None, b"")?.label(), "INVITE");
        assert_eq!(
            response_with("SIP/2.0 200 OK", Some("application/sdp"), SDP_BODY)?.label(),
            "200 OK (SDP)"
        );
        assert_eq!(
            response_with("SIP/2.0 180 Ringing", None, b"")?.label(),
            "180 Ringing"
        );
        Ok(())
    }

    /// A response with no reason phrase is its code alone, with no trailing
    /// space before an `(SDP)` mark or the end of the label.
    #[test]
    fn a_response_without_a_reason_is_labeled_by_its_code() -> Result<(), TestError> {
        let mut m = response_with("SIP/2.0 200 OK", Some("application/sdp"), SDP_BODY)?;
        m.reason = None;
        assert_eq!(m.label(), "200 (SDP)");
        let mut m = response_with("SIP/2.0 180 Ringing", None, b"")?;
        m.reason = None;
        assert_eq!(m.label(), "180");
        Ok(())
    }

    /// A message whose method or status code was not parsed says which kind
    /// of message it is, rather than `?` or a status of 0.
    #[test]
    fn a_message_missing_its_method_or_code_says_what_it_is() -> Result<(), TestError> {
        let mut m = invite_with(None, b"")?;
        m.method = None;
        assert_eq!(m.label(), "request");
        let mut m = response_with("SIP/2.0 180 Ringing", None, b"")?;
        m.status_code = None;
        assert_eq!(m.label(), "response");
        Ok(())
    }
}
