//! SIP message type and header accessors.
//!
//! [`SipMessage`] holds a fully parsed SIP message with all headers extracted
//! and normalized. Accessor methods provide convenient typed access to
//! commonly used headers.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::sdp::{self, SdpSession};

/// A single SIP header: name (normalized to long form) and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHeader {
    /// Header name, normalized to canonical long form (e.g., `"Call-ID"` not `"i"`).
    pub name: String,
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
    /// Full raw message bytes as captured.
    pub raw: Vec<u8>,
    /// `true` for requests (INVITE, REGISTER, ...), `false` for responses.
    pub is_request: bool,
    /// Request method (e.g., `"INVITE"`). `None` for responses.
    pub method: Option<String>,
    /// Response status code (e.g., `200`). `None` for requests.
    pub status_code: Option<u16>,
    /// Response reason phrase (e.g., `"OK"`). `None` for requests.
    pub reason: Option<String>,
    /// Request-URI (e.g., `"sip:user@host"`). `None` for responses.
    pub request_uri: Option<String>,
    /// All headers in message order, with compact forms expanded.
    pub headers: Vec<SipHeader>,
    /// Message body (SDP or other payload after the blank line).
    pub body: Vec<u8>,
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
    /// Transport protocol name: `"UDP"`, `"TCP"`, `"TLS"`, or `"WS"`.
    pub transport: String,
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

    /// Parse the `CSeq` header into its sequence number and method.
    ///
    /// Returns `None` if the header is missing or malformed.
    pub fn cseq(&self) -> Option<(u32, String)> {
        let val = self.header("CSeq")?;
        let mut parts = val.trim().splitn(2, char::is_whitespace);
        let num: u32 = parts.next()?.parse().ok()?;
        let method = parts.next()?.trim().to_string();
        if method.is_empty() {
            return None;
        }
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
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|h| h.name.to_ascii_lowercase() == name_lower)
            .map(|h| h.value.as_str())
    }

    /// Return all header values matching `name` (case-insensitive).
    pub fn headers_by_name(&self, name: &str) -> Vec<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|h| h.name.to_ascii_lowercase() == name_lower)
            .map(|h| h.value.as_str())
            .collect()
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
    pub fn to_user(&self) -> Option<String> {
        extract_uri_user(self.to_header()?)
    }

    /// Extract the `tag` parameter from the `From` header.
    pub fn from_tag(&self) -> Option<&str> {
        extract_tag(self.from_header()?)
    }

    /// Extract the `tag` parameter from the `To` header.
    pub fn to_tag(&self) -> Option<&str> {
        extract_tag(self.to_header()?)
    }
}

/// Extract the user part from a SIP URI inside a header value.
///
/// Handles both `<sip:user@host>` and bare `sip:user@host` forms.
fn extract_uri_user(header_value: &str) -> Option<String> {
    // Look for "sip:" or "sips:" within angle brackets first, then bare
    let uri_start = header_value
        .find("<sip:")
        .or_else(|| header_value.find("<sips:"))?;

    let after_scheme = &header_value[uri_start + 1..]; // skip '<'
    let colon_pos = after_scheme.find(':')?;
    let after_colon = &after_scheme[colon_pos + 1..];

    // User part ends at '@'
    let at_pos = after_colon.find('@')?;
    let user = &after_colon[..at_pos];

    if user.is_empty() {
        return None;
    }
    Some(user.to_string())
}

/// Extract the `tag=` parameter from a From/To header value.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_user_with_display_name() {
        assert_eq!(
            extract_uri_user(r#""Alice" <sip:1001@example.com>;tag=abc"#),
            Some("1001".to_string())
        );
    }

    #[test]
    fn extract_user_no_display_name() {
        assert_eq!(
            extract_uri_user("<sip:1002@example.com>"),
            Some("1002".to_string())
        );
    }

    #[test]
    fn extract_user_sips() {
        assert_eq!(
            extract_uri_user("<sips:secure@example.com>"),
            Some("secure".to_string())
        );
    }

    #[test]
    fn extract_user_no_at() {
        assert_eq!(extract_uri_user("<sip:example.com>"), None);
    }

    #[test]
    fn extract_tag_present() {
        assert_eq!(
            extract_tag("<sip:1001@example.com>;tag=abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_tag_with_other_params() {
        assert_eq!(
            extract_tag("<sip:1001@example.com>;tag=abc;other=xyz"),
            Some("abc")
        );
    }

    #[test]
    fn extract_tag_absent() {
        assert_eq!(extract_tag("<sip:1001@example.com>"), None);
    }
}
