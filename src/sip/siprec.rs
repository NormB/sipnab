//! SIPREC metadata parsing (RFC 7866).
//!
//! Parses multipart/mixed SIP bodies to extract recording metadata
//! from the application/rs-metadata+xml MIME part.

use anyhow::{Result, bail};

/// Parsed SIPREC recording metadata.
#[derive(Debug, Clone, Default)]
pub struct SirecMetadata {
    /// Recording session identifier.
    pub session_id: Option<String>,
    /// Participants captured in the recording metadata.
    pub participants: Vec<SirecParticipant>,
    /// Media streams described by the metadata.
    pub streams: Vec<SirecStream>,
    /// Recording mode (e.g. "complete").
    pub mode: Option<String>,
}

/// A participant in a SIPREC-recorded session.
#[derive(Debug, Clone)]
pub struct SirecParticipant {
    /// Participant identifier from the metadata XML.
    pub participant_id: Option<String>,
    /// Address-of-record (SIP URI) of the participant.
    pub aor: Option<String>,
    /// Display name of the participant.
    pub name: Option<String>,
}

/// A media stream described by SIPREC metadata.
#[derive(Debug, Clone)]
pub struct SirecStream {
    /// Stream identifier from the metadata XML.
    pub stream_id: Option<String>,
    /// SDP label associating the stream with an m-line.
    pub label: Option<String>,
    /// Participant this stream belongs to.
    pub participant_id: Option<String>,
}

/// One part of a multipart MIME body: its Content-Type and body text.
struct MimePart {
    /// Value of the part's `Content-Type` header, if present.
    content_type: Option<String>,
    /// Part body text (everything after the part's blank line).
    body: String,
}

/// Extract the `boundary=` parameter from a Content-Type header value.
///
/// Handles both quoted (`boundary="x"`) and bare (`boundary=x`) forms.
/// Returns `None` when no boundary parameter is present.
fn extract_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|param| {
        let param = param.trim();
        // Try quoted form first to avoid greedily matching the opening quote
        param
            .strip_prefix("boundary=\"")
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| param.strip_prefix("boundary="))
            .map(|b| b.to_string())
    })
}

/// Split a multipart body into MIME parts using the given boundary.
///
/// # Arguments
///
/// * `body` — the full multipart body text.
/// * `boundary` — the boundary token (without the leading `--`).
///
/// # Returns
///
/// One `MimePart` per non-empty segment, each with its `Content-Type` (if
/// any) and body text. A missing final `--` terminator is tolerated; empty
/// segments and the terminator remnant are skipped.
fn split_multipart(body: &str, boundary: &str) -> Vec<MimePart> {
    let delimiter = format!("--{}", boundary);
    let mut parts = Vec::new();

    // RFC 2046 §5.1.1: a delimiter only counts when it starts a line — at the
    // very start of the body or preceded by a line break (CRLF, or bare LF for
    // tolerance). Mid-line occurrences inside part content are literal text.
    let mut segments = Vec::new();
    let mut segment_start = 0;
    let mut search_from = 0;
    while let Some(rel) = body[search_from..].find(&delimiter) {
        let pos = search_from + rel;
        let line_anchored = pos == 0 || body.as_bytes()[pos - 1] == b'\n';
        if !line_anchored {
            search_from = pos + delimiter.len();
            continue;
        }
        segments.push(&body[segment_start..pos]);
        segment_start = pos + delimiter.len();
        search_from = segment_start;
    }
    segments.push(&body[segment_start..]);

    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() || segment == "--" {
            continue;
        }
        // Remove trailing terminator marker if present
        let segment = segment.strip_suffix("--").map_or(segment, |s| s.trim());

        // Split headers from body at first blank line
        let (headers_part, body_part) = if let Some(pos) = segment.find("\r\n\r\n") {
            (&segment[..pos], &segment[pos + 4..])
        } else if let Some(pos) = segment.find("\n\n") {
            (&segment[..pos], &segment[pos + 2..])
        } else {
            ("", segment)
        };

        let content_type = headers_part.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-type:") {
                Some(line[13..].trim().to_string())
            } else {
                None
            }
        });

        parts.push(MimePart {
            content_type,
            body: body_part.to_string(),
        });
    }

    parts
}

/// Parse SIPREC metadata XML using simple string extraction.
/// No XML crate dependency — uses basic string matching for the well-defined RFC 7866 schema.
///
/// # Arguments
///
/// * `xml` — the `application/rs-metadata+xml` part body.
///
/// # Returns
///
/// The extracted session id, mode, `<participant>` blocks, and `<stream>`
/// blocks. Malformed or unrecognized XML degrades to empty/default fields.
///
/// # Errors
///
/// Currently never fails — the `Result` exists for future stricter parsing.
fn parse_rs_metadata(xml: &str) -> Result<SirecMetadata> {
    let mut metadata = SirecMetadata {
        session_id: extract_xml_attr(xml, "session_id")
            .or_else(|| extract_xml_content(xml, "sessionid")),
        mode: extract_xml_content(xml, "mode"),
        ..SirecMetadata::default()
    };

    // Extract participants — look for <participant> blocks
    let mut search_from = 0;
    while let Some(start) = xml[search_from..].find("<participant") {
        let abs_start = search_from + start;
        if let Some(end) = xml[abs_start..].find("</participant>") {
            let block = &xml[abs_start..abs_start + end + "</participant>".len()];
            let participant = SirecParticipant {
                participant_id: extract_xml_attr(block, "participant_id")
                    .or_else(|| extract_xml_attr(block, "participantid")),
                aor: extract_xml_content(block, "aor")
                    .or_else(|| extract_xml_content(block, "nameID")),
                name: extract_xml_content(block, "name"),
            };
            metadata.participants.push(participant);
            search_from = abs_start + end + "</participant>".len();
        } else {
            break;
        }
    }

    // Extract streams
    search_from = 0;
    while let Some(start) = xml[search_from..].find("<stream") {
        let abs_start = search_from + start;
        if let Some(end) = xml[abs_start..].find("</stream>") {
            let block = &xml[abs_start..abs_start + end + "</stream>".len()];
            let stream = SirecStream {
                stream_id: extract_xml_attr(block, "stream_id")
                    .or_else(|| extract_xml_attr(block, "streamid")),
                label: extract_xml_content(block, "label"),
                participant_id: extract_xml_content(block, "participant"),
            };
            metadata.streams.push(stream);
            search_from = abs_start + end + "</stream>".len();
        } else {
            break;
        }
    }

    Ok(metadata)
}

/// Extract content between `<tag>...</tag>` or `<tag attr="..">...</tag>`.
///
/// Ensures the match is an exact tag name and not a prefix
/// (e.g., `"name"` won't match `<nameID>`). Returns the trimmed content of
/// the first matching element, or `None` when the tag is absent, unclosed,
/// or empty.
fn extract_xml_content(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find(&open) {
        let abs_pos = search_from + pos;
        let after_tag = abs_pos + open.len();
        // Ensure the character after the tag name is '>' or whitespace (attribute),
        // not a continuation of the tag name (e.g., <nameID>)
        if after_tag < xml.len() {
            let next_ch = xml.as_bytes()[after_tag];
            if next_ch != b'>' && next_ch != b' ' && next_ch != b'/' {
                search_from = after_tag;
                continue;
            }
        }
        let content_start = xml[abs_pos..].find('>')? + abs_pos + 1;
        let end = xml[content_start..].find(&close)? + content_start;
        let content = xml[content_start..end].trim();
        return if content.is_empty() {
            None
        } else {
            Some(content.to_string())
        };
    }
    None
}

/// Extract an attribute value from an XML element.
///
/// Finds the first `attr_name="value"` occurrence anywhere in `xml` and
/// returns the value; `None` when absent, unterminated, or empty.
fn extract_xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    let start = xml.find(&pattern)?;
    let value_start = start + pattern.len();
    let end = xml[value_start..].find('"')? + value_start;
    let value = &xml[value_start..end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parse a multipart/mixed body to extract SIPREC metadata.
///
/// # Arguments
///
/// * `content_type` — the SIP message's `Content-Type` header value,
///   carrying the multipart boundary parameter.
/// * `body` — the raw multipart body bytes.
///
/// # Returns
///
/// The metadata parsed from the first `rs-metadata` MIME part.
///
/// # Errors
///
/// Fails when the Content-Type has no `boundary` parameter, the body is not
/// valid UTF-8, or no `rs-metadata` part is found in the multipart body.
pub fn parse_siprec_body(content_type: &str, body: &[u8]) -> Result<SirecMetadata> {
    let boundary = extract_boundary(content_type)
        .ok_or_else(|| anyhow::anyhow!("no boundary in content-type"))?;

    let body_str = std::str::from_utf8(body)?;
    let parts = split_multipart(body_str, &boundary);

    for part in parts {
        if part
            .content_type
            .as_deref()
            .is_some_and(|ct| ct.contains("rs-metadata") || ct.contains("rs-metadata+xml"))
        {
            return parse_rs_metadata(&part.body);
        }
    }

    bail!("no rs-metadata+xml part found in multipart body")
}

/// Tests for boundary extraction, multipart splitting, and SIPREC metadata
/// parsing including truncated and malformed bodies.
#[cfg(test)]
mod tests {
    use super::*;

    /// A bare boundary parameter is extracted from Content-Type.
    #[test]
    fn test_extract_boundary() {
        let ct = "multipart/mixed; boundary=uniqueBoundary";
        assert_eq!(extract_boundary(ct), Some("uniqueBoundary".to_string()));
    }

    /// A quoted boundary parameter is extracted without the quotes.
    #[test]
    fn test_extract_boundary_quoted() {
        let ct = r#"multipart/mixed; boundary="unique-Boundary""#;
        assert_eq!(extract_boundary(ct), Some("unique-Boundary".to_string()));
    }

    /// A full SDP+metadata multipart body yields session, participant, and
    /// stream fields.
    #[test]
    fn test_parse_siprec_body() {
        let ct = "multipart/mixed; boundary=boundary1";
        let body = b"--boundary1\r\n\
Content-Type: application/sdp\r\n\r\n\
v=0\r\n\
--boundary1\r\n\
Content-Type: application/rs-metadata+xml\r\n\r\n\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n\
  <session session_id=\"abc123\">\n\
    <participant participant_id=\"p1\">\n\
      <nameID><aor>sip:alice@example.com</aor></nameID>\n\
      <name>Alice</name>\n\
    </participant>\n\
    <stream stream_id=\"s1\">\n\
      <label>audio</label>\n\
    </stream>\n\
  </session>\n\
</recording>\n\
--boundary1--";

        let result = parse_siprec_body(ct, body).unwrap();
        assert_eq!(result.session_id.as_deref(), Some("abc123"));
        assert_eq!(result.participants.len(), 1);
        assert_eq!(result.participants[0].name.as_deref(), Some("Alice"));
        assert_eq!(result.streams.len(), 1);
        assert_eq!(result.streams[0].label.as_deref(), Some("audio"));
    }

    /// A multipart body without an rs-metadata part is an error.
    #[test]
    fn test_no_metadata_part() {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--";
        assert!(parse_siprec_body(ct, body).is_err());
    }

    /// A body missing the final `--boundary--` terminator still parses.
    #[test]
    fn test_truncated_body_no_final_boundary() {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\nContent-Type: application/rs-metadata+xml\r\n\r\n\
<recording><session session_id=\"abc\"></session></recording>";
        // No --b1-- terminator
        let result = parse_siprec_body(ct, body);
        // Should succeed (graceful handling of missing terminator)
        assert!(
            result.is_ok(),
            "truncated body should parse gracefully: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().session_id.as_deref(), Some("abc"));
    }

    /// A boundary string occurring mid-line inside part content is NOT a
    /// delimiter (RFC 2046 §5.1.1: delimiters must start a line); the part
    /// content must survive intact.
    #[test]
    fn test_boundary_mid_line_content_not_split() {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\n\
Content-Type: application/rs-metadata+xml\r\n\r\n\
<recording><session session_id=\"abc\"><participant participant_id=\"p1\">\
<name>Acme--b1 Corp</name></participant></session></recording>\r\n\
--b1--";
        let result = parse_siprec_body(ct, body).unwrap();
        assert_eq!(result.session_id.as_deref(), Some("abc"));
        assert_eq!(result.participants.len(), 1);
        assert_eq!(
            result.participants[0].name.as_deref(),
            Some("Acme--b1 Corp")
        );
    }

    /// Direct split check: a mid-line boundary occurrence in an SDP part does
    /// not create extra parts, while line-anchored delimiters (including the
    /// closing `--b1--`) still split correctly.
    #[test]
    fn test_split_multipart_line_anchored_only() {
        let body = "--b1\r\n\
Content-Type: application/sdp\r\n\r\n\
v=0\r\ns=call--b1session\r\n\
--b1\r\n\
Content-Type: text/plain\r\n\r\n\
hello\r\n\
--b1--";
        let parts = split_multipart(body, "b1");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].content_type.as_deref(), Some("application/sdp"));
        assert!(
            parts[0].body.contains("s=call--b1session"),
            "mid-line boundary must survive intact, got: {:?}",
            parts[0].body
        );
        assert_eq!(parts[1].body.trim(), "hello");
    }

    /// Bare-LF line endings are still tolerated for delimiter anchoring.
    #[test]
    fn test_split_multipart_bare_lf_delimiters() {
        let body = "--b1\n\
Content-Type: application/sdp\n\n\
v=0\n\
--b1\n\
Content-Type: text/plain\n\n\
world\n\
--b1--";
        let parts = split_multipart(body, "b1");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].body.trim(), "world");
    }

    /// Preamble text before the first delimiter does not break part
    /// extraction (first delimiter anchored by the preamble's CRLF).
    #[test]
    fn test_split_multipart_with_preamble() {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"preamble text\r\n\
--b1\r\n\
Content-Type: application/rs-metadata+xml\r\n\r\n\
<recording><session session_id=\"xyz\"></session></recording>\r\n\
--b1--";
        let result = parse_siprec_body(ct, body).unwrap();
        assert_eq!(result.session_id.as_deref(), Some("xyz"));
    }

    /// Malformed XML degrades to default metadata instead of failing.
    #[test]
    fn test_malformed_xml() {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\nContent-Type: application/rs-metadata+xml\r\n\r\n\
<not-valid-xml";
        // Should return Ok with empty/default metadata, not panic
        let result = parse_siprec_body(ct, body);
        assert!(result.is_ok());
    }
}
