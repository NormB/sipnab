//! SIPREC metadata parsing (RFC 7866).
//!
//! Parses multipart/mixed SIP bodies to extract recording metadata
//! from the application/rs-metadata+xml MIME part.

use anyhow::{Result, bail};

/// Parsed SIPREC recording metadata.
#[derive(Debug, Clone, Default)]
pub struct SirecMetadata {
    pub session_id: Option<String>,
    pub participants: Vec<SirecParticipant>,
    pub streams: Vec<SirecStream>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SirecParticipant {
    pub participant_id: Option<String>,
    pub aor: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SirecStream {
    pub stream_id: Option<String>,
    pub label: Option<String>,
    pub participant_id: Option<String>,
}

struct MimePart {
    content_type: Option<String>,
    body: String,
}

/// Extract boundary parameter from a Content-Type header value.
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
fn split_multipart(body: &str, boundary: &str) -> Vec<MimePart> {
    let delimiter = format!("--{}", boundary);
    let mut parts = Vec::new();

    for segment in body.split(&delimiter) {
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
/// (e.g., `"name"` won't match `<nameID>`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_boundary() {
        let ct = "multipart/mixed; boundary=uniqueBoundary";
        assert_eq!(extract_boundary(ct), Some("uniqueBoundary".to_string()));
    }

    #[test]
    fn test_extract_boundary_quoted() {
        let ct = r#"multipart/mixed; boundary="unique-Boundary""#;
        assert_eq!(extract_boundary(ct), Some("unique-Boundary".to_string()));
    }

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

    #[test]
    fn test_no_metadata_part() {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--";
        assert!(parse_siprec_body(ct, body).is_err());
    }

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
