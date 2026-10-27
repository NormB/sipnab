// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! SIPREC metadata parsing (RFC 7866).
//!
//! Parses multipart/mixed SIP bodies to extract recording metadata
//! from the application/rs-metadata+xml MIME part.

use anyhow::{Result, bail};
use serde::Serialize;

/// Parsed SIPREC recording metadata.
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SirecMetadata {
    /// Recording session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Participants captured in the recording metadata.
    pub participants: Vec<SirecParticipant>,
    /// Media streams described by the metadata.
    pub streams: Vec<SirecStream>,
    /// Recording mode (e.g. "complete").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// A participant in a SIPREC-recorded session.
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SirecParticipant {
    /// Participant identifier from the metadata XML.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
    /// Address-of-record (SIP URI) of the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aor: Option<String>,
    /// Display name of the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A media stream described by SIPREC metadata.
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SirecStream {
    /// Stream identifier from the metadata XML.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    /// SDP label associating the stream with an m-line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Participant this stream belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
}

/// One part of a multipart MIME body: its Content-Type and its bytes.
pub(crate) struct MimePart {
    /// Value of the part's `Content-Type` header, if present.
    pub(crate) content_type: Option<String>,
    /// The part's body: every byte after its blank line, up to the line break
    /// that belongs to the next delimiter. A part may be binary
    /// ([RFC 3204 section 3.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-3.1)
    /// encodes ISUP as "binary"), so this is bytes, not text.
    pub(crate) body: Vec<u8>,
}

impl MimePart {
    /// The body as text, or `None` when it is not UTF-8.
    pub(crate) fn text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}

/// Extract the `boundary=` parameter from a Content-Type header value.
///
/// Handles both quoted (`boundary="x"`) and bare (`boundary=x`) forms.
/// Returns `None` when no boundary parameter is present.
pub(crate) fn extract_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|param| {
        // RFC 2045 §5.1: parameter names are case-insensitive, so match the
        // `boundary` name without regard to case (a `BOUNDARY=` was missed),
        // then strip a quoted value.
        let (name, value) = param.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(value);
        Some(value.to_string())
    })
}

/// Split a multipart body into MIME parts using the given boundary, by
/// [RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1).
///
/// # Arguments
///
/// * `body` — the full multipart body, as bytes: a part may be binary.
/// * `boundary` — the boundary token (without the leading `--`).
///
/// # Returns
///
/// One `MimePart` per body part between the first delimiter and the close
/// delimiter, each with its `Content-Type` (if any) and its bytes.
///
/// - A delimiter is `--boundary` at the start of a line, followed by
///   optional linear white space and the line break, or by `--` for the
///   close delimiter. A `--boundary` inside a line, or followed by other
///   text, is part content.
/// - The line break before a delimiter belongs to the delimiter, not to the
///   part before it ("the CRLF preceding the boundary delimiter line is
///   conceptually attached to the boundary").
/// - The preamble before the first delimiter and the epilogue after the close
///   delimiter "are to be ignored".
/// - A missing close delimiter is tolerated: the last part runs to the end of
///   the body. Bare-LF line breaks are tolerated beside CRLF. A part with
///   nothing in it but white space is skipped.
pub(crate) fn split_multipart(body: &[u8], boundary: &str) -> Vec<MimePart> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();

    // Every delimiter line: where it starts, where its part's bytes start,
    // and whether it is the close delimiter.
    let mut lines: Vec<(usize, usize, bool)> = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = memchr::memmem::find(&body[search_from..], delimiter) {
        let pos = search_from + rel;
        search_from = pos + delimiter.len();
        if pos != 0 && body[pos - 1] != b'\n' {
            continue;
        }
        let after = &body[pos + delimiter.len()..];
        if after.starts_with(b"--") {
            lines.push((pos, body.len(), true));
            break;
        }
        // Transport padding, then the line break, or the end of the body.
        let padding = after
            .iter()
            .take_while(|b| **b == b' ' || **b == b'\t')
            .count();
        let rest = &after[padding..];
        let line_break = if rest.starts_with(b"\r\n") {
            2
        } else if rest.starts_with(b"\n") || rest.is_empty() {
            usize::from(!rest.is_empty())
        } else {
            continue;
        };
        lines.push((pos, pos + delimiter.len() + padding + line_break, false));
    }

    let mut parts = Vec::new();
    for (i, &(_, part_start, close)) in lines.iter().enumerate() {
        if close {
            break;
        }
        let part_end = lines.get(i + 1).map_or(body.len(), |next| next.0);
        let mut segment = &body[part_start..part_end];
        // The line break before the next delimiter is the delimiter's.
        if lines.get(i + 1).is_some() {
            segment = segment
                .strip_suffix(b"\r\n")
                .or_else(|| segment.strip_suffix(b"\n"))
                .unwrap_or(segment);
        }
        if segment.trim_ascii().is_empty() {
            continue;
        }

        // Headers end at the first blank line. A part that starts with the
        // blank line has no headers; one with no blank line at all is read
        // as a body with no headers, which is how this reader always
        // treated it.
        let (headers_part, body_part): (&[u8], &[u8]) = if let Some(b) = segment
            .strip_prefix(b"\r\n")
            .or_else(|| segment.strip_prefix(b"\n"))
        {
            (b"", b)
        } else if let Some(pos) = memchr::memmem::find(segment, b"\r\n\r\n") {
            (&segment[..pos], &segment[pos + 4..])
        } else if let Some(pos) = memchr::memmem::find(segment, b"\n\n") {
            (&segment[..pos], &segment[pos + 2..])
        } else {
            (b"", segment)
        };

        let headers_text = String::from_utf8_lossy(headers_part);
        let content_type = unfold_header_lines(&headers_text)
            .into_iter()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("content-type:") {
                    Some(line[13..].trim().to_string())
                } else {
                    None
                }
            });

        parts.push(MimePart {
            content_type,
            body: body_part.to_vec(),
        });
    }

    parts
}

/// Unfold RFC 5322 folded header lines within a MIME part's header block.
///
/// A line beginning with SP or HTAB is a continuation of the preceding header;
/// unfolding removes the intervening line break while keeping the continuation's
/// leading whitespace. Returns one string per logical header.
fn unfold_header_lines(headers: &str) -> Vec<String> {
    let mut logical: Vec<String> = Vec::new();
    for raw in headers.lines() {
        if raw.starts_with([' ', '\t'])
            && let Some(last) = logical.last_mut()
        {
            last.push_str(raw);
        } else {
            logical.push(raw.to_string());
        }
    }
    logical
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
        // RFC 7866 §7 names this element `datamode`, and OpenSIPS's siprec
        // module writes exactly that. `<mode>` is kept as a fallback for any
        // SRC that emits the shorter spelling; neither pattern can match the
        // other, since the scan anchors on `<datamode` and `<mode`.
        mode: extract_xml_content(xml, "datamode").or_else(|| extract_xml_content(xml, "mode")),
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
                // RFC 7865 defines the AOR as an `aor` attribute on `<nameID>`;
                // that canonical attribute form takes precedence over the
                // non-standard `<aor>` child element and the nameID content.
                aor: extract_nameid_aor(block)
                    .or_else(|| extract_xml_content(block, "aor"))
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

    // Ownership: which participant each stream belongs to.
    //
    // Nothing inside `<stream>` says so. RFC 7866 puts the association in
    // `<participantstreamassoc participant_id="...">`, whose `<send>` children
    // name the streams that participant originates and whose `<recv>` children
    // name the ones it merely hears -- so `send` is ownership and `recv` is
    // not. Without this the field is None on every stream a real SRC sends,
    // which is the whole route from a recorded stream back to the person on
    // it. The in-stream `<participant>` element read below stays as a fallback
    // for SRCs that write one; the assoc is authoritative where both appear.
    let mut search_from = 0;
    while let Some(start) = xml[search_from..].find("<participantstreamassoc") {
        let abs_start = search_from + start;
        let Some(end) = xml[abs_start..].find("</participantstreamassoc>") else {
            break;
        };
        let block = &xml[abs_start..abs_start + end];
        if let Some(owner) = extract_xml_attr(block, "participant_id") {
            for sent in extract_all_xml_content(block, "send") {
                for stream in &mut metadata.streams {
                    if stream.stream_id.as_deref() == Some(sent.as_str()) {
                        stream.participant_id = Some(owner.clone());
                    }
                }
            }
        }
        search_from = abs_start + end + "</participantstreamassoc>".len();
    }

    Ok(metadata)
}

/// Every `<tag>...</tag>` content in `xml`, in document order.
///
/// [`extract_xml_content`] returns only the first, which is right for a field
/// that appears once and wrong for `<send>`: a participant sending both audio
/// and video has two, and reading one would leave the other stream unowned.
///
/// Walks the elements itself rather than calling the single-value reader in a
/// loop. That loop had two defects, both of which lost associations silently:
/// it stopped at the first element with empty content, because the reader
/// answers `None` for one and the loop read `None` as "no more"; and it
/// advanced by searching for the next closing tag from the start of the
/// remainder, so a self-closing `<send/>` -- which has no closing tag --
/// consumed the following element's and reported `<send>s1` as a stream id.
///
/// Empty and self-closing elements are skipped and the scan continues. Neither
/// names a stream, and neither is a reason to stop reading the ones that do.
fn extract_all_xml_content(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut i = 0usize;

    while let Some(rel) = xml[i..].find(&open) {
        let start = i + rel;
        let after = start + open.len();
        // Exact tag name, not a prefix: `<sendmode>` is not a `<send>`.
        let delim = xml.as_bytes().get(after).copied();
        if !matches!(delim, Some(b'>' | b' ' | b'\t' | b'\r' | b'\n' | b'/')) {
            i = after;
            continue;
        }
        let Some(gt_rel) = xml[start..].find('>') else {
            break;
        };
        let gt = start + gt_rel;
        if xml[start..gt].ends_with('/') {
            // Self-closing: no content and no closing tag. Step over it.
            i = gt + 1;
            continue;
        }
        let content_start = gt + 1;
        let Some(close_rel) = xml[content_start..].find(&close) else {
            break;
        };
        let content_end = content_start + close_rel;
        let content = xml[content_start..content_end].trim();
        if !content.is_empty() {
            out.push(content.to_string());
        }
        i = content_end + close.len();
    }
    out
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

/// Extract the RFC 7865 `aor` attribute from a participant's `<nameID>` opening
/// tag (e.g. `<nameID aor="sip:alice@example.com">`).
///
/// Scoped to the `<nameID>` start tag so it cannot match an `aor` attribute
/// that might appear elsewhere in the participant block.
fn extract_nameid_aor(block: &str) -> Option<String> {
    let start = block.find("<nameID")?;
    let tag_end = block[start..].find('>')? + start;
    extract_xml_attr(&block[start..tag_end], "aor")
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
/// Fails when the Content-Type has no `boundary` parameter, no `rs-metadata`
/// part is found in the multipart body, or that part is not valid UTF-8.
/// Another part may be binary.
pub fn parse_siprec_body(content_type: &str, body: &[u8]) -> Result<SirecMetadata> {
    let boundary = extract_boundary(content_type)
        .ok_or_else(|| anyhow::anyhow!("no boundary in content-type"))?;

    for part in split_multipart(body, &boundary) {
        if part
            .content_type
            .as_deref()
            .is_some_and(is_rs_metadata_type)
        {
            let xml = part
                .text()
                .ok_or_else(|| anyhow::anyhow!("the rs-metadata part is not UTF-8"))?;
            return parse_rs_metadata(xml);
        }
    }

    bail!("no rs-metadata+xml part found in multipart body")
}

/// The recording metadata a SIP message carries, when it carries any.
///
/// The one rule for "this message describes a recording": a `multipart/mixed`
/// body with an `rs-metadata` part that [`parse_siprec_body`] reads. The
/// dialog store keeps the newest such message's metadata, and the vCon export
/// finds that message again with the same rule, so the two cannot disagree
/// about which message described the recording.
#[must_use]
pub fn metadata_of(msg: &crate::sip::SipMessage) -> Option<SirecMetadata> {
    let ct = msg.content_type()?;
    if !media_type_of(ct).eq_ignore_ascii_case("multipart/mixed") {
        return None;
    }
    parse_siprec_body(ct, &msg.body).ok()
}

/// The type and subtype of a `Content-Type` value, without its parameters.
fn media_type_of(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

/// Whether a part's `Content-Type` is the recording metadata:
/// `application/rs-metadata+xml`, the type [RFC 7865 section 5](https://www.rfc-editor.org/rfc/rfc7865.html#section-5)
/// names, or `application/rs-metadata`, as the examples in
/// [RFC 7866 section 9.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-9.1) write it. Matched in any case
/// ([RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1)), on the type and subtype only.
fn is_rs_metadata_type(content_type: &str) -> bool {
    media_type_of(content_type)
        .to_ascii_lowercase()
        .contains("rs-metadata")
}

/// One media description of a SIPREC message's SDP that carries an `a=label`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabeledStream {
    /// The `a=label` pointer, which the metadata's `<stream><label>` names.
    pub label: String,
    /// The address and port the media description names, when both parse.
    ///
    /// `None` for port 0, which [RFC 7866 section 7.1.1.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-7.1.1.1)
    /// uses to remove a recorded stream: nothing is sent from it.
    pub socket: Option<std::net::SocketAddr>,
}

/// Every labeled media description in the `application/sdp` part of a SIPREC
/// multipart body, in `m=` line order.
///
/// Read from the SAME body as the metadata on purpose.
/// [RFC 7866 section 7.1.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-7.1.1):
/// "The scope of the "a=label" attribute only applies to the SDP and metadata
/// conveyed in the bodies of the SIP request or response that the label
/// appeared in." A label from another message's SDP may name another stream.
///
/// The SDP part is the one [`crate::sip::SipMessage::sdp`] reads, by the same
/// rule. Empty when the body has no boundary, no SDP part, or an SDP part that
/// does not parse.
#[must_use]
pub fn labeled_streams(content_type: &str, body: &[u8]) -> Vec<LabeledStream> {
    let Some(session) = crate::sip::message::multipart_sdp(content_type, body) else {
        return Vec::new();
    };
    session
        .media
        .iter()
        .filter_map(|media| {
            let label = media.label.clone()?;
            let socket = (media.port != 0)
                .then(|| crate::sip::sdp::effective_address(media, &session))
                .flatten()
                .and_then(|addr| addr.parse().ok())
                .map(|ip| std::net::SocketAddr::new(ip, media.port));
            Some(LabeledStream { label, socket })
        })
        .collect()
}

/// Tests for boundary extraction, multipart splitting, and SIPREC metadata
/// parsing including truncated and malformed bodies.
#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A bare boundary parameter is extracted from Content-Type.
    #[test]
    fn test_extract_boundary() -> Result<(), TestError> {
        let ct = "multipart/mixed; boundary=uniqueBoundary";
        assert_eq!(extract_boundary(ct), Some("uniqueBoundary".to_string()));
        Ok(())
    }

    /// A quoted boundary parameter is extracted without the quotes.
    #[test]
    fn test_extract_boundary_quoted() -> Result<(), TestError> {
        let ct = r#"multipart/mixed; boundary="unique-Boundary""#;
        assert_eq!(extract_boundary(ct), Some("unique-Boundary".to_string()));
        Ok(())
    }

    /// The `boundary` parameter name is case-insensitive ([RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1)), so an
    /// uppercase or mixed-case `BOUNDARY=` is still recognized.
    #[test]
    fn test_extract_boundary_case_insensitive() -> Result<(), TestError> {
        assert_eq!(
            extract_boundary("multipart/mixed; BOUNDARY=upperCase"),
            Some("upperCase".to_string())
        );
        assert_eq!(
            extract_boundary(r#"multipart/mixed; Boundary="Mixed-Case""#),
            Some("Mixed-Case".to_string())
        );
        Ok(())
    }

    /// A full SDP+metadata multipart body yields session, participant, and
    /// stream fields.
    #[test]
    fn test_parse_siprec_body() -> Result<(), TestError> {
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

        let result = parse_siprec_body(ct, body)?;
        assert_eq!(result.session_id.as_deref(), Some("abc123"));
        assert_eq!(result.participants.len(), 1);
        assert_eq!(result.participants[0].name.as_deref(), Some("Alice"));
        assert_eq!(result.streams.len(), 1);
        assert_eq!(result.streams[0].label.as_deref(), Some("audio"));
        Ok(())
    }

    /// The metadata OpenSIPS's `siprec` module actually emits.
    ///
    /// Built from `modules/siprec/siprec_body.c::srs_build_xml` rather than
    /// from a reading of RFC 7866, because the packets sipnab has to read are
    /// the ones a real SRC sends. The earlier fixture in this file was written
    /// by hand and nests `<participant>` and `<stream>` inside `<session>`
    /// with `<aor>` as a child element; OpenSIPS emits them as siblings of
    /// `<session>` with `aor` an attribute of `<nameID>`, and associates a
    /// stream to a participant only through `<participantstreamassoc>`.
    ///
    /// Two participants and three streams, so the audio/video case is present:
    /// Alice sends two streams whose labels are the `m=` line indices, which
    /// is the whole reason a label is worth carrying.
    fn opensips_metadata() -> &'static str {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<recording xmlns='urn:ietf:params:xml:ns:recording:1'>\r\n\t\
<datamode>complete</datamode>\r\n\t\
<session session_id=\"sess-1\">\r\n\t\t\
<sipSessionID>call-abc@example.invalid</sipSessionID>\r\n\t\
</session>\r\n\
\t<participant participant_id=\"p-alice\">\r\n\t\t\
<nameID aor=\"sip:alice@example.invalid\">\r\n\t\t\t\
<name>Alice</name>\r\n\t\t</nameID>\r\n\t</participant>\r\n\
\t<participant participant_id=\"p-bob\">\r\n\t\t\
<nameID aor=\"sip:bob@example.invalid\"/>\r\n\t</participant>\r\n\
\t<stream stream_id=\"s-alice-audio\" session_id=\"sess-1\">\r\n\t\t\
<label>0</label>\r\n\t</stream>\r\n\
\t<stream stream_id=\"s-alice-video\" session_id=\"sess-1\">\r\n\t\t\
<label>1</label>\r\n\t</stream>\r\n\
\t<stream stream_id=\"s-bob-audio\" session_id=\"sess-1\">\r\n\t\t\
<label>2</label>\r\n\t</stream>\r\n\
\t<sessionrecordingassoc session_id=\"sess-1\">\r\n\t\t\
<associate-time>2026-09-04T12:00:00-0400</associate-time>\r\n\t\
</sessionrecordingassoc>\r\n\
\t<participantsessionassoc participant_id=\"p-alice\" session_id=\"sess-1\">\r\n\t\t\
<associate-time>2026-09-04T12:00:00-0400</associate-time>\r\n\t\
</participantsessionassoc>\r\n\
\t<participantstreamassoc participant_id=\"p-alice\">\r\n\t\t\
<send>s-alice-audio</send>\r\n\t\t<send>s-alice-video</send>\r\n\t\t\
<recv>s-bob-audio</recv>\r\n\t</participantstreamassoc>\r\n\
\t<participantstreamassoc participant_id=\"p-bob\">\r\n\t\t\
<send>s-bob-audio</send>\r\n\t\t<recv>s-alice-audio</recv>\r\n\t\
</participantstreamassoc>\r\n\
</recording>\r\n"
    }

    /// Wrap metadata in the multipart body OpenSIPS sends it in.
    fn opensips_body() -> Vec<u8> {
        format!(
            "--OSS\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\
             --OSS\r\nContent-Type: application/rs-metadata+xml\r\n\r\n{}\r\n--OSS--",
            opensips_metadata()
        )
        .into_bytes()
    }

    /// The recording mode is in `<datamode>`, which is what RFC 7866 defines
    /// and what OpenSIPS emits. Looking for `<mode>` finds nothing.
    #[test]
    fn the_recording_mode_comes_from_datamode() -> Result<(), TestError> {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())?;
        assert_eq!(
            md.mode.as_deref(),
            Some("complete"),
            "the mode an SRC declares is <datamode>, not <mode>"
        );
        Ok(())
    }

    /// A stream belongs to the participant that SENDS it.
    ///
    /// This is the field that makes the metadata worth surfacing: it is the
    /// only route from a recorded stream back to the person on it. OpenSIPS
    /// puts nothing inside `<stream>` naming a participant -- the association
    /// lives in `<participantstreamassoc>`, whose `<send>` children name the
    /// streams that participant originates.
    #[test]
    fn a_stream_is_owned_by_the_participant_that_sends_it() -> Result<(), TestError> {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())?;
        let owner = |id: &str| -> Result<_, TestError> {
            Ok(md
                .streams
                .iter()
                .find(|s| s.stream_id.as_deref() == Some(id))
                .ok_or_else(|| format!("stream {id} parsed"))?
                .participant_id
                .clone())
        };
        assert_eq!(owner("s-alice-audio")?.as_deref(), Some("p-alice"));
        assert_eq!(
            owner("s-alice-video")?.as_deref(),
            Some("p-alice"),
            "a participant's second stream is theirs too -- this is the audio \
             and video case, where each label is an m= line index"
        );
        assert_eq!(
            owner("s-bob-audio")?.as_deref(),
            Some("p-bob"),
            "and a stream only Bob sends is Bob's, though Alice receives it"
        );
        Ok(())
    }

    /// Every participant and stream OpenSIPS emits is found, with its label.
    #[test]
    fn every_participant_and_stream_opensips_emits_is_found() -> Result<(), TestError> {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())?;
        assert_eq!(md.session_id.as_deref(), Some("sess-1"));
        assert_eq!(md.participants.len(), 2, "two participants");
        assert_eq!(md.streams.len(), 3, "three streams");
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:alice@example.invalid")
        );
        assert_eq!(md.participants[0].name.as_deref(), Some("Alice"));
        let labels: Vec<_> = md
            .streams
            .iter()
            .filter_map(|s| s.label.as_deref())
            .collect();
        assert_eq!(
            labels,
            ["0", "1", "2"],
            "labels are the m= line indices, carried verbatim"
        );
        Ok(())
    }

    /// A participant whose `<nameID>` is self-closing still yields its AOR.
    ///
    /// OpenSIPS writes `<nameID aor="..."/>` when it has no display name for
    /// the party, which is the common case for the callee.
    #[test]
    fn a_self_closing_nameid_still_yields_its_aor() -> Result<(), TestError> {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())?;
        let bob = &md.participants[1];
        assert_eq!(bob.aor.as_deref(), Some("sip:bob@example.invalid"));
        assert_eq!(
            bob.name, None,
            "no display name was sent, so none is invented"
        );
        Ok(())
    }

    /// `<participantsessionassoc>` and `<participantstreamassoc>` are not
    /// participants.
    ///
    /// Both start with the same eleven characters as `<participant`, and the
    /// scan that finds participants is a substring search. Counting them as
    /// participants would double a call's party list.
    #[test]
    fn an_assoc_element_is_not_mistaken_for_a_participant() -> Result<(), TestError> {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())?;
        assert_eq!(
            md.participants.len(),
            2,
            "exactly the two <participant> elements, not the assoc blocks: {:?}",
            md.participants
        );
        assert!(
            md.participants
                .iter()
                .all(|p| p.aor.is_some() || p.name.is_some()),
            "an assoc block would parse as a participant with neither: {:?}",
            md.participants
        );
        Ok(())
    }

    /// An assoc naming a stream the metadata never described owns nothing.
    ///
    /// The two lists are independent in the XML, and an SRC that renumbers
    /// mid-session can emit a `<send>` for a stream this snapshot does not
    /// carry. Inventing a stream to hang the id on would put a row in front of
    /// an operator that no SRC ever sent.
    #[test]
    fn an_assoc_naming_an_unknown_stream_owns_nothing() -> Result<(), TestError> {
        let xml = "<recording><datamode>complete</datamode>\
<stream stream_id=\"known\"><label>0</label></stream>\
<participantstreamassoc participant_id=\"p1\"><send>never-described</send>\
</participantstreamassoc></recording>";
        let md = parse_rs_metadata(xml)?;
        assert_eq!(
            md.streams.len(),
            1,
            "no stream is invented: {:?}",
            md.streams
        );
        assert_eq!(
            md.streams[0].participant_id, None,
            "and the one real stream stays unowned, because nothing claimed it"
        );
        Ok(())
    }

    /// A stream no assoc claims has no owner, rather than a guessed one.
    ///
    /// One participant in the metadata is not evidence that this stream is
    /// theirs: a recording with two parties and one described stream is
    /// exactly the case where guessing picks wrong half the time.
    #[test]
    fn a_stream_no_assoc_claims_has_no_owner() -> Result<(), TestError> {
        let xml = "<recording>\
<participant participant_id=\"p1\"><nameID aor=\"sip:a@b\"/></participant>\
<stream stream_id=\"s1\"><label>0</label></stream></recording>";
        let md = parse_rs_metadata(xml)?;
        assert_eq!(md.streams.len(), 1);
        assert_eq!(
            md.streams[0].participant_id, None,
            "a single participant is not a reason to assign the stream to them"
        );
        Ok(())
    }

    /// When two participants both send one stream, the last assoc read wins.
    ///
    /// RFC 7866 gives one sender per stream, so this is malformed input rather
    /// than a case with a right answer. What matters is that it is
    /// deterministic and that neither claim silently disappears into a panic.
    #[test]
    fn the_last_assoc_wins_when_two_claim_one_stream() -> Result<(), TestError> {
        let xml = "<recording>\
<stream stream_id=\"s1\"><label>0</label></stream>\
<participantstreamassoc participant_id=\"p1\"><send>s1</send></participantstreamassoc>\
<participantstreamassoc participant_id=\"p2\"><send>s1</send></participantstreamassoc>\
</recording>";
        let md = parse_rs_metadata(xml)?;
        assert_eq!(
            md.streams[0].participant_id.as_deref(),
            Some("p2"),
            "document order decides, so the same input always reads the same way"
        );
        Ok(())
    }

    /// A metadata part delimited with bare LF parses.
    ///
    /// SIP is CRLF on the wire, but a body that has been through a text tool,
    /// a log, or a test fixture may not be, and the boundary scan already
    /// tolerates it. The XML reading must not be stricter than the framing.
    #[test]
    fn metadata_delimited_with_bare_lf_still_parses() -> Result<(), TestError> {
        let ct = "multipart/mixed; boundary=b";
        let body = b"--b\nContent-Type: application/rs-metadata+xml\n\n\
<recording><datamode>complete</datamode>\
<session session_id=\"s\"/></recording>\n--b--";
        let md = parse_siprec_body(ct, body)?;
        assert_eq!(md.session_id.as_deref(), Some("s"));
        assert_eq!(md.mode.as_deref(), Some("complete"));
        Ok(())
    }

    /// A multipart Content-Type with no boundary parameter is refused.
    ///
    /// Without a boundary there is no way to find the metadata part, and
    /// guessing one would either find nothing or find the wrong bytes. The
    /// error is the honest answer.
    #[test]
    fn a_multipart_content_type_with_no_boundary_is_refused() -> Result<(), TestError> {
        assert!(
            parse_siprec_body("multipart/mixed", b"--x\r\n\r\n<recording/>\r\n--x--").is_err(),
            "a body that cannot be split must not report empty metadata"
        );
        Ok(())
    }

    /// The all-occurrences reader returns every match, in document order.
    ///
    /// [`extract_xml_content`] answers with the first, which is right for a
    /// field that appears once and wrong for `<send>`. This is the difference
    /// between a participant owning one stream and owning both.
    #[test]
    fn extract_all_xml_content_returns_every_occurrence_in_order() -> Result<(), TestError> {
        let block = "<a><send>one</send><send>two</send><send>three</send></a>";
        assert_eq!(
            extract_all_xml_content(block, "send"),
            ["one", "two", "three"]
        );
        assert!(
            extract_all_xml_content("<a/>", "send").is_empty(),
            "no matches is an empty list, not a panic"
        );
        assert_eq!(
            extract_all_xml_content("<a><send>only</send></a>", "send"),
            ["only"],
            "and a single match still comes back"
        );
        Ok(())
    }

    /// An empty element must not end the scan.
    ///
    /// `extract_xml_content` answers `None` for an element with no content,
    /// and the all-occurrences loop treats `None` as "no more". So one
    /// `<send></send>` anywhere in the list silently discards every stream
    /// after it, and the participant is reported owning fewer streams than the
    /// SRC said. Losing an association is worse than reporting none: the
    /// operator sees a plausible answer with a stream missing from it.
    #[test]
    fn an_empty_element_does_not_end_the_scan() -> Result<(), TestError> {
        assert_eq!(
            extract_all_xml_content("<a><send></send><send>s1</send></a>", "send"),
            ["s1"],
            "an empty first element must be skipped, not treated as the end"
        );
        assert_eq!(
            extract_all_xml_content("<a><send>s1</send><send></send><send>s2</send></a>", "send"),
            ["s1", "s2"],
            "and an empty one in the middle must not drop what follows"
        );
        assert_eq!(
            extract_all_xml_content("<a><send>   </send><send>s3</send></a>", "send"),
            ["s3"],
            "whitespace-only content is empty too, and just as fatal to the scan"
        );
        Ok(())
    }

    /// A longer tag that starts with this one's name is a different tag.
    ///
    /// `<sendonly>` shares four characters with `<send>`, and a scan that
    /// matched on the prefix would read its content as a stream id -- then
    /// look for `</send>`, not find one there, and run on into the next real
    /// element. The guard is one `matches!` on the delimiter, and nothing
    /// tested it until a mutation removed it and every test stayed green.
    #[test]
    fn a_tag_whose_name_merely_starts_the_same_is_not_matched() -> Result<(), TestError> {
        assert_eq!(
            extract_all_xml_content("<a><sendonly>no</sendonly><send>s1</send></a>", "send"),
            ["s1"],
            "<sendonly> is not a <send>"
        );
        assert_eq!(
            extract_all_xml_content("<a><sendonly>no</sendonly></a>", "send"),
            Vec::<String>::new(),
            "and with no real <send> present the answer is none, not the \
             longer tag's content"
        );
        Ok(())
    }

    /// A self-closing element must not swallow the next one's content.
    ///
    /// `<send/>` has no closing tag. The scan looks for `</send>` and finds
    /// the NEXT element's, so a self-closing entry can consume the following
    /// stream id and report it as the first one's.
    #[test]
    fn a_self_closing_element_does_not_swallow_the_next() -> Result<(), TestError> {
        assert_eq!(
            extract_all_xml_content("<a><send/><send>s1</send></a>", "send"),
            ["s1"],
            "a self-closing element carries no id, and must not be credited \
             with the following one's"
        );
        Ok(())
    }

    /// A participant that sends one stream after an empty entry still owns it.
    ///
    /// The end-to-end shape of the bug above: ownership is resolved from the
    /// `<send>` list, so a dropped entry leaves a real stream unowned while
    /// every other field looks right.
    #[test]
    fn an_empty_send_does_not_orphan_the_streams_after_it() -> Result<(), TestError> {
        let xml = "<recording>\
<stream stream_id=\"s1\"><label>0</label></stream>\
<stream stream_id=\"s2\"><label>1</label></stream>\
<participantstreamassoc participant_id=\"p1\">\
<send></send><send>s1</send><send>s2</send>\
</participantstreamassoc></recording>";
        let md = parse_rs_metadata(xml)?;
        let owner = |id: &str| {
            md.streams
                .iter()
                .find(|s| s.stream_id.as_deref() == Some(id))
                .and_then(|s| s.participant_id.clone())
        };
        assert_eq!(owner("s1").as_deref(), Some("p1"));
        assert_eq!(
            owner("s2").as_deref(),
            Some("p1"),
            "both streams are p1's; an empty <send> must not orphan them"
        );
        Ok(())
    }

    /// The SDP part of [RFC 7866 section 7.1.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-7.1.1)'s
    /// Figure 5, audio lines only, with a removed stream added.
    fn labeled_body() -> Vec<u8> {
        format!(
            "--OSS\r\nContent-Type: application/sdp\r\n\r\n\
             v=0\r\no=SRC 2890844526 2890844526 IN IP4 198.51.100.1\r\ns=-\r\n\
             c=IN IP4 198.51.100.1\r\nt=0 0\r\n\
             m=audio 12240 RTP/AVP 0 4 8\r\na=sendonly\r\na=label:1\r\n\
             m=audio 12242 RTP/AVP 0 4 8\r\na=sendonly\r\na=label:3\r\n\
             m=audio 0 RTP/AVP 0\r\na=label:5\r\n\
             m=audio 12246 RTP/AVP 0\r\n\
             --OSS\r\nContent-Type: application/rs-metadata+xml\r\n\r\n{}\r\n--OSS--",
            opensips_metadata()
        )
        .into_bytes()
    }

    /// Each labeled m-line of the SDP part yields its label and the socket it
    /// names, in m-line order. An unlabeled line yields nothing, and a removed
    /// one (port 0) keeps its label with no socket.
    #[test]
    fn the_sdp_part_yields_each_label_with_its_socket() -> Result<(), TestError> {
        let streams = labeled_streams("multipart/mixed; boundary=OSS", &labeled_body());
        assert_eq!(
            streams,
            [
                LabeledStream {
                    label: "1".into(),
                    socket: Some("198.51.100.1:12240".parse()?),
                },
                LabeledStream {
                    label: "3".into(),
                    socket: Some("198.51.100.1:12242".parse()?),
                },
                LabeledStream {
                    label: "5".into(),
                    socket: None,
                },
            ]
        );
        Ok(())
    }

    /// A SIP message from an SRC carrying `body` as `content_type`.
    fn src_message(content_type: &str, body: &[u8]) -> Result<crate::sip::SipMessage, TestError> {
        let ct = format!("Content-Type: {content_type}");
        let len = format!("Content-Length: {}", body.len());
        // Built here rather than with the shared test-message builder, which the wasm32
        // build does not compile and this module does.
        let mut raw = String::from("INVITE sip:srs@192.0.2.30 SIP/2.0\r\n");
        for h in [
            "Via: SIP/2.0/UDP 192.0.2.31:5060;branch=z9hG4bKcase",
            "From: <sip:src@192.0.2.31>;tag=s1",
            "To: <sip:srs@192.0.2.30>",
            "Call-ID: case@192.0.2.31",
            "CSeq: 1 INVITE",
            &ct,
            &len,
        ] {
            raw.push_str(h);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        let mut raw = raw.into_bytes();
        raw.extend_from_slice(body);
        Ok(crate::sip::parser::parse_sip(
            &raw,
            chrono::Utc::now(),
            std::net::IpAddr::from([192, 0, 2, 31]),
            std::net::IpAddr::from([192, 0, 2, 30]),
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )?)
    }

    /// [RFC 2045 section 5.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1):
    /// type and subtype are case-insensitive. A recording whose
    /// `Multipart/Mixed` body carries an `Application/RS-Metadata+XML` part is
    /// a recording, read by the rule the dialog store and the vCon export
    /// share.
    #[test]
    fn the_recording_types_are_matched_without_regard_to_case() -> Result<(), TestError> {
        let body = String::from_utf8(opensips_body())?.replace(
            "Content-Type: application/rs-metadata+xml",
            "Content-Type: Application/RS-Metadata+XML",
        );
        let md = parse_siprec_body("Multipart/Mixed; Boundary=OSS", body.as_bytes())?;
        assert!(md.session_id.is_some(), "the metadata part is read");
        let msg = src_message("Multipart/Mixed; boundary=OSS", body.as_bytes())?;
        assert!(
            metadata_of(&msg).is_some(),
            "the message describes a recording"
        );
        Ok(())
    }

    /// Negative controls. [RFC 7866 section 9.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-9.1):
    /// a message carrying SDP and metadata "MUST have content type
    /// "multipart/mixed"". Another multipart type is not a recording, and
    /// neither is a type that only names `multipart/mixed` inside a parameter.
    #[test]
    fn only_a_multipart_mixed_body_describes_a_recording() -> Result<(), TestError> {
        let body = opensips_body();
        let mixed = src_message("multipart/mixed; boundary=OSS", &body)?;
        assert!(metadata_of(&mixed).is_some(), "the ordinary case");
        for ct in [
            "multipart/alternative; boundary=OSS",
            "text/plain; note=\"multipart/mixed\"; boundary=OSS",
        ] {
            let msg = src_message(ct, &body)?;
            assert!(metadata_of(&msg).is_none(), "{ct} is not a recording");
        }
        Ok(())
    }

    /// A binary part beside the SDP and the metadata (a vendor extension
    /// body, or ISUP, which [RFC 3204 section 3.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-3.1)
    /// encodes as binary) hides neither: the labels and the metadata are both
    /// still read from the same body.
    #[test]
    fn a_binary_part_hides_neither_the_labels_nor_the_metadata() -> Result<(), TestError> {
        let mut body = labeled_body();
        let close = body.len() - b"--OSS--".len();
        body.truncate(close);
        body.extend_from_slice(b"--OSS\r\nContent-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(&[0x00, 0xff, 0xc3, 0x28, 0x0d, 0x0a, 0x80]);
        body.extend_from_slice(b"\r\n--OSS--");
        assert!(std::str::from_utf8(&body).is_err(), "the fixture is binary");
        let ct = "multipart/mixed; boundary=OSS";
        assert_eq!(labeled_streams(ct, &body).len(), 3);
        let md = parse_siprec_body(ct, &body)?;
        assert_eq!(md.participants.len(), 2);
        Ok(())
    }

    /// A binary part comes back byte for byte: the line break before the next
    /// delimiter is the delimiter's ([RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1):
    /// "the CRLF preceding the boundary delimiter line is conceptually
    /// attached to the boundary"), while a CR LF and a `--b` inside the part
    /// are content. Transport padding after a delimiter is not.
    #[test]
    fn a_binary_part_is_returned_byte_for_byte() -> Result<(), TestError> {
        let isup: &[u8] = &[0x01, 0x0d, 0x0a, 0x2d, 0x2d, 0x62, 0x80, 0x0d, 0x0a];
        let mut body = b"--b \t\r\nContent-Type: application/ISUP; version=itu-t\r\n\r\n".to_vec();
        body.extend_from_slice(isup);
        body.extend_from_slice(b"\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n");
        let parts = split_multipart(&body, "b");
        assert_eq!(parts.len(), 2);
        assert_eq!(
            parts[0].content_type.as_deref(),
            Some("application/ISUP; version=itu-t")
        );
        assert_eq!(parts[0].body, isup, "the ISUP bytes, exactly");
        assert_eq!(parts[1].body, b"x");
        Ok(())
    }

    /// A body with no SDP part, or none that parses, yields no labels.
    #[test]
    fn no_sdp_part_yields_no_labels() -> Result<(), TestError> {
        let only_metadata = format!(
            "--OSS\r\nContent-Type: application/rs-metadata+xml\r\n\r\n{}\r\n--OSS--",
            opensips_metadata()
        );
        assert!(
            labeled_streams("multipart/mixed; boundary=OSS", only_metadata.as_bytes()).is_empty()
        );
        assert!(
            labeled_streams("multipart/mixed", &labeled_body()).is_empty(),
            "no boundary, no parts"
        );
        Ok(())
    }

    /// A multipart body without an rs-metadata part is an error.
    #[test]
    fn test_no_metadata_part() -> Result<(), TestError> {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--";
        assert!(parse_siprec_body(ct, body).is_err());
        Ok(())
    }

    /// A body missing the final `--boundary--` terminator still parses.
    #[test]
    fn test_truncated_body_no_final_boundary() -> Result<(), TestError> {
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
        assert_eq!(result?.session_id.as_deref(), Some("abc"));
        Ok(())
    }

    /// A boundary string occurring mid-line inside part content is NOT a
    /// delimiter ([RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1): delimiters must start a line); the part
    /// content must survive intact.
    #[test]
    fn test_boundary_mid_line_content_not_split() -> Result<(), TestError> {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\n\
Content-Type: application/rs-metadata+xml\r\n\r\n\
<recording><session session_id=\"abc\"><participant participant_id=\"p1\">\
<name>Acme--b1 Corp</name></participant></session></recording>\r\n\
--b1--";
        let result = parse_siprec_body(ct, body)?;
        assert_eq!(result.session_id.as_deref(), Some("abc"));
        assert_eq!(result.participants.len(), 1);
        assert_eq!(
            result.participants[0].name.as_deref(),
            Some("Acme--b1 Corp")
        );
        Ok(())
    }

    /// Direct split check: a mid-line boundary occurrence in an SDP part does
    /// not create extra parts, while line-anchored delimiters (including the
    /// closing `--b1--`) still split correctly.
    #[test]
    fn test_split_multipart_line_anchored_only() -> Result<(), TestError> {
        let body = "--b1\r\n\
Content-Type: application/sdp\r\n\r\n\
v=0\r\ns=call--b1session\r\n\
--b1\r\n\
Content-Type: text/plain\r\n\r\n\
hello\r\n\
--b1--";
        let parts = split_multipart(body.as_bytes(), "b1");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].content_type.as_deref(), Some("application/sdp"));
        assert!(
            parts[0]
                .text()
                .is_some_and(|t| t.contains("s=call--b1session")),
            "mid-line boundary must survive intact, got: {:?}",
            parts[0].text()
        );
        assert_eq!(parts[1].text().map(str::trim), Some("hello"));
        Ok(())
    }

    /// Bare-LF line endings are still tolerated for delimiter anchoring.
    #[test]
    fn test_split_multipart_bare_lf_delimiters() -> Result<(), TestError> {
        let body = "--b1\n\
Content-Type: application/sdp\n\n\
v=0\n\
--b1\n\
Content-Type: text/plain\n\n\
world\n\
--b1--";
        let parts = split_multipart(body.as_bytes(), "b1");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].text().map(str::trim), Some("world"));
        Ok(())
    }

    /// Preamble text before the first delimiter does not break part
    /// extraction (first delimiter anchored by the preamble's CRLF).
    #[test]
    fn test_split_multipart_with_preamble() -> Result<(), TestError> {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"preamble text\r\n\
--b1\r\n\
Content-Type: application/rs-metadata+xml\r\n\r\n\
<recording><session session_id=\"xyz\"></session></recording>\r\n\
--b1--";
        let result = parse_siprec_body(ct, body)?;
        assert_eq!(result.session_id.as_deref(), Some("xyz"));
        Ok(())
    }

    /// A part whose `Content-Type` header is folded across lines
    /// (RFC 5322 continuation lines starting with SP/HTAB) is unfolded
    /// before parsing, so the full media type + parameters are recovered.
    #[test]
    fn test_split_multipart_unfolds_folded_content_type() -> Result<(), TestError> {
        // Note: the SP after `;\r\n` is written before the `\` line-continuation
        // so it survives in the literal — the continuation line genuinely starts
        // with a space (an RFC 5322 fold).
        let body = "--b1\r\n\
Content-Type: application/rs-metadata+xml;\r\n \
charset=\"utf-8\"\r\n\r\n\
<recording></recording>\r\n\
--b1--";
        assert!(
            body.contains(";\r\n charset"),
            "test fixture must contain a genuine folded (SP-prefixed) line"
        );
        let parts = split_multipart(body.as_bytes(), "b1");
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].content_type.as_deref(),
            Some("application/rs-metadata+xml; charset=\"utf-8\""),
            "folded Content-Type must be unfolded to its full value"
        );
        Ok(())
    }

    /// A folded HTAB continuation is also unfolded.
    #[test]
    fn test_split_multipart_unfolds_htab_continuation() -> Result<(), TestError> {
        // HTAB written before the `\` line-continuation so the fold survives.
        let body = "--b1\r\n\
Content-Type: application/rs-metadata+xml;\r\n\t\
charset=\"utf-8\"\r\n\r\n\
<recording></recording>\r\n\
--b1--";
        assert!(
            body.contains(";\r\n\tcharset"),
            "test fixture must contain a genuine HTAB-folded line"
        );
        let parts = split_multipart(body.as_bytes(), "b1");
        assert_eq!(parts.len(), 1);
        // Unfolding removes the line break but preserves the folding WSP, so the
        // HTAB is retained in the joined value (RFC 5322 §2.2.3).
        assert_eq!(
            parts[0].content_type.as_deref(),
            Some("application/rs-metadata+xml;\tcharset=\"utf-8\"")
        );
        Ok(())
    }

    /// RFC 7865 canonical participant AOR: the `aor` attribute on `<nameID>`.
    #[test]
    fn test_participant_aor_attribute_form() -> Result<(), TestError> {
        let xml = "<recording><participant participant_id=\"p1\">\
<nameID aor=\"sip:alice@example.com\"><name>Alice</name></nameID>\
</participant></recording>";
        let md = parse_rs_metadata(xml)?;
        assert_eq!(md.participants.len(), 1);
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:alice@example.com")
        );
        Ok(())
    }

    /// The non-standard `<aor>` child-element form remains supported.
    #[test]
    fn test_participant_aor_element_form_still_supported() -> Result<(), TestError> {
        let xml = "<recording><participant participant_id=\"p1\">\
<nameID><aor>sip:bob@example.com</aor></nameID></participant></recording>";
        let md = parse_rs_metadata(xml)?;
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:bob@example.com")
        );
        Ok(())
    }

    /// When both the RFC 7865 `aor` attribute and a non-standard `<aor>`
    /// child element are present, the canonical attribute wins.
    #[test]
    fn test_participant_aor_attribute_wins_over_element() -> Result<(), TestError> {
        let xml = "<recording><participant participant_id=\"p1\">\
<nameID aor=\"sip:attr@example.com\"><aor>sip:elem@example.com</aor></nameID>\
</participant></recording>";
        let md = parse_rs_metadata(xml)?;
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:attr@example.com"),
            "RFC 7865 aor attribute takes precedence over the <aor> child element"
        );
        Ok(())
    }

    /// Malformed XML degrades to default metadata instead of failing.
    #[test]
    fn test_malformed_xml() -> Result<(), TestError> {
        let ct = "multipart/mixed; boundary=b1";
        let body = b"--b1\r\nContent-Type: application/rs-metadata+xml\r\n\r\n\
<not-valid-xml";
        // Should return Ok with empty/default metadata, not panic
        let result = parse_siprec_body(ct, body);
        assert!(result.is_ok());
        Ok(())
    }
}
