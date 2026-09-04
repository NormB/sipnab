// SPDX-License-Identifier: MIT OR Apache-2.0

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

        let content_type = unfold_header_lines(headers_part)
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
            body: body_part.to_string(),
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
fn extract_all_xml_content(xml: &str, tag: &str) -> Vec<String> {
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(found) = extract_xml_content(rest, tag) {
        out.push(found);
        let Some(pos) = rest.find(&close) else {
            break;
        };
        rest = &rest[pos + close.len()..];
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
    fn the_recording_mode_comes_from_datamode() {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())
            .expect("OpenSIPS metadata parses");
        assert_eq!(
            md.mode.as_deref(),
            Some("complete"),
            "the mode an SRC declares is <datamode>, not <mode>"
        );
    }

    /// A stream belongs to the participant that SENDS it.
    ///
    /// This is the field that makes the metadata worth surfacing: it is the
    /// only route from a recorded stream back to the person on it. OpenSIPS
    /// puts nothing inside `<stream>` naming a participant -- the association
    /// lives in `<participantstreamassoc>`, whose `<send>` children name the
    /// streams that participant originates.
    #[test]
    fn a_stream_is_owned_by_the_participant_that_sends_it() {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())
            .expect("OpenSIPS metadata parses");
        let owner = |id: &str| {
            md.streams
                .iter()
                .find(|s| s.stream_id.as_deref() == Some(id))
                .unwrap_or_else(|| panic!("stream {id} parsed"))
                .participant_id
                .clone()
        };
        assert_eq!(owner("s-alice-audio").as_deref(), Some("p-alice"));
        assert_eq!(
            owner("s-alice-video").as_deref(),
            Some("p-alice"),
            "a participant's second stream is theirs too -- this is the audio \
             and video case, where each label is an m= line index"
        );
        assert_eq!(
            owner("s-bob-audio").as_deref(),
            Some("p-bob"),
            "and a stream only Bob sends is Bob's, though Alice receives it"
        );
    }

    /// Every participant and stream OpenSIPS emits is found, with its label.
    #[test]
    fn every_participant_and_stream_opensips_emits_is_found() {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())
            .expect("OpenSIPS metadata parses");
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
    }

    /// A participant whose `<nameID>` is self-closing still yields its AOR.
    ///
    /// OpenSIPS writes `<nameID aor="..."/>` when it has no display name for
    /// the party, which is the common case for the callee.
    #[test]
    fn a_self_closing_nameid_still_yields_its_aor() {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())
            .expect("OpenSIPS metadata parses");
        let bob = &md.participants[1];
        assert_eq!(bob.aor.as_deref(), Some("sip:bob@example.invalid"));
        assert_eq!(
            bob.name, None,
            "no display name was sent, so none is invented"
        );
    }

    /// `<participantsessionassoc>` and `<participantstreamassoc>` are not
    /// participants.
    ///
    /// Both start with the same eleven characters as `<participant`, and the
    /// scan that finds participants is a substring search. Counting them as
    /// participants would double a call's party list.
    #[test]
    fn an_assoc_element_is_not_mistaken_for_a_participant() {
        let md = parse_siprec_body("multipart/mixed; boundary=OSS", &opensips_body())
            .expect("OpenSIPS metadata parses");
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

    /// A part whose `Content-Type` header is folded across lines
    /// (RFC 5322 continuation lines starting with SP/HTAB) is unfolded
    /// before parsing, so the full media type + parameters are recovered.
    #[test]
    fn test_split_multipart_unfolds_folded_content_type() {
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
        let parts = split_multipart(body, "b1");
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].content_type.as_deref(),
            Some("application/rs-metadata+xml; charset=\"utf-8\""),
            "folded Content-Type must be unfolded to its full value"
        );
    }

    /// A folded HTAB continuation is also unfolded.
    #[test]
    fn test_split_multipart_unfolds_htab_continuation() {
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
        let parts = split_multipart(body, "b1");
        assert_eq!(parts.len(), 1);
        // Unfolding removes the line break but preserves the folding WSP, so the
        // HTAB is retained in the joined value (RFC 5322 §2.2.3).
        assert_eq!(
            parts[0].content_type.as_deref(),
            Some("application/rs-metadata+xml;\tcharset=\"utf-8\"")
        );
    }

    /// RFC 7865 canonical participant AOR: the `aor` attribute on `<nameID>`.
    #[test]
    fn test_participant_aor_attribute_form() {
        let xml = "<recording><participant participant_id=\"p1\">\
<nameID aor=\"sip:alice@example.com\"><name>Alice</name></nameID>\
</participant></recording>";
        let md = parse_rs_metadata(xml).unwrap();
        assert_eq!(md.participants.len(), 1);
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:alice@example.com")
        );
    }

    /// The non-standard `<aor>` child-element form remains supported.
    #[test]
    fn test_participant_aor_element_form_still_supported() {
        let xml = "<recording><participant participant_id=\"p1\">\
<nameID><aor>sip:bob@example.com</aor></nameID></participant></recording>";
        let md = parse_rs_metadata(xml).unwrap();
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:bob@example.com")
        );
    }

    /// When both the RFC 7865 `aor` attribute and a non-standard `<aor>`
    /// child element are present, the canonical attribute wins.
    #[test]
    fn test_participant_aor_attribute_wins_over_element() {
        let xml = "<recording><participant participant_id=\"p1\">\
<nameID aor=\"sip:attr@example.com\"><aor>sip:elem@example.com</aor></nameID>\
</participant></recording>";
        let md = parse_rs_metadata(xml).unwrap();
        assert_eq!(
            md.participants[0].aor.as_deref(),
            Some("sip:attr@example.com"),
            "RFC 7865 aor attribute takes precedence over the <aor> child element"
        );
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
