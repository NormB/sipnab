// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provenance tools: taking a frame pointer down to the field it names.
//!
//! [`show_evidence`](crate::mcp::server::SipnabMcp::show_evidence) answers one
//! half of #128 — *are these the bytes the claim was made against* — and hands
//! back a hexdump. That leaves the reader holding 414 bytes of Ethernet, IP,
//! UDP and SIP when what provoked the finding was one header line.
//!
//! `decode_evidence` answers the other half. It follows the same pointer
//! through the same resolver, then says what the frame CONTAINS and where each
//! SIP header sits inside it. That is the byte-range granularity #128 lists as
//! still open, delivered at the resolver rather than inside
//! [`FrameOrigin`](crate::capture::packet::FrameOrigin).
//!
//! # Why the range lives here and not in the pointer
//!
//! Widening `FrameOrigin` to `{ ordinal, digest, byte_range }` would stamp a
//! span on every packet the capture path touches, and the digest already
//! measured what that costs: hashing every frame as the reader read it spent
//! ~93% of the work on pointers nobody keeps, at 29% of two-core throughput. A
//! span has the same shape. The overwhelming majority of frames are never
//! cited, and a frame that IS cited can be read again — so the pointer stays
//! `<source>#<ordinal>@<digest>`, one text form with one parser, and the field
//! granularity comes from re-reading the frame at the moment somebody asks.
//!
//! # Why a range can be missing
//!
//! The SIP parser keeps no span per header: [`SipHeader`](crate::sip::SipHeader)
//! is `{ name, value }`. So this module walks the raw message a second time to
//! find where each logical header line sits, and a second walk of one grammar
//! can disagree with the first. Nothing here assumes it does not. Every located
//! range must reproduce the value the parser already produced; on any
//! disagreement the whole set drops and `ranges_unavailable` says which check
//! failed. Citing a neighboring header would be worse than citing none, because
//! it resolves.

use crate::mcp::server::SipnabMcp;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Parameters for `decode_evidence`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DecodeEvidenceParams {
    /// One frame pointer, in the `<source>#<ordinal>@<digest>` form the query
    /// tools emit — as `frame` on a dialog, message or stream, and as
    /// `frame_ref` on a `lint_dialog` or `validate_message` finding. Both names
    /// carry the same text.
    ///
    /// One pointer rather than a batch: a decode is a whole packet's structure,
    /// and a batch of them fills a context window with frames nobody asked to
    /// read. `show_evidence` batches because a status line per pointer is small.
    pub frame_ref: String,
    /// Keep only the headers with this name, matched case-insensitively against
    /// the canonical long form (`Contact`, not `m`). Omit it for every header.
    ///
    /// This is the compact form of the answer, and it is the one an agent
    /// chasing a specific finding wants: a REGISTER carries a dozen headers and
    /// the malformed one is a single line.
    #[serde(default)]
    pub field: Option<String>,
}

#[tool_router(router = provenance_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Follow one frame pointer and decode the frame it names.
    ///
    /// # What comes back
    ///
    /// `status` uses the same three words as `show_evidence`, and they are
    /// deliberately not collapsible: `verified` (the frame is there and its
    /// bytes hash to what the pointer recorded), `unverified` (the frame is
    /// there, the pointer carried no digest, and nothing checked the bytes),
    /// `unresolvable` (no bytes, and `reason` says why).
    ///
    /// On a resolved frame the response adds the link type read from the
    /// capture, the innermost addressing, and — when the payload parses as SIP
    /// — the start line and one row per header. Each row carries
    /// `message_byte_start`/`message_byte_end` relative to the SIP message and
    /// `frame_byte_start`/`frame_byte_end` relative to the whole frame, so a
    /// reader can quote the offending bytes out of `show_evidence`'s hexdump or
    /// out of the capture itself.
    ///
    /// Keys stay absent rather than empty wherever the answer is unknown, which
    /// is the rule `findings_with_refs` already follows: `0` and `""` both read
    /// as real values. The frame-relative pair drops when the payload does not
    /// sit at exactly one place in the frame, and both pairs drop together when
    /// the header walk disagrees with the parse.
    ///
    /// # What it deliberately does not say
    ///
    /// No timestamp. The resolver returns the frame's bytes, not the capture
    /// record that framed them, so a time here would be manufactured — and a
    /// manufactured capture time on an evidence surface is exactly the failure
    /// this mechanism exists to prevent. `get_message` carries the message's
    /// time alongside the same pointer.
    ///
    /// A frame carrying two pipelined SIP messages over one TCP segment decodes
    /// as the first one. The pointer is frame-granular, so it cannot name the
    /// second, and reporting one message's headers under a pointer that also
    /// covers another is the honest limit of what the pointer says.
    ///
    /// # Confinement
    ///
    /// A pointer's `source` is whatever the producing run read, often an
    /// absolute path outside this server's reach. This tool never opens that
    /// path: it takes the final component and resolves it through
    /// `resolve_in_root`, the same guard the file tools use. Without it, a tool
    /// that takes a caller-supplied path and returns the decoded contents of
    /// the file there is an arbitrary-file-read primitive wearing a
    /// `readOnlyHint`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `frame_ref` is blank. A pointer that
    /// cannot be followed is a result with `status: "unresolvable"`, never a
    /// call failure — the reason is the answer.
    #[tool(
        name = "decode_evidence",
        description = "Follows one frame pointer (the `frame` field on a \
                       dialog, message or stream, or the `frame_ref` field on \
                       a lint_dialog or validate_message finding) back to the \
                       captured frame and decodes it: link type, addressing, \
                       and — when the payload is SIP — the start line plus one \
                       row per header with that header's byte range inside \
                       both the message and the frame. Where show_evidence \
                       returns the bytes, this returns their structure, so a \
                       finding about one malformed header names the bytes of \
                       that header rather than of the whole packet. Byte \
                       ranges are omitted, with a reason, when the header walk \
                       and the parser disagree. Status is `verified`, \
                       `unverified` or `unresolvable`, as in show_evidence. \
                       Sources are confined to --mcp-file-root.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn decode_evidence(
        &self,
        Parameters(params): Parameters<DecodeEvidenceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let pointer = params.frame_ref.trim();
        if pointer.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "frame_ref must name one frame pointer, in the \
                 <source>#<ordinal>@<digest> form the query tools emit. A blank \
                 string names no frame, and an empty decode would read as 'this \
                 frame holds nothing'"
                    .to_string(),
                None,
            ));
        }
        let body = decode_one(self, pointer, params.field.as_deref());
        Ok(CallToolResult::success(vec![
            ContentBlock::json(body)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }
}

/// The answer for a pointer that leads to no bytes anyone should read.
///
/// A separate shape from the resolved one on purpose: an `unresolvable` entry
/// carries no `frame_bytes`, no addressing and no headers, so a caller cannot
/// read a partially-filled decode as a thin one.
fn unresolvable(pointer: &str, reason: String) -> Value {
    json!({
        "schema_version": 1,
        "pointer": pointer,
        "status": "unresolvable",
        "reason": reason,
    })
}

/// Follow one pointer, confine it, resolve it and decode what comes back.
///
/// The order of the refusals below matches `show_evidence`, and the ordering is
/// load-bearing rather than stylistic: a uprobe pointer has to be refused
/// BEFORE the path logic, because `Path::file_name()` on `uprobe:opensips/1234`
/// returns `"1234"` and would send it down the file-root check to answer with a
/// missing file — a wrong answer about evidence rather than an honest refusal.
fn decode_one(server: &SipnabMcp, pointer: &str, field: Option<&str>) -> Value {
    let parsed = match crate::capture::resolve::parse_pointer(pointer) {
        Ok(p) => p,
        Err(e) => return unresolvable(pointer, e.to_string()),
    };

    if matches!(
        parsed.kind,
        crate::capture::packet::FrameSource::Uprobe { .. }
    ) {
        let reason = crate::capture::resolve::resolve(&parsed).err().map_or_else(
            || "pointer names a uprobe read".to_string(),
            |e| e.to_string(),
        );
        return unresolvable(pointer, reason);
    }

    let leaf = std::path::Path::new(parsed.source.as_ref())
        .file_name()
        .map(|s| s.to_string_lossy().into_owned());
    let Some(leaf) = leaf else {
        return unresolvable(
            pointer,
            format!(
                "'{}' does not name a capture file. A pointer from live capture \
                 or from a HEP listener cannot be followed: sipnab holds parsed \
                 messages, not frames, so there is nothing to seek to.",
                parsed.source
            ),
        );
    };

    let path = match server.resolve_in_root(&leaf) {
        Ok(p) => p,
        Err(e) => {
            return unresolvable(
                pointer,
                format!(
                    "source '{}' is not reachable from the configured file \
                     root: {}",
                    parsed.source, e.message
                ),
            );
        }
    };

    // Resolve against the CONFINED path, never the one the pointer carried.
    // Confining rewrites the path and nothing else: the kind of thing the
    // pointer named still decides how it may be followed.
    let confined = crate::capture::packet::FrameRef {
        source: path.display().to_string().into(),
        origin: parsed.origin,
        kind: parsed.kind.clone(),
    };
    let resolution = match crate::capture::resolve::resolve(&confined) {
        Ok(r) => r,
        Err(e) => return unresolvable(pointer, e.to_string()),
    };

    let frame = resolution.bytes();
    let mut out = Map::new();
    out.insert("schema_version".to_string(), json!(1));
    out.insert("pointer".to_string(), json!(pointer));
    out.insert(
        "status".to_string(),
        json!(if resolution.is_verified() {
            "verified"
        } else {
            "unverified"
        }),
    );
    out.insert("source".to_string(), json!(leaf));
    out.insert("ordinal".to_string(), json!(parsed.origin.ordinal));
    out.insert("frame_bytes".to_string(), json!(frame.len()));

    // The resolver hands back bytes and no link type, and the link type decides
    // how many bytes precede the IP header. Reading it costs a second open of
    // the same file, which an evidence lookup can afford; decoding an SLL or
    // PPPoE capture as Ethernet cannot be afforded at all, because it produces
    // addressing that looks decoded and is wrong.
    let link_type = match crate::capture::file::open_offline(&path) {
        Ok((cap, _guard)) => cap.get_datalink().0,
        Err(e) => {
            out.insert(
                "decode_unavailable".to_string(),
                json!(format!(
                    "the frame resolved, but '{leaf}' would not reopen for its \
                     link-layer type: {e:#}. Decoding it as Ethernet would be a \
                     guess about the wire format, and a wrong guess reads as a \
                     decoded packet."
                )),
            );
            return Value::Object(out);
        }
    };
    out.insert("link_type".to_string(), json!(link_type));

    // UNIX_EPOCH, not `now()`: this field never reaches the response. The
    // resolver returns the frame's bytes without the capture record that framed
    // them, so any time put here would be invented, and `parse_packet` needs one
    // to build a packet at all.
    let packet = crate::capture::packet::Packet::with_source(
        chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        frame.to_vec(),
        frame.len(),
        frame.len(),
        Some(std::sync::Arc::from(leaf.as_str())),
        link_type,
    );
    let decoded = match crate::capture::parse::parse_packet(&packet) {
        Ok(d) => d,
        Err(e) => {
            out.insert(
                "decode_unavailable".to_string(),
                json!(format!(
                    "frame {} of '{leaf}' carries no SIP-bearing transport: {e}",
                    parsed.origin.ordinal
                )),
            );
            return Value::Object(out);
        }
    };

    out.insert(
        "network".to_string(),
        json!({
            "src_addr": decoded.src_addr.to_string(),
            "dst_addr": decoded.dst_addr.to_string(),
            "src_port": decoded.src_port,
            "dst_port": decoded.dst_port,
            "transport": decoded.transport.as_str(),
        }),
    );
    out.insert("payload_bytes".to_string(), json!(decoded.payload.len()));

    // Where the transport payload sits in the frame, which turns a
    // message-relative header range into a frame-relative one. Found by search
    // rather than by subtracting header lengths, because a decapsulated or
    // reassembled payload need not be a contiguous slice of the frame at all —
    // and when it is not, this reports nothing instead of an offset.
    let payload_offset = unique_offset(frame, &decoded.payload);
    if let Some(offset) = payload_offset {
        out.insert("payload_offset".to_string(), json!(offset));
    }

    let message = match crate::sip::parser::parse_sip_bytes(
        &decoded.payload,
        decoded.timestamp,
        decoded.src_addr,
        decoded.dst_addr,
        decoded.src_port,
        decoded.dst_port,
        decoded.transport,
    ) {
        Ok(m) => m,
        Err(e) => {
            out.insert("not_sip".to_string(), json!(e.to_string()));
            return Value::Object(out);
        }
    };

    out.insert(
        "sip".to_string(),
        Value::Object(sip_view(&message, payload_offset, field)),
    );
    Value::Object(out)
}

/// The SIP half of the decode: start line, headers, and where each one sits.
fn sip_view(
    message: &crate::sip::SipMessage,
    payload_offset: Option<usize>,
    field: Option<&str>,
) -> Map<String, Value> {
    let raw = &message.raw;
    let mut sip = Map::new();
    sip.insert("is_request".to_string(), json!(message.is_request));
    if let Some(method) = &message.method {
        sip.insert("method".to_string(), json!(method.as_str()));
    }
    if let Some(code) = message.status_code {
        sip.insert("status_code".to_string(), json!(code));
    }
    if let Some(reason) = &message.reason {
        // The responder wrote this phrase. RFC 3261 fixes the CODE, never the
        // text beside it, so a proxy is free to answer `486 <anything>`.
        sip.insert(
            "reason".to_string(),
            json!(crate::mcp::shape::fence_field(reason)),
        );
    }
    if let Some(line) = memchr::memmem::find(raw, b"\r\n")
        .and_then(|end| raw.get(..end))
        .and_then(|line| std::str::from_utf8(line).ok())
    {
        // The request line carries the Request-URI, which the sender chose
        // in full. Fenced as a FIELD: a start line is one line by definition,
        // so a line break in this string is something the sender put there.
        sip.insert(
            "start_line".to_string(),
            json!(crate::mcp::shape::fence_field(line)),
        );
    }

    let spans = matched_spans(raw, &message.headers);
    let mut rows = Vec::new();
    for (index, header) in message.headers.iter().enumerate() {
        if let Some(wanted) = field
            && !header.name.eq_ignore_ascii_case(wanted)
        {
            continue;
        }
        let mut row = Map::new();
        // The largest run of sender-authored text this surface returns:
        // `decode_evidence` exists to show what the bytes actually say, so it
        // hands back EVERY header verbatim, name and value. The name is
        // fenced too -- a header name is a `token` the sender chose and an
        // unknown one is reported rather than dropped, so it is as free-form
        // as the value beside it.
        row.insert(
            "name".to_string(),
            json!(crate::mcp::shape::fence_field(header.name.as_ref())),
        );
        row.insert(
            "value".to_string(),
            json!(crate::mcp::shape::fence_field(&header.value)),
        );
        // The index a lint finding cites, so a caller holding a finding can pair
        // the two without matching on header names.
        row.insert("index".to_string(), json!(index));
        if let Ok(spans) = &spans
            && let Some(span) = spans.get(index)
        {
            row.insert("message_byte_start".to_string(), json!(span.start));
            row.insert("message_byte_end".to_string(), json!(span.end));
            if let Some(offset) = payload_offset {
                row.insert("frame_byte_start".to_string(), json!(offset + span.start));
                row.insert("frame_byte_end".to_string(), json!(offset + span.end));
            }
        }
        rows.push(Value::Object(row));
    }

    sip.insert("header_count".to_string(), json!(message.headers.len()));
    sip.insert("headers_returned".to_string(), json!(rows.len()));
    sip.insert("headers".to_string(), Value::Array(rows));
    if let Err(why) = spans {
        sip.insert("ranges_unavailable".to_string(), json!(why));
    }
    sip
}

/// Pair every parsed header with the bytes it came from, or refuse the set.
///
/// The refusal is the point. `header_line_spans` walks the same grammar
/// `parse_headers_and_body` walks, and the two can part company — over a line
/// with no colon, a non-UTF-8 line, an over-long one, or the per-message header
/// cap. A positional pairing after any of those cites a NEIGHBORING header,
/// which resolves and therefore reads as evidence; citing nothing does not.
///
/// # Errors
///
/// Returns the disagreement as prose, for the `ranges_unavailable` key, when
/// the walk finds a different number of header lines than the parser produced
/// headers, or when a located line does not carry the value the parser read
/// out of it.
fn matched_spans(
    raw: &[u8],
    headers: &[crate::sip::SipHeader],
) -> Result<Vec<std::ops::Range<usize>>, String> {
    let spans = header_line_spans(raw);
    if spans.len() != headers.len() {
        return Err(format!(
            "the header walk found {} logical header line(s) where the parser \
             produced {} header(s), so nothing pairs them reliably. A range \
             pinned to the wrong header still resolves, which makes it worse \
             than no range.",
            spans.len(),
            headers.len()
        ));
    }
    for (index, (span, header)) in spans.iter().zip(headers).enumerate() {
        let located = raw
            .get(span.clone())
            .and_then(unfolded_value)
            .ok_or_else(|| {
                format!(
                    "the bytes located for header {index} ('{}') do not form a \
                     header line, so the walk and the parse disagree about \
                     where this header sits",
                    header.name
                )
            })?;
        if located != header.value {
            return Err(format!(
                "the bytes located for header {index} ('{}') carry a different \
                 value than the parser read, so the walk and the parse disagree \
                 about where this header sits",
                header.name
            ));
        }
    }
    Ok(spans)
}

/// Byte ranges of each logical header line inside a raw SIP message.
///
/// "Logical" is load-bearing. [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)
/// §7.3.1 lets a header continue on the next line when that line opens with SP
/// or HTAB, so the range spans the continuations too and a caller quoting it
/// quotes the whole header.
///
/// Ranges cover the header line and stop before its CRLF, so `raw[span]` is the
/// header and nothing else.
///
/// A continuation line with no header ahead of it produces no span, where the
/// parser folds it onto an empty buffer and may still emit a header. That
/// divergence is deliberate and safe: it shows up as a count mismatch in
/// [`matched_spans`], which drops the set.
fn header_line_spans(raw: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut spans = Vec::new();
    // Headers start just past the first line's CRLF, exactly where the parser
    // starts them.
    let Some(first_crlf) = memchr::memmem::find(raw, b"\r\n") else {
        return spans;
    };
    let mut pos = first_crlf + 2;
    let mut current: Option<std::ops::Range<usize>> = None;

    while pos < raw.len() {
        let continuation = matches!(raw.get(pos), Some(b' ' | b'\t'));
        match memchr::memmem::find(&raw[pos..], b"\r\n") {
            Some(offset) => {
                let end = pos + offset;
                if end == pos {
                    // The blank line closing the header section.
                    break;
                }
                if continuation {
                    if let Some(span) = current.as_mut() {
                        span.end = end;
                    }
                } else {
                    if let Some(span) = current.take() {
                        spans.push(span);
                    }
                    current = Some(pos..end);
                }
                pos = end + 2;
            }
            None => {
                // A truncated message, with no CRLF closing the last line. The
                // parser reads the remainder as a header all the same.
                if continuation {
                    if let Some(span) = current.as_mut() {
                        span.end = raw.len();
                    }
                } else {
                    if let Some(span) = current.take() {
                        spans.push(span);
                    }
                    current = Some(pos..raw.len());
                }
                break;
            }
        }
    }

    if let Some(span) = current.take() {
        spans.push(span);
    }
    spans
}

/// The value a located header line carries, unfolded the way the parser unfolds
/// it.
///
/// One rule expressed twice is the hazard this whole module guards against, so
/// this reproduces `parse_headers_and_body` step for step: join the physical
/// lines with a single space after dropping each continuation's leading
/// whitespace, then take everything past the first colon and trim it. The
/// result feeds [`matched_spans`], which compares it against what the parser
/// produced and throws the ranges away on any difference — so a drift between
/// the two shows up as missing ranges, never as wrong ones.
///
/// Returns `None` for a non-UTF-8 line or a line with no colon, both of which
/// the parser also declines to turn into a header.
fn unfolded_value(line: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(line).ok()?;
    let mut joined = String::with_capacity(text.len());
    for (index, part) in text.split("\r\n").enumerate() {
        if index == 0 {
            joined.push_str(part);
        } else {
            joined.push(' ');
            joined.push_str(part.trim_start());
        }
    }
    let colon = joined.find(':')?;
    Some(joined.get(colon + 1..)?.trim().to_string())
}

/// Where `needle` sits inside `hay`, when exactly one place does.
///
/// One place, or none at all. A second match makes the anchor ambiguous, and an
/// ambiguous frame offset is the manufactured confidence this mechanism exists
/// to prevent: a reader quoting `frame[start..end]` would be quoting bytes
/// chosen by a coin toss.
fn unique_offset(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let mut hits = memchr::memmem::find_iter(hay, needle);
    let first = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    Some(first)
}

// ── Tests ────────────────────────────────────────────────────────────

/// Following a pointer to a header's bytes, and refusing when the answer would
/// be a guess.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use parking_lot::RwLock;
    use std::sync::Arc;

    /// A server with empty stores and a file root, which is all these tools use.
    fn server_rooted(root: &std::path::Path) -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(16, false))),
            Arc::new(RwLock::new(StreamStore::new(16))),
        )
        .with_file_root(root)
    }

    /// A private directory named for the test using it.
    ///
    /// Named per test rather than per process: a fixed path shared by two tests
    /// in one binary is state they poison for each other, and the failure is a
    /// flake that only appears under a full run.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sipnab-decode-evidence-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Copy one of the repo's sample captures into `root` and return its path.
    fn seed(root: &std::path::Path, sample: &str) -> std::path::PathBuf {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples")
            .join(sample);
        let dst = root.join(sample);
        std::fs::copy(&src, &dst).expect("seed the capture");
        dst
    }

    /// The bytes of frame `ordinal` in a classic little-endian pcap.
    ///
    /// Read here, independently of everything under test, so an assertion can
    /// compare the tool's byte range against the capture on disk rather than
    /// against a number this file wrote down.
    fn frame_bytes(path: &std::path::Path, ordinal: usize) -> Vec<u8> {
        let data = std::fs::read(path).expect("read the capture");
        let mut offset = 24;
        for index in 0.. {
            let header: [u8; 16] = data[offset..offset + 16].try_into().expect("record header");
            let caplen = u32::from_le_bytes(header[8..12].try_into().expect("caplen")) as usize;
            let body = data[offset + 16..offset + 16 + caplen].to_vec();
            if index == ordinal {
                return body;
            }
            offset += 16 + caplen;
        }
        unreachable!()
    }

    /// The JSON payload of a tool result.
    fn payload(result: &CallToolResult) -> Value {
        let note = crate::mcp::shape::untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("a payload block");
        serde_json::from_str(&text).expect("the payload is JSON")
    }

    /// Call the tool for one pointer.
    async fn decode(server: &SipnabMcp, pointer: &str, field: Option<&str>) -> Value {
        let result = server
            .decode_evidence(Parameters(DecodeEvidenceParams {
                frame_ref: pointer.to_string(),
                field: field.map(str::to_string),
            }))
            .await
            .expect("the call succeeds");
        payload(&result)
    }

    /// THE test: the byte range must land on the header's bytes in the capture.
    ///
    /// This is what #128 asked for and did not have — a finding about a
    /// malformed `Contact` pointing at the `Contact` rather than at the packet.
    /// The assertion slices the capture file itself with the range the tool
    /// returned, so it holds only if the range is right in the file's own
    /// coordinates. Nothing here is a pinned offset: a recompiled fixture moves
    /// both sides together.
    #[tokio::test]
    async fn a_field_range_lands_on_that_header_in_the_capture() {
        let root = scratch("field-range");
        let capture = seed(&root, "sip-register.pcap");
        let frame = frame_bytes(&capture, 0);

        let value = decode(
            &server_rooted(&root),
            &format!("{}#0", capture.display()),
            Some("Contact"),
        )
        .await;

        assert_eq!(
            value["sip"]["headers_returned"], 1,
            "the field filter must keep the one Contact and drop the rest: {value}"
        );
        let row = &value["sip"]["headers"][0];
        let start = row["frame_byte_start"].as_u64().unwrap_or_default() as usize;
        let end = row["frame_byte_end"].as_u64().unwrap_or_default() as usize;
        assert!(
            start < end && end <= frame.len(),
            "the range must sit inside the frame: {value}"
        );
        assert_eq!(
            std::str::from_utf8(&frame[start..end]).unwrap_or_default(),
            "Contact: <sip:alice@192.0.2.101:5060>",
            "the frame-relative range must quote the Contact header out of the \
             capture file itself, header name included: {value}"
        );

        let msg_start = row["message_byte_start"].as_u64().unwrap_or_default() as usize;
        assert!(
            msg_start < start,
            "the message-relative offset must sit before the frame-relative one \
             by the length of the link/IP/transport headers, not equal it: {value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A pointer carrying a digest reports `verified`; the same pointer without
    /// one reports `unverified`, and never the other way round.
    ///
    /// Collapsing the two is the manufactured confidence the whole mechanism
    /// exists to prevent, so it is asserted here and not inherited from
    /// `show_evidence`.
    #[tokio::test]
    async fn a_digest_separates_verified_from_unverified() {
        let root = scratch("digest");
        let capture = seed(&root, "sip-register.pcap");
        let digest = crate::capture::packet::frame_digest(&frame_bytes(&capture, 0));
        let server = server_rooted(&root);

        let bare = decode(&server, &format!("{}#0", capture.display()), None).await;
        assert_eq!(
            bare["status"], "unverified",
            "a pointer with no digest was checked against nothing and must say \
             so: {bare}"
        );

        let sealed = decode(
            &server,
            &format!("{}#0@{digest:016x}", capture.display()),
            None,
        )
        .await;
        assert_eq!(
            sealed["status"], "verified",
            "a pointer whose digest matches the frame must report it: {sealed}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The link type comes from the capture, not from an assumption.
    ///
    /// `linux-sll-pppoe.pcap` is DLT 113 with a PPPoE session inside it, so the
    /// IP header sits 27 bytes further in than Ethernet would put it. Decoding
    /// it as DLT 1 does not fail loudly — it reads addressing out of the wrong
    /// bytes — which is why this asserts the decoded addresses rather than the
    /// absence of an error.
    #[tokio::test]
    async fn the_link_type_comes_from_the_capture_not_from_ethernet() {
        let root = scratch("link-type");
        let capture = seed(&root, "linux-sll-pppoe.pcap");

        let value = decode(
            &server_rooted(&root),
            &format!("{}#0", capture.display()),
            None,
        )
        .await;

        assert_eq!(
            value["link_type"], 113,
            "DLT 113 is what the file says: {value}"
        );
        assert_eq!(
            value["network"]["src_addr"], "192.0.2.10",
            "the addressing must come out of the SLL/PPPoE frame: {value}"
        );
        assert_eq!(
            value["sip"]["method"], "INVITE",
            "the payload must decode as the INVITE it is: {value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A pointer whose source escapes the file root returns no decode.
    ///
    /// The reason this tool needs the test more than most: it takes a
    /// caller-supplied string, pulls a path out of it, and reports the contents
    /// of the file there. Asserted on the EFFECT — no addressing, no headers —
    /// so a reworded refusal cannot turn this green while the read succeeds.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_pointer_escaping_the_file_root_decodes_nothing() {
        let base = scratch("escape");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        // A REAL capture outside the root, so a bypass would actually succeed.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sip-register.pcap");
        let hidden = outside.join("hidden.pcap");
        std::fs::copy(&src, &hidden).expect("seed outside the root");

        let value = decode(
            &server_rooted(&root),
            &format!("{}#0", hidden.display()),
            None,
        )
        .await;

        assert_eq!(value["status"], "unresolvable", "{value}");
        assert!(
            value.get("network").is_none() && value.get("sip").is_none(),
            "a refused pointer must return no decode at all: {value}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A frame that is not SIP says so, and offers no SIP object.
    ///
    /// Frame 7 of `rtp-protocol.pcap` is the first media packet after the
    /// signaling: it decodes cleanly down to UDP and its payload is an RTP
    /// header, so this separates "the frame would not decode" from "the frame
    /// decoded and carries no message".
    #[tokio::test]
    async fn a_frame_that_is_not_sip_says_so_rather_than_showing_an_empty_message() {
        let root = scratch("not-sip");
        let capture = seed(&root, "rtp-protocol.pcap");

        let value = decode(
            &server_rooted(&root),
            &format!("{}#7", capture.display()),
            None,
        )
        .await;

        assert!(
            value.get("sip").is_none(),
            "an RTP frame must not come back with a SIP object: {value}"
        );
        assert!(
            value["not_sip"].as_str().is_some_and(|s| !s.is_empty()),
            "and it must say why the payload is not a message: {value}"
        );
        assert!(
            value["network"]["transport"].as_str().is_some(),
            "the frame still decoded down to transport, so that half stays: \
             {value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A blank pointer is refused rather than answered with an empty decode.
    #[tokio::test]
    async fn a_blank_pointer_is_refused() {
        let root = scratch("blank");
        let err = server_rooted(&root)
            .decode_evidence(Parameters(DecodeEvidenceParams {
                frame_ref: "   ".to_string(),
                field: None,
            }))
            .await
            .expect_err("a blank pointer must be refused");
        assert!(
            err.message.contains("frame_ref"),
            "the refusal must name the parameter at fault: {}",
            err.message
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A malformed pointer is a result with a reason, not a failed call.
    #[tokio::test]
    async fn a_malformed_pointer_answers_with_its_reason() {
        let root = scratch("malformed");
        let value = decode(&server_rooted(&root), "not a pointer at all", None).await;
        assert_eq!(value["status"], "unresolvable", "{value}");
        assert!(
            value["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "an unfollowable pointer must say why: {value}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A folded header's range covers the continuation line too.
    ///
    /// The mutation this holds: treating a continuation as a new header line
    /// makes the walk find one more line than the parser found headers, and
    /// `matched_spans` then refuses the whole set rather than returning a range
    /// that stops mid-header.
    #[test]
    fn a_folded_header_is_one_range_covering_both_lines() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
                    Contact: <sip:alice@192.0.2.1>\r\n \
                    ;expires=180\r\n\
                    Content-Length: 0\r\n\r\n";
        let message = crate::sip::parser::parse_sip(
            raw,
            chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            "192.0.2.1".parse().expect("ip"),
            "192.0.2.2".parse().expect("ip"),
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .expect("a valid REGISTER");

        let spans = matched_spans(&message.raw, &message.headers)
            .expect("the walk and the parse must agree on a well-formed message");
        assert_eq!(spans.len(), 3, "three headers, folding included");

        let contact = &message.raw[spans[1].clone()];
        assert!(
            contact.ends_with(b";expires=180"),
            "the range must run to the end of the folded continuation, not stop \
             at the first CRLF: {:?}",
            std::str::from_utf8(contact)
        );
    }

    /// When the walk and the parser disagree, no range comes back at all.
    ///
    /// A line with no colon is dropped by the parser and counted by the walk, so
    /// pairing them positionally would cite every later header one line early —
    /// a range that resolves, onto the wrong bytes.
    #[test]
    fn a_disagreement_between_walk_and_parse_yields_no_ranges() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
                    this line carries no colon\r\n\
                    Contact: <sip:alice@192.0.2.1>\r\n\
                    Content-Length: 0\r\n\r\n";
        let message = crate::sip::parser::parse_sip(
            raw,
            chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            "192.0.2.1".parse().expect("ip"),
            "192.0.2.2".parse().expect("ip"),
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .expect("a REGISTER with one junk line still parses");

        assert_eq!(
            message.headers.len(),
            3,
            "the parser drops the colon-less line, which is what makes the \
             counts differ"
        );
        let refusal = matched_spans(&message.raw, &message.headers)
            .expect_err("the walk counts four lines and must refuse to pair them");
        assert!(
            refusal.contains('4') && refusal.contains('3'),
            "the refusal must name both counts so a reader can see the drift: \
             {refusal}"
        );

        // And the refusal must reach the response rather than stopping here.
        let view = sip_view(&message, Some(42), None);
        assert!(
            view.contains_key("ranges_unavailable"),
            "the response must carry the reason: {view:?}"
        );
        assert!(
            view["headers"]
                .as_array()
                .is_some_and(|rows| rows.iter().all(|r| r.get("frame_byte_start").is_none())),
            "and not a single header may carry a range: {view:?}"
        );
    }

    /// Matching counts are not enough: the located bytes must carry the value
    /// the parser read out of them.
    ///
    /// The count guard alone passes any drift that adds one line and drops
    /// another, and the ranges would then be off by a header while still
    /// resolving. So every range reproduces its own value or the set goes.
    #[test]
    fn a_located_line_that_carries_another_value_refuses_the_whole_set() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
                    Contact: <sip:alice@192.0.2.1>\r\n\
                    Content-Length: 0\r\n\r\n";
        let message = crate::sip::parser::parse_sip(
            raw,
            chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            "192.0.2.1".parse().expect("ip"),
            "192.0.2.2".parse().expect("ip"),
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .expect("a valid REGISTER");

        let mut headers = message.headers.clone();
        assert!(
            matched_spans(&message.raw, &headers).is_ok(),
            "the unmutated message must pair, or this proves nothing"
        );

        // One header's value now disagrees with the bytes at its position,
        // which is what a one-in-one-out drift looks like from here.
        headers[1].value = "<sip:mallory@198.51.100.1>".to_string();
        let refusal = matched_spans(&message.raw, &headers)
            .expect_err("a value that does not match its bytes must refuse");
        assert!(
            refusal.contains("Contact"),
            "the refusal must name the header that disagreed: {refusal}"
        );
    }

    /// An ambiguous anchor produces no frame-relative range.
    #[test]
    fn an_ambiguous_payload_offset_is_no_offset() {
        assert_eq!(unique_offset(b"abcXYZdef", b"XYZ"), Some(3));
        assert_eq!(
            unique_offset(b"XYZabcXYZ", b"XYZ"),
            None,
            "two matches name no single place, and picking the first would be a \
             coin toss dressed as evidence"
        );
        assert_eq!(
            unique_offset(b"abc", b""),
            None,
            "an empty needle is nowhere"
        );
    }
}
