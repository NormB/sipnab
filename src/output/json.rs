// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON/NDJSON structured output for SIP messages, dialogs, and RTP streams.
//!
//! All JSON output includes `"schema_version": 1` for forward compatibility.
//! Message output is NDJSON (one JSON object per line) for stream processing.
//! Dialog and stream output are complete JSON objects.

use serde::Serialize;

use crate::rtp::diagnosis::MediaDiagnosis;
use crate::rtp::stream::RtpStream;
use crate::sip::SipMessage;
use crate::sip::diagnosis::SignalingDiagnosis;
use crate::sip::dialog::SipDialog;

// ── JSON schema types ───────────────────────────────────────────────

/// JSON representation of a SIP message (NDJSON line).
#[derive(Serialize)]
struct MessageJson<'a> {
    /// Always 1 under the current schema.
    schema_version: u32,
    /// Capture timestamp, RFC 3339.
    timestamp: String,
    /// Source IP address.
    src: String,
    /// Source transport port.
    src_port: u16,
    /// Destination IP address.
    dst: String,
    /// Destination transport port.
    dst_port: u16,
    /// Transport tag (`UDP`/`TCP`/...).
    transport: &'a str,
    /// `true` for a request, `false` for a response.
    is_request: bool,
    /// Request method (requests only).
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    /// Status code (responses only).
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    /// Reason phrase (responses only).
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    /// `Call-ID` header value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<&'a str>,
    /// Full `From` header value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'a str>,
    /// Full `To` header value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
    /// `Contact` header (routing-critical, cross-checked by the field digest).
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<&'a str>,
    /// `User-Agent` header value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    ua: Option<&'a str>,
    /// Raw SDP body, emitted only when `Content-Type` is `application/sdp` and
    /// the body is valid UTF-8 — so the cross-check can verify the negotiated
    /// media (connection/media/rtpmap) the dynamic-PT decode relies on.
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp: Option<&'a str>,
    /// Parsed `CSeq` (number + method) on **every** message — requests included,
    /// so re-requests within a dialog stay distinguishable (SNB-0002). Omitted
    /// only when the `CSeq` header is absent or unparseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    cseq: Option<CSeqJson<'a>>,
    /// Deprecated alias of `cseq` on responses ("<num> <method>"), retained for
    /// backward compatibility under schema_version 1. Prefer `cseq`.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_context: Option<String>,
    /// Structural-malformation diagnostics (SNB-0003, spec §5.2): present and
    /// non-empty only when the message is malformed (missing mandatory header,
    /// content-length mismatch, control bytes, …). A well-formed message omits it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    malformed: Vec<String>,
}

/// JSON representation of a parsed `CSeq` header.
#[derive(Serialize)]
struct CSeqJson<'a> {
    /// CSeq sequence number.
    number: u32,
    /// CSeq method name.
    method: &'a str,
}

/// JSON representation of dialog timing.
#[derive(Serialize)]
struct TimingJson {
    /// Post-dial delay (INVITE → first 180/183), milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pdd_ms: Option<i64>,
    /// Call setup time (INVITE → 200 OK), milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    setup_ms: Option<i64>,
    /// Ringing duration (180 → 200 OK), milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    ring_ms: Option<i64>,
    /// Delay from INVITE to 100 Trying, milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    trying_delay_ms: Option<i64>,
    /// Teardown time (BYE → its 200 OK), milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    teardown_ms: Option<i64>,
    /// Total retransmissions observed in the dialog.
    retransmits: u32,
}

/// JSON representation of an SDP exchange.
#[derive(Serialize)]
struct SdpExchangeJson {
    /// Time the SDP was seen, RFC 3339.
    timestamp: String,
    /// `"offer"` or `"answer"`.
    direction: String,
    /// Codec names advertised in the media description.
    codecs: Vec<String>,
    /// Connection (`c=`) address, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    media_addr: Option<String>,
    /// Media (`m=`) port, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    media_port: Option<u16>,
    /// Media direction mode (e.g. `sendrecv`, `sendonly`).
    mode: String,
    /// Detected timeline event (Debug-formatted), e.g. hold/resume.
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
}

/// JSON representation of a media diagnosis.
#[derive(Serialize)]
struct DiagnosisJson {
    /// RTP flows in only one direction.
    one_way_audio: bool,
    /// SDP media address differs from the observed RTP address.
    nat_mismatch: bool,
    /// No RTP observed for an answered call.
    no_media: bool,
    /// Human-readable findings.
    hints: Vec<String>,
}

/// JSON representation of an RTP stream (embedded in dialog or standalone).
#[derive(Serialize)]
struct StreamJson {
    /// Always 1 under the current schema.
    schema_version: u32,
    /// SSRC as `0x`-prefixed 8-digit hex.
    ssrc: String,
    /// Codec name from SDP or heuristics, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    codec: Option<String>,
    /// RTP payload type number.
    payload_type: u8,
    /// Source `ip:port`.
    src: String,
    /// Destination `ip:port`.
    dst: String,
    /// RTP packets received.
    packets: u64,
    /// Payload octets received.
    octets: u64,
    /// Interarrival jitter, milliseconds.
    jitter_ms: f64,
    /// Packet loss percentage (0-100).
    loss_pct: f64,
    /// True when no SIP dialog explains this stream.
    orphaned: bool,
    /// Call-ID of the owning dialog, when linked.
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_dialog: Option<String>,
    /// First packet timestamp, RFC 3339.
    first_seen: String,
    /// Most recent packet timestamp, RFC 3339.
    last_seen: String,
    /// Per-interval quality history.
    quality_intervals: Vec<QualityIntervalJson>,
    /// Burst/gap loss-pattern analysis, when computable.
    #[serde(skip_serializing_if = "Option::is_none")]
    burst_gap: Option<crate::rtp::quality::BurstGapAnalysis>,
}

/// JSON representation of a quality interval.
#[derive(Serialize)]
struct QualityIntervalJson {
    /// Interval start, RFC 3339.
    timestamp: String,
    /// Jitter during the interval, milliseconds.
    jitter_ms: f64,
    /// Loss percentage during the interval.
    loss_pct: f64,
    /// Packets received during the interval.
    packets: u64,
}

/// JSON representation of a complete dialog.
#[derive(Serialize)]
struct DialogJson {
    /// Always 1 under the current schema.
    schema_version: u32,
    /// Call-ID identifying the dialog.
    call_id: String,
    /// User portion of the From URI, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    /// User portion of the To URI, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    /// From display name, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    from_display: Option<String>,
    /// To display name, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    to_display: Option<String>,
    /// Current dialog state (Display form, e.g. "InCall").
    state: String,
    /// SIP method that initiated the dialog.
    method: String,
    /// Number of SIP messages in the dialog.
    msg_count: usize,
    /// Wall-clock span from first to last message, seconds (0 for
    /// single-message dialogs).
    duration_sec: f64,
    /// User-defined classification tags; omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    /// Transaction timing metrics.
    timing: TimingJson,
    /// Chronological SDP offer/answer exchanges.
    sdp_timeline: Vec<SdpExchangeJson>,
    /// Media diagnosis findings.
    diagnosis: DiagnosisJson,
    /// Signalling diagnosis findings, omitted entirely when nothing was
    /// detected — the spec's rule, and what keeps a clean dialog's JSON the size
    /// it was before this existed.
    ///
    /// `SignalingDiagnosis` is serialized directly rather than projected into a
    /// `*Json` twin like the media diagnosis above. The projection exists there
    /// because `MediaDiagnosis` carries fields the wire format does not want;
    /// this type was designed as the wire shape, so a second copy would be two
    /// definitions of one thing waiting to disagree.
    #[serde(skip_serializing_if = "Option::is_none")]
    signaling_diagnosis: Option<SignalingDiagnosis>,
    /// Associated RTP streams.
    streams: Vec<StreamJson>,
}

// ── Public API ──────────────────────────────────────────────────────

/// Build the borrowed `MessageJson` projection of a SIP message — the
/// single source of truth for the NDJSON, writer, and `Value` variants.
fn build_message_json(msg: &SipMessage) -> MessageJson<'_> {
    let cseq = msg
        .cseq()
        .map(|(number, method)| CSeqJson { number, method });
    let response_context = if !msg.is_request {
        msg.cseq().map(|(seq, method)| format!("{seq} {method}"))
    } else {
        None
    };

    // Emit the raw SDP body only for application/sdp + valid UTF-8 (a non-UTF-8
    // body is left to the malformed path, not surfaced as a comparable sdp).
    let sdp = if msg
        .content_type()
        .map(|ct| ct.contains("application/sdp"))
        .unwrap_or(false)
    {
        std::str::from_utf8(&msg.body).ok()
    } else {
        None
    };

    MessageJson {
        schema_version: 1,
        timestamp: msg.timestamp.to_rfc3339(),
        src: msg.src_addr.to_string(),
        src_port: msg.src_port,
        dst: msg.dst_addr.to_string(),
        dst_port: msg.dst_port,
        transport: msg.transport.as_str(),
        is_request: msg.is_request,
        method: msg.method.as_ref().map(|m| m.as_str()),
        status_code: msg.status_code,
        reason: msg.reason.as_deref(),
        call_id: msg.call_id(),
        from: msg.from_header(),
        to: msg.to_header(),
        contact: msg.contact(),
        ua: msg.user_agent(),
        sdp,
        cseq,
        response_context,
        malformed: msg.malformations(),
    }
}

/// Serialize a SIP message as NDJSON (one JSON object per line).
///
/// Returns a single JSON line with a trailing newline, suitable for
/// piping to `jq` or other stream processors.
pub fn message_to_json(msg: &SipMessage) -> String {
    let mut buf = Vec::with_capacity(512);
    // The Vec writer cannot fail; write_message_json handles serializer
    // errors internally, so the buffer always holds a complete line.
    let _ = write_message_json(msg, &mut buf);
    // build_message_json emits only valid UTF-8 (strings are checked or
    // escaped by serde_json).
    String::from_utf8(buf).unwrap_or_default()
}

/// Serialize a SIP message as one NDJSON line (trailing newline included)
/// directly into `w` — the batch `-N --json` hot path, which avoids the
/// per-message intermediate `String` of `message_to_json`.
///
/// Output is byte-identical to `message_to_json`.
///
/// # Errors
///
/// Propagates only I/O errors from the writer; a pure serialization error
/// is converted into an `{"error": ...}` line instead.
pub fn write_message_json<W: std::io::Write>(msg: &SipMessage, w: &mut W) -> std::io::Result<()> {
    let json = build_message_json(msg);
    // serde_json::to_writer should not fail on these well-typed fields; an
    // I/O error propagates, a pure serialization error falls back to the
    // same error object message_to_json historically produced.
    match serde_json::to_writer(&mut *w, &json) {
        Ok(()) => {}
        Err(e) if e.is_io() => return Err(e.into()),
        Err(e) => write!(w, "{{\"error\":\"serialization failed: {e}\"}}")?,
    }
    w.write_all(b"\n")
}

/// Serialize a SIP message directly to a `serde_json::Value` — for
/// callers that need a structured object (MCP tool responses). Equal to
/// parsing the `message_to_json` line, without the print→re-parse
/// round-trip. Falls back to an `{"error": ...}` object on serialization
/// failure.
pub fn message_to_json_value(msg: &SipMessage) -> serde_json::Value {
    serde_json::to_value(build_message_json(msg))
        .unwrap_or_else(|e| serde_json::json!({"error": format!("serialization failed: {e}")}))
}

/// Pretty-printed variant of `message_to_json` for `--json-pretty`:
/// multi-line, human-readable objects instead of NDJSON. Still a valid
/// concatenated-JSON stream for tolerant parsers. Falls back to the
/// compact line if the pretty round-trip fails; always
/// newline-terminated.
pub fn message_to_json_pretty(msg: &SipMessage) -> String {
    let compact = message_to_json(msg);
    let mut pretty = serde_json::from_str::<serde_json::Value>(compact.trim_end())
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or(compact);
    if !pretty.ends_with('\n') {
        pretty.push('\n');
    }
    pretty
}

/// Serialize a dialog with associated streams and diagnosis as JSON.
///
/// Produces a complete JSON object with timing, SDP timeline, diagnosis,
/// and linked RTP stream details.
///
/// # Arguments
///
/// * `dialog` — The dialog to serialize.
/// * `streams` — RTP streams associated with the dialog.
/// * `diagnosis` — Pre-computed media diagnosis to embed.
///
/// # Returns
///
/// A pretty-printed JSON object string (an `{"error": ...}` object on
/// serialization failure).
pub fn dialog_to_json(
    dialog: &SipDialog,
    streams: &[&RtpStream],
    diagnosis: &MediaDiagnosis,
) -> String {
    let duration_sec = if dialog.messages.len() >= 2 {
        let first = dialog.created_at;
        let last = dialog.updated_at;
        (last - first).num_milliseconds() as f64 / 1000.0
    } else {
        0.0
    };

    let timing = TimingJson {
        pdd_ms: dialog.timing.pdd_ms(),
        setup_ms: dialog.timing.setup_ms(),
        ring_ms: dialog.timing.ring_ms(),
        trying_delay_ms: dialog.timing.trying_delay_ms(),
        teardown_ms: dialog.timing.teardown_ms(),
        retransmits: dialog.timing.total_retransmits(),
    };

    let sdp_timeline: Vec<SdpExchangeJson> = dialog
        .sdp_timeline
        .iter()
        .map(|ex| {
            let direction = match ex.direction {
                crate::sip::sdp_timeline::OfferAnswer::Offer => "offer",
                crate::sip::sdp_timeline::OfferAnswer::Answer => "answer",
            };
            let event = ex.event.as_ref().map(|e| format!("{e:?}"));
            SdpExchangeJson {
                timestamp: ex.timestamp.to_rfc3339(),
                direction: direction.to_string(),
                codecs: ex.codecs.clone(),
                media_addr: ex.media_addr.clone(),
                media_port: ex.media_port,
                mode: ex.mode.clone(),
                event,
            }
        })
        .collect();

    let diag = DiagnosisJson {
        one_way_audio: diagnosis.one_way_audio,
        nat_mismatch: diagnosis.nat_mismatch,
        no_media: diagnosis.no_media,
        hints: diagnosis.hints.clone(),
    };

    let stream_jsons: Vec<StreamJson> = streams.iter().map(|s| build_stream_json(s)).collect();

    let json = DialogJson {
        schema_version: 1,
        call_id: dialog.call_id.clone(),
        from: dialog.from_user.clone(),
        to: dialog.to_user.clone(),
        from_display: dialog.from_display.clone(),
        to_display: dialog.to_display.clone(),
        state: dialog.state().to_string(),
        method: dialog.method.to_string(),
        msg_count: dialog.messages.len(),
        duration_sec,
        tags: dialog.tags.clone(),
        timing,
        sdp_timeline,
        diagnosis: diag,
        // Computed here rather than taken as a parameter: it is a property of the
        // dialog, which every caller already passes, so threading it through four
        // call sites would only create a way for one of them to forget.
        signaling_diagnosis: Some(crate::sip::diagnosis::diagnose_signaling(&dialog.messages))
            .filter(|d| !d.is_empty()),
        streams: stream_jsons,
    };

    serde_json::to_string_pretty(&json)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
}

/// Serialize an RTP stream as JSON.
///
/// Produces a complete pretty-printed JSON object with stream metadata,
/// quality metrics, and quality interval history (an `{"error": ...}`
/// object on serialization failure).
pub fn stream_to_json(stream: &RtpStream) -> String {
    let json = build_stream_json(stream);
    serde_json::to_string_pretty(&json)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
}

/// Build the internal `StreamJson` struct from an `RtpStream`, deriving
/// loss percentage and mapping quality intervals.
fn build_stream_json(stream: &RtpStream) -> StreamJson {
    let total = stream.packet_count + stream.lost_packets;
    let loss_pct = if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let intervals: Vec<QualityIntervalJson> = stream
        .quality_intervals
        .iter()
        .map(|qi| QualityIntervalJson {
            timestamp: qi.timestamp.to_rfc3339(),
            jitter_ms: qi.jitter_ms,
            loss_pct: qi.loss_pct,
            packets: qi.packets,
        })
        .collect();

    StreamJson {
        schema_version: 1,
        ssrc: format!("0x{:08x}", stream.key.ssrc),
        codec: stream.codec.clone(),
        payload_type: stream.payload_type,
        src: stream.key.src.to_string(),
        dst: stream.key.dst.to_string(),
        packets: stream.packet_count,
        octets: stream.octet_count,
        jitter_ms: stream.jitter,
        loss_pct,
        orphaned: stream.orphaned,
        associated_dialog: stream.associated_dialog.clone(),
        first_seen: stream.first_seen.to_rfc3339(),
        last_seen: stream.last_seen.to_rfc3339(),
        quality_intervals: intervals,
        burst_gap: stream.burst_gap_analysis(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for the NDJSON message projection (CSeq/SDP/malformed handling),
/// the writer/Value equivalence guarantees, and dialog/stream JSON shape.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// The loopback IPv4 address used for all synthetic messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed timestamp (2024-06-15 12:00:00 UTC) for determinism.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Parse a minimal bodyless INVITE with a User-Agent header.
    fn make_invite() -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>",
                "Call-ID: json-test@example.com",
                "CSeq: 1 INVITE",
                "User-Agent: TestUA/1.0",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// Build a fresh single-packet PCMU RTP stream with SSRC 0x12345678.
    fn make_stream() -> RtpStream {
        let key = StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0x12345678,
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, ts())
    }

    // Perf path (batch `-N --json`): the writer variant must produce bytes
    // identical to `message_to_json` — same NDJSON line, same trailing
    // newline — so switching the batch loop to it cannot change output.
    /// The writer variant is byte-identical to `message_to_json` for
    /// plain, SDP-carrying, and malformed messages.
    #[test]
    fn write_message_json_matches_message_to_json() {
        let body = b"v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 6000 RTP/AVP 8\r\na=label:a\\b\"c\r\n";
        let cl = format!("Content-Length: {}", body.len());
        let with_sdp = parse_sip(
            &build_sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &[
                    "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                    "To: <sip:1002@example.com>",
                    "Call-ID: writer-eq@example.com",
                    "CSeq: 1 INVITE",
                    "Content-Type: application/sdp",
                    &cl,
                ],
                body,
            ),
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        // A malformed message (missing mandatory headers) exercises the
        // `malformed` array path.
        let malformed = req_with_headers(&["CSeq: 1 REGISTER", "Content-Length: 0"]);
        for msg in [make_invite(), with_sdp, malformed] {
            let mut buf = Vec::new();
            write_message_json(&msg, &mut buf).expect("write should succeed");
            assert_eq!(
                String::from_utf8(buf).expect("utf8"),
                message_to_json(&msg),
                "writer variant must be byte-identical"
            );
        }
    }

    // Perf path (MCP get_dialog/get_message): the Value variant must equal
    // parse(message_to_json) so replacing the to_string→from_str round-trip
    // cannot change any MCP response.
    /// The `Value` variant equals the parsed NDJSON line for request and
    /// response messages.
    #[test]
    fn message_to_json_value_matches_parsed_string() {
        let resp = parse_sip(
            &build_sip(
                "SIP/2.0 200 OK",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: value-eq@example.com",
                    "CSeq: 7 INVITE",
                    "Content-Length: 0",
                ],
                b"",
            ),
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        for msg in [make_invite(), resp] {
            let via_string: serde_json::Value =
                serde_json::from_str(message_to_json(&msg).trim_end()).expect("valid JSON");
            assert_eq!(
                message_to_json_value(&msg),
                via_string,
                "Value variant must match the parsed NDJSON line"
            );
        }
    }

    /// An INVITE serializes to valid JSON with schema, method, call_id,
    /// and UA fields.
    #[test]
    fn message_to_json_valid() {
        let msg = make_invite();
        let json_str = message_to_json(&msg);

        // Must be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(json_str.trim()).expect("should be valid JSON");

        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["method"], "INVITE");
        assert_eq!(parsed["call_id"], "json-test@example.com");
        assert_eq!(parsed["is_request"], true);
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["ua"].is_string());
    }

    /// A 200 OK serializes with status_code, is_request=false, and
    /// response_context.
    #[test]
    fn message_to_json_response() {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: json-resp@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        let json_str = message_to_json(&msg);
        let parsed: serde_json::Value =
            serde_json::from_str(json_str.trim()).expect("should be valid JSON");

        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["status_code"], 200);
        assert_eq!(parsed["is_request"], false);
        assert!(parsed["response_context"].is_string());
    }

    /// Contact and the raw SDP body (incl. rtpmap lines) are emitted for
    /// cross-checking.
    #[test]
    fn message_to_json_includes_contact_and_sdp() {
        // Field-digest cross-check (item 1): sipnab must EMIT Contact + the SDP
        // body so the comparator can verify them against tshark — without these
        // a dropped/mangled rtpmap or a corrupt Contact is invisible.
        let body = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 6000 RTP/AVP 8 96\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:96 telephone-event/8000\r\n";
        let cl = format!("Content-Length: {}", body.len());
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>",
                "Contact: <sip:1001@127.0.0.1:5062>",
                "Call-ID: sdp-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &cl,
            ],
            body,
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        let parsed = parsed_json(&msg);
        assert_eq!(parsed["contact"], "<sip:1001@127.0.0.1:5062>");
        let sdp = parsed["sdp"].as_str().expect("sdp body present");
        assert!(
            sdp.contains("m=audio 6000 RTP/AVP 8 96"),
            "sdp body emitted: {sdp}"
        );
        assert!(
            sdp.contains("a=rtpmap:96 telephone-event/8000"),
            "rtpmap present: {sdp}"
        );
    }

    /// Without a Contact header or SDP body, both keys are omitted.
    #[test]
    fn message_to_json_omits_contact_and_sdp_when_absent() {
        let parsed = parsed_json(&make_invite()); // no Contact, empty body
        assert!(parsed.get("contact").is_none(), "no Contact header => omit");
        assert!(parsed.get("sdp").is_none(), "no SDP body => omit");
    }

    /// A text/plain body is not surfaced as `sdp`.
    #[test]
    fn message_to_json_sdp_omitted_for_non_sdp_body() {
        let body = b"plain text body";
        let cl = format!("Content-Length: {}", body.len());
        let raw = build_sip(
            "MESSAGE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:a@h>;tag=t1",
                "To: <sip:b@h>",
                "Call-ID: txt@h",
                "CSeq: 1 MESSAGE",
                "Content-Type: text/plain",
                &cl,
            ],
            body,
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert!(
            parsed_json(&msg).get("sdp").is_none(),
            "a non-application/sdp body must not be emitted as sdp"
        );
    }

    /// Backslash and embedded quote in the SDP survive JSON escaping.
    #[test]
    fn message_to_json_sdp_preserves_adversarial_bytes() {
        // backslash + embedded quote in the SDP must round-trip through JSON
        // string escaping intact (not corrupt the line or get dropped).
        let body = b"v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 6000 RTP/AVP 8\r\na=label:a\\b\"c\r\n";
        let cl = format!("Content-Length: {}", body.len());
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:a@h>;tag=t1",
                "To: <sip:b@h>",
                "Call-ID: adv@h",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &cl,
            ],
            body,
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        let parsed = parsed_json(&msg); // must still be valid JSON
        let sdp = parsed["sdp"].as_str().expect("sdp present");
        assert!(
            sdp.contains("a=label:a\\b\"c"),
            "adversarial bytes preserved: {sdp:?}"
        );
    }

    /// Parse a REGISTER request carrying exactly `headers`.
    fn req_with_headers(headers: &[&str]) -> SipMessage {
        let raw = build_sip("REGISTER sip:example.com SIP/2.0", headers, b"");
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// Serialize `msg` via `message_to_json` and parse it back to a Value.
    fn parsed_json(msg: &SipMessage) -> serde_json::Value {
        serde_json::from_str(message_to_json(msg).trim()).expect("valid JSON")
    }

    /// Requests carry the structured `cseq` object (SNB-0002).
    #[test]
    fn message_to_json_request_includes_cseq() {
        // SNB-0002: requests MUST carry CSeq so re-requests within a dialog are
        // distinguishable — previously only responses got it (response_context).
        let parsed = parsed_json(&make_invite()); // CSeq: 1 INVITE
        assert_eq!(parsed["is_request"], true);
        assert_eq!(parsed["cseq"]["number"], 1);
        assert_eq!(parsed["cseq"]["method"], "INVITE");
    }

    /// Responses carry both `cseq` and the legacy `response_context`.
    #[test]
    fn message_to_json_response_includes_cseq() {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "Call-ID: resp-cseq@example.com",
                "CSeq: 7 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        let parsed = parsed_json(&msg);
        assert_eq!(parsed["is_request"], false);
        assert_eq!(parsed["cseq"]["number"], 7);
        assert_eq!(parsed["cseq"]["method"], "INVITE");
        // response_context retained for backward compatibility (schema_version 1).
        assert_eq!(parsed["response_context"], "7 INVITE");
    }

    /// Two REGISTERs differing only by CSeq number stay distinguishable.
    #[test]
    fn message_to_json_re_requests_are_distinguishable() {
        // The exact SNB-0002 regression: two REGISTERs in one dialog differ only
        // by CSeq number; their JSON must reflect that, not collapse.
        let mk = |cseq: &str| {
            req_with_headers(&[
                &format!("CSeq: {cseq}"),
                "Call-ID: same-dialog@example.com",
                "Content-Length: 0",
            ])
        };
        let a = parsed_json(&mk("1 REGISTER"));
        let b = parsed_json(&mk("2 REGISTER"));
        assert_ne!(a["cseq"], b["cseq"], "distinct CSeq must not collapse");
        assert_eq!(a["cseq"]["number"], 1);
        assert_eq!(b["cseq"]["number"], 2);
        assert_eq!(a["cseq"]["method"], "REGISTER");
    }

    /// `cseq` is omitted entirely when the CSeq header is absent.
    #[test]
    fn message_to_json_cseq_absent_when_header_missing() {
        let msg = req_with_headers(&["Call-ID: no-cseq@example.com", "Content-Length: 0"]);
        let parsed = parsed_json(&msg);
        assert!(
            parsed.get("cseq").is_none(),
            "cseq omitted when CSeq header absent, got {:?}",
            parsed.get("cseq")
        );
    }

    /// Malformed/boundary CSeq values (garbage, missing method, empty,
    /// overflow) omit `cseq` instead of emitting garbage.
    #[test]
    fn message_to_json_cseq_omitted_when_malformed_or_boundary() {
        // Adversarial / boundary: non-numeric seq, number-without-method, empty,
        // whitespace-only, and a u32-overflowing sequence are all unparseable per
        // RFC 3261 — the field is omitted entirely, never emitted garbled.
        for bad in [
            "CSeq: garbage INVITE",    // non-numeric sequence
            "CSeq: 5",                 // sequence with no method
            "CSeq: ",                  // empty value
            "CSeq: \t",                // whitespace-only value
            "CSeq: 4294967296 INVITE", // u32::MAX + 1 → overflow
        ] {
            let msg = req_with_headers(&[bad, "Call-ID: bad@example.com", "Content-Length: 0"]);
            let parsed = parsed_json(&msg);
            assert!(
                parsed.get("cseq").is_none(),
                "cseq must be omitted for malformed {bad:?}, got {:?}",
                parsed.get("cseq")
            );
        }
    }

    /// A `u32::MAX` CSeq sequence round-trips intact.
    #[test]
    fn message_to_json_cseq_max_u32_boundary() {
        // u32::MAX is a valid CSeq sequence and must round-trip.
        let msg = req_with_headers(&[
            "CSeq: 4294967295 OPTIONS",
            "Call-ID: max-cseq@example.com",
            "Content-Length: 0",
        ]);
        let parsed = parsed_json(&msg);
        assert_eq!(parsed["cseq"]["number"], 4294967295u32);
        assert_eq!(parsed["cseq"]["method"], "OPTIONS");
    }

    /// A message missing Call-ID carries a `malformed` array naming it
    /// (SNB-0003).
    #[test]
    fn message_to_json_flags_malformed() {
        // SNB-0003: a malformed message (missing mandatory Call-ID) carries a
        // `malformed` diagnostic array naming the defect.
        let msg = req_with_headers(&[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
            "From: <sip:a@x>;tag=1",
            "To: <sip:b@x>",
            "CSeq: 1 REGISTER",
            "Content-Length: 0",
        ]);
        let parsed = parsed_json(&msg);
        let m = parsed["malformed"]
            .as_array()
            .expect("malformed should be an array");
        assert!(
            m.iter()
                .any(|r| r.as_str().unwrap_or("").contains("Call-ID")),
            "expected a Call-ID reason, got {m:?}"
        );
    }

    /// A well-formed message omits the `malformed` key.
    #[test]
    fn message_to_json_well_formed_omits_malformed() {
        let msg = req_with_headers(&[
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
            "From: <sip:a@x>;tag=1",
            "To: <sip:b@x>",
            "Call-ID: clean@x",
            "CSeq: 1 REGISTER",
            "Content-Length: 0",
        ]);
        let parsed = parsed_json(&msg);
        assert!(
            parsed.get("malformed").is_none(),
            "well-formed message must omit `malformed`, got {:?}",
            parsed.get("malformed")
        );
    }

    /// Dialog JSON carries schema, timing, sdp_timeline, diagnosis,
    /// streams, call_id, and state.
    #[test]
    fn dialog_to_json_contains_required_fields() {
        let msg = make_invite();
        let dialog = crate::sip::dialog::SipDialog::new(&msg).expect("should create dialog");
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let diagnosis = MediaDiagnosis::default();

        let json_str = dialog_to_json(&dialog, &streams, &diagnosis);
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");

        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["timing"].is_object(), "should have timing object");
        assert!(
            parsed["sdp_timeline"].is_array(),
            "should have sdp_timeline array"
        );
        assert!(
            parsed["diagnosis"].is_object(),
            "should have diagnosis object"
        );
        assert!(parsed["streams"].is_array(), "should have streams array");
        assert!(parsed["call_id"].is_string());
        assert!(parsed["state"].is_string());
        // A single-INVITE dialog has nothing wrong with it, and the spec says the
        // object is omitted entirely rather than emitted empty.
        assert!(
            parsed.get("signaling_diagnosis").is_none(),
            "a clean dialog must omit signaling_diagnosis, got {:?}",
            parsed.get("signaling_diagnosis")
        );
    }

    /// A failed dialog carries `signaling_diagnosis` with its evidence indices.
    ///
    /// This is the wiring test, not a detection test — `sip::diagnosis` covers the
    /// detections. What it proves is that the diagnosis reaches the surface at
    /// all, which a module with passing unit tests and no caller would not.
    #[test]
    fn dialog_json_carries_signaling_diagnosis_when_the_call_failed() {
        let msg = make_invite();
        let mut dialog = crate::sip::dialog::SipDialog::new(&msg).expect("should create dialog");

        // A 503 on the same dialog: detection 1.
        let raw = "SIP/2.0 503 Service Unavailable\r\n\
                   Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n\
                   From: <sip:a@example.com>;tag=1\r\n\
                   To: <sip:b@example.com>;tag=2\r\n\
                   Call-ID: test-call-id@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Reason: Q.850;cause=34\r\n\
                   Content-Length: 0\r\n\r\n";
        let resp = crate::sip::parser::parse_sip(
            raw.as_bytes(),
            msg.timestamp,
            msg.dst_addr,
            msg.src_addr,
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .expect("fixture parses");
        dialog.messages.push(resp);

        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let json_str = dialog_to_json(&dialog, &streams, &MediaDiagnosis::default());
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");

        let sd = &parsed["signaling_diagnosis"];
        assert!(
            sd.is_object(),
            "expected signaling_diagnosis, got {json_str}"
        );
        assert_eq!(sd["final_failure"]["code"], 503);
        assert_eq!(sd["final_failure"]["reason_header"], "Q.850;cause=34");
        // Evidence points into dialog.messages: the response is index 1.
        assert_eq!(sd["final_failure"]["evidence"][0], 1);
        assert!(
            sd["hints"][0].as_str().is_some_and(|h| h.contains("503")),
            "hint should name the code, got {:?}",
            sd["hints"]
        );
    }

    /// Stream JSON carries schema, hex SSRC, and numeric quality fields.
    #[test]
    fn stream_to_json_contains_required_fields() {
        let stream = make_stream();
        let json_str = stream_to_json(&stream);
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");

        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["ssrc"].is_string());
        assert!(parsed["jitter_ms"].is_number());
        assert!(parsed["loss_pct"].is_number());
        assert!(parsed["packets"].is_number());
        assert_eq!(parsed["ssrc"], "0x12345678");
    }
}
