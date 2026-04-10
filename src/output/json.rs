//! JSON/NDJSON structured output for SIP messages, dialogs, and RTP streams.
//!
//! All JSON output includes `"schema_version": 1` for forward compatibility.
//! Message output is NDJSON (one JSON object per line) for stream processing.
//! Dialog and stream output are complete JSON objects.

use serde::Serialize;
use serde_json;

use crate::rtp::diagnosis::MediaDiagnosis;
use crate::rtp::stream::RtpStream;
use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;

// ── JSON schema types ───────────────────────────────────────────────

/// JSON representation of a SIP message (NDJSON line).
#[derive(Serialize)]
struct MessageJson<'a> {
    schema_version: u32,
    timestamp: String,
    src: String,
    src_port: u16,
    dst: String,
    dst_port: u16,
    transport: &'a str,
    is_request: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ua: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_context: Option<String>,
}

/// JSON representation of dialog timing.
#[derive(Serialize)]
struct TimingJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pdd_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    setup_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ring_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trying_delay_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    teardown_ms: Option<i64>,
    retransmits: u32,
}

/// JSON representation of an SDP exchange.
#[derive(Serialize)]
struct SdpExchangeJson {
    timestamp: String,
    direction: String,
    codecs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    media_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    media_port: Option<u16>,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
}

/// JSON representation of a media diagnosis.
#[derive(Serialize)]
struct DiagnosisJson {
    one_way_audio: bool,
    nat_mismatch: bool,
    no_media: bool,
    hints: Vec<String>,
}

/// JSON representation of an RTP stream (embedded in dialog or standalone).
#[derive(Serialize)]
struct StreamJson {
    schema_version: u32,
    ssrc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    codec: Option<String>,
    payload_type: u8,
    src: String,
    dst: String,
    packets: u64,
    octets: u64,
    jitter_ms: f64,
    loss_pct: f64,
    orphaned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_dialog: Option<String>,
    first_seen: String,
    last_seen: String,
    quality_intervals: Vec<QualityIntervalJson>,
}

/// JSON representation of a quality interval.
#[derive(Serialize)]
struct QualityIntervalJson {
    timestamp: String,
    jitter_ms: f64,
    loss_pct: f64,
    packets: u64,
}

/// JSON representation of a complete dialog.
#[derive(Serialize)]
struct DialogJson {
    schema_version: u32,
    call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_display: Option<String>,
    state: String,
    method: String,
    msg_count: usize,
    duration_sec: f64,
    timing: TimingJson,
    sdp_timeline: Vec<SdpExchangeJson>,
    diagnosis: DiagnosisJson,
    streams: Vec<StreamJson>,
}

// ── Public API ──────────────────────────────────────────────────────

/// Serialize a SIP message as NDJSON (one JSON object per line).
///
/// Returns a single JSON line with a trailing newline, suitable for
/// piping to `jq` or other stream processors.
pub fn message_to_json(msg: &SipMessage) -> String {
    let response_context = if !msg.is_request {
        msg.cseq().map(|(seq, method)| format!("{seq} {method}"))
    } else {
        None
    };

    let json = MessageJson {
        schema_version: 1,
        timestamp: msg.timestamp.to_rfc3339(),
        src: msg.src_addr.to_string(),
        src_port: msg.src_port,
        dst: msg.dst_addr.to_string(),
        dst_port: msg.dst_port,
        transport: &msg.transport,
        is_request: msg.is_request,
        method: msg.method.as_deref(),
        status_code: msg.status_code,
        reason: msg.reason.as_deref(),
        call_id: msg.call_id(),
        from: msg.from_header(),
        to: msg.to_header(),
        ua: msg.user_agent(),
        response_context,
    };

    // serde_json::to_string should not fail on these well-typed fields
    let mut line = serde_json::to_string(&json)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"));
    line.push('\n');
    line
}

/// Serialize a dialog with associated streams and diagnosis as JSON.
///
/// Produces a complete JSON object with timing, SDP timeline, diagnosis,
/// and linked RTP stream details.
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
        state: format!("{:?}", dialog.state),
        method: dialog.method.clone(),
        msg_count: dialog.messages.len(),
        duration_sec,
        timing,
        sdp_timeline,
        diagnosis: diag,
        streams: stream_jsons,
    };

    serde_json::to_string_pretty(&json)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
}

/// Serialize an RTP stream as JSON.
///
/// Produces a complete JSON object with stream metadata, quality metrics,
/// and quality interval history.
pub fn stream_to_json(stream: &RtpStream) -> String {
    let json = build_stream_json(stream);
    serde_json::to_string_pretty(&json)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
}

/// Build the internal StreamJson struct from an RtpStream.
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
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP").expect("should parse")
    }

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
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");
        let json_str = message_to_json(&msg);
        let parsed: serde_json::Value =
            serde_json::from_str(json_str.trim()).expect("should be valid JSON");

        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["status_code"], 200);
        assert_eq!(parsed["is_request"], false);
        assert!(parsed["response_context"].is_string());
    }

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
    }

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
