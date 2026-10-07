// SPDX-License-Identifier: MIT OR Apache-2.0

//! MCP reports an AMR-WB stream's wideband score, as REST and the TUI do.
//!
//! The narrowband `mos` an AMR-WB stream carries is on the G.107 scale, which
//! cannot score a wideband codec. REST (`GET /v1/streams`, through
//! `StreamSummary`) and the TUI's `MOS_CQEW` row carry the G.107.1 score.
//! `rtp_stats` builds its stream object from the NDJSON line instead, and
//! carried only the narrowband figure, so an agent asking about an AMR-WB call
//! got the one number the other two surfaces exist to correct.
//!
//! The stream is built through a real capture: SDP pins the octet-aligned
//! packing, and the payloads' table of contents carries the mode, so the test
//! fails if the pipeline never fills the mode, not only if `rtp_stats` drops it.
#![cfg(all(feature = "native", feature = "mcp"))]

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/pcap_build.rs"]
mod pcap_build;

use mcp::McpSession;
use pcap_build::{udp_frame, write_pcap_or_panic};

const CALL_ID: &str = "amr-wb-call@10.0.0.1";
const PT: u8 = 96;
const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];

/// SDP for one side of the call, octet-aligned AMR-WB on `port`.
fn sdp(ip: &str, port: u16, codec: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {PT}\r\na=rtpmap:{PT} {codec}\r\n\
         a=fmtp:{PT} octet-align=1\r\n"
    )
}

/// One RTP packet carrying one octet-aligned AMR frame of type `ft`
/// (RFC 4867 section 4.4): CMR 15, then a single table-of-contents entry.
fn rtp(seq: u16, ft: u8) -> Vec<u8> {
    let mut p = vec![0x80, PT];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 320).to_be_bytes());
    p.extend_from_slice(&0x0BAD_F00Du32.to_be_bytes());
    p.push(0xF0);
    p.push(((ft & 0x0F) << 3) | 0x04);
    p.extend_from_slice(&[0u8; 32]);
    p
}

/// An answered call and `packets` frames of mode `ft` from A to B, sequence
/// numbers advancing by `step` (2 loses every other packet). `codec` is the
/// rtpmap encoding name both sides offer.
fn capture(dir: &std::path::Path, codec: &str, ft: u8, packets: u16, step: u16) -> String {
    let offer = sdp("10.0.0.1", 20000, codec);
    let answer = sdp("10.0.0.2", 30000, codec);
    let invite = format!(
        "INVITE sip:bob@10.0.0.2 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKwb1\r\n\
         Max-Forwards: 70\r\nFrom: <sip:alice@10.0.0.1>;tag=a1\r\n\
         To: <sip:bob@10.0.0.2>\r\nCall-ID: {CALL_ID}\r\nCSeq: 1 INVITE\r\n\
         Contact: <sip:alice@10.0.0.1:5060>\r\nContent-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{offer}",
        offer.len()
    );
    let ok = format!(
        "SIP/2.0 200 OK\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKwb1\r\n\
         From: <sip:alice@10.0.0.1>;tag=a1\r\nTo: <sip:bob@10.0.0.2>;tag=b1\r\n\
         Call-ID: {CALL_ID}\r\nCSeq: 1 INVITE\r\n\
         Contact: <sip:bob@10.0.0.2:5060>\r\nContent-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{answer}",
        answer.len()
    );
    let mut frames = vec![
        udp_frame(A, B, 5060, 5060, invite.as_bytes()),
        udp_frame(B, A, 5060, 5060, ok.as_bytes()),
    ];
    for n in 0..packets {
        frames.push(udp_frame(A, B, 20000, 30000, &rtp(n * step, ft)));
    }
    let path = dir.join("amr-wb.pcap");
    write_pcap_or_panic(&path, &frames);
    path.to_str().expect("utf-8 path").to_string()
}

/// The `rtp_stats` stream objects for `CALL_ID`.
fn streams(session: &mut McpSession) -> Vec<serde_json::Value> {
    let msg = session.call_or_panic("rtp_stats", serde_json::json!({ "call_id": CALL_ID }));
    assert!(msg.get("error").is_none(), "rtp_stats must answer: {msg}");
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .expect("text payload")
        .to_string();
    let value: serde_json::Value = serde_json::from_str(&text).expect("payload is JSON");
    value["streams"].as_array().cloned().unwrap_or_default()
}

/// A published mode with no loss: the stream carries its wideband score and
/// the listening context it was read in.
#[test]
fn rtp_stats_carries_the_wideband_score_of_an_amr_wb_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path(), "AMR-WB/16000/1", 2, 20, 1);
    let mut session = McpSession::start_or_panic(&pcap, &["--no-config"]);
    let found = streams(&mut session);
    let stream = found
        .iter()
        .find(|s| s["codec"].as_str() == Some("AMR-WB"))
        .unwrap_or_else(|| panic!("no AMR-WB stream in {found:?}"));
    let mos = stream["mos_wideband"]
        .as_f64()
        .unwrap_or_else(|| panic!("no mos_wideband on {stream}"));
    assert!((1.0..=5.0).contains(&mos), "MOS_CQEW out of range: {mos}");
    assert_eq!(stream["mos_wideband_context"], "monotic", "{stream}");
    assert!(stream.get("mos_wideband_unavailable").is_none(), "{stream}");
}

/// A published mode that lost packets has no wideband score, and says so by
/// name rather than leaving the field out as if nothing were attempted.
#[test]
fn rtp_stats_names_why_a_lossy_amr_wb_stream_has_no_wideband_score() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path(), "AMR-WB/16000/1", 2, 20, 2);
    let mut session = McpSession::start_or_panic(&pcap, &["--no-config"]);
    let found = streams(&mut session);
    let stream = found
        .iter()
        .find(|s| s["codec"].as_str() == Some("AMR-WB"))
        .unwrap_or_else(|| panic!("no AMR-WB stream in {found:?}"));
    assert!(stream.get("mos_wideband").is_none(), "{stream}");
    assert!(
        stream["mos_wideband_unavailable"].is_string(),
        "the refusal must carry its reason: {stream}"
    );
}

/// A narrowband stream carries no wideband field at all.
#[test]
fn rtp_stats_adds_no_wideband_fields_to_a_narrowband_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path(), "AMR/8000/1", 2, 20, 1);
    let mut session = McpSession::start_or_panic(&pcap, &["--no-config"]);
    let found = streams(&mut session);
    assert!(!found.is_empty(), "no stream at all");
    for stream in &found {
        for key in [
            "mos_wideband",
            "mos_wideband_context",
            "mos_wideband_unavailable",
        ] {
            assert!(
                stream.get(key).is_none(),
                "{key} on a narrowband stream: {stream}"
            );
        }
    }
}
