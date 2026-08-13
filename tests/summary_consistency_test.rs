// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-surface consistency for the canonical dialog/stream summaries.
//!
//! Guards against the projection drift that shipped before WS3 (see
//! ../docs/design/maintainability-perf-spec.md): MCP said `message_count` where CLI/API
//! said `msg_count`, and MCP put Debug-formatted methods (`Invite`) on the
//! wire where every other surface used the canonical form (`INVITE`).
//! Every output surface must project a dialog through
//! `output::model::DialogSummary` (and streams through `StreamSummary`),
//! so field names and value formats cannot diverge again.

#![cfg(all(feature = "native", feature = "mcp"))]

use sipnab::net::TransportProto;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::parser::parse_sip;

/// Parses a literal IP address string, panicking on invalid input.
fn addr(s: &str) -> std::net::IpAddr {
    s.parse().expect("valid test address")
}

/// Build a two-message INVITE dialog (INVITE + 200 OK) in a store.
///
/// # Returns
/// A `DialogStore` containing the single dialog
/// `summary-consistency@test` with alice → bob parties.
fn make_dialog_store() -> DialogStore {
    let invite = b"INVITE sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsummary1\r\n\
        Max-Forwards: 70\r\n\
        To: <sip:bob@example.com>\r\n\
        From: \"Alice\" <sip:alice@example.com>;tag=summarytag\r\n\
        Call-ID: summary-consistency@test\r\n\
        CSeq: 1 INVITE\r\n\
        Contact: <sip:alice@10.0.0.1:5060>\r\n\
        Content-Length: 0\r\n\r\n";
    let ok = b"SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsummary1\r\n\
        To: <sip:bob@example.com>;tag=totag\r\n\
        From: \"Alice\" <sip:alice@example.com>;tag=summarytag\r\n\
        Call-ID: summary-consistency@test\r\n\
        CSeq: 1 INVITE\r\n\
        Content-Length: 0\r\n\r\n";

    let ts = chrono::Utc::now();
    let mut ds = DialogStore::new(16, false);
    for (raw, src, dst, sp, dp) in [
        (&invite[..], "10.0.0.1", "10.0.0.2", 5060u16, 5060u16),
        (&ok[..], "10.0.0.2", "10.0.0.1", 5060, 5060),
    ] {
        let msg = parse_sip(raw, ts, addr(src), addr(dst), sp, dp, TransportProto::Udp)
            .expect("test message parses");
        ds.process_message(msg);
    }
    ds
}

/// The canonical `DialogSummary` serializes the full shared key set, uses `msg_count` (not the drift key `message_count`), and formats the method as `INVITE`.
#[test]
fn canonical_summary_field_names_and_formats() {
    let ds = make_dialog_store();
    let dialog = ds.get("summary-consistency@test").expect("dialog tracked");

    let summary = sipnab::output::model::DialogSummary::from(dialog);
    let v = serde_json::to_value(&summary).expect("serializes");
    let obj = v.as_object().expect("object");

    // The canonical key set (names shared with output::json's DialogJson).
    for key in [
        "call_id",
        "state",
        "method",
        "from_user",
        "to_user",
        "msg_count",
        "duration_sec",
        "created_at",
        "updated_at",
        "timing",
    ] {
        assert!(obj.contains_key(key), "canonical summary missing `{key}`");
    }
    // The historical drift keys must NOT exist.
    assert!(
        !obj.contains_key("message_count"),
        "drift key message_count"
    );

    assert_eq!(obj["call_id"], "summary-consistency@test");
    assert_eq!(obj["msg_count"], 2);
    // Canonical method string, not the Debug form "Invite".
    assert_eq!(obj["method"], "INVITE");
    assert_eq!(obj["from_user"], "alice");
    assert_eq!(obj["to_user"], "bob");
}

/// The MCP `DialogSummary` serializes byte-identically to the canonical one, pinning both shipped drift bugs (msg_count key, canonical method form).
#[test]
fn mcp_summary_is_the_canonical_summary() {
    let ds = make_dialog_store();
    let dialog = ds.get("summary-consistency@test").expect("dialog tracked");

    let mcp = serde_json::to_value(sipnab::mcp::server::DialogSummary::from(dialog))
        .expect("mcp summary serializes");
    let canonical = serde_json::to_value(sipnab::output::model::DialogSummary::from(dialog))
        .expect("canonical summary serializes");

    assert_eq!(
        mcp, canonical,
        "MCP must serialize dialogs through the canonical projection"
    );
    // The two shipped drift bugs, pinned explicitly:
    let obj = mcp.as_object().expect("object");
    assert!(
        obj.contains_key("msg_count"),
        "MCP still says message_count"
    );
    assert_eq!(obj["method"], "INVITE", "MCP still Debug-formats methods");
}

/// The canonical `StreamSummary` exposes all shared stream keys and formats the SSRC as 0x-prefixed hex.
#[test]
fn stream_summary_canonical_keys() {
    // A stream summary must expose the canonical key set with the same
    // names json.rs StreamJson uses for the overlapping fields.
    let mut ss = sipnab::rtp::stream_store::StreamStore::new(16);
    let mut rtp = vec![0u8; 172];
    rtp[0] = 0x80;
    rtp[1] = 0x00; // PT 0 (PCMU)
    rtp[3] = 0x01;
    let hdr = sipnab::rtp::parser::parse_rtp_header(&rtp).expect("rtp parses");
    let pp = sipnab::capture::parse::ParsedPacket {
        frame: None,
        timestamp: chrono::Utc::now(),
        src_addr: addr("10.0.0.1"),
        dst_addr: addr("10.0.0.2"),
        src_port: 20000,
        dst_port: 30000,
        transport: TransportProto::Udp,
        payload: bytes::Bytes::from(rtp),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        from_hep: false,
    };
    ss.process_rtp(&pp, &hdr, pp.timestamp);
    let stream = ss.iter().next().expect("stream tracked");

    let v = serde_json::to_value(sipnab::output::model::StreamSummary::of(
        stream,
        sipnab::rtp::quality::MosDelay::from_capture(&ss),
    ))
    .expect("serializes");
    let obj = v.as_object().expect("object");
    for key in [
        "ssrc",
        "codec",
        "src",
        "dst",
        "packets",
        "jitter_ms",
        "loss_pct",
        "orphaned",
        "associated_dialog",
        "mos",
    ] {
        assert!(obj.contains_key(key), "stream summary missing `{key}`");
    }
    // ssrc is the 0x-prefixed hex form all surfaces use.
    let ssrc = obj["ssrc"].as_str().expect("ssrc string");
    assert!(ssrc.starts_with("0x"), "ssrc must be hex-formatted: {ssrc}");
}
