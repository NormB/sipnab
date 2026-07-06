//! Property-based tests (WS7.3).
//!
//! The fuzzers prove "no panic on hostile bytes"; these prove *semantic*
//! invariants the fuzzers can't: that a SIP message we build parses back
//! to the same fields, that SDP survives a build→parse→rebuild round
//! trip, and that the filter DSL is a total function on arbitrary text
//! (every input yields `Ok`/`Err`, never a panic — then valid
//! expressions evaluate against a dialog without panicking).

use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};
use proptest::prelude::*;

use sipnab::net::TransportProto;
use sipnab::sip::dialog::SipDialog;
use sipnab::sip::dsl::FilterExpr;
use sipnab::sip::parser::parse_sip;
use sipnab::sip::sdp::parse_sdp;

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
}

// ── SIP build → parse field round-trip ──────────────────────────────

/// A token safe to embed in a SIP header value: SIP-relevant printable
/// ASCII minus the delimiters that would change the message's structure
/// (CR/LF/`@`/`<`/`>`/`:`/`;`/`"`/whitespace). Non-empty.
fn header_token() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9._!~*'()+%-]{1,32}"
}

proptest! {
    /// An INVITE built from generated user/host/call-id/cseq fields must
    /// parse back to exactly those fields — the parser and the wire form
    /// agree for every valid combination, not just the hand-picked cases.
    #[test]
    fn invite_build_parse_roundtrips_fields(
        from_user in header_token(),
        to_user in header_token(),
        host in header_token(),
        call_id in header_token(),
        cseq in 1u32..=999_999u32,
    ) {
        let raw = format!(
            "INVITE sip:{to_user}@{host} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}\r\n\
             From: <sip:{from_user}@{host}>;tag=t1\r\n\
             To: <sip:{to_user}@{host}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} INVITE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let msg = parse_sip(raw.as_bytes(), ts(), ip(), ip(), 5060, 5060, TransportProto::Udp)
            .expect("a well-formed INVITE must parse");

        prop_assert!(msg.is_request);
        prop_assert_eq!(msg.call_id(), Some(call_id.as_str()));
        let got_from = msg.from_user();
        let got_to = msg.to_user();
        prop_assert_eq!(got_from.as_deref(), Some(from_user.as_str()));
        prop_assert_eq!(got_to.as_deref(), Some(to_user.as_str()));
        prop_assert_eq!(msg.cseq().map(|(n, m)| (n, m.to_string())),
            Some((cseq, "INVITE".to_string())));
    }
}

// ── SDP build → parse → rebuild round-trip ──────────────────────────

/// One of the static payload types the SDP parser maps to a codec name.
fn pt_codec() -> impl Strategy<Value = (u8, &'static str)> {
    prop::sample::select(vec![
        (0u8, "PCMU"),
        (8u8, "PCMA"),
        (9u8, "G722"),
        (18u8, "G729"),
    ])
}

proptest! {
    /// SDP built with a generated port and rtpmap must parse to the same
    /// media/port/codec, and re-parsing a canonical rebuild from the
    /// parsed fields must be stable (parse ∘ build is idempotent on the
    /// fields we surface).
    #[test]
    fn sdp_media_roundtrips(
        port in 1u16..=65535u16,
        (pt, codec) in pt_codec(),
        clock in prop::sample::select(vec![8000u32, 16000, 48000]),
    ) {
        let body = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.2\r\n\
             s=call\r\n\
             c=IN IP4 10.0.0.2\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP {pt}\r\n\
             a=rtpmap:{pt} {codec}/{clock}\r\n"
        );
        let sdp = parse_sdp(body.as_bytes()).expect("well-formed SDP must parse");
        prop_assert_eq!(sdp.media.len(), 1);
        let m = &sdp.media[0];
        prop_assert_eq!(&m.media_type, "audio");
        prop_assert_eq!(m.port, port);
        prop_assert_eq!(m.rtpmap.len(), 1);
        prop_assert_eq!(&m.rtpmap[0].encoding, codec);
        prop_assert_eq!(m.rtpmap[0].payload_type, pt);
        prop_assert_eq!(m.rtpmap[0].clock_rate, clock);

        // Rebuild from parsed fields and re-parse: fields must be stable.
        let rebuilt = format!(
            "v=0\r\nc=IN IP4 10.0.0.2\r\nm={} {} RTP/AVP {}\r\na=rtpmap:{} {}/{}\r\n",
            m.media_type, m.port, pt, pt, m.rtpmap[0].encoding, m.rtpmap[0].clock_rate
        );
        let again = parse_sdp(rebuilt.as_bytes()).expect("rebuild must parse");
        prop_assert_eq!(again.media[0].port, port);
        prop_assert_eq!(&again.media[0].rtpmap[0].encoding, codec);
    }
}

// ── Filter DSL: total function on arbitrary input ───────────────────

fn sample_dialog() -> SipDialog {
    let raw = b"INVITE sip:2002@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKprop\r\n\
        From: <sip:1001@example.com>;tag=t1\r\n\
        To: <sip:2002@example.com>\r\n\
        Call-ID: prop@example.com\r\n\
        CSeq: 1 INVITE\r\n\
        Content-Length: 0\r\n\r\n";
    let msg = parse_sip(raw, ts(), ip(), ip(), 5060, 5060, TransportProto::Udp).unwrap();
    SipDialog::new(&msg).expect("dialog from INVITE")
}

proptest! {
    /// `FilterExpr::parse` is total on arbitrary text: it returns `Ok`
    /// (a usable filter) or `Err`, but never panics or hangs. Anything
    /// that parses must also evaluate against a dialog without panicking.
    #[test]
    fn filter_dsl_parse_is_total(s in ".{0,120}") {
        let dialog = sample_dialog();
        if let Ok(filter) = FilterExpr::parse(&s) {
            // Evaluation is likewise total: a parsed expression never
            // panics against a real dialog (empty stream slice).
            let _ = filter.matches_dialog(&dialog, &[]);
        }
    }

    /// Well-formed expressions over known fields always parse *and*
    /// evaluate to a concrete bool.
    #[test]
    fn valid_filter_expressions_evaluate(
        user in "[0-9]{1,6}",
        op in prop::sample::select(vec!["==", "!=", "=~"]),
        loss in 0u8..=100u8,
    ) {
        let dialog = sample_dialog();
        let expr = format!("from.user {op} '{user}' AND rtp.loss > {loss}");
        let filter = FilterExpr::parse(&expr)
            .unwrap_or_else(|e| panic!("valid expr {expr:?} must parse: {e}"));
        let _got: bool = filter.matches_dialog(&dialog, &[]);
    }
}
