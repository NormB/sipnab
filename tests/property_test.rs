// SPDX-License-Identifier: MIT OR Apache-2.0

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
use sipnab::rtp::diagnosis::CaptureMedia;
use sipnab::sip::dialog::SipDialog;
use sipnab::sip::dsl::FilterExpr;
use sipnab::sip::parser::parse_sip;
use sipnab::sip::sdp::parse_sdp;

/// Fixed endpoint address (10.0.0.1) used for every generated message.
fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

/// Fixed deterministic timestamp (2024-06-15 12:00:00 UTC) for parses.
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

/// A concrete `SipDialog` built from a fixed INVITE, used as the evaluation
/// target for generated filter expressions.
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
            let _ = filter.matches_dialog(
                &dialog,
                &[],
                CaptureMedia::Absent,
                sipnab::rtp::quality::MosDelay::unknown(),
            );
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
        let _got: bool = filter.matches_dialog(
                &dialog,
                &[],
                CaptureMedia::Absent,
                sipnab::rtp::quality::MosDelay::unknown(),
            );
    }
}

// ── The capture analysis, RFC 7951-encoded ──────────────────────────

/// `sipnab::analysis` exists only in native builds, and this file compiles in
/// every feature combination CI checks.
#[cfg(feature = "native")]
mod rfc7951_round_trip {
    use proptest::prelude::*;

    /// A string for an evidence field: printable ASCII most of the time, any
    /// character at all some of the time, and — deliberately, since arbitrary
    /// Unicode almost never lands on them — strings dense with the characters
    /// YANG's `string` type cannot carry: C0 controls, U+FFFE and U+FFFF.
    /// Without that third arm a mutation that stopped replacing them passed
    /// this test.
    fn evidence_text() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => "[ -~]{0,24}",
            1 => any::<String>(),
            1 => "[a-z\\x00-\\x1F\\x{FFFE}\\x{FFFF}]{1,12}",
        ]
    }

    /// One evidence row with every field independently present or absent.
    fn evidence() -> impl Strategy<Value = sipnab::analysis::Evidence> {
        use sipnab::analysis::CountLabel;
        (
            proptest::option::of(evidence_text()),
            proptest::collection::vec(evidence_text(), 0..3),
            proptest::option::of(0i64..4_000_000_000_000),
            proptest::sample::subsequence(CountLabel::ALL.to_vec(), 0..4),
            proptest::collection::vec(any::<u64>(), 4),
            proptest::option::of(evidence_text()),
        )
            .prop_map(|(call_id, endpoints, at_ms, labels, values, note)| {
                sipnab::analysis::Evidence {
                    call_id,
                    endpoints,
                    at: at_ms.and_then(chrono::DateTime::from_timestamp_millis),
                    counts: labels.into_iter().zip(values).collect(),
                    note,
                }
            })
    }

    /// An analysis: any subset of kinds, each with any counts and evidence.
    ///
    /// The kinds are a subsequence of `FindingKind::ALL`, so at most one finding
    /// per kind — the property the YANG list key depends on and the accumulator
    /// guarantees.
    fn capture_analysis() -> impl Strategy<Value = sipnab::analysis::CaptureAnalysis> {
        use sipnab::analysis::{
            CAPTURE_ANALYSIS_SCHEMA_VERSION, CaptureAnalysis, Finding, FindingKind,
        };
        let finding = |kind: FindingKind| {
            (
                any::<u64>(),
                proptest::collection::vec(evidence(), 0..4),
                any::<u64>(),
            )
                .prop_map(move |(occurrences, evidence, evidence_omitted)| Finding {
                    kind,
                    severity: kind.meta().severity,
                    occurrences,
                    unit: kind.meta().unit,
                    evidence,
                    evidence_omitted,
                })
        };
        (
            proptest::option::of(evidence_text()),
            any::<u64>(),
            any::<u32>(),
            any::<u32>(),
            any::<bool>(),
            proptest::sample::subsequence(FindingKind::ALL.to_vec(), 0..6),
        )
            .prop_flat_map(move |(filter, frames, dialogs, streams, complete, kinds)| {
                let findings: Vec<_> = kinds.into_iter().map(finding).collect();
                (Just((filter, frames, dialogs, streams, complete)), findings)
            })
            .prop_map(
                |((filter, frames_read, dialogs, streams, complete), findings)| CaptureAnalysis {
                    schema_version: CAPTURE_ANALYSIS_SCHEMA_VERSION,
                    filter,
                    frames_read,
                    dialogs_examined: dialogs as usize,
                    streams_examined: streams as usize,
                    complete,
                    findings,
                },
            )
    }

    /// Every string in a plain JSON value, as the RFC 7951 encoding writes it.
    fn yang_strings(v: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::String(s) => Value::String(sipnab::analysis::yang::yang_string(s)),
            Value::Array(items) => Value::Array(items.iter().map(yang_strings).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), yang_strings(v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// The structural rules of RFC 7951 and of the module, checked on a document.
    fn assert_rfc7951_shape(doc: &serde_json::Value) {
        use serde_json::Value;
        let top = doc.as_object().expect("the document is an object");
        assert_eq!(top.len(), 1, "exactly one top-level member: {doc}");
        let body = &top["sipnab-diagnosis:capture-analysis"];
        for key in ["frames-read", "dialogs-examined", "streams-examined"] {
            assert!(
                body[key].is_string(),
                "{key} is a uint64, so a string: {body}"
            );
        }
        assert!(
            body["schema-version"].is_u64(),
            "schema-version is a uint32"
        );
        let findings = body["finding"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        for (i, f) in findings.iter().enumerate() {
            assert_eq!(f["rank"], Value::from(i + 1), "rank counts from 1 in order");
            for key in ["occurrences", "evidence-omitted"] {
                assert!(f[key].is_string(), "{key} is a uint64: {f}");
            }
            let evidence = f["evidence"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            for (j, e) in evidence.iter().enumerate() {
                assert_eq!(e["index"], Value::from(j + 1), "index counts from 1");
                for c in e["count"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                    assert!(c["value"].is_string(), "a count is a uint64: {c}");
                }
                for s in ["call-id", "note"] {
                    if let Some(text) = e.get(s).and_then(Value::as_str) {
                        assert!(
                            text.chars().all(sipnab::analysis::yang::yang_string_char),
                            "{s} holds a character YANG cannot carry: {text:?}"
                        );
                    }
                }
            }
        }
    }

    proptest! {
        /// Every analysis encodes, the document obeys RFC 7951's rules, and it
        /// decodes back to the plain JSON of the same analysis — the one change
        /// being a character YANG cannot carry, written as U+FFFD.
        #[test]
        fn every_analysis_survives_the_rfc_7951_round_trip(analysis in capture_analysis()) {
            use sipnab::analysis::yang;
            let plain = serde_json::to_value(&analysis).expect("serializes");
            let doc = yang::to_rfc7951(&analysis).expect("every analysis encodes");
            assert_rfc7951_shape(&doc);
            let back = yang::decode(&doc).expect("every document decodes");
            prop_assert_eq!(back, yang_strings(&plain));
        }
    }
}
