// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The per-message parse cache ([`super::ParseCache`]): the CSeq position and
//! the media summary, each read once and kept on the message.
//!
//! Three groups:
//!
//! * The CSeq position: the cached answer is the parsed one, a missing or
//!   malformed header answers `None` as before, and a position past what the
//!   packed word holds falls back to a fresh parse with the same answer.
//! * The media summary: one [`MediaLine`] per `m=` line, the address exactly
//!   as written, filled on the first read (never at ingest), and parsed at
//!   most once across requests.
//! * The stale-data guard: the cache is derived from `headers` and `body`, so
//!   it is only correct while nothing writes those (or `raw`) after the parser
//!   builds the message. A scan of the production source refuses any such
//!   write it does not know to be on another type.
//!
//! Every fixture is synthetic: RFC 5737 / RFC 3849 addresses, `example.com`
//! names.

use super::{MediaLine, SipHeader, SipMessage, media_lines_of, msg_key};
use crate::net::TransportProto;
use crate::sip::parser::parse_sip;
use crate::sip::sdp::SdpDirection;
use crate::test_utils::build_sip_message;
use std::borrow::Cow;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[path = "../../../tests/support/source_scan.rs"]
mod source_scan;

type TestError = Box<dyn std::error::Error>;

/// A fixed capture time, so nothing here depends on the clock.
fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap_or_default()
}

/// Parse one message made of `first`, `headers` and `body`.
fn parse(first: &str, headers: &[&str], body: &[u8]) -> Result<SipMessage, TestError> {
    let raw = build_sip_message(first, headers, body);
    parse_sip(
        &raw,
        ts(),
        [192, 0, 2, 1].into(),
        [192, 0, 2, 2].into(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .map_err(|e| format!("the fixture must parse: {e:?}").into())
}

/// An INVITE whose CSeq lines are `cseq` (none, one or several).
fn with_cseq(cseq: &[&str]) -> Result<SipMessage, TestError> {
    let mut headers = vec![
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-cache",
        "From: <sip:a@example.com>;tag=1",
        "To: <sip:b@example.com>",
        "Call-ID: cache@example.com",
    ];
    headers.extend_from_slice(cseq);
    parse("INVITE sip:b@example.com SIP/2.0", &headers, b"")
}

/// An INVITE carrying `body` as `content_type` (no header when `None`).
fn with_body(content_type: Option<&str>, body: &str) -> Result<SipMessage, TestError> {
    let ct = content_type.map(|ct| format!("Content-Type: {ct}"));
    let mut headers = vec![
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-cache",
        "From: <sip:a@example.com>;tag=1",
        "To: <sip:b@example.com>",
        "Call-ID: cache-sdp@example.com",
        "CSeq: 1 INVITE",
    ];
    if let Some(ct) = ct.as_deref() {
        headers.push(ct);
    }
    parse(
        "INVITE sip:b@example.com SIP/2.0",
        &headers,
        body.as_bytes(),
    )
}

/// An INVITE carrying `body` as `application/sdp`.
fn with_sdp(body: &str) -> Result<SipMessage, TestError> {
    with_body(Some("application/sdp"), body)
}

/// An SDP session whose session-level `c=` is `session_c` (none when
/// empty), followed by `media` (each a block of `m=` and its lines).
fn sdp_text(session_c: &str, media: &[&str]) -> String {
    let mut s = String::from("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\n");
    if !session_c.is_empty() {
        s.push_str(session_c);
        s.push_str("\r\n");
    }
    s.push_str("t=0 0\r\n");
    for m in media {
        s.push_str(m);
        s.push_str("\r\n");
    }
    s
}

/// The common one-line offer: audio to 192.0.2.10:16384.
fn audio_offer() -> String {
    sdp_text(
        "c=IN IP4 192.0.2.10",
        &["m=audio 16384 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000"],
    )
}

/// `(cseq parses, sdp parses)` of `msg` since [`crate::test_utils::clear_parses`].
fn parses_of(msg: &SipMessage) -> (u32, u32) {
    super::PARSES.with(|p| {
        p.borrow()
            .as_ref()
            .and_then(|p| p.get(&msg_key(msg)).copied())
            .unwrap_or_default()
    })
}

/// The summary of `msg`, which must hold SDP.
fn lines(msg: &SipMessage) -> Result<&[MediaLine], TestError> {
    msg.media_lines()
        .ok_or_else(|| "the message holds SDP, so it has a summary".into())
}

/// The address of `line` as an owned string, for comparisons.
fn addr(line: &MediaLine) -> Option<String> {
    line.address().map(Cow::into_owned)
}

// ── CSeq: answers ────────────────────────────────────────────────────

/// The cached answer is the parsed one: number and method.
#[test]
fn the_cseq_reads_number_and_method() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 314 INVITE"])?;
    assert_eq!(msg.cseq(), Some((314, "INVITE")), "first read");
    assert_eq!(
        msg.cseq(),
        Some((314, "INVITE")),
        "second read, from the cache"
    );
    Ok(())
}

/// Two reads of one message's CSeq parse it once.
#[test]
fn two_cseq_reads_parse_once() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 2 BYE"])?;
    crate::test_utils::clear_parses();
    for _ in 0..3 {
        assert_eq!(msg.cseq(), Some((2, "BYE")), "the answer");
    }
    assert_eq!(parses_of(&msg).0, 1, "three reads parse the CSeq once");
    Ok(())
}

/// A clone carries the kept answer: it reads its CSeq without a parse, and
/// the method it hands back borrows from its own headers.
#[test]
fn a_clone_reads_the_kept_cseq_without_a_parse() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 9 ACK"])?;
    assert_eq!(msg.cseq(), Some((9, "ACK")), "the original");
    let copy = msg.clone();
    drop(msg);
    crate::test_utils::clear_parses();
    assert_eq!(copy.cseq(), Some((9, "ACK")), "the clone");
    assert_eq!(parses_of(&copy).0, 0, "the clone parsed its CSeq again");
    Ok(())
}

/// The header name is matched in any case, as `header()` matches it.
#[test]
fn a_lowercase_cseq_name_is_found_and_kept() -> Result<(), TestError> {
    let msg = with_cseq(&["cseq: 7 OPTIONS"])?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((7, "OPTIONS")), "first read");
    assert_eq!(msg.cseq(), Some((7, "OPTIONS")), "second read");
    assert_eq!(parses_of(&msg).0, 1, "kept after one parse");
    Ok(())
}

/// The header name in capitals is the same header.
#[test]
fn an_uppercase_cseq_name_is_found() -> Result<(), TestError> {
    let msg = with_cseq(&["CSEQ: 8 INFO"])?;
    assert_eq!(msg.cseq(), Some((8, "INFO")), "first read");
    assert_eq!(msg.cseq(), Some((8, "INFO")), "second read");
    Ok(())
}

/// Trailing garbage after the method is ignored, cached or not.
#[test]
fn trailing_garbage_after_the_method_is_ignored() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 1 INVITE extra words"])?;
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "second read");
    Ok(())
}

/// A tab between number and method is linear white space.
#[test]
fn a_tab_separated_cseq_is_read() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 5\tPRACK"])?;
    assert_eq!(msg.cseq(), Some((5, "PRACK")), "first read");
    assert_eq!(msg.cseq(), Some((5, "PRACK")), "second read");
    Ok(())
}

/// The largest number RFC 3261 allows a CSeq to carry (2**32 - 1).
#[test]
fn the_largest_cseq_number_is_read() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 4294967295 INVITE"])?;
    assert_eq!(msg.cseq(), Some((u32::MAX, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((u32::MAX, "INVITE")), "second read");
    Ok(())
}

/// A CSeq that is the last of many headers is found at its own index.
#[test]
fn a_cseq_after_many_headers_is_kept_at_its_index() -> Result<(), TestError> {
    let extra: Vec<String> = (0..40).map(|n| format!("X-Pad-{n}: {n}")).collect();
    let mut cseq: Vec<&str> = extra.iter().map(String::as_str).collect();
    cseq.push("CSeq: 41 UPDATE");
    let msg = with_cseq(&cseq)?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((41, "UPDATE")), "first read");
    assert_eq!(msg.cseq(), Some((41, "UPDATE")), "second read");
    assert_eq!(parses_of(&msg).0, 1, "kept after one parse");
    Ok(())
}

/// The dialog helper over a message list reads each message's kept CSeq:
/// a second pass parses none.
#[test]
fn a_second_pass_over_a_call_parses_no_cseq() -> Result<(), TestError> {
    let call = crate::test_utils::sdp_call("cseq-twice@example.com")?;
    crate::test_utils::clear_parses();
    let first = super::cseqs(&call);
    let second = super::cseqs(&call);
    assert_eq!(first, second, "both passes answer the same");
    for msg in &call {
        assert_eq!(parses_of(msg).0, 1, "a message's CSeq was parsed again");
    }
    Ok(())
}

// ── CSeq: no answer ──────────────────────────────────────────────────

/// No CSeq header: `None`, on every read.
#[test]
fn a_missing_cseq_is_none() -> Result<(), TestError> {
    let msg = with_cseq(&[])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

/// A number that is not one: `None`.
#[test]
fn a_non_numeric_cseq_is_none() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: x INVITE"])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

/// A number past 2**32 - 1: `None`, as before the cache.
#[test]
fn a_cseq_number_past_u32_is_none() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 4294967296 INVITE"])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

/// A number with no method: `None`.
#[test]
fn a_cseq_without_a_method_is_none() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 1"])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

/// An empty CSeq value: `None`.
#[test]
fn an_empty_cseq_is_none() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq:"])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

/// A negative number: `None`.
#[test]
fn a_negative_cseq_is_none() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: -1 INVITE"])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

// ── CSeq: edges ──────────────────────────────────────────────────────

/// Two CSeq headers: the first one answers, cached or not.
#[test]
fn of_two_cseq_headers_the_first_answers() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 1 INVITE", "CSeq: 2 BYE"])?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "second read");
    assert_eq!(parses_of(&msg).0, 1, "the first header's position is kept");
    Ok(())
}

/// A malformed first CSeq is the answer even with a good second one:
/// `None`, which is what `header()` (the first match) always gave.
#[test]
fn a_malformed_first_cseq_hides_a_good_second() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: bad", "CSeq: 2 BYE"])?;
    assert_eq!(msg.cseq(), None, "first read");
    assert_eq!(msg.cseq(), None, "second read");
    Ok(())
}

/// `msg` with its CSeq value replaced by `value`, before anything read it.
fn with_cseq_value(value: String) -> Result<SipMessage, TestError> {
    let mut msg = with_cseq(&["CSeq: 1 INVITE"])?;
    let h = msg
        .headers
        .iter_mut()
        .find(|h| h.name.eq_ignore_ascii_case("CSeq"))
        .ok_or("the fixture has a CSeq")?;
    h.value = value;
    Ok(msg)
}

/// The largest value a packed field of `bits` bits holds.
fn field_max(bits: u32) -> usize {
    (1 << bits) - 1
}

/// The method starting at the last offset the packed word holds: kept.
#[test]
fn a_method_at_the_last_packed_offset_is_kept() -> Result<(), TestError> {
    let start = field_max(super::CSEQ_START_BITS);
    let msg = with_cseq_value(format!("1{}INVITE", " ".repeat(start - 1)))?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "second read");
    assert_eq!(parses_of(&msg).0, 1, "a position that fits is kept");
    Ok(())
}

/// The method starting one past that: the same answer, parsed on each read.
#[test]
fn a_method_past_the_packed_offsets_is_parsed_each_read() -> Result<(), TestError> {
    let start = field_max(super::CSEQ_START_BITS) + 1;
    let msg = with_cseq_value(format!("1{}INVITE", " ".repeat(start - 1)))?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((1, "INVITE")), "second read");
    assert!(
        parses_of(&msg).0 >= 2,
        "a position past the word is not kept, so each read parses"
    );
    Ok(())
}

/// A method of the longest length the packed word holds: kept.
#[test]
fn a_method_of_the_last_packed_length_is_kept() -> Result<(), TestError> {
    let method = "M".repeat(field_max(super::CSEQ_LEN_BITS));
    let msg = with_cseq_value(format!("6 {method}"))?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((6, method.as_str())), "first read");
    assert_eq!(msg.cseq(), Some((6, method.as_str())), "second read");
    assert_eq!(parses_of(&msg).0, 1, "a length that fits is kept");
    Ok(())
}

/// A method one byte longer: the same answer, parsed on each read.
#[test]
fn a_method_past_the_packed_length_is_parsed_each_read() -> Result<(), TestError> {
    let method = "M".repeat(field_max(super::CSEQ_LEN_BITS) + 1);
    let msg = with_cseq_value(format!("6 {method}"))?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((6, method.as_str())), "first read");
    assert_eq!(msg.cseq(), Some((6, method.as_str())), "second read");
    assert!(
        parses_of(&msg).0 >= 2,
        "a length past the word is not kept, so each read parses"
    );
    Ok(())
}

/// The largest CSeq number with the largest kept position: no field of
/// the packed word spills into another.
#[test]
fn the_largest_number_and_position_pack_apart() -> Result<(), TestError> {
    let start = field_max(super::CSEQ_START_BITS);
    let method = "M".repeat(field_max(super::CSEQ_LEN_BITS));
    let value = format!("4294967295{}{method}", " ".repeat(start - 10));
    let before = with_cseq(&[])?.headers.len();
    let mut msg = with_padding(field_max(super::CSEQ_HEADER_BITS) - before)?;
    let h = msg
        .headers
        .iter_mut()
        .find(|h| h.name.eq_ignore_ascii_case("CSeq"))
        .ok_or("the fixture has a CSeq")?;
    h.value = value;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((u32::MAX, method.as_str())), "first read");
    assert_eq!(msg.cseq(), Some((u32::MAX, method.as_str())), "second read");
    assert_eq!(parses_of(&msg).0, 1, "every field at its largest is kept");
    Ok(())
}

/// `msg` with `pad` headers inserted before its CSeq.
fn with_padding(pad: usize) -> Result<SipMessage, TestError> {
    let mut msg = with_cseq(&["CSeq: 3 INVITE"])?;
    let at = msg
        .headers
        .iter()
        .position(|h| h.name.eq_ignore_ascii_case("CSeq"))
        .ok_or("the fixture has a CSeq")?;
    let filler = SipHeader {
        name: Cow::Borrowed("X-Pad"),
        value: String::new(),
        line_span: None,
    };
    msg.headers.splice(at..at, std::iter::repeat_n(filler, pad));
    Ok(msg)
}

/// A CSeq at the last header index the packed word holds: kept.
#[test]
fn a_cseq_at_the_last_packed_index_is_kept() -> Result<(), TestError> {
    let before = with_cseq(&[])?.headers.len();
    let msg = with_padding(field_max(super::CSEQ_HEADER_BITS) - before)?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((3, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((3, "INVITE")), "second read");
    assert_eq!(parses_of(&msg).0, 1, "an index that fits is kept");
    Ok(())
}

/// A CSeq one header further: the same answer, parsed on each read.
#[test]
fn a_cseq_past_the_packed_indexes_is_parsed_each_read() -> Result<(), TestError> {
    let before = with_cseq(&[])?.headers.len();
    let msg = with_padding(field_max(super::CSEQ_HEADER_BITS) + 1 - before)?;
    crate::test_utils::clear_parses();
    assert_eq!(msg.cseq(), Some((3, "INVITE")), "first read");
    assert_eq!(msg.cseq(), Some((3, "INVITE")), "second read");
    assert!(
        parses_of(&msg).0 >= 2,
        "an index past the word is not kept, so each read parses"
    );
    Ok(())
}

/// A method that is not ASCII is cut on its own character boundaries.
#[test]
fn a_non_ascii_method_is_read_whole() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 4 INVIT\u{c9}"])?;
    assert_eq!(msg.cseq(), Some((4, "INVIT\u{c9}")), "first read");
    assert_eq!(msg.cseq(), Some((4, "INVIT\u{c9}")), "second read");
    Ok(())
}

// ── Media summary: answers ───────────────────────────────────────────

/// One audio line: the address as written, port, RTP and direction.
#[test]
fn an_audio_line_is_summarized() -> Result<(), TestError> {
    let msg = with_sdp(&audio_offer())?;
    let l = lines(&msg)?;
    assert_eq!(l.len(), 1, "one m= line");
    assert_eq!(addr(&l[0]).as_deref(), Some("192.0.2.10"), "address");
    assert_eq!(l[0].ip(), Some(IpAddr::from([192, 0, 2, 10])), "IP");
    assert_eq!(l[0].port(), 16384, "port");
    assert!(l[0].carries_rtp(), "RTP/AVP is RTP");
    assert_eq!(
        l[0].direction(),
        SdpDirection::SendRecv,
        "default direction"
    );
    Ok(())
}

/// A media-level `c=` wins over the session's.
#[test]
fn a_media_level_address_wins() -> Result<(), TestError> {
    let body = sdp_text(
        "c=IN IP4 192.0.2.10",
        &["m=audio 16384 RTP/AVP 0\r\nc=IN IP4 198.51.100.7"],
    );
    let msg = with_sdp(&body)?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("198.51.100.7"), "media c=");
    Ok(())
}

/// With no media-level `c=`, the session's applies.
#[test]
fn the_session_address_applies_to_a_line_without_one() -> Result<(), TestError> {
    let body = sdp_text(
        "c=IN IP4 203.0.113.5",
        &[
            "m=audio 4000 RTP/AVP 0",
            "m=video 4002 RTP/AVP 96\r\nc=IN IP4 192.0.2.99",
        ],
    );
    let msg = with_sdp(&body)?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("203.0.113.5"), "session c=");
    assert_eq!(addr(&l[1]).as_deref(), Some("192.0.2.99"), "media c=");
    Ok(())
}

/// Several `m=` lines are summarized in order.
#[test]
fn several_lines_keep_their_order() -> Result<(), TestError> {
    let body = sdp_text(
        "c=IN IP4 192.0.2.10",
        &[
            "m=audio 5000 RTP/AVP 0",
            "m=video 5002 RTP/AVP 96",
            "m=image 5004 udptl t38",
        ],
    );
    let msg = with_sdp(&body)?;
    let ports: Vec<u16> = lines(&msg)?.iter().map(MediaLine::port).collect();
    assert_eq!(ports, [5000, 5002, 5004], "one line per m=, in order");
    Ok(())
}

/// Secure and WebRTC profiles are RTP.
#[test]
fn secure_rtp_profiles_carry_rtp() -> Result<(), TestError> {
    let body = sdp_text(
        "c=IN IP4 192.0.2.10",
        &[
            "m=audio 5000 RTP/SAVP 0",
            "m=audio 5002 UDP/TLS/RTP/SAVPF 111",
        ],
    );
    let msg = with_sdp(&body)?;
    assert!(
        lines(&msg)?.iter().all(MediaLine::carries_rtp),
        "RTP/SAVP and UDP/TLS/RTP/SAVPF are RTP"
    );
    Ok(())
}

/// The transport is matched in any case.
#[test]
fn a_lowercase_rtp_profile_carries_rtp() -> Result<(), TestError> {
    let body = sdp_text("c=IN IP4 192.0.2.10", &["m=audio 5000 rtp/avp 0"]);
    let msg = with_sdp(&body)?;
    assert!(lines(&msg)?[0].carries_rtp(), "rtp/avp is RTP");
    Ok(())
}

/// Each line's direction is the parsed one.
#[test]
fn each_line_keeps_its_direction() -> Result<(), TestError> {
    let body = sdp_text(
        "c=IN IP4 192.0.2.10",
        &[
            "m=audio 5000 RTP/AVP 0\r\na=sendonly",
            "m=audio 5002 RTP/AVP 0\r\na=recvonly",
            "m=audio 5004 RTP/AVP 0\r\na=inactive",
        ],
    );
    let msg = with_sdp(&body)?;
    let parsed = msg.sdp().ok_or("the SDP parses")?;
    let want: Vec<SdpDirection> = parsed.media.iter().map(|m| m.direction).collect();
    let got: Vec<SdpDirection> = lines(&msg)?.iter().map(MediaLine::direction).collect();
    assert_eq!(got, want, "the parsed directions");
    assert_eq!(
        got,
        [
            SdpDirection::SendOnly,
            SdpDirection::RecvOnly,
            SdpDirection::Inactive
        ],
        "as written"
    );
    Ok(())
}

/// Two reads of the summary parse the SDP once.
#[test]
fn two_summary_reads_parse_once() -> Result<(), TestError> {
    let msg = with_sdp(&audio_offer())?;
    crate::test_utils::clear_parses();
    let first = lines(&msg)?.to_vec();
    let second = lines(&msg)?.to_vec();
    assert_eq!(first, second, "one summary");
    assert_eq!(parses_of(&msg).1, 1, "two reads parse the SDP once");
    Ok(())
}

/// Ingest builds no summary: every message in a store nobody queried has
/// none, so a capture that is only read costs no summary memory.
#[test]
fn ingest_builds_no_summary() -> Result<(), TestError> {
    let store = store_unread(2)?;
    for d in store.iter() {
        for m in &d.messages {
            assert!(m.cache.media.get().is_none(), "ingest built a summary");
        }
    }
    Ok(())
}

/// The summary of a message is the summary of its parsed SDP.
#[test]
fn the_message_summary_is_the_session_summary() -> Result<(), TestError> {
    let body = sdp_text(
        "c=IN IP4 192.0.2.10",
        &[
            "m=audio 5000 RTP/AVP 0",
            "m=video 0 RTP/AVP 96\r\na=inactive",
        ],
    );
    let msg = with_sdp(&body)?;
    let parsed = msg.sdp().ok_or("the SDP parses")?;
    assert_eq!(lines(&msg)?, &*media_lines_of(&parsed), "one rule");
    assert_eq!(media_lines_of(&parsed).len(), 2, "two m= lines");
    Ok(())
}

/// A multipart body's SDP part is summarized.
#[test]
fn a_multipart_sdp_part_is_summarized() -> Result<(), TestError> {
    let body = format!(
        "--b1\r\nContent-Type: application/sdp\r\n\r\n{}--b1\r\n\
         Content-Type: application/rs-metadata+xml\r\n\r\n<recording/>\r\n--b1--\r\n",
        audio_offer()
    );
    let msg = with_body(Some("multipart/mixed;boundary=b1"), &body)?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("192.0.2.10"), "the SDP part");
    Ok(())
}

/// A body that starts `v=` with no Content-Type is SDP, as `sdp()` reads it.
#[test]
fn an_untyped_sdp_body_is_summarized() -> Result<(), TestError> {
    let msg = with_body(None, &audio_offer())?;
    assert_eq!(lines(&msg)?.len(), 1, "the untyped SDP");
    Ok(())
}

/// A clone carries the summary: its first read parses nothing.
#[test]
fn a_clone_reads_the_kept_summary_without_a_parse() -> Result<(), TestError> {
    let msg = with_sdp(&audio_offer())?;
    let want = lines(&msg)?.to_vec();
    let copy = msg.clone();
    crate::test_utils::clear_parses();
    assert_eq!(lines(&copy)?, &*want, "the clone's summary");
    assert_eq!(parses_of(&copy).1, 0, "the clone parsed its SDP again");
    Ok(())
}

// ── Media summary: no summary ────────────────────────────────────────

/// A body that is not SDP has no summary, and that answer is kept too.
#[test]
fn a_non_sdp_body_has_no_summary_and_parses_once() -> Result<(), TestError> {
    let msg = with_body(Some("text/plain"), "hello")?;
    crate::test_utils::clear_parses();
    assert!(msg.media_lines().is_none(), "first read");
    assert!(msg.media_lines().is_none(), "second read");
    assert!(parses_of(&msg).1 <= 1, "the None is kept");
    Ok(())
}

/// SDP that does not parse has no summary.
#[test]
fn unparseable_sdp_has_no_summary() -> Result<(), TestError> {
    let msg = with_sdp("this is not a session description")?;
    crate::test_utils::clear_parses();
    assert!(msg.media_lines().is_none(), "first read");
    assert!(msg.media_lines().is_none(), "second read");
    assert_eq!(parses_of(&msg).1, 1, "the None is kept after one parse");
    Ok(())
}

/// No body: no summary.
#[test]
fn an_empty_body_has_no_summary() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 1 INVITE"])?;
    assert!(msg.media_lines().is_none(), "no body");
    Ok(())
}

/// A line with no `c=` anywhere has no address and no IP.
#[test]
fn a_line_without_any_address_has_none() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text("", &["m=audio 5000 RTP/AVP 0"]))?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]), None, "no c= line");
    assert_eq!(l[0].ip(), None, "no IP");
    Ok(())
}

/// A "no SDP" answer already read is carried by a clone, which reads it
/// with no parse.
#[test]
fn a_clone_reads_a_kept_none_without_a_parse() -> Result<(), TestError> {
    let msg = with_body(Some("text/plain"), "hello")?;
    assert!(msg.media_lines().is_none(), "no SDP");
    let copy = msg.clone();
    crate::test_utils::clear_parses();
    assert!(copy.media_lines().is_none(), "the clone's none");
    assert_eq!(parses_of(&copy).1, 0, "a kept none parses nothing");
    Ok(())
}

/// A host name in `c=` is kept as written and is no IP.
#[test]
fn a_host_name_address_is_kept_and_is_no_ip() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text(
        "c=IN IP4 media.example.com",
        &["m=audio 5000 RTP/AVP 0"],
    ))?;
    let l = lines(&msg)?;
    assert_eq!(
        addr(&l[0]).as_deref(),
        Some("media.example.com"),
        "as written"
    );
    assert_eq!(l[0].ip(), None, "a host name is no IP");
    Ok(())
}

/// A multipart body without an SDP part has no summary.
#[test]
fn a_multipart_body_without_sdp_has_no_summary() -> Result<(), TestError> {
    let body = "--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b1--\r\n";
    let msg = with_body(Some("multipart/mixed;boundary=b1"), body)?;
    assert!(msg.media_lines().is_none(), "no SDP part");
    Ok(())
}

/// An IPv4 address with a leading zero is no IP literal: kept as written,
/// and no IP.
#[test]
fn a_leading_zero_ipv4_is_kept_as_written_and_is_no_ip() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text(
        "c=IN IP4 192.0.2.010",
        &["m=audio 5000 RTP/AVP 0"],
    ))?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("192.0.2.010"), "as written");
    assert_eq!(l[0].ip(), None, "not an IP literal to std");
    Ok(())
}

/// An IPv6 address with a zone is no IP literal.
#[test]
fn an_ipv6_address_with_a_zone_is_no_ip() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text(
        "c=IN IP6 fe80::1%eth0",
        &["m=audio 5000 RTP/AVP 0"],
    ))?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("fe80::1%eth0"), "as written");
    assert_eq!(l[0].ip(), None, "a zone is not part of an IP literal");
    Ok(())
}

// ── Media summary: edges ─────────────────────────────────────────────

/// The cache grows every stored message, and ingest moves each message
/// several times: the size is pinned, so any growth is a decision. 312
/// bytes before the cache; the CSeq word adds 8 and the boxed summary 16.
#[test]
fn a_message_grows_by_at_most_24_bytes() {
    assert!(
        std::mem::size_of::<SipMessage>() <= 312 + 24,
        "SipMessage is {} bytes",
        std::mem::size_of::<SipMessage>()
    );
    assert!(
        std::mem::size_of::<super::ParseCache>() <= 24,
        "ParseCache is {} bytes",
        std::mem::size_of::<super::ParseCache>()
    );
}

/// A clone of a message nobody read yet reads its own CSeq once, and the
/// original still has none kept.
#[test]
fn a_clone_of_an_unread_message_parses_its_own_cseq_once() -> Result<(), TestError> {
    let msg = with_cseq(&["CSeq: 12 REFER"])?;
    let copy = msg.clone();
    crate::test_utils::clear_parses();
    assert_eq!(copy.cseq(), Some((12, "REFER")), "first read");
    assert_eq!(copy.cseq(), Some((12, "REFER")), "second read");
    assert_eq!(parses_of(&copy).0, 1, "the clone kept its own");
    assert_eq!(
        msg.cache.cseq.load(),
        super::CSEQ_UNREAD,
        "the original is untouched"
    );
    Ok(())
}

/// `sdp()` is not cached: every reader that wants the whole session parses
/// it, as before.
#[test]
fn the_full_sdp_is_still_parsed_on_each_call() -> Result<(), TestError> {
    let msg = with_sdp(&audio_offer())?;
    let _ = lines(&msg)?;
    crate::test_utils::clear_parses();
    let a = msg.sdp().ok_or("first parse")?;
    let b = msg.sdp().ok_or("second parse")?;
    assert_eq!(a.media.len(), b.media.len(), "the same session");
    assert_eq!(parses_of(&msg).1, 2, "sdp() parses on each call");
    Ok(())
}

/// IPv6 in capitals is kept exactly as written.
#[test]
fn an_uppercase_ipv6_address_is_kept_as_written() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text(
        "c=IN IP6 2001:DB8::1",
        &["m=audio 5000 RTP/AVP 0"],
    ))?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("2001:DB8::1"), "as written");
    assert_eq!(l[0].ip(), "2001:db8::1".parse().ok(), "the IP");
    Ok(())
}

/// IPv6 written without `::` is kept as written, not compressed.
#[test]
fn an_uncompressed_ipv6_address_is_kept_as_written() -> Result<(), TestError> {
    let written = "2001:db8:0:0:0:0:0:1";
    let msg = with_sdp(&sdp_text(
        &format!("c=IN IP6 {written}"),
        &["m=audio 5000 RTP/AVP 0"],
    ))?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some(written), "as written");
    assert_eq!(l[0].ip(), "2001:db8::1".parse().ok(), "the IP");
    Ok(())
}

/// An IPv4-mapped IPv6 address is kept as written.
#[test]
fn an_ipv4_mapped_address_is_kept_as_written() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text(
        "c=IN IP6 ::ffff:192.0.2.1",
        &["m=audio 5000 RTP/AVP 0"],
    ))?;
    let l = lines(&msg)?;
    assert_eq!(
        addr(&l[0]).as_deref(),
        Some("::ffff:192.0.2.1"),
        "as written"
    );
    assert_eq!(l[0].ip(), "::ffff:192.0.2.1".parse().ok(), "the IP");
    Ok(())
}

/// A declined line (port 0) is summarized with its port.
#[test]
fn a_declined_line_keeps_port_zero() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text("c=IN IP4 192.0.2.10", &["m=video 0 RTP/AVP 96"]))?;
    assert_eq!(lines(&msg)?[0].port(), 0, "declined");
    Ok(())
}

/// The RFC 2543 hold address is an IP, the unspecified one.
#[test]
fn the_hold_address_is_the_unspecified_ip() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text("c=IN IP4 0.0.0.0", &["m=audio 5000 RTP/AVP 0"]))?;
    let l = lines(&msg)?;
    assert_eq!(addr(&l[0]).as_deref(), Some("0.0.0.0"), "as written");
    assert!(
        l[0].ip().is_some_and(|ip| ip.is_unspecified()),
        "unspecified"
    );
    Ok(())
}

/// SDP with no `m=` line has an empty summary, not none: it is SDP.
#[test]
fn sdp_without_media_has_an_empty_summary() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text("c=IN IP4 192.0.2.10", &[]))?;
    assert_eq!(lines(&msg)?.len(), 0, "SDP with no m= line");
    Ok(())
}

/// T.38 is no RTP.
#[test]
fn a_t38_line_carries_no_rtp() -> Result<(), TestError> {
    let msg = with_sdp(&sdp_text(
        "c=IN IP4 192.0.2.10",
        &["m=image 5004 udptl t38"],
    ))?;
    assert!(!lines(&msg)?[0].carries_rtp(), "udptl is not RTP");
    Ok(())
}

// ── Across requests, through the store ───────────────────────────────

/// A dialog store holding `n` answered calls, each message read as the
/// pipeline reads it: its SDP parsed by the caller and handed over.
#[cfg(not(target_arch = "wasm32"))]
fn store_as_the_pipeline_fills_it(
    n: usize,
) -> Result<crate::sip::dialog_store::DialogStore, TestError> {
    use crate::sip::sdp::SdpRead;
    let mut store = crate::sip::dialog_store::DialogStore::new(64, false);
    for k in 0..n {
        for msg in crate::test_utils::sdp_call(&format!("piped-{k}@example.com"))? {
            let read = SdpRead::Read(msg.sdp().map(Box::new));
            store.process_message_read(msg, &read);
        }
    }
    Ok(store)
}

/// A store filled by plain `process_message` (no SDP read handed over).
fn store_unread(n: usize) -> Result<crate::sip::dialog_store::DialogStore, TestError> {
    let mut store = crate::sip::dialog_store::DialogStore::new(64, false);
    for k in 0..n {
        for msg in crate::test_utils::sdp_call(&format!("unread-{k}@example.com"))? {
            store.process_message(msg);
        }
    }
    Ok(store)
}

/// The pipeline's path into the store (an SDP parse handed over) builds no
/// summary either; two reads afterwards parse each message's SDP once.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn the_pipelines_path_builds_no_summary_and_reads_once() -> Result<(), TestError> {
    let store = store_as_the_pipeline_fills_it(2)?;
    for d in store.iter() {
        for m in &d.messages {
            assert!(m.cache.media.get().is_none(), "ingest built a summary");
        }
    }
    crate::test_utils::clear_parses();
    let mut with_sdp = 0;
    for _ in 0..2 {
        for d in store.iter() {
            for m in &d.messages {
                with_sdp += usize::from(m.media_lines().is_some());
            }
        }
    }
    let (_, sdp, read) = crate::test_utils::worst_parses();
    assert_eq!(read, 14, "every message was read");
    assert_eq!(with_sdp, 8, "the offer and the answer of each call, twice");
    assert_eq!(
        sdp, 1,
        "a message's SDP was parsed {sdp} times over two reads"
    );
    Ok(())
}

/// The same reads twice over a store nobody summarized: each message's SDP
/// is parsed at most once across both.
#[test]
fn a_second_read_over_the_store_parses_no_sdp() -> Result<(), TestError> {
    let store = store_unread(2)?;
    crate::test_utils::clear_parses();
    for _ in 0..2 {
        for d in store.iter() {
            for m in &d.messages {
                let _ = m.media_lines();
            }
        }
    }
    let (_, sdp, read) = crate::test_utils::worst_parses();
    assert_eq!(read, 14, "every message was read");
    assert_eq!(
        sdp, 1,
        "a message's SDP was parsed {sdp} times over two reads"
    );
    Ok(())
}

/// Two capture analyses parse each message's CSeq and SDP at most once
/// across both: the second reads what the first kept.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
#[test]
fn two_analyses_parse_each_message_once() -> Result<(), TestError> {
    let dialogs = store_unread(3)?;
    let streams = crate::rtp::stream_store::StreamStore::new(16);
    let facts = crate::analysis::CaptureFacts::default();
    crate::test_utils::clear_parses();
    let a = crate::analysis::analyze_with(&dialogs, &streams, None, &facts);
    let b = crate::analysis::analyze_with(&dialogs, &streams, None, &facts);
    assert_eq!(
        format!("{:?}", a.findings),
        format!("{:?}", b.findings),
        "the same findings"
    );
    let (cseq, sdp, read) = crate::test_utils::worst_parses();
    assert_eq!(read, 21, "both analyses read all 21 messages");
    assert!(cseq <= 1, "a message's CSeq was parsed {cseq} times");
    assert!(sdp <= 1, "a message's SDP was parsed {sdp} times");
    Ok(())
}

/// Two filter passes (the `problems` alias, which reads the diagnosis)
/// parse each message's CSeq and SDP at most once across both.
#[test]
fn two_filter_passes_parse_each_message_once() -> Result<(), TestError> {
    use crate::rtp::diagnosis::CaptureMedia;
    use crate::rtp::quality::MosDelay;
    use crate::sip::dsl::{AliasThresholds, FilterExpr, expand_alias};
    let store = store_unread(1)?;
    let dialog = store.iter().next().ok_or("the call opened a dialog")?;
    let expr = FilterExpr::parse(
        &expand_alias("problems", &AliasThresholds::default()).ok_or("the alias exists")?,
    )?;
    crate::test_utils::clear_parses();
    for pass in 0..2 {
        assert!(
            !expr.matches_dialog(dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "pass {pass}: a clean answered call is not a problem"
        );
    }
    let (cseq, sdp, read) = crate::test_utils::worst_parses();
    assert_eq!(read, 7, "the filter read all seven messages");
    assert!(cseq <= 1, "a message's CSeq was parsed {cseq} times");
    assert!(sdp <= 1, "a message's SDP was parsed {sdp} times");
    Ok(())
}

/// Two metrics scrapes parse each message's CSeq and SDP at most once
/// across both.
#[cfg(feature = "native")]
#[test]
fn two_metrics_scrapes_parse_each_message_once() -> Result<(), TestError> {
    use crate::output::prometheus::{PrometheusMetrics, populate_from_stores};
    let dialogs = store_unread(2)?;
    let streams = crate::rtp::stream_store::StreamStore::new(16);
    crate::test_utils::clear_parses();
    for _ in 0..2 {
        let mut m = PrometheusMetrics::for_scrape();
        populate_from_stores(&mut m, &dialogs, &streams);
    }
    let (cseq, sdp, read) = crate::test_utils::worst_parses();
    assert!(read > 0, "the scrapes read the messages");
    assert!(cseq <= 1, "a message's CSeq was parsed {cseq} times");
    assert!(sdp <= 1, "a message's SDP was parsed {sdp} times");
    Ok(())
}

// ── The stale-data guard ─────────────────────────────────────────────
//
// `ParseCache` holds what `headers` and `body` say. It is correct only while
// nothing changes those fields after the parser builds the message; the
// cache has no way to notice. So the production source is scanned for any
// write to a field named `headers`, `body` or `raw`, and for any place other
// than the parser that builds a `SipMessage`. A field of another type with
// one of those names is listed below with what it is. The scan is lexical
// (no types), so the list is checked both ways: a write it does not know
// fails, and an entry that no longer matches fails too.

/// The fields the cache is derived from (and the bytes they view).
const GUARDED: [&str; 3] = ["headers", "body", "raw"];

/// Writes to a guarded field name that are known to be on another type:
/// `(file under src/, the line as written, trimmed, what it writes)`.
const KNOWN_OTHER_WRITES: &[(&str, &str, &str)] = &[
    (
        "src/mcp/tools/vcon.rs",
        "record.body = record.body.take().map(|b| {",
        "a vCon spool FailureRecord's body (Option<String>)",
    ),
    (
        "src/output/vcon.rs",
        "drop_trace_bodies(&mut attachment.body);",
        "a vCon attachment's body (serde_json::Value)",
    ),
    (
        "src/output/vcon.rs",
        "&& let Some(map) = attachment.body.as_object_mut()",
        "a vCon attachment's body (serde_json::Value)",
    ),
    (
        "src/output/vcon.rs",
        "attachment.body.as_object_mut(),",
        "a vCon attachment's body (serde_json::Value)",
    ),
    (
        "src/output/vcon.rs",
        "move_body_parties(&mut a.body, \"messages\", &party);",
        "a vCon attachment's body (serde_json::Value)",
    ),
    (
        "src/output/vcon.rs",
        "move_body_parties(&mut a.body, \"streams\", &party);",
        "a vCon attachment's body (serde_json::Value)",
    ),
    (
        "src/output/vcon.rs",
        "object.body = Some(body.to_string());",
        "a vCon dialog object's body (Option<String>)",
    ),
    (
        "src/output/vcon.rs",
        ".and_then(|a| a.body.as_object_mut())",
        "a vCon attachment's body (serde_json::Value)",
    ),
    (
        "src/process_isolation/worker_process.rs",
        "sockets.raw = Some(RawKillSocket::from_inherited(raw_v4, raw_v6));",
        "the worker's raw kill socket (Option<RawKillSocket>)",
    ),
    (
        "src/rtp/ogg_opus.rs",
        "self.body.extend_from_slice(&rest[..take]);",
        "an Ogg page body being written (Vec<u8>)",
    ),
    (
        "src/rtp/ogg_opus.rs",
        "self.body.clear();",
        "an Ogg page body being written (Vec<u8>)",
    ),
    (
        "src/sip/parser.rs",
        "self.headers.push(hdr);",
        "the parser's HeaderLines builder, before the SipMessage exists",
    ),
];

/// Places that build or take apart a `SipMessage` by its fields:
/// `(file under src/, the line as written, trimmed)`.
const KNOWN_LITERALS: &[(&str, &str)] = &[("src/sip/parser.rs", "Ok(SipMessage {")];

/// Methods that change a `Vec`, a `String` or a `Bytes` in place.
const MUTATORS: &[&str] = &[
    "push",
    "push_str",
    "insert",
    "insert_str",
    "append",
    "clear",
    "truncate",
    "remove",
    "swap_remove",
    "drain",
    "reverse",
    "pop",
    "advance",
    "take",
    "replace",
    "set_len",
    "split_to",
    "split_off",
    "swap",
    "copy_from_slice",
    "clone_from_slice",
    "clone_from",
    "select_nth_unstable",
];

/// Method-name prefixes that change their receiver in place.
const MUTATOR_PREFIXES: &[&str] = &[
    "sort",
    "dedup",
    "retain",
    "rotate_",
    "extend",
    "fill",
    "resize",
    "make_ascii_",
];

/// Whether `name` is one of `bytes::Buf`'s reading getters (`get_u8`,
/// `get_i32_le`, `get_f64`, `get_uint`, `get_int`), which consume bytes.
fn is_buf_getter(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("get_") else {
        return false;
    };
    let b = rest.as_bytes();
    let sized =
        matches!(b.first(), Some(b'u' | b'i' | b'f')) && b.get(1).is_some_and(u8::is_ascii_digit);
    sized || rest.starts_with("uint") || rest.starts_with("int")
}

/// Whether `b` can continue an identifier.
fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The identifier at the start of `s`, if any.
fn ident_at(s: &str) -> &str {
    let end = s.bytes().position(|b| !ident_byte(b)).unwrap_or(s.len());
    &s[..end]
}

/// `s` past a balanced bracket group that opens at its first byte.
fn past_group(s: &str) -> Option<&str> {
    let (open, close) = match s.as_bytes().first()? {
        b'[' => (b'[', b']'),
        b'(' => (b'(', b')'),
        b'<' => (b'<', b'>'),
        _ => return None,
    };
    let mut depth = 0usize;
    for (i, b) in s.bytes().enumerate() {
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Some(&s[i + 1..]);
            }
        }
    }
    None
}

/// Whether the method `name` changes its receiver.
fn is_mutator(name: &str) -> bool {
    name.ends_with("_mut")
        || is_buf_getter(name)
        || MUTATORS.contains(&name)
        || MUTATOR_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether `after` (the code right after a guarded field name) writes the
/// field: an assignment, a compound assignment or a mutating method call,
/// through any index or sub-field chain (`.headers[0].value = ..`).
fn writes_after(mut after: &str) -> bool {
    loop {
        after = after.trim_start();
        if after.starts_with('[') {
            match past_group(after) {
                Some(rest) => after = rest,
                None => return false,
            }
            continue;
        }
        if let Some(rest) = after.strip_prefix('.') {
            let rest = rest.trim_start();
            let name = ident_at(rest);
            if name.is_empty() {
                return false;
            }
            let tail = rest[name.len()..].trim_start();
            let tail = tail.strip_prefix("::").map_or(tail, |t| {
                past_group(t.trim_start()).unwrap_or(t).trim_start()
            });
            if tail.starts_with('(') {
                return is_mutator(name);
            }
            after = tail;
            continue;
        }
        break;
    }
    let ops = ["<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|="];
    if ops.iter().any(|op| after.starts_with(op)) {
        return true;
    }
    after.starts_with('=') && !after.starts_with("==") && !after.starts_with("=>")
}

/// Whether the receiver expression that ends at `code[..dot]` is borrowed
/// `&mut` (`&mut msg.headers`, `&mut self.parts[i].body`).
fn borrowed_mut_before(code: &str, dot: usize) -> bool {
    let b = code.as_bytes();
    let mut i = dot;
    let mut depth = 0usize;
    while i > 0 {
        let c = b[i - 1];
        if c == b')' || c == b']' {
            depth += 1;
        } else if (c == b'(' || c == b'[') && depth > 0 {
            depth -= 1;
        } else if depth == 0 && !(ident_byte(c) || c == b'.' || c == b':' || c == b'*') {
            break;
        }
        i -= 1;
    }
    let before = code[..i].trim_end();
    before.ends_with("&mut")
        && !before[..before.len() - 4]
            .bytes()
            .last()
            .is_some_and(ident_byte)
}

/// Byte offsets in `code` (comments and literals already blanked) where a
/// field named `field` is written.
fn field_writes(code: &str, field: &str) -> Vec<usize> {
    let needle = format!(".{field}");
    let b = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = code[from..].find(&needle) {
        let dot = from + pos;
        let end = dot + needle.len();
        from = end;
        if b.get(end).copied().is_some_and(ident_byte) {
            continue;
        }
        // A receiver must end right before the dot: `x.`, `).`, `].`.
        let has_receiver = dot > 0 && (ident_byte(b[dot - 1]) || matches!(b[dot - 1], b')' | b']'));
        if !has_receiver {
            continue;
        }
        if writes_after(&code[end..]) || borrowed_mut_before(code, dot) {
            out.push(dot);
        }
    }
    out
}

/// Byte offsets in `code` where a `SipMessage` is built or destructured by
/// its fields (`SipMessage {` that is not `impl .. for`, `struct`, a return
/// type or a generic bound).
fn literal_sites(code: &str) -> Vec<usize> {
    let needle = "SipMessage";
    let b = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = code[from..].find(needle) {
        let at = from + pos;
        let end = at + needle.len();
        from = end;
        if (at > 0 && ident_byte(b[at - 1])) || b.get(end).copied().is_some_and(ident_byte) {
            continue;
        }
        if !code[end..].trim_start().starts_with('{') {
            continue;
        }
        let before = code[..at].trim_end();
        let before = before.strip_suffix("::").map_or(before, |s| {
            s.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        });
        let before = before.trim_end();
        let word = before
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        let typed = before.ends_with("->") || before.ends_with(':') && !before.ends_with("::");
        if matches!(word, "for" | "impl" | "struct") || typed {
            continue;
        }
        out.push(at);
    }
    out
}

/// The 1-based line of byte `at` in `src`, and that line trimmed.
fn line_of(src: &str, at: usize) -> (usize, &str) {
    let start = src[..at].rfind('\n').map_or(0, |n| n + 1);
    let end = src[at..].find('\n').map_or(src.len(), |n| at + n);
    (src[..at].matches('\n').count() + 1, src[start..end].trim())
}

/// The module directory of `file`: where its child modules live.
fn module_dir(file: &Path) -> PathBuf {
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let parent = file.parent().unwrap_or(Path::new(""));
    if matches!(stem, "mod" | "lib" | "main") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

/// The child modules `code` declares as test-only: a `mod name;` under a
/// `#[cfg(test)]` or `#[cfg(all(test, ..))]` attribute (other attributes
/// may sit between).
fn test_only_children(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = false;
    for line in code.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(all(test,") {
            pending = true;
            let rest = t.split_once(")]").map_or("", |(_, r)| r).trim();
            if rest.is_empty() {
                continue;
            }
            if let Some(name) = mod_decl_name(rest) {
                out.push(name);
            }
            pending = false;
            continue;
        }
        if t.starts_with("#[") {
            continue;
        }
        if pending && let Some(name) = mod_decl_name(t) {
            out.push(name);
        }
        pending = false;
    }
    out
}

/// The name in a `[pub[(..)]] mod name;` declaration.
fn mod_decl_name(t: &str) -> Option<String> {
    let mut rest = t;
    if let Some(p) = rest.strip_prefix("pub") {
        rest = p.trim_start();
        if rest.starts_with('(') {
            rest = past_group(rest)?.trim_start();
        }
    }
    let rest = rest.strip_prefix("mod")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start();
    let name = ident_at(rest);
    (!name.is_empty() && rest[name.len()..].trim_start().starts_with(';')).then(|| name.to_owned())
}

/// Every production `.rs` file under `src/` (relative paths): files that
/// are test-only modules, and everything under them, left out.
fn production_files(root: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root.join("src")) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|e| e == "rs") {
            files.push(entry.path().strip_prefix(root)?.to_path_buf());
        }
    }
    files.sort();
    let mut test_only: Vec<PathBuf> = Vec::new();
    for f in &files {
        let code = source_scan::code_only(&std::fs::read_to_string(root.join(f))?);
        let dir = module_dir(f);
        for name in test_only_children(&code) {
            test_only.push(dir.join(format!("{name}.rs")));
            test_only.push(dir.join(&name));
        }
    }
    Ok(files
        .into_iter()
        .filter(|f| {
            !test_only
                .iter()
                .any(|t| f == t || (t.extension().is_none() && f.starts_with(t)))
        })
        .collect())
}

/// The repository root.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `(file, line number, line)` of every write to a guarded field in the
/// production part of every production file.
fn production_writes() -> Result<Vec<(String, usize, String)>, TestError> {
    let root = root();
    let mut out = Vec::new();
    for f in production_files(&root)? {
        let src = std::fs::read_to_string(root.join(&f))?;
        let prod = source_scan::production_source(&src);
        let code = source_scan::code_only(prod);
        for field in GUARDED {
            for at in field_writes(&code, field) {
                let (n, line) = line_of(prod, at);
                out.push((f.display().to_string(), n, line.to_owned()));
            }
        }
    }
    Ok(out)
}

/// No production code writes `headers`, `body` or `raw` of a message
/// after it is built: every write the scan finds is a known write to
/// another type, and every known entry is still there.
#[test]
fn no_production_code_writes_what_the_cache_is_derived_from() -> Result<(), TestError> {
    let found = production_writes()?;
    let unknown: Vec<String> = found
        .iter()
        .filter(|(f, _, line)| !KNOWN_OTHER_WRITES.iter().any(|k| k.0 == f && k.1 == line))
        .map(|(f, n, line)| format!("{f}:{n}: {line}"))
        .collect();
    assert!(
        unknown.is_empty(),
        "these lines write a field the SipMessage parse cache is derived from \
         (headers, body, raw). A write to a stored SipMessage leaves its kept CSeq \
         and media summary stale: build a new message instead. If the line writes \
         another type's field, add it to KNOWN_OTHER_WRITES with what it is:\n{}",
        unknown.join("\n")
    );
    let stale: Vec<String> = KNOWN_OTHER_WRITES
        .iter()
        .filter(|k| !found.iter().any(|(f, _, line)| k.0 == f && k.1 == line))
        .map(|k| format!("{}: {}", k.0, k.1))
        .collect();
    assert!(
        stale.is_empty(),
        "these KNOWN_OTHER_WRITES entries no longer match a line; remove them:\n{}",
        stale.join("\n")
    );
    Ok(())
}

/// Only the parser builds a `SipMessage` from its fields in production
/// code, so no message is put together (or copied with `..`) with a cache
/// that does not match its headers and body.
#[test]
fn only_the_parser_builds_a_sip_message() -> Result<(), TestError> {
    let root = root();
    let mut found = Vec::new();
    for f in production_files(&root)? {
        let src = std::fs::read_to_string(root.join(&f))?;
        let prod = source_scan::production_source(&src);
        for at in literal_sites(&source_scan::code_only(prod)) {
            let (n, line) = line_of(prod, at);
            found.push((f.display().to_string(), n, line.to_owned()));
        }
    }
    let unknown: Vec<String> = found
        .iter()
        .filter(|(f, _, line)| !KNOWN_LITERALS.iter().any(|k| k.0 == f && k.1 == line))
        .map(|(f, n, line)| format!("{f}:{n}: {line}"))
        .collect();
    assert!(
        unknown.is_empty(),
        "a SipMessage is built from its fields outside the parser; its parse cache \
         must start empty (`cache: Default::default()`) and never be copied from \
         a message with other headers or body:\n{}",
        unknown.join("\n")
    );
    let stale: Vec<&str> = KNOWN_LITERALS
        .iter()
        .filter(|k| !found.iter().any(|(f, _, line)| k.0 == f && k.1 == line))
        .map(|k| k.1)
        .collect();
    assert!(stale.is_empty(), "stale KNOWN_LITERALS entries: {stale:?}");
    Ok(())
}

/// The scan reads a real file: `parser.rs`'s builder pushes headers, which
/// the scan must see (it is the builder's own `Vec`, before the message
/// exists, and is listed as such).
#[test]
fn the_scan_sees_the_parsers_own_header_push() -> Result<(), TestError> {
    let found = production_writes()?;
    assert!(
        found
            .iter()
            .any(|(f, _, line)| f == "src/sip/parser.rs" && line.contains("self.headers.push(")),
        "the scan must find parser.rs's header builder; it found {} writes",
        found.len()
    );
    Ok(())
}

/// The writes `field_writes` finds in `code`, by line text.
fn writes_in(code: &str, field: &str) -> Vec<String> {
    let blanked = source_scan::code_only(code);
    field_writes(&blanked, field)
        .into_iter()
        .map(|at| line_of(code, at).1.to_owned())
        .collect()
}

/// A push onto the headers is a write.
#[test]
fn the_scan_flags_a_header_push() {
    assert_eq!(
        writes_in("msg.headers.push(h);", "headers").len(),
        1,
        "push"
    );
}

/// An assignment to the body is a write.
#[test]
fn the_scan_flags_a_body_assignment() {
    assert_eq!(
        writes_in("m.body = Bytes::new();", "body").len(),
        1,
        "assignment"
    );
}

/// A `&mut` borrow of raw is a write.
#[test]
fn the_scan_flags_a_mutable_borrow() {
    assert_eq!(writes_in("take(&mut m.raw);", "raw").len(), 1, "&mut");
    assert_eq!(
        writes_in("for h in &mut self.msg.headers {}", "headers").len(),
        1,
        "&mut through a chain"
    );
}

/// A write through an index and a sub-field is a write.
#[test]
fn the_scan_flags_a_write_through_an_index() {
    assert_eq!(
        writes_in("m.headers[0].value = v;", "headers").len(),
        1,
        "index then field"
    );
    assert_eq!(
        writes_in("m.headers[i].value.push_str(\"x\");", "headers").len(),
        1,
        "index, field, mutator"
    );
}

/// Mutable iteration, `_mut` accessors, retain and sort are writes.
#[test]
fn the_scan_flags_mutating_methods() {
    for code in [
        "m.headers.iter_mut().for_each(f);",
        "m.headers.last_mut();",
        "m.headers.retain(|h| keep(h));",
        "m.headers.sort_by_key(|h| h.name.clone());",
        "m.body.truncate(3);",
        "m.raw.advance(1);",
        "m.headers.extend(more);",
    ] {
        let field = if code.contains("body") {
            "body"
        } else if code.contains("raw") {
            "raw"
        } else {
            "headers"
        };
        assert_eq!(writes_in(code, field).len(), 1, "{code}");
    }
}

/// A compound assignment is a write.
#[test]
fn the_scan_flags_a_compound_assignment() {
    assert_eq!(writes_in("p.body += 1;", "body").len(), 1, "+=");
}

/// A write on `self` is a write (the scan has no types).
#[test]
fn the_scan_flags_a_write_on_self() {
    assert_eq!(
        writes_in("self.headers.push(hdr);", "headers").len(),
        1,
        "self"
    );
}

/// Reads are not writes.
#[test]
fn the_scan_passes_reads() {
    for code in [
        "let n = m.headers.len();",
        "for h in m.headers.iter() {}",
        "for h in &m.headers {}",
        "if m.raw == other.raw {}",
        "let b = m.body.clone();",
        "let v = &m.headers[0].value;",
        "match x { _ if m.body.is_empty() => 1, _ => 2 }",
        "let s = m.headers.first().map(|h| h.value.as_str());",
    ] {
        for field in GUARDED {
            assert!(writes_in(code, field).is_empty(), "{code} reads {field}");
        }
    }
}

/// A longer field name that starts with a guarded one is another field.
#[test]
fn the_scan_passes_a_longer_field_name() {
    assert!(
        writes_in("self.body_cap = 3; m.headers_seen += 1;", "body").is_empty(),
        "body_cap"
    );
    assert!(
        writes_in("m.headers_seen += 1;", "headers").is_empty(),
        "headers_seen"
    );
}

/// A comment or a string that spells a write is no write.
#[test]
fn the_scan_passes_comments_and_strings() {
    assert!(
        writes_in("// m.headers.push(h);\nlet s = \"m.body = x\";", "headers").is_empty(),
        "comment"
    );
    assert!(
        writes_in("let s = \"m.body = x\";", "body").is_empty(),
        "string"
    );
}

/// A local binding named like a field is no field.
#[test]
fn the_scan_passes_a_plain_binding() {
    assert!(
        writes_in("headers.push(h); body = b;", "headers").is_empty(),
        "local"
    );
    assert!(
        writes_in("let raw = &mut buf;", "raw").is_empty(),
        "local raw"
    );
}

/// The production part of a file ends at its test module.
#[test]
fn the_scan_stops_at_the_test_module() {
    let src = "fn f(m: &M) {}\n#[cfg(test)]\nmod tests {\n    fn g(m: &mut M) { m.headers.push(h); }\n}\n";
    let prod = source_scan::production_source(src);
    assert!(writes_in(prod, "headers").is_empty(), "test module skipped");
    assert_eq!(writes_in(src, "headers").len(), 1, "the whole file has one");
}

/// A `#[cfg(test)]` module declaration makes its file test-only; a plain
/// or `not(test)` one does not.
#[test]
fn test_only_child_modules_are_found() {
    let code = "#[cfg(test)]\nmod cache_tests;\nmod plain;\n#[cfg(not(test))]\nmod real;\n\
                #[cfg(test)] pub mod test_utils;\n#[cfg(all(test, feature = \"x\"))]\n\
                #[allow(dead_code)]\npub(crate) mod engines;\n";
    assert_eq!(
        test_only_children(code),
        ["cache_tests", "test_utils", "engines"],
        "the three test-only modules"
    );
}

/// A child module's file sits in its parent's module directory.
#[test]
fn a_module_directory_follows_the_file_name() {
    assert_eq!(module_dir(Path::new("src/lib.rs")), Path::new("src"), "lib");
    assert_eq!(
        module_dir(Path::new("src/sip/message.rs")),
        Path::new("src/sip/message"),
        "a file module"
    );
    assert_eq!(
        module_dir(Path::new("src/sip/mod.rs")),
        Path::new("src/sip"),
        "mod.rs"
    );
}

/// This file is test-only, so the scan leaves it out; parser.rs is in.
#[test]
fn the_scan_leaves_out_test_only_files() -> Result<(), TestError> {
    let files = production_files(&root())?;
    assert!(
        !files.iter().any(|f| f.ends_with("message/cache_tests.rs")),
        "this test file is test-only"
    );
    assert!(
        !files.iter().any(|f| f.ends_with("src/test_utils.rs")),
        "test_utils is test-only"
    );
    assert!(
        files.iter().any(|f| f.ends_with("src/sip/parser.rs")),
        "parser.rs is production"
    );
    Ok(())
}

/// A struct literal or pattern is a literal site; an impl, the struct
/// itself and a return type are not.
#[test]
fn the_literal_scan_tells_a_literal_from_a_type() {
    let code = "impl Clone for SipMessage {}\nimpl SipMessage {}\npub struct SipMessage {}\n\
                fn f() -> SipMessage {}\nfn g(x: SipMessage) {}\n\
                let m = SipMessage { raw, ..base };\nlet crate::sip::SipMessage { headers, .. } = m;\n";
    let found: Vec<usize> = literal_sites(code)
        .into_iter()
        .map(|at| line_of(code, at).0)
        .collect();
    assert_eq!(found, [6, 7], "the literal and the pattern");
}
