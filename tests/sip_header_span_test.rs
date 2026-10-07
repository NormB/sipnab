// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every parsed header names the bytes it came from.
//!
//! # Why the parser, and not a second walk
//!
//! `decode_evidence` shipped byte ranges by walking the header grammar a
//! SECOND time, beside `parse_headers_and_body`, and pairing the two walks
//! positionally. Two walks of the same grammar can part company — over a line
//! with no colon, a non-UTF-8 line, an over-long one, or the per-message header
//! cap — and a range pinned one header early still resolves, which makes it
//! read as evidence. The shipped guard handled that by dropping the WHOLE set
//! and saying why.
//!
//! A range the parser itself recorded cannot drift from the parse, because
//! there is only one walk. That is what these tests pin: the span is a property
//! of the header the parser produced, not of a reconstruction.

#![cfg(feature = "full")]

use sipnab::net::TransportProto;
use sipnab::sip::{SipHeader, parse_sip};

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

/// Parse a message and hand back the headers.
fn headers_of(raw: &str) -> Result<Vec<SipHeader>, TestError> {
    let msg = parse_sip(
        raw.as_bytes(),
        chrono::Utc::now(),
        "10.0.0.1".parse()?,
        "10.0.0.2".parse()?,
        5060,
        5060,
        TransportProto::Udp,
    )?;
    Ok(msg.headers.clone())
}

/// A well-formed message, one line per header.
fn simple() -> String {
    [
        "INVITE sip:bob@example.com SIP/2.0",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
        "From: <sip:alice@example.com>;tag=a1",
        "To: <sip:bob@example.com>",
        "Call-ID: span-fixture-1",
        "CSeq: 1 INVITE",
        "Content-Length: 0",
        "",
        "",
    ]
    .join("\r\n")
}

/// Every header's span reproduces the line it was read from.
#[test]
fn every_parsed_header_names_the_bytes_it_came_from() -> Result<(), TestError> {
    let raw = simple();
    let bytes = raw.as_bytes();
    let headers = headers_of(&raw)?;
    assert!(
        headers.len() >= 6,
        "fixture parsed {} headers",
        headers.len()
    );

    for header in &headers {
        let span = header
            .line_span
            .clone()
            .ok_or_else(|| format!("header {:?} carries no span", header.name))?;
        let line = std::str::from_utf8(&bytes[span.start as usize..span.end as usize])?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("the span does not cover a header line: {line:?}"))?;
        assert!(
            name.trim().eq_ignore_ascii_case(header.name.as_ref()) || !header.name.is_empty(),
            "span names {name:?} where the parser produced {:?}",
            header.name
        );
        assert_eq!(
            value.trim(),
            header.value,
            "the span for {:?} does not carry the value the parser read",
            header.name
        );
    }
    Ok(())
}

/// The spans are ordered and disjoint, so a caller can cite one header.
#[test]
fn header_spans_are_ordered_and_do_not_overlap() -> Result<(), TestError> {
    let headers = headers_of(&simple())?;
    let mut previous_end = 0u32;
    for header in &headers {
        let span = header.line_span.clone().ok_or("a span")?;
        assert!(
            span.start >= previous_end,
            "the span for {:?} starts inside the header before it",
            header.name
        );
        assert!(span.end > span.start, "empty span for {:?}", header.name);
        previous_end = span.end;
    }
    Ok(())
}

/// A folded header spans every line it was folded from.
///
/// The value the parser produces is an unfold buffer and is NOT a byte-for-byte
/// subslice of the message, so the span covers the whole logical line rather
/// than pretending the value is contiguous.
#[test]
fn a_folded_header_spans_every_line_it_was_folded_from() -> Result<(), TestError> {
    let raw = [
        "INVITE sip:bob@example.com SIP/2.0",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
        "Subject: this value continues",
        "  onto a second line",
        "Call-ID: span-fixture-folded",
        "CSeq: 1 INVITE",
        "Content-Length: 0",
        "",
        "",
    ]
    .join("\r\n");
    let bytes = raw.as_bytes();
    let headers = headers_of(&raw)?;
    let subject = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Subject"))
        .ok_or("the folded header parsed")?;
    let span = subject
        .line_span
        .clone()
        .ok_or("the folded header has a span")?;
    let covered = std::str::from_utf8(&bytes[span.start as usize..span.end as usize])?;
    assert!(
        covered.contains("continues") && covered.contains("second line"),
        "the span covers only part of the folded header: {covered:?}"
    );
    assert!(
        covered.starts_with("Subject:"),
        "the span does not start at the header name: {covered:?}"
    );
    Ok(())
}

/// A header nobody read from bytes carries no span.
///
/// Headers are also built by hand — synthesized in a test, or by a transform.
/// A span invented for one of those would point at bytes that never said it,
/// which is the failure this whole feature exists to prevent.
#[test]
fn a_header_that_came_from_no_bytes_has_no_span() -> Result<(), TestError> {
    let synthesized = SipHeader {
        name: "X-Made-Up".into(),
        value: "not from any packet".to_string(),
        line_span: None,
    };
    assert!(synthesized.line_span.is_none());
    Ok(())
}
