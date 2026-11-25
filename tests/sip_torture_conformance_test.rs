// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Behavior that RFC 4475 (SIP torture test messages) and RFC 5118 (SIP torture
//! tests for IPv6) require of a SIP parser, checked through what an operator
//! reads: the parse, the lint findings and the `--json` malformation list.
//!
//! Each test builds a minimal message that keeps the property the RFC section
//! tests and nothing else from the RFC's message. Every value is reserved:
//! example.com, example.net and example.org names and RFC 5737 / RFC 3849
//! addresses. Each test names the RFC section it comes from.

use std::net::{IpAddr, Ipv4Addr};

use sipnab::net::TransportProto;
use sipnab::sip::lint::{LintConfig, Linter};
use sipnab::sip::message::SipMessage;
use sipnab::sip::parser::{parse_sip, starts_sip_message};

type TestError = Box<dyn std::error::Error>;

const CONTROL_BYTE: &str = "SIP-3261-25.1-HEADER-CONTROL-BYTE";
const LINE_SPACING: &str = "SIP-3261-7.1-REQUEST-LINE-SPACING";

/// The headers every request below starts from: all six RFC 3261 section 8.1.1
/// fields, a cookie branch and the recommended Max-Forwards, so a finding can
/// come only from the line a test changes.
const BASE: &[(&str, &str)] = &[
    ("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-torture-1"),
    ("Max-Forwards", "70"),
    ("To", "<sip:user@example.com>"),
    ("From", "<sip:caller@example.net>;tag=t1"),
    ("Call-ID", "torture-1@example.com"),
    ("CSeq", "1 OPTIONS"),
    ("Content-Length", "0"),
];

/// `start` as the first line, then [`BASE`] with each header named in
/// `replace` taking the given raw value bytes instead, then the blank line.
fn build(start: &[u8], replace: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = start.to_vec();
    out.extend_from_slice(b"\r\n");
    for (name, value) in BASE {
        let value = replace
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map_or(value.as_bytes(), |(_, v)| *v);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// An OPTIONS request built by [`build`].
fn options(replace: &[(&str, &[u8])]) -> Vec<u8> {
    build(b"OPTIONS sip:user@example.com SIP/2.0", replace)
}

fn parse(data: &[u8]) -> Result<SipMessage, TestError> {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    Ok(parse_sip(
        data,
        chrono::DateTime::from_timestamp(1_718_452_800, 0).unwrap_or_default(),
        ip,
        ip,
        5060,
        5060,
        TransportProto::Udp,
    )?)
}

/// Every rule identifier the full linter raises for `data`, in order.
fn findings(data: &[u8]) -> Result<Vec<&'static str>, TestError> {
    let msg = parse(data)?;
    Ok(Linter::new(LintConfig::new())
        .lint_message(&msg, 0)
        .iter()
        .map(|f| f.rule_id)
        .collect())
}

// RFC 4475 section 3.1.1.2 (intmeth): a quoted-pair may escape any octet but
// CR and LF (RFC 3261 section 25.1, `quoted-pair = "\" (%x00-09 / %x0B-0C /
// %x0E-7F)`), so an escaped BEL, NUL or DEL inside a quoted display name is
// well formed. A raw control byte anywhere else is not.

#[test]
fn escaped_control_bytes_in_a_quoted_display_name_are_not_flagged() -> Result<(), TestError> {
    let data = options(&[(
        "To",
        b"\"BEL:\\\x07 NUL:\\\x00 DEL:\\\x7f\" <sip:user@example.com>",
    )]);
    let found = findings(&data)?;
    assert!(
        !found.contains(&CONTROL_BYTE),
        "RFC 4475 3.1.1.2 calls this display name valid, got {found:?}"
    );
    let msg = parse(&data)?;
    assert!(
        msg.malformations().is_empty(),
        "no malformation for an escaped control byte, got {:?}",
        msg.malformations()
    );
    Ok(())
}

#[test]
fn an_escaped_vertical_tab_in_a_quoted_string_is_not_flagged() -> Result<(), TestError> {
    let data = options(&[("From", b"\"a\\\x0bb\" <sip:caller@example.net>;tag=t1")]);
    let found = findings(&data)?;
    assert!(
        !found.contains(&CONTROL_BYTE),
        "%x0B is inside the quoted-pair range, got {found:?}"
    );
    Ok(())
}

#[test]
fn a_raw_control_byte_in_a_quoted_display_name_is_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"BEL:\x07\" <sip:user@example.com>")]);
    let found = findings(&data)?;
    assert!(
        found.contains(&CONTROL_BYTE),
        "an unescaped BEL is outside qdtext, got {found:?}"
    );
    let msg = parse(&data)?;
    assert_eq!(
        msg.malformations(),
        vec!["control character in header: To".to_string()],
        "the --json malformation still names the header"
    );
    Ok(())
}

#[test]
fn a_control_byte_outside_any_quoted_string_is_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"<sip:user@example.com>;x=\x01")]);
    assert!(
        findings(&data)?.contains(&CONTROL_BYTE),
        "a control byte in a parameter value is never legal"
    );
    Ok(())
}

#[test]
fn a_backslash_outside_a_quoted_string_does_not_excuse_a_control_byte() -> Result<(), TestError> {
    let data = options(&[("To", b"<sip:user@example.com>;x=\\\x00")]);
    assert!(
        findings(&data)?.contains(&CONTROL_BYTE),
        "quoted-pair exists only inside a quoted-string"
    );
    Ok(())
}

#[test]
fn an_escaped_backslash_leaves_the_next_control_byte_raw() -> Result<(), TestError> {
    // `\\` is one quoted-pair (a backslash); the BEL after it is raw.
    let data = options(&[("To", b"\"a\\\\\x07\" <sip:user@example.com>")]);
    assert!(
        findings(&data)?.contains(&CONTROL_BYTE),
        "the BEL after an escaped backslash is not itself escaped"
    );
    Ok(())
}

#[test]
fn an_escaped_control_byte_in_a_quote_that_never_closes_is_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"a\\\x00 <sip:user@example.com>")]);
    assert!(
        findings(&data)?.contains(&CONTROL_BYTE),
        "without a closing quote there is no quoted-string to hold a quoted-pair"
    );
    Ok(())
}

#[test]
fn a_control_byte_after_a_closed_quoted_string_is_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"a\\\x00\" <sip:user@example.com>;x=\x02")]);
    assert!(
        findings(&data)?.contains(&CONTROL_BYTE),
        "the escape inside the quotes does not cover a byte after them"
    );
    Ok(())
}

// RFC 4475 sections 3.1.2.9 (lwsstart) and 3.1.2.10 (trws): extra SP between
// the Request-Line elements, or after the version, is outside RFC 3261
// section 7.1. Rejecting is acceptable and so is ignoring the SP; sipnab
// ignores it, as it already did inside the line, and reports it.

#[test]
fn a_request_line_with_trailing_spaces_is_parsed() -> Result<(), TestError> {
    let msg = parse(&build(b"OPTIONS sip:user@example.com SIP/2.0  ", &[]))?;
    assert!(
        msg.is_request,
        "RFC 4475 3.1.2.10 allows ignoring trailing SP"
    );
    assert_eq!(
        msg.request_uri.as_deref(),
        Some("sip:user@example.com"),
        "the Request-URI stops before the version"
    );
    assert_eq!(
        msg.method.map(|m| m.to_string()).as_deref(),
        Some("OPTIONS"),
        "the method is read as on a clean line"
    );
    Ok(())
}

#[test]
fn a_request_line_with_trailing_spaces_is_sniffed_as_sip() {
    assert!(
        starts_sip_message(&build(b"OPTIONS sip:user@example.com SIP/2.0  ", &[])),
        "the capture sniff must keep what the parser accepts, or the message never reaches it"
    );
}

#[test]
fn a_request_line_with_a_trailing_tab_is_parsed() -> Result<(), TestError> {
    let msg = parse(&build(b"OPTIONS sip:user@example.com SIP/2.0\t", &[]))?;
    assert_eq!(
        msg.request_uri.as_deref(),
        Some("sip:user@example.com"),
        "a trailing HTAB is whitespace as SP is"
    );
    Ok(())
}

#[test]
fn a_single_spaced_request_line_is_not_flagged() -> Result<(), TestError> {
    let found = findings(&options(&[]))?;
    assert!(
        !found.contains(&LINE_SPACING),
        "one SP between each element is the grammar, got {found:?}"
    );
    Ok(())
}

#[test]
fn trailing_spaces_on_a_request_line_are_flagged() -> Result<(), TestError> {
    let found = findings(&build(b"OPTIONS sip:user@example.com SIP/2.0  ", &[]))?;
    assert!(
        found.contains(&LINE_SPACING),
        "RFC 4475 3.1.2.10 trailing SP must be reported, got {found:?}"
    );
    Ok(())
}

#[test]
fn a_single_trailing_space_on_a_request_line_is_flagged() -> Result<(), TestError> {
    let found = findings(&build(b"OPTIONS sip:user@example.com SIP/2.0 ", &[]))?;
    assert!(
        found.contains(&LINE_SPACING),
        "one SP after the version is still outside section 7.1, got {found:?}"
    );
    Ok(())
}

#[test]
fn a_leading_space_before_the_method_is_flagged() -> Result<(), TestError> {
    let data = build(b" OPTIONS sip:user@example.com SIP/2.0", &[]);
    assert!(
        parse(&data)?.is_request,
        "the parser already skips leading whitespace"
    );
    assert!(
        findings(&data)?.contains(&LINE_SPACING),
        "whitespace before the method is outside section 7.1"
    );
    Ok(())
}

#[test]
fn doubled_spaces_between_request_line_elements_are_flagged() -> Result<(), TestError> {
    let data = build(b"OPTIONS  sip:user@example.com  SIP/2.0", &[]);
    let msg = parse(&data)?;
    assert_eq!(
        msg.request_uri.as_deref(),
        Some("sip:user@example.com"),
        "RFC 4475 3.1.2.9 is still parsed"
    );
    assert!(
        findings(&data)?.contains(&LINE_SPACING),
        "RFC 4475 3.1.2.9 doubled SP must be reported"
    );
    Ok(())
}

#[test]
fn a_trailing_tab_on_a_request_line_is_flagged() -> Result<(), TestError> {
    let found = findings(&build(b"OPTIONS sip:user@example.com SIP/2.0\t", &[]))?;
    assert!(
        found.contains(&LINE_SPACING),
        "HTAB is not the SP separator, got {found:?}"
    );
    Ok(())
}

#[test]
fn spaces_in_a_reason_phrase_are_not_flagged() -> Result<(), TestError> {
    let data = build(b"SIP/2.0 200 OK  then  more ", &[]);
    let found = findings(&data)?;
    assert!(
        !found.contains(&LINE_SPACING),
        "a Status-Line's Reason-Phrase may hold any spaces, got {found:?}"
    );
    Ok(())
}

#[test]
fn text_after_the_version_is_still_not_sip() {
    let data = build(b"OPTIONS sip:user@example.com SIP/2.0 x", &[]);
    assert!(
        parse(&data).is_err(),
        "only whitespace after the version is ignored"
    );
    assert!(
        !starts_sip_message(&data),
        "the sniff refuses what the parser refuses"
    );
}

#[test]
fn a_request_line_with_no_uri_and_trailing_space_is_refused() {
    let data = build(b"OPTIONS SIP/2.0 ", &[]);
    assert!(
        parse(&data).is_err(),
        "trimming the trailing SP must not invent a Request-URI"
    );
    assert!(
        !starts_sip_message(&data),
        "the sniff still needs a URI between method and version"
    );
}
