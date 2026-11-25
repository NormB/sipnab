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
use sipnab::sip::parser::parse_sip;

type TestError = Box<dyn std::error::Error>;

const CONTROL_BYTE: &str = "SIP-3261-25.1-HEADER-CONTROL-BYTE";

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
