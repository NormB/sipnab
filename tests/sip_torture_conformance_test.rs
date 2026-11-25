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
const IPV6_UNBRACKETED: &str = "SIP-3261-25.1-IPV6-REFERENCE-UNBRACKETED";
const EMPTY_PARAM: &str = "SIP-3261-25.1-EMPTY-PARAMETER";
const CL_INVALID: &str = "SIP-3261-20.14-CONTENT-LENGTH-INVALID";
const QUOTE_OPEN: &str = "SIP-3261-25.1-QUOTED-STRING-UNTERMINATED";
const RURI_BRACKETED: &str = "SIP-3261-25.1-REQUEST-URI-BRACKETED";
const RURI_LWS: &str = "SIP-3261-25.1-REQUEST-URI-WHITESPACE";
const RURI_HEADERS: &str = "SIP-3261-19.1.1-REQUEST-URI-HEADERS";
const ADDR_SPEC_LWS: &str = "SIP-3261-25.1-ADDR-SPEC-WHITESPACE";
const DISPLAY_UNQUOTED: &str = "SIP-3261-25.1-DISPLAY-NAME-UNQUOTED";
const DATE_NOT_GMT: &str = "SIP-3261-20.17-DATE-NOT-GMT";
const BRANCH_NO_ID: &str = "SIP-3261-8.1.1.7-BRANCH-NO-IDENTIFIER";

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
/// `replace` taking the given raw value bytes instead, then each `replace`
/// header [`BASE`] does not hold, then the blank line.
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
    for (name, value) in replace {
        if !BASE.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Whether the full linter raises `rule` for `data`.
fn has(data: &[u8], rule: &str) -> Result<bool, TestError> {
    Ok(findings(data)?.contains(&rule))
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

// RFC 5118 section 4.2 (ipv6-bad): RFC 3261 section 25.1 writes an IPv6 host
// as "[" IPv6address "]". Sections 4.1, 4.4 and 4.5 are the valid forms.

#[test]
fn a_bracketed_ipv6_request_uri_is_not_flagged() -> Result<(), TestError> {
    let data = build(
        b"REGISTER sip:[2001:db8::10] SIP/2.0",
        &[("CSeq", b"1 REGISTER")],
    );
    assert!(!has(&data, IPV6_UNBRACKETED)?, "RFC 5118 4.1 is valid");
    Ok(())
}

#[test]
fn a_bracketed_ipv6_host_with_a_port_is_not_flagged() -> Result<(), TestError> {
    let data = build(
        b"REGISTER sip:[2001:db8::10]:5070 SIP/2.0",
        &[
            ("CSeq", b"1 REGISTER"),
            ("Via", b"SIP/2.0/UDP [2001:db8::9:1]:6050;branch=z9hG4bK-t6"),
            ("To", b"<sip:user@[2001:db8::1]>"),
        ],
    );
    assert!(
        !has(&data, IPV6_UNBRACKETED)?,
        "RFC 5118 4.4: the port sits outside the ]"
    );
    Ok(())
}

#[test]
fn an_ipv6_via_received_without_brackets_is_not_flagged() -> Result<(), TestError> {
    // RFC 5118 4.5: via-received is IPv6address, without the brackets.
    let data = options(&[(
        "Via",
        b"SIP/2.0/UDP [2001:db8::9:1];received=2001:db8::9:255;branch=z9hG4bK-t7",
    )]);
    assert!(
        !has(&data, IPV6_UNBRACKETED)?,
        "received= takes the bare form"
    );
    Ok(())
}

#[test]
fn an_unbracketed_ipv6_request_uri_is_flagged() -> Result<(), TestError> {
    let data = build(
        b"REGISTER sip:2001:db8::10 SIP/2.0",
        &[("CSeq", b"1 REGISTER")],
    );
    assert!(has(&data, IPV6_UNBRACKETED)?, "RFC 5118 4.2 expects 400");
    Ok(())
}

#[test]
fn an_unbracketed_ipv6_host_in_a_contact_is_flagged() -> Result<(), TestError> {
    let data = options(&[("Contact", b"<sip:caller@2001:db8::1>")]);
    assert!(
        has(&data, IPV6_UNBRACKETED)?,
        "the rule reads header URIs too"
    );
    Ok(())
}

#[test]
fn an_unbracketed_ipv6_via_sent_by_is_flagged() -> Result<(), TestError> {
    let data = options(&[("Via", b"SIP/2.0/UDP 2001:db8::9:1;branch=z9hG4bK-t8")]);
    assert!(has(&data, IPV6_UNBRACKETED)?, "sent-by is host [ : port ]");
    Ok(())
}

// RFC 4475 section 3.1.2.1 (badinv01): empty elements between `;` and `,`.

#[test]
fn parameters_with_values_are_not_flagged_as_empty() -> Result<(), TestError> {
    let data = options(&[("Contact", b"<sip:caller@example.net>;expires=60;q=0.5")]);
    assert!(
        !has(&data, EMPTY_PARAM)?,
        "every separator has a parameter after it"
    );
    Ok(())
}

#[test]
fn empty_via_parameters_and_elements_are_flagged() -> Result<(), TestError> {
    let data = options(&[("Via", b"SIP/2.0/UDP 192.0.2.15;;,;,,")]);
    assert!(has(&data, EMPTY_PARAM)?, "RFC 4475 3.1.2.1 Via");
    Ok(())
}

#[test]
fn trailing_semicolons_on_a_contact_are_flagged() -> Result<(), TestError> {
    let data = options(&[("Contact", b"\"Usr\" <sip:usr@example.org>;;;;")]);
    assert!(has(&data, EMPTY_PARAM)?, "RFC 4475 3.1.2.1 Contact");
    Ok(())
}

#[test]
fn separators_inside_quotes_or_brackets_are_not_flagged() -> Result<(), TestError> {
    let data = options(&[(
        "Contact",
        b"\"a;;b,,c\" <sip:caller@example.net;lr;transport=udp>;expires=60",
    )]);
    assert!(
        !has(&data, EMPTY_PARAM)?,
        "the display name and the URI parameters are not header parameters"
    );
    Ok(())
}

// RFC 4475 section 3.1.2.3 (ncl): Content-Length = 1*DIGIT.

#[test]
fn a_decimal_content_length_is_not_flagged_invalid() -> Result<(), TestError> {
    assert!(!has(&options(&[]), CL_INVALID)?, "0 is a valid length");
    Ok(())
}

#[test]
fn a_negative_content_length_is_flagged() -> Result<(), TestError> {
    let data = options(&[("Content-Length", b"-999")]);
    assert!(has(&data, CL_INVALID)?, "RFC 4475 3.1.2.3 expects an error");
    Ok(())
}

#[test]
fn a_non_numeric_content_length_is_flagged() -> Result<(), TestError> {
    let data = options(&[("Content-Length", b"many")]);
    assert!(
        has(&data, CL_INVALID)?,
        "RFC 4475 3.1.2.3 names this case too"
    );
    Ok(())
}

#[test]
fn a_content_length_with_surrounding_whitespace_is_not_flagged() -> Result<(), TestError> {
    let data = options(&[("Content-Length", b"  0  ")]);
    assert!(
        !has(&data, CL_INVALID)?,
        "LWS around the HCOLON value is allowed"
    );
    Ok(())
}

// RFC 4475 section 3.1.2.6 (quotbal): a display name that never closes.

#[test]
fn a_closed_quoted_display_name_is_not_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"Mr. J. User\" <sip:user@example.com>")]);
    assert!(!has(&data, QUOTE_OPEN)?, "the quote closes");
    Ok(())
}

#[test]
fn an_unterminated_display_name_is_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"Mr. J. User <sip:user@example.com>")]);
    assert!(has(&data, QUOTE_OPEN)?, "RFC 4475 3.1.2.6");
    Ok(())
}

#[test]
fn an_escaped_quote_does_not_close_the_string() -> Result<(), TestError> {
    let data = options(&[("To", b"\"Mr. \\\" <sip:user@example.com>")]);
    assert!(
        has(&data, QUOTE_OPEN)?,
        "\\\" is a quoted-pair, not the closing quote"
    );
    let closed = options(&[("To", b"\"Mr. \\\"J\\\"\" <sip:user@example.com>")]);
    assert!(
        !has(&closed, QUOTE_OPEN)?,
        "escaped quotes inside a closed string are fine"
    );
    Ok(())
}

// RFC 4475 sections 3.1.2.7, 3.1.2.8 and 3.1.2.11: the Request-URI itself.

#[test]
fn a_plain_request_uri_raises_none_of_the_request_uri_rules() -> Result<(), TestError> {
    let found = findings(&options(&[]))?;
    for rule in [RURI_BRACKETED, RURI_LWS, RURI_HEADERS] {
        assert!(
            !found.contains(&rule),
            "{rule} on a clean Request-URI: {found:?}"
        );
    }
    Ok(())
}

#[test]
fn a_bracketed_request_uri_is_flagged() -> Result<(), TestError> {
    let data = build(b"OPTIONS <sip:user@example.com> SIP/2.0", &[]);
    assert!(has(&data, RURI_BRACKETED)?, "RFC 4475 3.1.2.7");
    Ok(())
}

#[test]
fn whitespace_inside_the_request_uri_is_flagged() -> Result<(), TestError> {
    let data = build(b"OPTIONS sip:user@example.com; lr SIP/2.0", &[]);
    assert!(has(&data, RURI_LWS)?, "RFC 4475 3.1.2.8");
    assert!(
        !has(&data, LINE_SPACING)?,
        "single SPs: the defect is in the URI, not the line spacing"
    );
    Ok(())
}

#[test]
fn headers_in_a_sip_request_uri_are_flagged() -> Result<(), TestError> {
    let data = build(
        b"OPTIONS sip:user@example.com?Route=%3Csip:example.com%3E SIP/2.0",
        &[],
    );
    assert!(has(&data, RURI_HEADERS)?, "RFC 4475 3.1.2.11");
    Ok(())
}

#[test]
fn a_question_mark_in_the_user_part_is_not_a_headers_component() -> Result<(), TestError> {
    // RFC 4475 3.1.1.2: `?` is an unreserved user character.
    let data = build(b"OPTIONS sip:crazy?,/;;*@example.com SIP/2.0", &[]);
    assert!(!has(&data, RURI_HEADERS)?, "the ? sits before the @");
    Ok(())
}

#[test]
fn a_query_in_a_non_sip_request_uri_is_not_flagged() -> Result<(), TestError> {
    let data = build(b"OPTIONS http://example.com/?a=b SIP/2.0", &[]);
    assert!(
        !has(&data, RURI_HEADERS)?,
        "Table 1 governs sip and sips URIs only"
    );
    Ok(())
}

// RFC 4475 section 3.1.2.14 (badaspec): whitespace inside < >.

#[test]
fn a_tight_name_addr_is_not_flagged() -> Result<(), TestError> {
    assert!(
        !has(&options(&[]), ADDR_SPEC_LWS)?,
        "<sip:user@example.com> is tight"
    );
    Ok(())
}

#[test]
fn spaces_inside_angle_brackets_are_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"User, Test\" < sip:user@example.org >")]);
    assert!(has(&data, ADDR_SPEC_LWS)?, "RFC 4475 3.1.2.14");
    Ok(())
}

#[test]
fn spaces_around_the_brackets_are_not_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"  \"User\"   <sip:user@example.org>  ;tag=x")]);
    assert!(
        !has(&data, ADDR_SPEC_LWS)?,
        "LWS outside the brackets is allowed"
    );
    Ok(())
}

// RFC 4475 section 3.1.2.15 (baddn): non-token characters, unquoted.

#[test]
fn an_unquoted_token_display_name_is_not_flagged() -> Result<(), TestError> {
    // RFC 4475 3.1.1.6 (lwsdisp): no LWS before < is valid too.
    let data = options(&[("From", b"caller<sip:caller@example.net>;tag=t1")]);
    assert!(!has(&data, DISPLAY_UNQUOTED)?, "tokens may go unquoted");
    let words = options(&[("From", b"Test User <sip:caller@example.net>;tag=t1")]);
    assert!(
        !has(&words, DISPLAY_UNQUOTED)?,
        "tokens separated by LWS may too"
    );
    Ok(())
}

#[test]
fn an_unquoted_display_name_with_a_comma_is_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"User, Test <sip:user@example.org>")]);
    assert!(has(&data, DISPLAY_UNQUOTED)?, "RFC 4475 3.1.2.15");
    Ok(())
}

#[test]
fn a_quoted_display_name_with_a_comma_is_not_flagged() -> Result<(), TestError> {
    let data = options(&[("To", b"\"User, Test\" <sip:user@example.org>")]);
    assert!(!has(&data, DISPLAY_UNQUOTED)?, "quoting is the fix");
    Ok(())
}

// RFC 4475 section 3.1.2.12 (baddate): SIP-date is GMT only.

#[test]
fn a_gmt_date_is_not_flagged() -> Result<(), TestError> {
    let data = options(&[("Date", b"Sat, 13 Nov 2010 23:29:00 GMT")]);
    assert!(!has(&data, DATE_NOT_GMT)?, "GMT is the one allowed zone");
    Ok(())
}

#[test]
fn a_date_in_another_zone_is_flagged() -> Result<(), TestError> {
    let data = options(&[("Date", b"Fri, 01 Jan 2010 16:00:00 EST")]);
    assert!(has(&data, DATE_NOT_GMT)?, "RFC 4475 3.1.2.12");
    Ok(())
}

#[test]
fn a_utc_date_is_flagged() -> Result<(), TestError> {
    // RFC 4475 3.1.2.12: "UT", "UTC" and "UCT" are also invalid.
    let data = options(&[("Date", b"Fri, 01 Jan 2010 16:00:00 UTC")]);
    assert!(has(&data, DATE_NOT_GMT)?, "UTC is not GMT in the grammar");
    Ok(())
}

// RFC 4475 section 3.2.1 (badbranch): the cookie and no identifier.

#[test]
fn a_cookie_with_an_identifier_is_not_flagged() -> Result<(), TestError> {
    assert!(
        !has(&options(&[]), BRANCH_NO_ID)?,
        "z9hG4bK-torture-1 identifies"
    );
    Ok(())
}

#[test]
fn a_bare_cookie_branch_is_flagged() -> Result<(), TestError> {
    let data = options(&[("Via", b"SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK")]);
    assert!(has(&data, BRANCH_NO_ID)?, "RFC 4475 3.2.1");
    Ok(())
}

#[test]
fn a_bare_cookie_on_a_response_is_not_flagged() -> Result<(), TestError> {
    // A response copies the request's Via; the request is where it is reported.
    let data = build(
        b"SIP/2.0 200 OK",
        &[("Via", b"SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK")],
    );
    assert!(
        !has(&data, BRANCH_NO_ID)?,
        "requests only, like the cookie rule"
    );
    Ok(())
}
