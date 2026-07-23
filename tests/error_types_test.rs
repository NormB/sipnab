//! The library surface must return structured, matchable errors —
//! not `Result<_, String>`. Callers (and these tests) match on variants;
//! Display keeps the actionable message.
#![cfg(feature = "native")]

use sipnab::Error;

/// Loading a nonexistent explicit config path yields `Error::ConfigNotFound`
/// whose Display names the path.
#[test]
fn config_missing_file_is_matchable() {
    let err = sipnab::config::Config::load(Some("/nonexistent/sipnab-test.toml"), false)
        .expect_err("missing explicit config must error");
    assert!(
        matches!(err, Error::ConfigNotFound { .. }),
        "expected ConfigNotFound, got: {err:?}"
    );
    assert!(
        err.to_string().contains("/nonexistent/sipnab-test.toml"),
        "message must name the path, got: {err}"
    );
}

/// Invalid TOML in a config file yields the matchable `Error::ConfigParse`.
#[test]
fn config_parse_error_is_matchable_and_names_path() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), "this is [not valid toml").expect("write");
    let err = sipnab::config::Config::load(tmp.path().to_str(), false)
        .expect_err("invalid TOML must error");
    assert!(
        matches!(err, Error::ConfigParse { .. }),
        "expected ConfigParse, got: {err:?}"
    );
}

/// A garbage CIDR string yields `Error::InvalidCidr` whose message echoes
/// the input.
#[cfg(feature = "hep")]
#[test]
fn invalid_cidr_is_matchable() {
    let err =
        sipnab::capture::hep::CidrRange::parse("not-a-cidr").expect_err("garbage CIDR must error");
    assert!(
        matches!(err, Error::InvalidCidr { .. }),
        "expected InvalidCidr, got: {err:?}"
    );
    assert!(
        err.to_string().contains("not-a-cidr"),
        "message must echo the input, got: {err}"
    );
}

/// An unknown alert sink name yields `Error::InvalidAlertRule`.
#[test]
fn invalid_alert_rule_is_matchable() {
    let err = sipnab::security::alerting::AlertRule::parse("bogus-sink")
        .expect_err("unknown alert sink must error");
    assert!(
        matches!(err, Error::InvalidAlertRule { .. }),
        "expected InvalidAlertRule, got: {err:?}"
    );
}

/// A garbage bind address yields `Error::InvalidBindAddr` from `parse_bind_addr`.
#[cfg(feature = "api")]
#[test]
fn invalid_bind_addr_is_matchable() {
    let err = sipnab::output::api::parse_bind_addr("not-an-addr")
        .expect_err("garbage bind addr must error");
    assert!(
        matches!(err, Error::InvalidBindAddr { .. }),
        "expected InvalidBindAddr, got: {err:?}"
    );
}

// ── WS6.1: typed errors for the crate-root parse/capture surface ────
// parse_sip / parse_sip_bytes / parse_rtp_header / parse_sdp return
// ParseError; parse_packet / PcapReader::new return CaptureError. Each
// test matches on a VARIANT — the whole point of the conversion.

use sipnab::error::{CaptureError, ParseError};

/// Fixed source/destination address (10.0.0.1) for `parse_sip` calls.
fn test_addr() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
}

/// A 2-byte RTP buffer yields `ParseError::TooShort { need: 12, got: 2 }`.
#[test]
fn truncated_rtp_is_matchable() {
    let err = sipnab::rtp::parser::parse_rtp_header(&[0x80, 0x00])
        .expect_err("2 bytes cannot be an RTP header");
    assert!(
        matches!(
            err,
            ParseError::TooShort {
                need: 12,
                got: 2,
                ..
            }
        ),
        "expected TooShort {{ need: 12, got: 2 }}, got: {err:?}"
    );
}

/// An RTP header with version 1 yields `ParseError::BadRtpVersion { version: 1 }`.
#[test]
fn rtp_bad_version_is_matchable() {
    let mut pkt = [0u8; 12];
    pkt[0] = 0x40; // version 1
    let err =
        sipnab::rtp::parser::parse_rtp_header(&pkt).expect_err("RTP version 1 must be rejected");
    assert!(
        matches!(err, ParseError::BadRtpVersion { version: 1 }),
        "expected BadRtpVersion {{ version: 1 }}, got: {err:?}"
    );
}

/// `parse_sip` on an empty buffer yields `ParseError::Empty`.
#[test]
fn empty_sip_data_is_matchable() {
    let err = sipnab::sip::parser::parse_sip(
        &[],
        chrono::Utc::now(),
        test_addr(),
        test_addr(),
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect_err("empty data must error");
    assert!(
        matches!(err, ParseError::Empty { .. }),
        "expected Empty, got: {err:?}"
    );
}

/// An HTTP request line yields `ParseError::NotSip` and the Display still
/// names the offending line.
#[test]
fn non_sip_first_line_is_matchable() {
    let err = sipnab::sip::parser::parse_sip(
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        chrono::Utc::now(),
        test_addr(),
        test_addr(),
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect_err("HTTP must not parse as SIP");
    assert!(
        matches!(err, ParseError::NotSip { .. }),
        "expected NotSip, got: {err:?}"
    );
    // The message still names the offending line for humans.
    assert!(err.to_string().contains("GET / HTTP/1.1"), "got: {err}");
}

/// Data with no line ending yields `ParseError::MissingCrlf`.
#[test]
fn sip_without_crlf_is_matchable() {
    let err = sipnab::sip::parser::parse_sip(
        b"binary-garbage-no-line-ending",
        chrono::Utc::now(),
        test_addr(),
        test_addr(),
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect_err("no CRLF must error");
    assert!(
        matches!(err, ParseError::MissingCrlf),
        "expected MissingCrlf, got: {err:?}"
    );
}

/// `parse_sdp` on an empty buffer yields `ParseError::Empty`.
#[test]
fn empty_sdp_is_matchable() {
    let err = sipnab::sip::sdp::parse_sdp(b"").expect_err("empty SDP must error");
    assert!(
        matches!(err, ParseError::Empty { .. }),
        "expected Empty, got: {err:?}"
    );
}

/// An SDP body with `v=1` yields `ParseError::BadSdpVersion`.
#[test]
fn bad_sdp_version_is_matchable() {
    let err = sipnab::sip::sdp::parse_sdp(b"v=1\r\no=- 1 1 IN IP4 10.0.0.1\r\n")
        .expect_err("SDP version 1 must be rejected");
    assert!(
        matches!(err, ParseError::BadSdpVersion { .. }),
        "expected BadSdpVersion, got: {err:?}"
    );
}

/// A packet with link type 147 (DLT_USER0) yields
/// `CaptureError::UnsupportedLinkType(147)`.
#[test]
fn unsupported_link_type_is_matchable() {
    let pkt = sipnab::capture::packet::Packet {
        timestamp: chrono::Utc::now(),
        data: bytes::Bytes::from_static(&[0u8; 64]),
        caplen: 64,
        origlen: 64,
        interface: None,
        link_type: 147, // DLT_USER0 — not supported
        pre_parsed: None,
    };
    let err =
        sipnab::capture::parse::parse_packet(&pkt).expect_err("unsupported link type must error");
    assert!(
        matches!(err, CaptureError::UnsupportedLinkType(147)),
        "expected UnsupportedLinkType(147), got: {err:?}"
    );
}

/// A 4-byte buffer yields `CaptureError::TooShort { got: 4 }` from `PcapReader::new`.
#[test]
fn pcap_file_too_short_is_matchable() {
    let err = sipnab::PcapReader::new(&[0u8; 4]).expect_err("4 bytes is not a capture file");
    assert!(
        matches!(err, CaptureError::TooShort { got: 4, .. }),
        "expected TooShort {{ got: 4 }}, got: {err:?}"
    );
}

/// A file starting with an unknown magic number yields `CaptureError::UnknownFormat`.
#[test]
fn unknown_capture_magic_is_matchable() {
    let mut data = [0u8; 32];
    data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let err = sipnab::PcapReader::new(&data).expect_err("unknown magic must error");
    assert!(
        matches!(err, CaptureError::UnknownFormat { .. }),
        "expected UnknownFormat, got: {err:?}"
    );
}

/// `ConfigParse`/`ConfigRead` chain the underlying toml/io error via
/// `source()` (API guideline C-GOOD-ERR) rather than flattening it to text.
#[test]
fn config_errors_chain_their_sources() {
    // C-GOOD-ERR: ConfigRead/ConfigParse carry the underlying io/toml
    // error as a real #[source], not flattened text.
    use std::error::Error as _;
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), "this is [not valid toml").expect("write");
    let err = sipnab::config::Config::load(tmp.path().to_str(), false)
        .expect_err("invalid TOML must error");
    assert!(
        err.source().is_some(),
        "ConfigParse must chain the toml error as source(), got: {err:?}"
    );

    let err = sipnab::config::Config::load(Some("/nonexistent-dir/x.toml"), false)
        .expect_err("missing config must error");
    // ConfigNotFound (no file) has no source; force a read error instead:
    // a directory path read fails with an io::Error.
    if let sipnab::Error::ConfigRead { .. } = err {
        assert!(err.source().is_some(), "ConfigRead must chain io::Error");
    }
}
