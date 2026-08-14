// SPDX-License-Identifier: MIT OR Apache-2.0

//! STIR/SHAKEN Identity header parsing.
//!
//! Parses the SIP `Identity` header defined by RFC 8224 / ATIS-1000074.
//! The header contains a JWT (JSON Web Token) with attestation level,
//! originating/destination telephone numbers, and an origination ID.
//!
//! This implementation decodes and extracts the JWT claims but does **not**
//! perform cryptographic signature verification (that requires fetching the
//! certificate from the `info` URL, and sipnab makes no outbound request to
//! analyse a capture). The `verified` field is therefore
//! [`VerificationStatus::NotChecked`], except that a stale `iat` claim
//! (RFC 8224 Section 4.4) reports [`VerificationStatus::Expired`]. Those are
//! the only two states the type has; an attestation level here is the
//! originator's claim, not a confirmed fact.
//!
//! # The freshness window is measured against CAPTURE time
//!
//! RFC 8224 §4.4 gives the `iat` claim a ±60 s window, and the only clock that
//! window may be read against is the timestamp of the packet that carried the
//! header. sipnab analyses files: a capture taken last Tuesday is read today,
//! and against the wall clock every Identity header in it is minutes, days or
//! years stale — so every token would report
//! [`Expired`](VerificationStatus::Expired) and the check would be reporting
//! the age of the FILE, not the freshness of the token.
//!
//! That is the same distinction `app::batch::SweepClock` draws for dialog and
//! stream expiry, and the same one the scanner and fraud detectors were
//! corrected for. Here it needs no enum: a parsed [`SipMessage`] already
//! carries the capture timestamp of the packet it came from, and for a LIVE
//! capture that timestamp *is* the wall clock. So
//! [`parse_identity_header`] takes the clock as an argument and
//! [`SipMessage::stir_shaken`] supplies the message's own timestamp — there is
//! no wall-clock-reading overload for a later caller to pick up by accident.

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use super::message::SipMessage;

// ── Public types ─────────────────────────────────────────────────────

/// STIR/SHAKEN attestation level.
///
/// - **A** — Full Attestation: the originating carrier can verify the calling
///   number is assigned to the customer and the customer is authorized to use it.
/// - **B** — Partial Attestation: the carrier has authenticated the customer
///   but cannot verify the calling number is assigned to them.
/// - **C** — Gateway Attestation: the call originated from a gateway (e.g.,
///   international) and the carrier cannot authenticate the source.
/// - **Unknown** — the attestation field was missing or unrecognized.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attestation {
    /// Full attestation.
    A,
    /// Partial attestation.
    B,
    /// Gateway attestation.
    C,
    /// Attestation level not recognized or missing.
    Unknown,
}

/// Signature verification status.
///
/// Both variants are reachable and nothing stronger exists: sipnab never
/// fetches the certificate the token references, so it can neither confirm
/// nor refute a signature. A locally parsed header is
/// [`NotChecked`](VerificationStatus::NotChecked) unless the `iat` freshness
/// check fails (→ [`Expired`](VerificationStatus::Expired)).
///
/// The enum is `#[non_exhaustive]` so that implementing verification later can
/// add variants without a semver-major bump.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationStatus {
    /// The signature was not checked: sipnab fetches no certificate.
    NotChecked,
    /// The `iat` claim is stale — more than 60 seconds from the capture
    /// timestamp of the packet that carried the header (RFC 8224 Section 4.4).
    Expired,
}

/// Parsed STIR/SHAKEN information from a SIP Identity header.
#[derive(Debug, Clone)]
pub struct StirShakenInfo {
    /// Attestation level (A, B, or C).
    pub attestation: Attestation,
    /// Originating telephone number from `orig.tn`.
    pub orig_tn: Option<String>,
    /// Destination telephone numbers from `dest.tn` (RFC 8225 Section 5.2.1
    /// allows several; empty when the claim is absent).
    pub dest_tn: Vec<String>,
    /// Destination URIs from `dest.uri` (empty when the claim is absent).
    pub dest_uri: Vec<String>,
    /// Origination identifier (UUID) from `origid`.
    pub orig_id: Option<String>,
    /// Issued-at timestamp (Unix epoch seconds) from `iat`.
    pub iat: Option<i64>,
    /// Signature verification status.
    pub verified: VerificationStatus,
}

// ── JWT payload deserialization ──────────────────────────────────────

/// Intermediate struct for the `orig` claim which contains `tn`.
#[derive(Deserialize)]
struct OrigClaim {
    /// Originating telephone number.
    tn: Option<String>,
}

/// Intermediate struct for the `dest` claim which contains arrays of `tn`
/// and/or `uri` (RFC 8225 Section 5.2.1).
#[derive(Deserialize)]
struct DestClaim {
    /// Destination telephone numbers (empty when absent).
    #[serde(default)]
    tn: Vec<String>,
    /// Destination URIs (empty when absent).
    #[serde(default)]
    uri: Vec<String>,
}

/// The JWT payload claims relevant to STIR/SHAKEN.
#[derive(Deserialize)]
struct ShakenPayload {
    /// Attestation level string (`"A"`, `"B"`, or `"C"`).
    attest: Option<String>,
    /// Originating-number claim.
    orig: Option<OrigClaim>,
    /// Destination-number claim.
    dest: Option<DestClaim>,
    /// Origination identifier (UUID).
    origid: Option<String>,
    /// Issued-at timestamp (Unix epoch seconds).
    iat: Option<i64>,
}

// ── Public API ───────────────────────────────────────────────────────

/// Parse a SIP `Identity` header value into [`StirShakenInfo`].
///
/// The Identity header format is:
/// ```text
/// header.payload.signature;info=<url>;alg=ES256;ppt=shaken
/// ```
///
/// Only the `header.payload` portions of the JWT are decoded (base64url).
/// Signature verification is **not** performed.
///
/// # Arguments
///
/// * `header_value` — the raw `Identity` header value (JWT plus optional
///   `;`-separated parameters).
/// * `now_unix` — the clock the RFC 8224 §4.4 freshness window is measured
///   against, in Unix epoch seconds. This is the **capture timestamp** of the
///   packet that carried the header, never `chrono::Utc::now()`: an offline
///   capture read a minute after it was taken would otherwise report every
///   token `Expired`. See the module docs.
///
/// # Returns
///
/// The decoded claims. `verified` is `Expired` when the `iat` claim is more
/// than 60 seconds from `now_unix`, otherwise `NotChecked`.
///
/// # Errors
///
/// Returns an error if the JWT cannot be split into its three parts or if
/// base64 decoding / JSON parsing of the payload fails.
pub fn parse_identity_header(header_value: &str, now_unix: i64) -> Result<StirShakenInfo> {
    // The Identity header may have parameters after the JWT, separated by ';'
    // The JWT itself is the first token (before any ';')
    let jwt_part = header_value.split(';').next().unwrap_or("").trim();

    // Split JWT into header.payload.signature
    let parts: Vec<&str> = jwt_part.split('.').collect();
    if parts.len() != 3 {
        bail!(
            "Invalid Identity header: expected 3 JWT parts (header.payload.signature), got {}",
            parts.len()
        );
    }

    // Decode payload (second part) — base64url without padding
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| anyhow::anyhow!("Failed to base64url-decode JWT payload: {e}"))?;

    let claims: ShakenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse JWT payload JSON: {e}"))?;

    let attestation = match claims.attest.as_deref() {
        Some("A") => Attestation::A,
        Some("B") => Attestation::B,
        Some("C") => Attestation::C,
        _ => Attestation::Unknown,
    };

    let orig_tn = claims.orig.and_then(|o| o.tn);
    let (dest_tn, dest_uri) = claims.dest.map(|d| (d.tn, d.uri)).unwrap_or_default();

    // RFC 8224 Section 4.4: the `iat` claim must be within 60 seconds of the
    // time the message was on the wire. If it is stale (or too far in the
    // future), mark the token as expired. Missing `iat` is noted by leaving
    // the field as `None` — callers can treat absence as suspicious.
    let verified = match claims.iat {
        Some(iat) => {
            if (now_unix - iat).abs() > 60 {
                VerificationStatus::Expired
            } else {
                VerificationStatus::NotChecked
            }
        }
        None => VerificationStatus::NotChecked,
    };

    Ok(StirShakenInfo {
        attestation,
        orig_tn,
        dest_tn,
        dest_uri,
        orig_id: claims.origid,
        iat: claims.iat,
        verified,
    })
}

impl StirShakenInfo {
    /// All destinations (TNs then URIs) joined with commas for display;
    /// `"-"` when the `dest` claim carried none.
    pub fn dest_display(&self) -> String {
        if self.dest_tn.is_empty() && self.dest_uri.is_empty() {
            return "-".to_string();
        }
        self.dest_tn
            .iter()
            .chain(&self.dest_uri)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

// ── SipMessage extension ─────────────────────────────────────────────

impl SipMessage {
    /// Extract STIR/SHAKEN information from the `Identity` header, if present.
    ///
    /// The RFC 8224 §4.4 freshness window is measured against **this message's
    /// capture timestamp**, not the wall clock. `--stir-shaken -I capture.pcap`
    /// therefore answers "was the token fresh when it was sent", which is the
    /// only question the capture can answer; reading the wall clock would
    /// instead report the age of the file, marking every token in any capture
    /// older than a minute `Expired`. On a live capture the two coincide,
    /// because the packet's timestamp is the current time.
    ///
    /// Returns `None` if there is no `Identity` header. Returns `Some(Err(...))`
    /// if the header exists but cannot be parsed.
    pub fn stir_shaken(&self) -> Option<Result<StirShakenInfo>> {
        let identity = self.header("Identity")?;
        Some(parse_identity_header(identity, self.timestamp.timestamp()))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for Identity header parsing: attestation levels, malformed JWTs,
/// iat freshness, and SipMessage integration (including the compact form).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;

    /// The `iat` every fixed payload below carries: 2023-11-14T22:13:20Z.
    const FIXED_IAT: i64 = 1_700_000_000;

    /// A capture clock a full hour after [`FIXED_IAT`], for the tests that are
    /// about claim extraction rather than freshness. Named and fixed rather
    /// than `Utc::now()`, so no test in this module can pass or fail because of
    /// when the suite ran.
    const LONG_AFTER_IAT: i64 = FIXED_IAT + 3600;

    /// Build a minimal SHAKEN JWT with the given claims.
    ///
    /// The header and signature are dummy values — only the payload matters
    /// for our parser since we don't verify signatures.
    fn build_identity_header(payload_json: &str) -> String {
        let header_json = r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://cert.example.com/cert.pem"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"fake_signature_bytes_here");

        format!(
            "{header_b64}.{payload_b64}.{sig_b64};info=<https://cert.example.com/cert.pem>;alg=ES256;ppt=shaken"
        )
    }

    /// A full attestation-A payload yields every claim (and a stale iat
    /// marks it Expired).
    #[test]
    fn parse_attest_a_full() {
        let payload = r#"{
            "attest": "A",
            "dest": {"tn": ["12025551234"]},
            "iat": 1700000000,
            "orig": {"tn": "12125559876"},
            "origid": "550e8400-e29b-41d4-a716-446655440000"
        }"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.attestation, Attestation::A);
        assert_eq!(info.orig_tn.as_deref(), Some("12125559876"));
        assert_eq!(info.dest_tn, ["12025551234"]);
        assert_eq!(
            info.orig_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(info.iat, Some(1_700_000_000));
        // iat is from 2023 — well beyond the 60s freshness window
        assert_eq!(info.verified, VerificationStatus::Expired);
    }

    /// A dest claim with multiple `tn` entries (RFC 8225 Section 5.2.1)
    /// retains every destination, not just the first.
    #[test]
    fn parse_multiple_dest_tns_all_retained() {
        let payload = r#"{
            "attest": "A",
            "dest": {"tn": ["12025551000", "12025551001", "12025551002"]},
            "iat": 1700000000,
            "orig": {"tn": "12125559876"}
        }"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(
            info.dest_tn,
            ["12025551000", "12025551001", "12025551002"],
            "every dest.tn entry must be retained"
        );
        assert!(info.dest_uri.is_empty());
        assert_eq!(info.dest_display(), "12025551000,12025551001,12025551002");
    }

    /// A dest claim carrying `uri` entries (allowed alongside or instead of
    /// `tn` per RFC 8225 Section 5.2.1) retains every URI.
    #[test]
    fn parse_dest_uris_all_retained() {
        let payload = r#"{
            "attest": "A",
            "dest": {"tn": ["12025551000"], "uri": ["sip:bob@example.com", "sip:carol@example.net"]},
            "iat": 1700000000,
            "orig": {"tn": "12125559876"}
        }"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.dest_tn, ["12025551000"]);
        assert_eq!(
            info.dest_uri,
            ["sip:bob@example.com", "sip:carol@example.net"],
            "every dest.uri entry must be retained"
        );
        assert_eq!(
            info.dest_display(),
            "12025551000,sip:bob@example.com,sip:carol@example.net"
        );
    }

    /// `"attest": "B"` maps to Attestation::B.
    #[test]
    fn parse_attest_b() {
        let payload = r#"{"attest": "B", "orig": {"tn": "1001"}, "dest": {"tn": ["2002"]}, "iat": 1700000001}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.attestation, Attestation::B);
    }

    /// `"attest": "C"` maps to Attestation::C.
    #[test]
    fn parse_attest_c() {
        let payload = r#"{"attest": "C", "orig": {"tn": "1001"}, "dest": {"tn": ["2002"]}, "iat": 1700000002}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.attestation, Attestation::C);
    }

    /// An unrecognized attestation letter maps to Attestation::Unknown.
    #[test]
    fn parse_unknown_attestation() {
        let payload = r#"{"attest": "X", "orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
    }

    /// A payload without an `attest` claim maps to Attestation::Unknown.
    #[test]
    fn parse_missing_attestation() {
        let payload = r#"{"orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
    }

    /// A token with more than 3 dot-separated parts is rejected.
    #[test]
    fn malformed_jwt_too_many_parts() {
        // "not.a.valid.jwt.with.too.many.parts" splits into 8 parts (> 3).
        let result = parse_identity_header("not.a.valid.jwt.with.too.many.parts", LONG_AFTER_IAT);
        assert!(result.is_err());
    }

    /// A single-segment token (no dots) is rejected.
    #[test]
    fn malformed_jwt_single_segment() {
        let result = parse_identity_header("justatoken", LONG_AFTER_IAT);
        assert!(result.is_err());
    }

    /// A payload segment that is not valid base64url is rejected.
    #[test]
    fn malformed_jwt_bad_base64() {
        let result = parse_identity_header("aaa.!!!invalid_base64!!!.ccc", LONG_AFTER_IAT);
        assert!(result.is_err());
    }

    /// A payload that decodes but is not JSON is rejected.
    #[test]
    fn malformed_jwt_bad_json() {
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"not json at all");
        let header = format!("aaa.{payload_b64}.ccc");
        let result = parse_identity_header(&header, LONG_AFTER_IAT);
        assert!(result.is_err());
    }

    /// An empty JSON payload parses with all claims absent.
    #[test]
    fn parse_minimal_payload() {
        let payload = r#"{}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
        assert!(info.orig_tn.is_none());
        assert!(info.dest_tn.is_empty());
        assert!(info.dest_uri.is_empty());
        assert_eq!(info.dest_display(), "-");
        assert!(info.orig_id.is_none());
        assert!(info.iat.is_none());
    }

    /// An iat matching the capture clock stays NotChecked.
    #[test]
    fn iat_fresh_within_window() {
        let payload = format!(
            r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "dest": {{"tn": ["2002"]}}, "iat": {LONG_AFTER_IAT}}}"#,
        );
        let header = build_identity_header(&payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.verified, VerificationStatus::NotChecked);
    }

    /// An iat two minutes before the capture clock is marked Expired.
    #[test]
    fn iat_stale_past() {
        // 2 minutes before the packet was captured — outside the 60s window.
        let stale = LONG_AFTER_IAT - 120;
        let payload = format!(r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "iat": {stale}}}"#,);
        let header = build_identity_header(&payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.verified, VerificationStatus::Expired);
    }

    /// An iat two minutes after the capture clock is also marked Expired.
    #[test]
    fn iat_stale_future() {
        // 2 minutes after the packet was captured — also outside the window.
        let future = LONG_AFTER_IAT + 120;
        let payload = format!(r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "iat": {future}}}"#,);
        let header = build_identity_header(&payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert_eq!(info.verified, VerificationStatus::Expired);
    }

    /// A missing iat leaves the status NotChecked, not Expired.
    #[test]
    fn iat_missing_not_expired() {
        let payload = r#"{"attest": "B", "orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header, LONG_AFTER_IAT).expect("should parse");

        assert!(info.iat.is_none());
        assert_eq!(info.verified, VerificationStatus::NotChecked);
    }

    /// The iat freshness window is classified deterministically against an
    /// injected clock: at exactly 60s from `now` the token is still fresh; at
    /// 61s (past or future) it is Expired. No dependency on the wall clock.
    #[test]
    fn iat_window_boundary_with_injected_clock() {
        // Fixed reference "now" so the test never depends on Utc::now().
        let now: i64 = FIXED_IAT;

        let header_at = |iat: i64| {
            let payload = format!(r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "iat": {iat}}}"#);
            build_identity_header(&payload)
        };

        // Exactly on the 60s boundary (both directions) stays NotChecked.
        for iat in [now - 60, now + 60] {
            let info = parse_identity_header(&header_at(iat), now).expect("should parse");
            assert_eq!(
                info.verified,
                VerificationStatus::NotChecked,
                "iat {iat} at now {now} should be within the 60s window"
            );
        }

        // One second past the boundary (both directions) is Expired.
        for iat in [now - 61, now + 61] {
            let info = parse_identity_header(&header_at(iat), now).expect("should parse");
            assert_eq!(
                info.verified,
                VerificationStatus::Expired,
                "iat {iat} at now {now} should be outside the 60s window"
            );
        }
    }

    /// `stir_shaken()` returns `None` when no Identity header is present.
    #[test]
    fn sip_message_stir_shaken_missing_header() {
        use std::net::{IpAddr, Ipv4Addr};
        let msg = SipMessage {
            frame: None,
            raw: Default::default(),
            is_request: true,
            method: Some(crate::sip::SipMethod::Invite),
            status_code: None,
            reason: None,
            request_uri: Some("sip:bob@example.com".to_string()),
            headers: vec![],
            body: Default::default(),
            parse_error: false,
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
            dscp: None,
            is_retransmission: false,
        };

        assert!(msg.stir_shaken().is_none());
    }

    /// The RFC 8224 compact `y:` form is expanded and analyzed identically
    /// to a long-form Identity header.
    #[test]
    fn compact_identity_header_cannot_evade_extraction() {
        // RFC 8224 registers `y` as the compact form of Identity. A caller
        // emitting `y:` is fully standards-compliant toward verifiers, so if
        // sipnab only recognized the long form, compact-form PASSporTs would
        // silently bypass STIR/SHAKEN analysis. Parse a real message (the
        // expansion is a parser concern) and require identical extraction.
        use crate::sip::parser::parse_sip;
        use std::net::{IpAddr, Ipv4Addr};

        let payload = r#"{"attest": "A", "orig": {"tn": "5551234"}, "dest": {"tn": ["5559876"]}, "iat": 1700000000}"#;
        let identity_value = build_identity_header(payload);

        let raw = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKy1\r\n\
             From: <sip:alice@example.com>;tag=y1\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: compact-identity@test\r\n\
             CSeq: 1 INVITE\r\n\
             y: {identity_value}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let msg = parse_sip(
            raw.as_bytes(),
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let info = msg
            .stir_shaken()
            .expect("compact y: header must be recognized as Identity")
            .expect("PASSporT should parse");
        assert_eq!(info.attestation, Attestation::A);
        assert_eq!(info.orig_tn.as_deref(), Some("5551234"));
    }

    /// An INVITE carrying `identity_value`, captured at `captured_at`.
    fn message_with_identity(
        identity_value: String,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> SipMessage {
        use crate::sip::message::SipHeader;
        use std::net::{IpAddr, Ipv4Addr};

        SipMessage {
            frame: None,
            raw: Default::default(),
            is_request: true,
            method: Some(crate::sip::SipMethod::Invite),
            status_code: None,
            reason: None,
            request_uri: Some("sip:bob@example.com".to_string()),
            headers: vec![SipHeader {
                name: "Identity".into(),
                value: identity_value,
            }],
            body: Default::default(),
            parse_error: false,
            timestamp: captured_at,
            src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
            dscp: None,
            is_retransmission: false,
        }
    }

    /// `stir_shaken()` parses a present Identity header into claims.
    #[test]
    fn sip_message_stir_shaken_with_identity() {
        let payload = r#"{"attest": "A", "orig": {"tn": "5551234"}, "dest": {"tn": ["5559876"]}, "iat": 1700000000}"#;
        let msg = message_with_identity(build_identity_header(payload), chrono::Utc::now());

        let info = msg
            .stir_shaken()
            .expect("should have Identity header")
            .expect("should parse");
        assert_eq!(info.attestation, Attestation::A);
        assert_eq!(info.orig_tn.as_deref(), Some("5551234"));
        // Captured now, issued in 2023: stale against this packet's own clock.
        assert_eq!(info.verified, VerificationStatus::Expired);
    }

    /// A token issued when the packet was captured is FRESH, however long ago
    /// the capture was taken.
    ///
    /// This is the whole defect in one assertion. sipnab reads files, so the
    /// wall clock answers a question nobody asked — "is this pcap younger than
    /// a minute" — and under it every Identity header in every stored capture
    /// reports `Expired`, including the ones a carrier signed correctly. The
    /// packet's own timestamp answers the question RFC 8224 §4.4 actually
    /// poses. Both readings are computed here so the test names what it is
    /// choosing between rather than merely asserting the good one.
    #[test]
    fn an_old_capture_does_not_expire_a_token_that_was_fresh_when_sent() {
        // A capture from 2023. The token was issued as the INVITE went out.
        let captured_at = chrono::DateTime::from_timestamp(FIXED_IAT, 0).expect("valid epoch");
        let payload =
            format!(r#"{{"attest": "A", "orig": {{"tn": "5551234"}}, "iat": {FIXED_IAT}}}"#);
        let identity_value = build_identity_header(&payload);

        let info = message_with_identity(identity_value.clone(), captured_at)
            .stir_shaken()
            .expect("should have Identity header")
            .expect("should parse");
        assert_eq!(
            info.verified,
            VerificationStatus::NotChecked,
            "a token issued at capture time is fresh; reading the wall clock \
             would call every header in every stored capture Expired"
        );

        // The reading that was replaced, computed rather than asserted from
        // memory: the same header against the wall clock IS Expired, so the
        // assertion above cannot pass by both clocks agreeing.
        let wall = chrono::Utc::now().timestamp();
        assert!(
            (wall - FIXED_IAT).abs() > 60,
            "this test needs the suite to run more than a minute after \
             {FIXED_IAT}; it is 2023, so only a badly wrong system clock \
             gets here"
        );
        let by_wall_clock = parse_identity_header(&identity_value, wall).expect("should parse");
        assert_eq!(by_wall_clock.verified, VerificationStatus::Expired);
    }
}
