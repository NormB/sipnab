//! STIR/SHAKEN Identity header parsing.
//!
//! Parses the SIP `Identity` header defined by RFC 8224 / ATIS-1000074.
//! The header contains a JWT (JSON Web Token) with attestation level,
//! originating/destination telephone numbers, and an origination ID.
//!
//! This implementation decodes and extracts the JWT claims but does **not**
//! perform cryptographic signature verification (that requires fetching the
//! certificate from the `info` URL). The `verified` field is always set to
//! [`VerificationStatus::NotChecked`].

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
/// sipnab does not fetch external certificates, so this is always
/// [`NotChecked`](VerificationStatus::NotChecked) for locally parsed headers
/// unless the `iat` freshness check fails (→ [`Expired`](VerificationStatus::Expired)).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationStatus {
    /// Signature was not checked (no cert available).
    NotChecked,
    /// Signature verified successfully.
    Valid,
    /// Signature verification failed.
    Invalid,
    /// No certificate available for verification.
    NoCert,
    /// The `iat` claim is stale — more than 60 seconds from the current time
    /// (RFC 8224 Section 4.4).
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
///
/// # Returns
///
/// The decoded claims. `verified` is `Expired` when the `iat` claim is more
/// than 60 seconds from the current system time (read via
/// `chrono::Utc::now`, so results are time-dependent), otherwise
/// `NotChecked`.
///
/// # Errors
///
/// Returns an error if the JWT cannot be split into its three parts or if
/// base64 decoding / JSON parsing of the payload fails.
pub fn parse_identity_header(header_value: &str) -> Result<StirShakenInfo> {
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

    // RFC 8224 Section 4.4: the `iat` claim must be within 60 seconds of
    // the current time. If it is stale (or too far in the future), mark
    // the token as expired. Missing `iat` is noted by leaving the field
    // as `None` — callers can treat absence as suspicious.
    let verified = match claims.iat {
        Some(iat) => {
            let now = chrono::Utc::now().timestamp();
            if (now - iat).abs() > 60 {
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
    /// Returns `None` if there is no `Identity` header. Returns `Some(Err(...))`
    /// if the header exists but cannot be parsed.
    pub fn stir_shaken(&self) -> Option<Result<StirShakenInfo>> {
        let identity = self.header("Identity")?;
        Some(parse_identity_header(identity))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for Identity header parsing: attestation levels, malformed JWTs,
/// iat freshness, and SipMessage integration (including the compact form).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;

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
        let info = parse_identity_header(&header).expect("should parse");

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
        let info = parse_identity_header(&header).expect("should parse");

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
        let info = parse_identity_header(&header).expect("should parse");

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
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::B);
    }

    /// `"attest": "C"` maps to Attestation::C.
    #[test]
    fn parse_attest_c() {
        let payload = r#"{"attest": "C", "orig": {"tn": "1001"}, "dest": {"tn": ["2002"]}, "iat": 1700000002}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::C);
    }

    /// An unrecognized attestation letter maps to Attestation::Unknown.
    #[test]
    fn parse_unknown_attestation() {
        let payload = r#"{"attest": "X", "orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
    }

    /// A payload without an `attest` claim maps to Attestation::Unknown.
    #[test]
    fn parse_missing_attestation() {
        let payload = r#"{"orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
    }

    /// A token with more than 3 dot-separated parts is rejected.
    #[test]
    fn malformed_jwt_too_few_parts() {
        let result = parse_identity_header("not.a.valid.jwt.with.too.many.parts");
        // This has more than 3 parts before ';', should fail
        // Actually: "not.a.valid.jwt.with.too.many.parts" has 7 parts
        assert!(result.is_err());
    }

    /// A single-segment token (no dots) is rejected.
    #[test]
    fn malformed_jwt_single_segment() {
        let result = parse_identity_header("justatoken");
        assert!(result.is_err());
    }

    /// A payload segment that is not valid base64url is rejected.
    #[test]
    fn malformed_jwt_bad_base64() {
        let result = parse_identity_header("aaa.!!!invalid_base64!!!.ccc");
        assert!(result.is_err());
    }

    /// A payload that decodes but is not JSON is rejected.
    #[test]
    fn malformed_jwt_bad_json() {
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"not json at all");
        let header = format!("aaa.{payload_b64}.ccc");
        let result = parse_identity_header(&header);
        assert!(result.is_err());
    }

    /// An empty JSON payload parses with all claims absent.
    #[test]
    fn parse_minimal_payload() {
        let payload = r#"{}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
        assert!(info.orig_tn.is_none());
        assert!(info.dest_tn.is_empty());
        assert!(info.dest_uri.is_empty());
        assert_eq!(info.dest_display(), "-");
        assert!(info.orig_id.is_none());
        assert!(info.iat.is_none());
    }

    /// An iat within the 60-second window stays NotChecked.
    #[test]
    fn iat_fresh_within_window() {
        let now = chrono::Utc::now().timestamp();
        let payload = format!(
            r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "dest": {{"tn": ["2002"]}}, "iat": {now}}}"#,
        );
        let header = build_identity_header(&payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.verified, VerificationStatus::NotChecked);
    }

    /// An iat two minutes in the past is marked Expired.
    #[test]
    fn iat_stale_past() {
        // 2 minutes ago — well outside the 60s window
        let stale = chrono::Utc::now().timestamp() - 120;
        let payload = format!(r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "iat": {stale}}}"#,);
        let header = build_identity_header(&payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.verified, VerificationStatus::Expired);
    }

    /// An iat two minutes in the future is also marked Expired.
    #[test]
    fn iat_stale_future() {
        // 2 minutes in the future — also outside the 60s window
        let future = chrono::Utc::now().timestamp() + 120;
        let payload = format!(r#"{{"attest": "A", "orig": {{"tn": "1001"}}, "iat": {future}}}"#,);
        let header = build_identity_header(&payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.verified, VerificationStatus::Expired);
    }

    /// A missing iat leaves the status NotChecked, not Expired.
    #[test]
    fn iat_missing_not_expired() {
        let payload = r#"{"attest": "B", "orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert!(info.iat.is_none());
        assert_eq!(info.verified, VerificationStatus::NotChecked);
    }

    /// `stir_shaken()` returns `None` when no Identity header is present.
    #[test]
    fn sip_message_stir_shaken_missing_header() {
        use std::net::{IpAddr, Ipv4Addr};
        let msg = SipMessage {
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

    /// `stir_shaken()` parses a present Identity header into claims.
    #[test]
    fn sip_message_stir_shaken_with_identity() {
        use crate::sip::message::SipHeader;
        use std::net::{IpAddr, Ipv4Addr};

        let payload = r#"{"attest": "A", "orig": {"tn": "5551234"}, "dest": {"tn": ["5559876"]}, "iat": 1700000000}"#;
        let identity_value = build_identity_header(payload);

        let msg = SipMessage {
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
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
            is_retransmission: false,
        };

        let info = msg
            .stir_shaken()
            .expect("should have Identity header")
            .expect("should parse");
        assert_eq!(info.attestation, Attestation::A);
        assert_eq!(info.orig_tn.as_deref(), Some("5551234"));
        // iat=1700000000 is stale
        assert_eq!(info.verified, VerificationStatus::Expired);
    }
}
