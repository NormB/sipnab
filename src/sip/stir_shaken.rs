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
/// [`NotChecked`](VerificationStatus::NotChecked) for locally parsed headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Signature was not checked (no cert available).
    NotChecked,
    /// Signature verified successfully.
    Valid,
    /// Signature verification failed.
    Invalid,
    /// No certificate available for verification.
    NoCert,
}

/// Parsed STIR/SHAKEN information from a SIP Identity header.
#[derive(Debug, Clone)]
pub struct StirShakenInfo {
    /// Attestation level (A, B, or C).
    pub attestation: Attestation,
    /// Originating telephone number from `orig.tn`.
    pub orig_tn: Option<String>,
    /// Destination telephone number(s) from `dest.tn`.
    pub dest_tn: Option<String>,
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
    tn: Option<String>,
}

/// Intermediate struct for the `dest` claim which contains an array of `tn`.
#[derive(Deserialize)]
struct DestClaim {
    #[serde(default)]
    tn: Vec<String>,
}

/// The JWT payload claims relevant to STIR/SHAKEN.
#[derive(Deserialize)]
struct ShakenPayload {
    attest: Option<String>,
    orig: Option<OrigClaim>,
    dest: Option<DestClaim>,
    origid: Option<String>,
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
    let dest_tn = claims.dest.and_then(|d| d.tn.into_iter().next());

    Ok(StirShakenInfo {
        attestation,
        orig_tn,
        dest_tn,
        orig_id: claims.origid,
        iat: claims.iat,
        verified: VerificationStatus::NotChecked,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;

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
        assert_eq!(info.dest_tn.as_deref(), Some("12025551234"));
        assert_eq!(
            info.orig_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(info.iat, Some(1_700_000_000));
        assert_eq!(info.verified, VerificationStatus::NotChecked);
    }

    #[test]
    fn parse_attest_b() {
        let payload = r#"{"attest": "B", "orig": {"tn": "1001"}, "dest": {"tn": ["2002"]}, "iat": 1700000001}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::B);
    }

    #[test]
    fn parse_attest_c() {
        let payload = r#"{"attest": "C", "orig": {"tn": "1001"}, "dest": {"tn": ["2002"]}, "iat": 1700000002}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::C);
    }

    #[test]
    fn parse_unknown_attestation() {
        let payload = r#"{"attest": "X", "orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
    }

    #[test]
    fn parse_missing_attestation() {
        let payload = r#"{"orig": {"tn": "1001"}}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
    }

    #[test]
    fn malformed_jwt_too_few_parts() {
        let result = parse_identity_header("not.a.valid.jwt.with.too.many.parts");
        // This has more than 3 parts before ';', should fail
        // Actually: "not.a.valid.jwt.with.too.many.parts" has 7 parts
        assert!(result.is_err());
    }

    #[test]
    fn malformed_jwt_single_segment() {
        let result = parse_identity_header("justatoken");
        assert!(result.is_err());
    }

    #[test]
    fn malformed_jwt_bad_base64() {
        let result = parse_identity_header("aaa.!!!invalid_base64!!!.ccc");
        assert!(result.is_err());
    }

    #[test]
    fn malformed_jwt_bad_json() {
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"not json at all");
        let header = format!("aaa.{payload_b64}.ccc");
        let result = parse_identity_header(&header);
        assert!(result.is_err());
    }

    #[test]
    fn parse_minimal_payload() {
        let payload = r#"{}"#;
        let header = build_identity_header(payload);
        let info = parse_identity_header(&header).expect("should parse");

        assert_eq!(info.attestation, Attestation::Unknown);
        assert!(info.orig_tn.is_none());
        assert!(info.dest_tn.is_none());
        assert!(info.orig_id.is_none());
        assert!(info.iat.is_none());
    }

    #[test]
    fn sip_message_stir_shaken_missing_header() {
        use std::net::{IpAddr, Ipv4Addr};
        let msg = SipMessage {
            raw: Vec::new(),
            is_request: true,
            method: Some("INVITE".to_string()),
            status_code: None,
            reason: None,
            request_uri: Some("sip:bob@example.com".to_string()),
            headers: vec![],
            body: Vec::new(),
            parse_error: false,
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
        };

        assert!(msg.stir_shaken().is_none());
    }

    #[test]
    fn sip_message_stir_shaken_with_identity() {
        use crate::sip::message::SipHeader;
        use std::net::{IpAddr, Ipv4Addr};

        let payload = r#"{"attest": "A", "orig": {"tn": "5551234"}, "dest": {"tn": ["5559876"]}, "iat": 1700000000}"#;
        let identity_value = build_identity_header(payload);

        let msg = SipMessage {
            raw: Vec::new(),
            is_request: true,
            method: Some("INVITE".to_string()),
            status_code: None,
            reason: None,
            request_uri: Some("sip:bob@example.com".to_string()),
            headers: vec![SipHeader {
                name: "Identity".into(),
                value: identity_value,
            }],
            body: Vec::new(),
            parse_error: false,
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
        };

        let info = msg
            .stir_shaken()
            .expect("should have Identity header")
            .expect("should parse");
        assert_eq!(info.attestation, Attestation::A);
        assert_eq!(info.orig_tn.as_deref(), Some("5551234"));
    }
}
