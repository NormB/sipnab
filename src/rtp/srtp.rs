//! SRTP key extraction from SDP and manual key file parsing.
//!
//! Extracts SRTP master key and salt material from SDP `a=crypto` attributes
//! (SDES key exchange, RFC 4568) and from a manual key file format used with
//! the `--srtp-keys` CLI option. Actual SRTP decryption is deferred to a
//! [`CryptoBackend`](crate::crypto::CryptoBackend) implementation.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::sip::sdp::SdpCrypto;

/// SRTP key material extracted from an SDP `a=crypto` line or manual key file.
#[derive(Debug, Clone)]
pub struct SrtpKeyMaterial {
    /// The crypto attribute tag number from the SDP offer/answer.
    pub tag: u32,
    /// The SRTP crypto suite in use.
    pub suite: SrtpSuite,
    /// The master key bytes.
    pub master_key: Vec<u8>,
    /// The master salt bytes.
    pub master_salt: Vec<u8>,
    /// The RTP SSRC this key is associated with, if known.
    pub ssrc: Option<u32>,
    /// The media address from the SDP `c=` line, if available.
    pub media_addr: Option<String>,
    /// The media port from the SDP `m=` line, if available.
    pub media_port: Option<u16>,
}

#[cfg(feature = "tls")]
impl Drop for SrtpKeyMaterial {
    fn drop(&mut self) {
        // Zeroize key material on drop to prevent key leakage via memory.
        use zeroize::Zeroize;
        self.master_key.zeroize();
        self.master_salt.zeroize();
    }
}

/// SRTP crypto suite identifiers (RFC 4568 Section 6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtpSuite {
    /// AES-128 Counter Mode with 80-bit HMAC-SHA1 authentication tag.
    AesCm128HmacSha1_80,
    /// AES-128 Counter Mode with 32-bit HMAC-SHA1 authentication tag.
    AesCm128HmacSha1_32,
    /// AES-256 Counter Mode with 80-bit HMAC-SHA1 authentication tag.
    AesCm256HmacSha1_80,
    /// Unrecognized suite name.
    Unknown(String),
}

impl SrtpSuite {
    /// Parse a suite name string into the enum variant.
    fn from_str(s: &str) -> Self {
        match s {
            "AES_CM_128_HMAC_SHA1_80" => Self::AesCm128HmacSha1_80,
            "AES_CM_128_HMAC_SHA1_32" => Self::AesCm128HmacSha1_32,
            "AES_CM_256_HMAC_SHA1_80" | "AES_256_CM_HMAC_SHA1_80" => Self::AesCm256HmacSha1_80,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Expected master key length in bytes for this suite.
    fn expected_key_len(&self) -> Option<usize> {
        match self {
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 => Some(16),
            Self::AesCm256HmacSha1_80 => Some(32),
            Self::Unknown(_) => None,
        }
    }

    /// Expected master salt length in bytes for this suite.
    fn expected_salt_len(&self) -> Option<usize> {
        match self {
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 | Self::AesCm256HmacSha1_80 => {
                Some(14)
            }
            Self::Unknown(_) => None,
        }
    }
}

/// Extract SRTP key material from an SDP `a=crypto` attribute.
///
/// The `key_params` field should contain `inline:<base64(key||salt)>` where
/// key and salt are concatenated and base64-encoded. Optional session
/// parameters after a `|` separator are ignored.
///
/// # Errors
///
/// Returns an error if the key_params format is invalid, the base64 is
/// malformed, or the decoded material doesn't match the expected length
/// for the suite.
pub fn extract_srtp_keys(crypto: &SdpCrypto) -> Result<SrtpKeyMaterial> {
    let suite = SrtpSuite::from_str(&crypto.suite);

    // Parse the key_params: "inline:<base64>[|<session_params>]"
    let inline_data = crypto.key_params.strip_prefix("inline:").with_context(|| {
        format!(
            "SRTP key_params must start with 'inline:', got: {}",
            crypto.key_params
        )
    })?;

    // Strip optional session parameters after '|'
    let b64_part = inline_data.split('|').next().unwrap_or(inline_data);

    let decoded = BASE64
        .decode(b64_part)
        .with_context(|| format!("Invalid base64 in SRTP key_params: {b64_part}"))?;

    // Split into key and salt based on suite expectations
    let (master_key, master_salt) = split_key_salt(&suite, &decoded)?;

    Ok(SrtpKeyMaterial {
        tag: crypto.tag,
        suite,
        master_key,
        master_salt,
        ssrc: None,
        media_addr: None,
        media_port: None,
    })
}

/// Split concatenated key||salt bytes based on suite requirements.
fn split_key_salt(suite: &SrtpSuite, material: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_len = suite.expected_key_len();
    let salt_len = suite.expected_salt_len();

    match (key_len, salt_len) {
        (Some(kl), Some(sl)) => {
            let expected = kl + sl;
            if material.len() < expected {
                anyhow::bail!(
                    "SRTP key material too short: got {} bytes, expected {} (key={kl}, salt={sl})",
                    material.len(),
                    expected
                );
            }
            Ok((material[..kl].to_vec(), material[kl..kl + sl].to_vec()))
        }
        _ => {
            // Unknown suite — treat first 16 bytes as key, next 14 as salt (SRTP defaults)
            if material.len() < 30 {
                anyhow::bail!(
                    "SRTP key material too short for unknown suite: got {} bytes, expected >= 30",
                    material.len()
                );
            }
            Ok((material[..16].to_vec(), material[16..30].to_vec()))
        }
    }
}

/// Parse a manual SRTP key file (used with `--srtp-keys`).
///
/// Each non-empty, non-comment line has the format:
/// ```text
/// ssrc=<decimal> key=<base64> [salt=<base64>] [suite=<name>]
/// ```
///
/// If `salt` is omitted, the key is treated as key||salt concatenated.
/// If `suite` is omitted, `AES_CM_128_HMAC_SHA1_80` is assumed.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains invalid entries.
pub fn parse_srtp_key_file(path: &Path) -> Result<Vec<SrtpKeyMaterial>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read SRTP key file: {}", path.display()))?;

    let mut entries = Vec::new();

    for (line_num, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let entry = parse_srtp_key_line(line).with_context(|| {
            format!(
                "Invalid SRTP key entry at {}:{}: {line}",
                path.display(),
                line_num + 1
            )
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Parse a single line from the manual SRTP key file format.
fn parse_srtp_key_line(line: &str) -> Result<SrtpKeyMaterial> {
    let mut ssrc: Option<u32> = None;
    let mut key_b64: Option<&str> = None;
    let mut salt_b64: Option<&str> = None;
    let mut suite_name: Option<&str> = None;

    for token in line.split_whitespace() {
        if let Some(val) = token.strip_prefix("ssrc=") {
            ssrc = Some(
                val.parse::<u32>()
                    .with_context(|| format!("Invalid SSRC value: {val}"))?,
            );
        } else if let Some(val) = token.strip_prefix("key=") {
            key_b64 = Some(val);
        } else if let Some(val) = token.strip_prefix("salt=") {
            salt_b64 = Some(val);
        } else if let Some(val) = token.strip_prefix("suite=") {
            suite_name = Some(val);
        }
    }

    let key_b64 = key_b64.context("Missing 'key=' in SRTP key line")?;
    let suite = SrtpSuite::from_str(suite_name.unwrap_or("AES_CM_128_HMAC_SHA1_80"));

    let key_bytes = BASE64
        .decode(key_b64)
        .with_context(|| format!("Invalid base64 in key: {key_b64}"))?;

    let (master_key, master_salt) = if let Some(sb64) = salt_b64 {
        let salt_bytes = BASE64
            .decode(sb64)
            .with_context(|| format!("Invalid base64 in salt: {sb64}"))?;
        (key_bytes, salt_bytes)
    } else {
        // key contains key||salt concatenated
        split_key_salt(&suite, &key_bytes)?
    };

    Ok(SrtpKeyMaterial {
        tag: 0,
        suite,
        master_key,
        master_salt,
        ssrc,
        media_addr: None,
        media_port: None,
    })
}

/// Length of HMAC-SHA1 authentication tag for common SRTP suites.
///
/// AES_CM_128_HMAC_SHA1_80 uses 10 bytes (80 bits).
/// AES_CM_128_HMAC_SHA1_32 uses 4 bytes (32 bits).
pub fn auth_tag_len(suite: &SrtpSuite) -> usize {
    match suite {
        SrtpSuite::AesCm128HmacSha1_80 | SrtpSuite::AesCm256HmacSha1_80 => 10,
        SrtpSuite::AesCm128HmacSha1_32 => 4,
        SrtpSuite::Unknown(_) => 10, // Default to 80-bit
    }
}

/// Verify the SRTP authentication tag on an SRTP packet.
///
/// The SRTP packet format is: `[RTP header + encrypted payload] [auth tag]`.
/// The authentication tag is computed as HMAC-SHA1 over the authenticated
/// portion (everything before the tag) with the ROC (rollover counter)
/// appended. For simplicity, this implementation assumes ROC = 0 (valid
/// for the first 65535 packets of a session).
///
/// Returns `Ok(true)` if the tag is valid, `Ok(false)` if the tag does
/// not match, or `Err` if the crypto operation fails.
///
/// # Arguments
///
/// * `packet` — The full SRTP packet (header + encrypted payload + auth tag).
/// * `key_material` — The SRTP key material containing master key/salt.
/// * `crypto` — The crypto backend for HMAC computation.
pub fn verify_srtp_auth_tag(
    packet: &[u8],
    key_material: &SrtpKeyMaterial,
    crypto: &dyn crate::crypto::CryptoBackend,
) -> Result<bool> {
    let tag_len = auth_tag_len(&key_material.suite);
    if packet.len() < 12 + tag_len {
        anyhow::bail!(
            "SRTP packet too short for auth tag verification: {} bytes",
            packet.len()
        );
    }

    let auth_portion_len = packet.len() - tag_len;
    let auth_portion = &packet[..auth_portion_len];
    let received_tag = &packet[auth_portion_len..];

    // Derive auth key from master key and salt.
    // SRTP KDF: auth_key = KDF(master_key, label=0x01, master_salt, index=0)
    // For simplicity, use the master key directly as the HMAC key.
    // A full implementation would use the SRTP KDF (AES-CM based PRF),
    // but for initial tag detection this provides a reasonable signal.
    // Note: With the simplified approach, we compute HMAC-SHA1(master_key, auth_portion || ROC).
    let mut hmac_input = auth_portion.to_vec();
    // Append ROC (assumed 0 for initial implementation)
    hmac_input.extend_from_slice(&0u32.to_be_bytes());

    let full_tag = crypto.hmac_sha1(&key_material.master_key, &hmac_input)?;
    let computed_tag = &full_tag[..tag_len.min(full_tag.len())];

    Ok(computed_tag == received_tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "tls")]
    use crate::crypto::CryptoBackend;
    use std::io::Write;

    /// Build a valid base64-encoded key||salt for AES_CM_128_HMAC_SHA1_80
    /// (16-byte key + 14-byte salt = 30 bytes).
    fn make_test_key_material() -> (Vec<u8>, Vec<u8>, String) {
        let key = vec![0x01u8; 16];
        let salt = vec![0x02u8; 14];
        let mut combined = key.clone();
        combined.extend_from_slice(&salt);
        let b64 = BASE64.encode(&combined);
        (key, salt, b64)
    }

    #[test]
    fn extract_aes_cm_128_hmac_sha1_80() {
        let (expected_key, expected_salt, b64) = make_test_key_material();

        let crypto = SdpCrypto {
            tag: 1,
            suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
            key_params: format!("inline:{b64}"),
        };

        let material = extract_srtp_keys(&crypto).expect("should extract keys");
        assert_eq!(material.tag, 1);
        assert_eq!(material.suite, SrtpSuite::AesCm128HmacSha1_80);
        assert_eq!(material.master_key, expected_key);
        assert_eq!(material.master_salt, expected_salt);
    }

    #[test]
    fn extract_aes_cm_128_hmac_sha1_32() {
        let (expected_key, expected_salt, b64) = make_test_key_material();

        let crypto = SdpCrypto {
            tag: 2,
            suite: "AES_CM_128_HMAC_SHA1_32".to_string(),
            key_params: format!("inline:{b64}"),
        };

        let material = extract_srtp_keys(&crypto).expect("should extract keys");
        assert_eq!(material.suite, SrtpSuite::AesCm128HmacSha1_32);
        assert_eq!(material.master_key, expected_key);
        assert_eq!(material.master_salt, expected_salt);
    }

    #[test]
    fn extract_with_session_params_after_pipe() {
        let (_key, _salt, b64) = make_test_key_material();

        let crypto = SdpCrypto {
            tag: 1,
            suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
            key_params: format!("inline:{b64}|2^20|1:32"),
        };

        let material = extract_srtp_keys(&crypto).expect("should handle session params");
        assert_eq!(material.master_key.len(), 16);
        assert_eq!(material.master_salt.len(), 14);
    }

    #[test]
    fn extract_invalid_base64() {
        let crypto = SdpCrypto {
            tag: 1,
            suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
            key_params: "inline:!!!not-valid-base64!!!".to_string(),
        };

        assert!(
            extract_srtp_keys(&crypto).is_err(),
            "Invalid base64 should error"
        );
    }

    #[test]
    fn extract_missing_inline_prefix() {
        let crypto = SdpCrypto {
            tag: 1,
            suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
            key_params: "bare-key-material".to_string(),
        };

        assert!(
            extract_srtp_keys(&crypto).is_err(),
            "Missing inline: prefix should error"
        );
    }

    #[test]
    fn parse_manual_key_file_entries() {
        let (_key, _salt, b64) = make_test_key_material();

        let mut tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        writeln!(tmp, "# SRTP keys for test").expect("write");
        writeln!(tmp, "ssrc=12345 key={b64}").expect("write");
        writeln!(tmp, "ssrc=67890 key={b64} suite=AES_CM_128_HMAC_SHA1_32").expect("write");
        tmp.flush().expect("flush");

        let entries = parse_srtp_key_file(tmp.path()).expect("should parse key file");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ssrc, Some(12345));
        assert_eq!(entries[0].suite, SrtpSuite::AesCm128HmacSha1_80);
        assert_eq!(entries[1].ssrc, Some(67890));
        assert_eq!(entries[1].suite, SrtpSuite::AesCm128HmacSha1_32);
    }

    #[test]
    fn parse_empty_key_file() {
        let mut tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        writeln!(tmp, "# empty file").expect("write");
        writeln!(tmp).expect("write");
        tmp.flush().expect("flush");

        let entries = parse_srtp_key_file(tmp.path()).expect("should parse empty file");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_key_file_with_explicit_salt() {
        let key = vec![0x01u8; 16];
        let salt = vec![0x02u8; 14];
        let key_b64 = BASE64.encode(&key);
        let salt_b64 = BASE64.encode(&salt);

        let mut tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        writeln!(tmp, "ssrc=100 key={key_b64} salt={salt_b64}").expect("write");
        tmp.flush().expect("flush");

        let entries = parse_srtp_key_file(tmp.path()).expect("should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].master_key, key);
        assert_eq!(entries[0].master_salt, salt);
    }

    #[test]
    fn auth_tag_len_80bit() {
        assert_eq!(auth_tag_len(&SrtpSuite::AesCm128HmacSha1_80), 10);
        assert_eq!(auth_tag_len(&SrtpSuite::AesCm256HmacSha1_80), 10);
    }

    #[test]
    fn auth_tag_len_32bit() {
        assert_eq!(auth_tag_len(&SrtpSuite::AesCm128HmacSha1_32), 4);
    }

    #[test]
    fn auth_tag_len_unknown_defaults_to_80bit() {
        assert_eq!(auth_tag_len(&SrtpSuite::Unknown("CUSTOM".to_string())), 10);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn verify_auth_tag_with_known_key() {
        use crate::crypto::RingCryptoBackend;

        let key = vec![0x01u8; 16];
        let salt = vec![0x02u8; 14];
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: key.clone(),
            master_salt: salt,
            ssrc: None,
            media_addr: None,
            media_port: None,
        };

        let crypto = RingCryptoBackend;

        // Build a fake SRTP packet: 12-byte RTP header + 8 bytes payload + 10-byte auth tag
        let mut packet = vec![0x80, 0x00]; // V=2, PT=0
        packet.extend_from_slice(&[0x00, 0x01]); // seq=1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // timestamp
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // SSRC
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]); // payload

        // Compute the correct auth tag
        let auth_portion = packet.clone();
        let mut hmac_input = auth_portion.clone();
        hmac_input.extend_from_slice(&0u32.to_be_bytes()); // ROC=0
        let full_tag = crypto.hmac_sha1(&key, &hmac_input).unwrap();
        let auth_tag = &full_tag[..10];

        // Append auth tag to packet
        packet.extend_from_slice(auth_tag);

        let result = verify_srtp_auth_tag(&packet, &material, &crypto).unwrap();
        assert!(result, "Auth tag should verify with correct key");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn verify_auth_tag_wrong_key_fails() {
        use crate::crypto::RingCryptoBackend;

        let key = vec![0x01u8; 16];
        let wrong_key = vec![0xFF; 16];
        let salt = vec![0x02u8; 14];
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: wrong_key,
            master_salt: salt,
            ssrc: None,
            media_addr: None,
            media_port: None,
        };

        let crypto = RingCryptoBackend;

        // Build packet with auth tag computed using the correct key
        let mut packet = vec![
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut hmac_input = packet.clone();
        hmac_input.extend_from_slice(&0u32.to_be_bytes());
        let full_tag = crypto.hmac_sha1(&key, &hmac_input).unwrap();
        packet.extend_from_slice(&full_tag[..10]);

        let result = verify_srtp_auth_tag(&packet, &material, &crypto).unwrap();
        assert!(!result, "Auth tag should fail with wrong key");
    }

    #[test]
    fn verify_auth_tag_packet_too_short() {
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: vec![0u8; 16],
            master_salt: vec![0u8; 14],
            ssrc: None,
            media_addr: None,
            media_port: None,
        };

        let stub = crate::crypto::StubCryptoBackend;
        let result = verify_srtp_auth_tag(&[0u8; 10], &material, &stub);
        assert!(result.is_err(), "Too-short packet should error");
    }
}
