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
///
/// `Debug` is implemented by hand to redact the key/salt — the derived `Debug`
/// would print the raw master key and salt to any log that formats this struct.
#[derive(Clone)]
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

impl std::fmt::Debug for SrtpKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material; show only its shape.
        f.debug_struct("SrtpKeyMaterial")
            .field("tag", &self.tag)
            .field("suite", &self.suite)
            .field(
                "master_key",
                &format_args!("<{} bytes redacted>", self.master_key.len()),
            )
            .field(
                "master_salt",
                &format_args!("<{} bytes redacted>", self.master_salt.len()),
            )
            .field("ssrc", &self.ssrc)
            .field("media_addr", &self.media_addr)
            .field("media_port", &self.media_port)
            .finish()
    }
}

impl Drop for SrtpKeyMaterial {
    fn drop(&mut self) {
        // Always wipe key material on drop (previously gated behind `tls`, so
        // non-tls builds leaked keys to freed heap). Best-effort manual zeroize
        // avoids requiring the `zeroize` crate outside the `tls` feature;
        // `black_box` blocks dead-store elimination of the writes.
        for b in self.master_key.iter_mut() {
            *b = 0;
        }
        for b in self.master_salt.iter_mut() {
            *b = 0;
        }
        std::hint::black_box(self.master_key.as_ptr());
        std::hint::black_box(self.master_salt.as_ptr());
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

    let decoded = BASE64.decode(b64_part).with_context(|| {
        // Never echo the candidate key material into the error/log.
        format!(
            "Invalid base64 in SRTP key_params ({} chars)",
            b64_part.len()
        )
    })?;

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
        // Never echo the candidate key material into the error/log.
        .with_context(|| format!("Invalid base64 in key ({} chars)", key_b64.len()))?;

    let (master_key, master_salt) = if let Some(sb64) = salt_b64 {
        let salt_bytes = BASE64
            .decode(sb64)
            .with_context(|| format!("Invalid base64 in salt ({} chars)", sb64.len()))?;
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

/// RFC 3711 §4.3.3 AES-CM key-derivation PRF.
///
/// Builds the 128-bit initial counter from the master salt with `label` mixed
/// in at the `2^48` octet (per `key_id = label || r`, `r = 0` with
/// key-derivation-rate 0, `x = key_id XOR master_salt`), then runs AES in
/// counter mode keyed with the master key, taking the first `output_len` bytes.
/// This is the spec PRF, so the derived session keys match any interoperable
/// SRTP endpoint (validated against the RFC 3711 Appendix B.3 test vectors).
#[cfg(feature = "tls")]
fn aes_cm_prf(
    master_key: &[u8],
    master_salt: &[u8],
    label: u8,
    output_len: usize,
) -> Result<Vec<u8>> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    if master_salt.len() > 14 {
        anyhow::bail!(
            "SRTP master salt too long: {} bytes (max 14)",
            master_salt.len()
        );
    }

    // x = master_salt (left-aligned, padded to 14 bytes) XOR (label << 48); the
    // low 16 bits are the AES-CM block counter, starting at 0.
    let mut iv = [0u8; 16];
    iv[..master_salt.len()].copy_from_slice(master_salt);
    iv[7] ^= label; // 2^48 ⇒ octet index 7 within the 14-byte salt

    // Encrypt one counter block with the correctly-sized AES key.
    let encrypt_block = |block: &mut [u8; 16]| -> Result<()> {
        let mut b = aes::Block::from(*block);
        match master_key.len() {
            16 => aes::Aes128::new_from_slice(master_key)
                .map_err(|e| anyhow::anyhow!("AES-128 key error: {e}"))?
                .encrypt_block(&mut b),
            32 => aes::Aes256::new_from_slice(master_key)
                .map_err(|e| anyhow::anyhow!("AES-256 key error: {e}"))?
                .encrypt_block(&mut b),
            n => anyhow::bail!("SRTP master key must be 16 or 32 bytes, got {n}"),
        }
        block.copy_from_slice(b.as_slice());
        Ok(())
    };

    let mut out = Vec::with_capacity(output_len + 16);
    let mut counter: u16 = 0;
    while out.len() < output_len {
        let mut block = iv;
        block[14] = (counter >> 8) as u8;
        block[15] = (counter & 0xff) as u8;
        encrypt_block(&mut block)?;
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(output_len);
    Ok(out)
}

/// Build the 128-bit AES-CM input block for SRTP payload encryption
/// (RFC 3711 §4.1.1):
///
/// ```text
/// IV = (session_salt ‖ 0x0000) XOR (SSRC * 2^64) XOR (packet_index * 2^16)
/// ```
///
/// `session_salt` is the 112-bit (14-byte) session salt; `packet_index` is the
/// 48-bit SRTP index `ROC * 2^16 + SEQ`. The SSRC lands in octets 4..8 and the
/// index in octets 8..14, leaving octets 14..16 as the per-block counter.
#[cfg(feature = "tls")]
fn srtp_cipher_iv(session_salt: &[u8], ssrc: u32, packet_index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    let n = session_salt.len().min(14);
    iv[..n].copy_from_slice(&session_salt[..n]);

    // SSRC * 2^64 → octets 4..8.
    for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
        iv[4 + i] ^= b;
    }

    // packet_index (48 bits) * 2^16 → octets 8..14. Take the low 6 bytes of the
    // 8-byte big-endian index (octets 2..8 of the encoding).
    let idx = (packet_index & 0xFFFF_FFFF_FFFF).to_be_bytes();
    for (i, b) in idx[2..8].iter().enumerate() {
        iv[8 + i] ^= b;
    }
    iv
}

/// Generate `len` bytes of AES-CM keystream from `session_key`, starting at
/// counter block `iv` and incrementing the full 128-bit block big-endian for
/// each successive block (RFC 3711 §4.1.1). The session key is 16 or 32 bytes.
#[cfg(feature = "tls")]
fn srtp_aes_cm_keystream(session_key: &[u8], iv: [u8; 16], len: usize) -> Result<Vec<u8>> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    // Lay out successive counter blocks (iv, iv+1, iv+2, …), then encrypt each
    // in place. The block cipher is instantiated once for the whole keystream.
    let block_count = len.div_ceil(16);
    let mut out = vec![0u8; block_count * 16];
    let mut counter = iv;
    for chunk in out.chunks_mut(16) {
        chunk.copy_from_slice(&counter);
        incr_be_128(&mut counter);
    }

    let mut encrypt_all = |cipher_block: &mut dyn FnMut(&mut aes::Block)| {
        // `out` is sized to a whole number of 16-byte blocks, so every chunk is
        // exactly 16 bytes — copy into a fixed array (no fallible conversion).
        for chunk in out.chunks_mut(16) {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(chunk);
            let mut b = aes::Block::from(arr);
            cipher_block(&mut b);
            chunk.copy_from_slice(b.as_slice());
        }
    };

    match session_key.len() {
        16 => {
            let c = aes::Aes128::new_from_slice(session_key)
                .map_err(|e| anyhow::anyhow!("AES-128 key error: {e}"))?;
            encrypt_all(&mut |b| c.encrypt_block(b));
        }
        32 => {
            let c = aes::Aes256::new_from_slice(session_key)
                .map_err(|e| anyhow::anyhow!("AES-256 key error: {e}"))?;
            encrypt_all(&mut |b| c.encrypt_block(b));
        }
        n => anyhow::bail!("SRTP session key must be 16 or 32 bytes, got {n}"),
    }

    out.truncate(len);
    Ok(out)
}

/// Increment a 128-bit big-endian counter block by one (with carry).
#[cfg(feature = "tls")]
fn incr_be_128(block: &mut [u8; 16]) {
    for byte in block.iter_mut().rev() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            break;
        }
    }
}

/// Decrypt an SRTP packet's payload in place (RFC 3711 AES-CM), returning the
/// recovered RTP payload (the bytes from `payload_offset` up to the auth tag).
///
/// * `packet` — the full SRTP packet: RTP header ‖ encrypted payload ‖ auth tag.
/// * `payload_offset` — byte offset where the encrypted payload starts (from
///   [`crate::rtp::parser::parse_rtp_header`]).
/// * `key_material` — SRTP master key/salt and suite.
/// * `roc` — rollover counter for this packet's SSRC (0 for short streams; use
///   [`SrtpRocTracker`] for the authenticated ROC).
///
/// This does NOT verify the auth tag — callers should verify first via
/// [`verify_srtp_auth_tag`] / [`SrtpRocTracker::verify`] and only decrypt
/// authenticated packets.
#[cfg(feature = "tls")]
pub fn decrypt_srtp_payload(
    packet: &[u8],
    payload_offset: usize,
    key_material: &SrtpKeyMaterial,
    roc: u32,
    crypto: &dyn crate::crypto::CryptoBackend,
) -> Result<Vec<u8>> {
    let _ = crypto; // AES-CM uses the `aes` crate directly (tls feature).

    let tag_len = auth_tag_len(&key_material.suite);
    if packet.len() < payload_offset + tag_len || payload_offset < 12 {
        anyhow::bail!(
            "SRTP packet too short to decrypt: {} bytes (payload_offset={payload_offset}, tag_len={tag_len})",
            packet.len()
        );
    }

    let seq = u16::from_be_bytes([packet[2], packet[3]]);
    let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let packet_index = ((roc as u64) << 16) | seq as u64;

    // Session cipher key (label 0x00) and session salt (label 0x02), RFC 3711
    // §4.3.1. The cipher key matches the master key length (16 or 32 bytes).
    let session_key = aes_cm_prf(
        &key_material.master_key,
        &key_material.master_salt,
        0x00,
        key_material.master_key.len(),
    )?;
    let session_salt = aes_cm_prf(
        &key_material.master_key,
        &key_material.master_salt,
        0x02,
        14,
    )?;

    let ciphertext = &packet[payload_offset..packet.len() - tag_len];
    let iv = srtp_cipher_iv(&session_salt, ssrc, packet_index);
    let keystream = srtp_aes_cm_keystream(&session_key, iv, ciphertext.len())?;

    let plaintext: Vec<u8> = ciphertext
        .iter()
        .zip(&keystream)
        .map(|(c, k)| c ^ k)
        .collect();
    Ok(plaintext)
}

/// Derive an SRTP session key (RFC 3711 §4.3.1).
///
/// With the `tls` feature this is the spec AES-CM PRF ([`aes_cm_prf`]), so the
/// result interoperates with real SRTP endpoints. Without `tls` there is no AES
/// primitive available, so it falls back to an HMAC-SHA1 key-separation step
/// (non-interoperable — but the verifier needs a real crypto backend anyway).
///
/// * `label` — 0x00 cipher, 0x01 auth, 0x02 salt (SRTP); 0x03/0x04/0x05 SRTCP.
/// * `output_len` — desired key length in bytes (e.g. 20 for the auth key).
fn derive_session_key(
    master_key: &[u8],
    master_salt: &[u8],
    label: u8,
    output_len: usize,
    crypto: &dyn crate::crypto::CryptoBackend,
) -> Result<Vec<u8>> {
    #[cfg(feature = "tls")]
    {
        let _ = crypto;
        aes_cm_prf(master_key, master_salt, label, output_len)
    }
    #[cfg(not(feature = "tls"))]
    {
        let mut kdf_input = Vec::with_capacity(1 + master_salt.len());
        kdf_input.push(label);
        kdf_input.extend_from_slice(master_salt);
        let derived = crypto.hmac_sha1(master_key, &kdf_input)?;
        if output_len > derived.len() {
            anyhow::bail!(
                "Requested KDF output length ({output_len}) exceeds HMAC-SHA1 output ({})",
                derived.len()
            );
        }
        Ok(derived[..output_len].to_vec())
    }
}

/// SRTP KDF label for the session authentication key (RFC 3711 Section 4.3.1).
const SRTP_LABEL_AUTH: u8 = 0x01;
/// Session auth key length: 160 bits (20 bytes) per RFC 3711.
const SRTP_AUTH_KEY_LEN: usize = 20;

/// Verify the SRTP authentication tag on an SRTP packet.
///
/// The SRTP packet format is: `[RTP header + encrypted payload] [auth tag]`.
/// The authentication tag is HMAC-SHA1 over the authenticated portion
/// (everything before the tag) with the 32-bit ROC (rollover counter) appended.
/// Being stateless, this verifier tries the first two ROC epochs (~131072
/// packets); longer sessions need stateful per-SSRC ROC tracking.
///
/// The session authentication key is derived from the master key and salt via
/// the RFC 3711 §4.3.1 AES-CM KDF ([`derive_session_key`], label 0x01), so it
/// interoperates with standard SRTP endpoints when built with the `tls`
/// feature.
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

    // Derive the session authentication key from master key + salt via KDF.
    // RFC 3711 Section 4.3.1: label=0x01 for auth, 160-bit (20-byte) output.
    let session_auth_key = derive_session_key(
        &key_material.master_key,
        &key_material.master_salt,
        SRTP_LABEL_AUTH,
        SRTP_AUTH_KEY_LEN,
        crypto,
    )?;

    // RFC 3711 §4.1: the auth tag is HMAC-SHA1 over (authenticated portion ||
    // ROC). This verifier is stateless and cannot know the true rollover count,
    // so it tries the first two ROC epochs — covering the first ~131072 packets
    // of a session (the 16-bit RTP sequence number wraps every 65536). For long
    // streams use [`SrtpRocTracker`], which tracks ROC per SSRC. Trying two ROCs
    // only doubles the (already negligible, 2^-tagbits) forgery chance.
    for roc in 0u32..=1 {
        if srtp_tag_matches(
            auth_portion,
            received_tag,
            &session_auth_key,
            roc,
            tag_len,
            crypto,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Compute the SRTP auth tag over `auth_portion || roc` and constant-time
/// compare it to `received_tag`.
fn srtp_tag_matches(
    auth_portion: &[u8],
    received_tag: &[u8],
    session_auth_key: &[u8],
    roc: u32,
    tag_len: usize,
    crypto: &dyn crate::crypto::CryptoBackend,
) -> Result<bool> {
    let mut hmac_input = auth_portion.to_vec();
    hmac_input.extend_from_slice(&roc.to_be_bytes());
    let full_tag = crypto.hmac_sha1(session_auth_key, &hmac_input)?;
    let computed_tag = &full_tag[..tag_len.min(full_tag.len())];
    // Constant-time comparison: a MAC verifier must not leak, via timing, how
    // many leading bytes of a forged tag matched.
    Ok(crate::crypto::constant_time_eq(computed_tag, received_tag))
}

/// Per-SSRC rollover-counter (ROC) state for stateful SRTP auth verification.
#[derive(Clone, Copy, Debug)]
struct RocState {
    /// Rollover counter for this SSRC.
    roc: u32,
    /// Highest sequence number seen (`s_l` in RFC 3711).
    s_l: u16,
}

/// Estimate the ROC for an incoming sequence number (RFC 3711 §3.3.1), given
/// the locally maintained `roc` and highest-seen sequence `s_l`.
fn estimate_roc(roc: u32, s_l: u16, seq: u16) -> u32 {
    let seq = seq as i32;
    let s_l = s_l as i32;
    const HALF: i32 = 1 << 15; // 2^15
    if s_l < HALF {
        if seq - s_l > HALF {
            roc.wrapping_sub(1) // an old packet from the previous epoch
        } else {
            roc
        }
    } else if s_l - HALF > seq {
        roc.wrapping_add(1) // sequence wrapped into the next epoch
    } else {
        roc
    }
}

/// Stateful SRTP authentication-tag verifier that tracks the rollover counter
/// per SSRC, so streams longer than 65536 packets verify correctly.
///
/// The ROC for each packet is estimated from the stored highest sequence number
/// (RFC 3711 §3.3.1) and advanced when the sequence number wraps. The first
/// packet seen for an SSRC is assumed to start at ROC 0 (joining a stream
/// mid-session with a non-zero ROC cannot be detected from the wire and will
/// not verify — an inherent limitation of passive analysis).
#[derive(Debug, Default)]
pub struct SrtpRocTracker {
    per_ssrc: std::collections::HashMap<u32, RocState>,
}

impl SrtpRocTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a packet's auth tag, estimating and advancing the ROC for the
    /// packet's SSRC. Returns `Ok(true)` on a valid tag, `Ok(false)` on a
    /// mismatch (state is left unchanged on mismatch), or `Err` on a crypto
    /// failure or a packet too short to contain header + tag.
    pub fn verify(
        &mut self,
        packet: &[u8],
        key_material: &SrtpKeyMaterial,
        crypto: &dyn crate::crypto::CryptoBackend,
    ) -> Result<bool> {
        Ok(self.verify_roc(packet, key_material, crypto)?.is_some())
    }

    /// Like [`verify`](Self::verify), but on success returns `Some(roc)` — the
    /// rollover counter that authenticated the packet — so the caller can
    /// decrypt the payload with the matching SRTP index. Returns `Ok(None)` on
    /// a tag mismatch (state untouched).
    pub fn verify_roc(
        &mut self,
        packet: &[u8],
        key_material: &SrtpKeyMaterial,
        crypto: &dyn crate::crypto::CryptoBackend,
    ) -> Result<Option<u32>> {
        let tag_len = auth_tag_len(&key_material.suite);
        if packet.len() < 12 + tag_len {
            anyhow::bail!(
                "SRTP packet too short for auth tag verification: {} bytes",
                packet.len()
            );
        }
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        let auth_portion_len = packet.len() - tag_len;
        let auth_portion = &packet[..auth_portion_len];
        let received_tag = &packet[auth_portion_len..];

        let session_auth_key = derive_session_key(
            &key_material.master_key,
            &key_material.master_salt,
            SRTP_LABEL_AUTH,
            SRTP_AUTH_KEY_LEN,
            crypto,
        )?;

        // First packet for this SSRC starts at ROC 0; otherwise estimate.
        let existing = self.per_ssrc.get(&ssrc).copied();
        let roc = match existing {
            Some(st) => estimate_roc(st.roc, st.s_l, seq),
            None => 0,
        };

        if !srtp_tag_matches(
            auth_portion,
            received_tag,
            &session_auth_key,
            roc,
            tag_len,
            crypto,
        )? {
            return Ok(None); // leave state untouched on a failed/forged tag
        }

        // Authenticated: advance ROC / highest-seq for this SSRC.
        let new = match existing {
            None => RocState { roc: 0, s_l: seq },
            Some(prev) => {
                // Advance when the packet wrapped into the next epoch, or is the
                // newest seen in the current one; otherwise it is an older /
                // replayed in-window packet and state is kept.
                let advanced =
                    roc == prev.roc.wrapping_add(1) || (roc == prev.roc && seq > prev.s_l);
                if advanced {
                    RocState { roc, s_l: seq }
                } else {
                    prev
                }
            }
        };
        self.per_ssrc.insert(ssrc, new);
        Ok(Some(roc))
    }
}

/// A keyed SRTP decryption context: holds candidate master keys (from
/// `--srtp-keys` and/or SDES `a=crypto` lines), the per-SSRC rollover-counter
/// tracker, and a crypto backend. For each RTP packet it finds the key whose
/// auth tag verifies, then decrypts the payload (RFC 3711 AES-CM).
///
/// Authentication is the gate: a packet is only decrypted if a candidate key's
/// HMAC-SHA1 tag verifies, so a wrong or unrelated key never yields plaintext.
pub struct SrtpContext {
    keys: Vec<SrtpKeyMaterial>,
    tracker: SrtpRocTracker,
    crypto: Box<dyn crate::crypto::CryptoBackend>,
    /// Number of packets successfully authenticated and decrypted.
    pub decrypted_count: u64,
}

impl SrtpContext {
    /// Create a context from pre-extracted key material.
    pub fn new(keys: Vec<SrtpKeyMaterial>, crypto: Box<dyn crate::crypto::CryptoBackend>) -> Self {
        Self {
            keys,
            tracker: SrtpRocTracker::new(),
            crypto,
            decrypted_count: 0,
        }
    }

    /// Load key material from a manual `--srtp-keys` file.
    pub fn from_key_file(
        path: &Path,
        crypto: Box<dyn crate::crypto::CryptoBackend>,
    ) -> Result<Self> {
        Ok(Self::new(parse_srtp_key_file(path)?, crypto))
    }

    /// Whether the context has no keys (nothing to try).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Append already-extracted key material (e.g. from DTLS-SRTP). Returns the
    /// number of keys added.
    pub fn add_keys(&mut self, keys: Vec<SrtpKeyMaterial>) -> usize {
        let n = keys.len();
        self.keys.extend(keys);
        n
    }

    /// Number of candidate keys held.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Ingest SDES `a=crypto` key material from an SDP media section, tagging it
    /// with the media address/port for provenance. Malformed/unsupported crypto
    /// lines are skipped. Returns the number of keys added.
    pub fn add_sdes(
        &mut self,
        media_addr: Option<String>,
        media_port: Option<u16>,
        cryptos: &[SdpCrypto],
    ) -> usize {
        let before = self.keys.len();
        for c in cryptos {
            if let Ok(mut km) = extract_srtp_keys(c) {
                km.media_addr = media_addr.clone();
                km.media_port = media_port;
                self.keys.push(km);
            }
        }
        self.keys.len() - before
    }

    /// Try to decrypt one SRTP packet. Returns `Some(plaintext_packet)` — the
    /// RTP header followed by the decrypted payload (auth tag stripped) — when a
    /// candidate key authenticates the packet, or `None` if none do.
    ///
    /// `payload_offset` is the RTP payload start from
    /// [`crate::rtp::parser::parse_rtp_header`].
    pub fn decrypt(&mut self, packet: &[u8], payload_offset: usize) -> Option<Vec<u8>> {
        if self.keys.is_empty() || packet.len() < 12 || payload_offset < 12 {
            return None;
        }
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        // Prefer keys pinned to this SSRC, then unpinned (file/SDES) keys.
        let order: Vec<usize> = (0..self.keys.len())
            .filter(|&i| self.keys[i].ssrc == Some(ssrc))
            .chain((0..self.keys.len()).filter(|&i| self.keys[i].ssrc.is_none()))
            .collect();

        for i in order {
            // Clone the (small) key material so the tracker can borrow &mut self
            // fields without aliasing the key slice.
            let key = self.keys[i].clone();
            match self.tracker.verify_roc(packet, &key, &*self.crypto) {
                Ok(Some(roc)) => {
                    match decrypt_srtp_payload(packet, payload_offset, &key, roc, &*self.crypto) {
                        Ok(plaintext) => {
                            let mut out = packet[..payload_offset].to_vec();
                            out.extend_from_slice(&plaintext);
                            self.decrypted_count += 1;
                            return Some(out);
                        }
                        Err(e) => {
                            tracing::debug!("SRTP authenticated but decrypt failed: {e}");
                            return None;
                        }
                    }
                }
                Ok(None) => continue, // tag mismatch — try the next key
                Err(_) => continue,   // too short / crypto error for this suite
            }
        }
        None
    }
}

/// Test-only helpers shared across the crate's test modules (e.g. DTLS-SRTP).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::crypto::{CryptoBackend, RingCryptoBackend};

    /// Build a fully valid SRTP packet (AES-CM-encrypted payload + correct
    /// 80-bit HMAC-SHA1 auth tag) for the given master key/salt and identifiers.
    pub fn build_srtp_packet(
        master_key: &[u8],
        master_salt: &[u8],
        ssrc: u32,
        seq: u16,
        roc: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let crypto = RingCryptoBackend;

        let mut header = vec![0x80, 0x00];
        header.extend_from_slice(&seq.to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // timestamp
        header.extend_from_slice(&ssrc.to_be_bytes());

        let session_key = aes_cm_prf(master_key, master_salt, 0x00, master_key.len()).unwrap();
        let session_salt = aes_cm_prf(master_key, master_salt, 0x02, 14).unwrap();
        let index = ((roc as u64) << 16) | seq as u64;
        let iv = srtp_cipher_iv(&session_salt, ssrc, index);
        let ks = srtp_aes_cm_keystream(&session_key, iv, plaintext.len()).unwrap();
        let ciphertext: Vec<u8> = plaintext.iter().zip(&ks).map(|(p, k)| p ^ k).collect();

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let auth_key = derive_session_key(
            master_key,
            master_salt,
            SRTP_LABEL_AUTH,
            SRTP_AUTH_KEY_LEN,
            &crypto,
        )
        .unwrap();
        let mut hmac_input = packet.clone();
        hmac_input.extend_from_slice(&roc.to_be_bytes());
        let tag = crypto.hmac_sha1(&auth_key, &hmac_input).unwrap();
        packet.extend_from_slice(&tag[..10]); // 80-bit tag
        packet
    }
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
    fn invalid_base64_errors_do_not_leak_key_material() {
        // SDP a=crypto path.
        let crypto = SdpCrypto {
            tag: 1,
            suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
            key_params: "inline:SUPERSECRETKEYMATERIAL_not_base64_@@@".to_string(),
        };
        let msg = format!("{:#}", extract_srtp_keys(&crypto).unwrap_err());
        assert!(
            !msg.contains("SUPERSECRET"),
            "key material must not appear in error: {msg}"
        );
        assert!(msg.contains("chars"), "error should report length: {msg}");

        // Manual key-file path (key= and salt=).
        let msg = format!(
            "{:#}",
            parse_srtp_key_line("ssrc=1 key=BADKEYSECRET_@@@").unwrap_err()
        );
        assert!(
            !msg.contains("BADKEYSECRET"),
            "key material must not appear in error: {msg}"
        );

        let msg = format!(
            "{:#}",
            parse_srtp_key_line("ssrc=1 key=AAAA salt=BADSALTSECRET_@@@").unwrap_err()
        );
        assert!(
            !msg.contains("BADSALTSECRET"),
            "salt material must not appear in error: {msg}"
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

    #[test]
    fn debug_redacts_key_material() {
        let m = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: vec![0xAB; 16], // 0xAB == 171 decimal in Vec<u8> Debug
            master_salt: vec![0xCD; 14], // 0xCD == 205
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        let s = format!("{m:?}");
        assert!(
            s.contains("redacted"),
            "Debug must mark key material redacted"
        );
        assert!(
            !s.contains("171"),
            "master key bytes must not appear in Debug"
        );
        assert!(
            !s.contains("205"),
            "master salt bytes must not appear in Debug"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn aes_cm_prf_matches_rfc3711_b3_vectors() {
        // RFC 3711 Appendix B.3 known-answer test for the AES-CM KDF. Matching
        // these proves the derivation interoperates with standard SRTP.
        let master_key = [
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE,
            0x41, 0x39,
        ];
        let master_salt = [
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];
        // label 0x00 → session cipher key (128 bits)
        assert_eq!(
            aes_cm_prf(&master_key, &master_salt, 0x00, 16).unwrap(),
            vec![
                0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, 0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7,
                0xA0, 0x87
            ]
        );
        // label 0x02 → session salt key (112 bits)
        assert_eq!(
            aes_cm_prf(&master_key, &master_salt, 0x02, 14).unwrap(),
            vec![
                0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, 0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1
            ]
        );
        // label 0x01 → session auth key (160 bits)
        assert_eq!(
            aes_cm_prf(&master_key, &master_salt, 0x01, 20).unwrap(),
            vec![
                0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25,
                0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4
            ]
        );
    }

    // ── SRTP AES-CM payload cipher (RFC 3711 §4.1) ─────────────────────

    /// RFC 3711 Appendix B.2 session salt (112-bit) for the AES-CM KAT.
    #[cfg(feature = "tls")]
    const B2_SESSION_SALT: [u8; 14] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
    ];

    #[cfg(feature = "tls")]
    #[test]
    fn srtp_cipher_iv_rfc3711_b2_and_xor_placement() {
        // B.2: SSRC=0, index=0 ⇒ IV = salt ‖ 0x0000.
        let iv = srtp_cipher_iv(&B2_SESSION_SALT, 0, 0);
        let mut expected = [0u8; 16];
        expected[..14].copy_from_slice(&B2_SESSION_SALT);
        assert_eq!(iv, expected, "B.2 IV must be the salt padded with 0x0000");

        // SSRC lands in octets 4..8, the 48-bit index in octets 8..14.
        let ssrc = 0xCAFE_BABEu32;
        let roc = 1u32;
        let seq = 0x0002u16;
        let index = ((roc as u64) << 16) | seq as u64; // 0x0001_0002
        let iv = srtp_cipher_iv(&B2_SESSION_SALT, ssrc, index);
        let mut want = [0u8; 16];
        want[..14].copy_from_slice(&B2_SESSION_SALT);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            want[4 + i] ^= b;
        }
        // index low 6 bytes: 00 00 00 01 00 02
        for (i, b) in [0x00u8, 0x00, 0x00, 0x01, 0x00, 0x02].iter().enumerate() {
            want[8 + i] ^= b;
        }
        assert_eq!(iv, want, "SSRC/index must XOR into octets 4..8 / 8..14");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn srtp_aes_cm_keystream_matches_rfc3711_b2() {
        // RFC 3711 Appendix B.2 known-answer test for AES-128 Counter Mode.
        // Session key 2B7E1516…CF4F3C with the B.2 IV must produce this
        // keystream prefix — proving the IV layout and counter increment.
        let session_key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let iv = srtp_cipher_iv(&B2_SESSION_SALT, 0, 0);
        let ks = srtp_aes_cm_keystream(&session_key, iv, 32).unwrap();
        let expected: [u8; 32] = [
            0xE0, 0x3E, 0xAD, 0x09, 0x35, 0xC9, 0x5E, 0x80, 0xE1, 0x66, 0xB1, 0x6D, 0xD9, 0x2B,
            0x4E, 0xB4, 0xD2, 0x35, 0x13, 0x16, 0x2B, 0x02, 0xD0, 0xF7, 0x2A, 0x43, 0xA2, 0xFE,
            0x4A, 0x5F, 0x97, 0xAB,
        ];
        assert_eq!(ks, expected, "AES-CM keystream must match RFC 3711 B.2");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn decrypt_srtp_payload_roundtrip_recovers_plaintext() {
        use crate::crypto::RingCryptoBackend;

        let crypto = RingCryptoBackend;
        let master_key = vec![0x11u8; 16];
        let master_salt = vec![0x22u8; 14];
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: master_key.clone(),
            master_salt: master_salt.clone(),
            ssrc: None,
            media_addr: None,
            media_port: None,
        };

        // RTP header (12 bytes): V=2, PT=0, seq=0x0007, ts, ssrc=0x1234_5678.
        let ssrc = 0x1234_5678u32;
        let seq = 0x0007u16;
        let roc = 0u32;
        let mut header = vec![0x80, 0x00];
        header.extend_from_slice(&seq.to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // timestamp
        header.extend_from_slice(&ssrc.to_be_bytes());

        let plaintext = b"the quick brown fox jumps over the lazy SRTP payload".to_vec();

        // Encrypt the payload with the same session cipher key/salt the
        // decryptor will derive, then append a 10-byte dummy auth tag.
        let session_key = aes_cm_prf(&master_key, &master_salt, 0x00, 16).unwrap();
        let session_salt = aes_cm_prf(&master_key, &master_salt, 0x02, 14).unwrap();
        let index = ((roc as u64) << 16) | seq as u64;
        let iv = srtp_cipher_iv(&session_salt, ssrc, index);
        let ks = srtp_aes_cm_keystream(&session_key, iv, plaintext.len()).unwrap();
        let ciphertext: Vec<u8> = plaintext.iter().zip(&ks).map(|(p, k)| p ^ k).collect();

        let mut packet = header.clone();
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&[0u8; 10]); // dummy auth tag (10-byte / 80-bit)

        let recovered =
            decrypt_srtp_payload(&packet, header.len(), &material, roc, &crypto).unwrap();
        assert_eq!(
            recovered, plaintext,
            "AES-CM decrypt must recover plaintext"
        );
    }

    /// Build a fully valid SRTP packet — delegates to the shared test helper.
    #[cfg(feature = "tls")]
    fn build_valid_srtp_packet(
        master_key: &[u8],
        master_salt: &[u8],
        ssrc: u32,
        seq: u16,
        roc: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        super::test_support::build_srtp_packet(master_key, master_salt, ssrc, seq, roc, plaintext)
    }

    #[cfg(feature = "tls")]
    #[test]
    fn srtp_context_authenticates_and_decrypts() {
        use crate::crypto::RingCryptoBackend;
        let mk = vec![0x33u8; 16];
        let ms = vec![0x44u8; 14];
        let ssrc = 0xDEAD_BEEFu32;
        let plaintext = b"\x00\x01\x02\x03 decrypted media frame payload".to_vec();
        let packet = build_valid_srtp_packet(&mk, &ms, ssrc, 42, 0, &plaintext);

        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: mk,
            master_salt: ms,
            ssrc: None, // unpinned (as from --srtp-keys without ssrc=)
            media_addr: None,
            media_port: None,
        };
        let mut ctx = SrtpContext::new(vec![material], Box::new(RingCryptoBackend));
        let out = ctx
            .decrypt(&packet, 12)
            .expect("authenticated packet decrypts");
        assert_eq!(&out[..12], &packet[..12], "RTP header preserved");
        assert_eq!(
            &out[12..],
            &plaintext[..],
            "payload decrypted, tag stripped"
        );
        assert_eq!(ctx.decrypted_count, 1);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn srtp_context_rejects_wrong_key() {
        use crate::crypto::RingCryptoBackend;
        let packet =
            build_valid_srtp_packet(&[0x33u8; 16], &[0x44u8; 14], 0xCAFE, 7, 0, b"payload");
        // Context holds an unrelated key: auth tag must not verify ⇒ no plaintext.
        let wrong = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: vec![0xFFu8; 16],
            master_salt: vec![0xEEu8; 14],
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        let mut ctx = SrtpContext::new(vec![wrong], Box::new(RingCryptoBackend));
        assert!(ctx.decrypt(&packet, 12).is_none());
        assert_eq!(ctx.decrypted_count, 0);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn srtp_context_add_sdes_then_decrypts() {
        use crate::crypto::RingCryptoBackend;
        // SDES inline key||salt for AES_CM_128_HMAC_SHA1_80.
        let mk = vec![0x01u8; 16];
        let ms = vec![0x02u8; 14];
        let mut combined = mk.clone();
        combined.extend_from_slice(&ms);
        let b64 = BASE64.encode(&combined);
        let sdp_crypto = SdpCrypto {
            tag: 1,
            suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
            key_params: format!("inline:{b64}"),
        };

        let mut ctx = SrtpContext::new(Vec::new(), Box::new(RingCryptoBackend));
        assert!(ctx.is_empty());
        let added = ctx.add_sdes(Some("10.0.0.5".into()), Some(40000), &[sdp_crypto]);
        assert_eq!(added, 1);
        assert_eq!(ctx.key_count(), 1);

        let packet = build_valid_srtp_packet(&mk, &ms, 0x1111_2222, 100, 0, b"hello srtp");
        let out = ctx.decrypt(&packet, 12).expect("SDES key decrypts");
        assert_eq!(&out[12..], b"hello srtp");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn verify_roc_returns_authenticating_roc() {
        use crate::crypto::RingCryptoBackend;
        let mk = vec![0x33u8; 16];
        let ms = vec![0x44u8; 14];
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: mk.clone(),
            master_salt: ms.clone(),
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        let crypto = RingCryptoBackend;
        let mut tr = SrtpRocTracker::new();
        // First packet for the SSRC authenticates at ROC 0.
        let p0 = build_valid_srtp_packet(&mk, &ms, 0xABCD, 65000, 0, b"a");
        assert_eq!(tr.verify_roc(&p0, &material, &crypto).unwrap(), Some(0));
        // After a sequence wrap, it authenticates at ROC 1.
        let p1 = build_valid_srtp_packet(&mk, &ms, 0xABCD, 5, 1, b"b");
        assert_eq!(tr.verify_roc(&p1, &material, &crypto).unwrap(), Some(1));
        // A forged tag yields None (state untouched).
        let mut bad = p1.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        assert_eq!(tr.verify_roc(&bad, &material, &crypto).unwrap(), None);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn decrypt_srtp_payload_rejects_short_packet() {
        use crate::crypto::RingCryptoBackend;
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80, // tag_len = 10
            master_key: vec![0u8; 16],
            master_salt: vec![0u8; 14],
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        // 12-byte header + 10-byte tag region = 22; a 20-byte packet leaves no
        // room for header+tag and must error rather than panic-slice.
        let packet = vec![0x80u8; 20];
        assert!(decrypt_srtp_payload(&packet, 12, &material, 0, &RingCryptoBackend).is_err());
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
            master_salt: salt.clone(),
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

        // Derive the session auth key the same way verify_srtp_auth_tag does
        let session_auth_key =
            derive_session_key(&key, &salt, SRTP_LABEL_AUTH, SRTP_AUTH_KEY_LEN, &crypto).unwrap();

        // Compute the correct auth tag using the derived session auth key
        let auth_portion = packet.clone();
        let mut hmac_input = auth_portion.clone();
        hmac_input.extend_from_slice(&0u32.to_be_bytes()); // ROC=0
        let full_tag = crypto.hmac_sha1(&session_auth_key, &hmac_input).unwrap();
        let auth_tag = &full_tag[..10];

        // Append auth tag to packet
        packet.extend_from_slice(auth_tag);

        let result = verify_srtp_auth_tag(&packet, &material, &crypto).unwrap();
        assert!(result, "Auth tag should verify with correct key");

        // Tamper a single tag byte: the (constant-time) comparison must still
        // reject it. Flipping the last byte exercises the full-length compare
        // path rather than an early mismatch.
        let mut tampered = packet.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let bad = verify_srtp_auth_tag(&tampered, &material, &crypto).unwrap();
        assert!(!bad, "a tampered auth tag must not verify");
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
            master_salt: salt.clone(),
            ssrc: None,
            media_addr: None,
            media_port: None,
        };

        let crypto = RingCryptoBackend;

        // Build packet with auth tag computed using the correct key's derived session auth key
        let mut packet = vec![
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let session_auth_key =
            derive_session_key(&key, &salt, SRTP_LABEL_AUTH, SRTP_AUTH_KEY_LEN, &crypto).unwrap();
        let mut hmac_input = packet.clone();
        hmac_input.extend_from_slice(&0u32.to_be_bytes());
        let full_tag = crypto.hmac_sha1(&session_auth_key, &hmac_input).unwrap();
        packet.extend_from_slice(&full_tag[..10]);

        let result = verify_srtp_auth_tag(&packet, &material, &crypto).unwrap();
        assert!(!result, "Auth tag should fail with wrong key");
    }

    #[test]
    fn estimate_roc_handles_wrap_and_reorder() {
        // No state advance yet: within the first epoch, ROC stays 0.
        assert_eq!(estimate_roc(0, 100, 200), 0);
        // Sequence wrapped (high s_l, low seq) ⇒ next epoch.
        assert_eq!(estimate_roc(0, 65000, 200), 1);
        // Old packet arriving after a wrap (low s_l, high seq) ⇒ previous epoch.
        assert_eq!(estimate_roc(1, 100, 65000), 0);
        // Normal advance in a high epoch, no wrap.
        assert_eq!(estimate_roc(5, 40000, 41000), 5);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn roc_tracker_follows_sequence_rollover() {
        use crate::crypto::RingCryptoBackend;

        let key = vec![0x01u8; 16];
        let salt = vec![0x02u8; 14];
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: key.clone(),
            master_salt: salt.clone(),
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        let crypto = RingCryptoBackend;
        let session_auth_key =
            derive_session_key(&key, &salt, SRTP_LABEL_AUTH, SRTP_AUTH_KEY_LEN, &crypto).unwrap();

        // Build an SRTP packet with a valid 80-bit tag for the given seq/ROC.
        let build = |seq: u16, ssrc: u32, roc: u32| -> Vec<u8> {
            let mut p = vec![0x80, 0x00];
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // timestamp
            p.extend_from_slice(&ssrc.to_be_bytes());
            p.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // payload
            let mut hmac_input = p.clone();
            hmac_input.extend_from_slice(&roc.to_be_bytes());
            let full = crypto.hmac_sha1(&session_auth_key, &hmac_input).unwrap();
            p.extend_from_slice(&full[..10]);
            p
        };

        let mut tr = SrtpRocTracker::new();
        let ssrc = 0x1234_5678;
        // First packet near the top of epoch 0.
        assert!(
            tr.verify(&build(65000, ssrc, 0), &material, &crypto)
                .unwrap()
        );
        // Sequence wraps → tracker must advance to ROC 1 and still verify.
        assert!(tr.verify(&build(200, ssrc, 1), &material, &crypto).unwrap());
        // Continue in epoch 1.
        assert!(tr.verify(&build(300, ssrc, 1), &material, &crypto).unwrap());
        // A tag computed with the wrong (stale) ROC must be rejected.
        assert!(!tr.verify(&build(400, ssrc, 0), &material, &crypto).unwrap());
        // A tampered tag must be rejected.
        let mut bad = build(500, ssrc, 1);
        *bad.last_mut().unwrap() ^= 0xFF;
        assert!(!tr.verify(&bad, &material, &crypto).unwrap());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn derive_session_key_produces_different_keys_per_label() {
        use crate::crypto::RingCryptoBackend;

        let crypto = RingCryptoBackend;
        let master_key = vec![0xAA; 16];
        let master_salt = vec![0xBB; 14];

        let cipher_key = derive_session_key(&master_key, &master_salt, 0x00, 16, &crypto).unwrap();
        let auth_key =
            derive_session_key(&master_key, &master_salt, SRTP_LABEL_AUTH, 20, &crypto).unwrap();
        let salt_key = derive_session_key(&master_key, &master_salt, 0x02, 14, &crypto).unwrap();

        // Each label must produce a different key
        assert_ne!(
            cipher_key,
            auth_key[..16],
            "cipher and auth keys must differ"
        );
        assert_ne!(
            cipher_key,
            salt_key[..14],
            "cipher and salt keys must differ"
        );
        assert_ne!(
            &auth_key[..14],
            salt_key.as_slice(),
            "auth and salt keys must differ"
        );
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

    #[cfg(feature = "tls")]
    #[test]
    fn derive_session_key_not_equal_to_master_key() {
        use crate::crypto::RingCryptoBackend;

        let crypto = RingCryptoBackend;
        let master_key = vec![0xAA; 16];
        let master_salt = vec![0xBB; 14];

        // Derive auth key (label 0x01) and verify it differs from the master key
        let auth_key =
            derive_session_key(&master_key, &master_salt, SRTP_LABEL_AUTH, 20, &crypto).unwrap();

        assert_ne!(
            &auth_key[..16],
            master_key.as_slice(),
            "Derived session auth key must differ from master key"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn derive_different_labels_produce_different_keys() {
        use crate::crypto::RingCryptoBackend;

        let crypto = RingCryptoBackend;
        let master_key = vec![0xCC; 16];
        let master_salt = vec![0xDD; 14];

        let cipher_key = derive_session_key(&master_key, &master_salt, 0x00, 20, &crypto).unwrap();
        let auth_key = derive_session_key(&master_key, &master_salt, 0x01, 20, &crypto).unwrap();
        let salt_key = derive_session_key(&master_key, &master_salt, 0x02, 20, &crypto).unwrap();

        assert_ne!(
            cipher_key, auth_key,
            "label 0x00 and 0x01 must produce different keys"
        );
        assert_ne!(
            cipher_key, salt_key,
            "label 0x00 and 0x02 must produce different keys"
        );
        assert_ne!(
            auth_key, salt_key,
            "label 0x01 and 0x02 must produce different keys"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn verify_auth_tag_with_derived_key() {
        use crate::crypto::{CryptoBackend, RingCryptoBackend};

        let crypto = RingCryptoBackend;
        let key = vec![0x55u8; 16];
        let salt = vec![0x66u8; 14];
        let material = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: key.clone(),
            master_salt: salt.clone(),
            ssrc: None,
            media_addr: None,
            media_port: None,
        };

        // Build a minimal RTP packet: 12-byte header + 4-byte payload
        let mut packet = vec![0x80, 0x00]; // V=2, PT=0
        packet.extend_from_slice(&[0x00, 0x42]); // seq=66
        packet.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // timestamp
        packet.extend_from_slice(&[0x00, 0x00, 0xAB, 0xCD]); // SSRC
        packet.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]); // payload

        // Derive the session auth key and compute the correct tag
        let session_auth_key =
            derive_session_key(&key, &salt, SRTP_LABEL_AUTH, SRTP_AUTH_KEY_LEN, &crypto).unwrap();

        let mut hmac_input = packet.clone();
        hmac_input.extend_from_slice(&0u32.to_be_bytes()); // ROC=0
        let full_tag = crypto.hmac_sha1(&session_auth_key, &hmac_input).unwrap();
        let auth_tag = &full_tag[..10]; // 80-bit tag

        // Append auth tag to make a complete SRTP packet
        packet.extend_from_slice(auth_tag);

        let result = verify_srtp_auth_tag(&packet, &material, &crypto).unwrap();
        assert!(
            result,
            "Auth tag computed with derived session key should verify"
        );
    }
}
