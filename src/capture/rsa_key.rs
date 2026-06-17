//! RSA private-key loading for TLS 1.2 RSA-key-exchange decryption.
//!
//! Loads a PEM-encoded RSA private key (PKCS#1 `RSA PRIVATE KEY` or PKCS#8
//! `PRIVATE KEY`) supplied via `--tls-key` and decrypts the RSA-encrypted
//! pre-master secret from a TLS 1.2 `ClientKeyExchange` (PKCS#1 v1.5).
//!
//! This only helps non-PFS RSA key-exchange handshakes (no ECDHE/DHE); modern
//! suites with forward secrecy cannot be decrypted from the private key alone
//! and require an `SSLKEYLOGFILE` instead.

use anyhow::{Context, Result};
use std::path::Path;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

/// A loaded RSA private key used to recover the TLS pre-master secret.
pub struct RsaKey {
    key: RsaPrivateKey,
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key internals.
        f.write_str("RsaKey(<redacted>)")
    }
}

impl RsaKey {
    /// Load an RSA private key from a PEM string, accepting either PKCS#1
    /// (`-----BEGIN RSA PRIVATE KEY-----`) or PKCS#8
    /// (`-----BEGIN PRIVATE KEY-----`) encodings.
    pub fn from_pem(pem: &str) -> Result<Self> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;

        // Try PKCS#8 first, then PKCS#1. Error messages never echo key bytes.
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .context("failed to parse RSA private key (expected PKCS#1 or PKCS#8 PEM)")?;
        Ok(Self { key })
    }

    /// Load an RSA private key from a PEM file at `path`.
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("reading TLS private key from {}", path.display()))?;
        Self::from_pem(&pem)
    }

    /// Decrypt a PKCS#1 v1.5-encrypted TLS pre-master secret (the
    /// `ClientKeyExchange.encrypted_pre_master_secret`). Returns the 48-byte
    /// pre-master on success.
    pub fn decrypt_premaster(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // PKCS#1 v1.5 decryption. A wrong key / malformed block yields an error
        // (never key material), so callers can fall through to other secrets.
        self.key
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .context("RSA pre-master decryption failed (wrong key or non-RSA-kx handshake)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_PEM: &str = include_str!("../../tests/fixtures/tls_rsa/key.pem");
    const PREMASTER_CT: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster_ct.bin");
    const PREMASTER: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster.bin");

    #[test]
    fn loads_pkcs8_pem() {
        assert!(RsaKey::from_pem(KEY_PEM).is_ok());
    }

    #[test]
    fn rejects_garbage_pem_without_leaking() {
        let err = RsaKey::from_pem(
            "-----BEGIN PRIVATE KEY-----\nNOTBASE64!!!\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("RSA private key"), "got: {msg}");
        assert!(!msg.contains("NOTBASE64"), "must not echo key bytes: {msg}");
    }

    #[test]
    fn decrypts_known_premaster() {
        // KAT: the fixture ciphertext was produced by openssl pkeyutl
        // (PKCS#1 v1.5) over the 48-byte fixture premaster.
        let key = RsaKey::from_pem(KEY_PEM).unwrap();
        let pm = key.decrypt_premaster(PREMASTER_CT).unwrap();
        assert_eq!(pm.len(), 48, "TLS pre-master is 48 bytes");
        assert_eq!(pm, PREMASTER, "decrypt must recover the known premaster");
        // The premaster begins with the offered client_version (0x0303).
        assert_eq!(&pm[..2], &[0x03, 0x03]);
    }

    #[test]
    fn wrong_ciphertext_length_errors() {
        let key = RsaKey::from_pem(KEY_PEM).unwrap();
        // A truncated ciphertext (not a full RSA block) must error, not panic.
        assert!(key.decrypt_premaster(&PREMASTER_CT[..100]).is_err());
    }
}
