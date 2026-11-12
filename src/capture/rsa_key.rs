// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

use rsa::Pkcs1v15Encrypt;

/// The length of a TLS 1.2 RSA pre-master secret, in octets (RFC 5246
/// section 7.4.7.1).
const PREMASTER_LEN: usize = 48;

/// Whether a decrypted plaintext of `len` octets can be a pre-master secret.
fn is_premaster_len(len: usize) -> bool {
    len == PREMASTER_LEN
}

/// A loaded RSA private key used to recover the TLS pre-master secret.
pub struct RsaKey {
    /// The parsed RSA private key. Never logged or exposed; the `Debug` impl
    /// redacts it.
    key: rsa::PrivateKey,
}

impl std::fmt::Debug for RsaKey {
    /// Format as the fixed string `RsaKey(<redacted>)`, deliberately hiding the
    /// key bytes so private key material can never leak through `Debug`/logs.
    ///
    /// # Side effects
    ///
    /// Writes to the formatter `f`.
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
        let key = rsa::PrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::PrivateKey::from_pkcs1_pem(pem))
            .context("failed to parse RSA private key (expected PKCS#1 or PKCS#8 PEM)")?;
        Ok(Self { key })
    }

    /// Load an RSA private key from a PEM file at `path`.
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        // Read before the privilege drop when this run drops; see
        // `crate::secret_files`.
        let pem = crate::secret_files::read_to_string(path)
            .with_context(|| format!("reading TLS private key from {}", path.display()))?;
        Self::from_pem(&pem)
    }

    /// Decrypt a PKCS#1 v1.5-encrypted TLS pre-master secret (the
    /// `ClientKeyExchange.encrypted_pre_master_secret`). Returns the 48-byte
    /// pre-master on success.
    ///
    /// # Errors
    ///
    /// A ciphertext that is not one RSA block for this key, and a plaintext
    /// that is not 48 octets. The `rsa` crate answers bad
    /// padding (a wrong key, a damaged block) with a made-up plaintext of a
    /// pseudo-random length instead of an error, so that no caller can tell
    /// the two apart by timing; the length rule here is what refuses it, and
    /// callers fall through to other secrets. A made-up plaintext that happens
    /// to be 48 octets is returned: the keys derived from it open no record,
    /// as with a wrong key-log entry.
    pub fn decrypt_premaster(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self
            .key
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .context("RSA pre-master decryption failed (wrong key or non-RSA-kx handshake)")?;
        if !is_premaster_len(plaintext.len()) {
            anyhow::bail!(
                "RSA pre-master decryption failed (wrong key, damaged key exchange or \
                 non-RSA-kx handshake)"
            );
        }
        Ok(plaintext)
    }
}

/// Unit tests for RSA private-key loading and pre-master decryption, driven by
/// a fixed PKCS#8 key + known-answer ciphertext/pre-master fixtures.
#[cfg(test)]
mod tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A 512-bit PKCS#8 RSA key, made for this test and used nowhere else.
    const KEY_512_PEM: &str = include_str!("../../tests/fixtures/tls_rsa/key_512.pem");

    /// The fixture pre-master encrypted to `KEY_512_PEM` (from `openssl`).
    const PREMASTER_CT_512: &[u8] =
        include_bytes!("../../tests/fixtures/tls_rsa/premaster_ct_512.bin");

    /// A 512-bit key still loads and decrypts: captures from old equipment
    /// carry such keys, and `rsa` 0.10's 1024-bit minimum is for public keys
    /// and key generation, not for a private key read from a file.
    #[test]
    fn a_512_bit_key_loads_and_decrypts() -> Result<(), TestError> {
        let key = RsaKey::from_pem(KEY_512_PEM)?;
        let pm = key.decrypt_premaster(PREMASTER_CT_512)?;
        assert_eq!(pm, PREMASTER, "the 512-bit key recovers the pre-master");
        Ok(())
    }

    /// A ciphertext damaged in any one octet never comes back as something a
    /// caller could take for a pre-master: the answer is an error, never a
    /// plaintext of another length, and never the fixture's pre-master.
    ///
    /// `rsa` 0.10 answers bad PKCS#1 v1.5 padding with a made-up plaintext of
    /// a pseudo-random length instead of an error, so the length rule is what
    /// refuses it.
    #[test]
    fn a_damaged_ciphertext_never_yields_a_plaintext_of_another_length() -> Result<(), TestError> {
        let key = RsaKey::from_pem(KEY_PEM)?;
        let mut refused = 0_usize;
        for at in (0..PREMASTER_CT.len()).step_by(4) {
            let mut ct = PREMASTER_CT.to_vec();
            ct[at] ^= 0x01;
            match key.decrypt_premaster(&ct) {
                Err(_) => refused += 1,
                Ok(pm) => {
                    assert_eq!(pm.len(), 48, "octet {at}: a pre-master is 48 octets");
                    assert_ne!(pm, PREMASTER, "octet {at}: the damage changed nothing");
                }
            }
        }
        assert!(
            refused >= 32,
            "only {refused} of 64 damaged ciphertexts were refused"
        );
        Ok(())
    }

    /// The refusal of a plaintext that is not 48 octets says what was wrong,
    /// not how long the plaintext was.
    #[test]
    fn the_refusal_of_a_damaged_ciphertext_does_not_give_the_length() -> Result<(), TestError> {
        let key = RsaKey::from_pem(KEY_PEM)?;
        let mut ct = PREMASTER_CT.to_vec();
        let mut seen = false;
        for at in 0..ct.len() {
            ct[at] ^= 0x01;
            if let Err(e) = key.decrypt_premaster(&ct) {
                let msg = format!("{e:#}");
                assert!(msg.contains("pre-master"), "got: {msg}");
                assert!(
                    !msg.chars().any(|c| c.is_ascii_digit()),
                    "the message carries a number: {msg}"
                );
                seen = true;
                break;
            }
            ct[at] ^= 0x01;
        }
        assert!(seen, "no damaged ciphertext was refused");
        Ok(())
    }

    /// PEM-encoded PKCS#8 RSA private key fixture used across the tests.
    const KEY_PEM: &str = include_str!("../../tests/fixtures/tls_rsa/key.pem");
    /// The PKCS#1 v1.5 ciphertext of the fixture pre-master (from `openssl`).
    const PREMASTER_CT: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster_ct.bin");
    /// The expected 48-byte plaintext pre-master matching `PREMASTER_CT`.
    const PREMASTER: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster.bin");

    /// A valid PKCS#8 PEM loads successfully.
    #[test]
    fn loads_pkcs8_pem() {
        assert!(RsaKey::from_pem(KEY_PEM).is_ok());
    }

    /// Malformed PEM is rejected with an error that names "RSA private key"
    /// but never echoes the offending key bytes.
    #[test]
    fn rejects_garbage_pem_without_leaking() -> Result<(), TestError> {
        let err = RsaKey::from_pem(
            "-----BEGIN PRIVATE KEY-----\nNOTBASE64!!!\n-----END PRIVATE KEY-----\n",
        )
        .err()
        .ok_or("expected an error")?;
        let msg = format!("{err:#}");
        assert!(msg.contains("RSA private key"), "got: {msg}");
        assert!(!msg.contains("NOTBASE64"), "must not echo key bytes: {msg}");
        Ok(())
    }

    /// Known-answer test: decrypting the fixture ciphertext recovers the
    /// 48-byte pre-master, whose first two bytes carry the client version.
    #[test]
    fn decrypts_known_premaster() -> Result<(), TestError> {
        // KAT: the fixture ciphertext was produced by openssl pkeyutl
        // (PKCS#1 v1.5) over the 48-byte fixture premaster.
        let key = RsaKey::from_pem(KEY_PEM)?;
        let pm = key.decrypt_premaster(PREMASTER_CT)?;
        assert_eq!(pm.len(), 48, "TLS pre-master is 48 bytes");
        assert_eq!(pm, PREMASTER, "decrypt must recover the known premaster");
        // The premaster begins with the offered client_version (0x0303).
        assert_eq!(&pm[..2], &[0x03, 0x03]);
        Ok(())
    }

    /// A truncated ciphertext (not a full RSA block) errors rather than panics.
    #[test]
    fn wrong_ciphertext_length_errors() -> Result<(), TestError> {
        let key = RsaKey::from_pem(KEY_PEM)?;
        // A truncated ciphertext (not a full RSA block) must error, not panic.
        assert!(key.decrypt_premaster(&PREMASTER_CT[..100]).is_err());
        Ok(())
    }
}
