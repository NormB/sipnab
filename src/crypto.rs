//! Cryptographic backend abstraction for TLS/SRTP decryption.
//!
//! Defines the [`CryptoBackend`] trait that abstracts over different crypto
//! implementations (pure-Rust via `ring`, wolfSSL, or OpenSSL). Only the
//! trait definition and a [`StubCryptoBackend`] are provided in this phase;
//! real implementations are planned for Phase 5.3.

use anyhow::Result;

/// Trait abstracting cryptographic operations for TLS and SRTP decryption.
///
/// Three implementations are planned:
/// - **Pure-Rust** (`ring` crate) — the default when the `tls` feature is enabled.
/// - **wolfSSL** — via `tls-wolfssl` feature for environments requiring FIPS.
/// - **OpenSSL** — via `tls-openssl` feature for compatibility with existing deployments.
///
/// All implementations must be `Send + Sync` to allow sharing across threads.
pub trait CryptoBackend: Send + Sync {
    /// Decrypt an AES-GCM ciphertext with the given key, nonce, and AAD.
    ///
    /// Used for TLS 1.3 record decryption and SRTP with GCM suites.
    fn aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypt an AES-CBC ciphertext with the given key and IV.
    ///
    /// Used for TLS 1.2 record decryption with CBC cipher suites.
    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Compute HMAC-SHA1 over the given data with the provided key.
    ///
    /// Used for SRTP authentication tag computation and verification.
    fn hmac_sha1(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    /// HKDF-Expand (RFC 5869) using SHA-256 as the hash function.
    ///
    /// Expands the PRK (pseudo-random key) with the given info context
    /// to produce `len` bytes of output key material. Used for TLS 1.3
    /// key derivation.
    fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>>;
}

/// Stub crypto backend that returns errors for all operations.
///
/// Used as a placeholder until a real backend is compiled in. Calling any
/// method returns an error instructing the user to build with the `tls` feature.
pub struct StubCryptoBackend;

impl CryptoBackend for StubCryptoBackend {
    fn aes_gcm_decrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        anyhow::bail!("No crypto backend compiled. Build with --features tls")
    }

    fn aes_cbc_decrypt(&self, _key: &[u8], _iv: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("No crypto backend compiled. Build with --features tls")
    }

    fn hmac_sha1(&self, _key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("No crypto backend compiled. Build with --features tls")
    }

    fn hkdf_expand(&self, _prk: &[u8], _info: &[u8], _len: usize) -> Result<Vec<u8>> {
        anyhow::bail!("No crypto backend compiled. Build with --features tls")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_aes_gcm_decrypt_returns_error() {
        let stub = StubCryptoBackend;
        let result = stub.aes_gcm_decrypt(b"key", b"nonce", b"aad", b"ct");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("No crypto backend"),
            "Error should mention missing backend: {msg}"
        );
    }

    #[test]
    fn stub_aes_cbc_decrypt_returns_error() {
        let stub = StubCryptoBackend;
        let result = stub.aes_cbc_decrypt(b"key", b"iv", b"ct");
        assert!(result.is_err());
    }

    #[test]
    fn stub_hmac_sha1_returns_error() {
        let stub = StubCryptoBackend;
        let result = stub.hmac_sha1(b"key", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn stub_hkdf_expand_returns_error() {
        let stub = StubCryptoBackend;
        let result = stub.hkdf_expand(b"prk", b"info", 32);
        assert!(result.is_err());
    }

    #[test]
    fn stub_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StubCryptoBackend>();
    }
}
