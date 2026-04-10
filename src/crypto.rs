//! Cryptographic backend abstraction for TLS/SRTP decryption.
//!
//! Defines the [`CryptoBackend`] trait that abstracts over different crypto
//! implementations (pure-Rust via `ring`, wolfSSL, or OpenSSL). When the
//! `tls` feature is enabled, [`RingCryptoBackend`] provides the real
//! implementation using the `ring` crate. Without `tls`, only the
//! [`StubCryptoBackend`] is available (returns errors for all operations).

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

// ---------------------------------------------------------------------------
// ring-based crypto backend (feature = "tls")
// ---------------------------------------------------------------------------

/// Pure-Rust crypto backend powered by `ring` (GCM, HMAC, HKDF) and the
/// RustCrypto `aes`+`cbc` crates (AES-CBC for TLS 1.2 CBC cipher suites).
///
/// Supports AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC,
/// HMAC-SHA1, and HKDF-SHA256.
#[cfg(feature = "tls")]
pub struct RingCryptoBackend;

#[cfg(feature = "tls")]
impl CryptoBackend for RingCryptoBackend {
    fn aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        use ring::aead;

        let algo = match key.len() {
            16 => &aead::AES_128_GCM,
            32 => &aead::AES_256_GCM,
            _ => anyhow::bail!("Invalid AES-GCM key length: {}", key.len()),
        };

        let unbound_key = aead::UnboundKey::new(algo, key)
            .map_err(|e| anyhow::anyhow!("AES-GCM key error: {e}"))?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| anyhow::anyhow!("AES-GCM nonce error: {e}"))?;
        let aad = aead::Aad::from(aad);
        let opening_key = aead::LessSafeKey::new(unbound_key);

        let mut buf = ciphertext.to_vec();
        let plaintext = opening_key
            .open_in_place(nonce, aad, &mut buf)
            .map_err(|e| anyhow::anyhow!("AES-GCM decrypt failed: {e}"))?;
        Ok(plaintext.to_vec())
    }

    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};

        if iv.len() != 16 {
            anyhow::bail!("AES-CBC IV must be 16 bytes, got {}", iv.len());
        }
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            anyhow::bail!(
                "AES-CBC ciphertext must be a non-empty multiple of 16 bytes, got {}",
                ciphertext.len()
            );
        }

        let mut buf = ciphertext.to_vec();

        match key.len() {
            16 => {
                type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
                let decryptor = Aes128CbcDec::new_from_slices(key, iv)
                    .map_err(|e| anyhow::anyhow!("AES-128-CBC key/IV error: {e}"))?;
                let plaintext = decryptor
                    .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
                    .map_err(|e| anyhow::anyhow!("AES-128-CBC decrypt failed: {e}"))?;
                Ok(plaintext.to_vec())
            }
            32 => {
                type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
                let decryptor = Aes256CbcDec::new_from_slices(key, iv)
                    .map_err(|e| anyhow::anyhow!("AES-256-CBC key/IV error: {e}"))?;
                let plaintext = decryptor
                    .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
                    .map_err(|e| anyhow::anyhow!("AES-256-CBC decrypt failed: {e}"))?;
                Ok(plaintext.to_vec())
            }
            _ => anyhow::bail!(
                "Invalid AES-CBC key length: {} (expected 16 or 32)",
                key.len()
            ),
        }
    }

    fn hmac_sha1(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use ring::hmac;

        let signing_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let tag = hmac::sign(&signing_key, data);
        Ok(tag.as_ref().to_vec())
    }

    fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
        use ring::hkdf;

        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, prk);
        let info_refs: &[&[u8]] = &[info];
        let okm = prk
            .expand(info_refs, HkdfLen(len))
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
        let mut out = vec![0u8; len];
        okm.fill(&mut out)
            .map_err(|e| anyhow::anyhow!("HKDF fill failed: {e}"))?;
        Ok(out)
    }
}

/// Helper for ring's HKDF output length specification.
#[cfg(feature = "tls")]
struct HkdfLen(usize);

#[cfg(feature = "tls")]
impl ring::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Create the default crypto backend for the current feature set.
///
/// Returns [`RingCryptoBackend`] when `tls` is enabled, [`StubCryptoBackend`]
/// otherwise.
pub fn default_backend() -> Box<dyn CryptoBackend> {
    #[cfg(feature = "tls")]
    {
        Box::new(RingCryptoBackend)
    }
    #[cfg(not(feature = "tls"))]
    {
        Box::new(StubCryptoBackend)
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

    // -----------------------------------------------------------------------
    // RingCryptoBackend tests (feature = "tls")
    // -----------------------------------------------------------------------

    #[cfg(feature = "tls")]
    mod ring_tests {
        use super::*;

        /// Encrypt with ring, then decrypt — roundtrip must match.
        fn aes_gcm_roundtrip(key: &[u8]) {
            use ring::aead;

            let algo = match key.len() {
                16 => &aead::AES_128_GCM,
                32 => &aead::AES_256_GCM,
                _ => panic!("bad key len"),
            };

            let plaintext = b"SIP/2.0 200 OK\r\n\r\n";
            let nonce_bytes = [0x01u8; 12];

            // Encrypt
            let unbound = aead::UnboundKey::new(algo, key).unwrap();
            let sealing_key = aead::LessSafeKey::new(unbound);
            let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let aad_bytes = b"additional data";
            let mut in_out = plaintext.to_vec();
            sealing_key
                .seal_in_place_append_tag(nonce, aead::Aad::from(&aad_bytes[..]), &mut in_out)
                .unwrap();

            // Decrypt
            let backend = RingCryptoBackend;
            let decrypted = backend
                .aes_gcm_decrypt(key, &nonce_bytes, aad_bytes, &in_out)
                .unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn aes_128_gcm_roundtrip() {
            aes_gcm_roundtrip(&[0xAAu8; 16]);
        }

        #[test]
        fn aes_256_gcm_roundtrip() {
            aes_gcm_roundtrip(&[0xBBu8; 32]);
        }

        #[test]
        fn aes_gcm_wrong_key_fails() {
            use ring::aead;

            let key = [0xAAu8; 16];
            let wrong_key = [0xCCu8; 16];
            let plaintext = b"secret";
            let nonce_bytes = [0x01u8; 12];

            let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap();
            let sealing_key = aead::LessSafeKey::new(unbound);
            let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let mut in_out = plaintext.to_vec();
            sealing_key
                .seal_in_place_append_tag(nonce, aead::Aad::from(&b""[..]), &mut in_out)
                .unwrap();

            let backend = RingCryptoBackend;
            let result = backend.aes_gcm_decrypt(&wrong_key, &nonce_bytes, b"", &in_out);
            assert!(result.is_err(), "Wrong key should produce an error");
        }

        #[test]
        fn aes_gcm_invalid_key_length() {
            let backend = RingCryptoBackend;
            let result = backend.aes_gcm_decrypt(&[0u8; 24], &[0u8; 12], b"", b"ct");
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid AES-GCM key length")
            );
        }

        #[test]
        fn hmac_sha1_known_vector() {
            // RFC 2202 Test Case 1: key=0x0b repeated 20 times, data="Hi There"
            let key = [0x0bu8; 20];
            let data = b"Hi There";
            let expected: [u8; 20] = [
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
                0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
            ];

            let backend = RingCryptoBackend;
            let result = backend.hmac_sha1(&key, data).unwrap();
            assert_eq!(result, expected);
        }

        #[test]
        fn hkdf_expand_produces_correct_length() {
            let backend = RingCryptoBackend;
            // Use a 32-byte PRK (minimum for SHA-256)
            let prk = [0x07u8; 32];
            let info = b"tls13 key";

            let out16 = backend.hkdf_expand(&prk, info, 16).unwrap();
            assert_eq!(out16.len(), 16);

            let out32 = backend.hkdf_expand(&prk, info, 32).unwrap();
            assert_eq!(out32.len(), 32);

            // HKDF-Expand with the same PRK and info: shorter output is a prefix
            // of longer output (this is the standard HKDF property).
            assert_eq!(out16[..], out32[..16]);

            // Different info produces different output
            let out_diff = backend.hkdf_expand(&prk, b"tls13 iv", 16).unwrap();
            assert_ne!(
                out16, out_diff,
                "Different info should produce different keys"
            );
        }

        #[test]
        fn hkdf_expand_deterministic() {
            let backend = RingCryptoBackend;
            let prk = [0x42u8; 32];
            let info = b"test info";

            let a = backend.hkdf_expand(&prk, info, 16).unwrap();
            let b = backend.hkdf_expand(&prk, info, 16).unwrap();
            assert_eq!(a, b, "HKDF-Expand must be deterministic");
        }

        #[test]
        fn ring_is_send_and_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<RingCryptoBackend>();
        }

        #[test]
        fn aes_128_cbc_roundtrip() {
            use cbc::cipher::{BlockEncryptMut, KeyIvInit};

            let key = [0xAAu8; 16];
            let iv = [0xBBu8; 16];
            let plaintext = b"SIP/2.0 200 OK\r\n";

            // Encrypt with PKCS7 padding
            type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
            let encryptor = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
            let ciphertext =
                encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext);

            // Decrypt
            let backend = RingCryptoBackend;
            let decrypted = backend.aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn aes_256_cbc_roundtrip() {
            use cbc::cipher::{BlockEncryptMut, KeyIvInit};

            let key = [0xCCu8; 32];
            let iv = [0xDDu8; 16];
            let plaintext = b"INVITE sip:test SIP/2.0\r\n\r\n";

            type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
            let encryptor = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
            let ciphertext =
                encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext);

            let backend = RingCryptoBackend;
            let decrypted = backend.aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn aes_cbc_invalid_key_length() {
            let backend = RingCryptoBackend;
            let result = backend.aes_cbc_decrypt(&[0u8; 24], &[0u8; 16], &[0u8; 16]);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid AES-CBC key length")
            );
        }

        #[test]
        fn aes_cbc_invalid_ciphertext_length() {
            let backend = RingCryptoBackend;
            // Not a multiple of 16
            let result = backend.aes_cbc_decrypt(&[0u8; 16], &[0u8; 16], &[0u8; 15]);
            assert!(result.is_err());
        }
    }
}
