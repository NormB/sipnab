//! TLS session decryption engine.
//!
//! Manages TLS session state and decrypts ApplicationData records using
//! secrets from an SSLKEYLOGFILE. Currently supports TLS 1.3 traffic
//! secrets (the keylog already provides derived per-direction secrets,
//! so only HKDF-Expand-Label is needed to derive key + IV).
//!
//! TLS 1.2 with `CLIENT_RANDOM` requires the full TLS PRF key derivation,
//! which is planned but not yet implemented.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

use super::tls::{KeyLogEntry, TlsContentType, TlsRecord, parse_keylog_file};
use crate::crypto::CryptoBackend;

// ---------------------------------------------------------------------------
// Cipher suite identification
// ---------------------------------------------------------------------------

/// Supported cipher suites for record-layer decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128Gcm,
    /// TLS_AES_256_GCM_SHA384 (0x1302).
    Aes256Gcm,
}

impl CipherSuite {
    /// Key length in bytes for this cipher suite.
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    /// IV (nonce) length in bytes — always 12 for GCM.
    fn iv_len(self) -> usize {
        12
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "TLS_AES_128_GCM_SHA256"),
            Self::Aes256Gcm => write!(f, "TLS_AES_256_GCM_SHA384"),
        }
    }
}

// ---------------------------------------------------------------------------
// Session key types
// ---------------------------------------------------------------------------

/// Lookup key for a TLS session: the 32-byte client_random from the ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TlsSessionKey {
    client_random: [u8; 32],
}

/// Derived per-direction key material for a TLS session.
struct TlsSession {
    /// Encryption key for client-to-server records.
    client_write_key: Vec<u8>,
    /// Encryption key for server-to-client records.
    server_write_key: Vec<u8>,
    /// IV base for client-to-server records.
    client_write_iv: Vec<u8>,
    /// IV base for server-to-client records.
    server_write_iv: Vec<u8>,
    /// The cipher suite in use.
    cipher_suite: CipherSuite,
    /// Record sequence number for client-to-server direction.
    sequence_client: u64,
    /// Record sequence number for server-to-client direction.
    sequence_server: u64,
    /// Client IP address (set from the first handshake we observe).
    client_addr: Option<IpAddr>,
}

// ---------------------------------------------------------------------------
// TLS 1.3 HKDF-Expand-Label
// ---------------------------------------------------------------------------

/// Build the HKDF info for TLS 1.3 `HKDF-Expand-Label`.
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn hkdf_expand_label_info(label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    let tls_label = [b"tls13 ", label].concat();
    let mut info = Vec::with_capacity(2 + 1 + tls_label.len() + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(tls_label.len() as u8);
    info.extend_from_slice(&tls_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

/// Derive key and IV from a TLS 1.3 traffic secret via HKDF-Expand-Label.
fn derive_key_iv(
    crypto: &dyn CryptoBackend,
    secret: &[u8],
    suite: CipherSuite,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_info = hkdf_expand_label_info(b"key", &[], suite.key_len() as u16);
    let key = crypto.hkdf_expand(secret, &key_info, suite.key_len())?;

    let iv_info = hkdf_expand_label_info(b"iv", &[], suite.iv_len() as u16);
    let iv = crypto.hkdf_expand(secret, &iv_info, suite.iv_len())?;

    Ok((key, iv))
}

// ---------------------------------------------------------------------------
// TlsDecryptor
// ---------------------------------------------------------------------------

/// Manages TLS session state and decrypts application data records.
///
/// Constructed with an optional keylog file path; sessions are lazily
/// populated from keylog entries when matching client randoms are
/// encountered.
pub struct TlsDecryptor {
    /// Raw keylog entries loaded from the SSLKEYLOGFILE.
    keylog_entries: Vec<KeyLogEntry>,
    /// Active sessions indexed by client random.
    sessions: HashMap<TlsSessionKey, TlsSession>,
    /// Crypto backend for actual decryption operations.
    crypto: Box<dyn CryptoBackend>,
    /// Number of records successfully decrypted (for logging).
    pub decrypted_count: u64,
}

impl TlsDecryptor {
    /// Create a new TLS decryptor, optionally loading keylog entries from a file.
    ///
    /// If `keylog_path` is `None`, the decryptor is created with no keys
    /// and will not be able to decrypt any records.
    pub fn new(keylog_path: Option<&Path>, crypto: Box<dyn CryptoBackend>) -> Result<Self> {
        let keylog_entries = if let Some(path) = keylog_path {
            parse_keylog_file(path)
                .with_context(|| format!("Loading keylog from {}", path.display()))?
        } else {
            Vec::new()
        };

        let entry_count = keylog_entries.len();
        if entry_count > 0 {
            log::info!("Loaded {} keylog entries", entry_count);
        }

        Ok(Self {
            keylog_entries,
            sessions: HashMap::new(),
            crypto,
            decrypted_count: 0,
        })
    }

    /// Return the number of loaded keylog entries.
    pub fn keylog_entry_count(&self) -> usize {
        self.keylog_entries.len()
    }

    /// Attempt to decrypt a TLS ApplicationData record.
    ///
    /// Returns `Some(plaintext)` if decryption succeeds, `None` if no
    /// matching session keys are found or decryption fails.
    ///
    /// # Arguments
    ///
    /// * `record` — The TLS record to decrypt (must be ApplicationData).
    /// * `src_addr` — Source IP of the packet containing this record.
    /// * `dst_addr` — Destination IP of the packet.
    pub fn try_decrypt(
        &mut self,
        record: &TlsRecord,
        src_addr: IpAddr,
        dst_addr: IpAddr,
    ) -> Option<Vec<u8>> {
        if record.content_type != TlsContentType::ApplicationData {
            return None;
        }

        // Lazily populate sessions from keylog entries
        self.ensure_sessions_populated();

        // Try each session — in practice, the right session is found quickly
        // because captures typically have very few concurrent TLS sessions.
        let session_keys: Vec<TlsSessionKey> = self.sessions.keys().cloned().collect();
        for key in &session_keys {
            // Read cipher suite before mutable borrow in try_decrypt_with_session
            let cipher = self.sessions.get(key).map(|s| s.cipher_suite);
            if let Some(plaintext) = self.try_decrypt_with_session(key, record, src_addr, dst_addr)
            {
                self.decrypted_count += 1;
                if let Some(suite) = cipher {
                    log::info!(
                        "TLS session decrypted [session={}, cipher={}]",
                        hex_id(&key.client_random),
                        suite,
                    );
                }
                return Some(plaintext);
            }
        }

        None
    }

    /// Populate sessions from keylog entries (idempotent).
    fn ensure_sessions_populated(&mut self) {
        if self.keylog_entries.is_empty() {
            return;
        }

        // Group entries by client_random
        let mut grouped: HashMap<[u8; 32], Vec<&KeyLogEntry>> = HashMap::new();
        for entry in &self.keylog_entries {
            if entry.client_random.len() == 32 {
                let mut cr = [0u8; 32];
                cr.copy_from_slice(&entry.client_random);
                grouped.entry(cr).or_default().push(entry);
            }
        }

        for (cr, entries) in &grouped {
            let session_key = TlsSessionKey { client_random: *cr };
            if self.sessions.contains_key(&session_key) {
                continue;
            }

            // Look for TLS 1.3 traffic secrets
            let client_secret = entries
                .iter()
                .find(|e| e.label == "CLIENT_TRAFFIC_SECRET_0")
                .map(|e| &e.secret);
            let server_secret = entries
                .iter()
                .find(|e| e.label == "SERVER_TRAFFIC_SECRET_0")
                .map(|e| &e.secret);

            if let (Some(cs), Some(ss)) = (client_secret, server_secret) {
                // Determine cipher suite from secret length:
                // - 32 bytes (SHA-256 output) -> AES-128-GCM
                // - 48 bytes (SHA-384 output) -> AES-256-GCM
                let suite = match cs.len() {
                    32 => CipherSuite::Aes128Gcm,
                    48 => CipherSuite::Aes256Gcm,
                    _ => {
                        log::debug!(
                            "Skipping session with unsupported secret length: {}",
                            cs.len()
                        );
                        continue;
                    }
                };

                match (
                    derive_key_iv(self.crypto.as_ref(), cs, suite),
                    derive_key_iv(self.crypto.as_ref(), ss, suite),
                ) {
                    (Ok((ck, civ)), Ok((sk, siv))) => {
                        log::info!(
                            "TLS session ready [session={}, cipher={}]",
                            hex_id(cr),
                            suite
                        );
                        self.sessions.insert(
                            session_key,
                            TlsSession {
                                client_write_key: ck,
                                server_write_key: sk,
                                client_write_iv: civ,
                                server_write_iv: siv,
                                cipher_suite: suite,
                                sequence_client: 0,
                                sequence_server: 0,
                                client_addr: None,
                            },
                        );
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        log::debug!("Failed to derive keys for session {}: {e}", hex_id(cr));
                    }
                }
            }
            // TLS 1.2 CLIENT_RANDOM: would need full PRF derivation — not yet implemented.
        }
    }

    /// Try to decrypt a record using a specific session's keys.
    fn try_decrypt_with_session(
        &mut self,
        session_key: &TlsSessionKey,
        record: &TlsRecord,
        src_addr: IpAddr,
        dst_addr: IpAddr,
    ) -> Option<Vec<u8>> {
        let session = self.sessions.get_mut(session_key)?;

        // Determine direction: try both if we haven't established client_addr yet
        let directions: Vec<bool> = if let Some(client) = session.client_addr {
            // Known direction
            vec![src_addr == client]
        } else {
            // Unknown: try client->server first, then server->client
            vec![true, false]
        };

        for is_client_to_server in directions {
            let (write_key, write_iv, seq) = if is_client_to_server {
                (
                    &session.client_write_key,
                    &session.client_write_iv,
                    session.sequence_client,
                )
            } else {
                (
                    &session.server_write_key,
                    &session.server_write_iv,
                    session.sequence_server,
                )
            };

            // Construct nonce: IV XOR sequence number (TLS 1.3 style).
            // The sequence number is left-padded with zeros to IV length,
            // then XOR'd with the base IV.
            let mut nonce = write_iv.clone();
            let seq_bytes = seq.to_be_bytes();
            let offset = nonce.len().saturating_sub(seq_bytes.len());
            for (i, &b) in seq_bytes.iter().enumerate() {
                if offset + i < nonce.len() {
                    nonce[offset + i] ^= b;
                }
            }

            // TLS 1.3 AAD is the 5-byte record header:
            // content_type(1) + legacy_version(2) + length(2)
            let aad = build_record_aad(record);

            if let Ok(mut plaintext) =
                self.crypto
                    .aes_gcm_decrypt(write_key, &nonce, &aad, &record.payload)
            {
                // TLS 1.3: the actual content type is the last non-zero byte
                // of the plaintext (inner content type), preceded by optional
                // zero padding.
                strip_tls13_padding(&mut plaintext);

                // Update direction tracking and sequence number
                if session.client_addr.is_none() {
                    session.client_addr = Some(if is_client_to_server {
                        src_addr
                    } else {
                        dst_addr
                    });
                }

                if is_client_to_server {
                    // We need to re-borrow mutably
                    if let Some(s) = self.sessions.get_mut(session_key) {
                        s.sequence_client = seq + 1;
                    }
                } else if let Some(s) = self.sessions.get_mut(session_key) {
                    s.sequence_server = seq + 1;
                }

                return Some(plaintext);
            }
        }

        None
    }
}

/// Build the 5-byte AAD for a TLS record (used as additional authenticated data).
fn build_record_aad(record: &TlsRecord) -> [u8; 5] {
    let ct_byte = match record.content_type {
        TlsContentType::ChangeCipherSpec => 20,
        TlsContentType::Alert => 21,
        TlsContentType::Handshake => 22,
        TlsContentType::ApplicationData => 23,
        TlsContentType::Unknown(b) => b,
    };
    let version = match record.version {
        super::tls::TlsVersion::Tls10 => 0x0301u16,
        super::tls::TlsVersion::Tls11 => 0x0302,
        super::tls::TlsVersion::Tls12 | super::tls::TlsVersion::Tls13 => 0x0303,
        super::tls::TlsVersion::Unknown(v) => v,
    };
    let len = record.length;

    let mut aad = [0u8; 5];
    aad[0] = ct_byte;
    aad[1..3].copy_from_slice(&version.to_be_bytes());
    aad[3..5].copy_from_slice(&len.to_be_bytes());
    aad
}

/// Strip TLS 1.3 inner content type and zero padding from decrypted plaintext.
///
/// In TLS 1.3, the decrypted record has the structure:
/// `[actual_content...] [zero_padding...] [content_type_byte]`
///
/// We strip the trailing content type byte and any zero padding. The
/// content type byte is always the last non-zero byte.
fn strip_tls13_padding(plaintext: &mut Vec<u8>) {
    // TLS 1.3 decrypted record structure:
    //   [actual_content] [zero_padding (0+)] [content_type_byte]
    //
    // The content type byte is the very last byte. Zero padding (if any)
    // sits between the content and the content type. We scan backwards:
    // 1. Remove the last byte (content type).
    // 2. Remove any trailing zero-padding bytes.

    if plaintext.is_empty() {
        return;
    }

    // Step 1: Pop the content type byte (last byte in the record).
    plaintext.pop();

    // Step 2: Strip any trailing zero-padding bytes.
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }
}

/// Format first 4 bytes of a client random as a short session ID for logs.
/// No key material is exposed.
fn hex_id(cr: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}...", cr[0], cr[1], cr[2], cr[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::tls::{TlsContentType, TlsVersion};

    /// A minimal crypto backend for testing that tracks calls.
    struct MockCrypto {
        /// If set, aes_gcm_decrypt returns this plaintext.
        decrypt_result: Option<Vec<u8>>,
    }

    impl CryptoBackend for MockCrypto {
        fn aes_gcm_decrypt(
            &self,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            match &self.decrypt_result {
                Some(pt) => Ok(pt.clone()),
                None => anyhow::bail!("mock decrypt failure"),
            }
        }

        fn aes_cbc_decrypt(&self, _key: &[u8], _iv: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("not implemented")
        }

        fn hmac_sha1(&self, _key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("not implemented")
        }

        fn hkdf_expand(&self, _prk: &[u8], _info: &[u8], len: usize) -> Result<Vec<u8>> {
            // Return deterministic bytes for testing
            Ok(vec![0x42u8; len])
        }
    }

    fn make_keylog_entries() -> Vec<KeyLogEntry> {
        let cr = [0xAAu8; 32];
        vec![
            KeyLogEntry {
                label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
                client_random: cr.to_vec(),
                secret: vec![0x11u8; 32], // 32 bytes -> AES-128-GCM
            },
            KeyLogEntry {
                label: "SERVER_TRAFFIC_SECRET_0".to_string(),
                client_random: cr.to_vec(),
                secret: vec![0x22u8; 32],
            },
        ]
    }

    #[test]
    fn new_without_keylog() {
        let decryptor = TlsDecryptor::new(
            None,
            Box::new(MockCrypto {
                decrypt_result: None,
            }),
        );
        assert!(decryptor.is_ok());
        let d = decryptor.unwrap();
        assert_eq!(d.keylog_entry_count(), 0);
    }

    #[test]
    fn load_keylog_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            "aa".repeat(32),
            "bb".repeat(32),
        )
        .unwrap();
        writeln!(
            tmp,
            "SERVER_TRAFFIC_SECRET_0 {} {}",
            "aa".repeat(32),
            "cc".repeat(32),
        )
        .unwrap();
        tmp.flush().unwrap();

        let d = TlsDecryptor::new(
            Some(tmp.path()),
            Box::new(MockCrypto {
                decrypt_result: None,
            }),
        )
        .unwrap();
        assert_eq!(d.keylog_entry_count(), 2);
    }

    #[test]
    fn sessions_populated_from_entries() {
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: None,
            }),
            decrypted_count: 0,
        };

        d.ensure_sessions_populated();
        assert_eq!(d.sessions.len(), 1);

        let key = TlsSessionKey {
            client_random: [0xAAu8; 32],
        };
        let session = d.sessions.get(&key).unwrap();
        assert_eq!(session.cipher_suite, CipherSuite::Aes128Gcm);
    }

    #[test]
    fn try_decrypt_no_matching_session() {
        let mut d = TlsDecryptor {
            keylog_entries: Vec::new(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: None,
            }),
            decrypted_count: 0,
        };

        let record = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 10,
            payload: vec![0u8; 10],
        };

        let result = d.try_decrypt(
            &record,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn try_decrypt_with_matching_session() {
        // The mock returns a fixed plaintext with TLS 1.3 content type appended
        let mut plaintext = b"INVITE sip:test@example.com SIP/2.0\r\n\r\n".to_vec();
        plaintext.push(23); // inner content type = ApplicationData

        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: Some(plaintext),
            }),
            decrypted_count: 0,
        };

        let record = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 64,
            payload: vec![0xEE; 64],
        };

        let result = d.try_decrypt(
            &record,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        );
        assert!(result.is_some());
        let decrypted = result.unwrap();
        assert!(decrypted.starts_with(b"INVITE sip:"));
        assert_eq!(d.decrypted_count, 1);
    }

    #[test]
    fn non_application_data_returns_none() {
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: Some(vec![0x42]),
            }),
            decrypted_count: 0,
        };

        let record = TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 10,
            payload: vec![0u8; 10],
        };

        let result = d.try_decrypt(
            &record,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn strip_padding_removes_content_type() {
        let mut data = b"hello".to_vec();
        data.push(0); // zero padding
        data.push(0); // zero padding
        data.push(23); // content type
        strip_tls13_padding(&mut data);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn strip_padding_no_padding() {
        let mut data = b"hello".to_vec();
        data.push(23); // content type, no padding
        strip_tls13_padding(&mut data);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn build_aad_correct() {
        let record = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 256,
            payload: vec![],
        };
        let aad = build_record_aad(&record);
        assert_eq!(aad[0], 23); // ApplicationData
        assert_eq!(u16::from_be_bytes([aad[1], aad[2]]), 0x0303); // TLS 1.2
        assert_eq!(u16::from_be_bytes([aad[3], aad[4]]), 256);
    }

    #[test]
    fn hkdf_expand_label_info_format() {
        let info = hkdf_expand_label_info(b"key", &[], 16);
        // Length prefix: 0x0010
        assert_eq!(info[0], 0x00);
        assert_eq!(info[1], 0x10);
        // Label length: "tls13 key" = 9 bytes
        assert_eq!(info[2], 9);
        assert_eq!(&info[3..12], b"tls13 key");
        // Context length: 0
        assert_eq!(info[12], 0);
    }
}
