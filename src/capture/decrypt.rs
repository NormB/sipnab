//! TLS session decryption engine.
//!
//! Manages TLS session state and decrypts ApplicationData records using
//! secrets from an SSLKEYLOGFILE. Currently supports TLS 1.3 traffic
//! secrets (the keylog already provides derived per-direction secrets,
//! so only HKDF-Expand-Label is needed to derive key + IV).
//!
//! TLS 1.2 with `CLIENT_RANDOM` is supported via `tls12_prf()` and
//! `derive_tls12_keys()` — requires observing the ServerHello on the wire.

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
    /// TLS_AES_128_GCM_SHA256 (0x1301) — TLS 1.3 / 1.2.
    Aes128Gcm,
    /// TLS_AES_256_GCM_SHA384 (0x1302) — TLS 1.3 / 1.2.
    Aes256Gcm,
    /// TLS_RSA_WITH_AES_128_CBC_SHA (0x002F) — TLS 1.2 CBC.
    Aes128CbcSha,
    /// TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D) — TLS 1.2 CBC.
    Aes256CbcSha256,
}

impl CipherSuite {
    /// Key length in bytes for this cipher suite.
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128CbcSha => 16,
            Self::Aes256Gcm | Self::Aes256CbcSha256 => 32,
        }
    }

    /// IV (nonce) length in bytes.
    fn iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
            Self::Aes128CbcSha => 16,
            Self::Aes256CbcSha256 => 16,
        }
    }

    /// MAC key length in bytes (only relevant for CBC cipher suites).
    fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 20,               // SHA-1 = 20 bytes
            Self::Aes256CbcSha256 => 32,            // SHA-256 = 32 bytes
            Self::Aes128Gcm | Self::Aes256Gcm => 0, // GCM uses AEAD, no separate MAC
        }
    }

    /// Whether this is a CBC (non-AEAD) cipher suite.
    fn is_cbc(self) -> bool {
        matches!(self, Self::Aes128CbcSha | Self::Aes256CbcSha256)
    }

    /// Try to identify a cipher suite from the TLS cipher suite code point.
    fn from_code_point(code: u16) -> Option<Self> {
        match code {
            0x009C => Some(Self::Aes128Gcm), // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D => Some(Self::Aes256Gcm), // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x1301 => Some(Self::Aes128Gcm), // TLS_AES_128_GCM_SHA256 (TLS 1.3)
            0x1302 => Some(Self::Aes256Gcm), // TLS_AES_256_GCM_SHA384 (TLS 1.3)
            0x002F => Some(Self::Aes128CbcSha), // TLS_RSA_WITH_AES_128_CBC_SHA
            0x003C => Some(Self::Aes128CbcSha), // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003D => Some(Self::Aes256CbcSha256), // TLS_RSA_WITH_AES_256_CBC_SHA256
            0x0035 => Some(Self::Aes256CbcSha256), // TLS_RSA_WITH_AES_256_CBC_SHA
            _ => None,
        }
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "TLS_AES_128_GCM_SHA256"),
            Self::Aes256Gcm => write!(f, "TLS_AES_256_GCM_SHA384"),
            Self::Aes128CbcSha => write!(f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
            Self::Aes256CbcSha256 => write!(f, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
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

impl Drop for TlsSession {
    fn drop(&mut self) {
        // Zeroize key material on drop to prevent key leakage via memory.
        use zeroize::Zeroize;
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
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
// TLS 1.2 PRF (P_SHA256)
// ---------------------------------------------------------------------------

/// Compute the TLS 1.2 PRF using P_SHA256.
///
/// ```text
/// PRF(secret, label, seed) = P_SHA256(secret, label + seed)
/// P_hash(secret, seed) = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
/// A(0) = seed
/// A(i) = HMAC(secret, A(i-1))
/// ```
fn tls12_prf(
    crypto: &dyn CryptoBackend,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let label_seed = [label, seed].concat();
    let mut result = Vec::with_capacity(output_len);

    // A(0) = seed (which is label + seed)
    let mut a = hmac_sha256(crypto, secret, &label_seed)?;

    while result.len() < output_len {
        // HMAC(secret, A(i) + seed)
        let input = [a.as_slice(), label_seed.as_slice()].concat();
        let p = hmac_sha256(crypto, secret, &input)?;
        result.extend_from_slice(&p);

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha256(crypto, secret, &a)?;
    }

    result.truncate(output_len);
    Ok(result)
}

/// HMAC-SHA256 using ring (the hmac_sha1 method on CryptoBackend uses SHA1,
/// so we use ring directly here for SHA256).
fn hmac_sha256(_crypto: &dyn CryptoBackend, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use ring::hmac;
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, data);
    Ok(tag.as_ref().to_vec())
}

/// Derived TLS 1.2 key block: (client_write_key, server_write_key, client_write_iv, server_write_iv).
type Tls12KeyBlock = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Derive TLS 1.2 key block from master secret, client_random, and server_random.
///
/// The key block layout is:
/// ```text
/// key_block = PRF(master_secret, "key expansion", server_random + client_random)
///
/// client_write_MAC_key[mac_key_len]
/// server_write_MAC_key[mac_key_len]
/// client_write_key[key_len]
/// server_write_key[key_len]
/// client_write_IV[iv_len]
/// server_write_IV[iv_len]
/// ```
fn derive_tls12_keys(
    crypto: &dyn CryptoBackend,
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> Result<Tls12KeyBlock> {
    let seed = [server_random.as_slice(), client_random.as_slice()].concat();
    let mac_len = suite.mac_key_len();
    let key_len = suite.key_len();
    let iv_len = suite.iv_len();

    let needed = 2 * mac_len + 2 * key_len + 2 * iv_len;
    let key_block = tls12_prf(crypto, master_secret, b"key expansion", &seed, needed)?;

    let mut off = 0;
    // Skip MAC keys (we don't verify MAC for decryption-only)
    off += 2 * mac_len;
    let client_write_key = key_block[off..off + key_len].to_vec();
    off += key_len;
    let server_write_key = key_block[off..off + key_len].to_vec();
    off += key_len;
    let client_write_iv = key_block[off..off + iv_len].to_vec();
    off += iv_len;
    let server_write_iv = key_block[off..off + iv_len].to_vec();

    Ok((
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    ))
}

// ---------------------------------------------------------------------------
// TLS handshake parsing (minimal: extract server_random and cipher suite)
// ---------------------------------------------------------------------------

/// Partial state extracted from observed TLS handshake records.
#[derive(Debug, Clone, Default)]
struct HandshakeInfo {
    /// The server_random from the ServerHello (32 bytes).
    server_random: Option<[u8; 32]>,
    /// The negotiated cipher suite code point.
    cipher_suite_code: Option<u16>,
}

/// Parse a TLS Handshake record payload to extract ServerHello fields.
///
/// ServerHello structure (RFC 5246 Section 7.4.1.3):
/// ```text
/// struct {
///     HandshakeType msg_type;    // 1 byte (2 = ServerHello)
///     uint24 length;             // 3 bytes
///     ProtocolVersion version;   // 2 bytes
///     Random random;             // 32 bytes
///     SessionID session_id;      // 1 byte length + variable
///     CipherSuite cipher_suite;  // 2 bytes
///     CompressionMethod compression; // 1 byte
///     ...extensions...
/// } ServerHello;
/// ```
fn parse_server_hello(handshake_data: &[u8]) -> Option<HandshakeInfo> {
    if handshake_data.len() < 4 {
        return None;
    }

    let msg_type = handshake_data[0];
    if msg_type != 2 {
        // Not a ServerHello
        return None;
    }

    // Skip: msg_type (1) + length (3) + version (2) = offset 6
    if handshake_data.len() < 6 + 32 {
        return None;
    }

    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&handshake_data[6..38]);

    // session_id length at offset 38
    if handshake_data.len() < 39 {
        return None;
    }
    let session_id_len = handshake_data[38] as usize;
    let cipher_offset = 39 + session_id_len;

    if handshake_data.len() < cipher_offset + 2 {
        return None;
    }

    let cipher_suite_code = u16::from_be_bytes([
        handshake_data[cipher_offset],
        handshake_data[cipher_offset + 1],
    ]);

    Some(HandshakeInfo {
        server_random: Some(server_random),
        cipher_suite_code: Some(cipher_suite_code),
    })
}

// ---------------------------------------------------------------------------
// TlsDecryptor
// ---------------------------------------------------------------------------

/// Manages TLS session state and decrypts application data records.
///
/// Constructed with an optional keylog file path; sessions are lazily
/// populated from keylog entries when matching client randoms are
/// encountered. Supports both TLS 1.3 traffic secrets and TLS 1.2
/// CLIENT_RANDOM entries (the latter requires observing the ServerHello
/// to extract the server_random and cipher suite).
pub struct TlsDecryptor {
    /// Raw keylog entries loaded from the SSLKEYLOGFILE.
    keylog_entries: Vec<KeyLogEntry>,
    /// Active sessions indexed by client random.
    sessions: HashMap<TlsSessionKey, TlsSession>,
    /// Crypto backend for actual decryption operations.
    crypto: Box<dyn CryptoBackend>,
    /// Number of records successfully decrypted (for logging).
    pub decrypted_count: u64,
    /// Path to the keylog file (for --keylog-watch polling).
    keylog_path: Option<std::path::PathBuf>,
    /// Last known size of the keylog file (for change detection).
    last_keylog_size: u64,
    /// Handshake info extracted from observed ServerHello records, keyed by
    /// client_random (we correlate via the record stream; here we key by
    /// the server_random's first 8 bytes + cipher code as a quick hash,
    /// but in practice we just store all observed ServerHellos).
    observed_handshakes: Vec<HandshakeInfo>,
    /// Number of keylog entries already processed into sessions.
    /// Avoids rebuilding the group map on every ApplicationData record.
    keylog_processed_count: usize,
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

        let last_keylog_size = keylog_path
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(Self {
            keylog_entries,
            sessions: HashMap::new(),
            crypto,
            decrypted_count: 0,
            keylog_path: keylog_path.map(|p| p.to_path_buf()),
            last_keylog_size,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
        })
    }

    /// Return the number of loaded keylog entries.
    pub fn keylog_entry_count(&self) -> usize {
        self.keylog_entries.len()
    }

    /// Poll the keylog file for new entries (for --keylog-watch).
    ///
    /// Checks if the file has grown since the last poll. If so, reads
    /// the new lines and parses them as keylog entries. Returns the
    /// number of new keys loaded.
    ///
    /// Should be called periodically (e.g., every 5 seconds).
    pub fn poll_keylog_file(&mut self) -> Result<usize> {
        let Some(ref path) = self.keylog_path else {
            return Ok(0);
        };

        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("Failed to stat keylog file: {e}");
                return Ok(0);
            }
        };

        let current_size = metadata.len();
        if current_size <= self.last_keylog_size {
            return Ok(0);
        }

        // Read from where we left off
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open keylog file: {}", path.display()))?;
        file.seek(SeekFrom::Start(self.last_keylog_size))?;

        let mut new_data = String::new();
        file.read_to_string(&mut new_data)?;

        let mut new_count = 0;
        for line in new_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match super::tls::parse_keylog_line(line) {
                Ok(entry) => {
                    self.keylog_entries.push(entry);
                    new_count += 1;
                }
                Err(e) => {
                    log::debug!("Skipping invalid keylog line: {e}");
                }
            }
        }

        self.last_keylog_size = current_size;

        if new_count > 0 {
            // Clear sessions cache so new entries are picked up
            self.sessions.clear();
            log::info!("Keylog watch: loaded {new_count} new key(s)");
        }

        Ok(new_count)
    }

    /// Load DTLS keylog entries from a file.
    ///
    /// DTLS keylog files use the same NSS SSLKEYLOGFILE format as TLS.
    /// The entries are appended to the existing keylog entries and can be
    /// used for DTLS-SRTP key extraction when that feature is implemented.
    ///
    /// Returns the number of entries loaded.
    pub fn load_dtls_keylog(path: &Path) -> Result<usize> {
        let entries = parse_keylog_file(path)
            .with_context(|| format!("Loading DTLS keylog from {}", path.display()))?;
        let count = entries.len();
        if count > 0 {
            log::info!("DTLS keys loaded: {count} entries from {}", path.display());
        } else {
            log::info!(
                "DTLS keylog file {} is empty (no entries loaded)",
                path.display()
            );
        }
        Ok(count)
    }

    /// Process a TLS record, extracting handshake information if it is a
    /// Handshake record (e.g., ServerHello). Call this for every TLS record
    /// observed on the wire so that TLS 1.2 CLIENT_RANDOM key derivation
    /// can find the server_random and negotiated cipher suite.
    pub fn process_record(&mut self, record: &TlsRecord) {
        if record.content_type == TlsContentType::Handshake
            && let Some(info) = parse_server_hello(&record.payload)
        {
            log::debug!(
                "Observed ServerHello: cipher=0x{:04X}",
                info.cipher_suite_code.unwrap_or(0)
            );
            self.observed_handshakes.push(info);
            // Clear sessions so they get re-derived with the new handshake info
            self.sessions.clear();
        }
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

        // NOTE: Collects session keys to avoid borrow conflict with try_decrypt_with_session's &mut self.
        // In practice, session count is 1-3 per capture, making this negligible.
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

    /// Populate sessions from keylog entries.
    /// Skips work when no new entries have been added since last call.
    fn ensure_sessions_populated(&mut self) {
        if self.keylog_entries.is_empty()
            || self.keylog_entries.len() == self.keylog_processed_count
        {
            return;
        }
        self.keylog_processed_count = self.keylog_entries.len();

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
                            session_key.clone(),
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
            // TLS 1.2 CLIENT_RANDOM: derive keys via the full TLS PRF if we have
            // a master_secret and an observed ServerHello with matching parameters.
            let master_secret = entries
                .iter()
                .find(|e| e.label == "CLIENT_RANDOM")
                .map(|e| &e.secret);

            if let Some(ms) = master_secret {
                // Try to find a matching ServerHello from observed handshakes.
                // We try all observed handshakes since we don't have a direct
                // correlation between client_random and ServerHello at this layer.
                for hs in &self.observed_handshakes.clone() {
                    let Some(server_random) = hs.server_random else {
                        continue;
                    };
                    let Some(cipher_code) = hs.cipher_suite_code else {
                        continue;
                    };
                    let Some(suite) = CipherSuite::from_code_point(cipher_code) else {
                        log::debug!(
                            "Unsupported TLS 1.2 cipher suite 0x{:04X} for session {}",
                            cipher_code,
                            hex_id(cr)
                        );
                        continue;
                    };

                    match derive_tls12_keys(self.crypto.as_ref(), ms, cr, &server_random, suite) {
                        Ok((ck, sk, civ, siv)) => {
                            log::info!(
                                "TLS 1.2 session ready [session={}, cipher={}]",
                                hex_id(cr),
                                suite
                            );
                            self.sessions.insert(
                                session_key.clone(),
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
                            break;
                        }
                        Err(e) => {
                            log::debug!(
                                "Failed to derive TLS 1.2 keys for session {}: {e}",
                                hex_id(cr)
                            );
                        }
                    }
                }
            }
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

        let is_cbc = session.cipher_suite.is_cbc();

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

            let decrypt_result = if is_cbc {
                // TLS 1.2 CBC: the record payload starts with an explicit IV
                // (16 bytes for AES), followed by the ciphertext.
                let iv_len = write_iv.len(); // 16 for AES-CBC
                if record.payload.len() <= iv_len {
                    continue;
                }
                let explicit_iv = &record.payload[..iv_len];
                let ciphertext = &record.payload[iv_len..];
                self.crypto
                    .aes_cbc_decrypt(write_key, explicit_iv, ciphertext)
            } else {
                // GCM (TLS 1.3 or 1.2 GCM): IV XOR sequence number
                let mut nonce = write_iv.clone();
                let seq_bytes = seq.to_be_bytes();
                let offset = nonce.len().saturating_sub(seq_bytes.len());
                for (i, &b) in seq_bytes.iter().enumerate() {
                    if offset + i < nonce.len() {
                        nonce[offset + i] ^= b;
                    }
                }
                let aad = build_record_aad(record);
                self.crypto
                    .aes_gcm_decrypt(write_key, &nonce, &aad, &record.payload)
            };

            if let Ok(mut plaintext) = decrypt_result {
                if !is_cbc {
                    // TLS 1.3: strip inner content type and zero padding
                    strip_tls13_padding(&mut plaintext);
                }

                // Update direction tracking and sequence number
                if session.client_addr.is_none() {
                    session.client_addr = Some(if is_client_to_server {
                        src_addr
                    } else {
                        dst_addr
                    });
                }

                if is_client_to_server {
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
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
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
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
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
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
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
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
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

    #[test]
    fn ensure_sessions_populated_idempotent() {
        // First call should process all entries; second call should be a no-op.
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: None,
            }),
            decrypted_count: 0,
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
        };

        // First call: should create sessions
        d.ensure_sessions_populated();
        assert_eq!(d.sessions.len(), 1);
        assert_eq!(
            d.keylog_processed_count,
            d.keylog_entries.len(),
            "processed count must match entry count after first call"
        );

        let sessions_after_first = d.sessions.len();
        let processed_after_first = d.keylog_processed_count;

        // Second call: should be a no-op (early return because
        // keylog_entries.len() == keylog_processed_count)
        d.ensure_sessions_populated();
        assert_eq!(
            d.sessions.len(),
            sessions_after_first,
            "session count must not change on second call"
        );
        assert_eq!(
            d.keylog_processed_count, processed_after_first,
            "processed count must not change on second call"
        );
    }

    #[test]
    fn ensure_sessions_populated_processes_incremental_entries() {
        // Verify that adding new keylog entries after the first populate
        // causes a second call to process only the new entries.
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(), // 2 entries, same client_random
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: None,
            }),
            decrypted_count: 0,
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
        };

        d.ensure_sessions_populated();
        assert_eq!(d.sessions.len(), 1);
        assert_eq!(d.keylog_processed_count, 2);

        // Add entries with a different client_random
        let cr2 = [0xBBu8; 32];
        d.keylog_entries.push(KeyLogEntry {
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            client_random: cr2.to_vec(),
            secret: vec![0x33u8; 32],
        });
        d.keylog_entries.push(KeyLogEntry {
            label: "SERVER_TRAFFIC_SECRET_0".to_string(),
            client_random: cr2.to_vec(),
            secret: vec![0x44u8; 32],
        });

        // Now keylog_entries.len() (4) != keylog_processed_count (2),
        // so ensure_sessions_populated should process the new entries.
        d.ensure_sessions_populated();
        assert_eq!(d.sessions.len(), 2, "should now have 2 sessions");
        assert_eq!(
            d.keylog_processed_count, 4,
            "processed count should reflect all entries"
        );
    }
}
