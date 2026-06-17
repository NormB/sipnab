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
use crate::capture::rsa_key::RsaKey;
use crate::crypto::CryptoBackend;

/// Accumulated TLS 1.2 RSA-key-exchange handshake state for `--tls-key`.
///
/// Records arrive in wire order; we collect the ClientHello `client_random`,
/// the ServerHello `server_random` + negotiated cipher, and finally the
/// `ClientKeyExchange` RSA-encrypted pre-master. When all are present we
/// recover the master secret and derive the session keys. This pairs the
/// fields of a single handshake; interleaved concurrent RSA handshakes in one
/// capture cannot be correlated from the wire (a passive-analysis limitation).
struct RsaHandshakeState {
    /// The server's RSA private key.
    key: RsaKey,
    /// `client_random` from the most recent ClientHello.
    client_random: Option<[u8; 32]>,
    /// `server_random` from the most recent ServerHello.
    server_random: Option<[u8; 32]>,
    /// Negotiated cipher suite code point from the ServerHello.
    cipher: Option<u16>,
}

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

    /// IV (nonce) length in bytes — the full TLS 1.3 per-record nonce width.
    fn iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
            Self::Aes128CbcSha => 16,
            Self::Aes256CbcSha256 => 16,
        }
    }

    /// Fixed (implicit) IV length carried in the TLS 1.2 key block. For GCM this
    /// is the 4-byte salt (RFC 5288); the remaining 8 nonce bytes are the
    /// explicit per-record nonce. CBC uses a full 16-byte IV.
    fn tls12_fixed_iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 4,
            Self::Aes128CbcSha | Self::Aes256CbcSha256 => 16,
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

/// TLS record-layer version for a session — selects the AEAD record framing.
///
/// TLS 1.2 GCM (RFC 5246 §6.2.3.3, RFC 5288): a 4-byte fixed (implicit) IV plus
/// an 8-byte explicit nonce carried in each record, with a 13-byte AAD that
/// includes the 64-bit sequence number. TLS 1.3 (RFC 8446 §5.2): a 12-byte
/// per-record nonce derived as `write_iv XOR seq`, a 5-byte AAD, and an inner
/// content-type byte appended to the plaintext.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SessionVersion {
    Tls12,
    Tls13,
}

/// Derived per-direction key material for a TLS session.
struct TlsSession {
    /// Record-layer version (TLS 1.2 vs 1.3 AEAD framing).
    version: SessionVersion,
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
pub(crate) fn tls12_prf(
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
    // TLS 1.2 key block uses the fixed/implicit IV width (4 bytes for GCM),
    // not the full 12-byte TLS 1.3 nonce.
    let iv_len = suite.tls12_fixed_iv_len();

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

/// Extract `client_random` (32 bytes) from a ClientHello handshake message.
///
/// Layout mirrors ServerHello: `msg_type(1)=1 ‖ length(3) ‖ version(2) ‖
/// random(32) ‖ …`, so the random sits at offset 6..38.
fn parse_client_hello_random(handshake_data: &[u8]) -> Option<[u8; 32]> {
    if handshake_data.len() < 38 || handshake_data[0] != 1 {
        return None;
    }
    let mut cr = [0u8; 32];
    cr.copy_from_slice(&handshake_data[6..38]);
    Some(cr)
}

/// Extract the RSA-encrypted pre-master secret from a TLS 1.2 ClientKeyExchange.
///
/// Layout: `msg_type(1)=16 ‖ length(3) ‖ EncryptedPreMasterSecret`, where the
/// `EncryptedPreMasterSecret` is itself `uint16 length ‖ opaque[length]`
/// (RFC 5246 §7.4.7.1). Returns the ciphertext bytes.
fn parse_client_key_exchange_rsa(handshake_data: &[u8]) -> Option<&[u8]> {
    if handshake_data.len() < 6 || handshake_data[0] != 16 {
        return None;
    }
    let body = &handshake_data[4..];
    let ct_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let ct = body.get(2..2 + ct_len)?;
    Some(ct)
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
    /// RSA private-key handshake state (`--tls-key`); `None` unless a key is set.
    rsa: Option<RsaHandshakeState>,
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
            tracing::info!("Loaded {} keylog entries", entry_count);
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
            rsa: None,
        })
    }

    /// Return the number of loaded keylog entries.
    pub fn keylog_entry_count(&self) -> usize {
        self.keylog_entries.len()
    }

    /// Install an RSA private key (`--tls-key`) to recover the pre-master secret
    /// of TLS 1.2 RSA-key-exchange handshakes observed on the wire. Only non-PFS
    /// RSA suites are decryptable this way; ECDHE/DHE handshakes are unaffected.
    pub fn set_rsa_key(&mut self, key: RsaKey) {
        self.rsa = Some(RsaHandshakeState {
            key,
            client_random: None,
            server_random: None,
            cipher: None,
        });
    }

    /// Whether an RSA private key has been installed.
    pub fn has_rsa_key(&self) -> bool {
        self.rsa.is_some()
    }

    /// Ingest NSS Key Log text into the decryptor — e.g. secrets extracted from
    /// a pcapng Decryption Secrets Block. Parses one entry per line, skipping
    /// blanks, `#` comments, and any malformed line (untrusted-input safe).
    /// Returns the number of valid entries added.
    pub fn add_keylog_text(&mut self, text: &str) -> usize {
        let before = self.keylog_entries.len();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Malformed lines are skipped (DSB content may be untrusted).
            if let Ok(entry) = super::tls::parse_keylog_line(line) {
                self.keylog_entries.push(entry);
            }
        }
        self.keylog_entries.len() - before
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

        // Open the file FIRST, then stat the fd — prevents TOCTOU symlink race
        // where an attacker could swap the file between stat() and open().
        use std::io::{Read, Seek, SeekFrom};
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("Failed to open keylog file: {e}");
                return Ok(0);
            }
        };

        let current_size = file.metadata()?.len();
        if current_size <= self.last_keylog_size {
            return Ok(0);
        }

        // Read from where we left off
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
                    tracing::debug!("Skipping invalid keylog line: {e}");
                }
            }
        }

        self.last_keylog_size = current_size;

        if new_count > 0 {
            // Clear sessions cache so new entries are picked up
            self.sessions.clear();
            tracing::info!("Keylog watch: loaded {new_count} new key(s)");
        }

        Ok(new_count)
    }

    /// Count the entries in a DTLS keylog file (NSS `SSLKEYLOGFILE` format).
    ///
    /// DTLS-SRTP key extraction itself is performed by
    /// [`DtlsSrtpExtractor`](crate::capture::dtls::DtlsSrtpExtractor), which runs
    /// the RFC 5764 exporter over these entries. This helper is retained for a
    /// quick validity/count check of the keylog file.
    ///
    /// Returns the number of entries loaded.
    pub fn load_dtls_keylog(path: &Path) -> Result<usize> {
        let entries = parse_keylog_file(path)
            .with_context(|| format!("Loading DTLS keylog from {}", path.display()))?;
        let count = entries.len();
        if count > 0 {
            tracing::info!("DTLS keys loaded: {count} entries from {}", path.display());
        } else {
            tracing::info!(
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
        if record.content_type != TlsContentType::Handshake {
            return;
        }
        // Dispatch on the first handshake message's type. Handshake messages are
        // parsed from offset 0 (tolerating trailing coalesced messages like
        // Certificate/ServerHelloDone), matching `parse_server_hello`.
        match record.payload.first() {
            // ClientHello — capture client_random for RSA key exchange.
            Some(1) => {
                if let Some(cr) = parse_client_hello_random(&record.payload)
                    && let Some(rsa) = self.rsa.as_mut()
                {
                    rsa.client_random = Some(cr);
                }
            }
            // ServerHello — server_random + negotiated cipher.
            Some(2) => {
                if let Some(info) = parse_server_hello(&record.payload) {
                    tracing::debug!(
                        "Observed ServerHello: cipher=0x{:04X}",
                        info.cipher_suite_code.unwrap_or(0)
                    );
                    if let Some(rsa) = self.rsa.as_mut() {
                        rsa.server_random = info.server_random;
                        rsa.cipher = info.cipher_suite_code;
                    }
                    self.observed_handshakes.push(info);
                    // Clear sessions so they get re-derived with the new handshake info
                    self.sessions.clear();
                }
            }
            // ClientKeyExchange — RSA-encrypted pre-master; derive the session.
            Some(16) => {
                if self.rsa.is_some()
                    && let Some(ct) = parse_client_key_exchange_rsa(&record.payload)
                    && let Some((skey, session)) = self.derive_rsa_session(ct)
                {
                    tracing::info!(
                        "TLS RSA session ready [session={}, cipher={}]",
                        hex_id(&skey.client_random),
                        session.cipher_suite
                    );
                    self.sessions.insert(skey, session);
                }
            }
            _ => {}
        }
    }

    /// Recover a TLS 1.2 session from the RSA-encrypted pre-master secret using
    /// the installed private key and the captured client/server randoms.
    /// Returns the derived session keyed by `client_random`, or `None` if the
    /// handshake state is incomplete, the suite is unsupported, or decryption
    /// fails. Classic (non-extended) master-secret derivation only — handshakes
    /// negotiating Extended Master Secret (RFC 7627) will not decrypt.
    fn derive_rsa_session(&self, premaster_ct: &[u8]) -> Option<(TlsSessionKey, TlsSession)> {
        let rsa = self.rsa.as_ref()?;
        let cr = rsa.client_random?;
        let sr = rsa.server_random?;
        let suite = CipherSuite::from_code_point(rsa.cipher?)?;

        let pm = match rsa.key.decrypt_premaster(premaster_ct) {
            Ok(pm) => pm,
            Err(e) => {
                tracing::debug!("RSA pre-master decryption failed: {e}");
                return None;
            }
        };
        if pm.len() != 48 {
            tracing::debug!("RSA pre-master has unexpected length {}", pm.len());
            return None;
        }

        // master_secret = PRF(pre_master, "master secret", client_random ‖ server_random)[..48]
        let seed = [cr.as_slice(), sr.as_slice()].concat();
        let master = tls12_prf(self.crypto.as_ref(), &pm, b"master secret", &seed, 48).ok()?;
        let (ck, sk, civ, siv) =
            derive_tls12_keys(self.crypto.as_ref(), &master, &cr, &sr, suite).ok()?;

        Some((
            TlsSessionKey { client_random: cr },
            TlsSession {
                version: SessionVersion::Tls12,
                client_write_key: ck,
                server_write_key: sk,
                client_write_iv: civ,
                server_write_iv: siv,
                cipher_suite: suite,
                sequence_client: 0,
                sequence_server: 0,
                client_addr: None,
            },
        ))
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
                    tracing::info!(
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
                        tracing::debug!(
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
                        tracing::info!(
                            "TLS session ready [session={}, cipher={}]",
                            hex_id(cr),
                            suite
                        );
                        self.sessions.insert(
                            session_key.clone(),
                            TlsSession {
                                version: SessionVersion::Tls13,
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
                        tracing::debug!("Failed to derive keys for session {}: {e}", hex_id(cr));
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
                        tracing::debug!(
                            "Unsupported TLS 1.2 cipher suite 0x{:04X} for session {}",
                            cipher_code,
                            hex_id(cr)
                        );
                        continue;
                    };

                    match derive_tls12_keys(self.crypto.as_ref(), ms, cr, &server_random, suite) {
                        Ok((ck, sk, civ, siv)) => {
                            tracing::info!(
                                "TLS 1.2 session ready [session={}, cipher={}]",
                                hex_id(cr),
                                suite
                            );
                            self.sessions.insert(
                                session_key.clone(),
                                TlsSession {
                                    version: SessionVersion::Tls12,
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
                            tracing::debug!(
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

        // Refuse TLS 1.2 CBC: those suites are MAC-then-encrypt and we do not
        // verify the record MAC, so emitting CBC plaintext would surface
        // unauthenticated data — a crafted capture could inject forged
        // "decrypted" SIP. AEAD suites (AES-GCM), which are authenticated by
        // `ring`'s `open_in_place`, remain fully supported.
        if session.cipher_suite.is_cbc() {
            tracing::debug!(
                "TLS 1.2 CBC record not decrypted (suite {:?}): MAC verification \
                 unsupported; refusing to emit unauthenticated plaintext",
                session.cipher_suite
            );
            return None;
        }

        let version = session.version;

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

            // Decrypt with the per-version AEAD framing. On success both paths
            // return (plaintext, matched_seq) so the per-direction counter can
            // resync — important for TLS 1.2, where the encrypted Finished is a
            // Handshake record we never see, leaving the app-data counter offset.
            let decrypted: Option<(Vec<u8>, u64)> = match version {
                SessionVersion::Tls13 => {
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
                        .ok()
                        .map(|mut pt| {
                            // TLS 1.3: strip inner content type and zero padding.
                            strip_tls13_padding(&mut pt);
                            (pt, seq)
                        })
                }
                SessionVersion::Tls12 => {
                    decrypt_tls12_gcm_record(self.crypto.as_ref(), write_key, write_iv, seq, record)
                }
            };

            if let Some((plaintext, used_seq)) = decrypted {
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
                        s.sequence_client = used_seq + 1;
                    }
                } else if let Some(s) = self.sessions.get_mut(session_key) {
                    s.sequence_server = used_seq + 1;
                }

                return Some(plaintext);
            }
        }

        None
    }
}

/// Decrypt a TLS 1.2 AES-GCM record (RFC 5246 §6.2.3.3, RFC 5288).
///
/// The record payload is `explicit_nonce(8) ‖ ciphertext ‖ tag(16)`. The AEAD
/// nonce is `fixed_iv(4) ‖ explicit_nonce(8)` and the additional data is
/// `seq_num(8) ‖ type(1) ‖ version(2) ‖ plaintext_len(2)`.
///
/// Because the encrypted Finished message (a Handshake record) is never offered
/// to this decryptor, the application-data sequence counter can be offset; we
/// search a small forward window of sequence numbers. GCM's tag authenticates
/// the choice, so only the correct sequence yields plaintext. Returns
/// `(plaintext, matched_seq)` on success.
fn decrypt_tls12_gcm_record(
    crypto: &dyn CryptoBackend,
    write_key: &[u8],
    fixed_iv: &[u8],
    seq_start: u64,
    record: &TlsRecord,
) -> Option<(Vec<u8>, u64)> {
    const EXPLICIT_NONCE_LEN: usize = 8;
    const TAG_LEN: usize = 16;
    if fixed_iv.len() < 4 || record.payload.len() < EXPLICIT_NONCE_LEN + TAG_LEN {
        return None;
    }

    let explicit_nonce = &record.payload[..EXPLICIT_NONCE_LEN];
    let aead_input = &record.payload[EXPLICIT_NONCE_LEN..]; // ciphertext ‖ tag
    let plaintext_len = (aead_input.len() - TAG_LEN) as u16;

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&fixed_iv[..4]);
    nonce[4..].copy_from_slice(explicit_nonce);

    // Content type + record version come from the 5-byte TLS 1.3-style header
    // helper (it computes the same type/version bytes we need here).
    let hdr = build_record_aad(record);
    let content_type = hdr[0];
    let version = u16::from_be_bytes([hdr[1], hdr[2]]);

    // Bounded sequence-number search to resync past unseen encrypted records.
    const SEQ_WINDOW: u64 = 16;
    for seq in seq_start..=seq_start.saturating_add(SEQ_WINDOW) {
        let aad = build_tls12_gcm_aad(seq, content_type, version, plaintext_len);
        if let Ok(pt) = crypto.aes_gcm_decrypt(write_key, &nonce, &aad, aead_input) {
            return Some((pt, seq));
        }
    }
    None
}

/// Build the 13-byte TLS 1.2 AEAD additional data: `seq(8) ‖ type(1) ‖
/// version(2) ‖ plaintext_len(2)` (RFC 5246 §6.2.3.3).
fn build_tls12_gcm_aad(seq: u64, content_type: u8, version: u16, plaintext_len: u16) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = content_type;
    aad[9..11].copy_from_slice(&version.to_be_bytes());
    aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
    aad
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

/// Load any TLS Key Log secrets embedded in the pcapng at `path` (Decryption
/// Secrets Blocks) into `decryptor`, so a self-contained capture decrypts
/// without an external `--keylog`. Returns the number of keylog entries added;
/// a no-op (0) for non-pcapng files or files without a TLS DSB.
#[cfg(feature = "native")]
pub fn feed_embedded_secrets(path: &Path, decryptor: &mut TlsDecryptor) -> usize {
    match crate::capture::pcapng_meta::read_pcapng_metadata(path) {
        Ok(meta) => meta
            .tls_secrets
            .iter()
            .map(|s| decryptor.add_keylog_text(s))
            .sum(),
        Err(_) => 0,
    }
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
            rsa: None,
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
            rsa: None,
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
            rsa: None,
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
            rsa: None,
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

    // ── --tls-key RSA key exchange end-to-end ──────────────────────────

    #[cfg(feature = "tls")]
    const RSA_KEY_PEM: &str = include_str!("../../tests/fixtures/tls_rsa/key.pem");
    #[cfg(feature = "tls")]
    const RSA_PREMASTER_CT: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster_ct.bin");
    #[cfg(feature = "tls")]
    const RSA_PREMASTER: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster.bin");

    /// A ClientHello handshake record carrying `client_random`.
    fn client_hello_record(client_random: &[u8; 32]) -> TlsRecord {
        let mut hs = vec![1u8, 0, 0, 0, 0x03, 0x03]; // type=ClientHello, len, version
        hs.extend_from_slice(client_random);
        hs.push(0); // session_id length
        TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: hs.len() as u16,
            payload: hs,
        }
    }

    /// A ClientKeyExchange record wrapping the RSA-encrypted pre-master.
    fn client_key_exchange_record(ct: &[u8]) -> TlsRecord {
        let mut hs = vec![16u8]; // type = ClientKeyExchange
        let body_len = 2 + ct.len();
        hs.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        hs.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        hs.extend_from_slice(ct);
        TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: hs.len() as u16,
            payload: hs,
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_key_rsa_handshake_decrypts_tls12_gcm_appdata() {
        use crate::crypto::RingCryptoBackend;
        use ring::aead;

        let client_random = [0xAAu8; 32];
        // server_hello(0x009C, 0) advertises TLS_RSA_WITH_AES_128_GCM_SHA256
        // with server_random = [0x5A; 32].
        let server_random = [0x5Au8; 32];
        let suite = CipherSuite::Aes128Gcm;

        // Independently derive the session keys from the known fixture premaster,
        // mirroring what the decryptor will compute from the RSA ciphertext.
        let backend = RingCryptoBackend;
        let seed = [client_random.as_slice(), server_random.as_slice()].concat();
        let master = tls12_prf(&backend, RSA_PREMASTER, b"master secret", &seed, 48).unwrap();
        let (client_write_key, _swk, client_write_iv, _swiv) =
            derive_tls12_keys(&backend, &master, &client_random, &server_random, suite).unwrap();
        assert_eq!(client_write_iv.len(), 4, "TLS 1.2 GCM fixed IV is 4 bytes");

        // Encrypt a SIP message as a TLS 1.2 AES-128-GCM ApplicationData record
        // (client→server, seq 0): payload = explicit_nonce(8) ‖ ciphertext ‖ tag.
        let sip = b"REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/TLS\r\n\r\n".to_vec();
        let explicit_nonce = [0x11u8; 8];
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&client_write_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let aad = build_tls12_gcm_aad(0, 23, 0x0303, sip.len() as u16);

        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &client_write_key).unwrap();
        let sealing = aead::LessSafeKey::new(unbound);
        let mut in_out = sip.clone();
        sealing
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad),
                &mut in_out,
            )
            .unwrap();
        let mut rec_payload = explicit_nonce.to_vec();
        rec_payload.extend_from_slice(&in_out);
        let appdata = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: rec_payload.len() as u16,
            payload: rec_payload,
        };

        // Build the decryptor with the RSA private key and feed the handshake.
        let mut d = TlsDecryptor::new(None, Box::new(RingCryptoBackend)).unwrap();
        d.set_rsa_key(RsaKey::from_pem(RSA_KEY_PEM).unwrap());
        assert!(d.has_rsa_key());

        d.process_record(&client_hello_record(&client_random));
        d.process_record(&server_hello_record(0x009C));
        d.process_record(&client_key_exchange_record(RSA_PREMASTER_CT));

        // The RSA session must now decrypt the application data back to the SIP.
        let client = "10.0.0.1".parse().unwrap();
        let server = "10.0.0.2".parse().unwrap();
        let out = d
            .try_decrypt(&appdata, client, server)
            .expect("RSA-derived decrypt");
        assert_eq!(
            out, sip,
            "decrypted ApplicationData must equal the SIP message"
        );
        assert_eq!(d.decrypted_count, 1);
    }

    /// A ServerHello carried in a real TLS record (wraps `server_hello`).
    fn server_hello_record(cipher: u16) -> TlsRecord {
        TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 0,
            payload: server_hello(cipher, 0),
        }
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
            rsa: None,
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
            rsa: None,
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

    // ── helpers for the added tests ────────────────────────────────────

    /// A decryptor wrapping `crypto` with no keylog file and empty state.
    fn decryptor_with(crypto: Box<dyn CryptoBackend>) -> TlsDecryptor {
        TlsDecryptor {
            keylog_entries: Vec::new(),
            sessions: HashMap::new(),
            crypto,
            decrypted_count: 0,
            keylog_path: None,
            last_keylog_size: 0,
            observed_handshakes: Vec::new(),
            keylog_processed_count: 0,
            rsa: None,
        }
    }

    const CLIENT_RANDOM_LINE: &str = "CLIENT_RANDOM \
        aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd \
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn add_keylog_text_ingests_valid_lines_skips_junk() {
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        assert_eq!(d.keylog_entry_count(), 0);
        let text = format!("# comment\n\n{CLIENT_RANDOM_LINE}\nthis is not a keylog line\n");
        let added = d.add_keylog_text(&text);
        assert_eq!(added, 1, "one valid entry; comment/blank/junk skipped");
        assert_eq!(d.keylog_entry_count(), 1);
    }

    #[test]
    fn add_keylog_text_empty_or_all_junk_adds_nothing() {
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        assert_eq!(d.add_keylog_text(""), 0);
        assert_eq!(d.add_keylog_text("# only a comment\ngarbage line\n"), 0);
        assert_eq!(d.keylog_entry_count(), 0);
    }

    #[cfg(feature = "native")]
    #[test]
    fn feed_embedded_secrets_loads_dsb_into_decryptor() {
        use crate::capture::{PcapExportMode, PcapWriter};
        let dir = tempfile::tempdir().unwrap();
        let keylog = dir.path().join("k.txt");
        std::fs::write(&keylog, format!("{CLIENT_RANDOM_LINE}\n")).unwrap();
        let path = dir.path().join("withdsb.pcapng");
        {
            let mut w = PcapWriter::with_format(
                &path,
                1,
                None,
                None,
                true,
                PcapExportMode::EncryptedWithDsb,
            )
            .unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();
            w.finish().unwrap();
        }
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        let added = super::feed_embedded_secrets(&path, &mut d);
        assert_eq!(
            added, 1,
            "the embedded DSB secret should reach the decryptor"
        );
        assert_eq!(d.keylog_entry_count(), 1);
    }

    #[cfg(feature = "native")]
    #[test]
    fn feed_embedded_secrets_no_dsb_is_noop() {
        use crate::capture::{PcapExportMode, PcapWriter};
        // A pcapng with no DSB → nothing fed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.pcapng");
        PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw)
            .unwrap()
            .finish()
            .unwrap();
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        assert_eq!(super::feed_embedded_secrets(&path, &mut d), 0);
    }

    /// A minimal but well-formed ServerHello handshake payload advertising
    /// `cipher_code`, with a `session_id_len`-byte session id.
    fn server_hello(cipher_code: u16, session_id_len: u8) -> Vec<u8> {
        let mut hs = vec![2u8, 0, 0, 0]; // msg_type=ServerHello + 3-byte length
        hs.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        hs.extend_from_slice(&[0x5Au8; 32]); // server_random
        hs.push(session_id_len);
        hs.extend(std::iter::repeat_n(0xCDu8, session_id_len as usize));
        hs.extend_from_slice(&cipher_code.to_be_bytes());
        hs.push(0); // compression method
        hs
    }

    // ── CipherSuite table ──────────────────────────────────────────────

    #[test]
    fn cipher_suite_properties() {
        use CipherSuite::*;
        // (suite, key_len, iv_len, mac_key_len, is_cbc, display)
        let table = [
            (Aes128Gcm, 16, 12, 0, false, "TLS_AES_128_GCM_SHA256"),
            (Aes256Gcm, 32, 12, 0, false, "TLS_AES_256_GCM_SHA384"),
            (
                Aes128CbcSha,
                16,
                16,
                20,
                true,
                "TLS_RSA_WITH_AES_128_CBC_SHA",
            ),
            (
                Aes256CbcSha256,
                32,
                16,
                32,
                true,
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
            ),
        ];
        for (suite, kl, il, ml, cbc, disp) in table {
            assert_eq!(suite.key_len(), kl, "{disp} key_len");
            assert_eq!(suite.iv_len(), il, "{disp} iv_len");
            assert_eq!(suite.mac_key_len(), ml, "{disp} mac_key_len");
            assert_eq!(suite.is_cbc(), cbc, "{disp} is_cbc");
            assert_eq!(format!("{suite}"), disp);
        }
    }

    #[test]
    fn cipher_suite_from_code_point_all_known_and_unknown() {
        use CipherSuite::*;
        let known = [
            (0x009Cu16, Aes128Gcm),
            (0x009D, Aes256Gcm),
            (0x1301, Aes128Gcm),
            (0x1302, Aes256Gcm),
            (0x002F, Aes128CbcSha),
            (0x003C, Aes128CbcSha),
            (0x003D, Aes256CbcSha256),
            (0x0035, Aes256CbcSha256),
        ];
        for (code, expected) in known {
            assert_eq!(CipherSuite::from_code_point(code), Some(expected));
        }
        for code in [0x0000u16, 0x1303, 0xFFFF, 0x00FF] {
            assert!(CipherSuite::from_code_point(code).is_none());
        }
    }

    // ── parse_server_hello ─────────────────────────────────────────────

    #[test]
    fn parse_server_hello_valid() {
        let info = parse_server_hello(&server_hello(0x009C, 0)).unwrap();
        assert_eq!(info.server_random, Some([0x5Au8; 32]));
        assert_eq!(info.cipher_suite_code, Some(0x009C));

        // With a non-empty session id, the cipher offset shifts accordingly.
        let info = parse_server_hello(&server_hello(0x1302, 32)).unwrap();
        assert_eq!(info.cipher_suite_code, Some(0x1302));
    }

    #[test]
    fn parse_server_hello_rejects_malformed() {
        assert!(parse_server_hello(&[]).is_none()); // < 4 bytes
        assert!(parse_server_hello(&[1, 0, 0, 0]).is_none()); // msg_type != 2 (ClientHello)
        // ServerHello type but truncated before the 32-byte random.
        assert!(parse_server_hello(&[2, 0, 0, 0, 0x03, 0x03, 0, 0]).is_none());
        // Long enough for the random, but session_id_len pushes cipher past the end.
        let mut hs = server_hello(0x009C, 0);
        hs[38] = 200; // session_id_len far beyond the buffer
        assert!(parse_server_hello(&hs).is_none());
    }

    // ── process_record ─────────────────────────────────────────────────

    #[test]
    fn process_record_observes_serverhello_and_ignores_others() {
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));

        // A Handshake record carrying a ServerHello is observed.
        let rec = TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 0,
            payload: server_hello(0x009C, 0),
        };
        d.process_record(&rec);
        assert_eq!(d.observed_handshakes.len(), 1);

        // A non-Handshake record is ignored.
        let rec = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 0,
            payload: vec![0u8; 8],
        };
        d.process_record(&rec);
        assert_eq!(d.observed_handshakes.len(), 1);
    }

    // ── TLS 1.2 CLIENT_RANDOM key derivation ───────────────────────────

    #[test]
    fn tls12_client_random_derives_session() {
        let cr = [0x77u8; 32];
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        d.keylog_entries.push(KeyLogEntry {
            label: "CLIENT_RANDOM".to_string(),
            client_random: cr.to_vec(),
            secret: vec![0x01u8; 48], // 48-byte master secret
        });

        // Observe a ServerHello negotiating an AES-128-GCM TLS 1.2 suite.
        d.process_record(&TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 0,
            payload: server_hello(0x009C, 0),
        });

        d.ensure_sessions_populated();
        let key = TlsSessionKey { client_random: cr };
        let session = d.sessions.get(&key).expect("TLS 1.2 session derived");
        assert_eq!(session.cipher_suite, CipherSuite::Aes128Gcm);
        // TLS 1.2 AES-128-GCM: 16-byte key, 4-byte fixed (implicit) IV.
        assert_eq!(session.client_write_key.len(), 16);
        assert_eq!(session.client_write_iv.len(), 4);
    }

    #[test]
    fn tls12_client_random_derives_cbc_session() {
        let cr = [0x88u8; 32];
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        d.keylog_entries.push(KeyLogEntry {
            label: "CLIENT_RANDOM".to_string(),
            client_random: cr.to_vec(),
            secret: vec![0x02u8; 48],
        });
        // CBC suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F).
        d.process_record(&TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 0,
            payload: server_hello(0x002F, 0),
        });
        d.ensure_sessions_populated();
        let session = d
            .sessions
            .get(&TlsSessionKey { client_random: cr })
            .expect("CBC session derived");
        assert_eq!(session.cipher_suite, CipherSuite::Aes128CbcSha);
        assert_eq!(session.client_write_iv.len(), 16);
    }

    #[test]
    fn tls12_unsupported_cipher_yields_no_session() {
        let cr = [0x99u8; 32];
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        d.keylog_entries.push(KeyLogEntry {
            label: "CLIENT_RANDOM".to_string(),
            client_random: cr.to_vec(),
            secret: vec![0x03u8; 48],
        });
        // 0x0000 is not a supported suite -> from_code_point returns None.
        d.process_record(&TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 0,
            payload: server_hello(0x0000, 0),
        });
        d.ensure_sessions_populated();
        assert!(d.sessions.is_empty());
    }

    // ── CBC decryption path ────────────────────────────────────────────

    /// Crypto backend that succeeds for CBC and fails for GCM.
    struct CbcMock;
    impl CryptoBackend for CbcMock {
        fn aes_gcm_decrypt(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("no gcm")
        }
        fn aes_cbc_decrypt(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            Ok(b"MESSAGE sip:bob@example.com SIP/2.0\r\n\r\n".to_vec())
        }
        fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("n/a")
        }
        fn hkdf_expand(&self, _: &[u8], _: &[u8], len: usize) -> Result<Vec<u8>> {
            Ok(vec![0u8; len])
        }
    }

    fn insert_cbc_session(d: &mut TlsDecryptor, key: &TlsSessionKey) {
        d.sessions.insert(
            key.clone(),
            TlsSession {
                version: SessionVersion::Tls12,
                client_write_key: vec![0u8; 16],
                server_write_key: vec![0u8; 16],
                client_write_iv: vec![0u8; 16],
                server_write_iv: vec![0u8; 16],
                cipher_suite: CipherSuite::Aes128CbcSha,
                sequence_client: 0,
                sequence_server: 0,
                client_addr: None,
            },
        );
    }

    #[test]
    fn cbc_record_refused_not_emitted_unauthenticated() {
        // TLS 1.2 CBC is MAC-then-encrypt; without verifying the record MAC we
        // must not surface (possibly forged) plaintext. The decryptor refuses
        // even when the underlying CBC primitive would return bytes.
        let key = TlsSessionKey {
            client_random: [0x10u8; 32],
        };
        let mut d = decryptor_with(Box::new(CbcMock));
        insert_cbc_session(&mut d, &key);

        let record = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 48,
            payload: vec![0xABu8; 48],
        };
        let out = d.try_decrypt(
            &record,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        );
        assert!(
            out.is_none(),
            "CBC plaintext must not be emitted unverified"
        );
        assert_eq!(d.decrypted_count, 0, "no record counted as decrypted");
    }

    #[test]
    fn cbc_record_too_short_for_iv_returns_none() {
        let key = TlsSessionKey {
            client_random: [0x20u8; 32],
        };
        let mut d = decryptor_with(Box::new(CbcMock));
        insert_cbc_session(&mut d, &key);

        // Payload <= 16-byte IV: both direction attempts hit `continue`.
        let record = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 8,
            payload: vec![0u8; 8],
        };
        assert!(
            d.try_decrypt(
                &record,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            )
            .is_none()
        );
    }

    // ── poll_keylog_file ───────────────────────────────────────────────

    #[test]
    fn poll_keylog_without_path_is_noop() {
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        assert_eq!(d.poll_keylog_file().unwrap(), 0);
    }

    #[test]
    fn poll_keylog_loads_appended_entries() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            "aa".repeat(32),
            "bb".repeat(32)
        )
        .unwrap();
        tmp.flush().unwrap();

        let mut d = TlsDecryptor::new(
            Some(tmp.path()),
            Box::new(MockCrypto {
                decrypt_result: None,
            }),
        )
        .unwrap();
        assert_eq!(d.keylog_entry_count(), 1);

        // No growth yet -> nothing new.
        assert_eq!(d.poll_keylog_file().unwrap(), 0);

        // Append a valid line and a junk line (the junk is skipped).
        writeln!(
            tmp,
            "SERVER_TRAFFIC_SECRET_0 {} {}",
            "aa".repeat(32),
            "cc".repeat(32)
        )
        .unwrap();
        writeln!(tmp, "this is not a valid keylog line").unwrap();
        tmp.flush().unwrap();

        assert_eq!(d.poll_keylog_file().unwrap(), 1, "one new valid key");
        assert_eq!(d.keylog_entry_count(), 2);
    }

    // ── load_dtls_keylog ───────────────────────────────────────────────

    #[test]
    fn load_dtls_keylog_empty_and_populated() {
        use std::io::Write;
        // Empty file -> 0 entries.
        let empty = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(TlsDecryptor::load_dtls_keylog(empty.path()).unwrap(), 0);

        // One entry.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "CLIENT_RANDOM {} {}", "aa".repeat(32), "dd".repeat(48)).unwrap();
        tmp.flush().unwrap();
        assert_eq!(TlsDecryptor::load_dtls_keylog(tmp.path()).unwrap(), 1);
    }

    // ── strip_tls13_padding edge ───────────────────────────────────────

    #[test]
    fn strip_padding_all_zeros_and_empty() {
        // All-zero record collapses to empty (content type popped, rest stripped).
        let mut data = vec![0u8; 6];
        strip_tls13_padding(&mut data);
        assert!(data.is_empty());

        // Empty input is a no-op.
        let mut empty: Vec<u8> = Vec::new();
        strip_tls13_padding(&mut empty);
        assert!(empty.is_empty());
    }

    // ── build_record_aad for other content types/versions ──────────────

    #[test]
    fn build_aad_covers_content_types_and_versions() {
        let cases = [
            (
                TlsContentType::ChangeCipherSpec,
                TlsVersion::Tls10,
                20u8,
                0x0301u16,
            ),
            (TlsContentType::Alert, TlsVersion::Tls11, 21, 0x0302),
            (TlsContentType::Handshake, TlsVersion::Tls13, 22, 0x0303),
            (
                TlsContentType::Unknown(99),
                TlsVersion::Unknown(0x7F7F),
                99,
                0x7F7F,
            ),
        ];
        for (ct, ver, want_ct, want_ver) in cases {
            let aad = build_record_aad(&TlsRecord {
                content_type: ct,
                version: ver,
                length: 5,
                payload: vec![],
            });
            assert_eq!(aad[0], want_ct);
            assert_eq!(u16::from_be_bytes([aad[1], aad[2]]), want_ver);
            assert_eq!(u16::from_be_bytes([aad[3], aad[4]]), 5);
        }
    }
}
