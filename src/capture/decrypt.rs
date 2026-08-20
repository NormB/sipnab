// SPDX-License-Identifier: MIT OR Apache-2.0

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
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use indexmap::IndexMap;

use super::tls::{KeyLogEntry, TlsContentType, TlsRecord, parse_keylog_file};
use crate::capture::rsa_key::RsaKey;
use crate::crypto::{CryptoBackend, HashAlg};

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
#[non_exhaustive]
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

    /// The hash this suite derives its key material under.
    ///
    /// TLS names it in the suite itself, and every derivation for the suite —
    /// the TLS 1.3 HKDF-Expand-Label and the TLS 1.2 PRF alike — must use it.
    /// Deriving under any other hash is not an approximation: it produces key
    /// material that decrypts nothing, and does so without an error.
    fn hash(self) -> HashAlg {
        match self {
            // ..._SHA384
            Self::Aes256Gcm => HashAlg::Sha384,
            // ..._SHA256, and the TLS 1.2 default PRF for the SHA-1 suites
            // (RFC 5246 §5: suites that predate the negotiated-PRF rule use
            // P_SHA256, not P_SHA1).
            Self::Aes128Gcm | Self::Aes128CbcSha | Self::Aes256CbcSha256 => HashAlg::Sha256,
        }
    }

    /// Try to identify a cipher suite from the TLS cipher suite code point.
    ///
    /// Only the record-layer cipher matters here — sipnab decrypts, it does not
    /// perform a handshake — so suites that differ only in key exchange or
    /// signature (RSA vs ECDHE vs DHE, RSA vs ECDSA) collapse onto the same
    /// entry. What must be right is the AEAD and the hash.
    ///
    /// The static-RSA suites below were once the whole table, which meant the
    /// suites that deployments actually negotiate were all unidentified: a
    /// TLS 1.2 ServerHello offering `ECDHE-RSA-AES256-GCM-SHA384` (0xC030,
    /// OpenSSL's default) returned `None`, so no session was built from a
    /// `CLIENT_RANDOM` keylog entry and the capture stayed opaque.
    fn from_code_point(code: u16) -> Option<Self> {
        match code {
            // TLS 1.3
            0x1301 => Some(Self::Aes128Gcm), // TLS_AES_128_GCM_SHA256
            0x1302 => Some(Self::Aes256Gcm), // TLS_AES_256_GCM_SHA384

            // TLS 1.2, ECDHE — what a modern deployment negotiates
            0xC02B => Some(Self::Aes128Gcm), // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02C => Some(Self::Aes256Gcm), // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xC02F => Some(Self::Aes128Gcm), // ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030 => Some(Self::Aes256Gcm), // ECDHE_RSA_WITH_AES_256_GCM_SHA384

            // TLS 1.2, DHE
            0x009E => Some(Self::Aes128Gcm), // DHE_RSA_WITH_AES_128_GCM_SHA256
            0x009F => Some(Self::Aes256Gcm), // DHE_RSA_WITH_AES_256_GCM_SHA384

            // TLS 1.2, static RSA
            0x009C => Some(Self::Aes128Gcm), // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D => Some(Self::Aes256Gcm), // TLS_RSA_WITH_AES_256_GCM_SHA384

            // CBC. Parsed so the gate in `try_decrypt_with_session` can refuse
            // them by name; sipnab does not verify the record MAC, so it will
            // not emit unauthenticated plaintext.
            0x002F => Some(Self::Aes128CbcSha), // TLS_RSA_WITH_AES_128_CBC_SHA
            0x003C => Some(Self::Aes128CbcSha), // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003D => Some(Self::Aes256CbcSha256), // TLS_RSA_WITH_AES_256_CBC_SHA256
            0x0035 => Some(Self::Aes256CbcSha256), // TLS_RSA_WITH_AES_256_CBC_SHA
            0xC013 => Some(Self::Aes128CbcSha), // ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014 => Some(Self::Aes256CbcSha256), // ECDHE_RSA_WITH_AES_256_CBC_SHA

            // ChaCha20-Poly1305 (0x1303, 0xCCA8, 0xCCA9) is deliberately absent:
            // the backend implements AES-GCM and AES-CBC only, so claiming the
            // suite would mean deriving key material for an AEAD that cannot be
            // opened. `None` here is reported by the caller as an unsupported
            // suite, naming the code point.
            _ => None,
        }
    }
}

impl std::fmt::Display for CipherSuite {
    /// Write the IANA cipher-suite name (e.g. `TLS_AES_128_GCM_SHA256`) for logs.
    ///
    /// # Side effects
    ///
    /// Writes to the formatter `f`.
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
    /// The 32-byte ClientHello `client_random` identifying the session.
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
    /// TLS 1.2 AEAD framing: 4-byte fixed IV + 8-byte explicit nonce, 13-byte AAD.
    Tls12,
    /// TLS 1.3 AEAD framing: 12-byte `write_iv XOR seq` nonce, 5-byte AAD, inner
    /// content-type byte.
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
    /// Whether the client-to-server direction has ever produced plaintext.
    ///
    /// Until it has, `sequence_client` is a guess (zero) rather than a count,
    /// and the wide [`SEQ_LOCKON_WINDOW`] applies instead of the narrow
    /// resync one.
    locked_client: bool,
    /// Whether the server-to-client direction has ever produced plaintext.
    locked_server: bool,
    /// Client IP address (set from the first handshake we observe).
    client_addr: Option<IpAddr>,
    /// Failed lock-on attempts on this session, which widen the next search.
    ///
    /// A wide window is free when the answer is near — the search stops at the
    /// match — and costs its full width only when there is no match at all,
    /// which is a session whose keys belong to some other connection just as
    /// often as it is a trunk the capture joined late. Starting narrow and
    /// widening keeps the first case cheap and still reaches the second within
    /// a handful of records, instead of stalling a live capture for a second
    /// on the very first packet it cannot open.
    lockon_attempts: u32,
}

impl Drop for TlsSession {
    /// Zeroize the four key/IV buffers when the session is dropped.
    ///
    /// # Side effects
    ///
    /// Overwrites `client_write_key`, `server_write_key`, `client_write_iv`, and
    /// `server_write_iv` with zeros via the `zeroize` crate (compiler cannot
    /// elide the write).
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
    let hash = suite.hash();

    let key_info = hkdf_expand_label_info(b"key", &[], suite.key_len() as u16);
    let key = crypto.hkdf_expand(secret, &key_info, suite.key_len(), hash)?;

    let iv_info = hkdf_expand_label_info(b"iv", &[], suite.iv_len() as u16);
    let iv = crypto.hkdf_expand(secret, &iv_info, suite.iv_len(), hash)?;

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
///
/// `_crypto` is unused: the PRF's HMAC-SHA256 uses `ring` directly (the
/// `CryptoBackend` trait only exposes SHA1). The parameter is retained because
/// the backend is threaded from the public `DtlsSrtpExtractor` constructors and
/// the TLS 1.2 derivation entry points down to here for API symmetry; those
/// callers cannot be changed without touching their public signatures.
pub(crate) fn tls12_prf(
    _crypto: &dyn CryptoBackend,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    output_len: usize,
    hash: HashAlg,
) -> Result<Vec<u8>> {
    let label_seed = [label, seed].concat();
    let mut result = Vec::with_capacity(output_len);

    // A(0) = seed (which is label + seed)
    let mut a = hmac_hash(secret, &label_seed, hash)?;

    while result.len() < output_len {
        // HMAC(secret, A(i) + seed)
        let input = [a.as_slice(), label_seed.as_slice()].concat();
        let p = hmac_hash(secret, &input, hash)?;
        result.extend_from_slice(&p);

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_hash(secret, &a, hash)?;
    }

    result.truncate(output_len);
    Ok(result)
}

/// HMAC under `hash`, using ring directly (the `hmac_sha1` method on
/// `CryptoBackend` is SHA-1 only).
///
/// `hash` comes from the cipher suite, never from a constant. This was fixed at
/// SHA-256, which silently derived the wrong key block for every `..._SHA384`
/// suite — including `ECDHE-RSA-AES256-GCM-SHA384`, OpenSSL's default for
/// TLS 1.2.
fn hmac_hash(key: &[u8], data: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
    use ring::hmac;
    let algorithm = match hash {
        HashAlg::Sha256 => hmac::HMAC_SHA256,
        HashAlg::Sha384 => hmac::HMAC_SHA384,
    };
    let signing_key = hmac::Key::new(algorithm, key);
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
    let key_block = tls12_prf(
        crypto,
        master_secret,
        b"key expansion",
        &seed,
        needed,
        suite.hash(),
    )?;

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
    /// The `client_random` of the ClientHello this ServerHello answers, paired
    /// in wire order by [`TlsDecryptor::process_record`]. `None` when the
    /// ClientHello was not observed (e.g. capture started mid-handshake).
    client_random: Option<[u8; 32]>,
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
        client_random: None,
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
    if handshake_data.first() != Some(&16) {
        return None;
    }
    // Body after the 4-byte handshake header (msg_type(1) + length(3)); its
    // first two bytes are the ciphertext length. Each slice is fetched with a
    // local, checked bound so the length guard and the indexing can't drift
    // apart when either is edited.
    let body = handshake_data.get(4..)?;
    let len_bytes = body.get(0..2)?;
    let ct_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    body.get(2..2 + ct_len)
}

// ---------------------------------------------------------------------------
// TlsDecryptor
// ---------------------------------------------------------------------------

/// Cap on connections with pending (unanswered) ClientHellos. When full, the
/// oldest-inserted connection is evicted so a peer opening many
/// half-handshakes cannot pin memory. Matches the HEP peer-tracking /
/// DNS-cache cap (see `MAX_DNS_CACHE_ENTRIES` in `names.rs`).
const MAX_PENDING_HANDSHAKE_CONNS: usize = 4096;

/// Cap on queued unanswered ClientHellos per connection (renegotiation-style
/// repeats); the oldest is dropped so one connection cannot pin memory either.
const MAX_PENDING_PER_CONN: usize = 32;

/// Direction-normalized TCP connection key: the 4-tuple as an ordered
/// (lower, higher) endpoint pair, so a ClientHello seen client→server and its
/// ServerHello seen server→client map to the same connection.
fn conn_key(src: SocketAddr, dst: SocketAddr) -> (SocketAddr, SocketAddr) {
    if src <= dst { (src, dst) } else { (dst, src) }
}

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
    /// ApplicationData records offered to [`TlsDecryptor::try_decrypt`].
    ///
    /// Counted whether or not they opened, because the gap between this and
    /// `decrypted_count` is the only evidence a run has that it is holding
    /// SIP it could not read. See [`crate::capture::TlsDecryptReport`].
    app_data_records: u64,
    /// Lock-on trials left for this run. See [`LOCKON_TRIAL_BUDGET`].
    lockon_budget: u64,
    /// Widest sequence search any one record may drive, before the run budget.
    ///
    /// Configurable because the right answer is a property of the deployment,
    /// not of sipnab: how far into an established connection a capture may
    /// start and still be readable. Defaults to
    /// [`crate::capture::TLS_SEQ_LOCKON_WINDOW`].
    lockon_window: u64,
    /// Path to the keylog file (for --keylog-watch polling).
    keylog_path: Option<std::path::PathBuf>,
    /// Where `--keylog-watch` reads from.
    ///
    /// This replaced a bare `last_keylog_size: u64`. Resuming by size alone
    /// could not survive a producer that truncates or replaces the file, and
    /// could not read a FIFO at all — a pipe stats as zero length however much
    /// is queued, so the freshness check returned "nothing new" forever. See
    /// [`super::keylog_source`].
    keylog_source: Option<super::keylog_source::KeylogSource>,
    /// All ServerHello infos (server_random + cipher) observed on the wire, in
    /// arrival order. Each is paired with the `client_random` of the oldest
    /// still-unanswered ClientHello (wire order), so TLS 1.2 `CLIENT_RANDOM`
    /// key derivation can bind a keylog entry to the handshake whose
    /// ClientHello random matches it exactly, falling back to unpaired
    /// handshakes only when the ClientHello was never observed.
    observed_handshakes: Vec<HandshakeInfo>,
    /// `client_random`s of observed ClientHellos not yet paired with a
    /// ServerHello, in arrival order (FIFO) per connection. Keyed by the
    /// direction-normalized 4-tuple (`conn_key`) so a ServerHello pops only
    /// its own connection's queue; bounded by `MAX_PENDING_HANDSHAKE_CONNS`
    /// (oldest-inserted connection evicted, mirroring `names.rs`).
    pending_client_randoms: IndexMap<(SocketAddr, SocketAddr), Vec<[u8; 32]>>,
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
        use super::keylog_source::KeylogSource;

        // A FIFO is never read eagerly: opening one `O_RDONLY` blocks until a
        // writer appears, so parsing "what is already there" would hang the
        // process rather than return empty. Its contents arrive through the
        // streaming source instead.
        let streaming = keylog_path.is_some_and(KeylogSource::is_fifo);

        let keylog_entries = match keylog_path {
            Some(path) if !streaming => parse_keylog_file(path)
                .with_context(|| format!("Loading keylog from {}", path.display()))?,
            _ => Vec::new(),
        };

        // A regular file was just parsed in full, so resume at its end rather
        // than delivering every entry a second time on the first poll.
        let keylog_source = match keylog_path {
            Some(path) if streaming => Some(KeylogSource::open_auto(path)?),
            Some(path) => Some(KeylogSource::open_file_at_end(path)?),
            None => None,
        };

        let entry_count = keylog_entries.len();
        if entry_count > 0 {
            tracing::info!("Loaded {} keylog entries", entry_count);
        }

        Ok(Self {
            keylog_entries,
            sessions: HashMap::new(),
            crypto,
            decrypted_count: 0,
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: keylog_path.map(|p| p.to_path_buf()),
            keylog_source,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
            keylog_processed_count: 0,
            rsa: None,
        })
    }

    /// What this decryptor has been asked to do and how much of it worked.
    ///
    /// Sessions are populated lazily from the keylog, so this reflects the
    /// state after the records seen so far — call it at the end of a run.
    #[must_use]
    pub fn report(&self) -> crate::capture::TlsDecryptReport {
        crate::capture::TlsDecryptReport {
            keylog_entries: self.keylog_entries.len(),
            sessions_with_keys: self.sessions.len(),
            app_data_records: self.app_data_records,
            decrypted_records: self.decrypted_count,
        }
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

    /// Adopt a keylog source opened elsewhere.
    ///
    /// Used for sources that must be opened while the process is still
    /// privileged — a FIFO under `/run`, or the descriptor handed to
    /// `--keylog-fd` — since by the time the decryptor is built the process may
    /// have chrooted and dropped privileges. Replaces any source already set.
    pub fn set_keylog_source(&mut self, source: super::keylog_source::KeylogSource) {
        self.keylog_source = Some(source);
    }

    /// Poll the keylog source for new entries (for `--keylog-watch`).
    ///
    /// Returns the number of new keys loaded. Never blocks, so it is safe on
    /// the sweep loop that also drives dialog expiry and output flushing.
    ///
    /// Should be called periodically (e.g., every 5 seconds).
    ///
    /// The reading lives in [`super::keylog_source::KeylogSource`]. This used
    /// to resume by comparing the file's size against the size last seen, which
    /// failed three ways: a truncating or rotating producer left the comparison
    /// permanently false so no key ever loaded again; a FIFO stats as zero
    /// length however much is queued, so a pipe loaded nothing while reporting
    /// nothing wrong; and the read ran to EOF past the size it had stat'd, so
    /// overlapping bytes were parsed twice into an unbounded `Vec`.
    pub fn poll_keylog_file(&mut self) -> Result<usize> {
        // Named before the mutable borrow below, and named at all because an
        // operator reading "the keylog was replaced" needs to know which one.
        let which = self
            .keylog_path
            .as_ref()
            .map_or_else(|| "keylog".to_string(), |p| p.display().to_string());

        let Some(ref mut source) = self.keylog_source else {
            return Ok(0);
        };

        let outcome = source.poll()?;

        if let Some(cause) = outcome.reset {
            // Say it. A capture that silently stopped loading keys is the
            // defect this replaced; one that reloaded them reports the fact.
            tracing::warn!(
                "{which} {} by its producer — reloading it from the beginning",
                match cause {
                    super::keylog_source::ResetCause::Truncated => "was truncated",
                    super::keylog_source::ResetCause::Replaced => "was replaced",
                }
            );
        }

        if outcome.lines.is_empty() {
            return Ok(0);
        }

        let new_count = self.add_keylog_text(&outcome.lines);

        if new_count > 0 {
            // Drop only TLS 1.2 sessions here, for the same reason as the
            // ServerHello handler in `process_record`: a newly-arrived
            // CLIENT_RANDOM entry can let a TLS 1.2 session that was
            // speculatively (and maybe wrongly) paired via
            // `ensure_sessions_populated`'s fallback now re-derive against
            // its real match, but TLS 1.3 sessions have nothing to
            // re-derive — they come straight from CLIENT_TRAFFIC_SECRET_0/
            // SERVER_TRAFFIC_SECRET_0 keyed by client_random alone, and
            // `ensure_sessions_populated` already skips a client_random it
            // has already derived (`if sessions.contains_key(...) { continue }`),
            // so nothing here was ever needed to "pick up" a genuinely new
            // TLS 1.3 entry either.
            //
            // This call site matters far more than the ServerHello one:
            // `--keylog-watch` polls on its own ~100ms wall-clock cadence
            // (see the sweep-loop comment on `keylog_poll_clock`), so on a
            // trunk where the keylog producer delivers a handshake's keys
            // in more than one flush, blanket-clearing here could wipe a
            // session within milliseconds of it becoming ready — often
            // before the call's own SIP INVITE had even arrived to be
            // decrypted against it. Confirmed live: a TLS 1.3 session
            // reached "ready" a few seconds after one such flush, a second
            // flush landed ~14s later (a second handshake, or the same
            // handshake's keys arriving in more than one batch), and the
            // call's SIP never decrypted — this call site's blanket clear
            // is what did it, independent of the ServerHello fix above.
            self.sessions
                .retain(|_, session| session.version != SessionVersion::Tls12);
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
    ///
    /// `src`/`dst` are the packet's transport endpoints as seen on the wire
    /// (either direction); they identify the TCP connection so ClientHello /
    /// ServerHello pairing never crosses connections.
    pub fn process_record(&mut self, record: &TlsRecord, src: SocketAddr, dst: SocketAddr) {
        if record.content_type != TlsContentType::Handshake {
            return;
        }
        let conn = conn_key(src, dst);
        // Dispatch on the first handshake message's type. Handshake messages are
        // parsed from offset 0 (tolerating trailing coalesced messages like
        // Certificate/ServerHelloDone), matching `parse_server_hello`.
        match record.payload.first() {
            // ClientHello — capture client_random for ServerHello pairing and
            // RSA key exchange.
            Some(1) => {
                if let Some(cr) = parse_client_hello_random(&record.payload) {
                    if !self.pending_client_randoms.contains_key(&conn)
                        && self.pending_client_randoms.len() >= MAX_PENDING_HANDSHAKE_CONNS
                    {
                        // Evicting here means a CLIENT_RANDOM is discarded
                        // before its ServerHello arrives, so that session never
                        // decrypts. Nothing said so: decryption simply stopped
                        // working for some sessions and not others, which reads
                        // as a bad keylog or a broken tap rather than a cap.
                        //
                        // Warned once per process; the condition persists while
                        // the tap is busy and a line per handshake would be its
                        // own flood.
                        static EVICT_WARNED: std::sync::atomic::AtomicBool =
                            std::sync::atomic::AtomicBool::new(false);
                        if !EVICT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            tracing::warn!(
                                "TLS: {MAX_PENDING_HANDSHAKE_CONNS} handshakes are already \
                                 waiting for a ServerHello, so the oldest is being dropped \
                                 before it can be paired. Sessions evicted this way never \
                                 decrypt, and the keylog is not at fault — the tap is seeing \
                                 more concurrent handshakes than sipnab tracks."
                            );
                        }
                        self.pending_client_randoms.shift_remove_index(0);
                    }
                    let queue = self.pending_client_randoms.entry(conn).or_default();
                    if queue.len() >= MAX_PENDING_PER_CONN {
                        queue.remove(0);
                    }
                    queue.push(cr);
                    if let Some(rsa) = self.rsa.as_mut() {
                        rsa.client_random = Some(cr);
                    }
                }
            }
            // ServerHello — server_random + negotiated cipher.
            Some(2) => {
                if let Some(mut info) = parse_server_hello(&record.payload) {
                    tracing::debug!(
                        "Observed ServerHello: cipher=0x{:04X}",
                        info.cipher_suite_code.unwrap_or(0)
                    );
                    if let Some(rsa) = self.rsa.as_mut() {
                        rsa.server_random = info.server_random;
                        rsa.cipher = info.cipher_suite_code;
                    }
                    // Pair with the oldest still-unanswered ClientHello of THIS
                    // connection only (per TCP connection the ClientHello
                    // precedes its ServerHello, so a per-connection FIFO binds
                    // each ServerHello to its own handshake's client_random).
                    // Cross-connection interleavings like CH1(A), CH2(B),
                    // SH2(B), SH1(A) must never cross-pair.
                    if let Some(queue) = self.pending_client_randoms.get_mut(&conn) {
                        if !queue.is_empty() {
                            info.client_random = Some(queue.remove(0));
                        }
                        if queue.is_empty() {
                            self.pending_client_randoms.shift_remove(&conn);
                        }
                    }
                    self.observed_handshakes.push(info);
                    // Drop only TLS 1.2 sessions, not TLS 1.3 ones.
                    //
                    // A TLS 1.2 session in `ensure_sessions_populated` is looked
                    // up by pairing a CLIENT_RANDOM keylog entry with a
                    // same-client_random handshake if one has been observed yet,
                    // falling back to the oldest handshake with an unknown
                    // client_random otherwise (`has_exact` above). If that
                    // CLIENT_RANDOM entry arrived and got paired via the fallback
                    // *before* this ServerHello supplied the real match, the
                    // session already in the map is bound to the wrong
                    // server_random/cipher — this ServerHello is what makes that
                    // pairing resolvable, so TLS 1.2 sessions need a chance to
                    // re-derive against it.
                    //
                    // TLS 1.3 sessions have no such ambiguity to correct:
                    // `ensure_sessions_populated`'s TLS 1.3 branch derives keys
                    // straight from CLIENT_TRAFFIC_SECRET_0/SERVER_TRAFFIC_SECRET_0
                    // keylog entries grouped by client_random alone, never
                    // consulting `observed_handshakes`. Clearing them here bought
                    // nothing — it only meant that any TLS 1.3 session already
                    // marked ready (and about to decrypt its call's actual SIP
                    // traffic) got silently destroyed the moment a second,
                    // unrelated TLS connection did its own ServerHello, e.g. a
                    // trunk that opens more than one TLS connection around the
                    // same time (a keepalive, a second concurrent call). The
                    // decrypt failure this produced looked exactly like a missing
                    // key: no error anywhere, `try_decrypt` just stopped finding
                    // a session for a client_random it had already keyed.
                    self.sessions
                        .retain(|_, session| session.version != SessionVersion::Tls12);
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
        let master = tls12_prf(
            self.crypto.as_ref(),
            &pm,
            b"master secret",
            &seed,
            48,
            suite.hash(),
        )
        .ok()?;
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
                locked_client: false,
                locked_server: false,
                lockon_attempts: 0,
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
        self.app_data_records += 1;

        // Lazily populate sessions from keylog entries
        self.ensure_sessions_populated();

        // Split the whole-`self` borrow into disjoint field references so each
        // session can be mutated in place while iterating. This replaces the
        // previous `self.sessions.keys().cloned().collect()` (a fresh Vec of
        // session keys per ApplicationData record, purely to dodge the borrow
        // checker) — `try_decrypt_with_session` now borrows one `TlsSession`
        // directly, so no key clone and no redundant map lookups remain.
        let Self {
            sessions,
            crypto,
            decrypted_count,
            lockon_budget,
            lockon_window,
            ..
        } = self;
        let lockon_window = *lockon_window;
        let crypto = crypto.as_ref();
        for (key, session) in sessions.iter_mut() {
            let cipher = session.cipher_suite;
            if let Some(plaintext) = try_decrypt_with_session(
                session,
                crypto,
                record,
                src_addr,
                dst_addr,
                lockon_budget,
                lockon_window,
            ) {
                *decrypted_count += 1;
                tracing::info!(
                    "TLS session decrypted [session={}, cipher={}]",
                    hex_id(&key.client_random),
                    cipher,
                );
                return Some(plaintext);
            }
        }

        None
    }

    /// Set how wide the sequence search may become, in records.
    ///
    /// The ceiling, not work always done: the search stops at the first
    /// candidate that authenticates, so a connection captured from its
    /// handshake costs one trial whatever this is. Zero is rejected rather
    /// than silently disabling lock-on — a capture that joined an established
    /// connection would then never decrypt, with nothing saying why.
    pub fn set_lockon_window(&mut self, records: u64) {
        if records > 0 {
            self.lockon_window = records;
        }
    }

    /// Populate sessions from keylog entries.
    /// Skips work when no new entries have been added since last call.
    fn ensure_sessions_populated(&mut self) {
        if self.keylog_entries.is_empty()
            || self.keylog_entries.len() == self.keylog_processed_count
        {
            return;
        }
        // Split the borrow into disjoint field references so the TLS 1.2
        // handshake-matching path can iterate `observed_handshakes` by reference
        // while inserting into `sessions`, without cloning the observed-handshake
        // vector on every pass (the borrow checker would otherwise reject an
        // immutable iterator over `observed_handshakes` alongside `sessions`
        // mutation while `self` is borrowed whole).
        let Self {
            keylog_entries,
            sessions,
            crypto,
            observed_handshakes,
            keylog_processed_count,
            ..
        } = self;
        *keylog_processed_count = keylog_entries.len();

        // Group entries by client_random
        let mut grouped: HashMap<[u8; 32], Vec<&KeyLogEntry>> = HashMap::new();
        for entry in keylog_entries.iter() {
            if entry.client_random.len() == 32 {
                let mut cr = [0u8; 32];
                cr.copy_from_slice(&entry.client_random);
                grouped.entry(cr).or_default().push(entry);
            }
        }

        for (cr, entries) in &grouped {
            let session_key = TlsSessionKey { client_random: *cr };
            if sessions.contains_key(&session_key) {
                continue;
            }

            // Look for TLS 1.3 traffic secrets — the LAST matching entry, not
            // the first. eCapture's own extraction hooks fire on every
            // `SSL_write` on the connection (confirmed live: its debug log
            // shows a dozen+ "mastersecret event"s for the same client_random
            // within the same handshake), not once at the point the traffic
            // secret is actually derived. An early hook firing mid-handshake
            // can log a premature snapshot under the same
            // CLIENT_TRAFFIC_SECRET_0/SERVER_TRAFFIC_SECRET_0 label before the
            // real post-handshake secret is established; taking the first
            // match locked onto that stale value permanently for the
            // connection's whole life. Confirmed live with an independent
            // reference AES-GCM decrypt (not sipnab's own code): a session
            // derived from the first-seen entry never decrypted a single real
            // record, on both a long-lived persistent connection and a
            // brand-new one — ruling out staleness-over-time and pointing
            // squarely at picking the wrong entry within one handshake.
            let client_secret = entries
                .iter()
                .rev()
                .find(|e| e.label == "CLIENT_TRAFFIC_SECRET_0")
                .map(|e| &e.secret);
            let server_secret = entries
                .iter()
                .rev()
                .find(|e| e.label == "SERVER_TRAFFIC_SECRET_0")
                .map(|e| &e.secret);

            // Two entries under one label for one client_random that DISAGREE
            // are the signature of a mid-life re-attach, and which one is right
            // is not decidable here. eCapture dedups per (label, client_random)
            // and truncates on start, so a single run yields one entry; more
            // than one means the log was reloaded across an extractor restart.
            // If a KeyUpdate happened in between, OpenSSL's tls13_update_key()
            // overwrote the traffic secret in place and the later entry is a
            // ratcheted secret still labelled _0, which cannot open records
            // from before the ratchet. Say so rather than pick silently: the
            // operator can restart the connection and get an unambiguous log.
            for label in ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"] {
                let mut seen: Option<&Vec<u8>> = None;
                for e in entries.iter().filter(|e| e.label == label) {
                    match seen {
                        None => seen = Some(&e.secret),
                        Some(first) if first != &e.secret => {
                            tracing::warn!(
                                "{label} for this session was logged more than once with \
                                 different values; using the latest. A key log reloaded \
                                 across an extractor restart can carry a secret rotated \
                                 by a TLS 1.3 KeyUpdate, which cannot decrypt records \
                                 from before the rotation. Restart the connection while \
                                 capturing for an unambiguous log."
                            );
                            break;
                        }
                        Some(_) => {}
                    }
                }
            }

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
                    derive_key_iv(crypto.as_ref(), cs, suite),
                    derive_key_iv(crypto.as_ref(), ss, suite),
                ) {
                    (Ok((ck, civ)), Ok((sk, siv))) => {
                        tracing::info!(
                            "TLS session ready [session={}, cipher={}]",
                            hex_id(cr),
                            suite
                        );
                        sessions.insert(
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
                                locked_client: false,
                                locked_server: false,
                                lockon_attempts: 0,
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
                // Bind the entry to the handshake whose ClientHello random
                // matches this entry's client_random exactly. Only when no
                // observed ServerHello was paired with this client_random
                // (e.g. the ClientHello predates the capture) fall back to
                // handshakes with an unknown client_random — never to a
                // handshake bound to a DIFFERENT session, which would
                // silently derive keys from the wrong server_random.
                let has_exact = observed_handshakes
                    .iter()
                    .any(|hs| hs.client_random == Some(*cr));
                let candidates = observed_handshakes.iter().filter(|hs| {
                    if has_exact {
                        hs.client_random == Some(*cr)
                    } else {
                        hs.client_random.is_none()
                    }
                });
                for hs in candidates {
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

                    match derive_tls12_keys(crypto.as_ref(), ms, cr, &server_random, suite) {
                        Ok((ck, sk, civ, siv)) => {
                            tracing::info!(
                                "TLS 1.2 session ready [session={}, cipher={}]",
                                hex_id(cr),
                                suite
                            );
                            sessions.insert(
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
                                    locked_client: false,
                                    locked_server: false,
                                    lockon_attempts: 0,
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
}

/// Forward sequence-number search window for a direction that has already
/// produced plaintext.
///
/// Covers records the capture never saw — a kernel drop, a segment that could
/// not be reassembled — so that one gap does not end decryption for the rest
/// of the connection.
const SEQ_RESYNC_WINDOW: u64 = 16;

/// Forward sequence-number search window for a direction that has not yet
/// produced plaintext.
///
/// A capture started against a connection that was already running joins the
/// record stream part-way through, and nothing on the wire carries the record
/// number: both TLS versions derive their per-record nonce from a counter the
/// two endpoints keep privately (RFC 8446 §5.3). Seeing the handshake would
/// not help either — the counter is a function of how many records have gone
/// by, not of anything in the ClientHello. The only way to recover it is to
/// try, and the AEAD tag makes trying safe: a wrong sequence number cannot
/// forge a passing tag, at 2^-128 per attempt for AES-GCM. This window is
/// therefore the answer to "how far into an established connection may a
/// capture start and still be readable". Defined beside the report type that
/// quotes it to the operator, so the search and the message cannot drift apart.
const SEQ_LOCKON_WINDOW: u64 = crate::capture::TLS_SEQ_LOCKON_WINDOW;

/// Ceiling on lock-on trials for one run.
///
/// Every loaded session is tried against every ApplicationData record, so a
/// session whose keys belong to some other connection would burn the whole
/// lock-on window on each record it is offered. The budget makes that worst
/// case a bounded one-off instead of a per-record cost across a large capture;
/// once it is spent only [`SEQ_RESYNC_WINDOW`] is searched, which is what a
/// run that has already locked on needs anyway.
const LOCKON_TRIAL_BUDGET: u64 = 1 << 22;

// Four full windows. It must exceed [`SEQ_LOCKON_WINDOW`] by a margin,
// otherwise the first session offered a record it cannot open spends the
// entire run's allowance and a later session that WOULD have locked on is left
// with only [`SEQ_RESYNC_WINDOW`]. Keys belonging to some other connection are
// the normal case on a busy host, not an exceptional one.

/// Try to decrypt a record using a specific session's keys.
///
/// Borrows a single [`TlsSession`] and the crypto backend directly (rather than
/// re-looking-up the session by key), so the caller can iterate `sessions` in
/// place without cloning session keys. Key material stays owned by `session`;
/// its `Drop`/zeroize behavior is unaffected.
///
/// `lockon_budget` is the run's remaining allowance for searching a sequence
/// number that has not been established yet; see [`LOCKON_TRIAL_BUDGET`].
fn try_decrypt_with_session(
    session: &mut TlsSession,
    crypto: &dyn CryptoBackend,
    record: &TlsRecord,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    lockon_budget: &mut u64,
    lockon_window: u64,
) -> Option<Vec<u8>> {
    // Determine direction: try both if we haven't established client_addr yet.
    //
    // An address only discriminates when the two ends have different ones. A
    // loopback connection has the same IP on both sides, so `src_addr ==
    // client` is true for every record and pinning the direction from it would
    // lock the session to one side and silently drop everything the other side
    // sent. Fall back to trying both; the AEAD tag decides, at no risk.
    let directions: Vec<bool> = match session.client_addr {
        Some(client) if src_addr != dst_addr => vec![src_addr == client],
        _ => vec![true, false],
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
        let (write_key, write_iv, seq, locked) = if is_client_to_server {
            (
                &session.client_write_key,
                &session.client_write_iv,
                session.sequence_client,
                session.locked_client,
            )
        } else {
            (
                &session.server_write_key,
                &session.server_write_iv,
                session.sequence_server,
                session.locked_server,
            )
        };

        // How far forward to search for the sequence number that opens this
        // record. A direction that has decrypted before is counting, and needs
        // only to step over records the capture missed; one that has not is
        // guessing from zero, and the capture may have joined an established
        // connection at any record number.
        let window = if locked {
            SEQ_RESYNC_WINDOW
        } else {
            // Widen with each failed attempt rather than spending the ceiling
            // on the first record. `1 << attempts` reaches a million by the
            // fourteenth record a direction fails to open, which a trunk
            // carrying traffic passes in seconds, while a session whose keys
            // are simply wrong stays cheap for far longer than it used to.
            let widened = SEQ_RESYNC_WINDOW.saturating_mul(1u64 << session.lockon_attempts.min(24));
            widened.min(lockon_window).min(*lockon_budget)
        };

        // Decrypt with the per-version AEAD framing. On success both paths
        // return (plaintext, matched_seq) so the per-direction counter can
        // resync — important for TLS 1.2, where the encrypted Finished is a
        // Handshake record we never see, leaving the app-data counter offset,
        // and for TLS 1.3, where the server's NewSessionTickets ride inside
        // ApplicationData records and offset it the same way.
        let mut trials = 0u64;
        let decrypted: Option<(Vec<u8>, u64)> = match version {
            SessionVersion::Tls13 => decrypt_tls13_record(
                crypto,
                write_key,
                write_iv,
                seq,
                window,
                record,
                &mut trials,
            ),
            SessionVersion::Tls12 => decrypt_tls12_gcm_record(
                crypto,
                write_key,
                write_iv,
                seq,
                window,
                record,
                &mut trials,
            ),
        };
        if !locked {
            *lockon_budget = lockon_budget.saturating_sub(trials);
            if decrypted.is_none() {
                // Only a direction still guessing escalates. A failure here is
                // the evidence that the next search should be wider, and it is
                // the ONLY thing that widens it — without this the ceiling is
                // never reached and a long-lived trunk stays unreadable.
                session.lockon_attempts = session.lockon_attempts.saturating_add(1);
            } else {
                session.lockon_attempts = 0;
            }
        }

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
                session.sequence_client = used_seq + 1;
                session.locked_client = true;
            } else {
                session.sequence_server = used_seq + 1;
                session.locked_server = true;
            }

            return Some(plaintext);
        }
    }

    None
}

/// Decrypt a TLS 1.3 AEAD record (RFC 8446 §5.2), searching forward from
/// `seq_start` across `window` sequence numbers.
///
/// The nonce is `write_iv XOR seq` and the additional data is the record
/// header. Nothing on the wire carries `seq`, so a capture that did not start
/// with the connection has to find the counter rather than know it — seeing
/// the handshake would not help, because the counter is a function of how many
/// records have since gone by. The AEAD tag authenticates the choice, so only
/// the correct sequence yields plaintext. `trials` accumulates the attempts
/// made, which is what the run's lock-on budget is spent from. Returns
/// `(plaintext, matched_seq)`.
fn decrypt_tls13_record(
    crypto: &dyn CryptoBackend,
    write_key: &[u8],
    write_iv: &[u8],
    seq_start: u64,
    window: u64,
    record: &TlsRecord,
    trials: &mut u64,
) -> Option<(Vec<u8>, u64)> {
    let aad = build_record_aad(record);
    for seq in seq_start..=seq_start.saturating_add(window) {
        let mut nonce = write_iv.to_vec();
        let seq_bytes = seq.to_be_bytes();
        let offset = nonce.len().saturating_sub(seq_bytes.len());
        for (i, &b) in seq_bytes.iter().enumerate() {
            if offset + i < nonce.len() {
                nonce[offset + i] ^= b;
            }
        }
        *trials += 1;
        if let Ok(mut pt) = crypto.aes_gcm_decrypt(write_key, &nonce, &aad, &record.payload) {
            // TLS 1.3: strip inner content type and zero padding.
            strip_tls13_padding(&mut pt);
            return Some((pt, seq));
        }
    }
    None
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
    window: u64,
    record: &TlsRecord,
    trials: &mut u64,
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
    for seq in seq_start..=seq_start.saturating_add(window) {
        let aad = build_tls12_gcm_aad(seq, content_type, version, plaintext_len);
        *trials += 1;
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

/// Unit tests for the TLS decryption engine: cipher-suite tables, ServerHello /
/// ClientHello / ClientKeyExchange parsing, TLS 1.3 and TLS 1.2 (GCM + refused
/// CBC) session derivation, the `--tls-key` RSA-kx round trip, keylog ingestion
/// / polling, and pcapng embedded-secret feeding.
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
        /// Return the preset `decrypt_result` plaintext, or error if none is set.
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

        /// Unsupported in this mock; always errors.
        fn aes_cbc_decrypt(&self, _key: &[u8], _iv: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("not implemented")
        }

        /// Unsupported in this mock; always errors.
        fn hmac_sha1(&self, _key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("not implemented")
        }

        /// Return `len` deterministic `0x42` bytes so key derivation is stable.
        fn hkdf_expand(
            &self,
            _prk: &[u8],
            _info: &[u8],
            len: usize,
            _hash: HashAlg,
        ) -> Result<Vec<u8>> {
            // Return deterministic bytes for testing
            Ok(vec![0x42u8; len])
        }
    }

    /// Build a TLS 1.3 client/server traffic-secret keylog pair (both 32-byte
    /// secrets → AES-128-GCM) sharing one `client_random`.
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

    /// `parse_client_key_exchange_rsa` extracts the ciphertext from a
    /// well-formed ClientKeyExchange and returns `None` for inputs that are
    /// too short at each bound (missing type, missing length field, and a
    /// length field that claims more ciphertext than is present).
    #[test]
    fn parse_client_key_exchange_rsa_bounds() {
        // Well-formed: type(16) ‖ len(3)=0x000004 ‖ ct_len(2)=2 ‖ ct(2).
        let good = [16u8, 0, 0, 4, 0, 2, 0xAA, 0xBB];
        assert_eq!(
            parse_client_key_exchange_rsa(&good),
            Some(&[0xAAu8, 0xBB][..])
        );

        // Empty / wrong message type.
        assert_eq!(parse_client_key_exchange_rsa(&[]), None);
        assert_eq!(
            parse_client_key_exchange_rsa(&[17, 0, 0, 4, 0, 2, 0, 0]),
            None
        );

        // Truncated before the 2-byte ciphertext length field (body < 2 bytes).
        assert_eq!(parse_client_key_exchange_rsa(&[16, 0, 0, 1, 0xAA]), None);
        // No body at all after the 4-byte header.
        assert_eq!(parse_client_key_exchange_rsa(&[16, 0, 0, 0]), None);

        // Length field claims 2 ciphertext bytes but only 1 is present.
        assert_eq!(
            parse_client_key_exchange_rsa(&[16, 0, 0, 3, 0, 2, 0xAA]),
            None
        );
    }

    /// Constructing a decryptor with no keylog path succeeds with zero entries.
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

    /// A keylog file with two traffic-secret lines loads two entries.
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

    /// A client/server traffic-secret pair populates exactly one AES-128-GCM
    /// session.
    #[test]
    fn sessions_populated_from_entries() {
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: None,
            }),
            decrypted_count: 0,
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
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

    /// When a client_random has more than one CLIENT_TRAFFIC_SECRET_0/
    /// SERVER_TRAFFIC_SECRET_0 pair (eCapture's own extraction hooks fire on
    /// every `SSL_write`, not once per connection — confirmed live via its
    /// debug log — so an early hook firing mid-handshake can log a premature
    /// secret under the same label before the real one is derived), the
    /// session must derive from the LAST pair for that client_random, not the
    /// first. Uses the real crypto backend (not the mock) so two different
    /// secret inputs are verifiably distinguishable in the derived key.
    #[test]
    fn sessions_populated_uses_latest_matching_secret_not_first() {
        let cr = [0xBBu8; 32];
        let stale_client = vec![0x01u8; 32];
        let stale_server = vec![0x02u8; 32];
        let real_client = vec![0x03u8; 32];
        let real_server = vec![0x04u8; 32];

        let mut d = TlsDecryptor {
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_entries: vec![
                KeyLogEntry {
                    label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
                    client_random: cr.to_vec(),
                    secret: stale_client,
                },
                KeyLogEntry {
                    label: "SERVER_TRAFFIC_SECRET_0".to_string(),
                    client_random: cr.to_vec(),
                    secret: stale_server,
                },
                KeyLogEntry {
                    label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
                    client_random: cr.to_vec(),
                    secret: real_client.clone(),
                },
                KeyLogEntry {
                    label: "SERVER_TRAFFIC_SECRET_0".to_string(),
                    client_random: cr.to_vec(),
                    secret: real_server.clone(),
                },
            ],
            sessions: HashMap::new(),
            crypto: crate::crypto::default_backend(),
            decrypted_count: 0,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
            keylog_processed_count: 0,
            rsa: None,
        };

        d.ensure_sessions_populated();
        let key = TlsSessionKey { client_random: cr };
        let session = d.sessions.get(&key).expect("session derived");

        let expected_client_key =
            derive_key_iv(d.crypto.as_ref(), &real_client, CipherSuite::Aes128Gcm)
                .unwrap()
                .0;
        let expected_server_key =
            derive_key_iv(d.crypto.as_ref(), &real_server, CipherSuite::Aes128Gcm)
                .unwrap()
                .0;
        assert_eq!(
            session.client_write_key, expected_client_key,
            "must derive from the LAST client secret, not the first"
        );
        assert_eq!(
            session.server_write_key, expected_server_key,
            "must derive from the LAST server secret, not the first"
        );
    }

    /// With no sessions loaded, decrypting an ApplicationData record yields
    /// `None`.
    #[test]
    fn try_decrypt_no_matching_session() {
        let mut d = TlsDecryptor {
            keylog_entries: Vec::new(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: None,
            }),
            decrypted_count: 0,
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
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

    /// A matching session decrypts an ApplicationData record (mock plaintext),
    /// strips the TLS 1.3 inner type, and increments `decrypted_count`.
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
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
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

    /// A non-ApplicationData (Handshake) record is never decrypted.
    #[test]
    fn non_application_data_returns_none() {
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            sessions: HashMap::new(),
            crypto: Box::new(MockCrypto {
                decrypt_result: Some(vec![0x42]),
            }),
            decrypted_count: 0,
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
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

    /// Stripping removes the trailing content-type byte and zero padding.
    #[test]
    fn strip_padding_removes_content_type() {
        let mut data = b"hello".to_vec();
        data.push(0); // zero padding
        data.push(0); // zero padding
        data.push(23); // content type
        strip_tls13_padding(&mut data);
        assert_eq!(data, b"hello");
    }

    /// Stripping removes just the content-type byte when there is no padding.
    #[test]
    fn strip_padding_no_padding() {
        let mut data = b"hello".to_vec();
        data.push(23); // content type, no padding
        strip_tls13_padding(&mut data);
        assert_eq!(data, b"hello");
    }

    // ── --tls-key RSA key exchange end-to-end ──────────────────────────

    /// PEM PKCS#8 RSA private key fixture for the `--tls-key` round-trip test.
    #[cfg(feature = "tls")]
    const RSA_KEY_PEM: &str = include_str!("../../tests/fixtures/tls_rsa/key.pem");
    /// PKCS#1 v1.5 ciphertext of the fixture pre-master (the ClientKeyExchange).
    #[cfg(feature = "tls")]
    const RSA_PREMASTER_CT: &[u8] = include_bytes!("../../tests/fixtures/tls_rsa/premaster_ct.bin");
    /// The 48-byte plaintext pre-master matching `RSA_PREMASTER_CT`.
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

    /// End-to-end `--tls-key`: feeding ClientHello, ServerHello, and
    /// ClientKeyExchange lets the RSA key derive a TLS 1.2 GCM session that
    /// decrypts a sealed SIP ApplicationData record back to plaintext.
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
        let master = tls12_prf(
            &backend,
            RSA_PREMASTER,
            b"master secret",
            &seed,
            48,
            HashAlg::Sha256,
        )
        .unwrap();
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

        d.process_record(
            &client_hello_record(&client_random),
            client_sock(),
            server_sock(),
        );
        d.process_record(&server_hello_record(0x009C), server_sock(), client_sock());
        d.process_record(
            &client_key_exchange_record(RSA_PREMASTER_CT),
            client_sock(),
            server_sock(),
        );

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

    /// Seal `plaintext` as a TLS 1.3 ApplicationData record at record
    /// sequence number `seq`, exactly as a TLS stack would put it on the wire.
    ///
    /// Real AEAD, so the resulting record can only be opened with the right
    /// key AND the right sequence number — which is the property under test.
    #[cfg(feature = "tls")]
    fn seal_tls13_record(key: &[u8], iv: &[u8], seq: u64, plaintext: &[u8]) -> TlsRecord {
        use ring::aead;

        // TLS 1.3 inner plaintext: content ‖ real content type.
        let mut inner = plaintext.to_vec();
        inner.push(23);

        // Per-record nonce (RFC 8446 §5.3): write_iv XOR the 64-bit sequence
        // number, right-aligned in the 12-byte IV.
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv);
        for (i, b) in seq.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }

        let ct_len = (inner.len() + aead::AES_128_GCM.tag_len()) as u16;
        let mut aad = [0u8; 5];
        aad[0] = 23;
        aad[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
        aad[3..5].copy_from_slice(&ct_len.to_be_bytes());

        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key).unwrap();
        let sealing = aead::LessSafeKey::new(unbound);
        let mut in_out = inner;
        sealing
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad),
                &mut in_out,
            )
            .unwrap();

        TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: ct_len,
            payload: in_out,
        }
    }

    /// A decryptor holding the TLS 1.3 traffic secrets of `make_keylog_entries`
    /// together with the client write key and IV those secrets derive to.
    #[cfg(feature = "tls")]
    fn tls13_decryptor_and_client_keys() -> (TlsDecryptor, Vec<u8>, Vec<u8>) {
        use crate::crypto::RingCryptoBackend;

        let (key, iv) =
            derive_key_iv(&RingCryptoBackend, &[0x11u8; 32], CipherSuite::Aes128Gcm).unwrap();
        let mut d = decryptor_with(Box::new(RingCryptoBackend));
        d.keylog_entries = make_keylog_entries();
        (d, key, iv)
    }

    /// A capture started against a connection that was ALREADY running joins
    /// the record stream part-way through, so the first record it sees is not
    /// record zero. The keylog holds the right secret and the session matches,
    /// but assuming a zero sequence number makes every record fail its AEAD
    /// tag check — decryption that silently yields nothing while the operator
    /// is told the keys loaded fine.
    ///
    /// The tag authenticates the choice of sequence number, so searching
    /// forward for the one that opens the record is safe: a wrong sequence
    /// cannot forge a passing tag.
    #[cfg(feature = "tls")]
    #[test]
    fn tls13_decrypts_a_record_whose_stream_began_before_the_capture() {
        // Eight records went by before the capture was started.
        const JOINED_AT: u64 = 8;

        let (mut d, key, iv) = tls13_decryptor_and_client_keys();
        let sip = b"OPTIONS sip:t@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let record = seal_tls13_record(&key, &iv, JOINED_AT, sip);

        let out = d
            .try_decrypt(
                &record,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            )
            .expect("a record captured mid-stream must still decrypt");
        assert_eq!(out, sip, "plaintext must be the SIP that was sealed");
        assert_eq!(d.decrypted_count, 1);
    }

    /// A carrier trunk held open for hours is far past a few thousand records,
    /// and asking an operator to restart it is not a debugging step they can
    /// take on live traffic. Verified in the field: a persistent trunk stayed
    /// unreadable until the daemon was restarted, while a fresh-per-call
    /// carrier on the same host decrypted immediately — the difference was
    /// only how far into the record stream the capture began.
    #[cfg(feature = "tls")]
    #[test]
    fn tls13_locks_on_to_a_trunk_that_has_been_up_far_longer_than_a_few_thousand_records() {
        // Well beyond the old 4096 ceiling, and not a round power of two.
        const JOINED_AT: u64 = 100_003;
        // A trunk carrying traffic offers records continuously; this is the
        // budget in RECORDS, not seconds, and a busy trunk passes it in
        // moments. The search widens only when a record fails to open, so a
        // single record can never reach the ceiling by itself -- that is the
        // point of escalating rather than spending it all on the first packet.
        const PATIENCE: u64 = 24;

        let (mut d, key, iv) = tls13_decryptor_and_client_keys();
        let sip = b"OPTIONS sip:t@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let server: IpAddr = "10.0.0.2".parse().unwrap();

        let mut opened = None;
        for n in 0..PATIENCE {
            let record = seal_tls13_record(&key, &iv, JOINED_AT + n, sip);
            if let Some(out) = d.try_decrypt(&record, client, server) {
                opened = Some((n, out));
                break;
            }
        }
        let (after, out) = opened
            .expect("a long-lived trunk must lock on from its own traffic, without restarting it");
        assert_eq!(out, sip, "plaintext must be the SIP that was sealed");
        assert!(
            after > 0,
            "escalation is what reaches this depth; locking on the first record \
             would mean the ceiling is being spent up front again"
        );
    }

    /// Once a direction has locked on, a gap in the captured records — a
    /// kernel drop, a record sipnab could not parse — must not end decryption
    /// for the rest of the connection. Before the forward search existed the
    /// counter simply stopped advancing and every later record was lost.
    #[cfg(feature = "tls")]
    #[test]
    fn tls13_resyncs_across_a_gap_in_the_captured_records() {
        let (mut d, key, iv) = tls13_decryptor_and_client_keys();
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let server: IpAddr = "10.0.0.2".parse().unwrap();

        let first = seal_tls13_record(&key, &iv, 0, b"OPTIONS sip:a@x SIP/2.0\r\n\r\n");
        assert!(
            d.try_decrypt(&first, client, server).is_some(),
            "record zero locks the direction on"
        );

        // Records 1..=3 were never captured; the next one seen is record 4.
        let later = seal_tls13_record(&key, &iv, 4, b"OPTIONS sip:b@x SIP/2.0\r\n\r\n");
        let out = d
            .try_decrypt(&later, client, server)
            .expect("a gap must not end decryption for the connection");
        assert_eq!(out, b"OPTIONS sip:b@x SIP/2.0\r\n\r\n");
        assert_eq!(d.decrypted_count, 2);
    }

    /// A loopback capture has the same IP on both ends, so the address cannot
    /// say which way a record was going. Pinning the direction from it anyway
    /// locks the session to one side and silently drops everything the other
    /// side sent — on `-d lo`, which is how most people first try TLS
    /// decryption, that is half the conversation.
    #[cfg(feature = "tls")]
    #[test]
    fn both_directions_decrypt_when_the_addresses_cannot_tell_them_apart() {
        use crate::crypto::RingCryptoBackend;

        let (mut d, client_key, client_iv) = tls13_decryptor_and_client_keys();
        let (server_key, server_iv) =
            derive_key_iv(&RingCryptoBackend, &[0x22u8; 32], CipherSuite::Aes128Gcm).unwrap();

        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let request = seal_tls13_record(
            &client_key,
            &client_iv,
            0,
            b"OPTIONS sip:a@x SIP/2.0\r\n\r\n",
        );
        let reply = seal_tls13_record(&server_key, &server_iv, 0, b"SIP/2.0 200 OK\r\n\r\n");

        assert!(
            d.try_decrypt(&request, lo, lo).is_some(),
            "the request must decrypt"
        );
        let out = d
            .try_decrypt(&reply, lo, lo)
            .expect("the reply must decrypt too, on the same loopback addresses");
        assert_eq!(out, b"SIP/2.0 200 OK\r\n\r\n");
        assert_eq!(d.decrypted_count, 2);
    }

    /// The counters behind the operator-facing report: every ApplicationData
    /// record offered is counted, and one that no session could open is
    /// counted as undecrypted. Without this the run has no basis for telling
    /// the operator it is holding ciphertext it could not read.
    #[cfg(feature = "tls")]
    #[test]
    fn undecryptable_application_data_is_counted_not_silently_dropped() {
        use crate::crypto::RingCryptoBackend;

        let (key, iv) = derive_key_iv(
            &RingCryptoBackend,
            &[0x99u8; 32], // a secret the decryptor does NOT hold
            CipherSuite::Aes128Gcm,
        )
        .unwrap();
        let (mut d, _k, _i) = tls13_decryptor_and_client_keys();
        let record = seal_tls13_record(&key, &iv, 0, b"OPTIONS sip:a@x SIP/2.0\r\n\r\n");

        assert!(
            d.try_decrypt(
                &record,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap()
            )
            .is_none(),
            "a record sealed under an unknown secret cannot open"
        );

        let report = d.report();
        assert_eq!(report.app_data_records, 1, "the record was seen");
        assert_eq!(report.decrypted_records, 0, "and not decrypted");
        assert_eq!(
            report.sessions_with_keys, 1,
            "a session was built from the keylog, which is why silence misleads"
        );
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

    /// `build_record_aad` yields the content type, 0x0303 version, and length.
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

    /// The HKDF-Expand-Label info matches the RFC 8446 wire layout
    /// (length prefix, `tls13 `-prefixed label, empty context).
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

    /// The first populate creates sessions; a second call with no new entries
    /// is a no-op.
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
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
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

    /// Entries added after the first populate are picked up on the next call,
    /// producing an additional session.
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
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
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

    /// Client-side transport endpoint for single-connection tests.
    fn client_sock() -> SocketAddr {
        "10.0.0.1:51000".parse().unwrap()
    }

    /// Server-side transport endpoint for single-connection tests.
    fn server_sock() -> SocketAddr {
        "10.0.0.2:5061".parse().unwrap()
    }

    /// A decryptor wrapping `crypto` with no keylog file and empty state.
    fn decryptor_with(crypto: Box<dyn CryptoBackend>) -> TlsDecryptor {
        TlsDecryptor {
            keylog_entries: Vec::new(),
            sessions: HashMap::new(),
            crypto,
            decrypted_count: 0,
            app_data_records: 0,
            lockon_budget: LOCKON_TRIAL_BUDGET,
            lockon_window: SEQ_LOCKON_WINDOW,
            keylog_path: None,
            keylog_source: None,
            observed_handshakes: Vec::new(),
            pending_client_randoms: IndexMap::new(),
            keylog_processed_count: 0,
            rsa: None,
        }
    }

    /// A syntactically valid TLS 1.2 `CLIENT_RANDOM` keylog line (32-byte
    /// random, 48-byte master secret) reused across ingestion tests.
    const CLIENT_RANDOM_LINE: &str = "CLIENT_RANDOM \
        aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd \
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// `add_keylog_text` adds the one valid line and skips comment/blank/junk.
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

    /// `add_keylog_text` adds nothing for empty or all-junk input.
    #[test]
    fn add_keylog_text_empty_or_all_junk_adds_nothing() {
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        assert_eq!(d.add_keylog_text(""), 0);
        assert_eq!(d.add_keylog_text("# only a comment\ngarbage line\n"), 0);
        assert_eq!(d.keylog_entry_count(), 0);
    }

    /// A pcapng carrying a keylog Decryption Secrets Block feeds its secret
    /// into the decryptor.
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

    /// A pcapng with no DSB feeds nothing (returns 0).
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
        server_hello_with_random(cipher_code, session_id_len, &[0x5Au8; 32])
    }

    /// Wrap a raw handshake payload in a TLS 1.2 Handshake record.
    fn handshake_record(payload: Vec<u8>) -> TlsRecord {
        TlsRecord {
            content_type: TlsContentType::Handshake,
            version: TlsVersion::Tls12,
            length: 0,
            payload,
        }
    }

    /// Like [`server_hello`], but with an explicit `server_random` so tests can
    /// distinguish concurrent handshakes.
    fn server_hello_with_random(
        cipher_code: u16,
        session_id_len: u8,
        server_random: &[u8; 32],
    ) -> Vec<u8> {
        let mut hs = vec![2u8, 0, 0, 0]; // msg_type=ServerHello + 3-byte length
        hs.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        hs.extend_from_slice(server_random);
        hs.push(session_id_len);
        hs.extend(std::iter::repeat_n(0xCDu8, session_id_len as usize));
        hs.extend_from_slice(&cipher_code.to_be_bytes());
        hs.push(0); // compression method
        hs
    }

    // ── Key derivation binds to the suite's hash ───────────────────────

    /// `derive_key_iv` derives with the hash its SUITE names, not a fixed one.
    ///
    /// This pins VALUES, and it has to. HKDF-Expand returns the requested
    /// length, is deterministic, and has the prefix property under *any* hash —
    /// which is all the `crypto.rs` HKDF tests assert, so not one of them can
    /// tell SHA-256 from SHA-384. The backend was pinned to `HKDF_SHA256` for
    /// one release: every `TLS_AES_256_GCM_SHA384` session then derived a key
    /// that decrypted nothing while still logging `TLS session ready`, and no
    /// test could see it. That suite is OpenSSL's FIRST TLS 1.3 preference, so
    /// it was the common case rather than an exotic one.
    ///
    /// Vectors computed independently from RFC 8446 §7.1 HKDF-Expand-Label.
    #[test]
    fn derive_key_iv_uses_the_hash_the_suite_names() {
        let crypto = crate::crypto::default_backend();

        // SHA-384 suite: 48-byte traffic secret 0x00..0x2f.
        let secret384: Vec<u8> = (0u8..48).collect();
        let (key, iv) = derive_key_iv(crypto.as_ref(), &secret384, CipherSuite::Aes256Gcm)
            .expect("derive AES-256-GCM key material");
        assert_eq!(
            key,
            vec![
                0x68, 0x77, 0xd0, 0x22, 0xf1, 0xc6, 0x1d, 0x24, 0xeb, 0xb7, 0x48, 0x7c, 0x16, 0x75,
                0x2d, 0x9a, 0x47, 0x98, 0xe4, 0x04, 0x31, 0xc7, 0x5b, 0x39, 0x32, 0x0e, 0x53, 0x7c,
                0x90, 0xe2, 0x32, 0x25,
            ],
            "TLS_AES_256_GCM_SHA384 must derive its key with SHA-384. Deriving \
             it with SHA-256 yields a key that never decrypts a record, and the \
             failure is silent because the AEAD open is discarded with .ok()"
        );
        assert_eq!(
            iv,
            vec![
                0x42, 0x82, 0x25, 0x31, 0xa0, 0xfe, 0x88, 0x64, 0x8f, 0xc0, 0x9e, 0x9f
            ],
            "TLS_AES_256_GCM_SHA384 must derive its IV with SHA-384"
        );

        // SHA-256 suite: 32-byte traffic secret 0x00..0x1f. The regression
        // guard — a fix that simply swapped the constant would pass above and
        // fail here.
        let secret256: Vec<u8> = (0u8..32).collect();
        let (key, iv) = derive_key_iv(crypto.as_ref(), &secret256, CipherSuite::Aes128Gcm)
            .expect("derive AES-128-GCM key material");
        assert_eq!(
            key,
            vec![
                0x9c, 0x97, 0x83, 0xcf, 0x77, 0xea, 0x32, 0xd4, 0x4f, 0x36, 0x9d, 0xa4, 0x1f, 0x19,
                0xf3, 0xcc,
            ],
            "TLS_AES_128_GCM_SHA256 must still derive its key with SHA-256"
        );
        assert_eq!(
            iv,
            vec![
                0x2f, 0x41, 0xc8, 0x46, 0xa4, 0x31, 0xa1, 0x63, 0x81, 0x4b, 0xcd, 0x71
            ],
            "TLS_AES_128_GCM_SHA256 must still derive its IV with SHA-256"
        );
    }

    // ── CipherSuite table ──────────────────────────────────────────────

    /// Every `CipherSuite` reports the expected key/IV/MAC lengths, CBC flag,
    /// and display name.
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

    /// Known code points map to their suites; unknown code points map to `None`.
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
            // ECDHE and DHE. Absent once, which made every ServerHello a real
            // deployment sends unidentifiable — 0xC030 is OpenSSL's default
            // TLS 1.2 suite.
            (0xC02B, Aes128Gcm),
            (0xC02C, Aes256Gcm),
            (0xC02F, Aes128Gcm),
            (0xC030, Aes256Gcm),
            (0x009E, Aes128Gcm),
            (0x009F, Aes256Gcm),
            (0xC013, Aes128CbcSha),
            (0xC014, Aes256CbcSha256),
        ];
        for (code, expected) in known {
            assert_eq!(
                CipherSuite::from_code_point(code),
                Some(expected),
                "code point 0x{code:04X} must be identified"
            );
        }

        // Every AES-GCM suite must carry the hash its NAME carries. This is the
        // assertion that distinguishes a real table from a plausible one: the
        // key/IV lengths above are equal for 0xC02F and 0xC030, and only the
        // hash separates them.
        for code in [0x1302u16, 0xC02C, 0xC030, 0x009F, 0x009D] {
            assert_eq!(
                CipherSuite::from_code_point(code).map(CipherSuite::hash),
                Some(HashAlg::Sha384),
                "0x{code:04X} is a _SHA384 suite"
            );
        }
        for code in [0x1301u16, 0xC02B, 0xC02F, 0x009E, 0x009C] {
            assert_eq!(
                CipherSuite::from_code_point(code).map(CipherSuite::hash),
                Some(HashAlg::Sha256),
                "0x{code:04X} is a _SHA256 suite"
            );
        }

        // ChaCha20-Poly1305 stays unmapped: the backend has no such AEAD, so
        // identifying it would derive key material that can never be opened.
        for code in [0x0000u16, 0x1303, 0xCCA8, 0xCCA9, 0xFFFF, 0x00FF] {
            assert!(
                CipherSuite::from_code_point(code).is_none(),
                "0x{code:04X} must stay unidentified"
            );
        }
    }

    // ── parse_server_hello ─────────────────────────────────────────────

    /// A valid ServerHello yields its server_random and cipher, including when a
    /// non-empty session id shifts the cipher offset.
    #[test]
    fn parse_server_hello_valid() {
        let info = parse_server_hello(&server_hello(0x009C, 0)).unwrap();
        assert_eq!(info.server_random, Some([0x5Au8; 32]));
        assert_eq!(info.cipher_suite_code, Some(0x009C));

        // With a non-empty session id, the cipher offset shifts accordingly.
        let info = parse_server_hello(&server_hello(0x1302, 32)).unwrap();
        assert_eq!(info.cipher_suite_code, Some(0x1302));
    }

    /// Malformed ServerHellos (too short, wrong type, truncated random,
    /// overlong session id) return `None`.
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

    /// A Handshake ServerHello is recorded in `observed_handshakes`; a
    /// non-Handshake record is ignored.
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
        d.process_record(&rec, server_sock(), client_sock());
        assert_eq!(d.observed_handshakes.len(), 1);

        // A non-Handshake record is ignored.
        let rec = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: TlsVersion::Tls12,
            length: 0,
            payload: vec![0u8; 8],
        };
        d.process_record(&rec, server_sock(), client_sock());
        assert_eq!(d.observed_handshakes.len(), 1);
    }

    /// A TLS 1.3 session, already derived and ready to decrypt, must survive
    /// a ServerHello observed on a second, unrelated connection — e.g. a
    /// trunk that opens more than one TLS connection around the same time
    /// (a keepalive, a second concurrent call). Before this fix,
    /// `process_record`'s `self.sessions.clear()` wiped every session,
    /// TLS 1.3 included, on every ServerHello it saw: a call's session could
    /// go from ready to gone before its actual SIP traffic was decrypted,
    /// with nothing in the logs to explain why.
    #[test]
    fn tls13_session_survives_an_unrelated_serverhello() {
        let mut d = TlsDecryptor {
            keylog_entries: make_keylog_entries(),
            ..decryptor_with(Box::new(MockCrypto {
                decrypt_result: None,
            }))
        };

        d.ensure_sessions_populated();
        let key = TlsSessionKey {
            client_random: [0xAAu8; 32],
        };
        assert!(
            d.sessions.contains_key(&key),
            "TLS 1.3 session must be derived before the ServerHello below"
        );

        // A second, unrelated handshake's ServerHello arrives on a different
        // connection.
        let other_client: SocketAddr = "10.0.0.3:51001".parse().unwrap();
        d.process_record(
            &handshake_record(server_hello(0x009C, 0)),
            server_sock(),
            other_client,
        );

        assert!(
            d.sessions.contains_key(&key),
            "an unrelated ServerHello must not wipe an already-ready TLS 1.3 session"
        );
    }

    // ── TLS 1.2 CLIENT_RANDOM key derivation ───────────────────────────

    /// A TLS 1.2 `CLIENT_RANDOM` master secret plus an observed AES-128-GCM
    /// ServerHello derives a session with a 16-byte key and 4-byte fixed IV.
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
        d.process_record(
            &TlsRecord {
                content_type: TlsContentType::Handshake,
                version: TlsVersion::Tls12,
                length: 0,
                payload: server_hello(0x009C, 0),
            },
            server_sock(),
            client_sock(),
        );

        d.ensure_sessions_populated();
        let key = TlsSessionKey { client_random: cr };
        let session = d.sessions.get(&key).expect("TLS 1.2 session derived");
        assert_eq!(session.cipher_suite, CipherSuite::Aes128Gcm);
        // TLS 1.2 AES-128-GCM: 16-byte key, 4-byte fixed (implicit) IV.
        assert_eq!(session.client_write_key.len(), 16);
        assert_eq!(session.client_write_iv.len(), 4);
    }

    /// With two concurrent handshakes observed on the wire, a `CLIENT_RANDOM`
    /// keylog entry must bind to the handshake whose ClientHello random matches
    /// the entry — not to the first observed ServerHello.
    #[test]
    fn tls12_client_random_binds_to_matching_handshake() {
        let cr1 = [0x11u8; 32];
        let sr1 = [0x5Au8; 32];
        let cr2 = [0x22u8; 32];
        let sr2 = [0xA5u8; 32];
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));

        // Two interleaved TLS 1.2 handshakes (different connections) in wire
        // order: CH1, SH1, CH2, SH2.
        let client2: SocketAddr = "10.0.0.3:51001".parse().unwrap();
        for (payload, src, dst) in [
            (
                client_hello_record(&cr1).payload,
                client_sock(),
                server_sock(),
            ),
            (
                server_hello_with_random(0x009C, 0, &sr1),
                server_sock(),
                client_sock(),
            ),
            (client_hello_record(&cr2).payload, client2, server_sock()),
            (
                server_hello_with_random(0x009C, 0, &sr2),
                server_sock(),
                client2,
            ),
        ] {
            d.process_record(
                &TlsRecord {
                    content_type: TlsContentType::Handshake,
                    version: TlsVersion::Tls12,
                    length: 0,
                    payload,
                },
                src,
                dst,
            );
        }

        // Keylog entry for the SECOND connection only.
        let master_secret = vec![0x0Bu8; 48];
        d.keylog_entries.push(KeyLogEntry {
            label: "CLIENT_RANDOM".to_string(),
            client_random: cr2.to_vec(),
            secret: master_secret.clone(),
        });

        d.ensure_sessions_populated();
        let session = d
            .sessions
            .get(&TlsSessionKey { client_random: cr2 })
            .expect("TLS 1.2 session derived");

        // The session keys must come from the SECOND handshake's server_random.
        let (expected_ck, _, expected_civ, _) = derive_tls12_keys(
            d.crypto.as_ref(),
            &master_secret,
            &cr2,
            &sr2,
            CipherSuite::Aes128Gcm,
        )
        .unwrap();
        assert_eq!(
            session.client_write_key, expected_ck,
            "keys must derive from the matching handshake's server_random, not the first observed"
        );
        assert_eq!(session.client_write_iv, expected_civ);
    }

    /// Cross-connection interleaving must not cross-pair: with the pathological
    /// order CH1(A), CH2(B), SH2(B), SH1(A), each ServerHello pairs with its
    /// OWN connection's ClientHello random.
    #[test]
    fn serverhello_pairs_with_own_connections_clienthello_only() {
        let cr_a = [0x11u8; 32];
        let sr_a = [0x5Au8; 32];
        let cr_b = [0x22u8; 32];
        let sr_b = [0xA5u8; 32];
        let client_a = client_sock();
        let client_b: SocketAddr = "10.0.0.3:51001".parse().unwrap();
        let server = server_sock();

        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        d.process_record(
            &handshake_record(client_hello_record(&cr_a).payload),
            client_a,
            server,
        );
        d.process_record(
            &handshake_record(client_hello_record(&cr_b).payload),
            client_b,
            server,
        );
        d.process_record(
            &handshake_record(server_hello_with_random(0x009C, 0, &sr_b)),
            server,
            client_b,
        );
        d.process_record(
            &handshake_record(server_hello_with_random(0x009C, 0, &sr_a)),
            server,
            client_a,
        );

        assert_eq!(d.observed_handshakes.len(), 2);
        // observed_handshakes[0] is SH2 (connection B), [1] is SH1 (connection A).
        assert_eq!(d.observed_handshakes[0].server_random, Some(sr_b));
        assert_eq!(
            d.observed_handshakes[0].client_random,
            Some(cr_b),
            "SH(B) must pair with connection B's ClientHello random"
        );
        assert_eq!(d.observed_handshakes[1].server_random, Some(sr_a));
        assert_eq!(
            d.observed_handshakes[1].client_random,
            Some(cr_a),
            "SH(A) must pair with connection A's ClientHello random"
        );
    }

    /// One connection's records as seen on the wire — ClientHello
    /// client→server, ServerHello server→client — normalize to the same
    /// connection key and pair.
    #[test]
    fn clienthello_serverhello_pair_across_wire_directions() {
        let cr = [0x33u8; 32];
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        d.process_record(
            &handshake_record(client_hello_record(&cr).payload),
            client_sock(),
            server_sock(),
        );
        d.process_record(
            &handshake_record(server_hello(0x009C, 0)),
            server_sock(),
            client_sock(),
        );
        assert_eq!(d.observed_handshakes.len(), 1);
        assert_eq!(
            d.observed_handshakes[0].client_random,
            Some(cr),
            "src/dst-swapped directions must normalize to one connection"
        );
    }

    /// The pending-connection map is bounded: exceeding the cap evicts the
    /// oldest connection's queued ClientHello (no panic) while the newest
    /// connection still pairs.
    #[test]
    fn pending_connection_map_bounded_evicts_oldest() {
        let server = server_sock();
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        let conn_addr = |i: usize| -> SocketAddr {
            format!("10.1.{}.{}:49152", i / 256, i % 256)
                .parse()
                .unwrap()
        };
        let conn_random = |i: usize| -> [u8; 32] {
            let mut cr = [0u8; 32];
            cr[..8].copy_from_slice(&(i as u64).to_be_bytes());
            cr
        };

        // One more connection than the cap admits.
        for i in 0..=MAX_PENDING_HANDSHAKE_CONNS {
            d.process_record(
                &handshake_record(client_hello_record(&conn_random(i)).payload),
                conn_addr(i),
                server,
            );
        }

        // Connection 0 was evicted: its ServerHello finds no queued ClientHello.
        d.process_record(
            &handshake_record(server_hello_with_random(0x009C, 0, &[0x5A; 32])),
            server,
            conn_addr(0),
        );
        assert_eq!(
            d.observed_handshakes[0].client_random, None,
            "oldest connection's pending ClientHello must be evicted at the cap"
        );

        // The newest connection still pairs.
        let last = MAX_PENDING_HANDSHAKE_CONNS;
        d.process_record(
            &handshake_record(server_hello_with_random(0x009C, 0, &[0xA5; 32])),
            server,
            conn_addr(last),
        );
        assert_eq!(
            d.observed_handshakes[1].client_random,
            Some(conn_random(last))
        );
    }

    /// A CBC ServerHello derives a session whose IV is the full 16-byte block.
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
        d.process_record(
            &TlsRecord {
                content_type: TlsContentType::Handshake,
                version: TlsVersion::Tls12,
                length: 0,
                payload: server_hello(0x002F, 0),
            },
            server_sock(),
            client_sock(),
        );
        d.ensure_sessions_populated();
        let session = d
            .sessions
            .get(&TlsSessionKey { client_random: cr })
            .expect("CBC session derived");
        assert_eq!(session.cipher_suite, CipherSuite::Aes128CbcSha);
        assert_eq!(session.client_write_iv.len(), 16);
    }

    /// An unsupported negotiated cipher (0x0000) derives no session.
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
        d.process_record(
            &TlsRecord {
                content_type: TlsContentType::Handshake,
                version: TlsVersion::Tls12,
                length: 0,
                payload: server_hello(0x0000, 0),
            },
            server_sock(),
            client_sock(),
        );
        d.ensure_sessions_populated();
        assert!(d.sessions.is_empty());
    }

    // ── CBC decryption path ────────────────────────────────────────────

    /// Crypto backend that succeeds for CBC and fails for GCM.
    struct CbcMock;
    impl CryptoBackend for CbcMock {
        /// Always errors, so the GCM path never succeeds for this backend.
        fn aes_gcm_decrypt(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("no gcm")
        }
        /// Returns fixed SIP plaintext, simulating a successful CBC decrypt.
        fn aes_cbc_decrypt(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            Ok(b"MESSAGE sip:bob@example.com SIP/2.0\r\n\r\n".to_vec())
        }
        /// Unsupported in this mock; always errors.
        fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("n/a")
        }
        /// Returns `len` zero bytes for deterministic key derivation.
        fn hkdf_expand(&self, _: &[u8], _: &[u8], len: usize, _: HashAlg) -> Result<Vec<u8>> {
            Ok(vec![0u8; len])
        }
    }

    /// Insert a ready-made TLS 1.2 AES-128-CBC session into `d` under `key`.
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
                locked_client: false,
                locked_server: false,
                lockon_attempts: 0,
                client_addr: None,
            },
        );
    }

    /// A CBC record is refused (no plaintext emitted, count unchanged) even when
    /// the CBC primitive would return bytes, since the MAC is not verified.
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

    /// A CBC record shorter than the 16-byte IV returns `None` on both
    /// directions.
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

    /// Polling with no keylog path configured returns 0.
    #[test]
    fn poll_keylog_without_path_is_noop() {
        let mut d = decryptor_with(Box::new(MockCrypto {
            decrypt_result: None,
        }));
        assert_eq!(d.poll_keylog_file().unwrap(), 0);
    }

    /// Polling loads newly appended valid lines (skipping junk) once the file
    /// grows, and is a no-op when it has not.
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

    /// A TLS 1.3 session already derived and ready must survive a later poll
    /// that loads an unrelated second call's keylog entries. Before this
    /// fix, `poll_keylog_file` cleared every session (TLS 1.3 included)
    /// whenever any new keylog line arrived — on `--keylog-watch`'s ~100ms
    /// wall-clock cadence, that meant a session could be wiped within
    /// milliseconds of becoming ready, often before its own call's SIP
    /// INVITE had arrived to be decrypted against it.
    #[test]
    fn poll_keylog_does_not_wipe_an_already_ready_tls13_session() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            "aa".repeat(32),
            "bb".repeat(32)
        )
        .unwrap();
        writeln!(
            tmp,
            "SERVER_TRAFFIC_SECRET_0 {} {}",
            "aa".repeat(32),
            "cc".repeat(32)
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
        d.ensure_sessions_populated();
        let first_call = TlsSessionKey {
            client_random: [0xAAu8; 32],
        };
        assert!(
            d.sessions.contains_key(&first_call),
            "first call's session must be ready before the second call's keys arrive"
        );

        // A second, unrelated call's full TLS 1.3 keylog pair lands in a
        // later poll.
        writeln!(
            tmp,
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            "dd".repeat(32),
            "ee".repeat(32)
        )
        .unwrap();
        writeln!(
            tmp,
            "SERVER_TRAFFIC_SECRET_0 {} {}",
            "dd".repeat(32),
            "ff".repeat(32)
        )
        .unwrap();
        tmp.flush().unwrap();

        assert_eq!(
            d.poll_keylog_file().unwrap(),
            2,
            "second call's two entries"
        );
        assert!(
            d.sessions.contains_key(&first_call),
            "the first call's already-ready session must survive the second call's keylog poll"
        );
    }

    // ── load_dtls_keylog ───────────────────────────────────────────────

    /// `load_dtls_keylog` counts 0 for an empty file and 1 for a one-entry file.
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

    /// An all-zero record strips to empty, and empty input is a no-op.
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

    /// `build_record_aad` maps each content type and version, including the
    /// `Unknown` passthrough cases, to the right AAD bytes.
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
