//! DTLS-SRTP key extraction (RFC 5764).
//!
//! For SRTP keyed via DTLS-SRTP, the SRTP master keys are not on the wire — they
//! are *exported* from the DTLS handshake's master secret using the RFC 5705
//! keying-material exporter with the label `EXTRACTOR-dtls_srtp`. Given a DTLS
//! keylog (NSS `SSLKEYLOGFILE` `CLIENT_RANDOM` entries) plus the `client_random`
//! / `server_random` observed in the DTLS handshake, this module recomputes the
//! per-direction SRTP master key + salt and yields
//! [`SrtpKeyMaterial`](crate::rtp::srtp::SrtpKeyMaterial) ready for
//! [`SrtpContext`](crate::rtp::srtp::SrtpContext).
//!
//! Only the AES-CM SRTP protection profiles are produced (matching the SRTP
//! cipher this tool can decrypt); the DTLS handshake itself is not decrypted —
//! the master secret comes from the keylog.

use anyhow::{Context, Result};
use std::path::Path;

use super::tls::{KeyLogEntry, parse_keylog_file};
use crate::crypto::CryptoBackend;
use crate::rtp::srtp::{SrtpKeyMaterial, SrtpSuite};

/// RFC 5705 exporter label for DTLS-SRTP (RFC 5764 §4.2).
const EXPORTER_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// SRTP protection profile negotiated by the DTLS `use_srtp` extension
/// (RFC 5764 §4.1.2). Only AES-CM profiles (decryptable by this tool) are
/// represented; other codes map to `None` when parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    /// `SRTP_AES128_CM_HMAC_SHA1_80` (0x0001).
    Aes128CmHmacSha1_80,
    /// `SRTP_AES128_CM_HMAC_SHA1_32` (0x0002).
    Aes128CmHmacSha1_32,
}

impl SrtpProfile {
    fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(Self::Aes128CmHmacSha1_80),
            0x0002 => Some(Self::Aes128CmHmacSha1_32),
            _ => None,
        }
    }

    /// SRTP master key length in bytes.
    fn key_len(self) -> usize {
        16
    }

    /// SRTP master salt length in bytes.
    fn salt_len(self) -> usize {
        14
    }

    fn suite(self) -> SrtpSuite {
        match self {
            Self::Aes128CmHmacSha1_80 => SrtpSuite::AesCm128HmacSha1_80,
            Self::Aes128CmHmacSha1_32 => SrtpSuite::AesCm128HmacSha1_32,
        }
    }
}

/// Whether a UDP payload looks like a DTLS record (RFC 6347): a known content
/// type and a DTLS version (0xFEFF = 1.0, 0xFEFD = 1.2).
pub fn is_dtls(payload: &[u8]) -> bool {
    payload.len() >= 13
        && matches!(payload[0], 20..=23)
        && payload[1] == 0xFE
        && (payload[2] == 0xFF || payload[2] == 0xFD)
}

/// Yield `(handshake_type, message_body)` for each handshake message across the
/// DTLS records in `payload`. Only complete, unfragmented messages are
/// returned (the common case for ClientHello/ServerHello).
fn dtls_handshake_messages(payload: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    // DTLSPlaintext: type(1) version(2) epoch(2) seq(6) length(2) fragment[length]
    while off + 13 <= payload.len() {
        let content_type = payload[off];
        let rec_len = u16::from_be_bytes([payload[off + 11], payload[off + 12]]) as usize;
        let frag_start = off + 13;
        let frag_end = match frag_start.checked_add(rec_len) {
            Some(e) if e <= payload.len() => e,
            _ => break,
        };
        if content_type == 22 {
            // Handshake fragment: msg_type(1) length(3) message_seq(2)
            // fragment_offset(3) fragment_length(3) body
            let frag = &payload[frag_start..frag_end];
            if frag.len() >= 12 {
                let msg_type = frag[0];
                let length = u32::from_be_bytes([0, frag[1], frag[2], frag[3]]) as usize;
                let frag_off = u32::from_be_bytes([0, frag[4 + 2], frag[4 + 3], frag[4 + 4]]);
                let frag_len =
                    u32::from_be_bytes([0, frag[4 + 5], frag[4 + 6], frag[4 + 7]]) as usize;
                // Only handle a single unfragmented message per record.
                if frag_off == 0 && frag_len == length && frag.len() >= 12 + length {
                    out.push((msg_type, &frag[12..12 + length]));
                }
            }
        }
        off = frag_end;
    }
    out
}

/// Extract the 32-byte random from a ClientHello/ServerHello body. The body
/// begins `version(2) ‖ random(32) ‖ …`, so the random is at offset 2..34.
fn hello_random(body: &[u8]) -> Option<[u8; 32]> {
    if body.len() < 34 {
        return None;
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&body[2..34]);
    Some(r)
}

/// Parse the selected SRTP profile from a ServerHello body's `use_srtp`
/// extension (type 14), if present. Returns `None` if absent/unsupported.
fn server_hello_srtp_profile(body: &[u8]) -> Option<SrtpProfile> {
    // version(2) random(32) session_id(1+n) cipher_suite(2) compression(1)
    // extensions_len(2) extensions...
    let mut p = 2 + 32;
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    p += 2; // cipher_suite
    p += 1; // compression_method
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(body.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let data_start = p + 4;
        let data_end = data_start.checked_add(ext_len)?;
        if data_end > ext_end {
            break;
        }
        if ext_type == 14 {
            // use_srtp: SRTPProtectionProfiles = u16 list-length + list of u16.
            let data = &body[data_start..data_end];
            if data.len() >= 4 {
                let code = u16::from_be_bytes([data[2], data[3]]); // first profile
                return SrtpProfile::from_code(code);
            }
        }
        p = data_end;
    }
    None
}

/// Run the RFC 5705 exporter (label `EXTRACTOR-dtls_srtp`, no context) and split
/// the output into per-direction SRTP master key + salt (RFC 5764 §4.2).
/// Returns `(client_to_server, server_to_client)` key material.
pub fn derive_srtp_keys(
    crypto: &dyn CryptoBackend,
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    profile: SrtpProfile,
) -> Result<(SrtpKeyMaterial, SrtpKeyMaterial)> {
    let key_len = profile.key_len();
    let salt_len = profile.salt_len();
    let total = 2 * key_len + 2 * salt_len;

    // RFC 5705: seed = client_random ‖ server_random (no context for dtls_srtp).
    let seed = [client_random.as_slice(), server_random.as_slice()].concat();
    let block = super::decrypt::tls12_prf(crypto, master_secret, EXPORTER_LABEL, &seed, total)?;

    // Layout: client_key ‖ server_key ‖ client_salt ‖ server_salt.
    let ck = block[0..key_len].to_vec();
    let sk = block[key_len..2 * key_len].to_vec();
    let cs = block[2 * key_len..2 * key_len + salt_len].to_vec();
    let ss = block[2 * key_len + salt_len..total].to_vec();

    let mk = |key: Vec<u8>, salt: Vec<u8>| SrtpKeyMaterial {
        tag: 0,
        suite: profile.suite(),
        master_key: key,
        master_salt: salt,
        ssrc: None,
        media_addr: None,
        media_port: None,
    };
    Ok((mk(ck, cs), mk(sk, ss)))
}

/// Accumulates DTLS handshake state and a DTLS keylog, producing SRTP key
/// material once the `client_random`, `server_random`, and a matching master
/// secret are all known. Keys are emitted once per handshake.
pub struct DtlsSrtpExtractor {
    keylog: Vec<KeyLogEntry>,
    crypto: Box<dyn CryptoBackend>,
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    profile: Option<SrtpProfile>,
    produced: bool,
}

impl DtlsSrtpExtractor {
    /// Build from pre-parsed keylog entries.
    pub fn new(keylog: Vec<KeyLogEntry>, crypto: Box<dyn CryptoBackend>) -> Self {
        Self {
            keylog,
            crypto,
            client_random: None,
            server_random: None,
            profile: None,
            produced: false,
        }
    }

    /// Load DTLS keylog entries (NSS `SSLKEYLOGFILE` format) from a file.
    pub fn from_keylog_file(path: &Path, crypto: Box<dyn CryptoBackend>) -> Result<Self> {
        let entries = parse_keylog_file(path)
            .with_context(|| format!("Loading DTLS keylog from {}", path.display()))?;
        Ok(Self::new(entries, crypto))
    }

    /// Number of keylog entries available.
    pub fn keylog_len(&self) -> usize {
        self.keylog.len()
    }

    /// Feed a UDP payload that may be DTLS. Returns the per-direction SRTP key
    /// material the first time the handshake state and a matching master secret
    /// are complete; empty otherwise.
    pub fn process_dtls(&mut self, payload: &[u8]) -> Vec<SrtpKeyMaterial> {
        if !is_dtls(payload) {
            return Vec::new();
        }
        for (msg_type, body) in dtls_handshake_messages(payload) {
            match msg_type {
                1 => self.client_random = hello_random(body).or(self.client_random), // ClientHello
                2 => {
                    // ServerHello
                    if let Some(r) = hello_random(body) {
                        self.server_random = Some(r);
                    }
                    if let Some(p) = server_hello_srtp_profile(body) {
                        self.profile = Some(p);
                    }
                }
                _ => {}
            }
        }
        self.try_extract()
    }

    /// Attempt extraction; returns keys once when all inputs are present.
    fn try_extract(&mut self) -> Vec<SrtpKeyMaterial> {
        if self.produced {
            return Vec::new();
        }
        let (Some(cr), Some(sr)) = (self.client_random, self.server_random) else {
            return Vec::new();
        };
        // Default to the most common AES-CM-80 profile if no use_srtp seen.
        let profile = self.profile.unwrap_or(SrtpProfile::Aes128CmHmacSha1_80);

        // Find the master secret whose CLIENT_RANDOM matches.
        let master = self.keylog.iter().find_map(|e| {
            (e.label == "CLIENT_RANDOM" && e.client_random.as_slice() == cr.as_slice())
                .then(|| e.secret.clone())
        });
        let Some(master) = master else {
            return Vec::new();
        };

        match derive_srtp_keys(self.crypto.as_ref(), &master, &cr, &sr, profile) {
            Ok((c2s, s2c)) => {
                self.produced = true;
                tracing::info!("DTLS-SRTP: extracted SRTP keys ({:?})", profile);
                vec![c2s, s2c]
            }
            Err(e) => {
                tracing::debug!("DTLS-SRTP key derivation failed: {e}");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RingCryptoBackend;

    fn backend() -> Box<dyn CryptoBackend> {
        Box::new(RingCryptoBackend)
    }

    /// Wrap a handshake message body in a DTLS handshake record.
    fn dtls_handshake_record(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut hs = vec![msg_type];
        let len = body.len();
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(&[0, 0]); // message_seq
        hs.extend_from_slice(&[0, 0, 0]); // fragment_offset
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]); // fragment_length
        hs.extend_from_slice(body);

        let mut rec = vec![22u8, 0xFE, 0xFD]; // Handshake, DTLS 1.2
        rec.extend_from_slice(&[0, 0]); // epoch
        rec.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // sequence
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A ClientHello body with `random`.
    fn client_hello_body(random: &[u8; 32]) -> Vec<u8> {
        let mut b = vec![0xFE, 0xFD]; // client_version
        b.extend_from_slice(random);
        b.push(0); // session_id len
        b.push(0); // cookie len (DTLS)
        b.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // cipher_suites
        b.extend_from_slice(&[0x01, 0x00]); // compression
        b
    }

    /// A ServerHello body with `random` and a `use_srtp` extension selecting
    /// `profile_code`.
    fn server_hello_body(random: &[u8; 32], profile_code: u16) -> Vec<u8> {
        let mut b = vec![0xFE, 0xFD];
        b.extend_from_slice(random);
        b.push(0); // session_id len
        b.extend_from_slice(&[0x00, 0x2F]); // cipher_suite
        b.push(0); // compression
        // extensions: one use_srtp (type 14)
        // ext_data = profiles_len(2) ‖ profile(2) ‖ mki_len(1)=0
        let ext_data = [
            0x00u8,
            0x02,
            (profile_code >> 8) as u8,
            profile_code as u8,
            0x00,
        ];
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x0E]); // ext type 14
        exts.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_data);
        b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        b.extend_from_slice(&exts);
        b
    }

    #[test]
    fn is_dtls_detects_records_and_rejects_others() {
        let cr = [0u8; 32];
        assert!(is_dtls(&dtls_handshake_record(1, &client_hello_body(&cr))));
        assert!(!is_dtls(&[0u8; 4])); // too short
        // TLS (not DTLS) record version 0x0303.
        assert!(!is_dtls(&[22, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn parses_hello_randoms_and_profile() {
        let cr = [0xC1u8; 32];
        let sr = [0x5Eu8; 32];
        let ch = dtls_handshake_record(1, &client_hello_body(&cr));
        let sh = dtls_handshake_record(2, &server_hello_body(&sr, 0x0001));

        let chm = dtls_handshake_messages(&ch);
        assert_eq!(chm.len(), 1);
        assert_eq!(hello_random(chm[0].1), Some(cr));

        let shm = dtls_handshake_messages(&sh);
        assert_eq!(hello_random(shm[0].1), Some(sr));
        assert_eq!(
            server_hello_srtp_profile(shm[0].1),
            Some(SrtpProfile::Aes128CmHmacSha1_80)
        );
    }

    #[test]
    fn derive_srtp_keys_lengths_and_distinctness() {
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let master = vec![0x33u8; 48];
        let (c2s, s2c) = derive_srtp_keys(
            backend().as_ref(),
            &master,
            &cr,
            &sr,
            SrtpProfile::Aes128CmHmacSha1_80,
        )
        .unwrap();
        assert_eq!(c2s.master_key.len(), 16);
        assert_eq!(c2s.master_salt.len(), 14);
        assert_eq!(s2c.master_key.len(), 16);
        assert_eq!(s2c.master_salt.len(), 14);
        // Per-direction keys must differ.
        assert_ne!(c2s.master_key, s2c.master_key);
        assert_ne!(c2s.master_salt, s2c.master_salt);
    }

    #[test]
    fn derive_srtp_keys_is_deterministic() {
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let master = vec![0x33u8; 48];
        let a = derive_srtp_keys(
            backend().as_ref(),
            &master,
            &cr,
            &sr,
            SrtpProfile::Aes128CmHmacSha1_80,
        )
        .unwrap();
        let b = derive_srtp_keys(
            backend().as_ref(),
            &master,
            &cr,
            &sr,
            SrtpProfile::Aes128CmHmacSha1_80,
        )
        .unwrap();
        assert_eq!(a.0.master_key, b.0.master_key);
        assert_eq!(a.1.master_salt, b.1.master_salt);
    }

    #[test]
    fn extractor_emits_keys_once_when_complete() {
        let cr = [0xABu8; 32];
        let sr = [0xCDu8; 32];
        let master = vec![0x44u8; 48];
        let entries = vec![KeyLogEntry {
            label: "CLIENT_RANDOM".to_string(),
            client_random: cr.to_vec(),
            secret: master.clone(),
        }];
        let mut ex = DtlsSrtpExtractor::new(entries, backend());
        assert_eq!(ex.keylog_len(), 1);

        // ClientHello alone: not enough yet.
        assert!(
            ex.process_dtls(&dtls_handshake_record(1, &client_hello_body(&cr)))
                .is_empty()
        );
        // ServerHello completes the handshake → two keys.
        let keys = ex.process_dtls(&dtls_handshake_record(2, &server_hello_body(&sr, 0x0001)));
        assert_eq!(keys.len(), 2, "client→server and server→client keys");

        // Independently derived keys must match the exporter output.
        let (c2s, _s2c) = derive_srtp_keys(
            backend().as_ref(),
            &master,
            &cr,
            &sr,
            SrtpProfile::Aes128CmHmacSha1_80,
        )
        .unwrap();
        assert_eq!(keys[0].master_key, c2s.master_key);

        // Idempotent: already produced, no second emission.
        assert!(
            ex.process_dtls(&dtls_handshake_record(2, &server_hello_body(&sr, 0x0001)))
                .is_empty()
        );
    }

    #[test]
    fn extractor_without_matching_master_secret_yields_nothing() {
        let cr = [0xABu8; 32];
        let sr = [0xCDu8; 32];
        // Keylog has a DIFFERENT client_random → no match.
        let entries = vec![KeyLogEntry {
            label: "CLIENT_RANDOM".to_string(),
            client_random: vec![0x00u8; 32],
            secret: vec![0x44u8; 48],
        }];
        let mut ex = DtlsSrtpExtractor::new(entries, backend());
        ex.process_dtls(&dtls_handshake_record(1, &client_hello_body(&cr)));
        let keys = ex.process_dtls(&dtls_handshake_record(2, &server_hello_body(&sr, 0x0001)));
        assert!(keys.is_empty(), "no matching master secret ⇒ no keys");
    }

    /// The extracted client→server material must be usable SRTP keys: an SRTP
    /// packet built with the exported key authenticates and decrypts via
    /// SrtpContext. This ties DTLS-SRTP extraction to the RFC 3711 cipher.
    #[test]
    fn extracted_keys_decrypt_srtp_via_context() {
        use crate::rtp::srtp::SrtpContext;

        let cr = [0x1Au8; 32];
        let sr = [0x2Bu8; 32];
        let master = vec![0x5Cu8; 48];
        let (c2s, _s2c) = derive_srtp_keys(
            backend().as_ref(),
            &master,
            &cr,
            &sr,
            SrtpProfile::Aes128CmHmacSha1_80,
        )
        .unwrap();

        // Encrypt a packet with the exported client key, then decrypt via a
        // context seeded with the same extracted material.
        let packet = crate::rtp::srtp::test_support::build_srtp_packet(
            &c2s.master_key,
            &c2s.master_salt,
            0x0BAD_F00D,
            55,
            0,
            b"dtls-srtp media payload",
        );
        let mut ctx = SrtpContext::new(vec![c2s], backend());
        let out = ctx.decrypt(&packet, 12).expect("exported key decrypts");
        assert_eq!(&out[12..], b"dtls-srtp media payload");
    }
}
