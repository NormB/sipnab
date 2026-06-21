//! HMAC self-describing bearer tokens with expiry, rotation, and revocation.
//!
//! Shared between the REST API (`output::api`) and the HTTP MCP transport
//! (`mcp::transport`). Compiles whenever either the `api` or `mcp` feature is
//! enabled.
//!
//! # Token format
//!
//! `s1.<b64url(payload)>.<b64url(sig)>`
//!
//! - `payload` = compact JSON `{"id":"<jti>","exp":<unix_seconds>}` (no spaces).
//! - `sig` = HMAC-SHA256(signing_key, ASCII of `"s1." + b64url(payload)`).
//! - `b64url` is base64 URL-safe with NO padding.
//!
//! # Verification (stateless)
//!
//! Verification splits on `.`, requires the `s1` version, b64url-decodes the
//! payload and signature, recomputes the HMAC over `"s1." + payload_b64`, and
//! compares it to the presented signature in **constant time**. It then parses
//! the payload, requiring `exp > now` and that `id` is not in the revocation
//! denylist. Any parse/format error rejects (fail closed); attacker input never
//! panics.
//!
//! # Backward compatibility
//!
//! If the presented value is not a parseable `s1.` token, the verifier falls
//! back to a constant-time comparison against the configured static secret(s).
//! Static secrets have no expiry.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The token version prefix. Only `s1` tokens are accepted.
const VERSION: &str = "s1";

/// Constant-time byte comparison for API keys and token signatures.
///
/// Re-exported from [`crate::crypto`] (the always-compiled home for this
/// primitive) so the API/MCP auth path and the SRTP auth-tag verifier share a
/// single hardened implementation.
pub use crate::crypto::constant_time_eq;

/// Decoded token payload: a unique id (`jti`) and an absolute expiry.
#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    /// Token id used for revocation (denylist).
    id: String,
    /// Expiry as Unix epoch seconds.
    exp: i64,
}

/// Mint a signed token from `signing_key`, with id `id` and absolute expiry
/// `exp_unix` (Unix epoch seconds).
///
/// Produces `s1.<b64url(payload)>.<b64url(sig)>`. The payload is compact JSON
/// `{"id":...,"exp":...}` with no spaces.
pub fn mint(signing_key: &[u8], id: &str, exp_unix: i64) -> String {
    let payload = Payload {
        id: id.to_string(),
        exp: exp_unix,
    };
    // serde_json::to_string produces compact JSON (no spaces) by default.
    let payload_json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| format!("{{\"id\":\"{id}\",\"exp\":{exp_unix}}}"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{VERSION}.{payload_b64}");
    let sig = hmac_sha256(signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    format!("{signing_input}.{sig_b64}")
}

/// Compute HMAC-SHA256 over `msg` with `key`. Never fails (HMAC accepts keys
/// of any length).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail here.
    // Handle the Result without panicking (production code forbids unwrap/
    // expect); on the impossible error path return an empty MAC, which compares
    // unequal to any real signature — i.e. fails closed.
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    }
}

/// Revocation denylist backed by a text file: one revoked token `id` per line.
/// Blank lines and `#` comments are ignored. The file is re-read whenever its
/// mtime changes (stat per check, reparse only on change), so revocation takes
/// effect without restarting the process.
struct RevocationList {
    path: Option<PathBuf>,
    cache: Mutex<RevocationCache>,
}

#[derive(Default)]
struct RevocationCache {
    /// The mtime observed when `ids` was last loaded.
    mtime: Option<SystemTime>,
    /// Whether we have loaded at least once (so a missing/empty file is cached).
    loaded: bool,
    ids: HashSet<String>,
}

impl RevocationList {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            cache: Mutex::new(RevocationCache::default()),
        }
    }

    /// Return `true` if `id` is currently revoked. Reloads the backing file
    /// when its mtime has changed since the last check.
    fn is_revoked(&self, id: &str) -> bool {
        let Some(ref path) = self.path else {
            return false;
        };

        // Stat the file. If it cannot be stat'd, treat as "no revocations"
        // (fail open ONLY for the denylist — a missing denylist file means
        // nothing is revoked; auth itself still requires a valid signature).
        let current_mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();

        let mut cache = self.cache.lock();
        if !cache.loaded || cache.mtime != current_mtime {
            cache.ids = match std::fs::read_to_string(path) {
                Ok(contents) => parse_revocation_file(&contents),
                Err(_) => HashSet::new(),
            };
            cache.mtime = current_mtime;
            cache.loaded = true;
        }
        cache.ids.contains(id)
    }
}

/// Parse a revocation file: one id per line, ignoring blank lines and lines
/// whose first non-whitespace character is `#`.
fn parse_revocation_file(contents: &str) -> HashSet<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
}

/// Resolved authentication configuration for one surface (API or MCP).
#[derive(Debug, Clone, Default)]
pub struct VerifierConfig {
    /// HMAC signing keys. The first is used to mint; ALL are accepted on
    /// verify (signing-key rotation with overlap).
    pub signing_keys: Vec<Vec<u8>>,
    /// Static shared secrets (no expiry), accepted for backward compatibility.
    pub static_keys: Vec<String>,
    /// Optional path to the revocation denylist file.
    pub revoked_file: Option<PathBuf>,
}

impl VerifierConfig {
    /// `true` if no signing keys AND no static secrets are configured — i.e.
    /// auth is effectively unconfigured and the surface should behave as it did
    /// before this feature existed (loopback allowed, non-loopback refused).
    pub fn is_unconfigured(&self) -> bool {
        self.signing_keys.is_empty() && self.static_keys.is_empty()
    }
}

/// Stateless signed-token verifier. `Send + Sync` for use in async axum
/// handlers.
pub struct TokenVerifier {
    signing_keys: Vec<Vec<u8>>,
    static_keys: Vec<String>,
    revocation: RevocationList,
}

impl TokenVerifier {
    /// Build a verifier from a resolved [`VerifierConfig`].
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            signing_keys: config.signing_keys,
            static_keys: config.static_keys,
            revocation: RevocationList::new(config.revoked_file),
        }
    }

    /// `true` if neither signing keys nor static secrets are configured.
    pub fn is_unconfigured(&self) -> bool {
        self.signing_keys.is_empty() && self.static_keys.is_empty()
    }

    /// Verify a presented Authorization value (the part after `Bearer `).
    ///
    /// Returns `true` iff the value is either:
    /// - a valid, unexpired, non-revoked `s1.` token signed by one of the
    ///   configured signing keys; or
    /// - an exact (constant-time) match for one of the configured static
    ///   secrets.
    ///
    /// `now_unix` is the current time in Unix epoch seconds (production passes
    /// `chrono::Utc::now().timestamp()`); injecting it keeps expiry logic
    /// deterministically testable. Fails closed on any parse/format error.
    pub fn verify(&self, presented: &str, now_unix: i64) -> bool {
        // Try the signed-token path first.
        if let Some(result) = self.verify_signed(presented, now_unix) {
            return result;
        }
        // Fall back to static-secret comparison (no expiry).
        self.verify_static(presented)
    }

    /// Attempt signed-token verification. Returns `None` if `presented` is not
    /// a structurally-recognizable `s1.` token (so the caller can fall back to
    /// static secrets); `Some(true)`/`Some(false)` for accept/reject of a token
    /// that *is* an `s1.` token.
    fn verify_signed(&self, presented: &str, now_unix: i64) -> Option<bool> {
        // Split into exactly 3 dot-parts.
        let mut parts = presented.split('.');
        let version = parts.next()?;
        let payload_b64 = parts.next()?;
        let sig_b64 = parts.next()?;
        if parts.next().is_some() {
            // More than 3 parts — not our format.
            return None;
        }
        if version != VERSION {
            // Not an s1 token — let static fallback handle it.
            return None;
        }
        // From here on this is unambiguously an s1 token; any failure rejects.

        // Decode the presented signature.
        let Ok(presented_sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
            return Some(false);
        };

        // Recompute HMAC over "s1." + payload_b64 and compare in constant time
        // against ALL signing keys (rotation with overlap).
        let signing_input = format!("{VERSION}.{payload_b64}");
        let mut sig_ok = false;
        for key in &self.signing_keys {
            let expected = hmac_sha256(key, signing_input.as_bytes());
            // OR rather than early-return so the comparison cost does not leak
            // which key (if any) matched.
            sig_ok |= constant_time_eq(&presented_sig, &expected);
        }
        if !sig_ok {
            return Some(false);
        }

        // Decode + parse the payload.
        let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
            return Some(false);
        };
        let Ok(payload) = serde_json::from_slice::<Payload>(&payload_bytes) else {
            return Some(false);
        };

        // Expiry: require exp strictly greater than now.
        if payload.exp <= now_unix {
            return Some(false);
        }

        // Revocation denylist.
        if self.revocation.is_revoked(&payload.id) {
            return Some(false);
        }

        Some(true)
    }

    /// Constant-time comparison against each configured static secret.
    fn verify_static(&self, presented: &str) -> bool {
        let mut ok = false;
        for key in &self.static_keys {
            ok |= constant_time_eq(presented.as_bytes(), key.as_bytes());
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &[u8] = b"signing-key-alpha-0123456789";
    const KEY_B: &[u8] = b"signing-key-beta-9876543210";

    fn verifier(cfg: VerifierConfig) -> TokenVerifier {
        TokenVerifier::new(cfg)
    }

    // ── constant_time_eq hardening tests (relocated from output::api) ──

    #[test]
    fn constant_time_eq_equal_slices() {
        assert!(
            constant_time_eq(b"secret-key-12345", b"secret-key-12345"),
            "Identical slices should return true"
        );
    }

    #[test]
    fn constant_time_eq_different_slices() {
        assert!(
            !constant_time_eq(b"secret-key-12345", b"secret-key-XXXXX"),
            "Different slices of same length should return false"
        );
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(
            !constant_time_eq(b"short", b"much-longer-string"),
            "Different length slices should return false"
        );
        assert!(
            !constant_time_eq(b"much-longer-string", b"short"),
            "Different length slices (reversed) should return false"
        );
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(
            constant_time_eq(b"", b""),
            "Two empty slices should return true"
        );
    }

    // ── token format ──────────────────────────────────────────────────

    #[test]
    fn minted_token_has_expected_shape() {
        let token = mint(KEY_A, "abc", 9999999999);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "token should have 3 dot-parts: {token}");
        assert_eq!(parts[0], "s1");
        // Payload decodes to compact JSON with id+exp.
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload b64");
        let s = String::from_utf8(payload).expect("utf8");
        assert_eq!(s, "{\"id\":\"abc\",\"exp\":9999999999}");
    }

    // ── valid / accept ─────────────────────────────────────────────────

    #[test]
    fn valid_token_accepted() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id1", 1_000);
        assert!(v.verify(&token, 999), "unexpired token should verify");
    }

    // ── expired ─────────────────────────────────────────────────────────

    #[test]
    fn expired_token_rejected() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id1", 1_000);
        // now == exp → reject (exp must be strictly greater than now).
        assert!(!v.verify(&token, 1_000), "exp == now should reject");
        // now > exp → reject.
        assert!(!v.verify(&token, 1_001), "expired token should reject");
    }

    // ── tampered payload ────────────────────────────────────────────────

    #[test]
    fn tampered_payload_rejected() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id1", 1_000_000);
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        // Flip a byte in the payload b64. Pick a char and replace with another.
        let payload = parts[1].clone();
        let mut bytes = payload.into_bytes();
        let idx = bytes.len() / 2;
        bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
        parts[1] = String::from_utf8(bytes).unwrap();
        let tampered = parts.join(".");
        assert!(
            !v.verify(&tampered, 1),
            "tampered payload must fail signature/parse"
        );
    }

    // ── forged / wrong-key signature ─────────────────────────────────────

    #[test]
    fn forged_wrong_key_signature_rejected() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        // Token signed with a DIFFERENT key.
        let forged = mint(KEY_B, "id1", 1_000_000);
        assert!(
            !v.verify(&forged, 1),
            "token signed with a non-configured key must reject"
        );
    }

    #[test]
    fn garbage_token_rejected_no_panic() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        for junk in [
            "",
            "s1",
            "s1.",
            "s1..",
            "s1.@@@.@@@",
            "s2.aaaa.bbbb",
            "s1.aaaa.bbbb.cccc",
            "not-a-token",
            "s1.\0.\0",
        ] {
            assert!(
                !v.verify(junk, 1),
                "junk {junk:?} must reject without panic"
            );
        }
    }

    // ── rotation ─────────────────────────────────────────────────────────

    #[test]
    fn rotation_accepts_either_key() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec(), KEY_B.to_vec()],
            ..Default::default()
        });
        let token_a = mint(KEY_A, "ida", 1_000_000);
        let token_b = mint(KEY_B, "idb", 1_000_000);
        assert!(v.verify(&token_a, 1), "token signed by first key accepted");
        assert!(v.verify(&token_b, 1), "token signed by second key accepted");
    }

    #[test]
    fn mint_uses_first_key() {
        // A verifier that only knows KEY_B should reject a token minted by the
        // "first key" of a {A,B} config (which is A).
        let mint_cfg_first = KEY_A;
        let token = mint(mint_cfg_first, "x", 1_000_000);
        let v_b_only = verifier(VerifierConfig {
            signing_keys: vec![KEY_B.to_vec()],
            ..Default::default()
        });
        assert!(!v_b_only.verify(&token, 1));
    }

    // ── revocation ───────────────────────────────────────────────────────

    #[test]
    fn revoked_id_rejected_and_reload_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("revoked.txt");
        std::fs::write(&path, "# comment\n\nrevoked-id-1\n").expect("write");

        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            revoked_file: Some(path.clone()),
            ..Default::default()
        });

        // A token with a revoked id is rejected even though the signature is
        // valid and it is unexpired.
        let revoked = mint(KEY_A, "revoked-id-1", 1_000_000);
        assert!(!v.verify(&revoked, 1), "revoked id must reject");

        // A fresh token with a different id is accepted.
        let fresh = mint(KEY_A, "fresh-id", 1_000_000);
        assert!(v.verify(&fresh, 1), "non-revoked id must accept");

        // Remove the revocation from the file; the previously-revoked id is now
        // accepted (mtime change triggers a reload). Touch mtime explicitly in
        // case the filesystem mtime granularity would otherwise collapse the
        // two writes.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, "# nothing revoked now\n").expect("rewrite");
        let after = mint(KEY_A, "revoked-id-1", 1_000_000);
        assert!(
            v.verify(&after, 1),
            "after removing from denylist, id should be accepted (reload)"
        );
    }

    // ── backward compat (static secrets) ────────────────────────────────

    #[test]
    fn static_secret_backward_compat() {
        let v = verifier(VerifierConfig {
            static_keys: vec!["legacy-secret".to_string()],
            ..Default::default()
        });
        assert!(
            v.verify("legacy-secret", 1),
            "correct static secret accepts"
        );
        assert!(!v.verify("wrong-secret", 1), "wrong static secret rejects");
        // Static secrets never expire — now_unix is irrelevant for them.
        assert!(
            v.verify("legacy-secret", i64::MAX),
            "static secret has no expiry"
        );
    }

    #[test]
    fn static_secret_does_not_collide_with_signed_format() {
        // A static secret that happens to look like "s1.foo.bar" is NOT a valid
        // signed token (bad b64 / signature), so it falls through to the static
        // comparison and matches itself.
        let secret = "s1.notreal.notreal";
        let v = verifier(VerifierConfig {
            static_keys: vec![secret.to_string()],
            ..Default::default()
        });
        // "s1.notreal.notreal" — b64 "notreal" decodes fine, but signature
        // mismatch → verify_signed returns Some(false), so the static fallback
        // is NOT reached. This is acceptable: do not pick static secrets that
        // look like s1 tokens. Document via assertion.
        assert!(!v.verify(secret, 1));
    }

    #[test]
    fn signing_and_static_both_configured() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            static_keys: vec!["legacy".to_string()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id", 1_000_000);
        assert!(v.verify(&token, 1), "signed token accepts");
        assert!(v.verify("legacy", 1), "static secret accepts");
        assert!(!v.verify("nope", 1), "unknown rejects");
    }

    #[test]
    fn unconfigured_verifier() {
        let v = verifier(VerifierConfig::default());
        assert!(v.is_unconfigured());
        // With nothing configured, even a well-formed-looking token rejects
        // (no key to verify against, no static secret to match).
        assert!(!v.verify("anything", 1));
    }
}
