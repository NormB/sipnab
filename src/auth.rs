// SPDX-License-Identifier: MIT OR Apache-2.0

//! HMAC self-describing bearer tokens with expiry, rotation, and revocation.
//!
//! Shared between the REST API (`output::api`) and the HTTP MCP transport
//! (`mcp::transport`). Compiles whenever either the `api` or `mcp` feature is
//! enabled.
//!
//! # Token format
//!
//! `s2.<b64url(payload)>.<b64url(sig)>`
//!
//! - `payload` = compact JSON `{"id":"<jti>","exp":<unix_seconds>,"aud":"<api|mcp>"}`
//!   (no spaces).
//! - `sig` = HMAC-SHA256(signing_key, ASCII of `"s2." + b64url(payload)`).
//! - `b64url` is base64 URL-safe with NO padding.
//!
//! # Audience binding
//!
//! `aud` names the surface the token was minted for. A REST API token is
//! rejected by HTTP MCP and vice versa, so configuring the *same* signing key
//! on both surfaces — an easy mistake, since they are separate flags reading
//! separate env vars — can no longer silently grant cross-surface access.
//! The version prefix is part of the signed input, so an `s2` token cannot be
//! downgraded to `s1` to shed its binding.
//!
//! # Verification (stateless)
//!
//! Verification splits on `.`, requires the `s2` version, b64url-decodes the
//! payload and signature, recomputes the HMAC over `"s2." + payload_b64`, and
//! compares it to the presented signature in **constant time**. It then parses
//! the payload, requiring the audience to match, `exp > now`, and that `id` is
//! not in the revocation denylist. Any parse/format error rejects (fail
//! closed); attacker input never panics.
//!
//! The audience check is unconditional — there is no accepted token version
//! that skips it.
//!
//! # Backward compatibility
//!
//! The pre-`aud` `s1` format is **no longer accepted**. It carried no audience,
//! so an `s1` token authenticated against both surfaces; honoring it would have
//! left the binding above best-effort rather than absolute. An `s1.` value now
//! falls through to the static-secret path and is compared as an opaque string,
//! which a real minted token will never match — so it is simply rejected.
//! Re-mint with `--mint-token`.
//!
//! If the presented value is not a parseable `s2.` token, the verifier falls
//! back to a constant-time comparison against the configured static secret(s).
//! Static secrets have no expiry and no audience.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// HMAC-SHA256 keyed hash used to sign and verify token payloads.
type HmacSha256 = Hmac<Sha256>;

/// The only accepted token version. `s2` tokens carry an `aud` claim binding
/// them to one surface. The pre-`aud` `s1` format is no longer minted *or*
/// accepted: it carried no audience, so an `s1` token authenticated against
/// either surface, which is exactly the weakness `s2` exists to remove.
const VERSION: &str = "s2";

/// Audience value for REST API tokens.
pub const AUDIENCE_API: &str = "api";

/// Audience value for HTTP MCP tokens.
pub const AUDIENCE_MCP: &str = "mcp";

/// Full access: every endpoint of the bound surface. The default for a token
/// minted without an explicit scope, and what every pre-scope token is treated
/// as — so adding this claim cannot revoke access a live token already had.
pub const SCOPE_FULL: &str = "full";

/// Scrape-only access: `GET /metrics` and nothing else.
///
/// A monitoring system needs one endpoint. Without this it had to be trusted
/// with a `full` credential, which on a TLS-decrypting capture tool reads
/// `/v1/dialogs`, `/v1/streams` and their message bodies — the call content
/// itself. That is the least-privilege split worth having; the rest of the
/// surface is one trust domain.
pub const SCOPE_METRICS: &str = "metrics";

/// Read-only access to the MCP surface: tools whose registered annotations
/// carry `read_only_hint = true`, and nothing else — no `export_capture` /
/// `export_audio`, no `shutdown_server`, no `open_capture`, no
/// `save_findings`.
///
/// A diagnostic agent needs to read dialogs and findings; before this scope
/// existed it had to be handed a `full` credential, so the token in a
/// read-only agent's config could also stop the server or point the capture
/// at a different file. Which tools the scope reaches is decided per call in
/// `mcp::server::call_tool` FROM the tool's own `read_only_hint` annotation —
/// the same annotation the client is shown — not from a second hand-kept
/// list that could drift from it.
pub const SCOPE_READ: &str = "read";

/// Constant-time byte comparison for API keys and token signatures.
///
/// Re-exported from `crate::crypto` (the always-compiled home for this
/// primitive) so the API/MCP auth path and the SRTP auth-tag verifier share a
/// single hardened implementation.
pub use crate::crypto::constant_time_eq;

/// Decoded token payload: a unique id (`jti`), an absolute expiry, and — for
/// `s2` tokens — the audience the token is bound to.
#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    /// Token id used for revocation (denylist).
    id: String,
    /// Expiry as Unix epoch seconds.
    exp: i64,
    /// Surface this token is valid for (`api` or `mcp`). Required: a payload
    /// without it cannot match any configured audience, so it never verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    /// What the token may reach within that surface ([`SCOPE_FULL`],
    /// [`SCOPE_METRICS`], or [`SCOPE_READ`]).
    ///
    /// Optional, and absent means [`SCOPE_FULL`] — unlike `aud`, which fails
    /// closed when missing. The asymmetry is deliberate: `aud` was introduced
    /// with a format bump (`s1` → `s2`) that stopped accepting the old tokens
    /// outright, whereas tokens minted before `scope` existed are still valid
    /// `s2` tokens in the field, and treating them as unscoped-therefore-denied
    /// would revoke live credentials on upgrade. Defaulting to `full` keeps
    /// them working exactly as they did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Mint a signed token from `signing_key`, with id `id`, absolute expiry
/// `exp_unix` (Unix epoch seconds), audience `audience` — one of
/// [`AUDIENCE_API`] or [`AUDIENCE_MCP`] — and scope `scope`, one of
/// [`SCOPE_FULL`], [`SCOPE_METRICS`], or [`SCOPE_READ`].
///
/// Produces `s2.<b64url(payload)>.<b64url(sig)>`. The payload is compact JSON
/// `{"id":...,"exp":...,"aud":...}` with no spaces. The version prefix is part
/// of the signed input, so it cannot be rewritten to `s1` to shed the audience
/// binding without invalidating the signature.
pub fn mint(signing_key: &[u8], id: &str, exp_unix: i64, audience: &str, scope: &str) -> String {
    let payload = Payload {
        id: id.to_string(),
        exp: exp_unix,
        aud: Some(audience.to_string()),
        // Emitted only when it narrows something. A `full` token stays
        // byte-identical to a pre-scope one, so the claim costs nothing on the
        // common path and its presence always means "restricted".
        scope: (scope != SCOPE_FULL).then(|| scope.to_string()),
    };
    // serde_json::to_string produces compact JSON (no spaces) by default, and
    // serializing this concrete `{id: String, exp: i64}` into an in-memory
    // String is infallible: serde_json only errors on a failing Serialize impl,
    // a non-string map key, or non-UTF-8 output — none of which this type can
    // produce. Handle the Result without unwrap/expect (production forbids
    // them) by failing closed on the unreachable error path. An empty payload
    // yields a token that cannot verify; the earlier hand-built fallback
    // interpolated `id` UNESCAPED (`{"id":"<id>",...}`), so a crafted id
    // carrying a quote/backslash/control char could break the JSON — that
    // dead branch is removed rather than escaped.
    let payload_json = serde_json::to_string(&payload).unwrap_or_default();
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
    /// Backing denylist file; `None` disables revocation (nothing revoked).
    path: Option<PathBuf>,
    /// Cached parsed ids plus the mtime they were loaded at, behind a mutex.
    cache: Mutex<RevocationCache>,
}

/// Cached parse of the revocation file plus the mtime it was read at,
/// so unchanged files are not re-read on every verification.
#[derive(Default)]
struct RevocationCache {
    /// The mtime observed when `ids` was last loaded.
    mtime: Option<SystemTime>,
    /// Whether we have loaded at least once (so a missing/empty file is cached).
    loaded: bool,
    /// The set of revoked token ids parsed from the file.
    ids: HashSet<String>,
}

impl RevocationList {
    /// Create a revocation list backed by `path` (or `None` for no denylist).
    /// The file is not read until the first `is_revoked` call.
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
    /// The surface this verifier guards ([`AUDIENCE_API`] / [`AUDIENCE_MCP`]).
    /// An `s2` token is accepted only when its `aud` matches. Left empty, no
    /// `s2` token can ever match — fail closed rather than accept anything.
    pub audience: String,
}

impl VerifierConfig {
    /// `true` if no signing keys AND no static secrets are configured — i.e.
    /// auth is effectively unconfigured and the surface should behave as it did
    /// before this feature existed (loopback allowed, non-loopback refused).
    pub fn is_unconfigured(&self) -> bool {
        self.signing_keys.is_empty() && self.static_keys.is_empty()
    }
}

/// The claims accepted from a verified credential.
///
/// Returned by [`TokenVerifier::verify_claims`] so the caller can enforce
/// scope per-resource (the MCP surface decides per TOOL, which a single
/// `required_scope` argument cannot express). Only claims that survived
/// signature, audience, expiry, and revocation checks ever end up here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedToken {
    /// The scope the credential carries: the token's `scope` claim, or
    /// [`SCOPE_FULL`] when the claim is absent (pre-scope tokens) or the
    /// credential is a static secret (which carries no claims at all).
    pub scope: String,
    /// The verified token's `id` claim — the `jti` the operator set with
    /// `--token-id`, and the string a revocation denylist matches on.
    ///
    /// Returned so an audit record can name WHICH credential made a call.
    /// Without it the strongest thing a log could say was "somebody holding a
    /// valid token, from this socket", which does not separate two agents
    /// sharing a host — and does not tell an operator what to revoke.
    ///
    /// `None` for a static shared secret, which carries no claims and
    /// therefore has no id. Absent rather than an empty string on purpose:
    /// a blank id would be indistinguishable from a token minted with one.
    pub id: Option<String>,
}

/// Outcome of the signed-token path, before the static-secret fallback.
///
/// Three-way rather than `Option<bool>` because the distinction it encodes is
/// the security property: a value that is not token-shaped may fall through
/// to the static-secret comparison, but a value that IS token-shaped and
/// fails must reject outright — otherwise a rejected token would get a second
/// chance against the static secrets.
enum SignedOutcome {
    /// Not structurally one of our tokens; the caller may fall back to the
    /// static-secret comparison.
    NotAToken,
    /// Token-shaped but failed verification (signature, audience, expiry, or
    /// revocation). Never falls through.
    Rejected,
    /// Verified; carries the accepted claims.
    Accepted(AcceptedToken),
}

/// Stateless signed-token verifier. `Send + Sync` for use in async axum
/// handlers.
pub struct TokenVerifier {
    /// HMAC signing keys; all are accepted on verify (rotation with overlap).
    signing_keys: Vec<Vec<u8>>,
    /// Static shared secrets accepted verbatim (no expiry), for compatibility.
    static_keys: Vec<String>,
    /// Revocation denylist consulted for a token's `id` after signature check.
    revocation: RevocationList,
    /// The surface this verifier guards; a token's `aud` must equal it.
    audience: String,
}

impl TokenVerifier {
    /// Build a verifier from a resolved `VerifierConfig`.
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            signing_keys: config.signing_keys,
            static_keys: config.static_keys,
            revocation: RevocationList::new(config.revoked_file),
            audience: config.audience,
        }
    }

    /// `true` if neither signing keys nor static secrets are configured.
    pub fn is_unconfigured(&self) -> bool {
        self.signing_keys.is_empty() && self.static_keys.is_empty()
    }

    /// Verify a presented Authorization value (the part after `Bearer `),
    /// requiring `required_scope` to be satisfied.
    ///
    /// Returns `true` iff [`verify_claims`](Self::verify_claims) accepts the
    /// credential AND its scope satisfies the requirement — `full` satisfies
    /// anything, a narrower scope satisfies only itself. This is a thin
    /// wrapper over `verify_claims` rather than a second verification path:
    /// two parallel implementations of "is this token valid" is exactly the
    /// kind of divergence that turns into a bypass.
    ///
    /// `now_unix` is the current time in Unix epoch seconds (production passes
    /// `chrono::Utc::now().timestamp()`); injecting it keeps expiry logic
    /// deterministically testable. Fails closed on any parse/format error.
    pub fn verify(&self, presented: &str, now_unix: i64, required_scope: &str) -> bool {
        match self.verify_claims(presented, now_unix) {
            Some(accepted) => {
                // A `full` token satisfies any requirement; a narrower one
                // satisfies only its own. Absent-means-full is resolved inside
                // `verify_claims` — see `Payload::scope` for why that
                // direction is safe and `aud`'s is not.
                accepted.scope == SCOPE_FULL || accepted.scope == required_scope
            }
            None => false,
        }
    }

    /// Verify a presented Authorization value and return the accepted claims,
    /// leaving scope enforcement to the caller.
    ///
    /// Applies every check [`verify`](Self::verify) applies — signature over
    /// all configured keys, audience match, expiry, revocation — EXCEPT the
    /// scope comparison, which the caller performs against whatever resource
    /// is being requested. The MCP surface needs this split: its middleware
    /// must admit any valid token so a read-scoped agent can initialize and
    /// list tools, while the per-tool check happens at dispatch where the
    /// requested tool's annotations are in hand.
    ///
    /// Returns `None` when the credential is invalid for any reason; a
    /// returned [`AcceptedToken`] always carries a resolved scope, and the
    /// token's id when the credential had one (see [`AcceptedToken::id`]).
    pub fn verify_claims(&self, presented: &str, now_unix: i64) -> Option<AcceptedToken> {
        match self.verify_signed(presented, now_unix) {
            SignedOutcome::Accepted(accepted) => Some(accepted),
            SignedOutcome::Rejected => None,
            // Fall back to static-secret comparison (no expiry).
            //
            // A static secret carries no claims at all, so it cannot express a
            // scope and is treated as [`SCOPE_FULL`]. Narrowing it here would
            // silently downgrade every existing `--api-key` deployment to
            // scrape-only; an operator who wants least privilege mints a
            // token, which is the mechanism that can carry the claim.
            SignedOutcome::NotAToken => self.verify_static(presented).then(|| AcceptedToken {
                scope: SCOPE_FULL.to_string(),
                // No claims at all means no id to report. See `AcceptedToken::id`.
                id: None,
            }),
        }
    }

    /// Attempt signed-token verification. Returns [`SignedOutcome::NotAToken`]
    /// if `presented` is not a structurally-recognizable `s2.` token (so the
    /// caller can fall back to static secrets); `Rejected`/`Accepted` for a
    /// value that *is* one of our tokens.
    fn verify_signed(&self, presented: &str, now_unix: i64) -> SignedOutcome {
        // Split into exactly 3 dot-parts.
        let mut parts = presented.split('.');
        let (Some(version), Some(payload_b64), Some(sig_b64)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return SignedOutcome::NotAToken;
        };
        if parts.next().is_some() {
            // More than 3 parts — not our format.
            return SignedOutcome::NotAToken;
        }
        if version != VERSION {
            // Not one of our tokens — let static fallback handle it. A legacy
            // `s1.` value lands here and is treated as an opaque string: it can
            // only succeed if it happens to equal a configured static secret,
            // which a real minted token never will.
            return SignedOutcome::NotAToken;
        }
        // From here on this is unambiguously one of our tokens; any failure
        // rejects rather than falling through to the static-secret path.

        // Decode the presented signature.
        let Ok(presented_sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
            return SignedOutcome::Rejected;
        };

        // Recompute HMAC over "<version>." + payload_b64 and compare in
        // constant time against ALL signing keys (rotation with overlap).
        // The version is part of the signed input, so an `s2` token cannot be
        // downgraded to `s1` (shedding its audience binding) by editing the
        // prefix — the signature would no longer match.
        let signing_input = format!("{version}.{payload_b64}");
        let mut sig_ok = false;
        for key in &self.signing_keys {
            let expected = hmac_sha256(key, signing_input.as_bytes());
            // OR rather than early-return so the comparison cost does not leak
            // which key (if any) matched.
            sig_ok |= constant_time_eq(&presented_sig, &expected);
        }
        if !sig_ok {
            return SignedOutcome::Rejected;
        }

        // Decode + parse the payload.
        let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
            return SignedOutcome::Rejected;
        };
        let Ok(payload) = serde_json::from_slice::<Payload>(&payload_bytes) else {
            return SignedOutcome::Rejected;
        };

        // Audience. A token names the surface it was minted for and is rejected
        // by any other — so reusing one signing key across the REST API and
        // HTTP MCP cannot grant cross-surface access. An empty configured
        // audience matches nothing, which fails closed. This is unconditional:
        // there is no version of the format that skips it.
        if payload.aud.as_deref() != Some(self.audience.as_str()) || self.audience.is_empty() {
            return SignedOutcome::Rejected;
        }

        // Expiry: require exp strictly greater than now.
        if payload.exp <= now_unix {
            return SignedOutcome::Rejected;
        }

        // Revocation denylist.
        if self.revocation.is_revoked(&payload.id) {
            return SignedOutcome::Rejected;
        }

        // The scope claim is NOT checked here — it is returned, and the
        // caller compares it against whatever is being requested. Absent
        // means `full`; see `Payload::scope` for why that direction is safe
        // and `aud`'s is not.
        //
        // The id is carried out with it. It has already been consulted above
        // (the revocation check) and was then dropped, which is why an audit
        // record could not name the credential it had just verified.
        SignedOutcome::Accepted(AcceptedToken {
            scope: payload.scope.unwrap_or_else(|| SCOPE_FULL.to_string()),
            id: Some(payload.id),
        })
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
    //! Token mint/verify, expiry, tampering, rotation, revocation, and
    //! static-secret backward-compat tests, plus the relocated
    //! `constant_time_eq` hardening cases.
    use super::*;

    /// First test signing key.
    const KEY_A: &[u8] = b"signing-key-alpha-0123456789";
    /// Second test signing key (for rotation/wrong-key cases).
    const KEY_B: &[u8] = b"signing-key-beta-9876543210";

    /// Build a `TokenVerifier` from a config (test-readability wrapper).
    /// Defaults the audience to the API surface so existing cases, which mint
    /// with `AUDIENCE_API`, read unchanged; the audience-specific cases set it
    /// explicitly.
    fn verifier(mut cfg: VerifierConfig) -> TokenVerifier {
        if cfg.audience.is_empty() {
            cfg.audience = AUDIENCE_API.to_string();
        }
        TokenVerifier::new(cfg)
    }

    /// Failing-first evidence for the removed hand-built serialization
    /// fallback: interpolating an unescaped `id` into `{"id":"<id>",...}`
    /// yields INVALID JSON when the id carries a quote/backslash/control char.
    /// The infallible serde path is now the only path, so this reproduction
    /// documents why the branch was dead-code+latent-bug and was dropped.
    #[test]
    fn removed_hand_built_fallback_produced_invalid_json() {
        let id = "a\"b\\c\u{0001}";
        let exp = 0i64;
        // Exactly what the removed `unwrap_or_else` branch built by hand.
        let hand_built = format!("{{\"id\":\"{id}\",\"exp\":{exp}}}");
        let parsed: Result<Payload, _> = serde_json::from_str(&hand_built);
        assert!(
            parsed.is_err(),
            "the removed fallback embedded id unescaped and produced invalid \
             JSON — proof it was a latent bug: {hand_built:?}"
        );
    }

    /// A token id carrying JSON metacharacters and a control character must be
    /// escaped in the payload so the token round-trips: the decoded payload
    /// yields the exact id byte-for-byte and the token still verifies. Locks
    /// in that the (now sole) serde serialization path escapes correctly.
    #[test]
    fn mint_escapes_hostile_id_in_payload() {
        let hostile = "id\"with\\meta\tand\u{0001}control";
        let exp = 4_000_000_000i64;
        let token = mint(KEY_A, hostile, exp, AUDIENCE_API, SCOPE_FULL);

        // The payload segment must be valid, escaped JSON decoding back to id.
        let payload_b64 = token.split('.').nth(1).expect("payload segment");
        let bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("payload must be valid base64url");
        let decoded: Payload =
            serde_json::from_slice(&bytes).expect("payload must be valid, escaped JSON");
        assert_eq!(decoded.id, hostile, "id must round-trip byte-for-byte");

        // And the whole token must verify against the signing key.
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        assert!(
            v.verify(&token, exp - 1, SCOPE_FULL),
            "a token minted with a hostile id must still verify"
        );
    }

    // ── constant_time_eq hardening tests (relocated from output::api) ──

    /// Identical byte slices compare equal.
    #[test]
    fn constant_time_eq_equal_slices() {
        assert!(
            constant_time_eq(b"secret-key-12345", b"secret-key-12345"),
            "Identical slices should return true"
        );
    }

    /// Equal-length but differing slices compare unequal.
    #[test]
    fn constant_time_eq_different_slices() {
        assert!(
            !constant_time_eq(b"secret-key-12345", b"secret-key-XXXXX"),
            "Different slices of same length should return false"
        );
    }

    /// Different-length slices compare unequal in both argument orders.
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

    /// Two empty slices compare equal.
    #[test]
    fn constant_time_eq_empty() {
        assert!(
            constant_time_eq(b"", b""),
            "Two empty slices should return true"
        );
    }

    // ── token format ──────────────────────────────────────────────────

    /// A minted token is `s1.<payload>.<sig>` with the payload decoding to the
    /// expected compact `{"id":...,"exp":...}` JSON.
    #[test]
    fn minted_token_has_expected_shape() {
        let token = mint(KEY_A, "abc", 9999999999, AUDIENCE_API, SCOPE_FULL);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "token should have 3 dot-parts: {token}");
        assert_eq!(parts[0], "s2");
        // Payload decodes to compact JSON with id+exp+aud.
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload b64");
        let s = String::from_utf8(payload).expect("utf8");
        assert_eq!(s, "{\"id\":\"abc\",\"exp\":9999999999,\"aud\":\"api\"}");
    }

    // ── valid / accept ─────────────────────────────────────────────────

    /// An unexpired token signed by a configured key verifies.
    #[test]
    fn valid_token_accepted() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id1", 1_000, AUDIENCE_API, SCOPE_FULL);
        assert!(
            v.verify(&token, 999, SCOPE_FULL),
            "unexpired token should verify"
        );
    }

    // ── expired ─────────────────────────────────────────────────────────

    /// A token is rejected once `now >= exp` (expiry is strict `exp > now`).
    #[test]
    fn expired_token_rejected() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id1", 1_000, AUDIENCE_API, SCOPE_FULL);
        // now == exp → reject (exp must be strictly greater than now).
        assert!(
            !v.verify(&token, 1_000, SCOPE_FULL),
            "exp == now should reject"
        );
        // now > exp → reject.
        assert!(
            !v.verify(&token, 1_001, SCOPE_FULL),
            "expired token should reject"
        );
    }

    // ── tampered payload ────────────────────────────────────────────────

    /// Flipping a byte in the payload breaks the signature and rejects.
    #[test]
    fn tampered_payload_rejected() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id1", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        // Flip a byte in the payload b64. Pick a char and replace with another.
        let payload = parts[1].clone();
        let mut bytes = payload.into_bytes();
        let idx = bytes.len() / 2;
        bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
        parts[1] = String::from_utf8(bytes).unwrap();
        let tampered = parts.join(".");
        assert!(
            !v.verify(&tampered, 1, SCOPE_FULL),
            "tampered payload must fail signature/parse"
        );
    }

    // ── forged / wrong-key signature ─────────────────────────────────────

    /// A token signed with a non-configured key is rejected.
    #[test]
    fn forged_wrong_key_signature_rejected() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        // Token signed with a DIFFERENT key.
        let forged = mint(KEY_B, "id1", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(
            !v.verify(&forged, 1, SCOPE_FULL),
            "token signed with a non-configured key must reject"
        );
    }

    /// A range of malformed/garbage inputs all reject without panicking.
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
                !v.verify(junk, 1, SCOPE_FULL),
                "junk {junk:?} must reject without panic"
            );
        }
    }

    // ── rotation ─────────────────────────────────────────────────────────

    /// With two signing keys configured, tokens signed by either verify.
    #[test]
    fn rotation_accepts_either_key() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec(), KEY_B.to_vec()],
            ..Default::default()
        });
        let token_a = mint(KEY_A, "ida", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        let token_b = mint(KEY_B, "idb", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(
            v.verify(&token_a, 1, SCOPE_FULL),
            "token signed by first key accepted"
        );
        assert!(
            v.verify(&token_b, 1, SCOPE_FULL),
            "token signed by second key accepted"
        );
    }

    /// `mint` signs with the first key, so a verifier lacking it rejects.
    #[test]
    fn mint_uses_first_key() {
        // A verifier that only knows KEY_B should reject a token minted by the
        // "first key" of a {A,B} config (which is A).
        let mint_cfg_first = KEY_A;
        let token = mint(mint_cfg_first, "x", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        let v_b_only = verifier(VerifierConfig {
            signing_keys: vec![KEY_B.to_vec()],
            ..Default::default()
        });
        assert!(!v_b_only.verify(&token, 1, SCOPE_FULL));
    }

    // ── revocation ───────────────────────────────────────────────────────

    /// A revoked id is rejected despite a valid signature, and removing it from
    /// the file (mtime change) causes a reload that re-accepts it.
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
        let revoked = mint(KEY_A, "revoked-id-1", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(!v.verify(&revoked, 1, SCOPE_FULL), "revoked id must reject");

        // A fresh token with a different id is accepted.
        let fresh = mint(KEY_A, "fresh-id", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(
            v.verify(&fresh, 1, SCOPE_FULL),
            "non-revoked id must accept"
        );

        // Remove the revocation from the file; the previously-revoked id is now
        // accepted (mtime change triggers a reload). Touch mtime explicitly in
        // case the filesystem mtime granularity would otherwise collapse the
        // two writes.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, "# nothing revoked now\n").expect("rewrite");
        let after = mint(KEY_A, "revoked-id-1", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(
            v.verify(&after, 1, SCOPE_FULL),
            "after removing from denylist, id should be accepted (reload)"
        );
    }

    // ── backward compat (static secrets) ────────────────────────────────

    /// A configured static secret matches verbatim and never expires.
    #[test]
    fn static_secret_backward_compat() {
        let v = verifier(VerifierConfig {
            static_keys: vec!["legacy-secret".to_string()],
            ..Default::default()
        });
        assert!(
            v.verify("legacy-secret", 1, SCOPE_FULL),
            "correct static secret accepts"
        );
        assert!(
            !v.verify("wrong-secret", 1, SCOPE_FULL),
            "wrong static secret rejects"
        );
        // Static secrets never expire — now_unix is irrelevant for them.
        assert!(
            v.verify("legacy-secret", i64::MAX, SCOPE_FULL),
            "static secret has no expiry"
        );
    }

    /// A static secret shaped like an `s1.` token fails the signed path and so
    /// Only the `s2.` prefix is intercepted by the signed-token path. A static
    /// secret shaped like `s2.x.y` is parsed as a (failing) token and never
    /// reaches the static comparison; one shaped like `s1.x.y` is no longer a
    /// recognized version, so it falls through and matches itself.
    #[test]
    fn only_the_s2_prefix_shadows_a_static_secret() {
        let s2_shaped = "s2.notreal.notreal";
        let v = verifier(VerifierConfig {
            static_keys: vec![s2_shaped.to_string()],
            ..Default::default()
        });
        assert!(
            !v.verify(s2_shaped, 1, SCOPE_FULL),
            "an s2.-shaped static secret is claimed by the signed path and fails"
        );

        // s1 is no longer a version we recognize, so this is just an opaque
        // string and the static comparison accepts it.
        let s1_shaped = "s1.notreal.notreal";
        let v = verifier(VerifierConfig {
            static_keys: vec![s1_shaped.to_string()],
            ..Default::default()
        });
        assert!(
            v.verify(s1_shaped, 1, SCOPE_FULL),
            "an s1.-shaped static secret now falls through to the static path"
        );
    }

    /// With both signing keys and static secrets configured, each accepts and
    /// an unknown value rejects.
    #[test]
    fn signing_and_static_both_configured() {
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            static_keys: vec!["legacy".to_string()],
            ..Default::default()
        });
        let token = mint(KEY_A, "id", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(v.verify(&token, 1, SCOPE_FULL), "signed token accepts");
        assert!(v.verify("legacy", 1, SCOPE_FULL), "static secret accepts");
        assert!(!v.verify("nope", 1, SCOPE_FULL), "unknown rejects");
    }

    /// An unconfigured verifier reports so and rejects everything.
    #[test]
    fn unconfigured_verifier() {
        let v = verifier(VerifierConfig::default());
        assert!(v.is_unconfigured());
        // With nothing configured, even a well-formed-looking token rejects
        // (no key to verify against, no static secret to match).
        assert!(!v.verify("anything", 1, SCOPE_FULL));
    }

    /// A token minted for the REST API must be rejected by the HTTP MCP
    /// surface even when BOTH share one signing key — the exact
    /// misconfiguration audience binding exists to defuse.
    #[test]
    fn api_token_is_rejected_by_the_mcp_surface() {
        let shared = KEY_A;
        let api_token = mint(shared, "id1", 1_000_000, AUDIENCE_API, SCOPE_FULL);

        let api_v = verifier(VerifierConfig {
            signing_keys: vec![shared.to_vec()],
            audience: AUDIENCE_API.to_string(),
            ..Default::default()
        });
        let mcp_v = verifier(VerifierConfig {
            signing_keys: vec![shared.to_vec()],
            audience: AUDIENCE_MCP.to_string(),
            ..Default::default()
        });

        assert!(
            api_v.verify(&api_token, 1_000, SCOPE_FULL),
            "an api token must work on the api surface"
        );
        assert!(
            !mcp_v.verify(&api_token, 1_000, SCOPE_FULL),
            "an api token must NOT work on the mcp surface, even with a shared key"
        );
    }

    /// And symmetrically, so neither direction is special-cased.
    #[test]
    fn mcp_token_is_rejected_by_the_api_surface() {
        let shared = KEY_A;
        let mcp_token = mint(shared, "id1", 1_000_000, AUDIENCE_MCP, SCOPE_FULL);

        let api_v = verifier(VerifierConfig {
            signing_keys: vec![shared.to_vec()],
            audience: AUDIENCE_API.to_string(),
            ..Default::default()
        });
        let mcp_v = verifier(VerifierConfig {
            signing_keys: vec![shared.to_vec()],
            audience: AUDIENCE_MCP.to_string(),
            ..Default::default()
        });

        assert!(mcp_v.verify(&mcp_token, 1_000, SCOPE_FULL));
        assert!(!api_v.verify(&mcp_token, 1_000, SCOPE_FULL));
    }

    /// Rewriting an `s2` token's version prefix to `s1` must not strip the
    /// audience check: the version is part of the signed input, so the
    /// downgrade invalidates the signature.
    #[test]
    fn s2_token_cannot_be_downgraded_to_s1() {
        let token = mint(KEY_A, "id1", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        assert!(
            token.starts_with("s2."),
            "mint must produce s2, got {token}"
        );

        let downgraded = format!("s1.{}", token.trim_start_matches("s2."));
        let mcp_v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            audience: AUDIENCE_MCP.to_string(),
            ..Default::default()
        });
        assert!(
            !mcp_v.verify(&downgraded, 1_000, SCOPE_FULL),
            "a version-downgraded token must fail the signature check"
        );
    }

    /// A legacy `s1` token (no `aud`) must now be REJECTED. It was accepted
    /// during the transition; honoring it left the audience binding
    /// best-effort, since an `s1` token authenticates against both surfaces.
    #[test]
    fn legacy_s1_token_is_rejected() {
        // Hand-build an s1 token: payload without `aud`, signed over "s1.".
        let payload = r#"{"id":"legacy-1","exp":1000000}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("s1.{payload_b64}");
        let sig = hmac_sha256(KEY_A, signing_input.as_bytes());
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig));

        for aud in [AUDIENCE_API, AUDIENCE_MCP] {
            let v = verifier(VerifierConfig {
                signing_keys: vec![KEY_A.to_vec()],
                audience: aud.to_string(),
                ..Default::default()
            });
            assert!(
                !v.verify(&token, 1_000, SCOPE_FULL),
                "a correctly-signed, unexpired s1 token must be rejected on {aud}"
            );
        }
    }

    /// The s1 rejection must not be an accident of the static-secret fallback:
    /// even if an operator configured the whole token string as a static
    /// secret it would match, so prove rejection holds with signing keys only.
    #[test]
    fn s1_rejection_is_not_a_static_secret_artifact() {
        let payload = r#"{"id":"legacy-2","exp":1000000}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("s1.{payload_b64}");
        let sig = hmac_sha256(KEY_A, signing_input.as_bytes());
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig));

        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            static_keys: vec![],
            audience: AUDIENCE_API.to_string(),
            ..Default::default()
        });
        assert!(!v.verify(&token, 1_000, SCOPE_FULL));
    }

    /// An empty configured audience must reject every `s2` token rather than
    /// accepting any of them — fail closed on a misconfigured verifier.
    #[test]
    fn empty_audience_rejects_every_s2_token() {
        let token = mint(KEY_A, "id1", 1_000_000, AUDIENCE_API, SCOPE_FULL);
        // Bypass the test `verifier()` helper, which fills in a default.
        let v = TokenVerifier::new(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            audience: String::new(),
            ..Default::default()
        });
        assert!(!v.verify(&token, 1_000, SCOPE_FULL));
    }

    /// A `metrics`-scoped token reaches the metrics scope and nothing else.
    ///
    /// This is the whole point of the claim: a monitoring system needs one
    /// endpoint, and before this it had to be trusted with a credential that
    /// also reads `/v1/dialogs` and the message bodies underneath — which, on a
    /// TLS-decrypting capture tool, is the call content.
    #[test]
    fn a_metrics_token_is_refused_where_full_access_is_required() {
        let token = mint(KEY_A, "scrape", 2_000, AUDIENCE_API, SCOPE_METRICS);
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });

        assert!(
            v.verify(&token, 1_000, SCOPE_METRICS),
            "a metrics token must satisfy a metrics requirement"
        );
        assert!(
            !v.verify(&token, 1_000, SCOPE_FULL),
            "a metrics token must NOT satisfy a full requirement — that is the \
             entire restriction this claim exists to impose"
        );
    }

    /// A `full` token satisfies every requirement, including the narrow one.
    ///
    /// The asymmetry matters: demanding `full` on a route admits only full
    /// tokens, demanding `metrics` admits both. That is why `full` is the
    /// default requirement for any route that does not say otherwise.
    #[test]
    fn a_full_token_satisfies_both_requirements() {
        let token = mint(KEY_A, "ops", 2_000, AUDIENCE_API, SCOPE_FULL);
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });

        assert!(v.verify(&token, 1_000, SCOPE_FULL));
        assert!(
            v.verify(&token, 1_000, SCOPE_METRICS),
            "a full token must still reach /metrics — adding this claim must not \
             narrow an existing deployment"
        );
    }

    /// A token minted before `scope` existed keeps full access.
    ///
    /// Tokens carrying no `scope` claim are live in the field. Treating absent
    /// as "no access" would revoke working credentials on upgrade, so absent
    /// means `full` — the opposite of `aud`, which fails closed when missing.
    /// Asserted against a hand-built payload rather than `mint`, because `mint`
    /// can no longer produce one.
    #[test]
    fn a_pre_scope_token_still_has_full_access() {
        let payload = r#"{"id":"legacy","exp":2000,"aud":"api"}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{VERSION}.{payload_b64}");
        let sig = hmac_sha256(KEY_A, signing_input.as_bytes());
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig));

        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });

        assert!(
            v.verify(&token, 1_000, SCOPE_FULL),
            "a token minted before the scope claim existed must keep working"
        );
    }

    /// The scope claim is signed: editing it in the payload breaks the token.
    ///
    /// Without this, "restricted" would be a suggestion — a holder could widen
    /// their own credential by rewriting one field.
    #[test]
    fn a_scope_cannot_be_widened_by_editing_the_payload() {
        let token = mint(KEY_A, "scrape", 2_000, AUDIENCE_API, SCOPE_METRICS);
        let mut parts = token.split('.');
        let version = parts.next().expect("version");
        let payload_b64 = parts.next().expect("payload");
        let sig_b64 = parts.next().expect("sig");

        let decoded = URL_SAFE_NO_PAD.decode(payload_b64).expect("decode");
        let json = String::from_utf8(decoded).expect("utf8");
        assert!(
            json.contains("\"scope\":\"metrics\""),
            "payload names the scope: {json}"
        );
        let widened = json.replace(r#","scope":"metrics""#, "");
        let forged = format!(
            "{version}.{}.{sig_b64}",
            URL_SAFE_NO_PAD.encode(widened.as_bytes())
        );

        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        assert!(
            !v.verify(&forged, 1_000, SCOPE_FULL),
            "stripping the scope claim must invalidate the signature"
        );
    }

    // ── verify_claims (scope returned, not compared) ─────────────────────

    /// A `read`-scoped token round-trips through `verify_claims` with its
    /// scope intact, so the MCP dispatch layer has the claim to enforce
    /// per-tool.
    #[test]
    fn a_read_token_round_trips_through_verify_claims() {
        let token = mint(KEY_A, "agent", 2_000, AUDIENCE_API, SCOPE_READ);
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        assert_eq!(
            v.verify_claims(&token, 1_000),
            Some(AcceptedToken {
                scope: SCOPE_READ.to_string(),
                id: Some("agent".to_string()),
            }),
            "the scope claim must come back exactly as minted"
        );
    }

    /// A token that carries no scope claim comes back as `full` — the same
    /// absent-means-full rule `verify` applies, now visible in the claims.
    #[test]
    fn a_scopeless_token_comes_back_as_full() {
        // `mint` omits the claim for `full`, so this payload has no `scope`.
        let token = mint(KEY_A, "ops", 2_000, AUDIENCE_API, SCOPE_FULL);
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            ..Default::default()
        });
        assert_eq!(
            v.verify_claims(&token, 1_000).map(|a| a.scope),
            Some(SCOPE_FULL.to_string())
        );
    }

    /// A static secret comes back as `full`: it carries no claims at all, so
    /// it cannot express a narrower scope — the operator who wants least
    /// privilege mints a token.
    #[test]
    fn a_static_secret_comes_back_as_full() {
        let v = verifier(VerifierConfig {
            static_keys: vec!["legacy-secret".to_string()],
            ..Default::default()
        });
        assert_eq!(
            v.verify_claims("legacy-secret", 1_000).map(|a| a.scope),
            Some(SCOPE_FULL.to_string())
        );
        assert_eq!(
            v.verify_claims("wrong-secret", 1_000),
            None,
            "a wrong static secret must yield no claims"
        );
    }

    /// The `id` a token was minted with survives verification, and a static
    /// secret reports having none.
    ///
    /// This is the claim the MCP audit line names the caller by. It has to be
    /// the id verbatim: it is the same string the operator passed to
    /// `--token-id` and the same string they would write into
    /// `--api-revoked-file`/`--mcp-revoked-file`, so anything else breaks the
    /// hop from "this line" to "revoke that credential". A static secret is
    /// `None` rather than an empty string — the credential genuinely has no
    /// id, and a blank one would read like a token whose id happens to be
    /// empty.
    #[test]
    fn verify_claims_carries_the_token_id_and_a_static_secret_has_none() {
        let token = mint(KEY_A, "ci-runner-1", 2_000, AUDIENCE_API, SCOPE_READ);
        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            static_keys: vec!["legacy-secret".to_string()],
            ..Default::default()
        });
        assert_eq!(
            v.verify_claims(&token, 1_000),
            Some(AcceptedToken {
                scope: SCOPE_READ.to_string(),
                id: Some("ci-runner-1".to_string()),
            }),
            "the id must come back exactly as minted, beside the scope"
        );
        assert_eq!(
            v.verify_claims("legacy-secret", 1_000),
            Some(AcceptedToken {
                scope: SCOPE_FULL.to_string(),
                id: None,
            }),
            "a static secret carries no id at all — absent, not empty"
        );
    }

    /// `verify_claims` applies the same non-scope checks as `verify`:
    /// expired, revoked, and wrong-audience tokens all yield no claims.
    /// Returning claims is not a relaxation of anything except the scope
    /// comparison, which the caller now owns.
    #[test]
    fn verify_claims_rejects_expired_revoked_and_wrong_audience() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("revoked.txt");
        std::fs::write(&path, "revoked-claims-id\n").expect("write");

        let v = verifier(VerifierConfig {
            signing_keys: vec![KEY_A.to_vec()],
            revoked_file: Some(path),
            ..Default::default()
        });

        let expired = mint(KEY_A, "id1", 1_000, AUDIENCE_API, SCOPE_READ);
        assert_eq!(v.verify_claims(&expired, 1_000), None, "exp == now rejects");

        let revoked = mint(KEY_A, "revoked-claims-id", 2_000, AUDIENCE_API, SCOPE_READ);
        assert_eq!(v.verify_claims(&revoked, 1_000), None, "revoked id rejects");

        let wrong_aud = mint(KEY_A, "id2", 2_000, AUDIENCE_MCP, SCOPE_READ);
        assert_eq!(
            v.verify_claims(&wrong_aud, 1_000),
            None,
            "an mcp token must yield no claims on the api surface"
        );
    }
}
