//! End-to-end REST API signed-token auth tests.
//!
//! Spawns a real `sipnab --api` process configured with an HMAC signing key
//! (and optionally a revocation file), then drives it over HTTP to prove the
//! fail-closed negatives: valid → 200, expired → 401, revoked → 401, plus the
//! static-secret backward-compat path. Tokens are minted in-process via the
//! library `sipnab::auth::mint` (same key the server is started with) rather
//! than shelling out.
#![cfg(feature = "api")]

#[path = "support/server.rs"]
mod server;

use server::ApiServer;

/// A long, deterministic signing key shared between the spawned server and the
/// in-test minting.
const SIGNING_KEY: &str = "e2e-api-signing-key-0123456789abcdef";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[test]
fn valid_signed_token_is_accepted() {
    let srv = ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]);
    let token = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "valid-id", now() + 3600);
    let resp = srv.get_bearer("/v1/dialogs", &token);
    assert_eq!(resp.status, 200, "valid signed token should be 200");
}

#[test]
fn missing_token_is_rejected() {
    let srv = ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]);
    let resp = srv.get("/v1/dialogs");
    assert_eq!(resp.status, 401, "missing token should be 401");
}

#[test]
fn expired_signed_token_is_rejected() {
    let srv = ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]);
    // exp already in the past — deterministic, no sleeping.
    let token = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "expired-id", now() - 1);
    let resp = srv.get_bearer("/v1/dialogs", &token);
    assert_eq!(resp.status, 401, "expired token should be 401");
}

#[test]
fn forged_wrong_key_token_is_rejected() {
    let srv = ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]);
    let token = sipnab::auth::mint(b"a-totally-different-key", "id", now() + 3600);
    let resp = srv.get_bearer("/v1/dialogs", &token);
    assert_eq!(resp.status, 401, "forged token should be 401");
}

#[test]
fn tampered_payload_token_is_rejected() {
    let srv = ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]);
    let token = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "id", now() + 3600);
    // Flip a byte in the payload (middle dot-part).
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let mut bytes = parts[1].clone().into_bytes();
    let idx = bytes.len() / 2;
    bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
    parts[1] = String::from_utf8(bytes).unwrap();
    let tampered = parts.join(".");
    let resp = srv.get_bearer("/v1/dialogs", &tampered);
    assert_eq!(resp.status, 401, "tampered payload should be 401");
}

#[test]
fn revoked_id_is_rejected_via_denylist_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let revoked_path = dir.path().join("revoked.txt");
    std::fs::write(&revoked_path, "revoked-jti\n").expect("write denylist");

    let srv = ApiServer::spawn(&[
        "--api-signing-key",
        SIGNING_KEY,
        "--api-revoked-file",
        revoked_path.to_str().unwrap(),
    ]);

    // A valid, unexpired token whose id is on the denylist → 401.
    let revoked = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "revoked-jti", now() + 3600);
    let resp = srv.get_bearer("/v1/dialogs", &revoked);
    assert_eq!(resp.status, 401, "revoked id should be 401");

    // A fresh token with a different id is accepted.
    let fresh = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "not-revoked-jti", now() + 3600);
    let resp = srv.get_bearer("/v1/dialogs", &fresh);
    assert_eq!(resp.status, 200, "non-revoked id should be 200");
}

#[test]
fn rotation_accepts_tokens_from_either_key() {
    let key2 = "second-rotation-key-abcdef0123456789";
    let srv = ApiServer::spawn(&["--api-signing-key", SIGNING_KEY, "--api-signing-key", key2]);
    let t1 = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "id1", now() + 3600);
    let t2 = sipnab::auth::mint(key2.as_bytes(), "id2", now() + 3600);
    assert_eq!(srv.get_bearer("/v1/dialogs", &t1).status, 200, "key1 token");
    assert_eq!(srv.get_bearer("/v1/dialogs", &t2).status, 200, "key2 token");
}

#[test]
fn static_api_key_backward_compat() {
    let srv = ApiServer::spawn(&["--api-key", "legacy-static-secret"]);
    // Correct static secret → 200.
    assert_eq!(
        srv.get_bearer("/v1/dialogs", "legacy-static-secret").status,
        200,
        "correct static key should be 200"
    );
    // Wrong static secret → 401.
    assert_eq!(
        srv.get_bearer("/v1/dialogs", "wrong-secret").status,
        401,
        "wrong static key should be 401"
    );
}
