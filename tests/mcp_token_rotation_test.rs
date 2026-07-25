// SPDX-License-Identifier: MIT OR Apache-2.0

//! Harness token-rotation end-to-end tests.
//!
//! The diagnostic harness (`harness/`) no longer ships a static bearer secret.
//! Instead it holds a long-lived HMAC *signing key* and continuously re-mints
//! short-lived bearer tokens from it via `harness/scripts/rotate-token.sh`,
//! publishing each to the shared token file the server and clients read. These
//! tests drive that exact script against a live `--mcp-signing-key-file` server
//! to prove the rotation contract the harness depends on:
//!
//! * a freshly rotated token authenticates (200); wrong/absent → 401,
//! * every rotation publishes a *distinct* token and leaves no temp file,
//! * a rotated token expires (401) and the next rotation restores access (200).
//!
//! Reuses the shared spawn/post helpers in `tests/support/mcp.rs`.
#![cfg(all(unix, feature = "mcp-http"))]

#[path = "support/mcp.rs"]
mod mcp;

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use mcp::{initialize_status, shutdown, spawn_http_loopback as spawn_http};

/// Absolute path to the harness rotation script under test.
fn rotate_script() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("harness/scripts/rotate-token.sh")
}

/// Run `rotate-token.sh <key_file> <token_file> <ttl> <sipnab-bin>` and return
/// its exit success plus captured stderr (for diagnostics on failure).
///
/// # Arguments
/// * `key_file` — path to the HMAC signing-key file.
/// * `token_file` — path the script publishes the minted token to.
/// * `ttl` — token lifetime in seconds.
///
/// # Side effects
/// Spawns `sh` running the rotation script, which invokes the sipnab binary
/// and writes/overwrites `token_file`.
fn rotate(key_file: &std::path::Path, token_file: &std::path::Path, ttl: i64) -> (bool, String) {
    let out = Command::new("sh")
        .arg(rotate_script())
        .arg(key_file)
        .arg(token_file)
        .arg(ttl.to_string())
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .output()
        .expect("run rotate-token.sh");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Poll `cond` every 100 ms until it returns `true` or `timeout` elapses.
///
/// # Returns
/// `true` if the condition became true within the deadline, else `false`.
///
/// Used instead of a fixed multi-second sleep: a token's `exp` is stamped at
/// mint time, so once it elapses the rejection is permanent — polling returns
/// as soon as the condition flips rather than always burning a worst-case wait.
fn poll_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Write a signing-key file and return (tempdir, key_path, token_path).
///
/// # Returns
/// The owning tempdir plus paths to the written signing-key file (with a
/// trailing newline the reader must trim) and the not-yet-written token file.
///
/// # Side effects
/// Creates a tempdir and writes the signing-key file into it.
fn rotation_dir() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("mcp.signing-key");
    // A non-trivial key with a trailing newline the script/reader must trim.
    std::fs::write(&key, "harness-rotation-signing-key-0123456789ab\n").expect("write key");
    let token = dir.path().join("mcp.token");
    (dir, key, token)
}

/// A token freshly minted by `rotate-token.sh` (s2. shape) gets 200 against a
/// `--mcp-signing-key-file` server; wrong and missing tokens get 401.
#[test]
fn rotated_token_authenticates_against_signing_key_server() {
    let (_dir, key, token_path) = rotation_dir();

    let (ok, stderr) = rotate(&key, &token_path, 3600);
    assert!(ok, "rotate-token.sh should succeed; stderr: {stderr}");

    let token = std::fs::read_to_string(&token_path)
        .expect("token file written")
        .trim()
        .to_string();
    assert!(
        token.starts_with("s2."),
        "rotated token should be a signed s2. token, got: {token}"
    );

    let (child, addr) = spawn_http(&["--mcp-signing-key-file", key.to_str().unwrap()])
        .expect("server should start with signing-key file");

    assert_eq!(
        initialize_status(&addr, Some(&token)),
        200,
        "rotated token → 200"
    );
    assert_eq!(
        initialize_status(&addr, Some("not-the-token")),
        401,
        "wrong token → 401"
    );
    assert_eq!(initialize_status(&addr, None), 401, "missing token → 401");
    shutdown(child);
}

/// Two consecutive rotations publish distinct tokens, leave no `.tmp` files
/// behind, and both tokens verify against the same signing key.
#[test]
fn each_rotation_publishes_a_fresh_token_atomically() {
    let (dir, key, token_path) = rotation_dir();

    let (ok1, e1) = rotate(&key, &token_path, 3600);
    assert!(ok1, "first rotation should succeed; stderr: {e1}");
    let first = std::fs::read_to_string(&token_path)
        .expect("first token")
        .trim()
        .to_string();

    let (ok2, e2) = rotate(&key, &token_path, 3600);
    assert!(ok2, "second rotation should succeed; stderr: {e2}");
    let second = std::fs::read_to_string(&token_path)
        .expect("second token")
        .trim()
        .to_string();

    assert_ne!(
        first, second,
        "each rotation must publish a distinct (freshly minted) token"
    );

    // Atomic publish must not leave temp files behind in the secrets dir.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "rotation should leave no temp files, found: {leftovers:?}"
    );

    // Both freshly minted tokens verify against the same signing key.
    let (child, addr) = spawn_http(&["--mcp-signing-key-file", key.to_str().unwrap()])
        .expect("server should start");
    assert_eq!(
        initialize_status(&addr, Some(&first)),
        200,
        "first token → 200"
    );
    assert_eq!(
        initialize_status(&addr, Some(&second)),
        200,
        "second token → 200"
    );
    shutdown(child);
}

/// Rotation with an empty or missing signing key fails closed: the previously
/// published good token is untouched and no half-written temp files remain.
#[test]
fn rotation_fails_loudly_without_clobbering_the_published_token() {
    let (dir, key, token_path) = rotation_dir();

    // Seed a known-good published token, then attempt rotations that must fail.
    let (ok, e) = rotate(&key, &token_path, 3600);
    assert!(ok, "seed rotation should succeed; stderr: {e}");
    let good = std::fs::read_to_string(&token_path)
        .expect("seed token")
        .trim()
        .to_string();
    assert!(good.starts_with("s2."), "seed token: {good}");

    // Empty signing key → fail closed, leave the good token and no temp files.
    let empty_key = dir.path().join("empty.key");
    std::fs::write(&empty_key, "").expect("write empty key");
    let (ok_empty, _) = rotate(&empty_key, &token_path, 3600);
    assert!(!ok_empty, "rotation with an empty signing key must fail");

    // Missing signing key → also fails.
    let missing_key = dir.path().join("does-not-exist.key");
    let (ok_missing, _) = rotate(&missing_key, &token_path, 3600);
    assert!(!ok_missing, "rotation with a missing signing key must fail");

    // The previously published good token is untouched by the failed attempts…
    let after = std::fs::read_to_string(&token_path)
        .expect("token still present")
        .trim()
        .to_string();
    assert_eq!(
        good, after,
        "failed rotation must not clobber the published token"
    );

    // …and no half-written temp files are left behind.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp files after failed rotation, found: {leftovers:?}"
    );
}

/// A short-TTL (5s) rotated token is valid immediately (200), rejected after
/// its TTL elapses (401), and a fresh rotation restores access without a
/// server restart.
#[test]
fn expired_rotated_token_is_rejected_then_rotation_restores_access() {
    let (_dir, key, token_path) = rotation_dir();

    let (child, addr) = spawn_http(&["--mcp-signing-key-file", key.to_str().unwrap()])
        .expect("server should start");

    // Rotate a short-TTL token: valid immediately…
    //
    // TTL margins matter here. Minting runs through a subprocess
    // (`rotate-token.sh` → the sipnab binary), so the window between the token's
    // `exp` being stamped and the "valid now" check below covers a process
    // teardown, a file read, and an HTTP round-trip. Under the full suite's load
    // that window was occasionally exceeding a 1s TTL, expiring the token before
    // the immediate check and flaking the 200. Use a TTL with ample headroom for
    // the "valid" check.
    const SHORT_TTL: i64 = 3;
    let (ok, e) = rotate(&key, &token_path, SHORT_TTL);
    assert!(ok, "short-TTL rotation should succeed; stderr: {e}");
    let short = std::fs::read_to_string(&token_path)
        .expect("token")
        .trim()
        .to_string();
    assert_eq!(
        initialize_status(&addr, Some(&short)),
        200,
        "freshly rotated short-TTL token → 200"
    );

    // …expires once its TTL elapses. Rather than sleeping a fixed span past the
    // TTL, poll for the rejection: the token's `exp` is fixed at mint time, so
    // once it passes the 401 is permanent. Polling flips to a pass as soon as
    // the token expires (≈ SHORT_TTL), with a generous bound to absorb suite
    // load, instead of always burning a worst-case fixed sleep.
    let expired = poll_until(Duration::from_secs(SHORT_TTL as u64 + 15), || {
        initialize_status(&addr, Some(&short)) == 401
    });
    assert!(
        expired,
        "rotated short-TTL token must be rejected (401) once its TTL elapses"
    );

    // The next rotation restores access without restarting the server.
    let (ok2, e2) = rotate(&key, &token_path, 3600);
    assert!(ok2, "re-rotation should succeed; stderr: {e2}");
    let fresh = std::fs::read_to_string(&token_path)
        .expect("token")
        .trim()
        .to_string();
    assert_ne!(short, fresh, "re-rotation should mint a new token");
    assert_eq!(
        initialize_status(&addr, Some(&fresh)),
        200,
        "rotated-in fresh token → 200"
    );
    shutdown(child);
}
