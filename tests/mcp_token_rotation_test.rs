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
//! Mirrors the spawn/post helpers in `tests/mcp_token_test.rs` (kept
//! self-contained per the existing per-file convention).
#![cfg(all(unix, feature = "mcp-http"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

/// Absolute path to the harness rotation script under test.
fn rotate_script() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("harness/scripts/rotate-token.sh")
}

/// Run `rotate-token.sh <key_file> <token_file> <ttl> <sipnab-bin>` and return
/// its exit success plus captured stderr (for diagnostics on failure).
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

/// Spawn sipnab with HTTP MCP + the given args; return child + bind address.
fn spawn_http(extra_args: &[&str]) -> Option<(std::process::Child, String)> {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let pcap = fixture("sip_call.pcap");
    let pcap_str = pcap.to_string_lossy().to_string();

    let mut cmd = Command::new(binary);
    cmd.args([
        "-N",
        "-I",
        &pcap_str,
        "--mcp",
        "--mcp-transport",
        "http",
        "--mcp-bind",
        "127.0.0.1:0",
        "--quiet",
    ]);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.env("SIPNAB_LOG", "info");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sipnab");
    let stderr = child.stderr.take().expect("stderr");

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(addr) = line.split("listening on ").nth(1) {
                return Some((child, addr.trim().to_string()));
            }
            if line.contains("refuses to start") {
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGTERM);
                }
                let _ = child.wait();
                return None;
            }
        } else if let Ok(Some(_)) = child.try_wait() {
            return None;
        }
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
    None
}

fn shutdown(mut child: std::process::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

fn initialize_status(addr: &str, bearer: Option<&str>) -> u16 {
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    });
    post_status(&format!("http://{addr}/mcp"), bearer, &payload)
}

fn post_status(url: &str, bearer: Option<&str>, body: &serde_json::Value) -> u16 {
    let parsed = url.strip_prefix("http://").expect("http url");
    let (authority, path) = parsed.split_once('/').unwrap_or((parsed, ""));
    let (host, port_str) = authority.rsplit_once(':').expect("host:port");
    let port: u16 = port_str.parse().expect("port");

    let mut stream = TcpStream::connect((host, port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let body_str = serde_json::to_string(body).expect("serialize");
    let mut req = format!(
        "POST /{path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body_str.len(),
    );
    if let Some(b) = bearer {
        req.push_str(&format!("Authorization: Bearer {b}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body_str);
    stream.write_all(req.as_bytes()).expect("write");

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).expect("read");
    let s = String::from_utf8_lossy(&resp);
    s.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// Write a signing-key file and return (tempdir, key_path, token_path).
fn rotation_dir() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("mcp.signing-key");
    // A non-trivial key with a trailing newline the script/reader must trim.
    std::fs::write(&key, "harness-rotation-signing-key-0123456789ab\n").expect("write key");
    let token = dir.path().join("mcp.token");
    (dir, key, token)
}

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
        token.starts_with("s1."),
        "rotated token should be a signed s1. token, got: {token}"
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
    assert!(good.starts_with("s1."), "seed token: {good}");

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
    // the "valid" check, and sleep comfortably past it for the "expired" check —
    // `thread::sleep` guarantees *at least* its duration, so once SHORT_TTL has
    // elapsed the rejection is deterministic.
    const SHORT_TTL: i64 = 5;
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

    // …expires once its TTL elapses (sleep > SHORT_TTL, with margin).
    thread::sleep(Duration::from_secs(SHORT_TTL as u64 + 2));
    assert_eq!(
        initialize_status(&addr, Some(&short)),
        401,
        "expired rotated token → 401"
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
