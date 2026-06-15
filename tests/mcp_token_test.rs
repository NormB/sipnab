//! End-to-end HTTP MCP signed-token auth tests.
//!
//! Spawns `sipnab --mcp --mcp-transport http` configured with an HMAC signing
//! key (and optionally a revocation file), then issues HTTP JSON-RPC requests
//! to prove the fail-closed negatives over the real network surface: valid →
//! 200, expired → 401, revoked → 401, plus the static `--mcp-token`
//! backward-compat path. Tokens are minted in-process via `sipnab::auth::mint`
//! (same key the server is started with). Mirrors `tests/mcp_http_test.rs`.
#![cfg(all(unix, feature = "mcp-http"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SIGNING_KEY: &str = "e2e-mcp-signing-key-0123456789abcdef";

fn fixture(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Spawn sipnab with HTTP MCP and return the child + bind address.
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

/// Issue an `initialize` JSON-RPC POST with an optional bearer token, returning
/// the HTTP status code.
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

#[test]
fn valid_signed_token_initialize_succeeds() {
    let (child, addr) =
        spawn_http(&["--mcp-signing-key", SIGNING_KEY]).expect("server should start");
    let token = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "id", now() + 3600);
    assert_eq!(
        initialize_status(&addr, Some(&token)),
        200,
        "valid token should be 200"
    );
    // Missing token → 401.
    assert_eq!(initialize_status(&addr, None), 401, "missing token → 401");
    shutdown(child);
}

#[test]
fn expired_signed_token_is_rejected() {
    let (child, addr) =
        spawn_http(&["--mcp-signing-key", SIGNING_KEY]).expect("server should start");
    let token = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "id", now() - 1);
    assert_eq!(
        initialize_status(&addr, Some(&token)),
        401,
        "expired token should be 401"
    );
    shutdown(child);
}

#[test]
fn forged_wrong_key_token_is_rejected() {
    let (child, addr) =
        spawn_http(&["--mcp-signing-key", SIGNING_KEY]).expect("server should start");
    let token = sipnab::auth::mint(b"a-different-key", "id", now() + 3600);
    assert_eq!(
        initialize_status(&addr, Some(&token)),
        401,
        "forged token should be 401"
    );
    shutdown(child);
}

#[test]
fn revoked_id_is_rejected_via_denylist_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let revoked_path = dir.path().join("revoked.txt");
    std::fs::write(&revoked_path, "revoked-mcp-jti\n").expect("write denylist");

    let (child, addr) = spawn_http(&[
        "--mcp-signing-key",
        SIGNING_KEY,
        "--mcp-revoked-file",
        revoked_path.to_str().unwrap(),
    ])
    .expect("server should start");

    let revoked = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "revoked-mcp-jti", now() + 3600);
    assert_eq!(
        initialize_status(&addr, Some(&revoked)),
        401,
        "revoked id should be 401"
    );

    let fresh = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "fresh-mcp-jti", now() + 3600);
    assert_eq!(
        initialize_status(&addr, Some(&fresh)),
        200,
        "non-revoked id should be 200"
    );
    shutdown(child);
}

#[test]
fn rotation_accepts_tokens_from_either_key() {
    let key2 = "second-mcp-rotation-key-abcdef0123";
    let (child, addr) = spawn_http(&["--mcp-signing-key", SIGNING_KEY, "--mcp-signing-key", key2])
        .expect("server should start");
    let t1 = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "id1", now() + 3600);
    let t2 = sipnab::auth::mint(key2.as_bytes(), "id2", now() + 3600);
    assert_eq!(initialize_status(&addr, Some(&t1)), 200, "key1 token");
    assert_eq!(initialize_status(&addr, Some(&t2)), 200, "key2 token");
    shutdown(child);
}

#[test]
fn static_mcp_token_backward_compat() {
    let (child, addr) =
        spawn_http(&["--mcp-token", "legacy-mcp-secret"]).expect("server should start");
    assert_eq!(
        initialize_status(&addr, Some("legacy-mcp-secret")),
        200,
        "correct static token → 200"
    );
    assert_eq!(
        initialize_status(&addr, Some("wrong-secret")),
        401,
        "wrong static token → 401"
    );
    shutdown(child);
}

#[test]
fn mint_token_cli_mode_produces_verifiable_token() {
    // Drive the --mint-token CLI mode and verify the printed token under the
    // same key via the library verifier.
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let out = Command::new(binary)
        .args([
            "--mint-token",
            "--mcp-signing-key",
            SIGNING_KEY,
            "--token-id",
            "cli-minted",
            "--mcp-token-ttl",
            "3600",
        ])
        .output()
        .expect("run --mint-token");
    assert!(out.status.success(), "mint-token should exit 0");
    let token = String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string();
    assert!(token.starts_with("s1."), "minted token: {token}");

    let verifier = sipnab::auth::TokenVerifier::new(sipnab::auth::VerifierConfig {
        signing_keys: vec![SIGNING_KEY.as_bytes().to_vec()],
        ..Default::default()
    });
    assert!(
        verifier.verify(&token, now()),
        "CLI-minted token should verify under same key"
    );
}

// M6 burn-down: --mcp-token-file (static token loaded from a file).
#[test]
fn static_mcp_token_file_backward_compat() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp.token");
    std::fs::write(&path, "file-static-mcp-secret\n").expect("write token file");

    let (child, addr) =
        spawn_http(&["--mcp-token-file", path.to_str().unwrap()]).expect("server should start");
    // The file's token (trimmed) authenticates; wrong/missing → 401.
    assert_eq!(
        initialize_status(&addr, Some("file-static-mcp-secret")),
        200,
        "token from --mcp-token-file → 200"
    );
    assert_eq!(
        initialize_status(&addr, Some("wrong")),
        401,
        "wrong token → 401"
    );
    assert_eq!(initialize_status(&addr, None), 401, "missing token → 401");
    shutdown(child);
}

/// POST `initialize` with an explicit `Host` header (to exercise the DNS-rebind
/// allowlist), connecting to `addr` regardless of the header value.
fn initialize_status_with_host(addr: &str, host_header: &str, bearer: Option<&str>) -> u16 {
    let (host, port_str) = addr.rsplit_once(':').expect("host:port");
    let port: u16 = port_str.parse().expect("port");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    });
    let body_str = serde_json::to_string(&body).unwrap();
    let mut stream = TcpStream::connect((host, port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\n\
         Host: {host_header}\r\n\
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
    String::from_utf8_lossy(&resp)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

// M6 burn-down: --mcp-allowed-host extends rmcp's Host-header allowlist.
#[test]
fn mcp_allowed_host_controls_host_header() {
    let (child, addr) = spawn_http(&[
        "--mcp-signing-key",
        SIGNING_KEY,
        "--mcp-allowed-host",
        "custom.example",
    ])
    .expect("server should start");
    let token = sipnab::auth::mint(SIGNING_KEY.as_bytes(), "host-test", now() + 3600);

    // The configured Host is accepted (and auth passes) → 200.
    assert_eq!(
        initialize_status_with_host(&addr, "custom.example", Some(&token)),
        200,
        "Host added via --mcp-allowed-host must be accepted"
    );
    // A Host that is neither loopback nor allow-listed is rejected (not 200).
    assert_ne!(
        initialize_status_with_host(&addr, "blocked.invalid", Some(&token)),
        200,
        "a non-allowlisted Host must be rejected by DNS-rebind protection"
    );
    shutdown(child);
}
