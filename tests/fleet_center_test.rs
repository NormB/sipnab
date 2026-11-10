// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The fleet center end to end: a real `sipnab fleet serve` taking
//! heartbeats on `POST /v1/fleet/ingest` and serving `GET /v1/fleet/members`.
//!
//! The members here are this test, posting what a member posts, so each rule
//! of the center can be driven on its own: three members and one gone silent,
//! a replayed batch, a revoked member, the scopes, the store's mode and
//! retention, plain HTTP off loopback, and HTTPS.
#![cfg(feature = "api")]

use std::io::{BufRead as _, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/tls_pki.rs"]
mod tls_pki;

type TestError = Box<dyn std::error::Error>;

/// The center's signing key.
const KEY: &str = "fleet-center-e2e-signing-key-0123456789abcdef";

/// A token minted with [`KEY`] for `id` and `scope`.
fn token(id: &str, scope: &str) -> String {
    sipnab::auth::mint(
        KEY.as_bytes(),
        id,
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        scope,
    )
}

/// A file in `dir` holding `text`, mode 0600.
fn private_file(
    dir: &std::path::Path,
    name: &str,
    text: &str,
) -> Result<std::path::PathBuf, TestError> {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(text.as_bytes())?;
    Ok(path)
}

/// A running `sipnab fleet serve`, stopped when dropped.
struct Center {
    child: std::process::Child,
    /// `host:port` it serves on.
    addr: String,
    /// Its log lines, as they come.
    log: std::sync::mpsc::Receiver<String>,
}

impl Center {
    /// `sipnab fleet serve` with `args`, once it says where it serves.
    fn start(args: &[&str]) -> Result<Self, TestError> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["fleet", "serve"])
            .args(args)
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .tied_to_test()
            .spawn()?;
        let stderr = child.stderr.take().ok_or("piped stderr")?;
        let (tx, log) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match log.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    if let Some(rest) = line.split(" on ").nth(1)
                        && line.contains("fleet center serving")
                    {
                        let addr = rest.trim().to_string();
                        return Ok(Self { child, addr, log });
                    }
                }
                Err(_) => {
                    if let Ok(Some(status)) = child.try_wait() {
                        return Err(format!("the center exited early: {status}").into());
                    }
                }
            }
        }
        let _ = child.kill();
        Err("the center did not say where it serves".into())
    }

    /// Wait up to `within` for a log line containing `want`.
    fn wait_for_log(&self, want: &str, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Ok(line) = self.log.recv_timeout(Duration::from_millis(100))
                && line.contains(want)
            {
                return Some(line);
            }
        }
        None
    }
}

impl Drop for Center {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `sipnab fleet serve` with `args` that should be refused: its exit code
/// and its log.
///
/// A center that starts when it should refuse would serve until stopped, so
/// the wait is bounded: past it the center is killed and the test fails with
/// what happened, where an unbounded wait would hang the suite.
fn refused(args: &[&str]) -> Result<(i32, String), TestError> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["fleet", "serve"])
        .args(args)
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("the center kept running when it should have refused to start".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut log = String::new();
    child
        .stderr
        .take()
        .ok_or("piped stderr")?
        .read_to_string(&mut log)?;
    Ok((status.code().unwrap_or(-1), log))
}

/// One HTTP exchange on `addr`: status and body.
fn http(
    addr: &str,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> Result<(u16, String), TestError> {
    let mut s = std::net::TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let (head, rest) = raw.split_once("\r\n\r\n").ok_or("an HTTP answer")?;
    let status = head.split_whitespace().nth(1).ok_or("a status")?.parse()?;
    Ok((status, rest.to_string()))
}

/// One heartbeat line, as a member writes it.
fn heartbeat(node: &str, stream: &str, seq: u64, secs: u64) -> String {
    serde_json::json!({
        "schema_version": 1,
        "kind": "heartbeat",
        "stream": stream,
        "seq": seq,
        "sent_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        "heartbeat_secs": secs,
        "inventory": {"schema_version": 1, "node_name": node},
    })
    .to_string()
        + "\n"
}

/// `POST /v1/fleet/ingest` with `body` under `token`, as JSON.
fn ingest(addr: &str, token: &str, body: &str) -> Result<(u16, serde_json::Value), TestError> {
    let (status, body) = http(addr, "POST", "/v1/fleet/ingest", token, body)?;
    let v = serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body));
    Ok((status, v))
}

/// `GET /v1/fleet/members` with an inventory token.
fn members(addr: &str) -> Result<serde_json::Value, TestError> {
    let (status, body) = http(
        addr,
        "GET",
        "/v1/fleet/members",
        &token("fleet-reader", sipnab::auth::SCOPE_INVENTORY),
        "",
    )?;
    if status != 200 {
        return Err(format!("members answered {status}: {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

/// The members answer's row for `member`.
fn row<'a>(v: &'a serde_json::Value, member: &str) -> Option<&'a serde_json::Value> {
    v["members"]
        .as_array()?
        .iter()
        .find(|r| r["member"] == member)
}

/// A center on loopback with a fresh store and key in `dir`.
fn center(dir: &std::path::Path, extra: &[&str]) -> Result<Center, TestError> {
    let key = private_file(dir, "center.signing", KEY)?;
    let store = dir.join("center.store");
    let store_key = store_key_file(dir)?;
    let mut args = vec![
        "--listen".to_string(),
        "127.0.0.1:0".to_string(),
        "--store".to_string(),
        store.to_string_lossy().into_owned(),
        "--store-key-file".to_string(),
        store_key.to_string_lossy().into_owned(),
        "--signing-key-file".to_string(),
        key.to_string_lossy().into_owned(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Center::start(&args)
}

/// Three members heartbeat into one center every 300 ms with a 1 s interval.
/// One stops. Within its three missed intervals and one check of the
/// center's, the center reports it silent and logs it, and the other two stay
/// heard. The answer keeps what the center verified apart from what each
/// member said about itself.
#[test]
fn three_members_report_and_a_stopped_one_is_silent_within_three_heartbeats()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let c = center(dir.path(), &["--silent-after-missed", "3"])?;
    let names = ["edge-a", "edge-b", "edge-c"];
    let tokens: Vec<String> = names
        .iter()
        .map(|n| token(n, sipnab::auth::SCOPE_FLEET_REPORT))
        .collect();
    let mut seq = 0;
    let mut stopped_at = None;
    let mut last_sent = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut silent_after = None;
    let mut silent_after_send = None;
    while Instant::now() < deadline {
        seq += 1;
        for (i, name) in names.iter().enumerate() {
            if i == 2 && stopped_at.is_some() {
                continue;
            }
            if i == 2 {
                last_sent = Some(Instant::now());
            }
            let (status, v) = ingest(
                &c.addr,
                &tokens[i],
                &heartbeat(name, &format!("s-{name}"), seq, 1),
            )?;
            assert_eq!(status, 200, "{name}: {v}");
            assert_eq!(v["accepted"], 1, "{name}: {v}");
            assert_eq!(v["member"], *name, "the member is the token's id: {v}");
        }
        if seq == 3 {
            stopped_at = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_millis(300));
        if let Some(at) = stopped_at {
            let v = members(&c.addr)?;
            if row(&v, "edge-c").is_some_and(|r| r["silent"] == true) {
                silent_after = Some(at.elapsed());
                silent_after_send = last_sent.map(|t: Instant| t.elapsed());
                for name in ["edge-a", "edge-b"] {
                    let r = row(&v, name).ok_or("a row")?;
                    assert_eq!(r["silent"], false, "{name} keeps reporting: {v}");
                }
                let a = row(&v, "edge-a").ok_or("a row")?;
                assert_eq!(a["verified"]["peer"], "127.0.0.1", "{v}");
                assert!(a["verified"]["heartbeats"].as_u64() >= Some(4), "{v}");
                assert_eq!(
                    a["self_reported"]["inventory"]["node_name"], "edge-a",
                    "{v}"
                );
                assert_eq!(a["self_reported"]["heartbeat_secs"], 1, "{v}");
                assert!(
                    a["inventory"].is_null() && a["verified"]["inventory"].is_null(),
                    "{v}"
                );
                break;
            }
        }
    }
    let after = silent_after.ok_or("edge-c was never reported silent")?;
    // Three 1 s intervals, then the center's 1 s check, the 300 ms poll and
    // slack for a loaded host.
    assert!(
        after <= Duration::from_millis(6_500),
        "silent only after {after:?}"
    );
    // Measured from before edge-c's last heartbeat was sent. The center counts
    // from when it received that heartbeat, which is no earlier than this, so
    // the bound holds at any load. From after the response it does not: on a
    // loaded host the response took tens of milliseconds to come back, and
    // silence at 2.989 s from there was correct.
    let since_send = silent_after_send.ok_or("no send time")?;
    assert!(
        since_send > Duration::from_secs(3),
        "silent {since_send:?} after the last heartbeat was sent, before three \
         intervals passed"
    );
    assert!(
        c.wait_for_log("fleet member 'edge-c' is silent", Duration::from_secs(5))
            .is_some(),
        "the center logs the silence"
    );
    Ok(())
}

/// A batch sent twice is counted once, also after the center restarts on the
/// same store; a record of a new stream sent later is counted.
#[test]
fn a_replayed_batch_is_not_counted_twice() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let tok = token("edge-a", sipnab::auth::SCOPE_FLEET_REPORT);
    let batch = heartbeat("edge-a", "s-1", 1, 30) + &heartbeat("edge-a", "s-1", 2, 30);
    {
        let c = center(dir.path(), &[])?;
        let (status, v) = ingest(&c.addr, &tok, &batch)?;
        assert_eq!(
            (status, v["accepted"].clone(), v["duplicate"].clone()),
            (200, 2.into(), 0.into()),
            "{v}"
        );
        let (status, v) = ingest(&c.addr, &tok, &batch)?;
        assert_eq!(
            (status, v["accepted"].clone(), v["duplicate"].clone()),
            (200, 0.into(), 2.into()),
            "{v}"
        );
        let m = members(&c.addr)?;
        assert_eq!(
            row(&m, "edge-a").ok_or("a row")?["verified"]["heartbeats"],
            2,
            "{m}"
        );
    }
    let c = center(dir.path(), &[])?;
    let (_, v) = ingest(&c.addr, &tok, &batch)?;
    assert_eq!(
        (v["accepted"].clone(), v["duplicate"].clone()),
        (0.into(), 2.into()),
        "after a restart: {v}"
    );
    let (_, v) = ingest(&c.addr, &tok, &heartbeat("edge-a", "s-2", 1, 30))?;
    assert_eq!(v["accepted"], 1, "a new stream, sent later: {v}");
    let m = members(&c.addr)?;
    assert_eq!(
        row(&m, "edge-a").ok_or("a row")?["verified"]["heartbeats"],
        3,
        "{m}"
    );
    Ok(())
}

/// Revoking one member's token id refuses that member and no other, with no
/// restart.
#[test]
fn a_revoked_member_is_refused_and_the_others_are_not() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let revoked = private_file(dir.path(), "revoked", "# revoked members\n")?;
    let srv = center(
        dir.path(),
        &["--revoked-file", revoked.to_str().ok_or("utf-8")?],
    )?;
    let tok_a = token("edge-a", sipnab::auth::SCOPE_FLEET_REPORT);
    let tok_b = token("edge-b", sipnab::auth::SCOPE_FLEET_REPORT);
    assert_eq!(
        ingest(&srv.addr, &tok_b, &heartbeat("edge-b", "s", 1, 30))?.0,
        200,
        "before"
    );
    // A later mtime, whatever the file system's resolution.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(&revoked, "# revoked members\nedge-b\n")?;
    let (status, v) = ingest(&srv.addr, &tok_b, &heartbeat("edge-b", "s", 2, 30))?;
    assert_eq!(status, 401, "a revoked member: {v}");
    assert_eq!(
        ingest(&srv.addr, &tok_a, &heartbeat("edge-a", "s", 1, 30))?.0,
        200,
        "another member"
    );
    let listed = members(&srv.addr)?;
    assert_eq!(
        row(&listed, "edge-b").ok_or("a row")?["verified"]["heartbeats"],
        1,
        "the refused one was not counted: {listed}"
    );
    Ok(())
}

/// The ingest takes a `fleet-report` token and nothing else; that token reads
/// nothing; a bad batch is refused with the line; a token whose id cannot
/// name a member is refused.
#[test]
fn the_ingest_and_the_members_list_take_only_their_scopes() -> Result<(), TestError> {
    use sipnab::auth::{
        SCOPE_ADMIN, SCOPE_FLEET_REPORT, SCOPE_FULL, SCOPE_INVENTORY, SCOPE_METRICS,
    };
    let dir = tempfile::tempdir()?;
    let c = center(dir.path(), &[])?;
    let hb = heartbeat("edge-a", "s", 1, 30);
    for scope in [SCOPE_FULL, SCOPE_ADMIN, SCOPE_INVENTORY, SCOPE_METRICS] {
        assert_eq!(
            ingest(&c.addr, &token("edge-a", scope), &hb)?.0,
            401,
            "{scope} ingests"
        );
    }
    assert_eq!(ingest(&c.addr, "not-a-token", &hb)?.0, 401, "no token");
    let other_key = sipnab::auth::mint(
        b"another-center-key-0123456789",
        "edge-a",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        SCOPE_FLEET_REPORT,
    );
    assert_eq!(
        ingest(&c.addr, &other_key, &hb)?.0,
        401,
        "another center's token"
    );
    let report = token("edge-a", SCOPE_FLEET_REPORT);
    let (status, _) = http(&c.addr, "GET", "/v1/fleet/members", &report, "")?;
    assert_eq!(status, 401, "a member token reads nothing");
    let (status, v) = ingest(&c.addr, &report, &format!("{hb}not json\n"))?;
    assert_eq!(status, 400, "{v}");
    assert!(v.to_string().contains("line 2"), "{v}");
    let (status, v) = ingest(&c.addr, &token("bad id", SCOPE_FLEET_REPORT), &hb)?;
    assert_eq!(status, 403, "{v}");
    assert_eq!(
        ingest(&c.addr, &report, &hb)?.0,
        200,
        "the member's own token"
    );
    for scope in [SCOPE_INVENTORY, SCOPE_FULL] {
        let (status, _) = http(
            &c.addr,
            "GET",
            "/v1/fleet/members",
            &token("reader", scope),
            "",
        )?;
        assert_eq!(status, 200, "{scope} reads the members");
    }
    Ok(())
}

/// A store an earlier release wrote in clear is imported and sealed at start.
/// The store is created 0600, a store other users can read is refused, and
/// retention removes a member past it at start, from the answer and the file.
#[cfg(unix)]
#[test]
fn the_store_is_private_and_retention_is_enforced() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("center.store");
    let store_key = store_key_file(dir.path())?;
    let old = serde_json::json!({
        "member": "edge-gone",
        "received_at": (chrono::Utc::now() - chrono::Duration::hours(100)).to_rfc3339(),
        "peer": "192.0.2.9",
        "heartbeats": 7,
        "cursor": {"stream": "s", "seq": 7, "sent_at": "2026-11-01T00:00:00Z"},
        "heartbeat_secs": 30,
        "inventory": {"node_name": "edge-gone"},
    });
    let recent = serde_json::json!({
        "member": "edge-kept",
        "received_at": (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
        "peer": "192.0.2.10",
        "heartbeats": 3,
        "cursor": {"stream": "s", "seq": 3, "sent_at": "2026-11-07T00:00:00Z"},
        "heartbeat_secs": 30,
        "inventory": {"node_name": "edge-kept"},
    });
    private_file(dir.path(), "center.store", &format!("{old}\n{recent}\n"))?;
    let c = center(dir.path(), &["--retention-hours", "72"])?;
    let m = members(&c.addr)?;
    assert!(row(&m, "edge-gone").is_none(), "past retention: {m}");
    assert!(row(&m, "edge-kept").is_some(), "inside retention: {m}");
    assert!(sealed(&store)?, "the store written in clear is sealed now");
    for name in ["edge-gone", "edge-kept"] {
        assert!(!holds(&store, name)?, "{name} is not in the file in clear");
    }
    assert_eq!(
        std::fs::metadata(&store)?.permissions().mode() & 0o777,
        0o600,
        "the rewritten store stays private"
    );
    drop(c);

    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644))?;
    let key = dir.path().join("center.signing");
    let (code, log) = refused(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ])?;
    assert_eq!(code, 2, "{log}");
    assert!(log.contains("chmod 600"), "{log}");

    let fresh = dir.path().join("fresh.store");
    let c = Center::start(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        fresh.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ])?;
    assert_eq!(
        std::fs::metadata(&fresh)?.permissions().mode() & 0o777,
        0o600,
        "created private"
    );
    drop(c);
    Ok(())
}

/// Plain HTTP is refused off loopback, before anything is bound; HTTPS
/// serves, and a member's heartbeat goes through it.
#[test]
fn plain_http_is_refused_off_loopback_and_https_serves() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let key = private_file(dir.path(), "center.signing", KEY)?;
    let store = dir.path().join("center.store");
    let store_key = store_key_file(dir.path())?;
    let (code, log) = refused(&[
        "--listen",
        "0.0.0.0:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ])?;
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("plain HTTP is refused except on loopback"),
        "{log}"
    );
    assert!(!store.exists(), "refused before the store was created");

    let pki = tls_pki::test_pki("fleet-center")?;
    let c = Center::start(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
        "--tls-cert",
        &pki.cert,
        "--tls-key",
        &pki.key,
    ])?;
    let body = heartbeat("edge-a", "s", 1, 30);
    let tok = format!(
        "Bearer {}",
        token("edge-a", sipnab::auth::SCOPE_FLEET_REPORT)
    );
    let resp = tls_pki::https_exchange(
        &c.addr,
        "POST /v1/fleet/ingest HTTP/1.1",
        &[
            ("Authorization", &tok),
            ("Content-Type", "application/x-ndjson"),
        ],
        body.as_bytes(),
        &pki.ca,
        Duration::from_secs(10),
    )?;
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(resp.body.contains("\"accepted\":1"), "{resp:?}");
    Ok(())
}

/// `--tls-client-ca` makes the center's HTTPS handshake require a member
/// certificate from that CA, on top of the member's token: a heartbeat
/// without one is refused at the handshake, one with it is accepted. The
/// settings that cannot be served are refused before anything is bound.
#[test]
fn a_client_ca_makes_the_center_require_a_member_certificate() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let key = private_file(dir.path(), "center.signing", KEY)?;
    let store = dir.path().join("center.store");
    let store_key = store_key_file(dir.path())?;
    let store_arg = store.to_str().ok_or("utf-8")?;
    let key_arg = key.to_str().ok_or("utf-8")?;
    let pki = tls_pki::test_pki("fleet-mtls")?;
    let ca = tls_pki::client_ca("fleet-mtls")?;
    let base = [
        "--listen",
        "127.0.0.1:0",
        "--store",
        store_arg,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key_arg,
    ];

    let mut no_ca = base.to_vec();
    no_ca.extend([
        "--tls-cert",
        &pki.cert,
        "--tls-key",
        &pki.key,
        "--tls-client-auth",
        "required",
    ]);
    let (code, log) = refused(&no_ca)?;
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains(
            "--tls-client-auth required needs --tls-client-ca: name the CA that issues the \
             client certificates"
        ),
        "{log}"
    );
    let mut no_tls = base.to_vec();
    no_tls.extend(["--tls-client-ca", &ca.ca_file]);
    let (code, log) = refused(&no_tls)?;
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("needs --tls-cert and --tls-key: a client certificate is asked for only"),
        "{log}"
    );

    let mut args = base.to_vec();
    args.extend([
        "--tls-cert",
        &pki.cert,
        "--tls-key",
        &pki.key,
        "--tls-client-ca",
        &ca.ca_file,
    ]);
    let c = Center::start(&args)?;
    let tok = format!(
        "Bearer {}",
        token("edge-a", sipnab::auth::SCOPE_FLEET_REPORT)
    );
    let send = |client: Option<&tls_pki::ClientCert>| {
        tls_pki::https_exchange_as(
            &c.addr,
            "POST /v1/fleet/ingest HTTP/1.1",
            &[
                ("Authorization", &tok),
                ("Content-Type", "application/x-ndjson"),
            ],
            heartbeat("edge-a", "s", 1, 30).as_bytes(),
            &pki.ca,
            client,
            Duration::from_secs(10),
        )
    };
    let refused_hb = send(None);
    assert!(refused_hb.is_err(), "no certificate: {refused_hb:?}");
    let member = ca.issue("edge-a", tls_pki::Validity::Current)?;
    let resp = send(Some(&member))?;
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(
        c.wait_for_log(
            "presented a verified client certificate",
            Duration::from_secs(10)
        )
        .is_some(),
        "the verified member is logged"
    );
    Ok(())
}

/// `--tls-client-auth optional` serves a member that sends no certificate,
/// and still refuses one whose certificate another CA issued.
#[test]
fn an_optional_center_serves_no_certificate_but_refuses_a_bad_one() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let key = private_file(dir.path(), "center.signing", KEY)?;
    let store = dir.path().join("center.store");
    let store_key = store_key_file(dir.path())?;
    let pki = tls_pki::test_pki("fleet-mtls-opt")?;
    let ca = tls_pki::client_ca("fleet-mtls-opt")?;
    let c = Center::start(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
        "--tls-cert",
        &pki.cert,
        "--tls-key",
        &pki.key,
        "--tls-client-ca",
        &ca.ca_file,
        "--tls-client-auth",
        "optional",
    ])?;
    let tok = format!(
        "Bearer {}",
        token("edge-b", sipnab::auth::SCOPE_FLEET_REPORT)
    );
    let send = |client: Option<&tls_pki::ClientCert>| {
        tls_pki::https_exchange_as(
            &c.addr,
            "POST /v1/fleet/ingest HTTP/1.1",
            &[
                ("Authorization", &tok),
                ("Content-Type", "application/x-ndjson"),
            ],
            heartbeat("edge-b", "s", 1, 30).as_bytes(),
            &pki.ca,
            client,
            Duration::from_secs(10),
        )
    };
    let resp = send(None)?;
    assert_eq!(
        resp.status, 200,
        "optional serves a member with no certificate: {resp:?}"
    );
    let stranger =
        tls_pki::client_ca("fleet-other")?.issue("edge-b", tls_pki::Validity::Current)?;
    assert!(
        send(Some(&stranger)).is_err(),
        "optional still refuses another CA's certificate"
    );
    Ok(())
}

/// A store key file in `dir` for a test center: mode 0600, a fixed key.
fn store_key_file(dir: &std::path::Path) -> Result<std::path::PathBuf, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("center.storekey");
    std::fs::write(&path, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// Whether the file at `path` starts as a sealed file does.
fn sealed(path: &std::path::Path) -> Result<bool, TestError> {
    Ok(std::fs::read(path)?.starts_with(b"SNFS"))
}

/// Whether the file at `path` holds `text` in clear.
fn holds(path: &std::path::Path, text: &str) -> Result<bool, TestError> {
    Ok(std::fs::read(path)?
        .windows(text.len())
        .any(|w| w == text.as_bytes()))
}

/// `sipnab fleet keygen --out path`: exit code, stdout, stderr.
fn keygen(path: &std::path::Path) -> Result<(i32, String, String), TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["fleet", "keygen", "--out"])
        .arg(path)
        .env("NO_COLOR", "1")
        .output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout)?,
        String::from_utf8(out.stderr)?,
    ))
}

/// The key id a `keygen` line names: `<path>: key id <id>`.
fn key_id_in(line: &str) -> Result<String, TestError> {
    Ok(line
        .trim()
        .rsplit(' ')
        .next()
        .ok_or("a key id")?
        .to_string())
}

/// The arguments of a center on loopback over `store`, with the store key
/// file `store_key` and the signing key in `dir`.
fn serve_args(
    dir: &std::path::Path,
    store: &std::path::Path,
    store_key: Option<&std::path::Path>,
    extra: &[&str],
) -> Result<Vec<String>, TestError> {
    let signing = private_file(dir, "center.signing", KEY)?;
    let mut args = vec![
        "--listen".to_string(),
        "127.0.0.1:0".to_string(),
        "--store".to_string(),
        store.to_string_lossy().into_owned(),
        "--signing-key-file".to_string(),
        signing.to_string_lossy().into_owned(),
    ];
    if let Some(key) = store_key {
        args.push("--store-key-file".to_string());
        args.push(key.to_string_lossy().into_owned());
    }
    args.extend(extra.iter().map(|s| (*s).to_string()));
    Ok(args)
}

/// A center started with [`serve_args`].
fn serve(
    dir: &std::path::Path,
    store: &std::path::Path,
    store_key: &std::path::Path,
    extra: &[&str],
) -> Result<Center, TestError> {
    let args = serve_args(dir, store, Some(store_key), extra)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Center::start(&args)
}

/// A center that should refuse to start, with [`serve_args`]: its exit code
/// and its log.
fn serve_refused(
    dir: &std::path::Path,
    store: &std::path::Path,
    store_key: Option<&std::path::Path>,
    extra: &[&str],
) -> Result<(i32, String), TestError> {
    let args = serve_args(dir, store, store_key, extra)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    refused(&args)
}

/// A store in `dir` under a new key, holding one heartbeat from each of
/// `nodes`, with its center stopped: the store, the key file and the key id.
fn stored(
    dir: &std::path::Path,
    nodes: &[&str],
) -> Result<(std::path::PathBuf, std::path::PathBuf, String), TestError> {
    let store = dir.join("center.store");
    let key = dir.join("first.key");
    let (code, out, err) = keygen(&key)?;
    assert_eq!(code, 0, "{err}");
    let c = serve(dir, &store, &key, &[])?;
    for node in nodes {
        let (status, body) = ingest(
            &c.addr,
            &token(node, sipnab::auth::SCOPE_FLEET_REPORT),
            &heartbeat(node, "s-1", 1, 30),
        )?;
        assert_eq!(status, 200, "{body}");
    }
    drop(c);
    Ok((store, key, key_id_in(&out)?))
}

/// The members a center lists, by name, in order.
fn member_names(addr: &str) -> Result<Vec<String>, TestError> {
    let m = members(addr)?;
    let mut names: Vec<String> = m["members"]
        .as_array()
        .ok_or("members")?
        .iter()
        .filter_map(|r| r["member"].as_str().map(str::to_string))
        .collect();
    names.sort();
    Ok(names)
}

/// A center without a store key does not start, creates no store, and says
/// which flag is missing and the command that makes a key.
#[test]
fn failure_a_center_without_a_store_key_refuses_to_start_and_names_the_fix() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("center.store");
    let (code, log) = serve_refused(dir.path(), &store, None, &[])?;
    assert_eq!(code, 2, "{log}");
    assert!(log.contains("--store-key-file is required"), "{log}");
    assert!(log.contains("sipnab fleet keygen --out"), "{log}");
    assert!(!log.contains("  "), "one line, single spaces: {log}");
    assert!(!store.exists(), "no store was written without a key");
    Ok(())
}

/// `sipnab fleet keygen` writes a private key file and prints its id, a
/// center starts with it, and a second run on the same path changes nothing.
#[cfg(unix)]
#[test]
fn success_keygen_makes_a_key_a_center_starts_with_and_never_overwrites_it() -> Result<(), TestError>
{
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("store.key");
    let (code, out, err) = keygen(&key)?;
    assert_eq!(code, 0, "{err}");
    let id = key_id_in(&out)?;
    assert!(out.contains("store.key: key id "), "{out}");
    assert!(
        id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit()),
        "{out}"
    );
    assert_eq!(
        std::fs::metadata(&key)?.permissions().mode() & 0o777,
        0o600,
        "the key file is for its owner only"
    );
    let text = std::fs::read_to_string(&key)?;
    assert!(!out.contains(text.trim()), "the key itself is not printed");

    let c = serve(dir.path(), &dir.path().join("center.store"), &key, &[])?;
    assert_eq!(
        member_names(&c.addr)?,
        Vec::<String>::new(),
        "a new store has no members"
    );
    drop(c);

    let (code, out, err) = keygen(&key)?;
    assert_eq!(code, 2, "{out}{err}");
    assert!(err.contains("store.key"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&key)?,
        text,
        "the key file is as it was"
    );
    Ok(())
}

/// Three members report to a real center. Its store file is sealed and
/// holds none of their names, node names or addresses in clear, and a new
/// center process on the same store and key lists all three.
#[test]
fn success_three_members_are_stored_sealed_and_survive_a_restart() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let nodes = ["edge-alpha", "edge-bravo", "edge-charlie"];
    let (store, key, _) = stored(dir.path(), &nodes)?;
    assert!(sealed(&store)?, "the store is a sealed file");
    for needle in nodes
        .iter()
        .copied()
        .chain(["127.0.0.1", "node_name", "heartbeat"])
    {
        assert!(!holds(&store, needle)?, "{needle} is in the store in clear");
    }
    let c = serve(dir.path(), &store, &key, &[])?;
    assert_eq!(
        member_names(&c.addr)?,
        nodes.map(str::to_string).to_vec(),
        "the three members, read from the store"
    );
    Ok(())
}

/// A heartbeat the center acknowledged is still there after the center is
/// killed without warning and started again.
#[test]
fn edge_an_acknowledged_heartbeat_survives_a_killed_center() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("center.store");
    let key = store_key_file(dir.path())?;
    let c = serve(dir.path(), &store, &key, &[])?;
    let (status, body) = ingest(
        &c.addr,
        &token("edge-a", sipnab::auth::SCOPE_FLEET_REPORT),
        &heartbeat("edge-a", "s-1", 1, 30),
    )?;
    assert_eq!(status, 200, "{body}");
    // Dropping the center kills it (SIGKILL): there is no rewrite on exit,
    // so the file is the base and one append.
    drop(c);
    let c = serve(dir.path(), &store, &key, &[])?;
    assert_eq!(
        member_names(&c.addr)?,
        vec!["edge-a".to_string()],
        "the member whose heartbeat was acknowledged"
    );
    Ok(())
}

/// A store under one key, started with another: the center refuses, names
/// the sealed layer, the file, the id of the key the file needs and the
/// flag that takes it, and leaves the file as it was.
#[test]
fn failure_a_store_under_another_key_refuses_the_start_and_names_the_key() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let (store, _, first_id) = stored(dir.path(), &["edge-a"])?;
    let before = std::fs::read(&store)?;
    let other = dir.path().join("second.key");
    assert_eq!(keygen(&other)?.0, 0, "a second key was made");
    let (code, log) = serve_refused(dir.path(), &store, Some(&other), &[])?;
    assert_eq!(code, 2, "{log}");
    for want in [
        "sealed layer",
        "center.store",
        first_id.as_str(),
        "--store-old-key-file",
    ] {
        assert!(log.contains(want), "wants {want}: {log}");
    }
    let key_text = std::fs::read_to_string(&other)?;
    assert!(!log.contains(key_text.trim()), "no key in the log");
    assert_eq!(
        std::fs::read(&store)?,
        before,
        "the refused store is untouched"
    );
    Ok(())
}

/// Key rotation: a center started with a new key and the old one listed
/// reads the store and rewrites it under the new key, so the next start
/// needs the new key only, and the old key alone no longer opens it.
#[test]
fn success_a_rotated_key_reads_the_store_once_with_the_old_key_listed() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (store, old, _) = stored(dir.path(), &["edge-a", "edge-b"])?;
    let new = dir.path().join("second.key");
    assert_eq!(keygen(&new)?.0, 0, "a second key was made");
    let old_arg = old.to_string_lossy().into_owned();
    let c = serve(
        dir.path(),
        &store,
        &new,
        &["--store-old-key-file", &old_arg],
    )?;
    assert_eq!(member_names(&c.addr)?.len(), 2, "read under the old key");
    drop(c);
    let c = serve(dir.path(), &store, &new, &[])?;
    assert_eq!(
        member_names(&c.addr)?.len(),
        2,
        "now under the new key alone"
    );
    drop(c);
    let (code, log) = serve_refused(dir.path(), &store, Some(&old), &[])?;
    assert_eq!(code, 2, "the old key no longer opens it: {log}");
    Ok(())
}

/// One changed byte in the store between two runs: the center refuses to
/// start, names the sealed layer and the file, and does not rewrite it.
#[test]
fn failure_a_modified_store_refuses_the_start() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (store, key, _) = stored(dir.path(), &["edge-a", "edge-b"])?;
    let good = std::fs::read(&store)?;
    for at in [8, good.len() / 2, good.len() - 1] {
        let mut bad = good.clone();
        bad[at] ^= 0x80;
        std::fs::write(&store, &bad)?;
        let (code, log) = serve_refused(dir.path(), &store, Some(&key), &[])?;
        assert_eq!(code, 2, "byte {at}: {log}");
        assert!(
            log.contains("sealed layer") && log.contains("center.store"),
            "byte {at}: {log}"
        );
        assert_eq!(std::fs::read(&store)?, bad, "byte {at}: left as found");
    }
    Ok(())
}

/// A store cut short inside the records it was written with refuses the
/// start as truncated.
#[test]
fn failure_a_truncated_store_refuses_the_start() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (store, key, _) = stored(dir.path(), &["edge-a", "edge-b"])?;
    // A clean start rewrites the store as one base, with no appends after.
    drop(serve(dir.path(), &store, &key, &[])?);
    let good = std::fs::read(&store)?;
    std::fs::write(&store, &good[..good.len() - 40])?;
    let (code, log) = serve_refused(dir.path(), &store, Some(&key), &[])?;
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("sealed layer") && log.contains("truncated"),
        "{log}"
    );
    Ok(())
}

/// One center's store put in the place of another's, under the other's key:
/// refused, because the file names the key it was written under.
#[test]
fn failure_a_store_swapped_in_from_another_center_is_refused() -> Result<(), TestError> {
    let (a, b) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let (store_a, _, id_a) = stored(a.path(), &["edge-a"])?;
    let (store_b, key_b, _) = stored(b.path(), &["edge-b"])?;
    std::fs::copy(&store_a, &store_b)?;
    let (code, log) = serve_refused(b.path(), &store_b, Some(&key_b), &[])?;
    assert_eq!(code, 2, "{log}");
    assert!(log.contains("sealed layer") && log.contains(&id_a), "{log}");
    Ok(())
}

/// `--store-encryption modular` and `both` are refused at start with a
/// message that names the value and the one that works; no store is made.
#[test]
fn failure_modular_and_both_are_refused_at_start_until_this_build_has_them() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("center.store");
    let key = store_key_file(dir.path())?;
    for mode in ["modular", "both"] {
        let (code, log) = serve_refused(
            dir.path(),
            &store,
            Some(&key),
            &["--store-encryption", mode],
        )?;
        assert_eq!(code, 2, "{mode}: {log}");
        assert!(
            log.contains(&format!("--store-encryption {mode}")) && log.contains("`sealed`"),
            "{mode}: {log}"
        );
        assert!(
            !log.contains("  "),
            "{mode}: one line, single spaces: {log}"
        );
        assert!(!store.exists(), "{mode}: no store was written");
    }
    Ok(())
}

/// `--store-encryption sealed` is the default spelled out, and there is no
/// value that turns encryption off.
#[test]
fn edge_sealed_can_be_named_and_no_value_turns_encryption_off() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("center.store");
    let key = store_key_file(dir.path())?;
    let c = serve(dir.path(), &store, &key, &["--store-encryption", "sealed"])?;
    assert!(sealed(&store)?, "the store is a sealed file");
    drop(c);
    for off in ["none", "off", "plain", ""] {
        let (code, log) =
            serve_refused(dir.path(), &store, Some(&key), &["--store-encryption", off])?;
        assert_eq!(code, 2, "{off:?}: {log}");
        assert!(
            log.contains("sealed") && log.contains("both"),
            "{off:?}: {log}"
        );
    }
    Ok(())
}

/// A store key file other users can read is refused, by the rule every
/// private file follows.
#[cfg(unix)]
#[test]
fn failure_a_store_key_others_can_read_is_refused() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let key = store_key_file(dir.path())?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640))?;
    let (code, log) = serve_refused(
        dir.path(),
        &dir.path().join("center.store"),
        Some(&key),
        &[],
    )?;
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("--store-key-file") && log.contains("chmod 600"),
        "{log}"
    );
    Ok(())
}

/// A store key file that holds something else is refused by what is wrong
/// with it, and its contents are not repeated.
#[test]
fn failure_a_store_key_file_that_is_not_a_key_is_refused_without_its_contents()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    for (text, want) in [
        ("correct-horse-battery\n", "not standard base64"),
        ("c2hvcnQ=\n", "5 bytes"),
        ("", "0 bytes"),
    ] {
        let key = private_file(dir.path(), "bad.key", text)?;
        let (code, log) = serve_refused(
            dir.path(),
            &dir.path().join("center.store"),
            Some(&key),
            &[],
        )?;
        assert_eq!(code, 2, "{text:?}: {log}");
        assert!(
            log.contains("bad.key") && log.contains(want),
            "{text:?}: {log}"
        );
        if !text.is_empty() {
            assert!(!log.contains(text.trim()), "{text:?} is repeated: {log}");
        }
    }
    Ok(())
}

/// An old key file that does not exist is refused by its own flag, with
/// the store untouched.
#[test]
fn failure_a_missing_old_key_file_is_named_by_its_flag() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (store, key, _) = stored(dir.path(), &["edge-a"])?;
    let before = std::fs::read(&store)?;
    let absent = dir.path().join("absent.key").to_string_lossy().into_owned();
    let (code, log) = serve_refused(
        dir.path(),
        &store,
        Some(&key),
        &["--store-old-key-file", &absent],
    )?;
    assert_eq!(code, 2, "{log}");
    assert!(
        log.contains("--store-old-key-file") && log.contains("absent.key"),
        "{log}"
    );
    assert_eq!(std::fs::read(&store)?, before, "the store is untouched");
    Ok(())
}

/// An old key that the store is not under is harmless: the store opens
/// under the current key.
#[test]
fn edge_an_old_key_the_store_does_not_need_changes_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (store, key, _) = stored(dir.path(), &["edge-a"])?;
    let spare = dir.path().join("spare.key");
    assert_eq!(keygen(&spare)?.0, 0, "a spare key was made");
    let spare_arg = spare.to_string_lossy().into_owned();
    let c = serve(
        dir.path(),
        &store,
        &key,
        &["--store-old-key-file", &spare_arg],
    )?;
    assert_eq!(
        member_names(&c.addr)?,
        vec!["edge-a".to_string()],
        "the member is read under the current key"
    );
    Ok(())
}

/// A center started on a path with no store makes a sealed one before it
/// takes a heartbeat, and leaves no staged file beside it.
#[test]
fn edge_a_new_store_is_sealed_before_the_first_heartbeat() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sub = dir.path().join("data");
    std::fs::create_dir(&sub)?;
    let store = sub.join("center.store");
    let key = store_key_file(dir.path())?;
    let c = serve(dir.path(), &store, &key, &[])?;
    assert!(sealed(&store)?, "sealed before any heartbeat");
    let mut names: Vec<String> = std::fs::read_dir(&sub)?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "center.store".to_string(),
            "center.store.intake".to_string()
        ],
        "the store and its intake, and no staged file beside them"
    );
    assert!(
        sealed(&sub.join("center.store.intake"))?,
        "the intake is sealed before any call record"
    );
    drop(c);
    Ok(())
}

/// `keygen` into a directory that does not exist is refused, names the
/// path, and prints no key id.
#[test]
fn failure_keygen_into_a_missing_directory_is_refused() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (code, out, err) = keygen(&dir.path().join("no-such-dir/store.key"))?;
    assert_eq!(code, 2, "{out}{err}");
    assert!(
        err.contains("sipnab fleet keygen") && err.contains("no-such-dir"),
        "{err}"
    );
    assert!(out.is_empty(), "{out}");
    Ok(())
}

/// Two keys from `keygen` differ, and so do their ids.
#[test]
fn edge_two_generated_keys_and_their_ids_differ() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (a, b) = (dir.path().join("a.key"), dir.path().join("b.key"));
    let (out_a, out_b) = (keygen(&a)?.1, keygen(&b)?.1);
    assert_ne!(std::fs::read(&a)?, std::fs::read(&b)?, "two keys differ");
    assert_ne!(key_id_in(&out_a)?, key_id_in(&out_b)?, "two key ids differ");
    Ok(())
}

include!("support/child_lifetime.rs");
