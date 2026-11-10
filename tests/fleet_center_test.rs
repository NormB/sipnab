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
fn refused(args: &[&str]) -> Result<(i32, String), TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["fleet", "serve"])
        .args(args)
        .env("NO_COLOR", "1")
        .output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stderr)?,
    ))
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
    let mut args = vec![
        "--listen".to_string(),
        "127.0.0.1:0".to_string(),
        "--store".to_string(),
        store.to_string_lossy().into_owned(),
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

/// The store is created 0600, a store other users can read is refused, and
/// retention removes a member past it at start, from the answer and the file.
#[cfg(unix)]
#[test]
fn the_store_is_private_and_retention_is_enforced() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("center.store");
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
    let text = std::fs::read_to_string(&store)?;
    assert!(
        !text.contains("edge-gone"),
        "removed from the file too: {text}"
    );
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
    let (code, log) = refused(&[
        "--listen",
        "0.0.0.0:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
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
    let store_arg = store.to_str().ok_or("utf-8")?;
    let key_arg = key.to_str().ok_or("utf-8")?;
    let pki = tls_pki::test_pki("fleet-mtls")?;
    let ca = tls_pki::client_ca("fleet-mtls")?;
    let base = [
        "--listen",
        "127.0.0.1:0",
        "--store",
        store_arg,
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
    let pki = tls_pki::test_pki("fleet-mtls-opt")?;
    let ca = tls_pki::client_ca("fleet-mtls-opt")?;
    let c = Center::start(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
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

include!("support/child_lifetime.rs");
