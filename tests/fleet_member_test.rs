// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Fleet members end to end: real `sipnab` capture runs with
//! `--fleet-report-url` pushing heartbeats into a real `sipnab fleet serve`.
//!
//! The phase P1 acceptance of docs/design/fleet-central.local.md: three
//! members heartbeat into one center; a killed member is reported silent
//! within three heartbeats; a revoked token is refused; a replayed batch is
//! not counted twice; the center down leaves the members' capture unaffected
//! and the spool drains on its return.
#![cfg(feature = "api")]

use std::io::Write as _;
use std::time::{Duration, Instant};

#[path = "support/server.rs"]
mod server;

#[path = "support/fleet_center.rs"]
mod fleet_center;

#[path = "support/tls_pki.rs"]
mod tls_pki;

use fleet_center::{Center, TestError, http};
use server::ApiServer;

/// The center's signing key.
const CENTER_KEY: &str = "fleet-member-e2e-center-key-0123456789abcdef";

/// The members' own REST API key.
const MEMBER_KEY: &str = "fleet-member-e2e-member-key-0123456789abcdef";

/// A token minted with the center's key.
fn token(id: &str, scope: &str) -> String {
    sipnab::auth::mint(
        CENTER_KEY.as_bytes(),
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

/// A center on loopback in `dir`, with `extra` arguments.
fn center(dir: &std::path::Path, listen: &str, extra: &[&str]) -> Result<Center, TestError> {
    let key = private_file(dir, "center.signing", CENTER_KEY)?;
    let store = dir.join("center.store");
    let mut args: Vec<String> = [
        "--listen",
        listen,
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.extend(extra.iter().map(|s| (*s).to_string()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Center::start(&args)
}

/// A member: a real capture run with the REST API (which keeps it running)
/// that reports to `center` every second, from its own spool in `dir`.
struct Member {
    srv: ApiServer,
    spool: std::path::PathBuf,
}

fn member(dir: &std::path::Path, name: &str, center: &str) -> Result<Member, TestError> {
    let tok = private_file(
        dir,
        &format!("{name}.token"),
        &token(name, sipnab::auth::SCOPE_FLEET_REPORT),
    )?;
    let spool = dir.join(format!("{name}.spool"));
    let cfg = dir.join(format!("{name}.toml"));
    std::fs::write(
        &cfg,
        format!(
            "[fleet]\nreport_url = \"http://{center}\"\nreport_token_file = {:?}\n\
             spool_dir = {:?}\nheartbeat_secs = 1\n",
            tok.to_str().ok_or("utf-8")?,
            spool.to_str().ok_or("utf-8")?,
        ),
    )?;
    let srv = ApiServer::spawn(&[
        "--api-signing-key",
        MEMBER_KEY,
        "--node-name",
        name,
        "--config",
        cfg.to_str().ok_or("utf-8")?,
    ])?;
    Ok(Member { srv, spool })
}

/// The center's members answer.
fn members(addr: &str) -> Result<serde_json::Value, TestError> {
    let (status, body) = http(
        addr,
        "GET",
        "/v1/fleet/members",
        &token("reader", sipnab::auth::SCOPE_INVENTORY),
        b"",
    )?;
    if status != 200 {
        return Err(format!("members answered {status}: {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

/// `member`'s row, if the center has one.
fn row(v: &serde_json::Value, member: &str) -> Option<serde_json::Value> {
    v["members"]
        .as_array()?
        .iter()
        .find(|r| r["member"] == member)
        .cloned()
}

/// Heartbeats the center accepted from `member`, 0 before the first.
fn heartbeats(addr: &str, member: &str) -> Result<u64, TestError> {
    Ok(row(&members(addr)?, member)
        .and_then(|r| r["verified"]["heartbeats"].as_u64())
        .unwrap_or(0))
}

/// Poll `f` every 100 ms for up to `within`.
fn wait_until(
    within: Duration,
    mut f: impl FnMut() -> Result<bool, TestError>,
) -> Result<bool, TestError> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if f()? {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(false)
}

/// Three members heartbeat into one center, each under its own name with
/// its own inventory. One is killed; within its three missed 1 s intervals
/// and the center's 1 s check, the center reports it silent, and the other
/// two stay heard.
#[test]
fn three_members_report_and_a_killed_one_is_silent_within_three_heartbeats() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let c = center(dir.path(), "127.0.0.1:0", &["--silent-after-missed", "3"])?;
    let names = ["edge-a", "edge-b", "edge-c"];
    let mut ms: Vec<Option<Member>> = names
        .iter()
        .map(|n| member(dir.path(), n, &c.addr).map(Some))
        .collect::<Result<_, _>>()?;
    let all_heard = wait_until(Duration::from_secs(20), || {
        Ok(names
            .iter()
            .map(|n| heartbeats(&c.addr, n))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .all(|h| *h >= 2))
    })?;
    assert!(all_heard, "every member reports: {}", members(&c.addr)?);
    let v = members(&c.addr)?;
    for name in names {
        let r = row(&v, name).ok_or("a row")?;
        assert_eq!(
            r["self_reported"]["inventory"]["node_name"], name,
            "each member's own inventory: {v}"
        );
        assert_eq!(r["self_reported"]["heartbeat_secs"], 1, "{v}");
        assert_eq!(r["silent"], false, "{v}");
    }

    let killed = ms[2].take().ok_or("edge-c")?;
    killed.srv.stop()?;
    let at = Instant::now();
    let silent = wait_until(Duration::from_secs(10), || {
        Ok(row(&members(&c.addr)?, "edge-c").is_some_and(|r| r["silent"] == true))
    })?;
    let after = at.elapsed();
    assert!(silent, "the killed member was never reported silent");
    // Three 1 s intervals since its last heartbeat, the center's 1 s check,
    // the 100 ms poll, and slack for a loaded host.
    assert!(
        after <= Duration::from_millis(6_000),
        "silent only {after:?} after the kill"
    );
    let v = members(&c.addr)?;
    for name in ["edge-a", "edge-b"] {
        assert_eq!(
            row(&v, name).ok_or("a row")?["silent"],
            false,
            "{name} keeps reporting: {v}"
        );
    }
    Ok(())
}

/// A member whose token the center revokes is refused: its count stops,
/// and its heartbeats wait in its spool. Another member is not affected.
#[test]
fn a_revoked_member_token_is_refused() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let revoked = private_file(dir.path(), "revoked", "")?;
    let c = center(
        dir.path(),
        "127.0.0.1:0",
        &["--revoked-file", revoked.to_str().ok_or("utf-8")?],
    )?;
    let r = member(dir.path(), "edge-r", &c.addr)?;
    let k = member(dir.path(), "edge-k", &c.addr)?;
    assert!(
        wait_until(Duration::from_secs(20), || Ok(heartbeats(
            &c.addr, "edge-r"
        )? >= 1
            && heartbeats(&c.addr, "edge-k")? >= 1))?,
        "both report before the revocation"
    );
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(&revoked, "edge-r\n")?;
    std::thread::sleep(Duration::from_millis(1500));
    let frozen = heartbeats(&c.addr, "edge-r")?;
    let kept = heartbeats(&c.addr, "edge-k")?;
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        heartbeats(&c.addr, "edge-r")?,
        frozen,
        "a revoked member is counted no more"
    );
    assert!(
        heartbeats(&c.addr, "edge-k")? > kept,
        "the other member is still counted"
    );
    let waiting = sipnab::app::spool::pending(&r.spool)?;
    assert!(
        !waiting.is_empty(),
        "the refused heartbeats wait in the member's spool"
    );
    drop(k);
    Ok(())
}

/// The center goes away. The members keep capturing and answering, and
/// their heartbeats wait in the spool; when the center returns on the same
/// address and store, the spool drains into it. One of those heartbeats,
/// sent again exactly as the member wrote it, is a duplicate and is not
/// counted twice.
#[test]
fn the_center_down_leaves_capture_alone_the_spool_drains_and_a_replay_counts_once()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let c = center(dir.path(), "127.0.0.1:0", &[])?;
    let addr = c.addr.clone();
    let m = member(dir.path(), "edge-d", &addr)?;
    assert!(
        wait_until(Duration::from_secs(20), || Ok(
            heartbeats(&addr, "edge-d")? >= 1
        ))?,
        "the member reports"
    );
    drop(c);

    // While the center is away: heartbeats pile up, the capture answers.
    assert!(
        wait_until(Duration::from_secs(10), || Ok(sipnab::app::spool::pending(
            &m.spool
        )?
        .len()
            >= 3))?,
        "heartbeats wait in the spool while the center is away"
    );
    let stats = m.srv.get_bearer(
        "/v1/stats",
        &sipnab::auth::mint(
            MEMBER_KEY.as_bytes(),
            "probe",
            chrono::Utc::now().timestamp() + 3600,
            sipnab::auth::AUDIENCE_API,
            sipnab::auth::SCOPE_FULL,
        ),
    )?;
    assert_eq!(stats.status, 200, "the capture answers: {}", stats.body);
    let waiting = sipnab::app::spool::pending(&m.spool)?;
    let first = waiting.first().ok_or("a waiting heartbeat")?.clone();
    let replay = std::fs::read(m.spool.join(&first))?;

    let c = center(dir.path(), &addr, &[])?;
    let before = heartbeats(&c.addr, "edge-d")?;
    assert!(
        wait_until(Duration::from_secs(20), || Ok(!m
            .spool
            .join(&first)
            .exists()
            && heartbeats(&c.addr, "edge-d")? >= before + 3))?,
        "the spool drains into the returned center: {}",
        members(&c.addr)?
    );

    let tok = token("edge-d", sipnab::auth::SCOPE_FLEET_REPORT);
    let counted = heartbeats(&c.addr, "edge-d")?;
    let (status, body) = http(&c.addr, "POST", "/v1/fleet/ingest", &tok, &replay)?;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        (v["accepted"].clone(), v["duplicate"].clone()),
        (0.into(), 1.into()),
        "a heartbeat the member already delivered is a duplicate: {v}"
    );
    assert!(
        heartbeats(&c.addr, "edge-d")? <= counted + 2,
        "the replay added nothing beyond the member's own new heartbeats"
    );
    Ok(())
}

/// A member setting the run cannot use stops it before any capture: exit 2
/// for a flag, exit 1 for a config key, naming the setting.
#[test]
fn a_bad_member_setting_stops_the_run() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let tok = private_file(dir.path(), "m.token", "s2.x.y")?;
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let run = |args: &[&str]| -> Result<(i32, String), TestError> {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "-q", "-I", pcap])
            .args(args)
            .env("NO_COLOR", "1")
            .output()?;
        Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8(out.stderr)?,
        ))
    };
    let spool = dir.path().join("spool");
    let (code, err) = run(&[
        "--config",
        "/dev/null",
        "--fleet-report-url",
        "http://192.0.2.10:8444",
        "--fleet-report-token-file",
        tok.to_str().ok_or("utf-8")?,
        "--fleet-spool-dir",
        spool.to_str().ok_or("utf-8")?,
    ])?;
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("plain HTTP is refused except to loopback"),
        "{err}"
    );
    assert!(!spool.exists(), "refused before the spool was made");
    let cfg = dir.path().join("bad.toml");
    std::fs::write(
        &cfg,
        format!(
            "[fleet]\nreport_url = \"https://192.0.2.10:8444\"\nreport_token_file = {:?}\n\
             spool_dir = {:?}\nheartbeat_secs = 0\n",
            tok.to_str().ok_or("utf-8")?,
            spool.to_str().ok_or("utf-8")?
        ),
    )?;
    let (code, err) = run(&["--config", cfg.to_str().ok_or("utf-8")?])?;
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("[fleet] heartbeat_secs 0"), "{err}");
    Ok(())
}

/// A token file other users can read: the member does not report, says so
/// naming the file and its mode, and the capture run goes on.
#[cfg(unix)]
#[test]
fn a_token_file_others_can_read_stops_the_member_not_the_run() -> Result<(), TestError> {
    use std::io::BufRead as _;
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let tok = private_file(
        dir.path(),
        "open.token",
        &token("edge-o", sipnab::auth::SCOPE_FLEET_REPORT),
    )?;
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644))?;
    let spool = dir.path().join("spool");
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            pcap,
            "--api",
            "127.0.0.1:0",
            "--config",
            "/dev/null",
        ])
        .args(["--api-signing-key", MEMBER_KEY])
        .args([
            "--fleet-report-url",
            "http://127.0.0.1:9",
            "--fleet-report-token-file",
        ])
        .arg(&tok)
        .arg("--fleet-spool-dir")
        .arg(&spool)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let stderr = child.stderr.take().ok_or("piped stderr")?;
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let (mut refused, mut serving) = (None, false);
    while Instant::now() < deadline && !(refused.is_some() && serving) {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if line.contains("fleet member: not reporting") {
                refused = Some(line);
            } else if line.contains("REST API listening on") {
                serving = true;
            }
        }
    }
    let alive = child.try_wait()?.is_none();
    let _ = child.kill();
    let _ = child.wait();
    let line = refused.ok_or("the member did not say it is not reporting")?;
    assert!(
        line.contains("can be read or written by other users (mode 0644)"),
        "{line}"
    );
    assert!(
        serving && alive,
        "the run goes on: serving={serving} alive={alive}"
    );
    assert!(
        sipnab::app::spool::pending(&spool).map_or(true, |p| p.is_empty()),
        "nothing was written to report"
    );
    Ok(())
}

/// A member reports over HTTPS, set by its flags alone: the center's
/// certificate comes from a test CA the host does not trust, and
/// `--fleet-report-ca-file` is what makes the member trust it.
#[test]
fn a_member_reports_over_https_with_its_own_ca() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("fleet-member")?;
    let c = center(
        dir.path(),
        "127.0.0.1:0",
        &["--tls-cert", &pki.cert, "--tls-key", &pki.key],
    )?;
    let tok = private_file(
        dir.path(),
        "edge-s.token",
        &token("edge-s", sipnab::auth::SCOPE_FLEET_REPORT),
    )?;
    let spool = dir.path().join("edge-s.spool");
    let cfg = dir.path().join("edge-s.toml");
    std::fs::write(&cfg, "[fleet]\nheartbeat_secs = 1\n")?;
    let url = format!("https://{}", c.addr);
    let _srv = ApiServer::spawn(&[
        "--api-signing-key",
        MEMBER_KEY,
        "--config",
        cfg.to_str().ok_or("utf-8")?,
        "--fleet-report-url",
        &url,
        "--fleet-report-token-file",
        tok.to_str().ok_or("utf-8")?,
        "--fleet-report-ca-file",
        &pki.ca_file,
        "--fleet-spool-dir",
        spool.to_str().ok_or("utf-8")?,
    ])?;
    let reader = format!("Bearer {}", token("reader", sipnab::auth::SCOPE_INVENTORY));
    let reported = wait_until(Duration::from_secs(20), || {
        let resp = tls_pki::https_exchange(
            &c.addr,
            "GET /v1/fleet/members HTTP/1.1",
            &[("Authorization", &reader)],
            b"",
            &pki.ca,
            Duration::from_secs(10),
        )?;
        let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap_or_default();
        Ok(row(&v, "edge-s")
            .and_then(|r| r["verified"]["heartbeats"].as_u64())
            .is_some_and(|n| n >= 2))
    })?;
    assert!(reported, "the member's heartbeats reach the HTTPS center");
    Ok(())
}

include!("support/child_lifetime.rs");
