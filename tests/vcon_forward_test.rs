// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vCon forwarder (`--vcon-forward`), driven against a fake store.
//!
//! Every test here talks to a store this file runs itself: a
//! `std::net::TcpListener` on `127.0.0.1` that records each request and
//! answers as its script says. No test contacts the internet.
//!
//! Two layers. Most tests drive [`Forwarder`] in-process, one pass at a time,
//! so a test can step the clock and change the spool between passes. The
//! tests at the end run the `sipnab` binary, because exit codes, log lines,
//! SIGTERM and the refusal of a capture flag exist only at that level.
//!
//! The whole file is gated: the forwarder is part of the non-default `vcon`
//! feature.

#![cfg(all(feature = "vcon", unix))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sipnab::app::vcon_forward::{
    AuthHeader, Compat, Endpoint, ForwardSettings, Forwarder, MAX_ERROR_BODY, backoff_delay,
};

#[path = "support/tls_pki.rs"]
mod tls_pki;

/// Any error, boxed, so `?` works on every error type alike.
type TestError = Box<dyn std::error::Error>;

/// The secret every test's auth file carries. Built at run time so no scanner
/// reads a literal credential here.
fn secret() -> String {
    format!("vcs_test_{}", "4f1d9e0c7b3a")
}

/// One request the fake store received.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    /// Every value of header `name`, compared case-insensitively.
    fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// What the fake store does with one request.
enum Reply {
    /// Answer this status with this body.
    Status(u16, String),
    /// Read the request and say nothing, for this long.
    Silence(Duration),
}

/// The script: the request and its 0-based index in, the reply out.
type Script = dyn Fn(&Recorded, usize) -> Reply + Send + Sync;

/// A store on `127.0.0.1` that records every request and answers by script.
struct FakeStore {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
}

impl FakeStore {
    /// Plain HTTP.
    fn start(
        script: impl Fn(&Recorded, usize) -> Reply + Send + Sync + 'static,
    ) -> Result<Self, TestError> {
        Self::start_with(Arc::new(script), None)
    }

    /// HTTPS with this server configuration when `tls` is set.
    fn start_with(
        script: Arc<Script>,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<Self, TestError> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, halt) = (requests.clone(), stop.clone());
        std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        let _ = serve_one(sock, tls.clone(), &log, script.as_ref());
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Ok(Self {
            addr,
            requests,
            stop,
        })
    }

    /// Everything received so far.
    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().clone()
    }

    /// `http://127.0.0.1:<port><path>`.
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for FakeStore {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Read one request from `sock`, record it, and answer it.
fn serve_one(
    sock: TcpStream,
    tls: Option<Arc<rustls::ServerConfig>>,
    log: &Mutex<Vec<Recorded>>,
    script: &Script,
) -> Result<(), TestError> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    match tls {
        Some(cfg) => {
            let conn = rustls::ServerConnection::new(cfg)?;
            let mut stream = rustls::StreamOwned::new(conn, sock);
            exchange(&mut stream, log, script)
        }
        None => {
            let mut stream = sock;
            exchange(&mut stream, log, script)
        }
    }
}

/// The HTTP half of [`serve_one`], over either stream.
fn exchange(
    stream: &mut (impl Read + Write),
    log: &Mutex<Vec<Recorded>>,
    script: &Script,
) -> Result<(), TestError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let target = first.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    let len = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    let req = Recorded {
        method,
        target,
        headers,
        body,
    };
    let index = {
        let mut held = log.lock();
        held.push(req.clone());
        held.len() - 1
    };
    match script(&req, index) {
        Reply::Status(code, text) => {
            let answer = format!(
                "HTTP/1.1 {code} Scripted\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            stream.write_all(answer.as_bytes())?;
            stream.flush()?;
        }
        Reply::Silence(d) => std::thread::sleep(d),
    }
    Ok(())
}

/// A synthetic container in sipnab's shape: two parties, an observer, and
/// the given dialog objects. Not a capture of anyone's call.
fn container(uuid: &str, dialog: &str) -> String {
    format!(
        r#"{{"vcon":"0.4.0","uuid":"{uuid}","created_at":"2026-10-07T12:00:00+00:00","extensions":["sip-signaling","CC"],"parties":[{{"tel":"+15550100001","validation":"none"}},{{"tel":"+15550100002","validation":"none"}},{{"validation":"none","role":"observer"}}],"dialog":[{dialog}],"attachments":[],"analysis":[]}}"#
    )
}

/// A recording Dialog Object, the kind `--retain-audio` makes sipnab write.
const RECORDING: &str = r#"{"type":"recording","parties":[0,1],"start":"2026-10-07T12:00:00+00:00","mediatype":"audio/x-wav","encoding":"base64url","body":"UklGRg"}"#;

/// The Dialog Object sipnab writes when the run kept no audio.
const NO_CONTENT: &str = r#"{"sip_call_id":"synthetic-1@192.0.2.1"}"#;

/// A spool with an auth file beside it, and the settings that forward it.
struct Rig {
    dir: tempfile::TempDir,
    settings: ForwardSettings,
}

impl Rig {
    /// A rig whose auth file holds `header_name: <secret>`.
    fn new(url: &str, header_name: &str) -> Result<Self, TestError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let spool = dir.path().join("spool");
        std::fs::create_dir(&spool)?;
        let auth_file = dir.path().join("auth");
        std::fs::write(&auth_file, format!("{header_name}: {}\n", secret()))?;
        std::fs::set_permissions(&auth_file, std::fs::Permissions::from_mode(0o600))?;
        let settings = ForwardSettings {
            done_dir: spool.join("delivered"),
            failed_dir: spool.join("failed"),
            spool,
            url: Endpoint::parse(url)?,
            replace_url: None,
            auth: AuthHeader::read_file(&auth_file)?,
            timeout: Duration::from_secs(5),
            compat: Compat::Off,
            ca: None,
        };
        Ok(Self { dir, settings })
    }

    fn spool(&self) -> &Path {
        &self.settings.spool
    }

    fn auth_file(&self) -> PathBuf {
        self.dir.path().join("auth")
    }

    /// Put a container in the spool the way sipnab does: stage, rename.
    fn drop_in(&self, name: &str, bytes: &str) -> Result<(), TestError> {
        let staged = self.spool().join(format!(".{name}.partial"));
        std::fs::write(&staged, bytes)?;
        std::fs::rename(&staged, self.spool().join(name))?;
        Ok(())
    }

    fn forwarder(&self) -> Result<Forwarder, TestError> {
        Ok(Forwarder::new(self.settings.clone())?)
    }
}

/// A stop check that never asks the forwarder to stop.
fn never() -> bool {
    false
}

// ── Delivery ────────────────────────────────────────────────────────────

/// A 201 delivers: the body is the file's bytes exactly, typed as JSON,
/// carrying sipnab's User-Agent and the one auth header from the file, and the
/// container moves to the delivered directory under its own name.
#[test]
fn a_container_is_posted_byte_for_byte_with_one_auth_header() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, "{}".into()))?;
    let rig = Rig::new(
        &store.url("/vcon/external-ingress?ingress_list=sipnab"),
        "x-conserver-api-token",
    )?;
    let bytes = container("018bcfe5-6800-8a6b-a667-78f1c5213800", RECORDING);
    rig.drop_in("call-1-0123456789abcdef.vcon.json", &bytes)?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);

    let seen = store.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let req = &seen[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.target, "/vcon/external-ingress?ingress_list=sipnab");
    assert_eq!(req.body, bytes.as_bytes(), "the container was rewritten");
    assert_eq!(req.header("content-type"), ["application/json"]);
    assert_eq!(
        req.header("user-agent"),
        [format!("sipnab/{}", env!("CARGO_PKG_VERSION")).as_str()]
    );
    assert_eq!(req.header("x-conserver-api-token"), [secret().as_str()]);
    assert!(req.header("authorization").is_empty());
    assert_eq!(report.delivered, ["call-1-0123456789abcdef.vcon.json"]);
    let moved = rig
        .settings
        .done_dir
        .join("call-1-0123456789abcdef.vcon.json");
    assert_eq!(std::fs::read_to_string(moved)?, bytes);
    assert!(
        !rig.spool()
            .join("call-1-0123456789abcdef.vcon.json")
            .exists()
    );
    Ok(())
}

/// A 204 delivers too, and an `Authorization: Bearer` file is sent as that
/// header.
#[test]
fn a_204_delivers_and_a_bearer_header_is_sent_as_written() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(204, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    let bytes = container("018bcfe5-6800-8a6b-a667-78f1c5213801", RECORDING);
    rig.drop_in("b.vcon.json", &bytes)?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    let seen = store.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("authorization"), [secret().as_str()]);
    assert_eq!(report.delivered, ["b.vcon.json"]);
    Ok(())
}

/// A dot-prefixed staging file and a name that does not end in `.json` are
/// never sent, and stay where they are.
#[test]
fn staging_files_and_other_names_are_never_sent() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    let bytes = container("018bcfe5-6800-8a6b-a667-78f1c5213802", RECORDING);
    std::fs::write(rig.spool().join(".x.vcon.json.partial"), &bytes)?;
    std::fs::write(rig.spool().join(".hidden.vcon.json"), &bytes)?;
    std::fs::write(rig.spool().join("notes.txt"), "not a container")?;
    std::fs::write(rig.spool().join("SHA256SUMS"), "")?;
    rig.drop_in("c.vcon.json", &bytes)?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);

    assert_eq!(store.requests().len(), 1);
    assert_eq!(report.delivered, ["c.vcon.json"]);
    for left in [
        ".x.vcon.json.partial",
        ".hidden.vcon.json",
        "notes.txt",
        "SHA256SUMS",
    ] {
        assert!(rig.spool().join(left).exists(), "{left} was moved");
    }
    Ok(())
}

// ── Retry ───────────────────────────────────────────────────────────────

/// A 5xx keeps the container in the spool and backs it off, and the next
/// container is still delivered in the same pass. The retry waits for its
/// delay, and then goes out again.
#[test]
fn a_5xx_keeps_the_file_backs_off_and_does_not_wedge_the_next() -> Result<(), TestError> {
    let store = FakeStore::start(|req, _| {
        if String::from_utf8_lossy(&req.body).contains("5555") {
            Reply::Status(503, "busy".into())
        } else {
            Reply::Status(201, String::new())
        }
    })?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("a.vcon.json", &container("5555", RECORDING))?;
    rig.drop_in("b.vcon.json", &container("018bcfe5-1", RECORDING))?;
    let mut fwd = rig.forwarder()?;
    let t0 = Instant::now();

    let first = fwd.pass(t0, &never);
    assert_eq!(first.delivered, ["b.vcon.json"]);
    assert_eq!(first.waiting, ["a.vcon.json"]);
    assert!(rig.spool().join("a.vcon.json").exists());
    assert_eq!(store.requests().len(), 2);

    let early = fwd.pass(t0 + backoff_delay(1) / 2, &never);
    assert_eq!(store.requests().len(), 2, "retried before its delay");
    assert_eq!(early.waiting, ["a.vcon.json"]);

    fwd.pass(t0 + backoff_delay(1) + Duration::from_millis(1), &never);
    assert_eq!(store.requests().len(), 3, "not retried after its delay");
    Ok(())
}

/// A store nobody listens on keeps the container for a later pass.
#[test]
fn an_unreachable_store_keeps_the_file() -> Result<(), TestError> {
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let rig = Rig::new(
        &format!("http://127.0.0.1:{port}/v1/vcons"),
        "Authorization",
    )?;
    rig.drop_in("d.vcon.json", &container("018bcfe5-2", RECORDING))?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert_eq!(report.waiting, ["d.vcon.json"]);
    assert!(report.delivered.is_empty() && report.refused.is_empty());
    assert!(rig.spool().join("d.vcon.json").exists());
    Ok(())
}

/// A store that accepts the request and never answers is given up on after
/// the timeout, and the container stays for a later pass.
#[test]
fn a_store_that_never_answers_times_out_and_keeps_the_file() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Silence(Duration::from_secs(8)))?;
    let mut rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.settings.timeout = Duration::from_millis(500);
    rig.drop_in("e.vcon.json", &container("018bcfe5-3", RECORDING))?;
    let started = Instant::now();
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(report.waiting, ["e.vcon.json"]);
    assert!(rig.spool().join("e.vcon.json").exists());
    Ok(())
}

// ── Refusal ─────────────────────────────────────────────────────────────

/// A 4xx moves the container to the failed directory beside a record of the
/// status and the store's answer. The answer is bounded, and the auth value
/// is removed from it even when the store echoes the request's headers.
#[test]
fn a_4xx_moves_to_failed_with_a_bounded_record_and_no_secret() -> Result<(), TestError> {
    let store = FakeStore::start(|req, _| {
        let echoed: String = req
            .headers
            .iter()
            .map(|(n, v)| format!("{n}: {v}\n"))
            .collect();
        Reply::Status(400, format!("bad vCon\n{echoed}{}", "x".repeat(20_000)))
    })?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("f.vcon.json", &container("018bcfe5-4", RECORDING))?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);

    assert_eq!(report.refused, ["f.vcon.json"]);
    assert!(rig.settings.failed_dir.join("f.vcon.json").exists());
    assert!(!rig.spool().join("f.vcon.json").exists());
    let record_text =
        std::fs::read_to_string(rig.settings.failed_dir.join("f.vcon.json.error.json"))?;
    assert!(!record_text.contains(&secret()), "{record_text}");
    let record: serde_json::Value = serde_json::from_str(&record_text)?;
    assert_eq!(record["status"], 400);
    let body = record["body"].as_str().ok_or("no body")?;
    assert!(body.starts_with("bad vCon"), "{body}");
    assert!(body.len() <= MAX_ERROR_BODY, "{} bytes", body.len());
    assert_eq!(record["body_truncated"], true);
    Ok(())
}

/// Files in a directory, by name, sorted; empty when it does not exist.
fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A 401 says the credentials are refused, for every container alike. The
/// pass stops at the first one: nothing more is sent, nothing moves to the
/// failed directory, every container stays in the spool, and the report says
/// why, naming the status.
#[test]
fn a_401_stops_the_pass_and_leaves_every_file() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(401, "bad token".into()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    for name in ["a.vcon.json", "b.vcon.json", "c.vcon.json"] {
        rig.drop_in(name, &container("018bcfe5-40", RECORDING))?;
    }
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert_eq!(store.requests().len(), 1, "sent after a 401");
    let why = report.halted.clone().ok_or("the pass did not stop")?;
    assert!(why.contains("401") && why.contains("bad token"), "{why}");
    assert!(
        report.refused.is_empty() && report.delivered.is_empty(),
        "{report:?}"
    );
    assert_eq!(
        report.waiting,
        ["a.vcon.json", "b.vcon.json", "c.vcon.json"]
    );
    assert_eq!(
        names_in(rig.spool()),
        [
            "a.vcon.json",
            "b.vcon.json",
            "c.vcon.json",
            "delivered",
            "failed"
        ]
    );
    assert!(names_in(&rig.settings.failed_dir).is_empty());
    Ok(())
}

/// A CDN front's 403 (`error code: 1010`, a client it refuses) stops the pass
/// the same way, and its body is in the reason, so the case is recognizable.
#[test]
fn a_403_from_a_cdn_front_stops_and_names_its_body() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(403, "error code: 1010".into()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("g.vcon.json", &container("018bcfe5-5", RECORDING))?;
    rig.drop_in("h.vcon.json", &container("018bcfe5-6", RECORDING))?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    let why = report.halted.clone().ok_or("the pass did not stop")?;
    assert!(
        why.contains("403") && why.contains("error code: 1010"),
        "{why}"
    );
    assert_eq!(store.requests().len(), 1);
    assert!(names_in(&rig.settings.failed_dir).is_empty());
    assert!(rig.spool().join("g.vcon.json").exists() && rig.spool().join("h.vcon.json").exists());
    Ok(())
}

/// A 403 to the replace PUT stops the pass too: the credential is refused
/// whichever request drew it.
#[test]
fn a_403_to_the_replace_put_stops_the_pass() -> Result<(), TestError> {
    let store = FakeStore::start(|req, _| {
        if req.method == "POST" {
            Reply::Status(409, "exists".into())
        } else {
            Reply::Status(403, "forbidden".into())
        }
    })?;
    let mut rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.settings.replace_url = Some(store.url("/v1/vcons/{uuid}"));
    rig.drop_in("p.vcon.json", &container("018bcfe5-41", RECORDING))?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    let why = report.halted.clone().ok_or("the pass did not stop")?;
    assert!(why.contains("PUT") && why.contains("403"), "{why}");
    assert!(rig.spool().join("p.vcon.json").exists());
    assert!(names_in(&rig.settings.failed_dir).is_empty());
    Ok(())
}

/// The reason a pass stopped never carries the auth value, even when the
/// store echoes the request back in its 401.
#[test]
fn the_stop_reason_never_carries_the_secret() -> Result<(), TestError> {
    let store = FakeStore::start(|req, _| {
        Reply::Status(
            401,
            format!("rejected: {}", req.header("authorization").join(",")),
        )
    })?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("s.vcon.json", &container("018bcfe5-42", RECORDING))?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    let why = report.halted.clone().ok_or("the pass did not stop")?;
    assert!(!why.contains(&secret()), "{why}");
    assert!(why.contains("[auth value removed]"), "{why}");
    Ok(())
}

// ── Rewritten containers ────────────────────────────────────────────────

/// sipnab rewrites a container under the same name when the call changes.
/// One rewritten after delivery is sent again, and the delivered copy becomes
/// the new one.
#[test]
fn a_container_rewritten_after_delivery_is_sent_again() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    let mut fwd = rig.forwarder()?;
    let first = container("018bcfe5-6", NO_CONTENT);
    let second = container("018bcfe5-6", RECORDING);
    rig.drop_in("h.vcon.json", &first)?;
    fwd.pass(Instant::now(), &never);
    rig.drop_in("h.vcon.json", &second)?;
    let report = fwd.pass(Instant::now(), &never);

    let seen = store.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].body, second.as_bytes());
    assert_eq!(report.delivered, ["h.vcon.json"]);
    assert_eq!(
        std::fs::read_to_string(rig.settings.done_dir.join("h.vcon.json"))?,
        second
    );
    Ok(())
}

/// A container rewritten while its send is in flight stays in the spool,
/// because the store has the old one, and the next pass sends the new one.
#[test]
fn a_container_rewritten_during_its_send_stays_and_goes_again() -> Result<(), TestError> {
    let rig_cell: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let spool_for_store = rig_cell.clone();
    let newer = container("018bcfe5-7", RECORDING);
    let newer_for_store = newer.clone();
    let store = FakeStore::start(move |_, n| {
        if n == 0
            && let Some(spool) = spool_for_store.lock().clone()
        {
            let staged = spool.join(".i.vcon.json.partial");
            let _ = std::fs::write(&staged, &newer_for_store);
            let _ = std::fs::rename(&staged, spool.join("i.vcon.json"));
        }
        Reply::Status(201, String::new())
    })?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    *rig_cell.lock() = Some(rig.spool().to_path_buf());
    rig.drop_in("i.vcon.json", &container("018bcfe5-7", NO_CONTENT))?;
    let mut fwd = rig.forwarder()?;

    let first = fwd.pass(Instant::now(), &never);
    assert!(first.delivered.is_empty(), "{first:?}");
    assert_eq!(first.waiting, ["i.vcon.json"]);
    assert_eq!(
        std::fs::read_to_string(rig.spool().join("i.vcon.json"))?,
        newer
    );

    let second = fwd.pass(Instant::now(), &never);
    assert_eq!(second.delivered, ["i.vcon.json"]);
    assert_eq!(store.requests()[1].body, newer.as_bytes());
    Ok(())
}

/// A 409 says the store already holds the uuid. With a replace URL the
/// forwarder PUTs the container to it, uuid filled in from the container.
#[test]
fn a_409_with_a_replace_url_is_put_to_the_uuid() -> Result<(), TestError> {
    let store = FakeStore::start(|req, _| {
        if req.method == "POST" {
            Reply::Status(409, "exists".into())
        } else {
            Reply::Status(200, "{}".into())
        }
    })?;
    let mut rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.settings.replace_url = Some(store.url("/v1/vcons/{uuid}"));
    let bytes = container("018bcfe5-6800-8a6b-a667-78f1c5213809", RECORDING);
    rig.drop_in("j.vcon.json", &bytes)?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);

    let seen = store.requests();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[1].method, "PUT");
    assert_eq!(
        seen[1].target,
        "/v1/vcons/018bcfe5-6800-8a6b-a667-78f1c5213809"
    );
    assert_eq!(seen[1].body, bytes.as_bytes());
    assert_eq!(seen[1].header("authorization"), [secret().as_str()]);
    assert_eq!(report.delivered, ["j.vcon.json"]);
    Ok(())
}

/// Without a replace URL, a 409 is a refusal like any other 4xx.
#[test]
fn a_409_without_a_replace_url_is_a_refusal() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(409, "exists".into()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("k.vcon.json", &container("018bcfe5-8", RECORDING))?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert_eq!(store.requests().len(), 1);
    assert_eq!(report.refused, ["k.vcon.json"]);
    Ok(())
}

// ── vcon.store compatibility ────────────────────────────────────────────

/// In `vcon-store` mode the copy sent carries `extensions` as an object, each
/// name mapped to `true` in the original order, and nothing else changes. The
/// file in the spool, and the delivered copy, keep the String[] form.
#[test]
fn vcon_store_mode_sends_extensions_as_an_object_and_keeps_the_file() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, "{}".into()))?;
    let mut rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.settings.compat = Compat::VconStore;
    let bytes = container("018bcfe5-6800-8a6b-a667-78f1c5213810", RECORDING);
    rig.drop_in("l.vcon.json", &bytes)?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);

    let seen = store.requests();
    assert_eq!(seen.len(), 1);
    let expected = bytes.replace(
        r#""extensions":["sip-signaling","CC"]"#,
        r#""extensions":{"sip-signaling":true,"CC":true}"#,
    );
    assert_ne!(expected, bytes, "the fixture carries no extensions");
    assert_eq!(String::from_utf8_lossy(&seen[0].body), expected);
    assert_eq!(report.delivered, ["l.vcon.json"]);
    assert_eq!(
        std::fs::read_to_string(rig.settings.done_dir.join("l.vcon.json"))?,
        bytes,
        "the container on disk was changed"
    );
    Ok(())
}

/// In `vcon-store` mode a Dialog Object with no `type` and no `parties` is
/// not rewritten and not sent: the container goes to the failed directory
/// with a reason that names what the store requires and how to get a dialog
/// it accepts.
#[test]
fn vcon_store_mode_refuses_a_dialog_without_type_and_parties() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let mut rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.settings.compat = Compat::VconStore;
    let bytes = container("018bcfe5-9", NO_CONTENT);
    rig.drop_in("m.vcon.json", &bytes)?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);

    assert!(store.requests().is_empty(), "the container was sent");
    assert_eq!(report.refused, ["m.vcon.json"]);
    assert_eq!(
        std::fs::read_to_string(rig.settings.failed_dir.join("m.vcon.json"))?,
        bytes
    );
    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(
        rig.settings.failed_dir.join("m.vcon.json.error.json"),
    )?)?;
    let reason = record["reason"].as_str().ok_or("no reason")?;
    // `--redact` too: a redacted export withholds the audio, so it is the
    // other way a container reaches the store with no typed dialog.
    for needle in [
        "`type`",
        "`parties`",
        "--retain-audio",
        "--redact",
        "recording",
    ] {
        assert!(reason.contains(needle), "{needle} missing from: {reason}");
    }
    assert!(record["status"].is_null());
    Ok(())
}

/// The same container is sent unchanged, empty dialog and all, when no compat
/// mode is set: the adjustment is opt-in.
#[test]
fn without_a_compat_mode_nothing_is_adjusted_or_refused() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    let bytes = container("018bcfe5-10", NO_CONTENT);
    rig.drop_in("n.vcon.json", &bytes)?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert_eq!(store.requests()[0].body, bytes.as_bytes());
    assert_eq!(report.delivered, ["n.vcon.json"]);
    Ok(())
}

// ── Stopping, HTTPS, the auth file ──────────────────────────────────────

/// Asked to stop, a pass sends nothing more and leaves the spool alone.
#[test]
fn a_stop_request_sends_nothing() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("o.vcon.json", &container("018bcfe5-11", RECORDING))?;
    let report = rig.forwarder()?.pass(Instant::now(), &|| true);
    assert!(store.requests().is_empty());
    assert!(report.stopped);
    assert!(rig.spool().join("o.vcon.json").exists());
    Ok(())
}

/// An HTTPS store whose certificate chains to `--vcon-forward-ca` is
/// delivered to; the same store with no CA named is not trusted, and the
/// container waits.
#[test]
fn https_delivers_to_a_store_the_named_ca_vouches_for() -> Result<(), TestError> {
    use rustls::pki_types::pem::PemObject;
    let pki = tls_pki::test_pki("vcon-forward")?;
    let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let store = FakeStore::start_with(
        Arc::new(|_: &Recorded, _| Reply::Status(201, String::new())),
        Some(Arc::new(server)),
    )?;
    let url = format!("https://{}/v1/vcons", store.addr);

    let mut untrusted = Rig::new(&url, "Authorization")?;
    untrusted.settings.ca = None;
    untrusted.drop_in("p.vcon.json", &container("018bcfe5-12", RECORDING))?;
    let report = match untrusted.forwarder() {
        Ok(mut fwd) => fwd.pass(Instant::now(), &never),
        // A host with no CA bundle refuses at startup, which is also "not
        // trusted".
        Err(_) => Default::default(),
    };
    assert!(report.delivered.is_empty(), "{report:?}");

    let mut rig = Rig::new(&url, "Authorization")?;
    rig.settings.ca = Some(PathBuf::from(&pki.ca_file));
    let bytes = container("018bcfe5-13", RECORDING);
    rig.drop_in("q.vcon.json", &bytes)?;
    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["q.vcon.json"]);
    let seen = store.requests();
    assert_eq!(
        seen.last().map(|r| r.body.clone()),
        Some(bytes.into_bytes())
    );
    Ok(())
}

/// The auth file is refused when other users can read it, by the rule every
/// sipnab secret file follows, and the refusal never quotes the value.
#[test]
fn a_group_readable_auth_file_is_refused_without_quoting_it() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let rig = Rig::new("http://127.0.0.1:9/v1/vcons", "Authorization")?;
    std::fs::set_permissions(rig.auth_file(), std::fs::Permissions::from_mode(0o640))?;
    match AuthHeader::read_file(&rig.auth_file()) {
        Ok(h) => Err(format!("accepted: {}", h.name()).into()),
        Err(e) => {
            assert!(e.contains("mode 0640") && e.contains("chmod 600"), "{e}");
            assert!(!e.contains(&secret()), "{e}");
            Ok(())
        }
    }
}

/// A delivered or failed directory that is the spool itself is refused: a
/// container moved "out" would stay in the queue and go again forever.
#[test]
fn a_destination_that_is_the_spool_is_refused() -> Result<(), TestError> {
    let mut rig = Rig::new("http://127.0.0.1:9/v1/vcons", "Authorization")?;
    rig.settings.done_dir = rig.spool().to_path_buf();
    match Forwarder::new(rig.settings.clone()) {
        Ok(_) => Err("the spool was accepted as the delivered directory".into()),
        Err(e) => {
            assert!(
                e.contains("--vcon-forward-done") && e.contains("spool itself"),
                "{e}"
            );
            Ok(())
        }
    }
}

/// A destination on another filesystem is refused, because moving a
/// container there is a copy, not a rename. Checked where this host has a
/// second filesystem (`/dev/shm`) to put one on.
#[test]
fn a_destination_on_another_filesystem_is_refused() -> Result<(), TestError> {
    use std::os::unix::fs::MetadataExt;
    let mut rig = Rig::new("http://127.0.0.1:9/v1/vcons", "Authorization")?;
    let shm = Path::new("/dev/shm");
    if !shm.is_dir() || std::fs::metadata(shm)?.dev() == std::fs::metadata(rig.spool())?.dev() {
        return Ok(());
    }
    let elsewhere = tempfile::tempdir_in(shm)?;
    rig.settings.failed_dir = elsewhere.path().join("failed");
    match Forwarder::new(rig.settings.clone()) {
        Ok(_) => Err("a failed directory on another filesystem was accepted".into()),
        Err(e) => {
            assert!(e.contains("another filesystem"), "{e}");
            Ok(())
        }
    }
}

/// A replace URL with no `{uuid}` would PUT every container to one place,
/// so it is refused at startup.
#[test]
fn a_replace_url_without_a_uuid_is_refused() -> Result<(), TestError> {
    let mut rig = Rig::new("http://127.0.0.1:9/v1/vcons", "Authorization")?;
    rig.settings.replace_url = Some("http://127.0.0.1:9/v1/vcons/fixed".into());
    match Forwarder::new(rig.settings.clone()) {
        Ok(_) => Err("a replace URL with no {uuid} was accepted".into()),
        Err(e) => {
            assert!(e.contains("{uuid}"), "{e}");
            Ok(())
        }
    }
}

// ── The binary ──────────────────────────────────────────────────────────

/// Run `sipnab` with `args` at trace level, returning (stdout, stderr, code).
fn sipnab(args: &[&str]) -> Result<(String, String, Option<i32>), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", "trace")
        .env("NO_COLOR", "1")
        .output()?;
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    ))
}

/// The forwarder flags for `rig` and `url`, as owned strings.
fn forward_args(rig: &Rig, url: &str) -> Vec<String> {
    vec![
        "--vcon-forward".into(),
        rig.spool().display().to_string(),
        "--vcon-forward-url".into(),
        url.into(),
        "--vcon-forward-auth-file".into(),
        rig.auth_file().display().to_string(),
        "--vcon-forward-once".into(),
    ]
}

/// `--vcon-forward-once` exits 0 when everything was delivered and 1 when a
/// container was refused, logs one line naming the refused file and its
/// status, and the auth value appears nowhere: not in stdout, not in stderr at
/// trace level, not in the failure record.
#[test]
fn once_exits_by_outcome_and_never_prints_the_secret() -> Result<(), TestError> {
    let store = FakeStore::start(|req, _| {
        if String::from_utf8_lossy(&req.body).contains("refuse-me") {
            Reply::Status(
                422,
                format!("no: {}", req.header("authorization").join(",")),
            )
        } else {
            Reply::Status(201, String::new())
        }
    })?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("good.vcon.json", &container("018bcfe5-20", RECORDING))?;
    let args = forward_args(&rig, &store.url("/v1/vcons"));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();

    let (out, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(0), "stdout: {out}\nstderr: {err}");

    rig.drop_in("bad.vcon.json", &container("refuse-me", RECORDING))?;
    let (out2, err2, code2) = sipnab(&argv)?;
    assert_eq!(code2, Some(1), "stdout: {out2}\nstderr: {err2}");
    assert!(
        err2.lines()
            .any(|l| l.contains("bad.vcon.json") && l.contains("422")),
        "{err2}"
    );
    let record = std::fs::read_to_string(rig.settings.failed_dir.join("bad.vcon.json.error.json"))?;
    for text in [&out, &err, &out2, &err2, &record] {
        assert!(!text.contains(&secret()), "the secret leaked: {text}");
    }
    Ok(())
}

/// `--once` against a store that refuses the client (a CDN's 403
/// `error code: 1010`) exits 3, moves nothing, sends one request, and logs one
/// error line naming the status and the start of the body.
#[test]
fn once_exits_3_when_the_store_refuses_the_client() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(403, "error code: 1010".into()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("u.vcon.json", &container("018bcfe5-43", RECORDING))?;
    rig.drop_in("v.vcon.json", &container("018bcfe5-44", RECORDING))?;
    let args = forward_args(&rig, &store.url("/v1/vcons"));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (out, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(3), "{err}");
    let lines: Vec<&str> = err
        .lines()
        .filter(|l| l.contains("403") && l.contains("error code: 1010"))
        .collect();
    assert_eq!(lines.len(), 1, "{err}");
    assert!(lines[0].contains("ERROR"), "{err}");
    assert_eq!(store.requests().len(), 1);
    assert!(rig.spool().join("u.vcon.json").exists() && rig.spool().join("v.vcon.json").exists());
    assert!(names_in(&rig.settings.failed_dir).is_empty());
    assert!(!out.contains(&secret()) && !err.contains(&secret()));
    Ok(())
}

/// A polling forwarder whose credentials draw a 401 exits 3 on its own, with
/// no signal, rather than retrying a refused credential forever.
#[test]
fn polling_exits_3_when_the_store_refuses_the_credentials() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(401, "bad token".into()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("w.vcon.json", &container("018bcfe5-45", RECORDING))?;
    let mut args = forward_args(&rig, &store.url("/v1/vcons"));
    args.retain(|a| a != "--vcon-forward-once");
    args.extend(["--vcon-forward-interval".into(), "1".into()]);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(15) {
            child.kill()?;
            return Err("the forwarder kept polling after a 401".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(3));
    assert_eq!(store.requests().len(), 1);
    assert!(rig.spool().join("w.vcon.json").exists());
    Ok(())
}

/// A container still waiting (the store answered 500) makes `--once` exit 1.
#[test]
fn once_exits_1_while_a_container_waits() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(500, "down".into()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("w.vcon.json", &container("018bcfe5-21", RECORDING))?;
    let args = forward_args(&rig, &store.url("/v1/vcons"));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (_, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(1), "{err}");
    assert!(rig.spool().join("w.vcon.json").exists());
    Ok(())
}

/// Every compat change is logged, one line per container naming the
/// transform, and a refused container's line says why.
#[test]
fn vcon_store_mode_logs_every_change() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("r.vcon.json", &container("018bcfe5-22", RECORDING))?;
    rig.drop_in("s.vcon.json", &container("018bcfe5-23", NO_CONTENT))?;
    let mut args = forward_args(&rig, &store.url("/v1/vcons"));
    args.extend(["--vcon-forward-compat".into(), "vcon-store".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (_, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(1), "{err}");
    let changed: Vec<&str> = err
        .lines()
        .filter(|l| l.contains("r.vcon.json") && l.contains("extensions"))
        .collect();
    assert_eq!(changed.len(), 1, "{err}");
    assert!(
        err.lines()
            .any(|l| l.contains("s.vcon.json") && l.contains("parties")),
        "{err}"
    );
    Ok(())
}

/// A real spool: sipnab exports the committed synthetic capture, and the
/// forwarder delivers what it wrote, byte for byte.
#[test]
fn a_spool_sipnab_wrote_is_delivered_byte_for_byte() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    let spool = rig.spool().display().to_string();
    let fixture = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let (_, err, code) = sipnab(&[
        "-N",
        "-q",
        "-I",
        &fixture,
        "--export-vcon-when",
        "state == 'Completed'",
        "--export-vcon-dir",
        &spool,
    ])?;
    assert_eq!(code, Some(0), "{err}");
    let names = sipnab::app::vcon_forward::pending(rig.spool())?;
    assert_eq!(names.len(), 1, "{names:?}");
    let bytes = std::fs::read(rig.spool().join(&names[0]))?;

    let report = rig.forwarder()?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, names);
    assert_eq!(store.requests()[0].body, bytes);
    Ok(())
}

/// The binary honors `--vcon-forward-done`, `--vcon-forward-failed`,
/// `--vcon-forward-ca` and `--vcon-forward-timeout`: over HTTPS to a store the
/// named CA vouches for, the delivered container lands in the named done
/// directory and the refused one in the named failed directory.
#[test]
fn the_binary_honors_the_directory_ca_and_timeout_flags() -> Result<(), TestError> {
    use rustls::pki_types::pem::PemObject;
    let pki = tls_pki::test_pki("vcon-forward-bin")?;
    let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let store = FakeStore::start_with(
        Arc::new(|req: &Recorded, _| {
            if String::from_utf8_lossy(&req.body).contains("refuse-me") {
                Reply::Status(400, "no".into())
            } else {
                Reply::Status(201, String::new())
            }
        }),
        Some(Arc::new(server)),
    )?;
    let url = format!("https://{}/v1/vcons", store.addr);
    let rig = Rig::new(&url, "Authorization")?;
    rig.drop_in("ok.vcon.json", &container("018bcfe5-30", RECORDING))?;
    rig.drop_in("no.vcon.json", &container("refuse-me", RECORDING))?;
    let sent = rig.dir.path().join("sent");
    let held = rig.dir.path().join("held");
    let mut args = forward_args(&rig, &url);
    args.extend([
        "--vcon-forward-done".into(),
        sent.display().to_string(),
        "--vcon-forward-failed".into(),
        held.display().to_string(),
        "--vcon-forward-ca".into(),
        pki.ca_file.clone(),
        "--vcon-forward-timeout".into(),
        "5".into(),
    ]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (_, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(1), "{err}");
    assert!(sent.join("ok.vcon.json").exists(), "{err}");
    assert!(held.join("no.vcon.json").exists(), "{err}");
    assert!(held.join("no.vcon.json.error.json").exists(), "{err}");
    assert!(
        !rig.settings.done_dir.exists(),
        "the default delivered directory was used"
    );
    Ok(())
}

/// `--vcon-forward-timeout` bounds the wait on a store that accepts the
/// connection and never answers: with 1 s the run ends in a few seconds, not
/// the default 30, and the container waits for the next run.
#[test]
fn the_binary_gives_up_on_a_silent_store_after_its_timeout() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Silence(Duration::from_secs(40)))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    rig.drop_in("x.vcon.json", &container("018bcfe5-31", RECORDING))?;
    let mut args = forward_args(&rig, &store.url("/v1/vcons"));
    args.extend(["--vcon-forward-timeout".into(), "1".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let started = Instant::now();
    let (_, err, code) = sipnab(&argv)?;
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "took {:?}: {err}",
        started.elapsed()
    );
    assert_eq!(code, Some(1), "{err}");
    assert!(rig.spool().join("x.vcon.json").exists());
    Ok(())
}

/// SIGTERM stops a polling forwarder promptly, with exit 0, even in the middle
/// of a 60-second wait between passes, and nothing put in the spool
/// afterwards is sent.
#[test]
fn sigterm_stops_the_forwarder_without_sending_more() -> Result<(), TestError> {
    let store = FakeStore::start(|_, _| Reply::Status(201, String::new()))?;
    let rig = Rig::new(&store.url("/v1/vcons"), "Authorization")?;
    let mut args = forward_args(&rig, &store.url("/v1/vcons"));
    args.retain(|a| a != "--vcon-forward-once");
    // A long interval, so the forwarder is asleep between passes when the
    // signal lands: stopping promptly means waking for it, not finishing the
    // nap.
    args.extend(["--vcon-forward-interval".into(), "60".into()]);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;
    // Wait for the forwarder to say it is watching the spool.
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(20);
    while !String::from_utf8_lossy(&seen).contains("watching") && Instant::now() < deadline {
        if stderr.read(&mut byte)? == 0 {
            break;
        }
        seen.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&seen).contains("watching"),
        "{}",
        String::from_utf8_lossy(&seen)
    );
    let sent = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()?;
    assert!(sent.success(), "kill -TERM failed: {sent}");
    let stopped_at = Instant::now();
    rig.drop_in("t.vcon.json", &container("018bcfe5-24", RECORDING))?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if stopped_at.elapsed() > Duration::from_secs(5) {
            child.kill()?;
            return Err("the forwarder did not stop within 5 s of SIGTERM".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut rest = String::new();
    stderr.read_to_string(&mut rest)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    std::thread::sleep(Duration::from_millis(1500));
    assert!(store.requests().is_empty(), "sent after SIGTERM");
    assert!(rig.spool().join("t.vcon.json").exists());
    Ok(())
}

/// At startup the binary refuses a group-readable auth file with exit 2, and
/// never prints the value.
#[test]
fn the_binary_refuses_a_group_readable_auth_file() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let rig = Rig::new("http://127.0.0.1:9/v1/vcons", "Authorization")?;
    std::fs::set_permissions(rig.auth_file(), std::fs::Permissions::from_mode(0o644))?;
    let args = forward_args(&rig, "http://127.0.0.1:9/v1/vcons");
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (out, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("chmod 600"), "{err}");
    assert!(!out.contains(&secret()) && !err.contains(&secret()));
    Ok(())
}

/// The binary refuses a forwarder that names a capture source, before it
/// opens anything.
#[test]
fn the_binary_refuses_a_forwarder_with_a_capture_flag() -> Result<(), TestError> {
    let rig = Rig::new("http://127.0.0.1:9/v1/vcons", "Authorization")?;
    let mut args = forward_args(&rig, "http://127.0.0.1:9/v1/vcons");
    args.extend(["-I".into(), "tests/fixtures/sip_call.pcap".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (_, err, code) = sipnab(&argv)?;
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("cannot be used with"), "{err}");
    Ok(())
}
