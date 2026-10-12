// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vCon fetcher (`--vcon-fetch`), driven against a fake store.
//!
//! Every test here talks to a store this file runs itself: a
//! `std::net::TcpListener` on `127.0.0.1` that records each request and
//! answers as its script says, the pattern `vcon_forward_test.rs` uses. No
//! test contacts the internet.
//!
//! Two layers. Most tests drive [`Fetcher`] in-process, one uuid at a time.
//! The tests at the end run the `sipnab` binary, because exit codes,
//! standard input and the refusal of a capture flag exist only at that level.
//!
//! The whole file is gated: the fetcher is part of the non-default `vcon`
//! feature.

#![cfg(all(feature = "vcon", unix))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use sipnab::app::vcon_fetch::{FetchLimits, FetchSettings, Fetched, Fetcher, read_url};
use sipnab::app::vcon_forward::{AuthHeader, Endpoint, StoreKind};

#[path = "support/tls_pki.rs"]
mod tls_pki;

/// Any error, boxed, so `?` works on every error type alike.
type TestError = Box<dyn std::error::Error>;

/// The secret every test's auth file carries. Built at run time so no scanner
/// reads a literal credential here.
fn secret() -> String {
    format!("vcf_test_{}", "7c2e91d04a5b")
}

/// The uuid most tests fetch. Synthetic.
const UUID: &str = "018bcfe5-6800-8a6b-a667-78f1c5213800";

/// One request the fake store received.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
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
    /// Answer this status with this JSON body and a `Content-Length`.
    Json(u16, String),
    /// Answer with these bytes exactly: status line, headers and body.
    Raw(Vec<u8>),
    /// Read the request and say nothing, for this long.
    Silence(Duration),
}

/// The script: the request in, the reply out.
type Script = dyn Fn(&Recorded) -> Reply + Send + Sync;

/// A store on `127.0.0.1` that records every request and answers by script.
struct FakeStore {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
}

impl FakeStore {
    /// Plain HTTP.
    fn start(
        script: impl Fn(&Recorded) -> Reply + Send + Sync + 'static,
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
    let req = Recorded {
        method: first.next().unwrap_or_default().to_string(),
        target: first.next().unwrap_or_default().to_string(),
        headers: lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .collect(),
    };
    log.lock().push(req.clone());
    let bytes = match script(&req) {
        Reply::Json(code, body) => format!(
            "HTTP/1.1 {code} Scripted\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
        Reply::Raw(bytes) => bytes,
        Reply::Silence(d) => {
            std::thread::sleep(d);
            return Ok(());
        }
    };
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// A synthetic container in sipnab's shape: two parties and one recording.
/// Not a capture of anyone's call.
fn container(uuid: &str) -> String {
    format!(
        r#"{{"vcon":"0.4.0","uuid":"{uuid}","created_at":"2026-10-07T12:00:00+00:00","parties":[{{"tel":"+15550100001"}},{{"tel":"+15550100002"}}],"dialog":[{{"type":"recording","parties":[0,1],"start":"2026-10-07T12:00:00+00:00","mediatype":"audio/x-wav","encoding":"base64url","body":"UklGRg"}}],"attachments":[],"analysis":[]}}"#
    )
}

/// What a store of `kind` answers for `container`: the container inside
/// the kind's envelope.
fn enveloped(kind: StoreKind, container: &str) -> String {
    match kind {
        StoreKind::VconStore => {
            let body = container.trim_end_matches('}');
            format!(r#"{body},"_meta":{{"owner":"synthetic","stored_at":"2026-10-09"}}}}"#)
        }
        StoreKind::VconMcp => format!(r#"{{"success":true,"vcon":{container}}}"#),
        StoreKind::Generic | StoreKind::Conserver => container.to_string(),
    }
}

/// An output directory and an auth file, and the settings that fetch into it.
struct Rig {
    dir: tempfile::TempDir,
    settings: FetchSettings,
}

impl Rig {
    /// A rig reading `base` as a store of `kind`. The auth file holds the
    /// bare key, or for the generic kind `x-test-auth: <secret>`.
    fn new(base: &str, kind: StoreKind) -> Result<Self, TestError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let auth_file = dir.path().join("auth");
        let line = match kind {
            StoreKind::Generic => format!("x-test-auth: {}\n", secret()),
            _ => format!("{}\n", secret()),
        };
        std::fs::write(&auth_file, line)?;
        std::fs::set_permissions(&auth_file, std::fs::Permissions::from_mode(0o600))?;
        let settings = FetchSettings {
            url: read_url(&Endpoint::parse(base)?, kind)?,
            kind,
            auth: AuthHeader::read_file_for(&auth_file, "--vcon-fetch-auth-file", kind)?,
            ca: None,
            timeout: Duration::from_secs(5),
            limits: FetchLimits {
                response_head: 64 * 1024,
                max_size: 1024 * 1024,
            },
            out_dir: dir.path().join("out"),
            overwrite: false,
        };
        Ok(Self { dir, settings })
    }

    fn auth_file(&self) -> PathBuf {
        self.dir.path().join("auth")
    }

    fn out(&self, uuid: &str) -> PathBuf {
        self.settings.out_dir.join(format!("{uuid}.vcon.json"))
    }

    fn fetch(&self, uuid: &str) -> Result<Fetched, TestError> {
        Ok(Fetcher::new(self.settings.clone())?.fetch_one(uuid))
    }
}

// ── Each kind ───────────────────────────────────────────────────────────

/// Each kind GETs its read path with its auth header, the key from the auth
/// file in it and no other auth header, carrying sipnab's User-Agent; the
/// file written is the container without the kind's envelope.
#[test]
fn each_kind_reads_its_path_with_its_header_and_strips_its_envelope() -> Result<(), TestError> {
    let cases = [
        (
            StoreKind::Generic,
            "/store/{uuid}/raw",
            format!("/store/{UUID}/raw"),
            "x-test-auth",
            secret(),
        ),
        (
            StoreKind::VconStore,
            "",
            format!("/v1/vcons/{UUID}"),
            "authorization",
            format!("Bearer {}", secret()),
        ),
        (
            StoreKind::Conserver,
            "",
            format!("/vcon/{UUID}"),
            "x-conserver-api-token",
            secret(),
        ),
        (
            StoreKind::VconMcp,
            "",
            format!("/api/v1/vcons/{UUID}"),
            "authorization",
            format!("Bearer {}", secret()),
        ),
    ];
    for (kind, base_path, want_target, header, value) in cases {
        let bytes = container(UUID);
        let answer = enveloped(kind, &bytes);
        let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
        let rig = Rig::new(&store.url(base_path), kind)?;

        let got = rig.fetch(UUID)?;

        let seen = store.requests();
        assert_eq!(seen.len(), 1, "{kind:?}: {seen:?}");
        let req = &seen[0];
        assert_eq!(req.method, "GET", "{kind:?}");
        assert_eq!(req.target, want_target, "{kind:?}");
        assert_eq!(req.header(header), [value.as_str()], "{kind:?}");
        for other in ["authorization", "x-conserver-api-token", "x-test-auth"] {
            if other != header {
                assert!(req.header(other).is_empty(), "{kind:?} also sent {other}");
            }
        }
        assert_eq!(
            req.header("user-agent"),
            [format!("sipnab/{}", env!("CARGO_PKG_VERSION")).as_str()],
            "{kind:?}"
        );
        assert_eq!(
            got,
            Fetched::Saved {
                path: rig.out(UUID),
                findings: Vec::new()
            },
            "{kind:?}"
        );
        assert_eq!(std::fs::read_to_string(rig.out(UUID))?, bytes, "{kind:?}");
    }
    Ok(())
}

/// A vcon.store answer without `_meta` is written as it came.
#[test]
fn a_vcon_store_answer_without_its_envelope_is_written_as_it_came() -> Result<(), TestError> {
    let bytes = container(UUID);
    let answer = bytes.clone();
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::VconStore)?;
    assert!(matches!(rig.fetch(UUID)?, Fetched::Saved { .. }));
    assert_eq!(std::fs::read_to_string(rig.out(UUID))?, bytes);
    Ok(())
}

/// A vcon-mcp answer that is not its envelope is refused, and nothing is
/// written.
#[test]
fn a_vcon_mcp_answer_without_its_envelope_is_refused() -> Result<(), TestError> {
    let answer = container(UUID);
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::VconMcp)?;
    let got = rig.fetch(UUID)?;
    assert!(
        matches!(&got, Fetched::Failed(why) if why.contains("vcon")),
        "{got:?}"
    );
    assert!(!rig.out(UUID).exists());
    Ok(())
}

// ── What the store answers ──────────────────────────────────────────────

/// 401 and 403 halt the run, naming the status, and write nothing; the
/// credential appears in no message.
#[test]
fn a_refused_credential_halts() -> Result<(), TestError> {
    for status in [401, 403] {
        let store = FakeStore::start(move |_| {
            Reply::Json(status, format!(r#"{{"error":"bad key {}"}}"#, secret()))
        })?;
        let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
        let got = rig.fetch(UUID)?;
        match &got {
            Fetched::Halt(why) => {
                assert!(why.contains(&status.to_string()), "{why}");
                assert!(!why.contains(&secret()), "the credential leaked: {why}");
            }
            other => return Err(format!("{status}: {other:?}").into()),
        }
        assert!(!rig.out(UUID).exists());
    }
    Ok(())
}

/// 404 is "not found", and writes nothing.
#[test]
fn a_missing_container_is_not_found() -> Result<(), TestError> {
    let store = FakeStore::start(|_| Reply::Json(404, r#"{"error":"Not found"}"#.into()))?;
    let rig = Rig::new(&store.url(""), StoreKind::VconStore)?;
    assert_eq!(rig.fetch(UUID)?, Fetched::NotFound);
    assert!(!rig.out(UUID).exists());
    Ok(())
}

/// Another status fails that uuid, naming the status, and writes nothing.
#[test]
fn another_status_fails_the_uuid() -> Result<(), TestError> {
    let store = FakeStore::start(|_| Reply::Json(500, r#"{"error":"down"}"#.into()))?;
    let rig = Rig::new(&store.url(""), StoreKind::VconStore)?;
    let got = rig.fetch(UUID)?;
    assert!(
        matches!(&got, Fetched::Failed(why) if why.contains("500")),
        "{got:?}"
    );
    assert!(!rig.out(UUID).exists());
    Ok(())
}

/// An answer larger than the size limit is refused naming the setting,
/// whether its length is declared or not, and nothing is written.
#[test]
fn an_oversized_answer_is_refused() -> Result<(), TestError> {
    let big = container(UUID).replace("UklGRg", &"A".repeat(4096));
    let declared = big.clone();
    let undeclared = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{big}"
    )
    .into_bytes();
    for reply in [
        Arc::new(move |_: &Recorded| Reply::Json(200, declared.clone())) as Arc<Script>,
        Arc::new(move |_: &Recorded| Reply::Raw(undeclared.clone())),
    ] {
        let store = FakeStore::start_with(reply, None)?;
        let mut rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
        rig.settings.limits.max_size = 1024;
        let got = rig.fetch(UUID)?;
        assert!(
            matches!(&got, Fetched::Failed(why) if why.contains("--vcon-fetch-max-size")),
            "{got:?}"
        );
        assert!(!rig.out(UUID).exists());
    }
    Ok(())
}

/// A chunked answer within the limit is read whole.
#[test]
fn a_chunked_answer_is_read_whole() -> Result<(), TestError> {
    let bytes = container(UUID);
    let (a, b) = bytes.split_at(40);
    let raw = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
        a.len(),
        b.len()
    )
    .into_bytes();
    let store = FakeStore::start(move |_| Reply::Raw(raw.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    assert!(matches!(rig.fetch(UUID)?, Fetched::Saved { .. }));
    assert_eq!(std::fs::read_to_string(rig.out(UUID))?, bytes);
    Ok(())
}

/// An answer that is not JSON, or ends before its declared length, is
/// refused and nothing is written.
#[test]
fn an_answer_that_is_not_json_is_refused() -> Result<(), TestError> {
    let short = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\nConnection: close\r\n\r\n{}",
        container(UUID)
    )
    .into_bytes();
    for reply in [
        Arc::new(|_: &Recorded| Reply::Json(200, "<html>proxy error</html>".into())) as Arc<Script>,
        Arc::new(move |_: &Recorded| Reply::Raw(short.clone())),
    ] {
        let store = FakeStore::start_with(reply, None)?;
        let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
        let got = rig.fetch(UUID)?;
        assert!(matches!(&got, Fetched::Failed(_)), "{got:?}");
        assert!(!rig.out(UUID).exists());
    }
    Ok(())
}

/// A container the store holds under another uuid is refused.
#[test]
fn a_container_with_another_uuid_is_refused() -> Result<(), TestError> {
    let answer = container("11111111-2222-3333-4444-555555555555");
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let got = rig.fetch(UUID)?;
    assert!(
        matches!(&got, Fetched::Failed(why) if why.contains("uuid")),
        "{got:?}"
    );
    assert!(!rig.out(UUID).exists());
    Ok(())
}

/// A container the schema refuses is still written, as the store holds it,
/// and the findings are reported.
#[test]
fn an_invalid_container_is_written_and_reported() -> Result<(), TestError> {
    let bytes = container(UUID).replace(r#""parties":[{"tel""#, r#""parties":[{"tel":5,"x""#);
    let answer = bytes.clone();
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    match rig.fetch(UUID)? {
        Fetched::Saved { path, findings } => {
            assert_eq!(path, rig.out(UUID));
            assert!(!findings.is_empty());
            assert!(
                findings.iter().any(|f| f.contains("/parties/0")),
                "{findings:?}"
            );
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(std::fs::read_to_string(rig.out(UUID))?, bytes);
    Ok(())
}

// ── The file ────────────────────────────────────────────────────────────

/// The file is mode 0600 and the directory created for it 0700.
#[test]
fn the_file_is_private() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let answer = container(UUID);
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    assert!(matches!(rig.fetch(UUID)?, Fetched::Saved { .. }));
    let file = std::fs::metadata(rig.out(UUID))?.permissions().mode() & 0o777;
    assert_eq!(file, 0o600, "file mode {file:o}");
    let dir = std::fs::metadata(&rig.settings.out_dir)?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir, 0o700, "directory mode {dir:o}");
    Ok(())
}

/// A file that exists is not replaced, and the store is not asked; with
/// overwrite it is replaced.
#[test]
fn an_existing_file_is_kept_unless_overwrite() -> Result<(), TestError> {
    let answer = container(UUID);
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let mut rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    std::fs::create_dir_all(&rig.settings.out_dir)?;
    std::fs::write(rig.out(UUID), "kept")?;

    assert_eq!(rig.fetch(UUID)?, Fetched::Exists(rig.out(UUID)));
    assert_eq!(std::fs::read_to_string(rig.out(UUID))?, "kept");
    assert!(store.requests().is_empty());

    rig.settings.overwrite = true;
    assert!(matches!(rig.fetch(UUID)?, Fetched::Saved { .. }));
    assert_eq!(std::fs::read_to_string(rig.out(UUID))?, container(UUID));
    Ok(())
}

/// A symbolic link in the file's place is not followed, with or without
/// overwrite.
#[test]
fn a_symbolic_link_in_the_file_s_place_is_not_followed() -> Result<(), TestError> {
    let answer = container(UUID);
    let store = FakeStore::start(move |_| Reply::Json(200, answer.clone()))?;
    let mut rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    std::fs::create_dir_all(&rig.settings.out_dir)?;
    let target = rig.dir.path().join("elsewhere");
    std::fs::write(&target, "untouched")?;
    std::os::unix::fs::symlink(&target, rig.out(UUID))?;
    rig.settings.overwrite = true;
    let _ = rig.fetch(UUID)?;
    assert_eq!(std::fs::read_to_string(&target)?, "untouched");
    Ok(())
}

// ── HTTPS ───────────────────────────────────────────────────────────────

/// An `https://` store is read with the CA named, and refused without it.
#[test]
fn an_https_store_is_read_with_the_named_ca() -> Result<(), TestError> {
    use rustls::pki_types::pem::PemObject;
    let pki = tls_pki::test_pki("vcon-fetch")?;
    let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let answer = container(UUID);
    let store = FakeStore::start_with(
        Arc::new(move |_: &Recorded| Reply::Json(200, answer.clone())),
        Some(Arc::new(server)),
    )?;
    let mut rig = Rig::new(&format!("https://{}", store.addr), StoreKind::Conserver)?;
    rig.settings.ca = Some(PathBuf::from(&pki.ca_file));
    assert!(matches!(rig.fetch(UUID)?, Fetched::Saved { .. }));
    Ok(())
}

// ── The binary ──────────────────────────────────────────────────────────

/// Run `sipnab` with `args` and `stdin`, returning (stderr, code).
fn sipnab(args: &[String], stdin: &str) -> Result<(String, Option<i32>), TestError> {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(stdin.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    Ok((
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    ))
}

/// The fetcher flags for `rig` reading `url` as a conserver, then `uuids`.
fn fetch_args(rig: &Rig, url: &str, uuids: &[&str]) -> Vec<String> {
    let mut args = vec![
        "--no-config".to_string(),
        "--vcon-fetch-kind".into(),
        "conserver".into(),
        "--vcon-fetch-url".into(),
        url.into(),
        "--vcon-fetch-auth-file".into(),
        rig.auth_file().display().to_string(),
        "--vcon-fetch-out".into(),
        rig.settings.out_dir.display().to_string(),
        "--vcon-fetch".into(),
    ];
    args.extend(uuids.iter().map(|u| (*u).to_string()));
    args
}

/// Two uuids [`holding_store`] holds, and one it does not. Synthetic.
const H1: &str = "018bcfe5-6800-8a6b-a667-78f1c52138a1";
const H2: &str = "018bcfe5-6800-8a6b-a667-78f1c52138a2";
const G1: &str = "ffffffff-6800-8a6b-a667-78f1c52138a3";

/// A store holding the containers whose uuids start with `018bcfe5-`.
fn holding_store() -> Result<FakeStore, TestError> {
    FakeStore::start(|req| {
        let uuid = req
            .target
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        if uuid.starts_with("018bcfe5-") {
            Reply::Json(200, container(&uuid))
        } else {
            Reply::Json(404, r#"{"detail":"vCon not found"}"#.into())
        }
    })
}

/// Every uuid saved and valid: exit 0, one file each.
#[test]
fn the_binary_exits_0_when_every_container_is_saved() -> Result<(), TestError> {
    let store = holding_store()?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let (err, code) = sipnab(&fetch_args(&rig, &store.url(""), &[H1, H2]), "")?;
    assert_eq!(code, Some(0), "{err}");
    assert!(rig.out(H1).exists() && rig.out(H2).exists(), "{err}");
    Ok(())
}

/// A uuid the store does not hold: the others are still fetched, and the run
/// exits 1 naming it.
#[test]
fn the_binary_exits_1_when_a_container_is_missing() -> Result<(), TestError> {
    let store = holding_store()?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let (err, code) = sipnab(&fetch_args(&rig, &store.url(""), &[G1, H2]), "")?;
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains(G1), "{err}");
    assert!(rig.out(H2).exists(), "{err}");
    Ok(())
}

/// A refused credential stops the run at the first uuid: exit 3, and the
/// second uuid is never asked for.
#[test]
fn the_binary_exits_3_and_stops_when_the_credential_is_refused() -> Result<(), TestError> {
    let store = FakeStore::start(|_| Reply::Json(403, r#"{"detail":"Invalid API Key"}"#.into()))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let (err, code) = sipnab(&fetch_args(&rig, &store.url(""), &[H1, H2]), "")?;
    assert_eq!(code, Some(3), "{err}");
    assert_eq!(store.requests().len(), 1, "{err}");
    assert!(!err.contains(&secret()), "the credential leaked: {err}");
    Ok(())
}

/// `-` reads the uuids from standard input.
#[test]
fn the_binary_reads_uuids_from_standard_input() -> Result<(), TestError> {
    let store = holding_store()?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let (err, code) = sipnab(
        &fetch_args(&rig, &store.url(""), &["-"]),
        &format!("# two\n{H1}\n\n{H2}\n"),
    )?;
    assert_eq!(code, Some(0), "{err}");
    assert!(rig.out(H1).exists() && rig.out(H2).exists(), "{err}");
    Ok(())
}

/// A file that exists ends the run 1 without replacing it.
#[test]
fn the_binary_exits_1_rather_than_overwrite() -> Result<(), TestError> {
    let store = holding_store()?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    std::fs::create_dir_all(&rig.settings.out_dir)?;
    std::fs::write(rig.out(H1), "kept")?;
    let (err, code) = sipnab(&fetch_args(&rig, &store.url(""), &[H1]), "")?;
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("--vcon-fetch-overwrite"), "{err}");
    assert_eq!(std::fs::read_to_string(rig.out(H1))?, "kept");
    let mut args = fetch_args(&rig, &store.url(""), &[H1]);
    args.insert(0, "--vcon-fetch-overwrite".into());
    let (err, code) = sipnab(&args, "")?;
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(std::fs::read_to_string(rig.out(H1))?, container(H1));
    Ok(())
}

/// An auth file other users can read is refused before any request: exit 2
/// for the flag that named it.
#[test]
fn the_binary_refuses_a_group_readable_auth_file() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let store = holding_store()?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    std::fs::set_permissions(rig.auth_file(), std::fs::Permissions::from_mode(0o640))?;
    let (err, code) = sipnab(&fetch_args(&rig, &store.url(""), &[H1]), "")?;
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("--vcon-fetch-auth-file"), "{err}");
    assert!(store.requests().is_empty());
    Ok(())
}

/// The fetcher is not a capture: a capture input beside it is refused.
#[test]
fn the_binary_refuses_a_fetcher_with_a_capture_flag() -> Result<(), TestError> {
    let rig = Rig::new("http://127.0.0.1:9", StoreKind::Conserver)?;
    let mut args = fetch_args(&rig, "http://127.0.0.1:9", &[H1]);
    args.extend(["-I".to_string(), "tests/fixtures/sip_call.pcap".to_string()]);
    let (err, code) = sipnab(&args, "")?;
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("--vcon-fetch") && err.contains("--input"),
        "{err}"
    );
    Ok(())
}

/// `--vcon-fetch-ca` names the CA an `https://` store is verified against,
/// and without it the same store is refused.
#[test]
fn the_binary_honors_the_ca_flag() -> Result<(), TestError> {
    use rustls::pki_types::pem::PemObject;
    let pki = tls_pki::test_pki("vcon-fetch-bin")?;
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
        Arc::new(|req: &Recorded| {
            let uuid = req
                .target
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
            Reply::Json(200, container(&uuid))
        }),
        Some(Arc::new(server)),
    )?;
    let url = format!("https://{}", store.addr);
    let rig = Rig::new(&url, StoreKind::Conserver)?;
    let mut args = fetch_args(&rig, &url, &[H1]);
    args.splice(0..0, ["--vcon-fetch-ca".to_string(), pki.ca_file.clone()]);
    let (err, code) = sipnab(&args, "")?;
    assert_eq!(code, Some(0), "{err}");
    assert!(rig.out(H1).exists(), "{err}");
    let (err, code) = sipnab(&fetch_args(&rig, &url, &[H2]), "")?;
    assert_eq!(code, Some(1), "the host bundle trusted a test CA: {err}");
    assert!(!rig.out(H2).exists(), "{err}");
    Ok(())
}

/// `--vcon-fetch-timeout` bounds the wait on a store that accepts the
/// connection and never answers: with 1 s the run ends in a few seconds,
/// not the default 30, and writes nothing.
#[test]
fn the_binary_gives_up_on_a_silent_store_after_its_timeout() -> Result<(), TestError> {
    let store = FakeStore::start(|_| Reply::Silence(Duration::from_secs(20)))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let mut args = fetch_args(&rig, &store.url(""), &[H1]);
    args.splice(0..0, ["--vcon-fetch-timeout".to_string(), "1".to_string()]);
    let started = std::time::Instant::now();
    let (err, code) = sipnab(&args, "")?;
    assert_eq!(code, Some(1), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}: {err}",
        started.elapsed()
    );
    assert!(!rig.out(H1).exists(), "{err}");
    Ok(())
}

/// `--vcon-fetch-max-response-head` refuses an answer whose status line and
/// headers pass it, naming the flag, and writes nothing.
#[test]
fn the_binary_refuses_an_answer_head_past_its_limit() -> Result<(), TestError> {
    let body = container(H1);
    let raw = format!(
        "HTTP/1.1 200 OK\r\nX-Padding: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        "p".repeat(2048),
        body.len()
    )
    .into_bytes();
    let store = FakeStore::start(move |_| Reply::Raw(raw.clone()))?;
    let rig = Rig::new(&store.url(""), StoreKind::Conserver)?;
    let mut args = fetch_args(&rig, &store.url(""), &[H1]);
    args.splice(
        0..0,
        [
            "--vcon-fetch-max-response-head".to_string(),
            "512".to_string(),
        ],
    );
    let (err, code) = sipnab(&args, "")?;
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("--vcon-fetch-max-response-head"), "{err}");
    assert!(!rig.out(H1).exists(), "{err}");
    let (err, code) = sipnab(&fetch_args(&rig, &store.url(""), &[H1]), "")?;
    assert_eq!(
        code,
        Some(0),
        "the default limit refused 2 KiB of headers: {err}"
    );
    Ok(())
}

/// Nothing in this file writes outside its temporary directories.
#[test]
fn the_rig_writes_under_its_own_directory() -> Result<(), TestError> {
    let rig = Rig::new("http://127.0.0.1:9", StoreKind::Conserver)?;
    assert!(rig.settings.out_dir.starts_with(rig.dir.path()));
    assert!(Path::new(&rig.auth_file()).starts_with(rig.dir.path()));
    Ok(())
}
