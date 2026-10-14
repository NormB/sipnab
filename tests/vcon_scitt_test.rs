// SPDX-License-Identifier: MIT OR Apache-2.0

//! SCITT lifecycle statements: the vCon forwarder registers `vcon_created`
//! and `vcon_sent` (draft-howe-vcon-lifecycle-01 section 5) with a SCRAPI
//! transparency service (draft-ietf-scitt-scrapi-11 section 2.3) when it
//! delivers a container.
//!
//! The store and the transparency service are both fakes this file runs on
//! `127.0.0.1`. The transparency service decodes each Signed Statement with
//! `ciborium`, a CBOR implementation sipnab does not use to write them, and
//! checks its signature with `ring` against the public half of the key it
//! was signed with, so a statement sipnab encodes or signs wrongly fails
//! here.

#![cfg(all(feature = "vcon", unix))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ciborium::value::Value as Cbor;
use parking_lot::Mutex;
use sipnab::app::vcon_forward::{
    AuthHeader, BackoffPolicy, Endpoint, ForwardSettings, Forwarder, ReadLimits, StoreKind,
};
use sipnab::app::vcon_scitt::{RECORD_SUFFIX, ScittSettings, ScittSigner};

#[path = "support/tls_pki.rs"]
mod tls_pki;

type TestError = Box<dyn std::error::Error>;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// The issuer every test's statements carry.
const ISSUER: &str = "https://sipnab.example/forwarder";

/// One request a fake server received.
#[derive(Debug, Clone)]
struct Recorded {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    /// The first value of header `name`.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A server on `127.0.0.1` that records each request and answers with the
/// bytes `reply` returns for it.
struct Fake {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
}

impl Fake {
    fn start(
        reply: impl Fn(&Recorded) -> Vec<u8> + Send + Sync + 'static,
    ) -> Result<Self, TestError> {
        Self::start_with(reply, None)
    }

    /// HTTPS with this server configuration when `tls` is set.
    fn start_with(
        reply: impl Fn(&Recorded) -> Vec<u8> + Send + Sync + 'static,
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
                        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                        let _ = match &tls {
                            Some(cfg) => rustls::ServerConnection::new(cfg.clone())
                                .map_err(TestError::from)
                                .and_then(|conn| {
                                    serve(rustls::StreamOwned::new(conn, sock), &log, &reply)
                                }),
                            None => serve(sock, &log, &reply),
                        };
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

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().clone()
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Read one request, record it, answer it.
fn serve(
    mut sock: impl Read + Write,
    log: &Mutex<Vec<Recorded>>,
    reply: &(impl Fn(&Recorded) -> Vec<u8> + ?Sized),
) -> Result<(), TestError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if sock.read(&mut byte)? == 0 {
            return Ok(());
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let target = lines
        .next()
        .unwrap_or_default()
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)?;
    let req = Recorded {
        target,
        headers,
        body,
    };
    log.lock().push(req.clone());
    sock.write_all(&reply(&req))?;
    sock.flush()?;
    Ok(())
}

/// An HTTP answer with `status`, extra header lines and `body`.
fn answer(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} Scripted\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A store that accepts every container.
fn store() -> Result<Fake, TestError> {
    Fake::start(|_| answer(201, "", b""))
}

/// The receipt the fake transparency service returns for a 201: bytes it
/// makes up, which sipnab keeps without reading.
const RECEIPT: &[u8] = b"\xd2\x84receipt-bytes";

/// A transparency service that registers every statement at once: 201, a
/// `Location` and the receipt, as SCRAPI section 2.3.1 shows.
fn scrapi_201() -> Result<Fake, TestError> {
    Fake::start(|_| {
        answer(
            201,
            "Location: https://ts.example/entries/e-1\r\nContent-Type: application/cose\r\n",
            RECEIPT,
        )
    })
}

/// The fixture chain: the key's certificate first.
fn chain_pem() -> Result<String, TestError> {
    let mut out = String::new();
    for name in ["fake_grp.crt", "fake_div.crt", "fake_ca_root.crt"] {
        out.push_str(&std::fs::read_to_string(Path::new(FIXTURES).join(name))?);
    }
    Ok(out)
}

/// The DER of each certificate in `pem`, in order.
fn ders(pem: &str) -> Result<Vec<Vec<u8>>, TestError> {
    use base64::Engine as _;
    let mut out = Vec::new();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let text: String = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        out.push(base64::engine::general_purpose::STANDARD.decode(text)?);
    }
    Ok(out)
}

/// The fixture key's public half, as `ring` verifies with it.
fn public_key() -> Result<Vec<u8>, TestError> {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;
    let pem = std::fs::read_to_string(Path::new(FIXTURES).join("fake_grp.key"))?;
    let text: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(text)?;
    let pair = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("{e}"))?;
    Ok(pair.public_key().as_ref().to_vec())
}

/// A spool, and forwarder settings that deliver it to `store` and register
/// with `scrapi`.
struct Rig {
    _dir: tempfile::TempDir,
    settings: ForwardSettings,
}

impl Rig {
    fn new(store: &Fake, scrapi: &Fake, scitt_auth: Option<&str>) -> Result<Self, TestError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let spool = dir.path().join("spool");
        std::fs::create_dir(&spool)?;
        let auth_file = dir.path().join("auth");
        std::fs::write(&auth_file, "Authorization: Bearer store-token-value\n")?;
        std::fs::set_permissions(&auth_file, std::fs::Permissions::from_mode(0o600))?;
        let key = std::fs::read_to_string(Path::new(FIXTURES).join("fake_grp.key"))?;
        let auth = match scitt_auth {
            Some(line) => {
                let path = dir.path().join("scitt-auth");
                std::fs::write(&path, line)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                Some(AuthHeader::read_file(&path)?)
            }
            None => None,
        };
        let settings = ForwardSettings {
            done_dir: spool.join("delivered"),
            failed_dir: spool.join("failed"),
            spool,
            url: Endpoint::parse(&store.url("/v1/vcons"))?,
            replace_url: None,
            auth: AuthHeader::read_file(&auth_file)?,
            timeout: Duration::from_secs(5),
            ca: None,
            extra_ca: None,
            kind: StoreKind::Generic,
            backoff: BackoffPolicy::default(),
            limits: ReadLimits::default(),
            scitt: Some(ScittSettings {
                url: Endpoint::parse(&scrapi.url("/scitt"))?,
                auth,
                ca: None,
                signer: Arc::new(ScittSigner::from_pem(&key, &chain_pem()?)?),
                issuer: ISSUER.into(),
            }),
        };
        Ok(Self {
            _dir: dir,
            settings,
        })
    }

    fn drop_in(&self, name: &str, bytes: &str) -> Result<(), TestError> {
        let staged = self.settings.spool.join(format!(".{name}.partial"));
        std::fs::write(&staged, bytes)?;
        std::fs::rename(&staged, self.settings.spool.join(name))?;
        Ok(())
    }

    /// The record the forwarder wrote beside the delivered `name`.
    fn record(&self, name: &str) -> Result<serde_json::Value, TestError> {
        let path = self
            .settings
            .done_dir
            .join(format!("{name}{RECORD_SUFFIX}"));
        Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
    }
}

/// A container as sipnab writes it, `extra` added to its top level.
fn container(uuid: &str, extra: &str) -> String {
    format!(
        r#"{{"vcon":"0.4.0","uuid":"{uuid}","created_at":"2026-10-07T12:00:00+00:00"{extra},"parties":[{{"validation":"none","role":"observer"}}],"dialog":[{{"sip_call_id":"c@192.0.2.1"}}],"attachments":[],"analysis":[]}}"#
    )
}

const UUID: &str = "018bcfe5-6800-8f87-bed9-9fac32562404";

fn never() -> bool {
    false
}

/// A Signed Statement, decoded and checked: the protected header, the
/// payload, and the signature.
struct Statement {
    protected: Vec<(Cbor, Cbor)>,
    payload: serde_json::Value,
}

impl Statement {
    /// The protected header's value at integer label `label`.
    fn header(&self, label: i64) -> Option<&Cbor> {
        self.protected
            .iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .map(|(_, v)| v)
    }
}

/// Decode `bytes` as a COSE_Sign1 Signed Statement
/// ([RFC 9052 section 4.2](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2)),
/// and verify its RS256 signature over the Sig_structure of
/// [RFC 9052 section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
fn decode(bytes: &[u8]) -> Result<Statement, TestError> {
    let value: Cbor = ciborium::from_reader(bytes)?;
    let Cbor::Tag(18, inner) = value else {
        return Err(format!("not tag 18 (COSE_Sign1): {value:?}").into());
    };
    let Cbor::Array(parts) = *inner else {
        return Err("COSE_Sign1 is not an array".into());
    };
    let [protected, unprotected, payload, signature] = parts.as_slice() else {
        return Err(format!("COSE_Sign1 has {} parts, not 4", parts.len()).into());
    };
    let (Cbor::Bytes(protected), Cbor::Bytes(payload), Cbor::Bytes(signature)) =
        (protected, payload, signature)
    else {
        return Err("protected, payload and signature are not byte strings".into());
    };
    assert_eq!(
        unprotected,
        &Cbor::Map(Vec::new()),
        "the unprotected header is empty"
    );
    let mut to_be_signed = Vec::new();
    ciborium::into_writer(
        &Cbor::Array(vec![
            Cbor::Text("Signature1".into()),
            Cbor::Bytes(protected.clone()),
            Cbor::Bytes(Vec::new()),
            Cbor::Bytes(payload.clone()),
        ]),
        &mut to_be_signed,
    )?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        public_key()?,
    )
    .verify(&to_be_signed, signature)
    .map_err(|_| "the RS256 signature does not verify")?;
    let Cbor::Map(protected) = ciborium::from_reader(protected.as_slice())? else {
        return Err("the protected header is not a map".into());
    };
    Ok(Statement {
        protected,
        payload: serde_json::from_slice(payload)?,
    })
}

/// A delivered container that sipnab wrote once registers `vcon_created` and
/// then `vcon_sent`, each a Signed Statement POSTed to `<url>/entries` as
/// `application/cose`, and the receipts go into a record beside it.
///
/// The protected header carries what
/// [section 6 of draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22#section-6)
/// requires: `alg`, the CWT Claims (label 15) with `iss` (1) and `sub` (2),
/// and, with X.509, `x5chain` (33) in the protected header.
#[test]
fn a_delivery_registers_created_and_sent() -> Result<(), TestError> {
    let store = store()?;
    let scrapi = scrapi_201()?;
    let rig = Rig::new(&store, &scrapi, None)?;
    let bytes = container(UUID, "");
    rig.drop_in("a.vcon.json", &bytes)?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["a.vcon.json"]);

    let posts = scrapi.requests();
    assert_eq!(posts.len(), 2);
    let chain = ders(&chain_pem()?)?;
    let mut events = Vec::new();
    for post in &posts {
        assert_eq!(post.target, "/scitt/entries");
        assert_eq!(post.header("content-type"), Some("application/cose"));
        let statement = decode(&post.body)?;
        // RS256, RFC 8812 section 2.
        assert_eq!(statement.header(1), Some(&Cbor::Integer((-257).into())));
        assert_eq!(
            statement.header(3),
            Some(&Cbor::Text("application/json".into()))
        );
        let Some(Cbor::Map(claims)) = statement.header(15) else {
            return Err("no CWT Claims".into());
        };
        let claim = |label: i64| {
            claims
                .iter()
                .find(|(k, _)| k.as_integer() == Some(label.into()))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(claim(1), Some(Cbor::Text(ISSUER.into())));
        assert_eq!(claim(2), Some(Cbor::Text(format!("urn:uuid:{UUID}"))));
        assert!(matches!(claim(6), Some(Cbor::Integer(_))), "iat");
        let Some(Cbor::Array(x5chain)) = statement.header(33) else {
            return Err("no x5chain array".into());
        };
        let carried: Vec<Vec<u8>> = x5chain
            .iter()
            .filter_map(|c| c.as_bytes().cloned())
            .collect();
        assert_eq!(carried, chain, "x5chain is the chain, leaf first");

        let payload = &statement.payload;
        assert_eq!(payload["vcon_uuid"], UUID);
        assert_eq!(
            payload["vcon_hash"],
            sipnab::app::vcon_hash::token(bytes.as_bytes())
        );
        events.push(payload["event"].as_str().unwrap_or_default().to_owned());
        if payload["event"] == "vcon_sent" {
            assert_eq!(payload["to"], store.url("/v1/vcons"));
            assert!(payload["at"].as_str().is_some_and(|t| t.ends_with('Z')));
        } else {
            assert_eq!(payload["at"], "2026-10-07T12:00:00+00:00", "created_at");
        }
    }
    assert_eq!(events, ["vcon_created", "vcon_sent"]);

    use base64::Engine as _;
    let record = rig.record("a.vcon.json")?;
    let statements = record["statements"].as_array().ok_or("statements")?;
    assert_eq!(statements.len(), 2);
    for (s, event) in statements.iter().zip(["vcon_created", "vcon_sent"]) {
        assert_eq!(s["event"], event);
        assert_eq!(s["status"], 201);
        assert_eq!(s["location"], "https://ts.example/entries/e-1");
        assert_eq!(
            s["receipt"],
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(RECEIPT)
        );
    }
    // The record is not a container: the delivered directory still counts
    // one, and the spool status reads it so.
    assert_eq!(
        sipnab::app::vcon_forward::pending(&rig.settings.done_dir)?,
        ["a.vcon.json"]
    );
    Ok(())
}

/// A container sipnab rewrote (its `updated_at` differs from `created_at`)
/// registers only `vcon_sent`: it was created before.
#[test]
fn a_rewritten_container_registers_only_sent() -> Result<(), TestError> {
    let store = store()?;
    let scrapi = scrapi_201()?;
    let rig = Rig::new(&store, &scrapi, None)?;
    rig.drop_in(
        "a.vcon.json",
        &container(UUID, r#","updated_at":"2026-10-07T12:05:00+00:00""#),
    )?;
    Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    let posts = scrapi.requests();
    assert_eq!(posts.len(), 1);
    assert_eq!(decode(&posts[0].body)?.payload["event"], "vcon_sent");
    Ok(())
}

/// A 202 records the `Location` to poll; a refusal and an unreachable
/// service record why. None of them undoes the delivery: the store already
/// accepted the container.
#[test]
fn a_registration_that_does_not_complete_is_recorded_and_delivery_stands() -> Result<(), TestError>
{
    let store = store()?;
    let accepted = Fake::start(|_| {
        answer(
            202,
            "Location: https://ts.example/entries/pending-1\r\nRetry-After: 5\r\n",
            b"",
        )
    })?;
    let rig = Rig::new(&store, &accepted, None)?;
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["a.vcon.json"]);
    let record = rig.record("a.vcon.json")?;
    assert_eq!(record["statements"][0]["status"], 202);
    assert_eq!(
        record["statements"][0]["location"],
        "https://ts.example/entries/pending-1"
    );
    assert!(record["statements"][0].get("receipt").is_none());
    assert!(
        record["statements"][0].get("error").is_none(),
        "a 202 registered"
    );

    // RFC 9290 Concise Problem Details: {-1: title, -2: detail}.
    let mut problem = Vec::new();
    ciborium::into_writer(
        &Cbor::Map(vec![
            (
                Cbor::Integer((-1).into()),
                Cbor::Text("Bad Signature Algorithm".into()),
            ),
            (
                Cbor::Integer((-2).into()),
                Cbor::Text("not supported".into()),
            ),
        ]),
        &mut problem,
    )?;
    let refusing = Fake::start(move |_| {
        answer(
            400,
            "Content-Type: application/concise-problem-details+cbor\r\n",
            &problem,
        )
    })?;
    let rig = Rig::new(&store, &refusing, None)?;
    rig.drop_in("b.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["b.vcon.json"]);
    let record = rig.record("b.vcon.json")?;
    let first = &record["statements"][0];
    assert_eq!(first["status"], 400);
    assert!(
        first["error"]
            .as_str()
            .is_some_and(|e| e.contains("Bad Signature Algorithm") && e.contains("not supported")),
    );
    assert!(first.get("receipt").is_none());

    // Nobody listening.
    let gone = Fake::start(|_| Vec::new())?;
    let mut rig = Rig::new(&store, &gone, None)?;
    if let Some(scitt) = rig.settings.scitt.as_mut() {
        scitt.url = Endpoint::parse("http://127.0.0.1:9/scitt")?;
    }
    rig.drop_in("c.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["c.vcon.json"]);
    let record = rig.record("c.vcon.json")?;
    assert!(record["statements"][0].get("status").is_none());
    assert!(
        record["statements"][0]["error"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
    );
    Ok(())
}

/// An `https://` transparency service is reached over TLS, trusting only
/// `--vcon-forward-scitt-ca`.
#[test]
fn an_https_service_is_trusted_by_its_own_ca() -> Result<(), TestError> {
    use rustls::pki_types::pem::PemObject;
    let pki = tls_pki::test_pki("vcon-scitt")?;
    let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let scrapi = Fake::start_with(
        |_| answer(201, "Location: https://ts.example/entries/e-1\r\n", RECEIPT),
        Some(Arc::new(server)),
    )?;
    let store = store()?;
    let mut rig = Rig::new(&store, &scrapi, None)?;
    if let Some(scitt) = rig.settings.scitt.as_mut() {
        scitt.url = Endpoint::parse(&format!("https://{}/scitt", scrapi.addr))?;
        scitt.ca = Some(PathBuf::from(&pki.ca_file));
    }
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["a.vcon.json"]);
    assert_eq!(scrapi.requests().len(), 2);
    let record = rig.record("a.vcon.json")?;
    assert_eq!(record["statements"][1]["status"], 201);
    Ok(())
}

/// The transparency service's auth header is sent to it and to nobody
/// else, and the store's never goes to it.
#[test]
fn each_service_gets_its_own_credential() -> Result<(), TestError> {
    let store = store()?;
    let scrapi = scrapi_201()?;
    let rig = Rig::new(&store, &scrapi, Some("X-Api-Key: scitt-key-value\n"))?;
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(scrapi.requests().len(), 2);
    for post in scrapi.requests() {
        assert_eq!(post.header("x-api-key"), Some("scitt-key-value"));
        assert_eq!(post.header("authorization"), None);
    }
    for post in store.requests() {
        assert_eq!(post.header("x-api-key"), None);
    }
    Ok(())
}

/// Run the `sipnab` binary.
fn sipnab(args: &[String]) -> Result<(String, Option<i32>), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("SIPNAB_VCON_FORWARD_AUTH")
        .output()?;
    Ok((
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    ))
}

/// The fixture key copied to `dir` with `mode`, and the chain beside it.
fn key_files(dir: &Path, mode: u32) -> Result<(PathBuf, PathBuf), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let key = dir.join("scitt.key");
    std::fs::copy(Path::new(FIXTURES).join("fake_grp.key"), &key)?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode))?;
    let cert = dir.join("scitt.crt");
    std::fs::write(&cert, chain_pem()?)?;
    Ok((key, cert))
}

/// The binary registers with the `[vcon_forward]` SCITT keys, and each flag
/// overrides its key.
#[test]
fn the_binary_registers_by_key_and_by_flag() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let store = store()?;
    let scrapi = scrapi_201()?;
    let dir = tempfile::tempdir()?;
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool)?;
    let auth = dir.path().join("auth");
    std::fs::write(&auth, "Authorization: Bearer store-token-value\n")?;
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600))?;
    let (key, cert) = key_files(dir.path(), 0o600)?;
    let config = dir.path().join("sipnab.toml");
    std::fs::write(
        &config,
        format!(
            "[vcon_forward]\nurl = \"{}\"\nauth_file = \"{}\"\nscitt_url = \"{}\"\n\
             scitt_sign_key = \"{}\"\nscitt_sign_cert = \"{}\"\nscitt_issuer = \"{ISSUER}\"\n",
            store.url("/v1/vcons"),
            auth.display(),
            scrapi.url("/by-key"),
            key.display(),
            cert.display()
        ),
    )?;
    std::fs::write(spool.join("a.vcon.json"), container(UUID, ""))?;
    let base = |more: &[String]| {
        let mut args: Vec<String> = vec![
            "--vcon-forward".into(),
            spool.display().to_string(),
            "--vcon-forward-once".into(),
            "--config".into(),
            config.display().to_string(),
        ];
        args.extend_from_slice(more);
        args
    };
    let (err, code) = sipnab(&base(&[]))?;
    assert_eq!(code, Some(0), "{err}");
    let posts = scrapi.requests();
    assert_eq!(posts.len(), 2, "{err}");
    assert!(posts.iter().all(|p| p.target == "/by-key/entries"));
    assert!(spool.join("delivered/a.vcon.json.scitt").exists());

    std::fs::write(spool.join("b.vcon.json"), container(UUID, ""))?;
    let (err, code) = sipnab(&base(&[
        "--vcon-forward-scitt-url".into(),
        scrapi.url("/by-flag"),
        "--vcon-forward-scitt-issuer".into(),
        "https://flag.example/".into(),
    ]))?;
    assert_eq!(code, Some(0), "{err}");
    let posts = scrapi.requests();
    assert_eq!(posts.len(), 4, "{err}");
    assert_eq!(posts[3].target, "/by-flag/entries");
    let statement = decode(&posts[3].body)?;
    let Some(Cbor::Map(claims)) = statement.header(15) else {
        return Err("no CWT Claims".into());
    };
    assert!(claims.iter().any(|(k, v)| k.as_integer() == Some(1.into())
        && v == &Cbor::Text("https://flag.example/".into())));
    Ok(())
}

/// The binary reaches an `https://` transparency service through
/// `--vcon-forward-scitt-ca`, and sends `--vcon-forward-scitt-auth-file`'s
/// header to it.
#[test]
fn the_binary_trusts_the_scitt_ca_and_sends_its_credential() -> Result<(), TestError> {
    use rustls::pki_types::pem::PemObject;
    use std::os::unix::fs::PermissionsExt;
    let pki = tls_pki::test_pki("vcon-scitt-bin")?;
    let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let scrapi = Fake::start_with(
        |_| answer(201, "Location: https://ts.example/entries/e-1\r\n", RECEIPT),
        Some(Arc::new(server)),
    )?;
    let store = store()?;
    let dir = tempfile::tempdir()?;
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool)?;
    let auth = dir.path().join("auth");
    std::fs::write(&auth, "Authorization: Bearer store-token-value\n")?;
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600))?;
    let scitt_auth = dir.path().join("scitt-auth");
    std::fs::write(&scitt_auth, "X-Api-Key: scitt-key-value\n")?;
    std::fs::set_permissions(&scitt_auth, std::fs::Permissions::from_mode(0o600))?;
    let (key, cert) = key_files(dir.path(), 0o600)?;
    std::fs::write(spool.join("a.vcon.json"), container(UUID, ""))?;
    let s = |p: &Path| p.display().to_string();
    let args = vec![
        "--vcon-forward".to_owned(),
        s(&spool),
        "--vcon-forward-url".into(),
        store.url("/v1/vcons"),
        "--vcon-forward-auth-file".into(),
        s(&auth),
        "--vcon-forward-once".into(),
        "--no-config".into(),
        "--vcon-forward-scitt-url".into(),
        format!("https://{}/scitt", scrapi.addr),
        "--vcon-forward-scitt-ca".into(),
        pki.ca_file.clone(),
        "--vcon-forward-scitt-auth-file".into(),
        s(&scitt_auth),
        "--vcon-forward-scitt-sign-key".into(),
        s(&key),
        "--vcon-forward-scitt-sign-cert".into(),
        s(&cert),
        "--vcon-forward-scitt-issuer".into(),
        ISSUER.into(),
    ];
    let (err, code) = sipnab(&args)?;
    assert_eq!(code, Some(0), "{err}");
    let posts = scrapi.requests();
    assert_eq!(posts.len(), 2, "{err}");
    assert!(
        posts
            .iter()
            .all(|p| p.header("x-api-key") == Some("scitt-key-value")),
    );
    assert!(
        !err.contains("scitt-key-value"),
        "the credential is not logged"
    );
    Ok(())
}

/// What the binary refuses before it sends anything, each naming the
/// setting: a SCITT setting without the URL, the URL without a key, a
/// certificate or an issuer, an issuer that is not a URI, and a key other
/// users can read.
#[test]
fn the_binary_refuses_an_incomplete_scitt_setup() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool)?;
    let auth = dir.path().join("auth");
    std::fs::write(&auth, "Authorization: Bearer store-token-value\n")?;
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600))?;
    let (key, cert) = key_files(dir.path(), 0o600)?;
    let open_dir = tempfile::tempdir()?;
    let (open_key, _) = key_files(open_dir.path(), 0o644)?;
    let s = |p: &Path| p.display().to_string();
    let base = vec![
        "--vcon-forward".to_owned(),
        s(&spool),
        "--vcon-forward-url".into(),
        "http://127.0.0.1:9/v1/vcons".into(),
        "--vcon-forward-auth-file".into(),
        s(&auth),
        "--vcon-forward-once".into(),
        "--no-config".into(),
    ];
    let full = |key: &Path, issuer: &str| {
        vec![
            "--vcon-forward-scitt-url".to_owned(),
            "http://127.0.0.1:9/scitt".into(),
            "--vcon-forward-scitt-sign-key".into(),
            s(key),
            "--vcon-forward-scitt-sign-cert".into(),
            s(&cert),
            "--vcon-forward-scitt-issuer".into(),
            issuer.into(),
        ]
    };
    let without = |flag: &str| {
        let mut args = full(&key, ISSUER);
        if let Some(i) = args.iter().position(|a| a == flag) {
            args.drain(i..i + 2);
        }
        args
    };
    let cases: Vec<(Vec<String>, &str)> = vec![
        (
            without("--vcon-forward-scitt-url"),
            "--vcon-forward-scitt-url",
        ),
        (
            without("--vcon-forward-scitt-sign-key"),
            "--vcon-forward-scitt-sign-key",
        ),
        (
            without("--vcon-forward-scitt-sign-cert"),
            "--vcon-forward-scitt-sign-cert",
        ),
        (
            without("--vcon-forward-scitt-issuer"),
            "--vcon-forward-scitt-issuer",
        ),
        (full(&key, "not a uri"), "URI"),
        (full(&open_key, ISSUER), "chmod 600"),
    ];
    for (extra, needle) in cases {
        let mut args = base.clone();
        args.extend(extra);
        let (err, code) = sipnab(&args)?;
        assert!(code.is_some_and(|c| c != 0), "{needle}: {err}");
        assert!(err.contains(needle), "{needle}: {err}");
    }
    Ok(())
}
