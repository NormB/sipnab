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
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// When the request's head had been read.
    at: Instant,
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
    let at = Instant::now();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or_default().to_owned();
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
        method,
        target,
        headers,
        body,
        at,
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
        let key = std::fs::read_to_string(Path::new(FIXTURES).join("fake_grp.key"))?;
        Self::signed_by(store, scrapi, scitt_auth, &key, &chain_pem()?)
    }

    /// [`Rig::new`] with the statements signed by `key` (PEM) under
    /// `chain` (PEM, leaf first).
    fn signed_by(
        store: &Fake,
        scrapi: &Fake,
        scitt_auth: Option<&str>,
        key: &str,
        chain: &str,
    ) -> Result<Self, TestError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let spool = dir.path().join("spool");
        std::fs::create_dir(&spool)?;
        let auth_file = dir.path().join("auth");
        std::fs::write(&auth_file, "Authorization: Bearer store-token-value\n")?;
        std::fs::set_permissions(&auth_file, std::fs::Permissions::from_mode(0o600))?;
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
            url: Endpoint::parse(
                &store.url("/v1/vcons"),
                sipnab::app::https_client::UrlUse::FORWARDER,
            )?,
            replace_url: None,
            auth: AuthHeader::read_file(&auth_file)?,
            timeout: Duration::from_secs(5),
            ca: None,
            extra_ca: None,
            kind: StoreKind::Generic,
            backoff: BackoffPolicy::default(),
            limits: ReadLimits::default(),
            content_type: "application/json".into(),
            scitt: Some(ScittSettings {
                url: Endpoint::parse(
                    &scrapi.url("/scitt"),
                    sipnab::app::https_client::UrlUse::FORWARDER_SCITT,
                )?,
                auth,
                ca: None,
                signer: Arc::new(ScittSigner::from_pem(key, chain)?),
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
    let (to_be_signed, signature, statement) = open(bytes)?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        public_key()?,
    )
    .verify(&to_be_signed, &signature)
    .map_err(|_| "the RS256 signature does not verify")?;
    Ok(statement)
}

/// Decode `bytes` as a COSE_Sign1 and verify its ES256 signature, the
/// 64-byte `r || s` of
/// [RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1),
/// with the uncompressed P-256 point `point`.
fn decode_es256(bytes: &[u8], point: &[u8]) -> Result<Statement, TestError> {
    let (to_be_signed, signature, statement) = open(bytes)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(&to_be_signed, &signature)
        .map_err(|_| "the ES256 signature does not verify")?;
    Ok(statement)
}

/// A COSE_Sign1's Sig_structure, its signature, and the statement it
/// carries, not yet verified.
fn open(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Statement), TestError> {
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
    let Cbor::Map(protected) = ciborium::from_reader(protected.as_slice())? else {
        return Err("the protected header is not a map".into());
    };
    Ok((
        to_be_signed,
        signature.clone(),
        Statement {
            protected,
            payload: serde_json::from_slice(payload)?,
        },
    ))
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
        scitt.url = Endpoint::parse(
            "http://127.0.0.1:9/scitt",
            sipnab::app::https_client::UrlUse::FORWARDER_SCITT,
        )?;
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
        scitt.url = Endpoint::parse(
            &format!("https://{}/scitt", scrapi.addr),
            sipnab::app::https_client::UrlUse::FORWARDER_SCITT,
        )?;
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

/// The URL of `path` on the origin `req` reached: the request's `Host`.
fn own(req: &Recorded, path: &str) -> String {
    format!("http://{}{path}", req.header("host").unwrap_or_default())
}

/// The requests of each registration: a POST and the GETs after it.
fn by_registration(requests: &[Recorded]) -> Vec<Vec<Recorded>> {
    let mut out: Vec<Vec<Recorded>> = Vec::new();
    for req in requests {
        if req.method == "POST" || out.is_empty() {
            out.push(Vec::new());
        }
        if let Some(last) = out.last_mut() {
            last.push(req.clone());
        }
    }
    out
}

/// A 202 is followed by GETs on its `Location`
/// ([draft-ietf-scitt-scrapi-11 section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2.4)):
/// a 204 (section 2.4.2) or a 202 means the registration is still running,
/// and a 200 (section 2.4.1) carries the receipt, which the record keeps as
/// it keeps a 201's. The wait after a `Retry-After` is at least that long
/// (section 5.1), and each GET carries the service's credential and
/// `Accept: application/cose`.
#[test]
fn a_202_is_polled_until_the_receipt_arrives() -> Result<(), TestError> {
    use std::sync::atomic::AtomicUsize;
    let store = store()?;
    let gets = Arc::new(AtomicUsize::new(0));
    let seen = gets.clone();
    let scrapi = Fake::start(move |req| {
        if req.method == "POST" {
            seen.store(0, Ordering::SeqCst);
            return answer(
                202,
                &format!("Location: {}\r\n", own(req, "/scitt/entries/e-1")),
                b"",
            );
        }
        match seen.fetch_add(1, Ordering::SeqCst) {
            0 => answer(204, "Retry-After: 1\r\nCache-Control: no-store\r\n", b""),
            1 => answer(202, "", b""),
            _ => answer(200, "Content-Type: application/cose\r\n", RECEIPT),
        }
    })?;
    let rig = Rig::new(&store, &scrapi, Some("X-Api-Key: scitt-key-value\n"))?;
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["a.vcon.json"]);

    let registrations = by_registration(&scrapi.requests());
    assert_eq!(registrations.len(), 2, "vcon_created and vcon_sent");
    for requests in &registrations {
        let shape: Vec<(&str, &str)> = requests
            .iter()
            .map(|r| (r.method.as_str(), r.target.as_str()))
            .collect();
        assert_eq!(
            shape,
            [
                ("POST", "/scitt/entries"),
                ("GET", "/scitt/entries/e-1"),
                ("GET", "/scitt/entries/e-1"),
                ("GET", "/scitt/entries/e-1"),
            ]
        );
        for get in &requests[1..] {
            assert_eq!(get.header("accept"), Some("application/cose"));
            assert_eq!(get.header("x-api-key"), Some("scitt-key-value"));
            assert!(get.body.is_empty());
        }
        let waited = requests[2].at.duration_since(requests[1].at);
        assert!(
            waited >= Duration::from_secs(1),
            "Retry-After: 1 is a minimum; waited {waited:?}"
        );
    }

    use base64::Engine as _;
    let record = rig.record("a.vcon.json")?;
    for s in record["statements"].as_array().ok_or("statements")? {
        assert_eq!(s["status"], 202);
        assert_eq!(s["poll_status"], 200);
        assert_eq!(
            s["receipt"],
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(RECEIPT)
        );
        assert!(
            s["location"]
                .as_str()
                .is_some_and(|l| l.ends_with("/scitt/entries/e-1"))
        );
        assert!(s.get("pending").is_none(), "{s}");
        assert!(s.get("error").is_none(), "{s}");
        assert!(s.get("poll_error").is_none(), "{s}");
    }
    Ok(())
}

/// Polling ends when the forwarder timeout runs out: the record says the
/// receipt is pending and keeps the `Location`, and the delivery stands.
/// A `Retry-After` longer than the time left ends it at once, and without
/// one the waits grow (section 5.1: "exponential backoff with jitter").
#[test]
fn polling_ends_at_the_timeout_and_leaves_the_receipt_pending() -> Result<(), TestError> {
    let budget = Duration::from_secs(2);
    let slack = Duration::from_millis(700);
    let store = store()?;
    for (case, post_retry, get_retry) in [
        ("Retry-After: 1 on each 204", "", "Retry-After: 1\r\n"),
        ("no Retry-After", "", ""),
        ("Retry-After: 3600 on the 202", "Retry-After: 3600\r\n", ""),
    ] {
        let scrapi = Fake::start(move |req| {
            if req.method == "POST" {
                answer(
                    202,
                    &format!(
                        "Location: {}\r\n{post_retry}",
                        own(req, "/scitt/entries/e-1")
                    ),
                    b"",
                )
            } else {
                answer(204, get_retry, b"")
            }
        })?;
        let mut rig = Rig::new(&store, &scrapi, None)?;
        rig.settings.timeout = budget;
        rig.drop_in("a.vcon.json", &container(UUID, ""))?;
        let started = Instant::now();
        let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
        let took = started.elapsed();
        assert_eq!(report.delivered, ["a.vcon.json"], "{case}");
        assert!(took < (budget + slack) * 2, "{case}: took {took:?}");

        let registrations = by_registration(&scrapi.requests());
        assert_eq!(registrations.len(), 2, "{case}");
        for requests in &registrations {
            let last = requests.last().ok_or("no request")?;
            let window = last.at.duration_since(requests[0].at);
            // The last GET is sent before the timeout runs out; the fake
            // records it once it has read the request.
            assert!(
                window <= budget + Duration::from_millis(100),
                "{case}: polled for {window:?}"
            );
            let gets = requests.len() - 1;
            match case {
                "Retry-After: 3600 on the 202" => assert_eq!(gets, 0, "{case}"),
                "Retry-After: 1 on each 204" => {
                    assert!((1..=2).contains(&gets), "{case}: {gets}");
                }
                _ => {
                    assert!(gets >= 3, "{case}: {gets} GETs");
                    assert!(gets <= 20, "{case}: {gets} GETs is not a backoff");
                    let first = requests[2].at.duration_since(requests[1].at);
                    let later = last.at.duration_since(requests[requests.len() - 2].at);
                    assert!(later > first, "{case}: waits {first:?} then {later:?}");
                }
            }
        }
        let record = rig.record("a.vcon.json")?;
        for s in record["statements"].as_array().ok_or("statements")? {
            assert_eq!(s["status"], 202, "{case}");
            assert_eq!(s["pending"], true, "{case}: {s}");
            assert!(
                s["location"]
                    .as_str()
                    .is_some_and(|l| l.ends_with("/scitt/entries/e-1")),
                "{case}: {s}"
            );
            assert!(s.get("receipt").is_none(), "{case}: {s}");
            assert!(s.get("error").is_none(), "{case}: {s}");
        }
    }
    Ok(())
}

/// A `Location` on another origin (scheme, host or port) than the service
/// URL is never fetched: the record says it was refused, and keeps it.
#[test]
fn a_location_on_another_origin_is_never_polled() -> Result<(), TestError> {
    let store = store()?;
    let elsewhere = Fake::start(|_| answer(200, "", RECEIPT))?;
    let other_port = format!("http://{}/scitt/entries/e-1", elsewhere.addr);
    for (case, location) in [
        ("another port", other_port.clone()),
        (
            "another scheme",
            "https://{host}/scitt/entries/e-1".to_owned(),
        ),
        (
            "another host",
            "http://localhost:{port}/scitt/entries/e-1".to_owned(),
        ),
        (
            "another host and scheme",
            "https://ts.example/entries/e-1".to_owned(),
        ),
    ] {
        let template = location.clone();
        let scrapi = Fake::start(move |req| {
            let host = req.header("host").unwrap_or_default().to_owned();
            let port = host.rsplit(':').next().unwrap_or_default().to_owned();
            let location = template.replace("{host}", &host).replace("{port}", &port);
            if req.method == "POST" {
                answer(202, &format!("Location: {location}\r\n"), b"")
            } else {
                answer(200, "", RECEIPT)
            }
        })?;
        let rig = Rig::new(&store, &scrapi, Some("X-Api-Key: scitt-key-value\n"))?;
        rig.drop_in("a.vcon.json", &container(UUID, ""))?;
        let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
        assert_eq!(report.delivered, ["a.vcon.json"], "{case}");
        assert!(
            scrapi.requests().iter().all(|r| r.method == "POST"),
            "{case}: the service's own origin got a GET"
        );
        let record = rig.record("a.vcon.json")?;
        for s in record["statements"].as_array().ok_or("statements")? {
            assert_eq!(s["status"], 202, "{case}");
            assert!(s["location"].as_str().is_some(), "{case}: {s}");
            assert!(
                s["poll_error"]
                    .as_str()
                    .is_some_and(|e| e.contains("origin")),
                "{case}: {s}"
            );
            assert!(s.get("receipt").is_none(), "{case}: {s}");
            assert!(s.get("error").is_none(), "{case}: {s}");
        }
    }
    assert!(
        elsewhere.requests().is_empty(),
        "another origin was sent a request"
    );
    Ok(())
}

/// A 404 while polling is a registration that failed
/// ([section 2.4.3](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2.4.3)):
/// the record carries the problem's title and detail as the error, and the
/// delivery stands.
#[test]
fn a_registration_that_fails_while_polled_records_why() -> Result<(), TestError> {
    let mut problem = Vec::new();
    ciborium::into_writer(
        &Cbor::Map(vec![
            (
                Cbor::Integer((-1).into()),
                Cbor::Text("Registration Failed".into()),
            ),
            (
                Cbor::Integer((-2).into()),
                Cbor::Text("could not be persisted".into()),
            ),
        ]),
        &mut problem,
    )?;
    let store = store()?;
    let scrapi = Fake::start(move |req| {
        if req.method == "POST" {
            answer(
                202,
                &format!("Location: {}\r\n", own(req, "/scitt/entries/e-1")),
                b"",
            )
        } else {
            answer(
                404,
                "Content-Type: application/concise-problem-details+cbor\r\n",
                &problem,
            )
        }
    })?;
    let rig = Rig::new(&store, &scrapi, None)?;
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["a.vcon.json"]);
    let record = rig.record("a.vcon.json")?;
    for s in record["statements"].as_array().ok_or("statements")? {
        assert_eq!(s["poll_status"], 404);
        assert!(
            s["error"].as_str().is_some_and(
                |e| e.contains("Registration Failed") && e.contains("could not be persisted")
            ),
            "{s}"
        );
        assert!(s.get("pending").is_none(), "{s}");
        assert!(s.get("receipt").is_none(), "{s}");
    }
    Ok(())
}

/// A stop asked for while a receipt is polled ends the polling at once,
/// and nothing more is sent: the record says the receipt is pending and
/// that the next statement was not sent.
#[test]
fn a_stop_ends_polling_and_sends_nothing_more() -> Result<(), TestError> {
    let store = store()?;
    let stop = Arc::new(AtomicBool::new(false));
    let asked = stop.clone();
    let scrapi = Fake::start(move |req| {
        if req.method == "POST" {
            answer(
                202,
                &format!("Location: {}\r\n", own(req, "/scitt/entries/e-1")),
                b"",
            )
        } else {
            asked.store(true, Ordering::SeqCst);
            answer(204, "Retry-After: 20\r\n", b"")
        }
    })?;
    let mut rig = Rig::new(&store, &scrapi, None)?;
    rig.settings.timeout = Duration::from_secs(60);
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    let started = Instant::now();
    let stopped = || stop.load(Ordering::SeqCst);
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &stopped);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(report.delivered, ["a.vcon.json"]);
    let posts = scrapi
        .requests()
        .iter()
        .filter(|r| r.method == "POST")
        .count();
    assert_eq!(posts, 1, "nothing is sent after the stop");
    let record = rig.record("a.vcon.json")?;
    let first = &record["statements"][0];
    assert_eq!(first["pending"], true, "{first}");
    assert!(
        first["poll_error"]
            .as_str()
            .is_some_and(|e| e.contains("stop")),
        "{first}"
    );
    let second = &record["statements"][1];
    assert_eq!(second["event"], "vcon_sent");
    assert!(second.get("status").is_none(), "{second}");
    assert!(
        second["error"].as_str().is_some_and(|e| e.contains("stop")),
        "{second}"
    );
    Ok(())
}

/// A fresh EC P-256 key (PKCS #8 PEM) and its self-signed certificate (PEM).
fn ec_identity() -> Result<(String, String), TestError> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "scitt ec signer test");
    let cert = params.self_signed(&key)?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// The uncompressed P-256 point in a certificate's SubjectPublicKeyInfo,
/// found by the fixed DER of an id-ecPublicKey prime256v1 key
/// ([RFC 5480 section 2](https://www.rfc-editor.org/rfc/rfc5480.html#section-2)):
/// SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04||x||y }.
fn p256_point(certificate: &[u8]) -> Result<Vec<u8>, TestError> {
    const SPKI_HEAD: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let at = certificate
        .windows(SPKI_HEAD.len())
        .position(|w| w == SPKI_HEAD)
        .ok_or("no P-256 SubjectPublicKeyInfo in the certificate")?;
    let point = certificate
        .get(at + SPKI_HEAD.len()..at + SPKI_HEAD.len() + 65)
        .ok_or("the point is cut short")?;
    assert_eq!(point.first(), Some(&0x04), "an uncompressed point");
    Ok(point.to_vec())
}

/// An EC P-256 signing key signs ES256: `alg` -7
/// ([RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1))
/// in the protected header, and the signature verifies with the public key
/// of the certificate the statement carries in `x5chain`, which is the
/// signing certificate. The RSA fixture key keeps RS256 (-257), which
/// `a_delivery_registers_created_and_sent` checks.
#[test]
fn an_ec_signing_key_signs_es256() -> Result<(), TestError> {
    let store = store()?;
    let scrapi = scrapi_201()?;
    let (key, cert) = ec_identity()?;
    let rig = Rig::signed_by(&store, &scrapi, None, &key, &cert)?;
    rig.drop_in("a.vcon.json", &container(UUID, ""))?;
    let report = Forwarder::new(rig.settings.clone())?.pass(Instant::now(), &never);
    assert_eq!(report.delivered, ["a.vcon.json"]);
    let posts = scrapi.requests();
    assert_eq!(posts.len(), 2);
    let leaf = ders(&cert)?.remove(0);
    let point = p256_point(&leaf)?;
    for post in &posts {
        let statement = decode_es256(&post.body, &point)?;
        assert_eq!(statement.header(1), Some(&Cbor::Integer((-7).into())));
        assert_eq!(statement.header(33), Some(&Cbor::Bytes(leaf.clone())));
    }
    assert!(decode(&posts[0].body).is_err(), "not an RS256 signature");
    Ok(())
}

/// A signing key that its certificate does not match is refused at start,
/// exit 2, naming both flags: an EC key with an RSA certificate, and an RSA
/// key with an EC certificate. A matching EC pair runs and signs ES256.
#[test]
fn the_binary_refuses_a_key_its_certificate_does_not_match() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool)?;
    let auth = dir.path().join("auth");
    std::fs::write(&auth, "Authorization: Bearer store-token-value\n")?;
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600))?;
    let (rsa_key, rsa_cert) = key_files(dir.path(), 0o600)?;
    let (ec_key_pem, ec_cert_pem) = ec_identity()?;
    let ec_key = dir.path().join("ec.key");
    std::fs::write(&ec_key, ec_key_pem)?;
    std::fs::set_permissions(&ec_key, std::fs::Permissions::from_mode(0o600))?;
    let ec_cert = dir.path().join("ec.crt");
    std::fs::write(&ec_cert, &ec_cert_pem)?;
    let store = store()?;
    let scrapi = scrapi_201()?;
    let s = |p: &Path| p.display().to_string();
    let args = |key: &Path, cert: &Path| {
        vec![
            "--vcon-forward".to_owned(),
            s(&spool),
            "--vcon-forward-url".into(),
            store.url("/v1/vcons"),
            "--vcon-forward-auth-file".into(),
            s(&auth),
            "--vcon-forward-once".into(),
            "--no-config".into(),
            "--vcon-forward-scitt-url".into(),
            scrapi.url("/scitt"),
            "--vcon-forward-scitt-sign-key".into(),
            s(key),
            "--vcon-forward-scitt-sign-cert".into(),
            s(cert),
            "--vcon-forward-scitt-issuer".into(),
            ISSUER.into(),
        ]
    };
    for (case, key, cert) in [
        ("EC key, RSA certificate", &ec_key, &rsa_cert),
        ("RSA key, EC certificate", &rsa_key, &ec_cert),
    ] {
        let (err, code) = sipnab(&args(key, cert))?;
        assert_eq!(code, Some(2), "{case}: {err}");
        for needle in [
            "--vcon-forward-scitt-sign-key",
            "--vcon-forward-scitt-sign-cert",
            "does not match",
        ] {
            assert!(err.contains(needle), "{case}: {needle}: {err}");
        }
    }
    assert!(scrapi.requests().is_empty(), "nothing was sent");

    std::fs::write(spool.join("a.vcon.json"), container(UUID, ""))?;
    let (err, code) = sipnab(&args(&ec_key, &ec_cert))?;
    assert_eq!(code, Some(0), "{err}");
    let point = p256_point(&ders(&ec_cert_pem)?.remove(0))?;
    let posts = scrapi.requests();
    assert_eq!(posts.len(), 2, "{err}");
    for post in &posts {
        let statement = decode_es256(&post.body, &point)?;
        assert_eq!(statement.header(1), Some(&Cbor::Integer((-7).into())));
    }
    Ok(())
}
