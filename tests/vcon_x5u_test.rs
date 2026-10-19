// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `x5u`: draft-ietf-vcon-vcon-core-04 section 5.2.2 has a signed vCon carry
//! "either the x5c or x5u", and x5u "MUST contain an [HTTPS] URL".
//!
//! - Writing: a `[[vcon.rule]]` `sign_cert_url` publishes an `x5u` beside the
//!   `x5c`; sipnab refuses a URL that is not `https://`.
//! - Reading: a container with `x5u` and no `x5c` has its chain fetched over
//!   HTTPS, only with `--vcon-x5u-ca`, within a size and time cap, and the
//!   signature verified against it. A URL that is not `https://` is refused.
//!
//! The HTTPS server runs in the test, on 127.0.0.1, under a CA the test
//! makes.
#![cfg(all(feature = "native", feature = "vcon"))]

#[path = "support/tls_pki.rs"]
mod tls_pki;

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine as _;
use sipnab::output::vcon_jose;

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL_ID: &str = "1-1966@10.0.2.20";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// An HTTPS server on 127.0.0.1 that answers every request with `status`
/// and `body`, counting the requests.
struct PemServer {
    addr: std::net::SocketAddr,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl PemServer {
    fn start(pki: &tls_pki::TestPki, body: Vec<u8>) -> Result<Self, TestError> {
        Self::start_answering(pki, "200 OK", body)
    }

    fn start_answering(
        pki: &tls_pki::TestPki,
        status: &'static str,
        body: Vec<u8>,
    ) -> Result<Self, TestError> {
        use rustls::pki_types::pem::PemObject;
        let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
            .collect::<Result<Vec<_>, _>>()?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, halt) = (hits.clone(), stop.clone());
        std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                let Ok((sock, _)) = listener.accept() else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                let _ = sock.set_nonblocking(false);
                let Ok(conn) = rustls::ServerConnection::new(config.clone()) else {
                    continue;
                };
                let mut stream = rustls::StreamOwned::new(conn, sock);
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                count.fetch_add(1, Ordering::SeqCst);
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/pem-certificate-chain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        Ok(Self { addr, hits, stop })
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.addr)
    }
}

impl Drop for PemServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn run(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()?)
}

/// The unsigned container sipnab writes for `CALL_ID`.
fn unsigned(home: &Path) -> Result<Vec<u8>, TestError> {
    let out_path = home.join("call.vcon.json");
    let out = run(
        home,
        &[
            "-N",
            "-I",
            CAPTURE,
            "--export-vcon",
            CALL_ID,
            "--vcon-out",
            out_path.to_str().ok_or("utf-8")?,
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned().into());
    }
    Ok(std::fs::read(out_path)?)
}

/// The fixture signing chain, PEM.
fn chain_pem() -> Result<String, TestError> {
    let mut pem = String::new();
    for name in ["fake_grp.crt", "fake_div.crt", "fake_ca_root.crt"] {
        pem.push_str(&std::fs::read_to_string(format!("{FIXTURES}/{name}"))?);
    }
    Ok(pem)
}

/// The signed form of the call, signed with the fixture key, with the
/// signature's `x5c` replaced by `x5u = url`. The signature covers only the
/// protected header and the payload, so it still verifies against the
/// chain the URL serves.
fn signed_by_url(home: &Path, url: &str) -> Result<PathBuf, TestError> {
    let unsigned = unsigned(home)?;
    let uuid = serde_json::from_slice::<serde_json::Value>(&unsigned)?["uuid"]
        .as_str()
        .ok_or("uuid")?
        .to_owned();
    let signer = vcon_jose::Signer::from_pem(
        &std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?,
        &chain_pem()?,
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&vcon_jose::sign(&unsigned, &uuid, &signer)?)?;
    let header = value["signatures"][0]["header"]
        .as_object_mut()
        .ok_or("header")?;
    header.remove("x5c");
    header.insert("x5u".into(), url.into());
    let path = home.join("signed-by-url.vcon.json");
    std::fs::write(&path, value.to_string())?;
    Ok(path)
}

/// `-I file --json-dialogs` with `extra`: whether the call was read, and the
/// run's standard error.
fn reads(home: &Path, file: &Path, extra: &[&str]) -> Result<(bool, String), TestError> {
    let mut args = vec![
        "-N",
        "--json-dialogs",
        "--quiet",
        "-I",
        file.to_str().ok_or("utf-8")?,
    ];
    args.extend_from_slice(extra);
    let out = run(home, &args)?;
    Ok((
        out.status.success() && String::from_utf8(out.stdout)?.contains(CALL_ID),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// With `--vcon-x5u-ca`, a container whose signature names its chain by an
/// HTTPS `x5u` is read: the chain is fetched and the signature verified
/// against it. Without the flag nothing is fetched and the container is
/// refused, naming the flag.
#[test]
fn an_x5u_chain_is_fetched_over_https_only_when_asked() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("x5u")?;
    let server = PemServer::start(&pki, chain_pem()?.into_bytes())?;
    let file = signed_by_url(home.path(), &server.url("/signer-chain.pem"))?;

    let (read, stderr) = reads(home.path(), &file, &[])?;
    assert!(!read, "{stderr}");
    assert!(stderr.contains("--vcon-x5u-ca"), "{stderr}");
    assert_eq!(server.hits.load(Ordering::SeqCst), 0, "fetched unasked");

    let (read, stderr) = reads(home.path(), &file, &["--vcon-x5u-ca", &pki.ca_file])?;
    assert!(read, "{stderr}");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

/// A chain that is not the signer's does not verify; a server the CA did
/// not issue is not trusted; an answer over the cap is refused; an `x5u`
/// that is not `https://` is refused before anything is fetched.
#[test]
fn an_x5u_that_cannot_be_trusted_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("x5u")?;
    let other = std::fs::read_to_string(format!("{FIXTURES}/other.crt"))?;
    let wrong = PemServer::start(&pki, other.into_bytes())?;
    let file = signed_by_url(home.path(), &wrong.url("/chain.pem"))?;
    let (read, stderr) = reads(home.path(), &file, &["--vcon-x5u-ca", &pki.ca_file])?;
    assert!(!read, "{stderr}");
    assert!(stderr.contains("does not verify"), "{stderr}");

    let stranger = tls_pki::test_pki("stranger")?;
    let (read, stderr) = reads(home.path(), &file, &["--vcon-x5u-ca", &stranger.ca_file])?;
    assert!(!read, "{stderr}");

    let huge = PemServer::start(&pki, vec![b'A'; 300 * 1024])?;
    let file = signed_by_url(home.path(), &huge.url("/chain.pem"))?;
    let (read, stderr) = reads(home.path(), &file, &["--vcon-x5u-ca", &pki.ca_file])?;
    assert!(!read, "{stderr}");
    assert!(stderr.contains("bytes"), "{stderr}");

    let file = signed_by_url(home.path(), &format!("http://{}/chain.pem", huge.addr))?;
    let before = huge.hits.load(Ordering::SeqCst);
    let (read, stderr) = reads(home.path(), &file, &["--vcon-x5u-ca", &pki.ca_file])?;
    assert!(!read, "{stderr}");
    assert!(stderr.contains("https"), "{stderr}");
    assert_eq!(
        huge.hits.load(Ordering::SeqCst),
        before,
        "fetched over http"
    );
    Ok(())
}

/// An `x5u` whose server answers anything but 2xx is no chain: the read is
/// refused, the refusal names the status and the URL, and the chain is not
/// tried.
#[test]
fn an_x5u_that_answers_an_error_status_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("x5u-404")?;
    let missing = PemServer::start_answering(&pki, "404 Not Found", b"no such chain".to_vec())?;
    let url = missing.url("/gone.pem");
    let file = signed_by_url(home.path(), &url)?;
    let (read, stderr) = reads(home.path(), &file, &["--vcon-x5u-ca", &pki.ca_file])?;
    assert!(!read, "{stderr}");
    assert!(stderr.contains("answered 404"), "{stderr}");
    assert!(stderr.contains(&url), "{stderr}");
    assert_eq!(missing.hits.load(Ordering::SeqCst), 1, "fetched once");
    Ok(())
}

/// A rule's `sign_cert_url` publishes an `x5u` beside the `x5c`; a URL that
/// is not `https://` is refused at startup.
#[test]
fn a_rule_publishes_sign_cert_url_as_x5u() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let key = home.path().join("signer.key");
    std::fs::copy(format!("{FIXTURES}/fake_grp.key"), &key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    let chain = home.path().join("chain.pem");
    std::fs::write(&chain, chain_pem()?)?;
    let dir = home.path().join("signed");
    let config = home.path().join("rules.toml");
    let write = |url: &str| -> Result<Output, TestError> {
        std::fs::write(
            &config,
            format!(
                "[[vcon.rule]]\nname = \"signed\"\nwhen = \"call_id == '{CALL_ID}'\"\ndir = \"{}\"\nsign_only = true\nsign_key = \"{}\"\nsign_cert = \"{}\"\nsign_cert_url = \"{url}\"\n",
                dir.display(),
                key.display(),
                chain.display()
            ),
        )?;
        run(
            home.path(),
            &[
                "-N",
                "-I",
                CAPTURE,
                "--no-cli-print",
                "--config",
                config.to_str().ok_or("utf-8")?,
            ],
        )
    };
    let out = write("https://pki.example.com/vcon-signer.pem")?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let file = std::fs::read_dir(&dir)?
        .next()
        .ok_or("no container")??
        .path();
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
    let header = &value["signatures"][0]["header"];
    assert_eq!(header["x5u"], "https://pki.example.com/vcon-signer.pem");
    assert!(header["x5c"].is_array(), "x5c stays beside x5u");
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
        value["signatures"][0]["protected"]
            .as_str()
            .ok_or("protected")?,
    )?;
    assert!(!String::from_utf8(protected)?.contains("x5u"));

    std::fs::remove_dir_all(&dir)?;
    std::fs::write(
        &config,
        format!(
            "[[vcon.rule]]\nname = \"signed\"\nwhen = \"call_id == '{CALL_ID}'\"\ndir = \"{}\"\nsign_cert_url = \"https://pki.example.com/vcon-signer.pem\"\n",
            dir.display()
        ),
    )?;
    let out = run(
        home.path(),
        &[
            "-N",
            "-I",
            CAPTURE,
            "--no-cli-print",
            "--config",
            config.to_str().ok_or("utf-8")?,
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("sign_cert_url without a signing key"),
        "{stderr}"
    );
    assert!(!dir.exists());

    let out = write("http://pki.example.com/vcon-signer.pem")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("sign_cert_url"), "{stderr}");
    assert!(stderr.contains("https"), "{stderr}");
    assert!(!dir.exists());
    Ok(())
}
