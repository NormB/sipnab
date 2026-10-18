// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--vcon-audio-fetch`: the audio a `[[vcon.rule]]` with `audio = "url"`
//! wrote beside its container, read back on the shipped binary.
//!
//! Each test makes its containers from a real capture with two rules, one
//! plain and one encrypting, the way `vcon_encrypt_rules_test.rs` does. The
//! audio is served from a stub HTTPS server this file runs on `127.0.0.1`,
//! or read beside the container with `--vcon-audio-fetch-local`. No test
//! contacts the internet.
//!
//! What is checked: the bytes written are the WAV the plain rule wrote for
//! the same call; the `content_hash` of draft-ietf-vcon-vcon-core-04
//! section 2.2 is checked before anything is decrypted; a wrong key, a plain
//! `http://` URL and an output that exists are refused, and nothing is
//! written.
#![cfg(all(feature = "native", feature = "vcon", unix))]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use sipnab::output::vcon_jose;

#[path = "support/tls_pki.rs"]
mod tls_pki;

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL: &str = "call_id == '1-1966@10.0.2.20'";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// `name` from the JOSE fixtures, copied to `home` with mode 0600: sipnab
/// refuses a key other users can read, and git checks the fixture out 0644.
fn private_copy(home: &Path, name: &str) -> Result<PathBuf, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = home.join(name);
    std::fs::copy(format!("{FIXTURES}/{name}"), &path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// The signing chain, leaf first, as one PEM file in `home`.
fn chain(home: &Path) -> Result<PathBuf, TestError> {
    let path = home.join("chain.pem");
    let mut pem = String::new();
    for name in ["fake_grp.crt", "fake_div.crt", "fake_ca_root.crt"] {
        pem.push_str(&std::fs::read_to_string(format!("{FIXTURES}/{name}"))?);
    }
    std::fs::write(&path, pem)?;
    Ok(path)
}

/// `sha512-` and the base64url SHA-512 of `bytes`.
fn hash_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    format!(
        "sha512-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha512::digest(bytes))
    )
}

/// What one capture run wrote: the plain rule's container and WAV, and the
/// encrypting rule's container and JWE audio file.
struct Made {
    plain_container: PathBuf,
    plain_wav: PathBuf,
    sealed_container: PathBuf,
    sealed_audio: PathBuf,
}

/// Run the capture with a plain and an encrypting `audio = "url"` rule,
/// both naming `base` as their `audio_url_base`.
fn make(home: &Path, base: &str) -> Result<Made, TestError> {
    let (plain, sealed) = (home.join("plain"), home.join("sealed"));
    let config = format!(
        "[[vcon.rule]]\nname = \"plain\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n\
         audio_url_base = \"{base}\"\n\n\
         [[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n\
         audio_url_base = \"{base}\"\nencrypt_to = \"{FIXTURES}/fake_grp.crt\"\n\
         sign_key = \"{}\"\nsign_cert = \"{}\"\n",
        plain.display(),
        sealed.display(),
        private_copy(home, "fake_grp.key")?.display(),
        chain(home)?.display()
    );
    let path = home.join("rules.toml");
    std::fs::write(&path, config)?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print"])
        .arg("--config")
        .arg(&path)
        .env("HOME", home)
        .output()?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned().into());
    }
    let pick = |dir: &Path, suffix: &str| -> Result<PathBuf, TestError> {
        let found: Vec<PathBuf> = std::fs::read_dir(dir)?
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|p| p.to_string_lossy().ends_with(suffix))
            .collect();
        match found.as_slice() {
            [one] => Ok(one.clone()),
            other => {
                Err(format!("{} files ending {suffix} in {}", other.len(), dir.display()).into())
            }
        }
    };
    Ok(Made {
        plain_container: pick(&plain, ".vcon.json")?,
        plain_wav: pick(&plain, ".wav")?,
        sealed_container: pick(&sealed, ".vcon.json")?,
        sealed_audio: pick(&sealed, ".wav.jwe")?,
    })
}

/// The unsigned container inside the sealed one, opened with the fixture key.
fn opened(sealed: &Path) -> Result<serde_json::Value, TestError> {
    let key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    let unsigned = vcon_jose::verify(&vcon_jose::decrypt(&std::fs::read(sealed)?, &key)?)?;
    Ok(serde_json::from_slice(&unsigned)?)
}

/// The container's uuid and the index of its one recording with a `url`.
fn uuid_and_index(container: &serde_json::Value) -> Result<(String, usize), TestError> {
    let uuid = container["uuid"].as_str().ok_or("uuid")?.to_string();
    let index = container["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .position(|d| d["url"].is_string())
        .ok_or("a recording with a url")?;
    Ok((uuid, index))
}

/// The file the command writes for `container`'s recording.
fn expected_out(
    out: &Path,
    container: &serde_json::Value,
    ext: &str,
) -> Result<PathBuf, TestError> {
    let (uuid, index) = uuid_and_index(container)?;
    Ok(out.join(format!("{uuid}-dialog{index}.{ext}")))
}

/// Run `sipnab --no-config` with `args`.
fn sipnab(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--no-config")
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("SIPNAB_LOG", "info")
        .output()?)
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap_or_default()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Every file in `dir`, or none when it does not exist.
fn listing(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|it| it.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default()
}

/// A stub server on `127.0.0.1`, HTTPS with `tls` or plain HTTP without,
/// that answers `GET <anything>/<name>` with the file `<name>` in `root`, or
/// 404, and records each request target.
struct Stub {
    port: u16,
    targets: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Stub {
    fn start(root: PathBuf, tls: Option<Arc<rustls::ServerConfig>>) -> Result<Self, TestError> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, halt) = (targets.clone(), stop.clone());
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
                                    serve(&mut rustls::StreamOwned::new(conn, sock), &root, &log)
                                }),
                            None => serve(&mut { sock }, &root, &log),
                        };
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Ok(Self {
            port,
            targets,
            stop,
        })
    }

    fn https(root: PathBuf, pki: &tls_pki::TestPki) -> Result<Self, TestError> {
        use rustls::pki_types::pem::PemObject;
        let chain = rustls::pki_types::CertificateDer::pem_file_iter(&pki.cert)?
            .collect::<Result<Vec<_>, _>>()?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&pki.key)?;
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
        Self::start(root, Some(Arc::new(server)))
    }

    fn targets(&self) -> Vec<String> {
        self.targets.lock().clone()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Answer one request on `stream`.
fn serve(
    stream: &mut (impl std::io::Read + Write),
    root: &Path,
    log: &Mutex<Vec<String>>,
) -> Result<(), TestError> {
    let mut reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let target = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
    }
    drop(reader);
    log.lock().push(target.clone());
    let name = target.rsplit('/').next().unwrap_or_default();
    match std::fs::read(root.join(name)) {
        Ok(body) => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(&body)?;
        }
        Err(_) => stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?,
    }
    stream.flush()?;
    Ok(())
}

fn mode_of(path: &Path) -> Result<u32, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
}

// ── Fetched, checked, decrypted ─────────────────────────────────────────

/// The sealed container's recording, fetched over HTTPS from the URL it
/// names, trusting the CA named, its hash checked, decrypted with
/// `--vcon-key`: the WAV written is the plain rule's WAV byte for byte,
/// mode 0600, at `<uuid>-dialog<N>.wav`.
#[test]
fn a_sealed_container_s_audio_is_fetched_over_https_and_decrypted() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("audio-fetch")?;
    let served = home.path().join("sealed");
    let stub = Stub::https(served, &pki)?;
    let made = make(
        home.path(),
        &format!("https://127.0.0.1:{}/calls", stub.port),
    )?;
    let out = home.path().join("out");
    let key = home.path().join("fake_grp.key");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.sealed_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-ca",
            &pki.ca_file,
            "--vcon-key",
            s(&key),
        ],
    )?;
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    let expected = expected_out(&out, &opened(&made.sealed_container)?, "wav")?;
    assert_eq!(listing(&out), vec![expected.clone()], "one file");
    assert_eq!(
        std::fs::read(&expected)?,
        std::fs::read(&made.plain_wav)?,
        "the same WAV"
    );
    assert_eq!(mode_of(&expected)?, 0o600);
    let name = made
        .sealed_audio
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name")?;
    assert_eq!(stub.targets(), vec![format!("/calls/{name}")]);
    Ok(())
}

/// Without the CA, the stub's certificate is not trusted and nothing is
/// written.
#[test]
fn an_https_server_the_ca_did_not_issue_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("audio-fetch")?;
    let stub = Stub::https(home.path().join("plain"), &pki)?;
    let made = make(
        home.path(),
        &format!("https://127.0.0.1:{}/calls", stub.port),
    )?;
    let out = home.path().join("out");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.plain_container),
            "--vcon-audio-fetch-out",
            s(&out),
        ],
    )?;
    assert_eq!(run.status.code(), Some(1), "{}", stderr(&run));
    assert!(listing(&out).is_empty(), "{:?}", listing(&out));
    Ok(())
}

/// `--vcon-audio-fetch-extra-ca` trusts the named CA beside the host's
/// bundle, and `--vcon-audio-fetch-max-size` below the file's size refuses
/// it: nothing is written.
#[test]
fn extra_ca_trusts_the_server_and_max_size_refuses_a_larger_file() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("audio-fetch")?;
    let stub = Stub::https(home.path().join("plain"), &pki)?;
    let made = make(
        home.path(),
        &format!("https://127.0.0.1:{}/calls", stub.port),
    )?;
    let wav_len = std::fs::metadata(&made.plain_wav)?.len();
    let small = (wav_len - 1).to_string();
    let small_out = home.path().join("small");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.plain_container),
            "--vcon-audio-fetch-out",
            s(&small_out),
            "--vcon-audio-fetch-extra-ca",
            &pki.ca_file,
            "--vcon-audio-fetch-max-size",
            &small,
        ],
    )?;
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(1), "{err}");
    assert!(err.contains("--vcon-audio-fetch-max-size"), "{err}");
    assert!(listing(&small_out).is_empty());

    let out = home.path().join("out");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.plain_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-extra-ca",
            &pki.ca_file,
            "--vcon-audio-fetch-max-size",
            &wav_len.to_string(),
        ],
    )?;
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    let container: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&made.plain_container)?)?;
    assert_eq!(
        std::fs::read(expected_out(&out, &container, "wav")?)?,
        std::fs::read(&made.plain_wav)?
    );
    Ok(())
}

/// The plain container's recording, an unencrypted WAV, fetched over HTTPS
/// and checked by its hash: the bytes written are the file served.
#[test]
fn an_unencrypted_url_wav_is_fetched_and_checked() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pki = tls_pki::test_pki("audio-fetch")?;
    let stub = Stub::https(home.path().join("plain"), &pki)?;
    let made = make(
        home.path(),
        &format!("https://127.0.0.1:{}/calls", stub.port),
    )?;
    let out = home.path().join("out");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.plain_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-ca",
            &pki.ca_file,
        ],
    )?;
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    let container: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&made.plain_container)?)?;
    let expected = expected_out(&out, &container, "wav")?;
    let wav = std::fs::read(&expected)?;
    assert_eq!(wav, std::fs::read(&made.plain_wav)?);
    let (_, index) = uuid_and_index(&container)?;
    assert_eq!(container["dialog"][index]["content_hash"], hash_of(&wav));
    Ok(())
}

/// `--vcon-audio-fetch-local` reads the file beside the container, by the
/// last segment of the URL, for a spool the storage has not served yet.
#[test]
fn local_reads_the_file_beside_the_container() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    let out = home.path().join("out");
    let key = home.path().join("fake_grp.key");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.sealed_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
            "--vcon-key",
            s(&key),
        ],
    )?;
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    let expected = expected_out(&out, &opened(&made.sealed_container)?, "wav")?;
    assert_eq!(std::fs::read(&expected)?, std::fs::read(&made.plain_wav)?);
    Ok(())
}

// ── Refused ─────────────────────────────────────────────────────────────

/// Flip one byte in the middle of `path`.
fn tamper(path: &Path) -> Result<(), TestError> {
    let mut bytes = std::fs::read(path)?;
    let mid = bytes.len() / 2;
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    std::fs::write(path, bytes)?;
    Ok(())
}

/// A JWE audio file changed after it was written fails the `content_hash`
/// check, which names the dialog, before any decryption: nothing is written.
#[test]
fn a_tampered_encrypted_file_fails_the_content_hash_check() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    tamper(&made.sealed_audio)?;
    let out = home.path().join("out");
    let key = home.path().join("fake_grp.key");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.sealed_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
            "--vcon-key",
            s(&key),
        ],
    )?;
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(1), "{err}");
    let (_, index) = uuid_and_index(&opened(&made.sealed_container)?)?;
    assert!(err.contains("content_hash"), "{err}");
    assert!(
        err.contains(&format!("dialog {index}")),
        "names the dialog: {err}"
    );
    assert!(!err.contains("decrypt"), "refused before decrypting: {err}");
    assert!(listing(&out).is_empty(), "{:?}", listing(&out));
    Ok(())
}

/// The same for an unencrypted WAV: only the hash can catch it.
#[test]
fn a_tampered_wav_fails_the_content_hash_check() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    tamper(&made.plain_wav)?;
    let out = home.path().join("out");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.plain_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
        ],
    )?;
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(1), "{err}");
    assert!(err.contains("content_hash"), "{err}");
    assert!(listing(&out).is_empty(), "{:?}", listing(&out));
    Ok(())
}

/// A key the audio was not encrypted to is refused. The container inside
/// the sealed one, written out unsigned, names the same JWE file, so the
/// container opens without a key and the refusal is the audio's own.
#[test]
fn a_wrong_key_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    let other = private_copy(home.path(), "other.key")?;
    let out = home.path().join("out");

    // The sealed container itself does not open with the other key.
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.sealed_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
            "--vcon-key",
            s(&other),
        ],
    )?;
    assert_eq!(run.status.code(), Some(1), "{}", stderr(&run));
    assert!(listing(&out).is_empty());

    // The unsigned container beside the JWE: the audio does not decrypt.
    let inner = opened(&made.sealed_container)?;
    let unsealed = made.sealed_container.with_file_name("unsealed.vcon.json");
    std::fs::write(&unsealed, serde_json::to_vec(&inner)?)?;
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&unsealed),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
            "--vcon-key",
            s(&other),
        ],
    )?;
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(1), "{err}");
    let (_, index) = uuid_and_index(&inner)?;
    assert!(err.contains(&format!("dialog {index}")), "{err}");
    assert!(err.contains("did not decrypt"), "{err}");
    assert!(listing(&out).is_empty(), "{:?}", listing(&out));

    // And with the right key it does.
    let key = home.path().join("fake_grp.key");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&unsealed),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
            "--vcon-key",
            s(&key),
        ],
    )?;
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    assert_eq!(
        std::fs::read(expected_out(&out, &inner, "wav")?)?,
        std::fs::read(&made.plain_wav)?
    );
    Ok(())
}

/// An `http://` URL is refused without a connection: draft-ietf-vcon-vcon-
/// core-04 section 2.4.1 says "HTTPS MUST be used for retrieval".
#[test]
fn an_http_url_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    let stub = Stub::start(home.path().join("plain"), None)?;
    let mut container: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&made.plain_container)?)?;
    let (_, index) = uuid_and_index(&container)?;
    let name = made
        .plain_wav
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name")?;
    container["dialog"][index]["url"] =
        serde_json::Value::from(format!("http://127.0.0.1:{}/calls/{name}", stub.port));
    let edited = home.path().join("http.vcon.json");
    std::fs::write(&edited, serde_json::to_vec(&container)?)?;
    let out = home.path().join("out");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&edited),
            "--vcon-audio-fetch-out",
            s(&out),
        ],
    )?;
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(1), "{err}");
    assert!(err.contains("https"), "{err}");
    assert!(
        stub.targets().is_empty(),
        "no request: {:?}",
        stub.targets()
    );
    assert!(listing(&out).is_empty());
    Ok(())
}

/// An output file that exists is kept as it is, and the run exits 1.
#[test]
fn an_existing_output_is_not_overwritten() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    let out = home.path().join("out");
    std::fs::create_dir(&out)?;
    let container: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&made.plain_container)?)?;
    let target = expected_out(&out, &container, "wav")?;
    std::fs::write(&target, b"keep")?;
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&made.plain_container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
        ],
    )?;
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(1), "{err}");
    assert!(err.contains("exists"), "{err}");
    assert_eq!(std::fs::read(&target)?, b"keep");
    assert_eq!(listing(&out), vec![target]);
    Ok(())
}

/// A container with no recording by `url` has nothing to fetch: exit 1.
#[test]
fn a_container_with_no_url_recording_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    let mut container: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&made.plain_container)?)?;
    let (_, index) = uuid_and_index(&container)?;
    container["dialog"]
        .as_array_mut()
        .ok_or("dialog")?
        .remove(index);
    let edited = home.path().join("none.vcon.json");
    std::fs::write(&edited, serde_json::to_vec(&container)?)?;
    let out = home.path().join("out");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(&edited),
            "--vcon-audio-fetch-out",
            s(&out),
        ],
    )?;
    assert_eq!(run.status.code(), Some(1), "{}", stderr(&run));
    assert!(stderr(&run).contains("no recording"), "{}", stderr(&run));
    Ok(())
}

// ── Settings ────────────────────────────────────────────────────────────

/// Settings that cannot be used exit 2: no output directory, a CA file
/// that does not read, a key file that does not read.
#[test]
fn settings_that_cannot_be_used_exit_2() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let made = make(home.path(), "https://media.example.com/calls")?;
    let out = home.path().join("out");
    let missing = home.path().join("missing.pem");
    for (named, args) in [
        (
            "--vcon-audio-fetch-out",
            vec!["--vcon-audio-fetch", s(&made.plain_container)],
        ),
        (
            "--vcon-audio-fetch-ca",
            vec![
                "--vcon-audio-fetch",
                s(&made.plain_container),
                "--vcon-audio-fetch-out",
                s(&out),
                "--vcon-audio-fetch-ca",
                s(&missing),
            ],
        ),
        (
            "--vcon-key",
            vec![
                "--vcon-audio-fetch",
                s(&made.sealed_container),
                "--vcon-audio-fetch-out",
                s(&out),
                "--vcon-key",
                s(&missing),
            ],
        ),
    ] {
        let run = sipnab(home.path(), &args)?;
        let err = stderr(&run);
        assert_eq!(run.status.code(), Some(2), "{args:?}: {err}");
        assert!(!err.contains("unexpected argument"), "{err}");
        assert!(err.contains(named), "names {named}: {err}");
    }
    assert!(listing(&out).is_empty());
    Ok(())
}

/// An encrypting rule with `audio_format = "opus"`: the file is an Ogg JWE,
/// written as `<uuid>-dialog<N>.ogg`, the Ogg stream the JWE holds.
#[cfg(feature = "opus")]
#[test]
fn an_ogg_opus_recording_is_written_as_ogg() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let sealed = home.path().join("sealed");
    let config = format!(
        "[[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n\
         audio_format = \"opus\"\naudio_url_base = \"https://media.example.com/calls\"\n\
         encrypt_to = \"{FIXTURES}/fake_grp.crt\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
        sealed.display(),
        private_copy(home.path(), "fake_grp.key")?.display(),
        chain(home.path())?.display()
    );
    let path = home.path().join("rules.toml");
    std::fs::write(&path, config)?;
    let made = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print", "--config"])
        .arg(&path)
        .env("HOME", home.path())
        .output()?;
    assert!(made.status.success(), "{}", stderr(&made));
    let files = listing(&sealed);
    let container = files
        .iter()
        .find(|p| p.to_string_lossy().ends_with(".vcon.json"))
        .ok_or("container")?;
    let jwe = files
        .iter()
        .find(|p| p.to_string_lossy().ends_with(".ogg.jwe"))
        .ok_or("ogg jwe")?;
    let out = home.path().join("out");
    let key = home.path().join("fake_grp.key");
    let run = sipnab(
        home.path(),
        &[
            "--vcon-audio-fetch",
            s(container),
            "--vcon-audio-fetch-out",
            s(&out),
            "--vcon-audio-fetch-local",
            "--vcon-key",
            s(&key),
        ],
    )?;
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    let expected = expected_out(&out, &opened(container)?, "ogg")?;
    let ogg = std::fs::read(&expected)?;
    assert_eq!(&ogg[..4], b"OggS");
    let fixture_key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    assert_eq!(ogg, vcon_jose::decrypt(&std::fs::read(jwe)?, &fixture_key)?);
    Ok(())
}
