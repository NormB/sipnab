// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every vCon reader takes every form a container arrives in: the unsigned
//! form, the signed form (draft-ietf-vcon-vcon-core-04 section 5.2), the
//! encrypted form (section 5.3), and the gzip format of any of them
//! (sections 5.4 and 6.2). `-I`, the MCP `analyze_vcon` and `validate_vcon`
//! tools, and `POST /v1/vcon/analyze` and `/v1/vcon/validate` share one
//! unwrap step, driven here through the shipped binary.
//!
//! The property that carries the weight: sipnab reads back its own
//! encrypted, gzip-compressed output.
#![cfg(all(feature = "native", feature = "vcon"))]

#[path = "support/vcon_signer_pki.rs"]
mod vcon_signer_pki;

#[cfg(feature = "mcp")]
#[path = "support/mcp.rs"]
mod mcp;

#[cfg(feature = "api")]
#[path = "support/server.rs"]
mod server;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sipnab::output::vcon_jose::{self, Form};

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL_ID: &str = "1-1966@10.0.2.20";
const CALL: &str = "call_id == '1-1966@10.0.2.20'";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// `name` from the fixtures, copied to `home` with `mode`: sipnab refuses a
/// private key other users can read, and git checks the fixture out 0644.
fn copy_with_mode(home: &Path, name: &str, mode: u32) -> Result<PathBuf, TestError> {
    let path = home.join(format!("{mode:o}-{name}"));
    std::fs::copy(format!("{FIXTURES}/{name}"), &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(path)
}

/// The fixture signing chain, leaf first, as one PEM file in `home`.
fn chain(home: &Path) -> Result<PathBuf, TestError> {
    let path = home.join("chain.pem");
    let mut pem = String::new();
    for name in ["fake_grp.crt", "fake_div.crt", "fake_ca_root.crt"] {
        pem.push_str(&std::fs::read_to_string(format!("{FIXTURES}/{name}"))?);
    }
    std::fs::write(&path, pem)?;
    Ok(path)
}

/// Run the shipped binary from the repository root with `HOME` at `home`.
fn run(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()?)
}

/// The one file in `dir`.
fn only_file(dir: &Path) -> Result<PathBuf, TestError> {
    let files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    match files.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!("{} files in the export directory, not 1", files.len()).into()),
    }
}

/// Export `CALL` from `CAPTURE` through a `[[vcon.rule]]` with `extra` keys
/// into `home/<name>`, and return the one container written.
fn export(home: &Path, name: &str, extra: &str) -> Result<PathBuf, TestError> {
    let dir = home.join(name);
    let config = home.join(format!("{name}.toml"));
    std::fs::write(
        &config,
        format!(
            "[[vcon.rule]]\nname = \"{name}\"\nwhen = \"{CALL}\"\ndir = \"{}\"\n{extra}\n",
            dir.display()
        ),
    )?;
    let config = config.to_str().ok_or("utf-8 path")?;
    let out = run(
        home,
        &["-N", "-I", CAPTURE, "--no-cli-print", "--config", config],
    )?;
    if !out.status.success() {
        return Err(format!(
            "the export exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    only_file(&dir)
}

/// An encrypting rule's keys: encrypted to the fixture certificate, signed
/// with its key and chain, compressed with gzip.
fn sealing(home: &Path) -> Result<String, TestError> {
    Ok(format!(
        "encrypt_to = \"{FIXTURES}/fake_grp.crt\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\ncompress = \"gzip\"\n",
        copy_with_mode(home, "fake_grp.key", 0o600)?.display(),
        chain(home)?.display()
    ))
}

/// The Call-IDs `--json-dialogs` prints for `-I file` with `extra` flags,
/// with the run's exit status and standard error.
fn dialogs(home: &Path, file: &Path, extra: &[&str]) -> Result<(Vec<String>, Output), TestError> {
    let mut args = vec![
        "-N",
        "-I",
        file.to_str().ok_or("utf-8 path")?,
        "--json-dialogs",
        "--quiet",
    ];
    args.extend_from_slice(extra);
    let out = run(home, &args)?;
    let ids = String::from_utf8(out.stdout.clone())?
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("msg_count").is_some())
        .filter_map(|v| v["call_id"].as_str().map(str::to_owned))
        .collect();
    Ok((ids, out))
}

/// The gzip of `bytes` ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952.html)).
fn gzip(bytes: &[u8]) -> Result<Vec<u8>, TestError> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

/// sipnab re-analyzes its own encrypted, gzip-compressed output: `-I` with
/// the recipient's key reads the call the export wrote.
#[test]
fn minus_i_reads_its_own_encrypted_gzip_container_with_the_key() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let sealed = export(home.path(), "sealed", &sealing(home.path())?)?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&sealed)?)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Encrypted);
    assert_eq!(value["unprotected"]["cty"], "application/vcon+gzip");

    let key = copy_with_mode(home.path(), "fake_grp.key", 0o600)?;
    let (ids, out) = dialogs(
        home.path(),
        &sealed,
        &["--vcon-key", key.to_str().ok_or("utf-8 path")?],
    )?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(ids, [CALL_ID]);
    Ok(())
}

/// Without a key an encrypted container is refused by name, never analyzed
/// as a JSON object that holds no SIP.
#[test]
fn an_encrypted_container_without_a_key_is_refused_naming_the_flag() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let sealed = export(home.path(), "sealed", &sealing(home.path())?)?;
    let (ids, out) = dialogs(home.path(), &sealed, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(ids.is_empty());
    assert!(stderr.contains("encrypted"), "{stderr}");
    assert!(stderr.contains("--vcon-key"), "{stderr}");
    assert!(!stderr.contains("no SIP signaling"), "{stderr}");
    Ok(())
}

/// The key must be readable by its owner only, as every sipnab private key.
#[cfg(unix)]
#[test]
fn a_key_other_users_can_read_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let sealed = export(home.path(), "sealed", &sealing(home.path())?)?;
    let open = copy_with_mode(home.path(), "fake_grp.key", 0o644)?;
    let (ids, out) = dialogs(
        home.path(),
        &sealed,
        &["--vcon-key", open.to_str().ok_or("utf-8 path")?],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(ids.is_empty());
    assert!(stderr.contains("chmod 600"), "{stderr}");
    Ok(())
}

/// `[vcon_input] key` in the config file does what `--vcon-key` does.
#[test]
fn the_config_key_opens_an_encrypted_container() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let sealed = export(home.path(), "sealed", &sealing(home.path())?)?;
    let key = copy_with_mode(home.path(), "fake_grp.key", 0o600)?;
    let config = home.path().join("reader.toml");
    std::fs::write(
        &config,
        format!("[vcon_input]\nkey = \"{}\"\n", key.display()),
    )?;
    let (ids, out) = dialogs(
        home.path(),
        &sealed,
        &["--config", config.to_str().ok_or("utf-8 path")?],
    )?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(ids, [CALL_ID]);
    Ok(())
}

/// A gzip format vCon (core-04 section 6.2) is read by its gzip magic
/// (section 5.4), under any name, not handed to libpcap as a compressed
/// capture.
#[test]
fn minus_i_reads_a_gzip_format_container() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let plain = export(home.path(), "plain", "")?;
    let packed = home.path().join("call.vcon");
    std::fs::write(&packed, gzip(&std::fs::read(&plain)?)?)?;
    let (ids, out) = dialogs(home.path(), &packed, &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(ids, [CALL_ID]);
    Ok(())
}

/// The signed form of `plain`, signed with the fixture key and `chain_pem`.
fn signed_with(plain: &Path, chain_pem: &str) -> Result<Vec<u8>, TestError> {
    let unsigned = std::fs::read(plain)?;
    let uuid = serde_json::from_slice::<serde_json::Value>(&unsigned)?["uuid"]
        .as_str()
        .ok_or("uuid")?
        .to_owned();
    let signer = vcon_jose::Signer::from_pem(
        &std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?,
        chain_pem,
    )?;
    Ok(vcon_jose::sign(&unsigned, &uuid, &signer)?)
}

/// A signed container is verified and read with no key; one whose
/// signature does not verify is refused.
#[test]
fn a_signed_container_is_verified_and_a_forged_one_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let plain = export(home.path(), "plain", "")?;
    let pem = std::fs::read_to_string(chain(home.path())?)?;
    let signed = home.path().join("signed.vcon.json");
    std::fs::write(&signed, signed_with(&plain, &pem)?)?;
    let (ids, out) = dialogs(home.path(), &signed, &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(ids, [CALL_ID]);

    let mut forged: serde_json::Value = serde_json::from_slice(&std::fs::read(&signed)?)?;
    let other = serde_json::json!({ "vcon": "0.4.0", "parties": [] });
    forged["payload"] = base64_url(other.to_string().as_bytes()).into();
    std::fs::write(&signed, forged.to_string())?;
    let (ids, out) = dialogs(home.path(), &signed, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(ids.is_empty());
    assert!(stderr.contains("does not verify"), "{stderr}");
    Ok(())
}

/// base64url without padding (RFC 7515 section 2).
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `--vcon-signer-ca` reads a container only when its signer chains to the
/// CA; `--vcon-signer-sha256` only when the signer has the fingerprint. An
/// unsigned container has no signer to check and is refused.
#[test]
fn the_signer_checks_admit_only_the_named_signer() -> Result<(), TestError> {
    use sha2::Digest as _;
    let home = tempfile::tempdir()?;
    let plain = export(home.path(), "plain", "")?;
    let ours = vcon_signer_pki::signer_pki("ours")?;
    let theirs = vcon_signer_pki::signer_pki("theirs")?;
    let signed = home.path().join("signed.vcon.json");
    std::fs::write(&signed, signed_with(&plain, &ours.chain)?)?;
    let ca_ours = home.path().join("ours.pem");
    let ca_theirs = home.path().join("theirs.pem");
    std::fs::write(&ca_ours, &ours.ca)?;
    std::fs::write(&ca_theirs, &theirs.ca)?;
    let pin: String = sha2::Sha256::digest(&ours.leaf_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let wrong_pin = "00".repeat(32);
    let path = |p: &Path| p.to_str().map(str::to_owned).ok_or("utf-8 path");

    for (args, read) in [
        (vec!["--vcon-signer-ca".to_owned(), path(&ca_ours)?], true),
        (
            vec!["--vcon-signer-ca".to_owned(), path(&ca_theirs)?],
            false,
        ),
        (vec!["--vcon-signer-sha256".to_owned(), pin.clone()], true),
        (vec!["--vcon-signer-sha256".to_owned(), wrong_pin], false),
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (ids, out) = dialogs(home.path(), &signed, &args)?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.success(), read, "{stderr}");
        assert_eq!(ids.len(), usize::from(read), "{stderr}");
    }

    let (ids, out) = dialogs(home.path(), &plain, &["--vcon-signer-sha256", &pin])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(ids.is_empty());
    assert!(stderr.contains("not signed"), "{stderr}");
    Ok(())
}

#[cfg(feature = "mcp")]
mod mcp_reader {
    use super::mcp;
    use super::{CALL_ID, TestError, copy_with_mode, export, gzip, sealing};

    /// The MCP tools read sipnab's encrypted, gzip-compressed output with
    /// the server's `--vcon-key`: `analyze_vcon` analyzes the call inside,
    /// `validate_vcon` validates the unsigned vCon inside, and a gzip format
    /// vCon passes as `container_base64`.
    #[test]
    fn the_mcp_tools_read_encrypted_and_gzip_containers() -> Result<(), TestError> {
        use base64::Engine as _;
        let home = tempfile::tempdir()?;
        let sealed = super::export(home.path(), "sealed", &sealing(home.path())?)?;
        let plain = export(home.path(), "plain", "")?;
        let key = copy_with_mode(home.path(), "fake_grp.key", 0o600)?;
        let container: serde_json::Value = serde_json::from_slice(&std::fs::read(&sealed)?)?;
        let mut session = mcp::McpSession::start(
            "tests/fixtures/sip_call.pcap",
            &["--vcon-key", key.to_str().ok_or("utf-8 path")?],
        )?;

        let analysis = session.ok(
            "analyze_vcon",
            serde_json::json!({ "container": container }),
        )?;
        assert_eq!(analysis["verdict"], "analyzed");
        assert_eq!(analysis["dialogs"][0]["call_id"], CALL_ID);

        let verdict = session.ok(
            "validate_vcon",
            serde_json::json!({ "container": container }),
        )?;
        assert_eq!(verdict["verdict"], "valid");

        let packed =
            base64::engine::general_purpose::STANDARD.encode(gzip(&std::fs::read(&plain)?)?);
        let analysis = session.ok(
            "analyze_vcon",
            serde_json::json!({ "container_base64": packed }),
        )?;
        assert_eq!(analysis["verdict"], "analyzed");
        assert_eq!(analysis["dialogs"][0]["call_id"], CALL_ID);
        Ok(())
    }

    /// A server without a key refuses an encrypted container, naming the
    /// flag, rather than reporting a JSON object with no SIP.
    #[test]
    fn analyze_vcon_without_a_key_refuses_an_encrypted_container() -> Result<(), TestError> {
        let home = tempfile::tempdir()?;
        let sealed = super::export(home.path(), "sealed", &sealing(home.path())?)?;
        let container: serde_json::Value = serde_json::from_slice(&std::fs::read(&sealed)?)?;
        let mut session = mcp::McpSession::start("tests/fixtures/sip_call.pcap", &[])?;
        let msg = session.call(
            "analyze_vcon",
            serde_json::json!({ "container": container }),
        )?;
        let text = msg.to_string();
        assert!(text.contains("--vcon-key"), "{text}");
        assert!(!text.contains("\"verdict\":\"analyzed\""), "{text}");
        Ok(())
    }
}

#[cfg(feature = "api")]
mod rest_reader {
    use std::io::{Read as _, Write as _};

    use super::server;
    use super::{CALL_ID, TestError, copy_with_mode, export, gzip, sealing};

    /// POST `body` with `content_type` to `path` on `addr`, and return the
    /// status and the body of the answer.
    fn post(
        addr: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<(u16, serde_json::Value), TestError> {
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        stream.write_all(body)?;
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer)?;
        let text = String::from_utf8(answer)?;
        let (head, rest) = text.split_once("\r\n\r\n").ok_or("no header end")?;
        let status: u16 = head.split_whitespace().nth(1).ok_or("no status")?.parse()?;
        // A chunked answer: the JSON is between the first chunk size and
        // the last.
        let json = rest
            .find('{')
            .and_then(|start| rest.rfind('}').map(|end| &rest[start..=end]))
            .unwrap_or("null");
        Ok((status, serde_json::from_str(json)?))
    }

    /// `POST /v1/vcon/analyze` and `/v1/vcon/validate` read sipnab's
    /// encrypted output with the server's `--vcon-key`, and a gzip format
    /// vCon sent as `application/vcon+gzip`.
    #[test]
    fn the_rest_routes_read_encrypted_and_gzip_containers() -> Result<(), TestError> {
        let home = tempfile::tempdir()?;
        let sealed = export(home.path(), "sealed", &sealing(home.path())?)?;
        let plain = export(home.path(), "plain", "")?;
        let key = copy_with_mode(home.path(), "fake_grp.key", 0o600)?;
        let srv = server::ApiServer::spawn(&["--vcon-key", key.to_str().ok_or("utf-8 path")?])?;

        let body = std::fs::read(&sealed)?;
        let (status, answer) = post(&srv.addr, "/v1/vcon/analyze", "application/json", &body)?;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["verdict"], "analyzed");
        assert_eq!(answer["dialogs"][0]["call_id"], CALL_ID);

        let (status, answer) = post(&srv.addr, "/v1/vcon/validate", "application/json", &body)?;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["verdict"], "valid");

        let packed = gzip(&std::fs::read(&plain)?)?;
        let (status, answer) = post(
            &srv.addr,
            "/v1/vcon/analyze",
            "application/vcon+gzip",
            &packed,
        )?;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["dialogs"][0]["call_id"], CALL_ID);
        Ok(())
    }

    /// A server without a key refuses an encrypted container, naming the
    /// flag: the analyze route answers `verdict: unreadable` with the
    /// reason, as for any container it cannot read, and the validate route
    /// answers 422, as for a container it must not operate on.
    #[test]
    fn the_rest_routes_refuse_an_encrypted_container_without_a_key() -> Result<(), TestError> {
        let home = tempfile::tempdir()?;
        let sealed = export(home.path(), "sealed", &sealing(home.path())?)?;
        let srv = server::ApiServer::spawn(&[])?;
        let body = std::fs::read(&sealed)?;
        let (status, answer) = post(&srv.addr, "/v1/vcon/analyze", "application/json", &body)?;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["verdict"], "unreadable");
        assert!(
            answer["reason"].to_string().contains("--vcon-key"),
            "{answer}"
        );
        let (status, answer) = post(&srv.addr, "/v1/vcon/validate", "application/json", &body)?;
        assert_eq!(status, 422, "{answer}");
        assert!(answer.to_string().contains("--vcon-key"), "{answer}");
        Ok(())
    }
}
