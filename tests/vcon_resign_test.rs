// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--vcon-resign`: the long-term archiving of draft-ietf-vcon-vcon-core-04
//! section 5.2.3, on the shipped binary. "Before the expiration of the JWS1
//! signing certificate, the content of JWS1 (the vCon) is verified and then
//! JWS1 is signed as the payload to construct JWS2." Reading walks the
//! nesting: every layer's signature verifies, and the outermost signer is
//! the one whose certificate must be valid now.
//!
//! Every key and certificate is generated per test.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use sipnab::output::vcon_jose::{self, Form};

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL_ID: &str = "1-1966@10.0.2.20";

/// A fresh EC P-256 signer: its key (PKCS #8 PEM) and a self-signed
/// certificate valid from `from` to `until` (years).
fn identity(name: &str, from: i32, until: i32) -> Result<(String, String), TestError> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("{name} archive signer"));
    params.not_before = rcgen::date_time_ymd(from, 1, 1);
    params.not_after = rcgen::date_time_ymd(until, 1, 1);
    let cert = params.self_signed(&key)?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// `identity` written to `home` as `<name>.key` (mode 0600) and
/// `<name>.crt`.
fn identity_files(
    home: &Path,
    name: &str,
    from: i32,
    until: i32,
) -> Result<(PathBuf, PathBuf, String), TestError> {
    let (key, cert) = identity(name, from, until)?;
    let key_path = home.join(format!("{name}.key"));
    std::fs::write(&key_path, &key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let cert_path = home.join(format!("{name}.crt"));
    std::fs::write(&cert_path, &cert)?;
    Ok((key_path, cert_path, cert))
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

/// The signed form of `bytes`, by a signer of `key` and `cert`.
fn signed(bytes: &[u8], key: &str, cert: &str) -> Result<Vec<u8>, TestError> {
    let uuid = uuid_of(bytes)?;
    Ok(vcon_jose::sign(
        bytes,
        &uuid,
        &vcon_jose::Signer::from_pem(key, cert)?,
    )?)
}

/// The vCon uuid of an unsigned container, or of a signed one's header.
fn uuid_of(bytes: &[u8]) -> Result<String, TestError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    value["uuid"]
        .as_str()
        .or_else(|| value["signatures"][0]["header"]["uuid"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| "no uuid".into())
}

fn run(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()?)
}

/// `sipnab --vcon-resign IN --vcon-resign-key KEY --vcon-resign-cert CERT
/// --vcon-resign-out OUT`, plus `extra`.
fn resign(
    home: &Path,
    input: &Path,
    key: &Path,
    cert: &Path,
    out: &Path,
    extra: &[&str],
) -> Result<Output, TestError> {
    let mut args = vec![
        "--vcon-resign",
        input.to_str().ok_or("utf-8")?,
        "--vcon-resign-key",
        key.to_str().ok_or("utf-8")?,
        "--vcon-resign-cert",
        cert.to_str().ok_or("utf-8")?,
        "--vcon-resign-out",
        out.to_str().ok_or("utf-8")?,
    ];
    args.extend_from_slice(extra);
    run(home, &args)
}

/// Whether `-I file` reads the call, with `extra` flags.
fn reads(home: &Path, file: &Path, extra: &[&str]) -> Result<bool, TestError> {
    let mut args = vec![
        "-N",
        "--json-dialogs",
        "--quiet",
        "-I",
        file.to_str().ok_or("utf-8")?,
    ];
    args.extend_from_slice(extra);
    let out = run(home, &args)?;
    Ok(out.status.success() && String::from_utf8(out.stdout)?.contains(CALL_ID))
}

/// JWS2's payload is JWS1 byte for byte, signed by the new signer with its
/// `x5c` and the vCon's uuid; a second re-sign makes JWS3; `-I` reads each
/// back by walking the nesting.
#[test]
fn a_signed_vcon_is_re_signed_as_the_payload_of_a_new_jws() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (k1, c1) = identity("first", 2020, 2040)?;
    let jws1 = signed(&unsigned(home.path())?, &k1, &c1)?;
    let in1 = home.path().join("jws1.vcon.json");
    std::fs::write(&in1, &jws1)?;
    let (key2, cert2, _) = identity_files(home.path(), "second", 2020, 2040)?;
    let out2 = home.path().join("jws2.vcon.json");
    let out = resign(home.path(), &in1, &key2, &cert2, &out2, &[])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let jws2 = std::fs::read(&out2)?;
    let value: serde_json::Value = serde_json::from_slice(&jws2)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Signed);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value["payload"].as_str().ok_or("payload")?)?;
    assert!(payload == jws1, "JWS2's payload is not JWS1 byte for byte");
    assert_eq!(value["signatures"][0]["header"]["uuid"], uuid_of(&jws1)?);
    assert_eq!(vcon_jose::verify(&jws2)?, jws1);
    assert!(reads(home.path(), &out2, &[])?);

    let (key3, cert3, _) = identity_files(home.path(), "third", 2020, 2040)?;
    let out3 = home.path().join("jws3.vcon.json");
    let out = resign(home.path(), &out2, &key3, &cert3, &out3, &[])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(vcon_jose::verify(&std::fs::read(&out3)?)?, jws2);
    assert!(reads(home.path(), &out3, &[])?);
    Ok(())
}

/// Section 5.2.3 re-signs "before the expiration of the JWS1 signing
/// certificate": an input whose signer has expired is refused, and nothing
/// is written. Once re-signed in time, the outer signer is the one whose
/// certificate must be valid, and the inner is assumed.
#[test]
fn an_expired_signer_is_refused_but_an_archived_one_still_reads() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (k1, c1) = identity("lapsed", 2015, 2020)?;
    let jws1 = signed(&unsigned(home.path())?, &k1, &c1)?;
    let in1 = home.path().join("jws1.vcon.json");
    std::fs::write(&in1, &jws1)?;
    let (key2, cert2, c2) = identity_files(home.path(), "current", 2020, 2040)?;
    let out2 = home.path().join("jws2.vcon.json");
    let out = resign(home.path(), &in1, &key2, &cert2, &out2, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("not valid now"), "{stderr}");
    assert!(!out2.exists());

    // JWS2 made while JWS1 was valid: the inner certificate has lapsed
    // since, and the archive still reads.
    let (k2, _) = (std::fs::read_to_string(&key2)?, ());
    let archived = home.path().join("archived.vcon.json");
    std::fs::write(&archived, signed(&jws1, &k2, &c2)?)?;
    assert!(reads(home.path(), &archived, &[])?);
    Ok(())
}

/// Reading verifies every layer: an archive whose inner signature does not
/// verify is refused, though its outer one does.
#[test]
fn a_broken_inner_signature_is_refused_through_a_valid_outer_one() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (k1, c1) = identity("first", 2020, 2040)?;
    let mut jws1: serde_json::Value =
        serde_json::from_slice(&signed(&unsigned(home.path())?, &k1, &c1)?)?;
    let forged = serde_json::json!({ "vcon": "0.4.0", "parties": [] });
    jws1["payload"] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(forged.to_string())
        .into();
    let (k2, c2) = identity("second", 2020, 2040)?;
    let archive = home.path().join("archive.vcon.json");
    std::fs::write(&archive, signed(jws1.to_string().as_bytes(), &k2, &c2)?)?;
    let out = run(
        home.path(),
        &[
            "-N",
            "--json-dialogs",
            "-I",
            archive.to_str().ok_or("utf-8")?,
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("does not verify"), "{stderr}");
    Ok(())
}

/// What is not a signed vCon, or does not verify, is refused with exit 1;
/// an output that exists is never replaced; `--vcon-signer-ca` checks the
/// input's signer.
#[test]
fn what_cannot_be_re_signed_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let plain = unsigned(home.path())?;
    let (k1, c1) = identity("first", 2020, 2040)?;
    let jws1 = signed(&plain, &k1, &c1)?;
    let (key2, cert2, _) = identity_files(home.path(), "second", 2020, 2040)?;
    let out2 = home.path().join("out.vcon.json");

    let unsigned_in = home.path().join("plain.vcon.json");
    std::fs::write(&unsigned_in, &plain)?;
    let mut forged: serde_json::Value = serde_json::from_slice(&jws1)?;
    forged["payload"] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(b"{\"vcon\":\"0.4.0\",\"parties\":[]}")
        .into();
    let forged_in = home.path().join("forged.vcon.json");
    std::fs::write(&forged_in, forged.to_string())?;
    for (input, expected) in [
        (&unsigned_in, "not signed"),
        (&forged_in, "does not verify"),
    ] {
        let out = resign(home.path(), input, &key2, &cert2, &out2, &[])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!out2.exists());
    }

    let in1 = home.path().join("jws1.vcon.json");
    std::fs::write(&in1, &jws1)?;
    std::fs::write(&out2, "keep")?;
    let out = resign(home.path(), &in1, &key2, &cert2, &out2, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("exists"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&out2)?, "keep");
    std::fs::remove_file(&out2)?;

    let (_, other_ca) = identity("unrelated", 2020, 2040)?;
    let ca = home.path().join("ca.pem");
    std::fs::write(&ca, other_ca)?;
    let out = resign(
        home.path(),
        &in1,
        &key2,
        &cert2,
        &out2,
        &["--vcon-signer-ca", ca.to_str().ok_or("utf-8")?],
    )?;
    assert_eq!(out.status.code(), Some(1));
    assert!(!out2.exists());
    Ok(())
}

/// The flags it needs are refused when missing, with exit 2.
#[test]
fn a_re_sign_without_a_key_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let out = run(
        home.path(),
        &[
            "--vcon-resign",
            "in.vcon.json",
            "--vcon-resign-out",
            "out.vcon.json",
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--vcon-resign-key"), "{stderr}");
    Ok(())
}
