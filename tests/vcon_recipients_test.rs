// SPDX-License-Identifier: MIT OR Apache-2.0

//! An encrypting `[[vcon.rule]]` with several recipients and EC keys, on the
//! shipped binary.
//!
//! - `encrypt_to` takes a list: one JWE JSON Serialization whose
//!   `recipients` array holds one entry per certificate
//!   ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1)),
//!   each able to open it with its own key.
//! - An EC P-256 recipient certificate gets `ECDH-ES+A256KW`
//!   ([RFC 7518 section 4.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6)),
//!   an RSA one `RSA-OAEP`.
//! - An EC P-256 signing key signs `ES256`
//!   ([RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)).
//!
//! The EC keys are generated per test; nothing leaves the test's directory.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use sipnab::output::vcon_jose::{self, Form};

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL_ID: &str = "1-1966@10.0.2.20";
const CALL: &str = "call_id == '1-1966@10.0.2.20'";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// Write `text` to `home/name` with mode 0600.
fn private_file(home: &Path, name: &str, text: &str) -> Result<PathBuf, TestError> {
    let path = home.join(name);
    std::fs::write(&path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// A fresh EC P-256 key and its self-signed certificate, as files in
/// `home`: `<name>.key` (PKCS #8, mode 0600) and `<name>.crt`.
fn ec_identity(home: &Path, name: &str) -> Result<(PathBuf, PathBuf), TestError> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("{name} test"));
    let cert = params.self_signed(&key)?;
    let key_path = private_file(home, &format!("{name}.key"), &key.serialize_pem())?;
    let cert_path = home.join(format!("{name}.crt"));
    std::fs::write(&cert_path, cert.pem())?;
    Ok((key_path, cert_path))
}

/// The fixture RSA key, copied with mode 0600.
fn rsa_key(home: &Path) -> Result<PathBuf, TestError> {
    private_file(
        home,
        "rsa.key",
        &std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?,
    )
}

/// Export `CALL` through one rule with `extra` keys into `home/out`, and
/// return the one container written.
fn export(home: &Path, extra: &str) -> Result<PathBuf, TestError> {
    let dir = home.join("out");
    let config = home.join("rules.toml");
    std::fs::write(
        &config,
        format!(
            "[[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\n{extra}\n",
            dir.display()
        ),
    )?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print", "--config"])
        .arg(&config)
        .env("HOME", home)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "the export exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    match files.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!("{} files written, not 1", files.len()).into()),
    }
}

/// `-I file --vcon-key key --json-dialogs`: whether the run read the call.
fn reads_with(home: &Path, file: &Path, key: &Path) -> Result<bool, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "--json-dialogs", "--quiet", "-I"])
        .arg(file)
        .arg("--vcon-key")
        .arg(key)
        .env("HOME", home)
        .output()?;
    Ok(out.status.success() && String::from_utf8(out.stdout)?.contains(CALL_ID))
}

/// One container, two recipients, an RSA certificate and an EC one: the
/// JWE carries two `recipients`, `RSA-OAEP` and `ECDH-ES+A256KW` with its
/// `epk`, and each recipient's key opens it; a third key does not.
#[test]
fn a_container_encrypted_to_an_rsa_and_an_ec_recipient_opens_with_either_key()
-> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (ec_key, ec_cert) = ec_identity(home.path(), "ec-recipient")?;
    let (stranger_key, _) = ec_identity(home.path(), "stranger")?;
    let extra = format!(
        "encrypt_to = [\"{FIXTURES}/fake_grp.crt\", \"{}\"]\nsign_key = \"{}\"\nsign_cert = \"{FIXTURES}/fake_grp.crt\"\n",
        ec_cert.display(),
        rsa_key(home.path())?.display(),
    );
    let sealed = export(home.path(), &extra)?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&sealed)?)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Encrypted);
    let recipients = value["recipients"].as_array().ok_or("recipients")?;
    assert_eq!(recipients.len(), 2);
    assert_eq!(recipients[0]["header"]["alg"], "RSA-OAEP");
    assert_eq!(recipients[1]["header"]["alg"], "ECDH-ES+A256KW");
    assert_eq!(recipients[1]["header"]["epk"]["kty"], "EC");
    assert_eq!(recipients[1]["header"]["epk"]["crv"], "P-256");
    assert_eq!(value["unprotected"]["enc"], "A256CBC-HS512");

    assert!(reads_with(home.path(), &sealed, &rsa_key(home.path())?)?);
    assert!(reads_with(home.path(), &sealed, &ec_key)?);
    assert!(!reads_with(home.path(), &sealed, &stranger_key)?);
    Ok(())
}

/// An EC P-256 signing key signs `ES256`, and the signature verifies.
#[test]
fn an_ec_signing_key_signs_es256() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (sign_key, sign_cert) = ec_identity(home.path(), "ec-signer")?;
    let extra = format!(
        "encrypt_to = \"{FIXTURES}/fake_grp.crt\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
        sign_key.display(),
        sign_cert.display(),
    );
    let sealed = export(home.path(), &extra)?;
    let key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    let signed = vcon_jose::decrypt(&std::fs::read(&sealed)?, &key)?;
    let value: serde_json::Value = serde_json::from_slice(&signed)?;
    let protected = value["signatures"][0]["protected"]
        .as_str()
        .ok_or("protected")?;
    use base64::Engine as _;
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected)?,
    )?;
    assert_eq!(header["alg"], "ES256");
    let inner: serde_json::Value = serde_json::from_slice(&vcon_jose::verify(&signed)?)?;
    assert_eq!(vcon_jose::form_of(&inner), Form::Unsigned);
    assert!(reads_with(home.path(), &sealed, &rsa_key(home.path())?)?);
    Ok(())
}

/// `[vcon] encrypt_to` takes a list too, and an empty list is refused.
#[test]
fn the_section_takes_a_list_and_an_empty_list_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (ec_key, ec_cert) = ec_identity(home.path(), "ec-recipient")?;
    let dir = home.path().join("out");
    let config = home.path().join("rules.toml");
    let section = |list: &str| -> Result<String, TestError> {
        Ok(format!(
            "[vcon]\nencrypt_to = {list}\nsign_key = \"{}\"\nsign_cert = \"{FIXTURES}/fake_grp.crt\"\n\n[[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\n",
            rsa_key(home.path())?.display(),
            dir.display()
        ))
    };
    std::fs::write(&config, section(&format!("[\"{}\"]", ec_cert.display()))?)?;
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["-N", "-I", CAPTURE, "--no-cli-print", "--config"])
            .arg(&config)
            .env("HOME", home.path())
            .output()
    };
    let out = run()?;
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
    assert_eq!(vcon_jose::form_of(&value), Form::Encrypted);
    assert_eq!(value["recipients"][0]["header"]["alg"], "ECDH-ES+A256KW");
    assert!(reads_with(home.path(), &file, &ec_key)?);

    std::fs::remove_dir_all(&dir)?;
    std::fs::write(&config, section("[]")?)?;
    let out = run()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("[vcon] encrypt_to is an empty list"),
        "{stderr}"
    );
    assert!(!dir.exists());

    std::fs::write(
        &config,
        format!(
            "[[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\nencrypt_to = []\nsign_key = \"{}\"\nsign_cert = \"{FIXTURES}/fake_grp.crt\"\n",
            dir.display(),
            rsa_key(home.path())?.display(),
        ),
    )?;
    let out = run()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("'sealed' has encrypt_to as an empty list"),
        "{stderr}"
    );
    assert!(!dir.exists());
    Ok(())
}
