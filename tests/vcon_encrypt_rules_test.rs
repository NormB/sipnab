// SPDX-License-Identifier: MIT OR Apache-2.0

//! `[[vcon.rule]]` with `encrypt_to`, on the shipped binary: the rule writes
//! only the encrypted form (signed with `sign_key` and `sign_cert`, then
//! encrypted to the `encrypt_to` certificate), names each file by the
//! container's uuid rather than the Call-ID, and refuses at startup every
//! setting that would leave something readable or unusable.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use sipnab::output::vcon_jose::{self, Form};

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL: &str = "call_id == '1-1966@10.0.2.20'";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// The signing key, copied to `home` with mode 0600: sipnab refuses a key
/// other users can read, and git checks the fixture out 0644.
fn private_copy(home: &Path, name: &str) -> Result<PathBuf, TestError> {
    let path = home.join(name);
    std::fs::copy(format!("{FIXTURES}/{name}"), &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
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

fn run(config: &str, home: &Path) -> Result<std::process::Output, TestError> {
    let path = home.join("rules.toml");
    std::fs::write(&path, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print"])
        .arg("--config")
        .arg(&path)
        .env("HOME", home)
        .output()?)
}

/// A rule writing `CALL` to `dir`, plus `extra` lines.
fn rule(name: &str, dir: &Path, extra: &str) -> String {
    format!(
        "[[vcon.rule]]\nname = \"{name}\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"inline\"\n{extra}\n",
        dir.display()
    )
}

/// The `encrypt_to`, `sign_key` and `sign_cert` lines for the fixture keys.
fn sealing(home: &Path, recipient: &str) -> Result<String, TestError> {
    Ok(format!(
        "encrypt_to = \"{FIXTURES}/{recipient}\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
        private_copy(home, "fake_grp.key")?.display(),
        chain(home)?.display()
    ))
}

fn files(dir: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    out.sort();
    Ok(out)
}

#[test]
fn an_encrypting_rule_writes_only_the_encrypted_form() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (plain, sealed) = (home.path().join("plain"), home.path().join("sealed"));
    let config = rule("plain", &plain, "")
        + &rule("sealed", &sealed, &sealing(home.path(), "fake_grp.crt")?);
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let plain_files = files(&plain)?;
    let sealed_files = files(&sealed)?;
    assert_eq!(plain_files.len(), 1, "{plain_files:?}");
    assert_eq!(sealed_files.len(), 1, "{sealed_files:?}");
    let reference: serde_json::Value = serde_json::from_slice(&std::fs::read(&plain_files[0])?)?;
    let uuid = reference["uuid"].as_str().ok_or("uuid")?;

    let name = sealed_files[0]
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name")?;
    assert_eq!(
        name,
        format!("{uuid}.vcon.json"),
        "named by uuid, not Call-ID"
    );

    let bytes = std::fs::read(&sealed_files[0])?;
    let text = String::from_utf8(bytes.clone())?;
    for clear in ["1-1966", "10.0.2.20", "sip-message-trace", "parties"] {
        assert!(!text.contains(clear), "{clear} in clear");
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Encrypted);
    assert_eq!(value["unprotected"]["uuid"], uuid);

    let key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    let unsigned = vcon_jose::verify(&vcon_jose::decrypt(&bytes, &key)?)?;
    let inner: serde_json::Value = serde_json::from_slice(&unsigned)?;
    assert_eq!(inner["uuid"], reference["uuid"]);
    assert_eq!(inner["parties"], reference["parties"]);
    assert_eq!(
        inner["dialog"], reference["dialog"],
        "the audio travels inside"
    );
    Ok(())
}

/// Each refusal, with what its message must name.
#[test]
fn an_encrypting_rule_that_cannot_work_is_refused_at_startup() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("sealed");
    let key = private_copy(home.path(), "fake_grp.key")?;
    let other_key = private_copy(home.path(), "other.key")?;
    let chain = chain(home.path())?;
    let recipient = format!("{FIXTURES}/fake_grp.crt");
    let cases: Vec<(String, &str)> = vec![
        (
            format!("encrypt_to = \"{recipient}\"\n"),
            "needs sign_key and sign_cert",
        ),
        (
            format!(
                "sign_key = \"{}\"\nsign_cert = \"{}\"\n",
                key.display(),
                chain.display()
            ),
            "without encrypt_to",
        ),
        (
            format!(
                "encrypt_to = \"{recipient}\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
                other_key.display(),
                chain.display()
            ),
            "does not match",
        ),
        (
            format!(
                "encrypt_to = \"{}\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
                key.display(),
                key.display(),
                chain.display()
            ),
            "no certificate",
        ),
        (
            format!(
                "encrypt_to = \"{}/missing.crt\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
                home.path().display(),
                key.display(),
                chain.display()
            ),
            "missing.crt",
        ),
    ];
    for (extra, expected) in cases {
        let out = run(&rule("sealed", &dir, &extra), home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{extra}: {stderr}");
        assert!(stderr.contains("'sealed'"), "{extra}: {stderr}");
        assert!(
            stderr.contains(expected),
            "{extra}: wants {expected:?}: {stderr}"
        );
        assert!(!dir.exists(), "{extra}: nothing written");
    }
    Ok(())
}

/// `audio = "url"` writes the WAV beside the container, where encryption
/// would not reach it.
#[test]
fn an_encrypting_rule_refuses_audio_by_url() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("sealed");
    let config = format!(
        "[[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n\
         audio_url_base = \"https://media.example.com/calls\"\n{}",
        dir.display(),
        sealing(home.path(), "fake_grp.crt")?
    );
    let out = run(&config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("audio = 'url'"), "{stderr}");
    Ok(())
}

/// A signing key other users can read is refused, as ssh refuses one.
#[cfg(unix)]
#[test]
fn an_encrypting_rule_refuses_a_signing_key_others_can_read() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir()?;
    let dir = home.path().join("sealed");
    let extra = sealing(home.path(), "fake_grp.crt")?;
    std::fs::set_permissions(
        home.path().join("fake_grp.key"),
        std::fs::Permissions::from_mode(0o644),
    )?;
    let out = run(&rule("sealed", &dir, &extra), home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("chmod 600"), "{stderr}");
    Ok(())
}
