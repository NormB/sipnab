// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `[[vcon.rule]]` with `sign_only = true`, on the shipped binary: the rule
//! writes the signed form of draft-ietf-vcon-vcon-core-04 section 5.2, a JWS
//! with no encryption. Signing alone stays opt-in: `sign_key` without
//! `encrypt_to` or `sign_only` is still refused.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use sipnab::output::vcon_jose::{self, Form};

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL: &str = "call_id == '1-1966@10.0.2.20'";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

/// The signing key, copied to `home` with mode 0600.
fn private_key(home: &Path) -> Result<PathBuf, TestError> {
    let path = home.join("signer.key");
    std::fs::copy(format!("{FIXTURES}/fake_grp.key"), &path)?;
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

/// The `sign_key` and `sign_cert` lines.
fn signing(home: &Path) -> Result<String, TestError> {
    Ok(format!(
        "sign_key = \"{}\"\nsign_cert = \"{}\"\n",
        private_key(home)?.display(),
        chain(home)?.display()
    ))
}

/// A rule writing `CALL` to `dir`, plus `extra` lines.
fn rule(name: &str, dir: &Path, extra: &str) -> String {
    format!(
        "[[vcon.rule]]\nname = \"{name}\"\nwhen = \"{CALL}\"\ndir = \"{}\"\n{extra}\n",
        dir.display()
    )
}

/// Run the export with `config` as the config file.
fn run(config: &str, home: &Path) -> Result<std::process::Output, TestError> {
    let path = home.join("rules.toml");
    std::fs::write(&path, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print"])
        .arg("--config")
        .arg(&path)
        .env("HOME", home)
        .output()?)
}

/// The one file in `dir`.
fn only_file(dir: &Path) -> Result<PathBuf, TestError> {
    let files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    match files.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!("{} files, not 1", files.len()).into()),
    }
}

/// `attachments` without the `tags` attachment.
fn without_tags(attachments: &serde_json::Value) -> Vec<serde_json::Value> {
    attachments
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["purpose"] != "tags")
        .cloned()
        .collect()
}

/// `sign_only = true` writes the signed form: a JWS whose signature
/// verifies against the rule's certificate, whose payload is the unsigned
/// vCon the plain rule writes, named by the uuid, and readable back with
/// `-I` and no key.
#[test]
fn a_sign_only_rule_writes_the_signed_form() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (plain, signed) = (home.path().join("plain"), home.path().join("signed"));
    let config = rule("plain", &plain, "")
        + &rule(
            "signed",
            &signed,
            &format!("{}sign_only = true\n", signing(home.path())?),
        );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reference: serde_json::Value = serde_json::from_slice(&std::fs::read(only_file(&plain)?)?)?;
    let file = only_file(&signed)?;
    let bytes = std::fs::read(&file)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Signed);
    let uuid = reference["uuid"].as_str().ok_or("uuid")?;
    assert_eq!(value["signatures"][0]["header"]["uuid"], uuid);
    assert_eq!(
        file.file_name().and_then(|n| n.to_str()),
        Some(format!("{uuid}.vcon.json").as_str())
    );
    let inner: serde_json::Value = serde_json::from_slice(&vcon_jose::verify(&bytes)?)?;
    assert_eq!(inner["parties"], reference["parties"]);
    // Each rule tags its containers with its own name (`rule:<name>`), so
    // the `tags` attachment is the one that differs between the two rules.
    assert_eq!(
        without_tags(&inner["attachments"]),
        without_tags(&reference["attachments"])
    );

    let read = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "--json-dialogs", "--quiet", "-I"])
        .arg(&file)
        .env("HOME", home.path())
        .output()?;
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert!(String::from_utf8(read.stdout)?.contains("1-1966@10.0.2.20"));
    Ok(())
}

/// The caveat inside a signed container does not deny that it is signed. The
/// payload is the plain container, so its caveat has to be true of both forms:
/// it says what the parties are, and leaves the signing to the JWS.
#[test]
fn a_signed_container_s_caveat_does_not_say_it_is_unsigned() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let signed = home.path().join("signed");
    let config = rule(
        "signed",
        &signed,
        &format!("{}sign_only = true\n", signing(home.path())?),
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let inner: serde_json::Value =
        serde_json::from_slice(&vcon_jose::verify(&std::fs::read(only_file(&signed)?)?)?)?;
    let notes: Vec<&str> = inner["attachments"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(inner["analysis"].as_array().into_iter().flatten())
        .filter_map(|a| {
            a["body"]["note"]
                .as_str()
                .or_else(|| a["body"]["capture_completeness"]["note"].as_str())
        })
        .collect();
    assert_eq!(notes.len(), 2, "the caveat is embedded twice: {inner}");
    for note in notes {
        assert!(note.contains("not identities anyone established"), "{note}");
        assert!(!note.contains("signed"), "{note}");
    }
    Ok(())
}

/// `compress = "gzip"` on a signing rule signs the gzip of the vCon (core-04
/// section 5.2).
#[test]
fn a_sign_only_rule_compresses_when_told() -> Result<(), TestError> {
    use base64::Engine as _;
    let home = tempfile::tempdir()?;
    let dir = home.path().join("signed");
    let extra = format!(
        "{}sign_only = true\ncompress = \"gzip\"\n",
        signing(home.path())?
    );
    let out = run(&rule("signed", &dir, &extra), home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(only_file(&dir)?)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value["payload"].as_str().ok_or("payload")?)?;
    assert_eq!(payload[..2], vcon_jose::GZIP_MAGIC);
    let inner: serde_json::Value = serde_json::from_slice(&vcon_jose::verify(&bytes)?)?;
    assert_eq!(vcon_jose::form_of(&inner), Form::Unsigned);
    Ok(())
}

/// `sign_only` takes `sign_key`, `sign_cert` and `compress` from `[vcon]`,
/// and not `[vcon] encrypt_to`: the rule asked for the signed form alone.
#[test]
fn a_sign_only_rule_inherits_the_signing_keys_and_not_the_recipient() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("signed");
    let config = format!(
        "[vcon]\nencrypt_to = \"{FIXTURES}/fake_grp.crt\"\n{}\n{}",
        signing(home.path())?,
        rule("signed", &dir, "sign_only = true\n"),
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(only_file(&dir)?)?)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Signed);
    Ok(())
}

/// What cannot work is refused at startup, naming the rule: `sign_only`
/// beside the rule's own `encrypt_to`, `sign_only` with no signing key, and,
/// as before, a signing key with neither `encrypt_to` nor `sign_only`.
#[test]
fn a_sign_only_rule_that_cannot_work_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("signed");
    let keys = signing(home.path())?;
    for (extra, expected) in [
        (
            format!("{keys}sign_only = true\nencrypt_to = \"{FIXTURES}/fake_grp.crt\"\n"),
            "sign_only and encrypt_to",
        ),
        (
            "sign_only = true\n".to_owned(),
            "sign_only and needs sign_key and sign_cert",
        ),
        (keys.clone(), "without encrypt_to"),
        (format!("{keys}sign_only = false\n"), "without encrypt_to"),
    ] {
        let out = run(&rule("signed", &dir, &extra), home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{extra}: {stderr}");
        assert!(stderr.contains("'signed'"), "{extra}: {stderr}");
        assert!(stderr.contains(expected), "{extra}: {stderr}");
        assert!(!dir.exists(), "{extra}: nothing written");
    }
    Ok(())
}

/// `sign_only = true` with `audio = "url"` writes the audio beside the
/// signed container as it is, not as a JWE: a signing rule has no
/// recipient to encrypt to. The signed container's recording names the
/// file's URL and the SHA-512 of the file as written.
#[test]
fn a_sign_only_url_rule_writes_its_audio_in_clear_and_signs_its_hash() -> Result<(), TestError> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let home = tempfile::tempdir()?;
    let signed = home.path().join("signed");
    let config = rule(
        "signed",
        &signed,
        &format!(
            "{}sign_only = true\naudio = \"url\"\naudio_url_base = \"https://media.example.com/calls\"\n",
            signing(home.path())?
        ),
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let files: Vec<PathBuf> = std::fs::read_dir(&signed)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    assert_eq!(files.len(), 2, "the container and the audio");
    let wav_path = files
        .iter()
        .find(|p| p.to_string_lossy().ends_with(".wav"))
        .ok_or("a .wav beside the container")?;
    let container_path = files
        .iter()
        .find(|p| p.to_string_lossy().ends_with(".vcon.json"))
        .ok_or("the container")?;
    let wav = std::fs::read(wav_path)?;
    assert_eq!(&wav[..4], b"RIFF", "the audio in clear");

    let bytes = std::fs::read(container_path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Signed);
    let inner: serde_json::Value = serde_json::from_slice(&vcon_jose::verify(&bytes)?)?;
    let recording = inner["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .find(|d| d["url"].is_string())
        .ok_or("a recording with a url")?;
    let name = wav_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name")?;
    assert_eq!(
        recording["url"],
        format!("https://media.example.com/calls/{name}")
    );
    assert_eq!(
        recording["content_hash"],
        format!(
            "sha512-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha512::digest(&wav))
        )
    );
    Ok(())
}
