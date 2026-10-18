// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

/// `sealed_updates = "same-uuid"` on an encrypting rule is warned about once
/// at startup, naming the rule and the sections of
/// draft-ietf-vcon-vcon-core-04 it departs from; the default is not.
#[test]
fn same_uuid_on_an_encrypting_rule_is_warned_about_at_startup() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let sealing = sealing(home.path(), "fake_grp.crt")?;
    let warned = rule(
        "kept",
        &home.path().join("kept"),
        &format!("{sealing}sealed_updates = \"same-uuid\"\n"),
    );
    let out = run(&warned, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        stderr.matches("sealed_updates = 'same-uuid'").count(),
        1,
        "one warning: {stderr}"
    );
    for needle in ["'kept'", "section 4.1.9", "section 4.1.2"] {
        assert!(stderr.contains(needle), "{needle}: {stderr}");
    }
    let quiet = rule("fresh", &home.path().join("fresh"), &sealing);
    let out = run(&quiet, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("sealed_updates"), "{stderr}");
    Ok(())
}

/// A `sealed_updates` value other than the three is refused at startup,
/// naming the rule and the three values.
#[test]
fn an_unknown_sealed_updates_value_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let config = rule(
        "odd",
        &home.path().join("odd"),
        &format!(
            "{}sealed_updates = \"sometimes\"\n",
            sealing(home.path(), "fake_grp.crt")?
        ),
    );
    let out = run(&config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    for needle in ["'odd'", "sometimes", "new-uuid", "same-uuid", "final-only"] {
        assert!(stderr.contains(needle), "{needle}: {stderr}");
    }
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

/// `sha512-` and the base64url SHA-512 of `bytes`.
fn hash_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    format!(
        "sha512-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha512::digest(bytes))
    )
}

/// `audio = "url"` on an encrypting rule writes the audio beside the
/// container as its own JWE, encrypted to the same recipient. The file is
/// named by its hash, not by the Call-ID. The sealed container's recording
/// names the file's URL, the `mediatype` of the audio inside, and the
/// `content_hash` of the file as written, which is the ciphertext. The key
/// that opens the container opens the file, and the audio inside is the WAV
/// an unencrypted `url` rule writes for the same call.
#[test]
fn an_encrypting_rule_writes_audio_by_url_as_its_own_jwe() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (plain, sealed) = (home.path().join("plain"), home.path().join("sealed"));
    let url_lines = "audio_url_base = \"https://media.example.com/calls\"\n";
    let config = format!(
        "[[vcon.rule]]\nname = \"plain\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n{url_lines}\n\
         [[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n{url_lines}{}",
        plain.display(),
        sealed.display(),
        sealing(home.path(), "fake_grp.crt")?
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let written = files(&sealed)?;
    assert_eq!(written.len(), 2, "the container and the audio: {written:?}");
    let (container_path, audio_path) = if written[0].to_string_lossy().ends_with(".vcon.json") {
        (&written[0], &written[1])
    } else {
        (&written[1], &written[0])
    };
    let audio_name = audio_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name")?;
    assert!(audio_name.ends_with(".wav.jwe"), "{audio_name}");
    assert!(
        !audio_name.contains("1-1966"),
        "no Call-ID in the name: {audio_name}"
    );

    let key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    let unsigned = vcon_jose::verify(&vcon_jose::decrypt(&std::fs::read(container_path)?, &key)?)?;
    let inner: serde_json::Value = serde_json::from_slice(&unsigned)?;
    let recording = inner["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .find(|d| d["url"].is_string())
        .ok_or("a recording with a url")?;
    assert_eq!(
        recording["url"],
        format!("https://media.example.com/calls/{audio_name}")
    );
    assert_eq!(recording["mediatype"], "audio/x-wav", "the audio inside");
    assert!(recording.get("body").is_none(), "{recording}");

    let file = std::fs::read(audio_path)?;
    assert_eq!(
        recording["content_hash"],
        hash_of(&file),
        "over the file as written"
    );
    let jwe: serde_json::Value = serde_json::from_slice(&file)?;
    assert_eq!(vcon_jose::form_of(&jwe), Form::Encrypted);
    assert_eq!(jwe["unprotected"]["cty"], "audio/x-wav");
    // The WAV's first 48 bytes, raw or in either base64 alphabet, do not
    // appear: 64 characters of chance match in random ciphertext is out of
    // reach, where a 4-byte "RIFF" is not.
    let plain_wav = std::fs::read(
        files(&plain)?
            .into_iter()
            .find(|p| p.to_string_lossy().ends_with(".wav"))
            .ok_or("the plain rule's WAV")?,
    )?;
    let head = &plain_wav[..48];
    let text = String::from_utf8(file.clone())?;
    {
        use base64::Engine as _;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        assert!(
            !file.windows(head.len()).any(|w| w == head)
                && !text.contains(&URL_SAFE_NO_PAD.encode(head))
                && !text.contains(&STANDARD.encode(head)),
            "no WAV in clear"
        );
    }

    let opener = vcon_jose::Opener::load(&home.path().join("fake_grp.key"))?;
    let audio = opener.open_file(&file)?;
    assert_eq!(&audio[..4], b"RIFF");
    assert_eq!(audio, plain_wav, "the same audio");
    assert_eq!(
        vcon_jose::decrypt(&file, &key)?,
        audio,
        "decrypt reads it too"
    );
    Ok(())
}

/// The same with `audio_format = "opus"`: the file inside the JWE is the
/// Ogg Opus stream, and the `mediatype` and `cty` say so.
#[cfg(feature = "opus")]
#[test]
fn an_encrypting_opus_rule_writes_ogg_opus_as_its_own_jwe() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("sealed");
    let config = format!(
        "[[vcon.rule]]\nname = \"sealed\"\nwhen = \"{CALL}\"\ndir = \"{}\"\naudio = \"url\"\n\
         audio_format = \"opus\"\naudio_url_base = \"https://media.example.com/calls\"\n{}",
        dir.display(),
        sealing(home.path(), "fake_grp.crt")?
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let audio_path = files(&dir)?
        .into_iter()
        .find(|p| p.to_string_lossy().ends_with(".ogg.jwe"))
        .ok_or("an .ogg.jwe beside the container")?;
    let file = std::fs::read(&audio_path)?;
    let jwe: serde_json::Value = serde_json::from_slice(&file)?;
    assert_eq!(jwe["unprotected"]["cty"], "audio/ogg");
    let opener = vcon_jose::Opener::load(&home.path().join("fake_grp.key"))?;
    assert_eq!(&opener.open_file(&file)?[..4], b"OggS");
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

/// The one container `dir` holds, as JSON, and its size.
fn only_container(dir: &Path) -> Result<(serde_json::Value, u64), TestError> {
    let written = files(dir)?;
    assert_eq!(written.len(), 1, "{written:?}");
    let bytes = std::fs::read(&written[0])?;
    Ok((serde_json::from_slice(&bytes)?, bytes.len() as u64))
}

/// `compress = "gzip"` signs the gzip of the vCon (core-04 section 5.2) and
/// names `cty` `application/vcon+gzip` (section 5.3.1); `compress = "none"`
/// and no `compress` name `application/vcon`. Each decrypts to the same
/// vCon. No container carries a JWE `zip`.
#[test]
fn an_encrypting_rule_compresses_when_told() -> Result<(), TestError> {
    use base64::Engine as _;
    let home = tempfile::tempdir()?;
    let seal = sealing(home.path(), "fake_grp.crt")?;
    let dirs: Vec<PathBuf> = ["unset", "none", "gzip"]
        .iter()
        .map(|n| home.path().join(n))
        .collect();
    let config = rule("unset", &dirs[0], &seal)
        + &rule("none", &dirs[1], &format!("{seal}compress = \"none\"\n"))
        + &rule("gzip", &dirs[2], &format!("{seal}compress = \"gzip\"\n"));
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    let mut opened = Vec::new();
    let mut sizes = Vec::new();
    for (dir, cty) in dirs.iter().zip([
        "application/vcon",
        "application/vcon",
        "application/vcon+gzip",
    ]) {
        let (value, size) = only_container(dir)?;
        assert_eq!(value["unprotected"]["cty"], cty, "{}", dir.display());
        let protected: serde_json::Value = match value.get("protected") {
            Some(text) => serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(text.as_str().ok_or("protected")?)?,
            )?,
            None => serde_json::Value::Null,
        };
        assert_eq!(protected.get("zip"), None);
        assert_eq!(value["unprotected"].get("zip"), None);
        let unsigned = vcon_jose::verify(&vcon_jose::decrypt(value.to_string().as_bytes(), &key)?)?;
        opened.push(serde_json::from_slice::<serde_json::Value>(&unsigned)?);
        sizes.push(size);
    }
    for member in ["parties", "dialog"] {
        assert_eq!(opened[1][member], opened[2][member], "{member}");
    }
    assert!(sizes[2] < sizes[1], "{sizes:?}");
    Ok(())
}

/// A `compress` value other than `none` or `gzip`, and `compress` on a rule
/// that does not encrypt, are refused at startup.
#[test]
fn a_compress_that_cannot_apply_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("sealed");
    let seal = sealing(home.path(), "fake_grp.crt")?;
    for (extra, expected) in [
        (format!("{seal}compress = \"deflate\"\n"), "deflate"),
        ("compress = \"gzip\"\n".to_string(), "without encrypt_to"),
    ] {
        let out = run(&rule("sealed", &dir, &extra), home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{extra}: {stderr}");
        assert!(stderr.contains("'sealed'"), "{extra}: {stderr}");
        assert!(stderr.contains("compress"), "{extra}: {stderr}");
        assert!(stderr.contains(expected), "{extra}: {stderr}");
        assert!(!dir.exists(), "{extra}: nothing written");
    }
    Ok(())
}

// ── [vcon] defaults ─────────────────────────────────────────────────────

/// The signing certificate (DER) of a sealed container's first signature,
/// opened with `key_name`.
fn signer_der(bytes: &[u8], key_name: &str) -> Result<Vec<u8>, TestError> {
    use base64::Engine as _;
    let key = std::fs::read_to_string(format!("{FIXTURES}/{key_name}"))?;
    let jws: serde_json::Value = serde_json::from_slice(&vcon_jose::decrypt(bytes, &key)?)?;
    Ok(base64::engine::general_purpose::STANDARD.decode(
        jws["signatures"][0]["header"]["x5c"][0]
            .as_str()
            .ok_or("x5c")?,
    )?)
}

/// The DER of the first certificate in the PEM fixture `name`.
fn fixture_der(name: &str) -> Result<Vec<u8>, TestError> {
    use base64::Engine as _;
    let pem = std::fs::read_to_string(format!("{FIXTURES}/{name}"))?;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(body)?)
}

/// A rule that sets none of the four keys takes each from `[vcon]`: it
/// encrypts to the section's certificate, signs with the section's key, and
/// compresses as the section says. A rule's own `compress` overrides it.
#[test]
fn a_rule_inherits_the_vcon_section_s_sealing() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (inherits, overrides) = (home.path().join("inherits"), home.path().join("overrides"));
    let config = format!(
        "[vcon]\n{}compress = \"gzip\"\n\n{}{}",
        sealing(home.path(), "fake_grp.crt")?,
        rule("inherits", &inherits, ""),
        rule("overrides", &overrides, "compress = \"none\"\n"),
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let key = std::fs::read_to_string(format!("{FIXTURES}/fake_grp.key"))?;
    for (dir, cty) in [
        (&inherits, "application/vcon+gzip"),
        (&overrides, "application/vcon"),
    ] {
        let written = files(dir)?;
        assert_eq!(written.len(), 1, "{written:?}");
        let bytes = std::fs::read(&written[0])?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            vcon_jose::form_of(&value),
            Form::Encrypted,
            "{}",
            dir.display()
        );
        assert_eq!(value["unprotected"]["cty"], cty, "{}", dir.display());
        vcon_jose::verify(&vcon_jose::decrypt(&bytes, &key)?)?;
    }
    Ok(())
}

/// A rule's own `encrypt_to`, `sign_key` and `sign_cert` override the
/// section's: the container opens with the rule's recipient key, not the
/// section's, and carries the rule's signing certificate.
#[test]
fn a_rule_s_own_keys_override_the_vcon_section() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("own");
    let other_key = private_copy(home.path(), "other.key")?;
    let config = format!(
        "[vcon]\nencrypt_to = \"{FIXTURES}/other.crt\"\nsign_key = \"{}\"\nsign_cert = \"{FIXTURES}/other.crt\"\n\n{}",
        other_key.display(),
        rule("own", &dir, &sealing(home.path(), "fake_grp.crt")?),
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = files(&dir)?;
    assert_eq!(written.len(), 1, "{written:?}");
    let bytes = std::fs::read(&written[0])?;
    let other = std::fs::read_to_string(format!("{FIXTURES}/other.key"))?;
    assert!(
        vcon_jose::decrypt(&bytes, &other).is_err(),
        "the section's recipient"
    );
    assert_eq!(
        signer_der(&bytes, "fake_grp.key")?,
        fixture_der("fake_grp.crt")?
    );
    Ok(())
}

/// `[vcon]` signing keys without `[vcon] encrypt_to` apply to the rules
/// that encrypt; a rule that does not encrypt writes the unsigned form, and
/// is not refused for keys it did not set.
#[test]
fn section_signing_keys_apply_only_to_rules_that_encrypt() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (plain, sealed) = (home.path().join("plain"), home.path().join("sealed"));
    let config = format!(
        "[vcon]\nsign_key = \"{}\"\nsign_cert = \"{}\"\ncompress = \"gzip\"\n\n{}{}",
        private_copy(home.path(), "fake_grp.key")?.display(),
        chain(home.path())?.display(),
        rule("plain", &plain, ""),
        rule(
            "sealed",
            &sealed,
            &format!("encrypt_to = \"{FIXTURES}/fake_grp.crt\"\n")
        ),
    );
    let out = run(&config, home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plain_value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&files(&plain)?[0])?)?;
    assert_eq!(vcon_jose::form_of(&plain_value), Form::Unsigned);
    let sealed_value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&files(&sealed)?[0])?)?;
    assert_eq!(vcon_jose::form_of(&sealed_value), Form::Encrypted);
    assert_eq!(sealed_value["unprotected"]["cty"], "application/vcon+gzip");
    Ok(())
}

/// A `[vcon]` value that cannot work is refused at startup, naming the
/// section key or the rule that inherits it.
#[test]
fn a_vcon_section_default_that_cannot_work_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("sealed");
    let cases: Vec<(String, &str)> = vec![
        (
            format!(
                "[vcon]\ncompress = \"deflate\"\n\n{}",
                rule("sealed", &dir, "")
            ),
            "[vcon] compress",
        ),
        (
            format!(
                "[vcon]\nencrypt_to = \"{FIXTURES}/fake_grp.crt\"\n\n{}",
                rule("sealed", &dir, "")
            ),
            "needs sign_key and sign_cert",
        ),
        (
            format!("[vcon]\nencrypt_to = \"\"\n\n{}", rule("sealed", &dir, "")),
            "[vcon] encrypt_to",
        ),
    ];
    for (config, expected) in cases {
        let out = run(&config, home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{config}: {stderr}");
        assert!(
            stderr.contains(expected),
            "{config}: wants {expected:?}: {stderr}"
        );
        assert!(!dir.exists(), "{config}: nothing written");
    }
    Ok(())
}
