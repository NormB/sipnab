// SPDX-License-Identifier: MIT OR Apache-2.0

//! Export rules: `[[vcon.rule]]`, each a filter paired with a directory and an
//! audio setting, on the shipped binary.
//!
//! A call that matches several rules is written once per rule, into each
//! rule's own directory, with each rule's own audio setting.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The completed call in `CAPTURE`, which holds a second call still in
/// progress.
const CALL: &str = "call_id == '1-1966@10.0.2.20'";

/// The containers in `dir`, parsed.
fn containers(dir: &Path) -> Result<Vec<serde_json::Value>, TestError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.to_string_lossy().ends_with(".vcon.json") {
            out.push(serde_json::from_slice(&std::fs::read(&path)?)?);
        }
    }
    Ok(out)
}

/// The `media` token the container's completeness block records.
fn media_of(container: &serde_json::Value) -> Result<String, TestError> {
    let body = container["attachments"]
        .as_array()
        .ok_or("attachments")?
        .iter()
        .find(|a| a["purpose"] == "sipnab-capture-completeness")
        .map(|a| &a["body"])
        .ok_or("a capture_completeness attachment")?;
    Ok(body["media"].as_str().unwrap_or_default().to_owned())
}

/// Run sipnab over the capture with `config` and `extra` arguments.
fn run(config: &str, extra: &[&str], home: &Path) -> Result<std::process::Output, TestError> {
    let path = home.join("rules.toml");
    std::fs::write(&path, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print"])
        .arg("--config")
        .arg(&path)
        .args(extra)
        .env("HOME", home)
        .output()?)
}

fn rule(name: &str, when: &str, dir: &Path, audio: &str) -> String {
    format!(
        "[[vcon.rule]]\nname = \"{name}\"\nwhen = \"{when}\"\ndir = \"{}\"\naudio = \"{audio}\"\n\n",
        dir.display()
    )
}

/// One call, three rules: two match it and each writes its own container
/// with its own audio setting; the third matches nothing and writes nothing.
#[test]
fn a_call_is_written_once_per_matching_rule() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (a, b, c): (PathBuf, PathBuf, PathBuf) = (
        home.path().join("with-audio"),
        home.path().join("signaling"),
        home.path().join("nobody"),
    );
    let config = rule("with-audio", CALL, &a, "inline")
        + &rule(
            "signaling",
            &format!("{CALL} AND to.user =~ '.'"),
            &b,
            "omit",
        )
        + &rule("nobody", "to.user == 'no-such-user'", &c, "inline");
    let out = run(&config, &[], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let with_audio = containers(&a)?;
    assert_eq!(with_audio.len(), 1, "{stderr}");
    assert_eq!(
        media_of(&with_audio[0])?,
        "carried",
        "inline audio is carried"
    );

    let signaling = containers(&b)?;
    assert_eq!(signaling.len(), 1, "{stderr}");
    assert_eq!(
        media_of(&signaling[0])?,
        "not-considered",
        "omit carries none"
    );

    assert!(
        containers(&c)?.is_empty(),
        "a rule that matched nothing wrote nothing"
    );
    for name in ["with-audio", "signaling", "nobody"] {
        assert!(
            stderr.contains(name),
            "the run reports rule {name}: {stderr}"
        );
    }
    Ok(())
}

/// `--export-vcon-when` and `--export-vcon-dir` are one more rule beside the
/// configured ones.
#[test]
fn the_flags_are_one_more_rule() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (a, flags) = (home.path().join("rule"), home.path().join("flags"));
    let config = rule("from-config", CALL, &a, "omit");
    let flags_dir = flags.to_string_lossy().into_owned();
    let out = run(
        &config,
        &["--export-vcon-when", CALL, "--export-vcon-dir", &flags_dir],
        home.path(),
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(containers(&a)?.len(), 1, "{stderr}");
    assert_eq!(containers(&flags)?.len(), 1, "{stderr}");
    Ok(())
}

/// A rule the config cannot run is refused at startup, naming it.
#[test]
fn an_unusable_rule_refuses_the_run_naming_it() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("x");
    for (config, needle) in [
        (
            rule("bad-audio", "method == 'INVITE'", &dir, "loud"),
            "bad-audio",
        ),
        (
            rule("bad-filter", "method === 'INVITE'", &dir, "omit"),
            "bad-filter",
        ),
        (
            rule("twice", "method == 'INVITE'", &dir, "omit")
                + &rule("twice", "method == 'BYE'", &dir, "omit"),
            "twice",
        ),
        (
            "[[vcon.rule]]\nname = \"no-dir\"\nwhen = \"method == 'INVITE'\"\n".to_owned(),
            "no-dir",
        ),
    ] {
        let out = run(&config, &[], home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{config}\n{stderr}");
        assert!(stderr.contains(needle), "names {needle}: {stderr}");
    }
    Ok(())
}

/// A rule's `max_inline_media_mib` bounds that rule's containers only: the
/// same call is carried by a rule without one and refused out loud by a rule
/// whose budget it exceeds.
#[test]
fn a_rule_has_its_own_inline_media_budget() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (small, open) = (home.path().join("small"), home.path().join("open"));
    let config = format!(
        "{}max_inline_media_mib = 0\n\n{}",
        rule("small", CALL, &small, "inline"),
        rule("open", CALL, &open, "inline")
    );
    let out = run(&config, &[], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(media_of(&containers(&small)?[0])?, "refused-over-budget");
    assert_eq!(media_of(&containers(&open)?[0])?, "carried");
    Ok(())
}

/// `audio = "url"`: the WAV is written beside the container, and the
/// container's recording names `audio_url_base` plus the WAV's file name and
/// the WAV's hash, with no body. sipnab writes the file and serves nothing.
#[test]
fn a_url_rule_writes_the_wav_beside_the_container_and_references_it() -> Result<(), TestError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha512};

    let home = tempfile::tempdir()?;
    let dir = home.path().join("by-url");
    let config = format!(
        "{}audio_url_base = \"https://media.example.com/calls/\"\n",
        rule("by-url", CALL, &dir, "url")
    );
    let out = run(&config, &[], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let container = containers(&dir)?.into_iter().next().ok_or("a container")?;
    assert_eq!(media_of(&container)?, "referenced");
    let recording = container["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .find(|d| d["url"].is_string())
        .ok_or("a recording with a url")?;
    assert!(recording.get("body").is_none(), "{recording}");
    let url = recording["url"].as_str().ok_or("url")?;
    let name = url
        .strip_prefix("https://media.example.com/calls/")
        .ok_or_else(|| format!("the base plus a file name: {url}"))?;
    assert!(name.ends_with(".wav") && !name.contains('/'), "{name}");
    let wav = std::fs::read(dir.join(name))?;
    assert_eq!(&wav[..4], b"RIFF", "a WAV beside the container");
    let expected = format!("sha512-{}", URL_SAFE_NO_PAD.encode(Sha512::digest(&wav)));
    assert_eq!(recording["content_hash"], expected);
    Ok(())
}

/// A `url` rule needs an HTTPS `audio_url_base`, and is refused without one.
#[test]
fn a_url_rule_needs_an_https_base() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("x");
    for (extra, needle) in [
        ("", "audio_url_base"),
        ("audio_url_base = \"http://media.example.com/\"\n", "https"),
    ] {
        let config = format!("{}{extra}", rule("needs-base", CALL, &dir, "url"));
        let out = run(&config, &[], home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("needs-base") && stderr.contains(needle),
            "{stderr}"
        );
    }
    Ok(())
}

/// `--redact` with export rules and no export flag redacts the rules'
/// containers: the rules are the export it applies to.
#[test]
fn redact_applies_to_rule_containers() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("redacted");
    let out = run(
        &rule("redacted", CALL, &dir, "omit"),
        &["--redact"],
        home.path(),
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    assert_eq!(
        written[0]["redacted"]["type"], "pseudonymized",
        "{}",
        written[0]["redacted"]
    );
    Ok(())
}

/// `--redact` on a run that exports nothing, by flag or by rule, is still
/// refused, saying why.
#[test]
fn redact_without_any_export_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    // `--cores N -I` is dispatched apart from the single-core run, and is
    // refused the same way.
    for extra in [&["--redact"][..], &["--redact", "--cores", "2"][..]] {
        let out = run("", extra, home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{extra:?}: {stderr}");
        assert!(stderr.contains("exports none"), "{extra:?}: {stderr}");
        assert!(
            stderr.contains("[[vcon.rule]]"),
            "the remedy names rules: {stderr}"
        );
    }
    Ok(())
}
