// SPDX-License-Identifier: MIT OR Apache-2.0

//! Export rules: `[[vcon.rule]]`, each a filter paired with a directory and an
//! audio setting, on the shipped binary.
//!
//! A call that matches several rules is written once per rule, into each
//! rule's own directory, with each rule's own audio setting.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};

#[path = "support/pcap_build.rs"]
mod pcap_build;
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

/// The recording of the one container in `dir`, and that container.
#[cfg(feature = "opus")]
fn recording_in(dir: &Path) -> Result<(serde_json::Value, serde_json::Value), TestError> {
    let container = containers(dir)?.into_iter().next().ok_or("a container")?;
    let recording = container["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .find(|d| d["content_hash"].is_string())
        .cloned()
        .ok_or("a recording with a content_hash")?;
    Ok((recording, container))
}

/// `sha512-` and the base64url SHA-512 of `bytes`.
#[cfg(feature = "opus")]
fn hash_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    format!(
        "sha512-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha512::digest(bytes))
    )
}

/// `audio_format = "opus"`: the recording is Ogg Opus, inline. Its
/// `mediatype` is `audio/ogg`, its body is an Ogg stream whose first packet
/// is the Opus ID header, and its `content_hash` is over the Ogg bytes. The
/// same call as a WAV rule's recording is larger.
#[cfg(feature = "opus")]
#[test]
fn an_opus_rule_carries_the_recording_as_ogg_opus() -> Result<(), TestError> {
    use base64::Engine as _;
    let home = tempfile::tempdir()?;
    let (wav_dir, opus_dir) = (home.path().join("wav"), home.path().join("opus"));
    let config = rule("as-wav", CALL, &wav_dir, "inline")
        + &format!(
            "{}audio_format = \"opus\"\n",
            rule("as-opus", CALL, &opus_dir, "inline")
        );
    let out = run(&config, &[], home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (recording, container) = recording_in(&opus_dir)?;
    assert_eq!(media_of(&container)?, "carried");
    assert_eq!(recording["mediatype"], "audio/ogg");
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(recording["body"].as_str().ok_or("an inline body")?)?;
    assert_eq!(&body[..4], b"OggS", "an Ogg page");
    assert_eq!(&body[28..36], b"OpusHead", "the Opus ID header first");
    assert_eq!(recording["content_hash"], hash_of(&body));

    let (wav, _) = recording_in(&wav_dir)?;
    assert_eq!(wav["mediatype"], "audio/x-wav", "the other rule keeps WAV");
    assert_eq!(wav["duration"], recording["duration"], "the same audio");
    let wav_body = wav["body"].as_str().ok_or("a WAV body")?;
    let ogg_body = recording["body"].as_str().ok_or("an Ogg body")?;
    assert!(
        ogg_body.len() * 3 < wav_body.len(),
        "Opus is a third of the WAV or less"
    );
    Ok(())
}

/// `audio = "url"` with `audio_format = "opus"` writes an `.ogg` beside the
/// container, and the recording names it with `audio/ogg` and its hash.
#[cfg(feature = "opus")]
#[test]
fn an_opus_url_rule_writes_an_ogg_beside_the_container() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("by-url");
    let config = format!(
        "{}audio_url_base = \"https://media.example.com/calls\"\naudio_format = \"opus\"\n",
        rule("by-url", CALL, &dir, "url")
    );
    let out = run(&config, &[], home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (recording, _) = recording_in(&dir)?;
    let url = recording["url"].as_str().ok_or("url")?;
    let name = url
        .strip_prefix("https://media.example.com/calls/")
        .ok_or("the base plus a file name")?;
    assert!(name.ends_with(".ogg"), "{name}");
    let file = std::fs::read(dir.join(name))?;
    assert_eq!(&file[..4], b"OggS");
    assert_eq!(recording["mediatype"], "audio/ogg");
    assert_eq!(recording["content_hash"], hash_of(&file));
    Ok(())
}

/// An `audio_format` other than `wav` and `opus` is refused at startup,
/// naming the rule and the two values; so is `audio_format` on a rule that
/// carries no audio.
#[test]
fn an_audio_format_that_cannot_apply_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("x");
    for (audio, format, needles) in [
        ("inline", "flac", &["'flac'", "'wav'", "'opus'"][..]),
        ("omit", "wav", &["audio_format", "'inline' or 'url'"][..]),
    ] {
        let config = format!(
            "{}audio_format = \"{format}\"\n",
            rule("fmt", CALL, &dir, audio)
        );
        let out = run(&config, &[], home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{format}: {stderr}");
        assert!(stderr.contains("'fmt'"), "{format}: {stderr}");
        for needle in needles {
            assert!(
                stderr.contains(needle),
                "{format}: wants {needle}: {stderr}"
            );
        }
        assert!(!dir.exists(), "{format}: nothing written");
    }
    Ok(())
}

/// A build without the `opus` feature refuses `audio_format = "opus"` at
/// startup and names the feature, rather than writing WAV under a setting
/// that asked for Ogg Opus.
#[cfg(not(feature = "opus"))]
#[test]
fn opus_is_refused_by_a_build_without_the_feature() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("x");
    let config = format!(
        "{}audio_format = \"opus\"\n",
        rule("needs-opus", CALL, &dir, "inline")
    );
    let out = run(&config, &[], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("'needs-opus'") && stderr.contains("`opus` feature"),
        "{stderr}"
    );
    assert!(!dir.exists(), "nothing written");
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

/// The purposes of a container's attachments.
fn purposes(container: &serde_json::Value) -> Vec<String> {
    container["attachments"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|a| a["purpose"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `sip_messages = true` adds the initial INVITE and the final response as
/// `message/sip` attachments, and their SDP as `application/sdp`
/// (draft-howe-vcon-sip-signaling-00 section 8.1); a rule without it adds
/// none.
#[test]
fn a_rule_with_sip_messages_attaches_the_wire_messages() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (with, without) = (home.path().join("with"), home.path().join("without"));
    let config = rule("with", CALL, &with, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\nsip_messages = true\n",
    ) + &rule("without", CALL, &without, "omit");
    let out = run(&config, &[], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let written = containers(&with)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let found = purposes(&written[0]);
    for purpose in ["sip-invite", "sip-response", "sip-sdp"] {
        assert!(found.iter().any(|p| p == purpose), "{purpose} in {found:?}");
    }
    let invite = written[0]["attachments"]
        .as_array()
        .and_then(|l| l.iter().find(|a| a["purpose"] == "sip-invite"))
        .ok_or("a sip-invite attachment")?;
    assert_eq!(invite["mediatype"], "message/sip");
    assert!(
        invite["body"]
            .as_str()
            .is_some_and(|b| b.starts_with("INVITE ")),
        "{invite}"
    );

    let plain = containers(&without)?;
    assert_eq!(plain.len(), 1, "{stderr}");
    let found = purposes(&plain[0]);
    assert!(
        !found
            .iter()
            .any(|p| p.starts_with("sip-") && p != "sip-message-trace"),
        "{found:?}"
    );
    Ok(())
}

/// Under `--redact` a `sip_messages` rule writes no wire attachment.
#[test]
fn redact_refuses_the_wire_messages() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("redacted");
    let config = rule("redacted", CALL, &dir, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\nsip_messages = true\n",
    );
    let out = run(&config, &["--redact"], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let found = purposes(&written[0]);
    for purpose in ["sip-invite", "sip-response", "sip-sdp"] {
        assert!(
            !found.iter().any(|p| p == purpose),
            "{purpose} in {found:?}"
        );
    }
    Ok(())
}

/// `run`, reading `capture` instead of [`CAPTURE`].
fn run_on(capture: &str, config: &str, home: &Path) -> Result<std::process::Output, TestError> {
    let path = home.join("rules.toml");
    std::fs::write(&path, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", capture, "--no-cli-print"])
        .arg("--config")
        .arg(&path)
        .env("HOME", home)
        .output()?)
}

/// The `(event, button)` pairs of a container's signaling object.
fn key_events(container: &serde_json::Value) -> Vec<(String, String)> {
    container["dialog"][0]["party_history"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|e| matches!(e["event"].as_str(), Some("keydown" | "keyup")))
                .map(|e| {
                    (
                        e["event"].as_str().unwrap_or_default().to_owned(),
                        e["button"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `dtmf_events = true` writes each INFO `application/dtmf-relay` as a
/// `keydown` and a `keyup` with its digit; a rule without it writes none.
#[test]
fn a_rule_with_dtmf_events_writes_the_info_key_presses() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (with, without) = (home.path().join("with"), home.path().join("without"));
    let when = "call_id == '2091060b-146f-e011-809a-0019cb53db77@admind-desktop'";
    let config = rule("with", when, &with, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\ndtmf_events = true\n",
    ) + &rule("without", when, &without, "omit");
    let out = run_on("tests/pcap-samples/DTMFsipinfo.pcap", &config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&with)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let events = key_events(&written[0]);
    assert!(
        events.starts_with(&[
            ("keydown".to_owned(), "1".to_owned()),
            ("keyup".to_owned(), "1".to_owned()),
        ]),
        "{events:?}"
    );
    let plain = containers(&without)?;
    assert_eq!(plain.len(), 1, "{stderr}");
    assert!(key_events(&plain[0]).is_empty());
    Ok(())
}

/// `dtmf_events = true` decodes RFC 4733 telephone events without
/// `--telephone-event` and writes each for the party whose SDP advertised the
/// sending socket: here the callee, `10.0.0.2:30000`, pressing `#`.
#[test]
fn a_rule_with_dtmf_events_writes_the_rtp_key_presses() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let capture = home.path().join("rtp-dtmf.pcap");
    let mut frames = pcap_build::g711_call_both_ways("rtp-dtmf@test", 1, |_, _, _| 0xff);
    // Event 11 (`#`), E bit set, duration 800 timestamp units (100 ms at
    // 8000 Hz), sent three times as RFC 4733 section 2.5.1.4 repeats an end
    // packet, half a second into the media.
    for repeat in 0..3u16 {
        let mut packet = vec![0x80, 101];
        packet.extend_from_slice(&(100 + repeat).to_be_bytes());
        packet.extend_from_slice(&8_000u32.to_be_bytes());
        packet.extend_from_slice(&0x3333_3333u32.to_be_bytes());
        packet.extend_from_slice(&[11, 0x80 | 10, 0x03, 0x20]);
        frames.push((
            pcap_build::udp_frame([10, 0, 0, 2], [10, 0, 0, 1], 30000, 20000, &packet),
            510_000 + u64::from(repeat) * 1_000,
        ));
    }
    frames.sort_by_key(|(_, at)| *at);
    pcap_build::write_pcap_at(&capture, &frames, 1)?;

    let dir = home.path().join("rtp");
    let config = rule("rtp", "call_id == 'rtp-dtmf@test'", &dir, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\ndtmf_events = true\n",
    );
    let out = run_on(&capture.to_string_lossy(), &config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let history = &written[0]["dialog"][0]["party_history"];
    let keys: Vec<&serde_json::Value> = history
        .as_array()
        .map(|l| {
            l.iter()
                .filter(|e| matches!(e["event"].as_str(), Some("keydown" | "keyup")))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(keys.len(), 2, "one press, written once: {history:#}");
    assert_eq!(keys[0]["event"], "keydown");
    assert_eq!(keys[0]["party"], 1);
    assert_eq!(keys[0]["button"], "#");
    assert_eq!(keys[1]["event"], "keyup");
    Ok(())
}

/// `SIP_DTMF2.cap` carries seven keys at PT 96, sent from
/// 192.168.105.172:4376, a socket neither party's SDP named, to
/// 192.168.105.110:4376, the socket the callee's 200 OK advertised. The
/// callee received them, so the caller (party 0) pressed them.
///
/// The expected digits and times were read from the capture with tshark,
/// independently of sipnab: `tshark -r tests/pcap-samples/SIP_DTMF2.cap
/// -d udp.port==4376,rtp -o rtpevent.event_payload_type_value:96
/// -Y "rtpevent && rtpevent.end_of_event==1" -T fields -e frame.time_epoch
/// -e rtpevent.event_id -e rtpevent.duration`. Each end packet states a
/// duration of 960 timestamp units, 120 ms at 8000 Hz.
#[test]
fn rtp_keys_from_an_unadvertised_socket_go_by_their_destination() -> Result<(), TestError> {
    const END_PACKETS: [(&str, i64); 7] = [
        ("6", 1_126_267_426_979_545),
        ("7", 1_126_267_428_509_604),
        ("8", 1_126_267_428_989_630),
        ("9", 1_126_267_429_439_658),
        ("1", 1_126_267_430_039_692),
        ("2", 1_126_267_430_549_702),
        ("3", 1_126_267_431_119_725),
    ];
    let home = tempfile::tempdir()?;
    let dir = home.path().join("dtmf2");
    let config = rule("dtmf2", "call_id == '25672@192.168.105.110'", &dir, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\ndtmf_events = true\n",
    );
    let out = run_on("tests/pcap-samples/SIP_DTMF2.cap", &config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let history = &written[0]["dialog"][0]["party_history"];
    let mut found: Vec<(String, String, Option<u64>, i64)> = Vec::new();
    for e in history.as_array().map(Vec::as_slice).unwrap_or_default() {
        if matches!(e["event"].as_str(), Some("keydown" | "keyup")) {
            let time = chrono::DateTime::parse_from_rfc3339(e["time"].as_str().ok_or("time")?)?;
            found.push((
                e["event"].as_str().unwrap_or_default().to_owned(),
                e["button"].as_str().unwrap_or_default().to_owned(),
                e["party"].as_u64(),
                time.timestamp_micros(),
            ));
        }
    }
    let expected: Vec<(String, String, Option<u64>, i64)> = END_PACKETS
        .iter()
        .flat_map(|(digit, up)| {
            [
                (
                    "keydown".to_owned(),
                    (*digit).to_owned(),
                    Some(0),
                    up - 120_000,
                ),
                ("keyup".to_owned(), (*digit).to_owned(), Some(0), *up),
            ]
        })
        .collect();
    assert_eq!(found, expected, "{history:#}");
    Ok(())
}

/// RTP key presses are not written when neither socket names a party: the
/// sender's socket is no party's advertised endpoint, and the destination was
/// advertised only by a forked `183` whose `To` tag is neither party's. The
/// stream still belongs to the call through that SDP, so its key is decoded;
/// the receiver is unknown, so `party_history` gets no `keydown` rather than
/// one with a guessed party.
#[test]
fn rtp_key_presses_from_a_socket_no_party_advertised_are_not_attributed() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let capture = home.path().join("rtp-dtmf-fork.pcap");
    let mut frames = pcap_build::g711_call_both_ways("rtp-dtmf-fork@test", 1, |_, _, _| 0xff);
    let sdp = "v=0\r\no=- 1 1 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 10.0.0.7\r\nt=0 0\r\n\
               m=audio 32000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
    let fork = format!(
        "SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKwhole\r\n\
         From: <sip:a@10.0.0.1>;tag=t1\r\nTo: <sip:b@10.0.0.2>;tag=fork\r\n\
         Call-ID: rtp-dtmf-fork@test\r\nCSeq: 1 INVITE\r\nContact: <sip:b@10.0.0.7:5060>\r\n\
         Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    );
    frames.push((
        pcap_build::udp_frame([10, 0, 0, 7], [10, 0, 0, 1], 5060, 5060, fork.as_bytes()),
        500,
    ));
    // Event 11 (`#`), E bit set, duration 800 timestamp units, from a socket
    // no SDP named to the socket only the forked 183 named.
    for repeat in 0..3u16 {
        let mut packet = vec![0x80, 101];
        packet.extend_from_slice(&(100 + repeat).to_be_bytes());
        packet.extend_from_slice(&8_000u32.to_be_bytes());
        packet.extend_from_slice(&0x4444_4444u32.to_be_bytes());
        packet.extend_from_slice(&[11, 0x80 | 10, 0x03, 0x20]);
        frames.push((
            pcap_build::udp_frame([10, 0, 0, 9], [10, 0, 0, 7], 41000, 32000, &packet),
            510_000 + u64::from(repeat) * 1_000,
        ));
    }
    frames.sort_by_key(|(_, at)| *at);
    pcap_build::write_pcap_at(&capture, &frames, 1)?;

    let dir = home.path().join("fork");
    let config = rule("fork", "call_id == 'rtp-dtmf-fork@test'", &dir, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\ndtmf_events = true\n",
    );
    let out = run_on(&capture.to_string_lossy(), &config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let decoded = stderr.lines().filter(|l| l.contains("DTMF digit=")).count();
    assert_eq!(decoded, 1, "the key is decoded\n{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    assert!(
        key_events(&written[0]).is_empty(),
        "no party to attribute to: {:#}",
        written[0]["dialog"][0]["party_history"]
    );
    Ok(())
}

/// The body of a container's `tags` attachment, when it has one.
fn tags(container: &serde_json::Value) -> Option<serde_json::Value> {
    container["attachments"]
        .as_array()?
        .iter()
        .find(|a| a["purpose"] == "tags")
        .map(|a| a["body"].clone())
}

/// A `[[vcon.rule]]` container carries a `tags` attachment naming the rule
/// and each referenced `[filters]` name the call matched; the flag rule's
/// container carries none.
#[test]
fn a_rule_container_is_tagged_with_its_rule_and_matched_filters() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (dir, flags) = (home.path().join("tagged"), home.path().join("flags"));
    let config =
        format!("[filters]\nthe-call = \"{CALL}\"\nnobody = \"to.user == 'no-such-user'\"\n\n")
            + &rule("tagged", "@nobody OR @the-call", &dir, "omit");
    let flags_dir = flags.to_string_lossy().into_owned();
    let path = home.path().join("rules.toml");
    std::fs::write(&path, &config)?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print"])
        .arg("--config")
        .arg(&path)
        .args(["--export-vcon-when", CALL, "--export-vcon-dir", &flags_dir])
        .env("HOME", home.path())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let body = tags(&written[0]).ok_or("a tags attachment")?;
    let list: Vec<&str> = body
        .as_array()
        .ok_or("a list body")?
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    assert_eq!(&list[..2], ["rule:tagged", "filter:the-call"], "{list:?}");
    assert!(!list.contains(&"filter:nobody"), "{list:?}");
    assert!(
        list.iter().all(|t| t.matches(':').count() == 1),
        "vcon-lib reads the text after the first colon up to the next: {list:?}"
    );

    let from_flags = containers(&flags)?;
    assert_eq!(from_flags.len(), 1, "{stderr}");
    assert!(
        tags(&from_flags[0]).is_none(),
        "the flag rule has no name to tag"
    );
    Ok(())
}

/// `skill_header`, `campaign_header` and `interaction_id_header` copy the
/// named headers' values into the signaling Dialog Object's `skill`,
/// `campaign` and `interaction_id` (draft-ietf-vcon-cc-extension-02 section
/// 3.2).
#[test]
fn a_rule_maps_headers_to_the_cc_dialog_parameters() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let capture = home.path().join("queue.pcap");
    let frames = pcap_build::g711_leg(
        &pcap_build::G711Leg {
            call_id: "queued@test",
            caller: ([10, 0, 0, 1], 20000, 0x1111_1111),
            callee: ([10, 0, 0, 2], 30000, 0x2222_2222),
            header: Some("X-Queue: billing"),
            start_us: 0,
            ends: true,
        },
        1,
        |_, _, _| 0xff,
    );
    pcap_build::write_pcap_at(&capture, &frames, 1)?;
    let dir = home.path().join("cc");
    let config = rule("cc", "call_id == 'queued@test'", &dir, "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\nskill_header = \"X-Queue\"\ncampaign_header = \"X-Campaign\"\n",
    );
    let out = run_on(&capture.to_string_lossy(), &config, home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let signaling = &written[0]["dialog"][0];
    assert_eq!(signaling["skill"], "billing", "{signaling:#}");
    assert!(
        signaling.get("campaign").is_none(),
        "no X-Campaign on the wire"
    );
    Ok(())
}

/// A header name that is not an RFC 3261 token refuses the run, naming the
/// rule and the key.
#[test]
fn a_cc_header_that_is_not_a_header_name_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let config = rule("cc", CALL, &home.path().join("cc"), "omit").replace(
        "audio = \"omit\"\n",
        "audio = \"omit\"\nskill_header = \"X Queue:\"\n",
    );
    let out = run(&config, &[], home.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("'cc'") && stderr.contains("skill_header"),
        "{stderr}"
    );
    Ok(())
}
