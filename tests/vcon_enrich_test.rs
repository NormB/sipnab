// SPDX-License-Identifier: MIT OR Apache-2.0

//! Post-call enrichment: `[[vcon.enrich]]` sends a call's audio and container
//! to the operator's own service before the container is written, and appends
//! the Analysis Objects it answers with.
//!
//! The service here is a stub on a loopback port, so every way a service can
//! behave is driven: it answers, it fails, it hangs past the timeout, and it
//! answers with something that is not an analysis. The container is written in
//! every case and says what happened.
#![cfg(all(feature = "native", feature = "vcon"))]

#[path = "support/executable.rs"]
mod executable;
#[path = "support/pcap_build.rs"]
mod pcap_build;
mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;

type TestError = Box<dyn std::error::Error>;

const ENRICHMENT: &str = "sipnab-enrichment";

/// How the stub service answers.
#[derive(Clone, Copy)]
enum Answer {
    /// One transcript analysis.
    Transcript,
    /// One summary analysis, after reading what it was sent.
    Summary,
    /// HTTP 500.
    Fail,
    /// No answer for longer than the timeout.
    Hang,
    /// HTTP 200 with a body that is not an analysis list.
    Malformed,
    /// HTTP 200 with this body.
    Raw(&'static str),
}

/// A stub service on a loopback port. Every request body it receives is sent
/// on the returned channel.
fn stub(answer: Answer) -> Result<(String, mpsc::Receiver<serde_json::Value>), TestError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/enrich", listener.local_addr()?);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut reader = BufReader::new(stream);
            let mut len = 0usize;
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                headers.push(line.trim_end().to_owned());
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; len];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let mut request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let seen = request.clone();
            request["_headers"] = headers.into();
            let reply = match answer {
                Answer::Transcript => serde_json::json!({"analysis": [{
                    "type": "transcript", "vendor": "stub", "product": "stub-stt",
                    "encoding": "none", "mediatype": "text/plain", "body": "hello there"
                }]})
                .to_string(),
                Answer::Summary => {
                    let seen = seen["vcon"]["analysis"].as_array().map_or(0, Vec::len);
                    serde_json::json!({"analysis": [{
                        "type": "summary", "vendor": "stub", "encoding": "none",
                        "body": format!("read {seen} earlier analysis")
                    }]})
                    .to_string()
                }
                Answer::Malformed => r#"{"analysis": [{"vendor": "no type"}]}"#.to_owned(),
                Answer::Raw(text) => text.to_owned(),
                Answer::Fail | Answer::Hang => String::new(),
            };
            let _ = tx.send(request);
            let stream = reader.get_mut();
            match answer {
                Answer::Hang => std::thread::sleep(std::time::Duration::from_secs(5)),
                Answer::Fail => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\n\r\nboom",
                    );
                }
                _ => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\n\r\n{reply}",
                        reply.len()
                    );
                }
            }
        }
    });
    Ok((url, rx))
}

/// A tone that differs per stream.
fn tone(stream: usize, frame: usize, i: usize) -> u8 {
    ((stream * 37 + frame * 3 + i) % 200) as u8
}

/// One answered call with a second of audio both ways.
fn call() -> Vec<(Vec<u8>, u64)> {
    pcap_build::g711_leg(
        &pcap_build::G711Leg {
            call_id: "enrich-call",
            caller: ([10, 1, 0, 1], 20000, 0xa1a1_a1a1),
            callee: ([10, 2, 0, 1], 30000, 0xa2a2_a2a2),
            header: None,
            start_us: 0,
            ends: true,
        },
        1,
        tone,
    )
}

/// A rule writing into `dir`, then `enrich`.
fn config(dir: &Path, enrich: &str) -> String {
    format!(
        "[[vcon.rule]]\nname = \"calls\"\nwhen = \"call_id =~ '.'\"\ndir = \"{}\"\n\n{enrich}",
        dir.display()
    )
}

/// One `[[vcon.enrich]]` for the rule, sending to `url`.
fn service(name: &str, url: &str, extra: &str) -> String {
    format!("[[vcon.enrich]]\nname = \"{name}\"\nrules = [\"calls\"]\nurl = \"{url}\"\n{extra}\n")
}

/// Run sipnab over the call with `config`.
fn run(home: &Path, config: &str, extra: &[&str]) -> Result<std::process::Output, TestError> {
    let pcap = home.join("call.pcap");
    pcap_build::write_pcap_at(&pcap, &call(), 1)?;
    let cfg = home.join("sipnab.toml");
    std::fs::write(&cfg, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--no-cli-print", "-I"])
        .arg(&pcap)
        .arg("--config")
        .arg(&cfg)
        .args(extra)
        .env("HOME", home)
        .output()?)
}

/// The one container in `dir`.
fn container(dir: &Path) -> Result<serde_json::Value, TestError> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.to_string_lossy().ends_with(".vcon.json") {
            found.push(serde_json::from_slice(&std::fs::read(&path)?)?);
        }
    }
    assert_eq!(found.len(), 1, "one container in {}", dir.display());
    Ok(found.remove(0))
}

/// The enrichment attachment's `services` list.
fn outcomes(v: &serde_json::Value) -> Result<Vec<serde_json::Value>, TestError> {
    let body = v["attachments"]
        .as_array()
        .ok_or("attachments")?
        .iter()
        .find(|a| a["purpose"] == ENRICHMENT)
        .map(|a| &a["body"])
        .ok_or("an enrichment attachment")?;
    Ok(body["services"].as_array().ok_or("services")?.clone())
}

/// The analysis entries whose `type` is `kind`.
fn analyses<'a>(v: &'a serde_json::Value, kind: &str) -> Vec<&'a serde_json::Value> {
    v["analysis"]
        .as_array()
        .map(|a| a.iter().filter(|x| x["type"] == kind).collect())
        .unwrap_or_default()
}

/// A service that answers: its analysis is appended, the request carried the
/// call's audio and its container, and the container says what was sent where.
#[test]
fn an_answer_is_appended_and_the_container_says_where_the_audio_went() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, requests) = stub(Answer::Transcript)?;
    let out = run(home.path(), &config(&dir, &service("stt", &url, "")), &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let request = requests.try_recv()?;
    assert_eq!(request["service"], "stt");
    // One entry per leg, naming the leg's signaling object.
    assert_eq!(
        request["audio"].as_array().map(Vec::len),
        Some(1),
        "{request}"
    );
    assert_eq!(request["audio"][0]["mediatype"], "audio/wav", "{request}");
    assert_eq!(request["audio"][0]["dialog"], 0);
    assert_eq!(request["audio"][0]["sip_call_id"], "enrich-call");
    assert!(
        request["audio"][0]["body"]
            .as_str()
            .is_some_and(|b| b.len() > 1000)
    );
    assert_eq!(request["vcon"]["dialog"][0]["sip_call_id"], "enrich-call");
    assert!(
        request["vcon"]["analysis"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "the container goes without sipnab's own analysis: {request}"
    );

    let v = container(&dir)?;
    let transcripts = analyses(&v, "transcript");
    assert_eq!(transcripts.len(), 1, "{v}");
    assert_eq!(transcripts[0]["body"], "hello there");
    assert_eq!(transcripts[0]["vendor"], "stub");
    assert_eq!(analyses(&v, "report").len(), 1, "sipnab's report stays");
    let services = outcomes(&v)?;
    assert_eq!(services.len(), 1);
    assert_eq!(services[0]["service"], "stt");
    assert_eq!(services[0]["outcome"], "ok", "{services:?}");
    assert_eq!(
        services[0]["sent"],
        serde_json::json!(["audio", "signaling"])
    );
    assert_eq!(services[0]["target"], url.as_str());
    let validator = support::schema::load_validator("vcon.schema.json")?;
    support::schema::assert_valid(&validator, &v, "an enriched container");
    Ok(())
}

/// Services run in order, and a later one is sent what an earlier one added.
#[test]
fn a_later_service_reads_an_earlier_answer() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (first, _) = stub(Answer::Transcript)?;
    let (second, requests) = stub(Answer::Summary)?;
    let enrich = service("stt", &first, "") + &service("summarize", &second, "");
    let out = run(home.path(), &config(&dir, &enrich), &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let request = requests.try_recv()?;
    assert_eq!(
        request["vcon"]["analysis"][0]["type"], "transcript",
        "{request}"
    );
    let v = container(&dir)?;
    assert_eq!(
        analyses(&v, "summary")[0]["body"],
        "read 1 earlier analysis"
    );
    Ok(())
}

/// `send = ["signaling"]` sends no audio, and the container records that,
/// even when the rule retains the call's audio for its own container.
#[test]
fn signaling_only_sends_no_audio() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, requests) = stub(Answer::Transcript)?;
    let enrich = service("stt", &url, "send = [\"signaling\"]");
    let rule = config(&dir, &enrich).replace(
        "when = \"call_id =~ '.'\"\n",
        "when = \"call_id =~ '.'\"\naudio = \"inline\"\n",
    );
    assert!(
        rule.contains("audio = \"inline\""),
        "the rule retains audio"
    );
    let out = run(home.path(), &rule, &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let request = requests.try_recv()?;
    assert!(request.get("audio").is_none(), "{request}");
    let v = container(&dir)?;
    assert_eq!(outcomes(&v)?[0]["sent"], serde_json::json!(["signaling"]));
    Ok(())
}

/// Every way a service can fail: the container is still written, without the
/// service's analysis, and says which service failed and how.
#[test]
fn a_failing_service_never_loses_the_call() -> Result<(), TestError> {
    for (answer, outcome) in [
        (Answer::Fail, "failed"),
        (Answer::Hang, "timeout"),
        (Answer::Malformed, "malformed"),
    ] {
        let home = tempfile::tempdir()?;
        let dir = home.path().join("out");
        let (url, _) = stub(answer)?;
        let enrich = service("stt", &url, "timeout_secs = 1");
        let out = run(home.path(), &config(&dir, &enrich), &[])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{outcome}: {stderr}");
        let v = container(&dir)?;
        assert!(analyses(&v, "transcript").is_empty(), "{outcome}: {v}");
        let services = outcomes(&v)?;
        assert_eq!(services[0]["outcome"], outcome, "{services:?}");
        assert!(
            services[0]["detail"]
                .as_str()
                .is_some_and(|d| !d.is_empty()),
            "{outcome}: {services:?}"
        );
        assert!(
            stderr.contains("stt"),
            "the run names the service: {stderr}"
        );
    }
    Ok(())
}

/// A `command` service reads the request on stdin and answers on stdout.
#[test]
fn a_command_service_answers_on_stdout() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let script = home.path().join("stt.sh");
    executable::write_executable(
        &script,
        "#!/bin/sh\ncat > /dev/null\nprintf '%s' '{\"analysis\":[{\"type\":\"transcript\",\
         \"vendor\":\"cmd\",\"encoding\":\"none\",\"body\":\"from a command\"}]}'\n",
    )?;
    let enrich = format!(
        "[[vcon.enrich]]\nname = \"stt\"\nrules = [\"calls\"]\ncommand = \"{}\"\n",
        script.display()
    );
    let out = run(home.path(), &config(&dir, &enrich), &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = container(&dir)?;
    assert_eq!(analyses(&v, "transcript")[0]["body"], "from a command");
    assert_eq!(outcomes(&v)?[0]["outcome"], "ok");
    Ok(())
}

/// What sipnab refuses at startup, each naming the enrichment.
#[test]
fn bad_enrichments_are_refused_at_startup() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let cases = [
        (
            service("stt", "http://127.0.0.1:9/x", "").replace("[\"calls\"]", "[\"nope\"]"),
            "no [[vcon.rule]] named 'nope'",
        ),
        (
            "[[vcon.enrich]]\nname = \"stt\"\nrules = [\"calls\"]\n".to_owned(),
            "one of url or command",
        ),
        (service("stt", "http://192.0.2.7/x", ""), "https"),
        (
            service("stt", "http://127.0.0.1:9/x", "send = [\"video\"]"),
            "send",
        ),
        (
            service("stt", "http://127.0.0.1:9/x", "")
                + &service("stt", "http://127.0.0.1:9/y", ""),
            "used by two",
        ),
    ];
    for (enrich, needle) in cases {
        let out = run(home.path(), &config(&dir, &enrich), &[])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{needle}: {stderr}");
        assert!(stderr.contains("[[vcon.enrich]]"), "{stderr}");
        assert!(stderr.contains(needle), "{needle}: {stderr}");
    }
    // Redaction cannot pseudonymize what a service answers.
    let out = run(
        home.path(),
        &config(&dir, &service("stt", "http://127.0.0.1:9/x", "")),
        &["--redact"],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("[[vcon.enrich]] cannot run with --redact"),
        "{stderr}"
    );
    Ok(())
}

/// A command that exits non-zero, and one that does not answer in time: the
/// container is written and records which.
#[test]
fn a_failing_command_never_loses_the_call() -> Result<(), TestError> {
    for (body, outcome, detail) in [
        ("cat > /dev/null\nexit 3", "failed", "exit"),
        ("sleep 5", "timeout", "within 1 s"),
    ] {
        let home = tempfile::tempdir()?;
        let dir = home.path().join("out");
        let script = home.path().join("stt.sh");
        executable::write_executable(&script, &format!("#!/bin/sh\n{body}\n"))?;
        let enrich = format!(
            "[[vcon.enrich]]\nname = \"stt\"\nrules = [\"calls\"]\ncommand = \"{}\"\n\
             timeout_secs = 1\n",
            script.display()
        );
        let out = run(home.path(), &config(&dir, &enrich), &[])?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let services = outcomes(&container(&dir)?)?;
        assert_eq!(services[0]["outcome"], outcome, "{services:?}");
        assert!(
            services[0]["detail"]
                .as_str()
                .is_some_and(|d| d.contains(detail)),
            "{services:?}"
        );
    }
    Ok(())
}

/// `auth_file` names the header that authenticates; it is sent to the
/// service and recorded nowhere in the container.
#[test]
fn the_auth_header_is_sent_and_not_recorded() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let token = home.path().join("stt.token");
    std::fs::write(&token, "Authorization: Bearer sekrit-token-value\n")?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    let (url, requests) = stub(Answer::Transcript)?;
    let enrich = service("stt", &url, &format!("auth_file = \"{}\"", token.display()));
    let out = run(home.path(), &config(&dir, &enrich), &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let request = requests.try_recv()?;
    let headers: Vec<&str> = request["_headers"]
        .as_array()
        .ok_or("headers")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        headers.contains(&"Authorization: Bearer sekrit-token-value"),
        "{headers:?}"
    );
    let text = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect::<String>();
    assert!(
        !text.contains("sekrit"),
        "the credential stays out of the container"
    );
    Ok(())
}

/// A WTF transcription answer: the body of the first Analysis Object in
/// [section 12.2 of draft-howe-vcon-wtf-extension-02](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-12.2).
const WTF_ANSWER: &str = r#"{"analysis": [{
    "type": "wtf_transcription", "vendor": "openai", "product": "whisper-large-v3",
    "encoding": "json",
    "body": {
        "transcript": {"text": "The quick brown fox jumps over the lazy dog.",
                       "language": "en-US", "duration": 3.5, "confidence": 0.96},
        "segments": [{"id": 0, "start": 0.0, "end": 3.5,
                      "text": "The quick brown fox jumps over the lazy dog.",
                      "confidence": 0.96, "speaker": 0}],
        "metadata": {"created_at": "2025-01-02T12:00:00Z",
                     "processed_at": "2025-01-02T12:00:15Z",
                     "provider": "whisper", "model": "whisper-large-v3",
                     "processing_time": 15.2}
    }
}]}"#;

/// The same answer without its required `segments` section.
const WTF_NO_SEGMENTS: &str = r#"{"analysis": [{
    "type": "wtf_transcription", "vendor": "openai", "encoding": "json",
    "body": {
        "transcript": {"text": "t", "language": "en-US", "duration": 3.5, "confidence": 0.96},
        "metadata": {"created_at": "2025-01-02T12:00:00Z",
                     "processed_at": "2025-01-02T12:00:15Z",
                     "provider": "whisper", "model": "whisper-large-v3"}
    }
}]}"#;

/// A WTF transcription is appended as the Analysis Object the service sent,
/// and the container declares the extension in `extensions` and not in
/// `critical`.
///
/// [Section 5.1 of draft-howe-vcon-wtf-extension-02](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-5.1):
/// the extension "Does not require listing in the critical parameter".
/// [Section 5.3](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-5.3):
/// a vCon holding one "SHOULD include \"wtf_transcription\" in the extensions
/// array".
#[test]
fn a_wtf_transcription_is_appended_and_declared() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, _) = stub(Answer::Raw(WTF_ANSWER))?;
    let out = run(home.path(), &config(&dir, &service("stt", &url, "")), &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = container(&dir)?;
    let wtf = analyses(&v, "wtf_transcription");
    assert_eq!(wtf.len(), 1);
    assert_eq!(wtf[0]["encoding"], "json");
    assert_eq!(
        wtf[0]["body"]["transcript"]["text"],
        "The quick brown fox jumps over the lazy dog."
    );
    assert_eq!(wtf[0]["body"]["segments"][0]["end"], 3.5);
    let extensions = v["extensions"].as_array().ok_or("extensions")?;
    assert_eq!(
        extensions
            .iter()
            .filter(|e| *e == "wtf_transcription")
            .count(),
        1,
        "{extensions:?}"
    );
    assert!(v.get("critical").is_none());
    assert_eq!(outcomes(&v)?[0]["outcome"], "ok");
    let validator = support::schema::load_validator("vcon.schema.json")?;
    support::schema::assert_valid(&validator, &v, "a container with a WTF transcription");
    Ok(())
}

/// A WTF transcription without a required section is not appended, and the
/// container records the service's answer as malformed, naming the section.
#[test]
fn an_invalid_wtf_transcription_is_recorded_as_a_failure() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, _) = stub(Answer::Raw(WTF_NO_SEGMENTS))?;
    let out = run(home.path(), &config(&dir, &service("stt", &url, "")), &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let v = container(&dir)?;
    assert!(analyses(&v, "wtf_transcription").is_empty());
    let extensions = v["extensions"].as_array().ok_or("extensions")?;
    assert!(
        !extensions.iter().any(|e| e == "wtf_transcription"),
        "{extensions:?}"
    );
    let services = outcomes(&v)?;
    assert_eq!(services[0]["outcome"], "malformed", "{services:?}");
    assert!(
        services[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("segments")),
        "{services:?}"
    );
    assert!(stderr.contains("segments"), "{stderr}");
    Ok(())
}

/// The `provenance` record on `analysis`, an Analysis Object.
fn provenance(analysis: &serde_json::Value) -> Result<&serde_json::Value, TestError> {
    analysis
        .get("provenance")
        .filter(|p| p.is_object())
        .ok_or_else(|| format!("no provenance object on {analysis}").into())
}

/// The `inputs` entries of `record` naming `element`, as (index, hash).
fn inputs(record: &serde_json::Value, element: &str) -> Vec<(u64, String)> {
    record["inputs"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|i| i["element"] == element)
                .map(|i| {
                    (
                        i["index"].as_u64().unwrap_or(u64::MAX),
                        i["content_hash"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every enrichment Analysis Object carries a provenance record of
/// draft-howe-vcon-provenance-00: the model, when it was generated, each
/// element sipnab sent the service bound by its hash, and the hash of the
/// output. The container lists `provenance` in `extensions`.
///
/// [Section 4.2.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-provenance-00#section-4.2.1)
/// requires `model.vendor`, `model.name` and `generated_at`;
/// [section 4.2.2](https://datatracker.ietf.org/doc/html/draft-howe-vcon-provenance-00#section-4.2.2)
/// defines `inputs` and `output_hash`;
/// [section 3](https://datatracker.ietf.org/doc/html/draft-howe-vcon-provenance-00#section-3)
/// says a vCon holding one "SHOULD include \"provenance\" in the extensions
/// array" and that it "Does not require listing in the critical parameter".
#[test]
fn an_enrichment_carries_its_provenance() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (first, first_requests) = stub(Answer::Transcript)?;
    let (second, second_requests) = stub(Answer::Summary)?;
    let enrich = service("stt", &first, "") + &service("summarize", &second, "");
    let rule = config(&dir, &enrich).replace(
        "when = \"call_id =~ '.'\"\n",
        "when = \"call_id =~ '.'\"\naudio = \"inline\"\n",
    );
    assert!(
        rule.contains("audio = \"inline\""),
        "the rule inlines audio"
    );
    let out = run(home.path(), &rule, &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = container(&dir)?;
    let extensions = v["extensions"].as_array().ok_or("extensions")?;
    assert_eq!(
        extensions.iter().filter(|e| *e == "provenance").count(),
        1,
        "{extensions:?}"
    );
    assert!(v.get("critical").is_none());

    let transcript = analyses(&v, "transcript")[0];
    let record = provenance(transcript)?;
    assert_eq!(record["model"]["vendor"], "stub");
    assert_eq!(record["model"]["name"], "stub-stt", "the analysis product");
    let at = record["generated_at"].as_str().ok_or("generated_at")?;
    assert!(
        chrono::DateTime::parse_from_rfc3339(at).is_ok(),
        "generated_at is RFC 3339: {at}"
    );
    // The output hash is over the body the service sent: a `none` body's
    // text.
    assert_eq!(
        record["output_hash"],
        sipnab::app::vcon_hash::token(b"hello there")
    );

    // Each element of the container sipnab sent, bound by the hash of its
    // canonical form as sent.
    let request = first_requests.try_recv()?;
    for element in ["dialog", "attachments"] {
        let sent = request["vcon"][element].as_array().ok_or(element)?;
        let name = element.trim_end_matches('s');
        let found = inputs(record, name);
        for (i, item) in sent.iter().enumerate() {
            let want = sipnab::app::vcon_hash::json_token(item);
            assert!(
                found.contains(&(i as u64, want.clone())),
                "{name} {i} with {want}: {found:?}"
            );
        }
    }
    assert!(inputs(record, "analysis").is_empty(), "stt saw no analysis");
    // The leg's audio, bound by the hash of the WAV sent, which is the
    // content_hash core-04 gives the leg's inline recording.
    let wav = request["audio"][0]["body"].as_str().ok_or("audio body")?;
    let wav = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(wav)?
    };
    let wav_hash = sipnab::app::vcon_hash::token(&wav);
    assert_eq!(v["dialog"][0]["content_hash"], wav_hash.as_str());
    assert!(inputs(record, "dialog").contains(&(0, wav_hash)));

    // The second service was sent the first one's transcript: its record
    // names it by its index in the container, with the hash of what was sent.
    let summary = analyses(&v, "summary")[0];
    let record = provenance(summary)?;
    assert_eq!(
        record["model"]["name"], "summarize",
        "no product: the service name"
    );
    let request = second_requests.try_recv()?;
    let sent = &request["vcon"]["analysis"][0];
    let index = v["analysis"]
        .as_array()
        .ok_or("analysis")?
        .iter()
        .position(|a| a["type"] == "transcript")
        .ok_or("the transcript")?;
    assert_eq!(
        inputs(record, "analysis"),
        [(index as u64, sipnab::app::vcon_hash::json_token(sent))]
    );
    // sipnab's own report is not among them: it was not sent.
    assert!(!inputs(record, "analysis").iter().any(|(i, _)| *i == 0));

    // The enrichment attachment stays: it records outcomes that have no
    // Analysis Object to carry a provenance record.
    assert_eq!(outcomes(&v)?.len(), 2);
    let validator = support::schema::load_validator("vcon.schema.json")?;
    support::schema::assert_valid(&validator, &v, "a container with provenance");
    Ok(())
}

/// A service's own provenance record is kept: its model, version,
/// parameters and time. sipnab writes `inputs` and `output_hash` itself,
/// from what it sent and what it carries. A record without a model name is
/// refused, and the answer recorded as malformed.
#[test]
fn a_services_provenance_is_kept_and_completed() -> Result<(), TestError> {
    const SUPPLIED: &str = r#"{"analysis": [{
        "type": "summary", "vendor": "acme", "product": "m1", "encoding": "json",
        "body": {"summary": "s"},
        "provenance": {
            "model": {"vendor": "acme", "name": "m1", "version": "m1-2026"},
            "generated_at": "2026-01-02T03:04:05Z",
            "parameters": {"temperature": 0.2},
            "prompt": {"template": "https://example.com/prompts/summary/v1"},
            "inputs": [{"element": "analysis", "index": 0}],
            "output_hash": "sha512-not-this"
        }
    }]}"#;
    const NO_NAME: &str = r#"{"analysis": [{
        "type": "summary", "vendor": "acme", "encoding": "none", "body": "s",
        "provenance": {"model": {"vendor": "acme"}, "generated_at": "2026-01-02T03:04:05Z"}
    }]}"#;
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, _) = stub(Answer::Raw(SUPPLIED))?;
    let out = run(home.path(), &config(&dir, &service("sum", &url, "")), &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = container(&dir)?;
    let record = provenance(analyses(&v, "summary")[0])?;
    assert_eq!(record["model"]["version"], "m1-2026");
    assert_eq!(record["generated_at"], "2026-01-02T03:04:05Z");
    assert_eq!(record["parameters"]["temperature"], 0.2);
    assert_eq!(
        record["prompt"]["template"],
        "https://example.com/prompts/summary/v1"
    );
    assert_eq!(
        record["output_hash"],
        sipnab::app::vcon_hash::json_token(&serde_json::json!({"summary": "s"}))
    );
    assert!(
        inputs(record, "analysis").is_empty(),
        "the service's own inputs are replaced"
    );
    assert!(!inputs(record, "dialog").is_empty());

    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, _) = stub(Answer::Raw(NO_NAME))?;
    let out = run(home.path(), &config(&dir, &service("sum", &url, "")), &[])?;
    assert!(out.status.success());
    let v = container(&dir)?;
    assert!(analyses(&v, "summary").is_empty());
    let services = outcomes(&v)?;
    assert_eq!(services[0]["outcome"], "malformed", "{services:?}");
    assert!(
        services[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("provenance") && d.contains("name")),
        "{services:?}"
    );
    Ok(())
}

/// An answer holding no analysis and the lawful basis attachment of
/// [section 5.3 of draft-howe-vcon-lawful-basis-02](https://datatracker.ietf.org/doc/html/draft-howe-vcon-lawful-basis-02#section-5.3).
const LAWFUL_BASIS_ANSWER: &str = r#"{"analysis": [], "attachments": [{
    "purpose": "lawful_basis", "start": "2025-01-02T12:15:30Z",
    "party": 0, "dialog": 0, "encoding": "json",
    "body": {
        "lawful_basis": "consent",
        "expiration": "2026-01-02T12:00:00Z",
        "purpose_grants": [
            {"purpose": "recording", "granted": true, "granted_at": "2025-01-02T12:15:30Z"},
            {"purpose": "transcription", "granted": true, "granted_at": "2025-01-02T12:15:30Z"},
            {"purpose": "sentiment_analysis", "granted": false, "granted_at": "2025-01-02T12:15:30Z"}
        ],
        "proof_mechanisms": [{
            "proof_type": "verbal_confirmation", "timestamp": "2025-01-02T12:15:30Z",
            "proof_data": {"dialog_reference": 0, "time_offset": "00:01:23",
                           "confirmation_text": "Yes, I consent to recording this call"}
        }],
        "terms_of_service": "https://example.com/terms/v2024.1",
        "status_interval": "30d",
        "content_hash": {"algorithm": "sha-256", "canonicalization": "jcs",
                         "value": "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"},
        "registry": {"type": "scitt", "url": "https://transparency.example.com/lawful_purpose/registry"}
    }
}]}"#;

/// With `lawful_basis = true`, a lawful basis attachment the service answers
/// with is carried as it was sent, the container lists `lawful_basis` in
/// `extensions`, and the service's line in the enrichment attachment names
/// it, so it reads as the service's and not sipnab's.
#[test]
fn an_opted_in_service_supplies_a_lawful_basis() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, _) = stub(Answer::Raw(LAWFUL_BASIS_ANSWER))?;
    let enrich = service("consent", &url, "lawful_basis = true");
    let out = run(home.path(), &config(&dir, &enrich), &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = container(&dir)?;
    let sent: serde_json::Value = serde_json::from_str(LAWFUL_BASIS_ANSWER)?;
    let sent = &sent["attachments"][0];
    let attachments = v["attachments"].as_array().ok_or("attachments")?;
    let found: Vec<(usize, &serde_json::Value)> = attachments
        .iter()
        .enumerate()
        .filter(|(_, a)| a["purpose"] == "lawful_basis")
        .collect();
    assert_eq!(found.len(), 1);
    let (index, carried) = found[0];
    for key in ["purpose", "start", "party", "dialog", "encoding", "body"] {
        assert_eq!(carried[key], sent[key], "{key} is carried unchanged");
    }
    let extensions = v["extensions"].as_array().ok_or("extensions")?;
    assert!(
        extensions.iter().any(|e| e == "lawful_basis"),
        "{extensions:?}"
    );
    assert!(v.get("critical").is_none());
    let services = outcomes(&v)?;
    assert_eq!(services[0]["outcome"], "ok", "{services:?}");
    assert_eq!(services[0]["attachments"], serde_json::json!([index]));
    let validator = support::schema::load_validator("vcon.schema.json")?;
    support::schema::assert_valid(&validator, &v, "a container with a lawful basis");
    Ok(())
}

/// Without `lawful_basis = true`, sipnab carries no lawful basis: an answer
/// with attachments is recorded as malformed, saying how to allow it.
#[test]
fn a_lawful_basis_is_refused_unless_the_service_opts_in() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let (url, _) = stub(Answer::Raw(LAWFUL_BASIS_ANSWER))?;
    let out = run(
        home.path(),
        &config(&dir, &service("consent", &url, "")),
        &[],
    )?;
    assert!(out.status.success());
    let v = container(&dir)?;
    let attachments = v["attachments"].as_array().ok_or("attachments")?;
    assert!(!attachments.iter().any(|a| a["purpose"] == "lawful_basis"));
    let extensions = v["extensions"].as_array().ok_or("extensions")?;
    assert!(!extensions.iter().any(|e| e == "lawful_basis"));
    let services = outcomes(&v)?;
    assert_eq!(services[0]["outcome"], "malformed", "{services:?}");
    assert!(
        services[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("lawful_basis = true")),
        "{services:?}"
    );
    Ok(())
}

/// `lawful_basis` takes `true` or `false`; anything else is refused at
/// startup.
#[test]
fn lawful_basis_is_a_boolean() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let enrich = service("consent", "http://127.0.0.1:9/x", "lawful_basis = \"yes\"");
    let out = run(home.path(), &config(&dir, &enrich), &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("lawful_basis"), "{stderr}");
    Ok(())
}
