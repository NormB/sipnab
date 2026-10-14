// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "vcon")]

//! `-I` reading stored vCon containers, driven through the real binary and
//! the shared store reader.
//!
//! The round trip is the property that carries the weight: a capture exported
//! as vCons and read back must describe the same calls as the capture itself,
//! except for the fields a vCon does not store. Those are asserted explicitly
//! rather than skipped, so a test that silently compared nothing cannot pass.

use std::path::{Path, PathBuf};
use std::process::Output;

type TestError = Box<dyn std::error::Error>;

/// Two INVITE dialogs, both completed, with RTP in one direction each.
const SAMPLE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// A temp directory unique to this test and this process.
fn tmp_dir(name: &str) -> Result<PathBuf, TestError> {
    let dir = std::env::temp_dir().join(format!("sipnab-vconin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Run the real binary from the repository root.
fn run(args: &[&str]) -> Result<Output, TestError> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()?)
}

/// Run, require success, and return stdout.
fn run_ok(args: &[&str]) -> Result<String, TestError> {
    let out = run(args)?;
    if !out.status.success() {
        return Err(format!(
            "sipnab {args:?} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// The JSON objects among the lines of `stdout`.
fn json_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Export every dialog of `SAMPLE` into `dir`, one container each.
fn export_sample(dir: &Path, extra: &[&str]) -> Result<Vec<PathBuf>, TestError> {
    let dir_s = dir.to_str().ok_or("utf-8 path")?;
    let mut args = vec![
        "-N",
        "-I",
        SAMPLE,
        "--export-vcon-when",
        "method == \"INVITE\"",
        "--export-vcon-dir",
        dir_s,
        "--quiet",
    ];
    args.extend_from_slice(extra);
    run_ok(&args)?;
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 2, "the sample holds two INVITE dialogs");
    Ok(files)
}

/// The per-message fields a vCon stores and a round trip must reproduce.
const STORED_MESSAGE_FIELDS: &[&str] = &[
    "timestamp",
    "src",
    "src_port",
    "dst",
    "dst_port",
    "transport",
    "is_request",
    "method",
    "status_code",
    "reason",
    "call_id",
    "from",
    "to",
    "contact",
    "ua",
    "sdp",
    "cseq",
];

/// One message reduced to the stored fields.
fn stored_view(m: &serde_json::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for key in STORED_MESSAGE_FIELDS {
        if let Some(v) = m.get(*key) {
            out.insert((*key).to_string(), v.clone());
        }
    }
    serde_json::Value::Object(out)
}

/// The per-dialog fields a round trip must reproduce.
const STORED_DIALOG_FIELDS: &[&str] = &[
    "call_id",
    "state",
    "method",
    "msg_count",
    "final_status_code",
    "final_status_reason",
    "from",
    "from_display",
    "to",
    "to_display",
    "timing",
    "sdp_timeline",
    "termination",
    "duration_sec",
];

/// One dialog reduced to the stored fields.
fn dialog_view(d: &serde_json::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for key in STORED_DIALOG_FIELDS {
        if let Some(v) = d.get(*key) {
            out.insert((*key).to_string(), v.clone());
        }
    }
    serde_json::Value::Object(out)
}

/// Every message and dialog the capture holds comes back from its vCons with
/// the same stored fields, in the same order — and the fields a vCon does not
/// store are named, not silently compared away.
#[test]
fn a_capture_exported_as_vcons_reads_back_as_the_same_calls() -> Result<(), TestError> {
    let dir = tmp_dir("roundtrip")?;
    export_sample(&dir, &[])?;
    let dir_s = dir.to_str().ok_or("utf-8 path")?;

    // ── Messages ────────────────────────────────────────────────────────
    let direct = json_lines(&run_ok(&["-N", "-I", SAMPLE, "--json", "--quiet"])?);
    let rebuilt = json_lines(&run_ok(&["-N", "-I", dir_s, "--json", "--quiet"])?);
    assert!(!direct.is_empty(), "the capture produced no messages");
    assert_eq!(
        direct.len(),
        rebuilt.len(),
        "the vCons hold a different number of messages than the capture"
    );
    for (i, (d, r)) in direct.iter().zip(&rebuilt).enumerate() {
        assert_eq!(
            stored_view(d),
            stored_view(r),
            "message {i} differs between the capture and its vCon"
        );
        // Provenance: the origin says where the message came from, and a
        // rebuilt message carries no frame pointer, because it was never a
        // frame anyone can re-read.
        assert_eq!(d["input_origin"], "wire");
        assert_eq!(r["input_origin"], "vcon", "message {i} does not say vcon");
        assert!(d.get("frame").is_some(), "a captured message has a frame");
        assert!(r.get("frame").is_none(), "a rebuilt message claims a frame");
        // Header order across names is not stored: the trace keys its header
        // map by name. The SET of extension headers survives; its order is
        // the map's, not the wire's.
        let mut dh: Vec<String> = serde_json::from_value(d["extension_headers"].clone())?;
        let mut rh: Vec<String> = serde_json::from_value(r["extension_headers"].clone())?;
        dh.sort();
        rh.sort();
        assert_eq!(dh, rh, "message {i} lost or gained an extension header");
    }

    // ── Dialogs ─────────────────────────────────────────────────────────
    let direct = json_lines(&run_ok(&["-N", "-I", SAMPLE, "--json-dialogs", "--quiet"])?);
    let rebuilt = json_lines(&run_ok(&["-N", "-I", dir_s, "--json-dialogs", "--quiet"])?);
    let direct: Vec<_> = direct
        .iter()
        .filter(|v| v.get("msg_count").is_some())
        .collect();
    let rebuilt: Vec<_> = rebuilt
        .iter()
        .filter(|v| v.get("msg_count").is_some())
        .collect();
    assert_eq!(direct.len(), 2);
    assert_eq!(rebuilt.len(), 2);
    for (d, r) in direct.iter().zip(&rebuilt) {
        assert_eq!(dialog_view(d), dialog_view(r), "a dialog differs");
        // No RTP is in a vCon, so nothing about media is recomputed: the
        // capture saw a stream per call, the vCon run sees none and claims
        // no media fault either.
        assert!(
            !d["streams"].as_array().ok_or("streams")?.is_empty(),
            "the capture carried RTP"
        );
        assert!(
            r["streams"].as_array().ok_or("streams")?.is_empty(),
            "a stream was fabricated from a vCon"
        );
        assert_eq!(r["diagnosis"]["no_media"], false, "no_media fabricated");
        assert_eq!(r["diagnosis"]["one_way_audio"], false);
        assert_eq!(r["input_origin"], "vcon");
    }

    // ── The analysis says where it came from ────────────────────────────
    let analysis = json_lines(&run_ok(&["-N", "-I", dir_s, "--json-analyze", "--quiet"])?);
    let analysis = analysis
        .iter()
        .find(|v| v.get("findings").is_some())
        .ok_or("no analysis object")?;
    assert_eq!(
        analysis["complete"], false,
        "an analysis rebuilt from vCons is never a complete one"
    );
    let first = &analysis["findings"][0];
    assert_eq!(first["kind"], "rebuilt_from_vcon", "{analysis}");
    assert_eq!(first["severity"], "blind");
    assert_eq!(first["occurrences"], 2, "one occurrence per container");
    let note = first["evidence"][0]["note"].as_str().ok_or("note")?;
    assert!(
        note.contains("RTP"),
        "the note must say media was not recomputed: {note}"
    );
    assert!(
        note.contains("Produced by sipnab"),
        "the producer's own caveat must travel: {note}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// The signaling diagnosis of each call, computed through the shared store
/// reader, is the same from the capture and from its vCons.
#[test]
fn the_signaling_diagnosis_survives_the_round_trip() -> Result<(), TestError> {
    use parking_lot::RwLock;
    use sipnab::rtp::stream_store::StreamStore;
    use sipnab::sip::dialog_store::DialogStore;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    let dir = tmp_dir("diagnosis")?;
    let files = export_sample(&dir, &[])?;
    let opts = sipnab::pipeline::PipelineOptions::default();

    let read = |path: &Path| {
        let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
        let outcome =
            sipnab::capture::replay::read_into_stores(path, &opts, &ds, &ss, &AtomicU64::new(0));
        (ds, ss, outcome)
    };
    let (direct, _, outcome) = read(Path::new(SAMPLE));
    assert!(outcome.error.is_none());
    for file in &files {
        let (rebuilt, streams, outcome) = read(file);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert!(streams.read().is_empty(), "a vCon fabricated a stream");
        let rebuilt = rebuilt.read();
        assert_eq!(rebuilt.len(), 1, "one dialog per container");
        let dialog = rebuilt.iter().next().ok_or("a dialog")?;
        let direct = direct.read();
        let original = direct.get(&dialog.call_id).ok_or("same Call-ID")?;
        assert_eq!(
            sipnab::sip::diagnosis::diagnose_signaling(&original.messages),
            sipnab::sip::diagnosis::diagnose_signaling(&dialog.messages),
            "the signaling diagnosis of {} changed",
            dialog.call_id
        );
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A container whose SIP cannot be read is named with the reason and
/// skipped, and the readable container beside it is still read. Two shapes:
/// a vCon carrying no SIP signaling, and a file that opens like JSON and is
/// not.
#[test]
fn an_unreadable_container_is_skipped_with_its_reason_and_the_rest_are_read()
-> Result<(), TestError> {
    let dir = tmp_dir("unreadable")?;
    let files = export_sample(&dir, &[])?;
    let no_sip = dir.join("no-sip.vcon.json");
    std::fs::write(&no_sip, r#"{"vcon": "0.4.0", "parties": []}"#)?;
    let not_json = dir.join("truncated.vcon.json");
    std::fs::write(&not_json, r#"{"vcon": "0.4.0", "attachm"#)?;
    std::fs::remove_file(&files[1])?;

    let out = run(&["-N", "-I", dir.to_str().ok_or("utf-8")?, "--json-dialogs"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the readable container must still be read: {stderr}"
    );
    assert!(
        stderr.contains("no-sip.vcon.json") && stderr.contains("no SIP signaling"),
        "the container without SIP and the reason must be named: {stderr}"
    );
    assert!(
        stderr.contains("truncated.vcon.json") && stderr.contains("not JSON"),
        "the file that is not JSON and the reason must be named: {stderr}"
    );
    let dialogs: Vec<_> = json_lines(&String::from_utf8(out.stdout)?)
        .into_iter()
        .filter(|v| v.get("msg_count").is_some())
        .collect();
    assert_eq!(
        dialogs.len(),
        1,
        "the readable container's dialog is missing"
    );

    // Named directly, an unreadable container fails the run with the reason.
    let out = run(&["-N", "-I", no_sip.to_str().ok_or("utf-8")?])?;
    assert!(
        !out.status.success(),
        "a named unreadable container must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no SIP signaling"), "{stderr}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A container the schema refuses is still READ when its SIP is readable,
/// and the schema findings travel with the analysis. The shapes are real:
/// vcon.store hands a container back with `extensions` as an object
/// (`{"sip-signaling": true, "CC": true}`), which the core-04 schema (an
/// array of strings) refuses, and a raw store response carries a `_meta`
/// member beside it.
#[test]
fn a_schema_invalid_container_with_readable_sip_is_read_with_its_findings() -> Result<(), TestError>
{
    let dir = tmp_dir("schema")?;
    let files = export_sample(&dir, &[])?;
    let mut container: serde_json::Value = serde_json::from_slice(&std::fs::read(&files[0])?)?;
    std::fs::remove_file(&files[0])?;
    std::fs::remove_file(&files[1])?;
    container["extensions"] = serde_json::json!({"sip-signaling": true, "CC": true});
    let store_shape = dir.join("store-shape.vcon.json");
    std::fs::write(&store_shape, container.to_string())?;
    container["_meta"] = serde_json::json!({"stored_at": "2026-10-09T12:00:00Z"});
    let raw_response = dir.join("raw-response.vcon.json");
    std::fs::write(&raw_response, container.to_string())?;

    for path in [&store_shape, &raw_response] {
        let p = path.to_str().ok_or("utf-8")?;
        let out = run(&["-N", "-I", p, "--json-dialogs", "--no-cli-print"])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{p} must be read: {stderr}");
        assert!(
            stderr.contains("/extensions") && stderr.contains("schema"),
            "{p}: the schema finding must be reported per container: {stderr}"
        );
        let dialogs: Vec<_> = json_lines(&String::from_utf8(out.stdout)?)
            .into_iter()
            .filter(|v| v.get("msg_count").is_some())
            .collect();
        assert_eq!(dialogs.len(), 1, "{p}: its dialog is missing");
        assert_eq!(dialogs[0]["msg_count"], 6);

        let analysis = json_lines(&run_ok(&["-N", "-I", p, "--json-analyze"])?)
            .into_iter()
            .find(|v| v.get("findings").is_some())
            .ok_or("no analysis")?;
        let note = analysis["findings"][0]["evidence"][0]["note"]
            .as_str()
            .ok_or("note")?;
        assert!(
            note.contains("fails the draft-ietf-vcon-vcon-core-04 schema")
                && note.contains("/extensions"),
            "{p}: the analysis must carry the schema finding: {note}"
        );
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A redacted container reads back with its pseudonyms, never anything else.
#[test]
fn a_redacted_container_keeps_its_pseudonyms() -> Result<(), TestError> {
    let dir = tmp_dir("redacted")?;
    let files = export_sample(&dir, &["--redact"])?;
    let container: serde_json::Value = serde_json::from_slice(&std::fs::read(&files[0])?)?;
    let call_id = container["dialog"][0]["sip_call_id"]
        .as_str()
        .ok_or("sip_call_id")?
        .to_string();
    assert!(
        !call_id.contains("10.0.2.20"),
        "the export was not redacted"
    );

    let out = run_ok(&["-N", "-I", files[0].to_str().ok_or("utf-8")?, "--json"])?;
    let messages = json_lines(&out);
    assert!(!messages.is_empty());
    for m in &messages {
        assert_eq!(
            m["call_id"],
            call_id.as_str(),
            "the pseudonymous Call-ID changed"
        );
        let text = m.to_string();
        assert!(
            !text.contains("10.0.2.20") && !text.contains("10.0.2.15") && !text.contains("sipp@"),
            "an original identity or address came back: {text}"
        );
        assert!(m["from"].as_str().ok_or("from")?.contains("u-"), "{text}");
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// The publisher's own conforming example (core-04 Appendix A.4) is a valid
/// container with a recording and no SIP. There is nothing to analyze, so
/// naming it with `-I` fails the run and says why.
/// `-I` refuses a container whose `critical` lists an extension sipnab does
/// not support, naming it, and reads the rest of a set.
///
/// [Section 4.1.4 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4):
/// "An implementation that does not recognize or support the extensions listed
/// in the critical parameter MUST NOT attempt to process or operate on the
/// vCon, except to reject it or report unsupported content."
#[test]
fn a_container_with_an_unsupported_critical_extension_is_refused() -> Result<(), TestError> {
    let dir = tmp_dir("critical")?;
    let files = export_sample(&dir, &[])?;
    let mut container: serde_json::Value = serde_json::from_slice(&std::fs::read(&files[0])?)?;
    container["critical"] = serde_json::json!(["x-redaction"]);
    std::fs::write(&files[0], container.to_string())?;

    let out = run(&[
        "-N",
        "-I",
        files[0].to_str().ok_or("utf-8")?,
        "--json-dialogs",
    ])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a named container sipnab must not read: {stderr}"
    );
    assert!(stderr.contains("x-redaction"), "{stderr}");
    assert!(
        json_lines(&String::from_utf8(out.stdout)?)
            .iter()
            .all(|v| v.get("msg_count").is_none()),
        "nothing from it is analyzed"
    );

    let out = run(&["-N", "-I", dir.to_str().ok_or("utf-8")?, "--json-dialogs"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the other container is read: {stderr}"
    );
    assert!(stderr.contains("x-redaction"), "{stderr}");
    let dialogs = json_lines(&String::from_utf8(out.stdout)?)
        .into_iter()
        .filter(|v| v.get("msg_count").is_some())
        .count();
    assert_eq!(dialogs, 1, "only the readable container's dialog");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn a_valid_container_without_signaling_is_refused_with_the_reason() -> Result<(), TestError> {
    let dir = tmp_dir("appendix")?;
    let path = dir.join("ab_call_ext_rec.vcon.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "created_at": "2022-06-21T13:53:00-04:00",
            "parties": [
                {"tel": "+12345678901", "name": "Alice"},
                {"tel": "+19876543210", "name": "Bob"}
            ],
            "dialog": [{
                "type": "recording",
                "start": "2022-06-21T17:53:26.000+00:00",
                "duration": 33.12,
                "parties": [0, 1],
                "url": "https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core/raw/refs/heads/main/examples/ab_call.mp3",
                "mediatype": "audio/x-mp3",
                "filename": "ab_call.mp3",
                "content_hash": "sha512-GLy6IPaIUM1GqzZqfIPZlWjaDsNgNvZM0iCONNThnH0a75fhUM6cYzLZ5GynSURREvZwmOh54-2lRRieyj82UQ"
            }],
            "analysis": [],
            "attachments": [],
            "uuid": "01a07da8-c2bb-83e5-b9a2-279e0d16bc46"
        })
        .to_string(),
    )?;
    let out = run(&["-N", "-I", path.to_str().ok_or("utf-8")?, "--json-analyze"])?;
    assert!(!out.status.success(), "there is nothing to analyze");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no SIP signaling"), "{stderr}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A container from a producer that stores each message whole, as a
/// `message/sip` attachment (draft-howe-vcon-sip-signaling), is read too.
/// Such a container stores no addressing, and the rebuilt messages say so by
/// carrying none.
#[test]
fn message_sip_attachments_are_read() -> Result<(), TestError> {
    let dir = tmp_dir("messagesip")?;
    let path = dir.join("howe.vcon.json");
    let invite = "INVITE sip:bob@example.com SIP/2.0\r\n\
                  Via: SIP/2.0/TCP client.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                  From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                  To: Bob <sip:bob@example.com>\r\n\
                  Call-ID: a84b4c76e66710@client.example.com\r\n\
                  CSeq: 314159 INVITE\r\n\
                  Max-Forwards: 70\r\n\
                  Content-Length: 0\r\n\r\n";
    let ok = "SIP/2.0 486 Busy Here\r\n\
              Via: SIP/2.0/TCP client.example.com:5060;branch=z9hG4bK776asdhds\r\n\
              From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
              To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
              Call-ID: a84b4c76e66710@client.example.com\r\n\
              CSeq: 314159 INVITE\r\n\
              Content-Length: 0\r\n\r\n";
    std::fs::write(
        &path,
        serde_json::json!({
            "vcon": "0.4.0",
            "uuid": "01928e10-193e-8231-b9a2-279e0d16bc46",
            "created_at": "2026-10-09T12:00:00Z",
            "extensions": ["sip-signaling"],
            "parties": [{"tel": "+12345678901"}, {"tel": "+19876543210"}],
            "attachments": [
                {"purpose": "sip-invite", "start": "2026-10-09T12:00:00.100Z", "party": 0,
                 "dialog": 0, "mediatype": "message/sip", "encoding": "none", "body": invite},
                {"purpose": "sip-response", "start": "2026-10-09T12:00:00.250Z", "party": 1,
                 "dialog": 0, "mediatype": "message/sip", "encoding": "none", "body": ok}
            ]
        })
        .to_string(),
    )?;
    let p = path.to_str().ok_or("utf-8")?;
    let messages = json_lines(&run_ok(&["-N", "-I", p, "--json"])?);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["method"], "INVITE");
    assert_eq!(messages[0]["timestamp"], "2026-10-09T12:00:00.100+00:00");
    assert_eq!(
        messages[0]["transport"], "TCP",
        "transport from the top Via"
    );
    assert_eq!(messages[1]["status_code"], 486);
    assert_eq!(messages[1]["input_origin"], "vcon");
    let dialogs: Vec<_> = json_lines(&run_ok(&["-N", "-I", p, "--json-dialogs"])?)
        .into_iter()
        .filter(|v| v.get("msg_count").is_some())
        .collect();
    assert_eq!(dialogs.len(), 1);
    assert_eq!(dialogs[0]["final_status_code"], 486);
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// `--cores` shards pcap frames across workers and has no reader for a
/// container, so a set holding one is refused rather than half-read.
#[test]
fn cores_refuses_a_set_holding_a_vcon() -> Result<(), TestError> {
    let dir = tmp_dir("cores")?;
    let files = export_sample(&dir, &[])?;
    let out = run(&[
        "-N",
        "-I",
        files[0].to_str().ok_or("utf-8")?,
        "--cores",
        "2",
    ])?;
    assert_eq!(
        out.status.code(),
        Some(2),
        "--cores with a vCon must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--cores") && stderr.contains("vCon"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A BPF filter selects captured frames, and a container holds rebuilt
/// messages, so the pair is refused with the reason rather than read
/// unfiltered.
#[test]
fn a_bpf_filter_is_refused_for_a_vcon() -> Result<(), TestError> {
    let dir = tmp_dir("bpf")?;
    let files = export_sample(&dir, &[])?;
    let out = run(&[
        "-N",
        "-I",
        files[0].to_str().ok_or("utf-8")?,
        "udp port 5060",
    ])?;
    assert!(
        !out.status.success(),
        "a BPF filter over a vCon must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BPF filter") && stderr.contains("vCon container"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
