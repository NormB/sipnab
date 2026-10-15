// SPDX-License-Identifier: MIT OR Apache-2.0

//! A SIPREC recording session exported as a vCon, through the real binary.
//!
//! The unit tests in `src/output/vcon_siprec.rs` build the dialog by hand.
//! This file reads the recording INVITE out of a capture, so the multipart
//! framing, the `Content-Length` and the dialog store's recognition of the
//! metadata are all in the path, and checks what an operator gets from
//! `--export-vcon`: the recorded call's participants as parties, the stream
//! map, a container the vendored schemas accept, and `--redact` treating the
//! participants like every other party.

#![cfg(all(feature = "native", feature = "vcon"))]

#[path = "support/schema.rs"]
mod schema;

type TestError = Box<dyn std::error::Error>;

/// The SIPREC INVITE `tests/mcp_siprec_test.rs` describes: generator-derived
/// from OpenSIPS 4.0.1's `siprec` module, two participants, three labeled
/// streams.
const SIPREC: &str = "tests/pcap-samples/siprec-opensips-invite.pcap";

/// The Call-ID of the recording session in [`SIPREC`].
const SIPREC_CALL: &str = "4f1c0a2e-siprec@172.28.0.31";

/// Export the recording session, with `extra` arguments, and parse it.
fn export(extra: &[&str]) -> Result<serde_json::Value, TestError> {
    let mut args = vec!["-N", "-q", "-I", SIPREC, "--export-vcon", SIPREC_CALL];
    args.extend_from_slice(extra);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(&args)
        .env("NO_COLOR", "1")
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "export failed ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// The attachment with `purpose`.
fn attachment<'a>(
    v: &'a serde_json::Value,
    purpose: &str,
) -> Result<&'a serde_json::Value, TestError> {
    Ok(v["attachments"]
        .as_array()
        .ok_or("attachments")?
        .iter()
        .find(|a| a["purpose"] == purpose)
        .ok_or_else(|| format!("no {purpose} attachment"))?)
}

/// The two participants of the recorded call are parties 2 and 3, the SRC
/// and SRS keep 0 and 1 with their roles, and the observer stays last.
#[test]
fn a_recording_session_names_the_recorded_participants() -> Result<(), TestError> {
    let v = export(&[])?;
    let parties = v["parties"].as_array().ok_or("parties")?;
    assert_eq!(parties.len(), 5, "{parties:#?}");
    assert_eq!(parties[0]["role"], "recording-client");
    assert_eq!(parties[1]["role"], "recording-server");
    assert_eq!(parties[2]["sip"], "sip:alice@example.invalid");
    assert_eq!(parties[2]["name"], "Alice");
    assert_eq!(parties[3]["sip"], "sip:bob@example.invalid");
    assert_eq!(parties[4]["role"], "observer");
    Ok(())
}

/// Each labeled stream names the participant that sends it.
#[test]
fn each_stream_names_its_sender() -> Result<(), TestError> {
    let v = export(&[])?;
    let map = attachment(&v, "sipnab-siprec-streams")?;
    let owners: Vec<(String, u64)> = map["body"]["streams"]
        .as_array()
        .ok_or("streams")?
        .iter()
        .filter_map(|s| Some((s["label"].as_str()?.to_string(), s["party"].as_u64()?)))
        .collect();
    assert_eq!(
        owners,
        [("0".into(), 2), ("1".into(), 2), ("2".into(), 3)],
        "Alice sends labels 0 and 1, Bob sends label 2"
    );
    let note = attachment(&v, "sipnab-capture-completeness")?["body"]["note"]
        .as_str()
        .ok_or("note")?
        .to_string();
    assert!(note.contains("SIPREC recording session"), "{note}");
    Ok(())
}

/// The container validates against both vendored copies of the working
/// group's schema: the test-suite copy and the one sipnab checks with.
#[test]
fn a_recording_session_container_validates_against_the_schema() -> Result<(), TestError> {
    let v = export(&[])?;
    let validator = schema::load_validator("vcon.schema.json")?;
    schema::assert_valid(&validator, &v, "SIPREC recording session");
    let report = sipnab::output::vcon_schema::validate(&v);
    assert!(
        report.errors.is_empty(),
        "the vendored core-04 schema refused it: {:#?}",
        report.errors
    );
    Ok(())
}

/// `--redact` rewrites the participants' AORs and names like any party's.
#[test]
fn redaction_reaches_the_recorded_participants() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("redact.key");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&key, "a fixed key for this test")?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    let key = key.display().to_string();
    let v = export(&["--redact", "--redact-key-file", &key])?;
    let parties = v["parties"].as_array().ok_or("parties")?;
    assert_eq!(parties.len(), 5, "the participants survive as parties");
    let text = serde_json::to_string(&v)?;
    for secret in ["alice@example.invalid", "bob@example.invalid", "\"Alice\""] {
        assert!(!text.contains(secret), "{secret} survived --redact");
    }
    assert!(
        parties[2]["sip"].as_str().is_some() && parties[2]["name"].as_str().is_some(),
        "rewritten, not dropped: {}",
        parties[2]
    );
    Ok(())
}
