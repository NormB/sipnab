// SPDX-License-Identifier: MIT OR Apache-2.0

//! `sipnab --vcon-spool-status <SPOOL_DIR>`: the command-line door to the
//! answer the MCP tool `vcon_spool_status` and `GET /v1/vcon/spool` give.
//!
//! These run the binary, because the exit code, what reaches standard output
//! and the flags clap refuses beside it are the surface.

#![cfg(all(feature = "vcon", unix))]

use std::path::Path;

type TestError = Box<dyn std::error::Error>;

/// Run the binary with `args`: standard output, standard error, exit code.
fn sipnab(args: &[&str]) -> Result<(String, String, Option<i32>), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["--no-config"])
        .args(args)
        .output()?;
    Ok((
        String::from_utf8(out.stdout)?,
        String::from_utf8(out.stderr)?,
        out.status.code(),
    ))
}

/// Write `text` to `dir/name`, creating `dir`.
fn put(dir: &Path, name: &str, text: &str) -> Result<(), TestError> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(name), text)?;
    Ok(())
}

/// A spool with one pending, one delivered and two failed containers, one of
/// them with its record.
fn spool() -> Result<tempfile::TempDir, TestError> {
    let dir = tempfile::tempdir()?;
    put(dir.path(), "p.vcon.json", "{}")?;
    put(&dir.path().join("delivered"), "d.vcon.json", "{}")?;
    put(&dir.path().join("failed"), "f.vcon.json", "{}")?;
    put(&dir.path().join("failed"), "g.vcon.json", "{}")?;
    put(
        &dir.path().join("failed"),
        "f.vcon.json.error.json",
        &serde_json::json!({
            "at": "2026-10-07T12:00:00Z", "body": "{\"error\":\"vCon already exists\"}",
            "body_truncated": false, "file": "f.vcon.json", "method": "POST",
            "reason": null, "status": 409, "url": "https://vcon.example.com/v1/vcons",
        })
        .to_string(),
    )?;
    Ok(dir)
}

/// The answer without `as_of`, the one member that differs between two reads.
fn undated(mut v: serde_json::Value) -> Result<serde_json::Value, TestError> {
    v.as_object_mut()
        .ok_or("the answer is an object")?
        .remove("as_of");
    Ok(v)
}

/// The command prints, as JSON, exactly what the shared function answers for
/// the same spool with every failed record on one page, and exits 0.
#[test]
fn the_cli_prints_the_shared_answer() -> Result<(), TestError> {
    let dir = spool()?;
    let path = dir.path().to_str().ok_or("utf-8 path")?;
    let (stdout, stderr, code) = sipnab(&["--vcon-spool-status", path])?;
    assert_eq!(code, Some(0), "{stderr}");
    let printed: serde_json::Value = serde_json::from_str(&stdout)?;

    let shared = sipnab::app::vcon_spool::snapshot(
        dir.path(),
        sipnab::app::vcon_spool::SpoolPage::all(),
        chrono::Utc::now(),
    )?;
    assert_eq!(
        undated(printed.clone())?,
        undated(serde_json::to_value(&shared)?)?,
        "the CLI must print the shared answer"
    );
    assert_eq!(printed["pending"], 1, "{printed}");
    assert_eq!(printed["failed"], 2, "{printed}");
    assert_eq!(printed["failures"][0]["record"]["status"], 409, "{printed}");
    assert_eq!(
        printed["truncated"], false,
        "every record on one page: {printed}"
    );
    Ok(())
}

/// A spool directory that does not exist yet is an answer, not an error: zero
/// everywhere and `exists: false`, and nothing is created.
#[test]
fn a_spool_that_does_not_exist_prints_zeros() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("not-yet");
    let (stdout, stderr, code) =
        sipnab(&["--vcon-spool-status", missing.to_str().ok_or("utf-8")?])?;
    assert_eq!(code, Some(0), "{stderr}");
    let printed: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(printed["spool"]["exists"], false, "{printed}");
    assert_eq!(printed["pending"], 0, "{printed}");
    assert!(
        !missing.exists(),
        "the status command must not create the spool"
    );
    Ok(())
}

/// Like `--vcon-forward` and `--vcon-fetch`, it is a separate mode: clap
/// refuses it beside a capture source, exit 2.
#[test]
fn it_refuses_a_capture_source_beside_it() -> Result<(), TestError> {
    let dir = spool()?;
    let (_, stderr, code) = sipnab(&[
        "--vcon-spool-status",
        dir.path().to_str().ok_or("utf-8")?,
        "-I",
        "tests/pcap-samples/sip-rtp-g711.pcap",
    ])?;
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    Ok(())
}
