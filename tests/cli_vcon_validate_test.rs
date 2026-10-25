// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--vcon-validate`: a vCon container checked against sipnab's vendored
//! schema on the CLI, held to REST.
//!
//! The same check `POST /v1/vcon/validate` and the MCP `validate_vcon` tool
//! run: `output::vcon_schema::validate`, after the readers' one step opens a
//! signed or encrypted container. The CLI prints the REST answer, so
//! `--vcon-validate --json` and the route agree field for field. It is a file
//! job: it reads the file it is given, runs before any capture opens, and
//! needs no `-I`. A valid container exits 0 and an invalid one 3, the code
//! for "the tool worked, the input is non-conformant", so a CI step can gate
//! on it.

#![cfg(all(unix, feature = "full"))]

#[path = "support/server.rs"]
mod server;

type TestError = Box<dyn std::error::Error>;

const VALID: &str = "tests/fixtures/vcon/sip-rtp-g711-1966.vcon.json";

/// Run `sipnab <args>` from the repository root, with no capture.
fn run(args: &[&str]) -> Result<std::process::Output, TestError> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()?)
}

/// The fixture with `vcon` made a number, which the schema refuses.
fn invalid_copy(dir: &std::path::Path) -> Result<std::path::PathBuf, TestError> {
    let text =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VALID))?;
    let mut v: serde_json::Value = serde_json::from_str(&text)?;
    v["vcon"] = serde_json::json!(7);
    let path = dir.join("bad.vcon.json");
    std::fs::write(&path, v.to_string())?;
    Ok(path)
}

/// The last line of stdout as JSON.
fn last_json(out: &std::process::Output) -> Result<serde_json::Value, TestError> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().last().ok_or("no stdout")?;
    Ok(serde_json::from_str(line)?)
}

/// A valid container is `valid`, exit 0, and the JSON is the REST answer.
#[test]
fn a_valid_container_is_valid_and_matches_rest() -> Result<(), TestError> {
    let out = run(&["--vcon-validate", VALID, "--json"])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cli = last_json(&out)?;
    assert_eq!(cli["verdict"], "valid", "{cli}");
    assert_eq!(cli["errors"], serde_json::json!([]), "{cli}");

    let srv = server::ApiServer::spawn_with_pcap("tests/pcap-samples/sip-problem-call.pcap", &[])?;
    let body =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VALID))?;
    let rest = srv.post_json("/v1/vcon/validate", &body)?;
    assert_eq!(rest.status, 200, "{}", rest.body);
    assert_eq!(cli, rest.json()?, "CLI --vcon-validate --json == REST");
    Ok(())
}

/// An invalid container exits 3, names each finding, and its JSON is the
/// REST answer.
#[test]
fn an_invalid_container_exits_3_and_matches_rest() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let bad = invalid_copy(dir.path())?;
    let bad_str = bad.to_str().ok_or("a UTF-8 temp path")?;

    let out = run(&["--vcon-validate", bad_str])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "stdout:\n{stdout}");
    assert!(stdout.contains("invalid: 1 finding"), "{stdout}");
    let row: Vec<&str> = stdout
        .lines()
        .find(|l| l.starts_with("/vcon"))
        .ok_or("the finding row")?
        .split_whitespace()
        .collect();
    assert_eq!(&row[..2], &["/vcon", "type"], "{stdout}");

    let out = run(&["--vcon-validate", bad_str, "--json"])?;
    assert_eq!(out.status.code(), Some(3));
    let cli = last_json(&out)?;
    let srv = server::ApiServer::spawn_with_pcap("tests/pcap-samples/sip-problem-call.pcap", &[])?;
    let rest = srv.post_json("/v1/vcon/validate", &std::fs::read_to_string(&bad)?)?;
    assert_eq!(cli, rest.json()?, "CLI --vcon-validate --json == REST");
    Ok(())
}

/// A file that is not JSON, or JSON that is not an object, cannot be
/// validated: exit 1 with REST's reason. A file that cannot be read exits 1
/// naming it.
#[test]
fn what_cannot_be_validated_exits_1() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let not_json = dir.path().join("not.json");
    std::fs::write(&not_json, "not json")?;
    let array = dir.path().join("array.json");
    std::fs::write(&array, "[1]")?;
    for (path, why) in [
        (&not_json, "must be a JSON vCon container"),
        (&array, "a vCon container is a JSON object"),
    ] {
        let out = run(&["--vcon-validate", path.to_str().ok_or("utf-8")?])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "stderr:\n{stderr}");
        assert!(stderr.contains(why), "stderr:\n{stderr}");
    }
    let missing = dir.path().join("missing.json");
    let out = run(&["--vcon-validate", missing.to_str().ok_or("utf-8")?])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(stderr.contains("missing.json"), "stderr:\n{stderr}");
    Ok(())
}
