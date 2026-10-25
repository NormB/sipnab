// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--find-in-files`: which of several capture files hold the dialogs a
//! filter selects, on the CLI, held to MCP.
//!
//! The same sweep the MCP `find_in_captures` tool runs on a job thread:
//! `capture::sweep::sweep_files` reads each file into scratch stores and
//! counts the dialogs the filter selects. It is a file job: it reads the
//! files it is given, runs before any capture opens, and needs no `-I`. A
//! directory stands for the capture files directly in it, chosen by name,
//! as the tool's file root is listed. The answer says whether every file
//! was read, because "not found" means nothing otherwise.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::mcp::{McpSession, ok_payload};

type TestError = Box<dyn std::error::Error>;

const CALL: &str = "busy-3a2b1c@192.0.2.30";

/// A directory holding three captures, only one of which carries `CALL`.
fn spool() -> Result<tempfile::TempDir, TestError> {
    let dir = tempfile::tempdir()?;
    let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples");
    for name in [
        "sip-problem-call.pcap",
        "sip-rtp-g711.pcap",
        "Asterisk_ZFONE_XLITE.pcap",
    ] {
        std::fs::copy(samples.join(name), dir.path().join(name))?;
    }
    Ok(dir)
}

/// Run `sipnab <args>` with no capture.
fn run(args: &[&str]) -> Result<std::process::Output, TestError> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()?)
}

/// The last line of stdout as JSON.
fn last_json(out: &std::process::Output) -> Result<serde_json::Value, TestError> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().last().ok_or("no stdout")?;
    Ok(serde_json::from_str(line)?)
}

/// `--find-in-files <dir> --filter ... --json` is the sweep the MCP tool
/// reports for the same directory and filter.
#[test]
fn the_json_answer_is_the_mcp_sweep() -> Result<(), TestError> {
    let dir = spool()?;
    let root = dir.path().to_str().ok_or("a UTF-8 temp path")?;
    let filter = format!("call_id == \"{CALL}\"");

    let out = run(&["--find-in-files", root, "--filter", &filter, "--json"])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cli = last_json(&out)?;
    assert_eq!(cli["complete"], true, "{cli}");
    assert_eq!(cli["files_total"], 3, "{cli}");
    assert_eq!(
        cli["matches"][0]["filename"], "sip-problem-call.pcap",
        "{cli}"
    );
    assert_eq!(cli["matches"][0]["first_call_id"], CALL, "{cli}");
    assert_eq!(cli["matches"].as_array().map(Vec::len), Some(1), "{cli}");

    let probe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pcap-samples/sip-problem-call.pcap");
    let mut mcp = McpSession::start(probe.to_str().ok_or("utf-8")?, &["--mcp-file-root", root])?;
    let msg = mcp.call(
        "find_in_captures",
        serde_json::json!({"filter": filter, "wait_seconds": 60}),
    )?;
    let payload = ok_payload(&msg)?;
    assert_eq!(payload["status"], "done", "{payload}");
    assert_eq!(
        cli, payload["sweep"],
        "CLI --find-in-files == MCP find_in_captures"
    );
    Ok(())
}

/// Files named one by one are swept in the order given; the text names the
/// file that holds the call and says the sweep was complete.
#[test]
fn named_files_and_the_text() -> Result<(), TestError> {
    let dir = spool()?;
    let a = dir.path().join("sip-rtp-g711.pcap");
    let b = dir.path().join("sip-problem-call.pcap");
    let filter = format!("call_id == \"{CALL}\"");
    let out = run(&[
        "--find-in-files",
        a.to_str().ok_or("utf-8")?,
        b.to_str().ok_or("utf-8")?,
        "--filter",
        &filter,
    ])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("Found in 1 of 2 files; every file was read."),
        "{stdout}"
    );
    let row: Vec<&str> = stdout
        .lines()
        .find(|l| l.starts_with("sip-problem-call.pcap"))
        .ok_or("the match row")?
        .split_whitespace()
        .collect();
    assert_eq!(row, vec!["sip-problem-call.pcap", "1", CALL], "{stdout}");
    Ok(())
}

/// A capture file that cannot be read is named with its reason and makes the
/// sweep incomplete, which exits 1: a "not found" over files nobody read is
/// not an answer. A file whose name is not a capture's is not a candidate.
#[test]
fn an_unreadable_file_makes_the_sweep_incomplete() -> Result<(), TestError> {
    let dir = spool()?;
    std::fs::write(dir.path().join("broken.pcap"), "not a capture")?;
    std::fs::write(dir.path().join("notes.txt"), "not a capture either")?;
    let root = dir.path().to_str().ok_or("utf-8")?;
    let out = run(&[
        "--find-in-files",
        root,
        "--filter",
        "call_id == \"nope\"",
        "--json",
    ])?;
    assert_eq!(out.status.code(), Some(1));
    let v = last_json(&out)?;
    assert_eq!(v["complete"], false, "{v}");
    assert_eq!(v["files_total"], 4, "notes.txt is not a candidate: {v}");
    assert_eq!(v["unreadable"][0]["filename"], "broken.pcap", "{v}");

    let out = run(&["--find-in-files", root, "--filter", "call_id == \"nope\""])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Not read: broken.pcap:"), "{stdout}");
    assert!(stdout.contains("not complete"), "{stdout}");
    Ok(())
}

/// With nothing to look for the job is refused, exit 2; a filter that does
/// not parse is refused the same way.
#[test]
fn a_missing_or_bad_filter_exits_2() -> Result<(), TestError> {
    let dir = spool()?;
    let root = dir.path().to_str().ok_or("utf-8")?;
    let out = run(&["--find-in-files", root])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("--filter"), "stderr:\n{stderr}");
    let out = run(&["--find-in-files", root, "--filter", "call_id ==="])?;
    assert_eq!(out.status.code(), Some(2));
    Ok(())
}

/// A diagnostic alias is a filter too: `--problems` finds the files with
/// failed calls.
#[test]
fn a_diagnostic_alias_selects_as_the_filter_does() -> Result<(), TestError> {
    let dir = spool()?;
    let root = dir.path().to_str().ok_or("utf-8")?;
    let out = run(&["--find-in-files", root, "--problems", "--json"])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = last_json(&out)?;
    let names: Vec<&str> = v["matches"]
        .as_array()
        .map(|m| m.iter().filter_map(|f| f["filename"].as_str()).collect())
        .unwrap_or_default();
    assert!(names.contains(&"sip-problem-call.pcap"), "{v}");
    Ok(())
}
