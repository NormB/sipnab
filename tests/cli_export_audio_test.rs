// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--export-audio`: one call's decoded RTP as a WAV file, on the CLI, held
//! to MCP and REST.
//!
//! The same decode `GET /v1/dialogs/{call_id}/audio` serves and the MCP
//! `export_audio` tool writes: `rtp::audio_export::decode_dialog_audio`, so
//! the file `--export-audio` writes is byte for byte the one the tool
//! writes. Asking for the export is the operator's consent to hold the
//! call's audio payload, which sipnab otherwise does not keep.
//!
//! `tests/pcap-samples/sip-rtp-g711.pcap` holds two calls; the first,
//! `1-1966@10.0.2.20`, carries 425 RTP packets of PCMU in one direction only,
//! so its export is 8.5 s of mono audio marked partial.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::mcp::McpSession;
use surface_parity::run_cli;

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL: &str = "1-1966@10.0.2.20";

/// The WAV `--export-audio` writes is the one MCP `export_audio` writes,
/// byte for byte, and the JSON answer names it and the facts REST sends as
/// headers.
#[test]
fn the_file_is_the_mcp_file_and_the_answer_describes_it() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cli_wav = dir.path().join("cli.wav");
    let cli_path = cli_wav.to_str().ok_or("a UTF-8 temp path")?;

    let run = run_cli(
        PCAP,
        &[
            "--export-audio",
            CALL,
            "--export-audio-out",
            cli_path,
            "--json",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["path"], cli_path, "{v}");
    assert_eq!(v["dialog_seen"], true, "{v}");
    // The capture holds one direction of this call, which the summary says,
    // and which makes the file partial.
    assert_eq!(v["partial"], true, "{v}");
    assert!(
        v["summary"]
            .as_str()
            .is_some_and(|s| s.contains("media in only ONE direction")),
        "{v}"
    );
    assert_eq!(v["sample_rate"], 8000, "{v}");
    assert!(
        v["summary"].as_str().is_some_and(|s| s.contains(cli_path)),
        "{v}"
    );
    let bytes = std::fs::read(&cli_wav)?;
    assert_eq!(v["bytes"], bytes.len(), "{v}");
    assert_eq!(&bytes[..4], b"RIFF", "a WAV file");

    let root = tempfile::tempdir()?;
    let root_str = root.path().to_str().ok_or("a UTF-8 temp path")?;
    let mut mcp = McpSession::start(PCAP, &["--retain-audio", "--mcp-file-root", root_str])?;
    let msg = mcp.call(
        "export_audio",
        serde_json::json!({"call_id": CALL, "filename": "mcp.wav"}),
    )?;
    surface_parity::mcp::ok_payload(&msg)?;
    let mcp_bytes = std::fs::read(root.path().join("mcp.wav"))?;
    assert!(bytes == mcp_bytes, "CLI and MCP wrote different WAVs");
    Ok(())
}

/// Without `--export-audio-out` the file takes the name REST offers in its
/// `Content-Disposition`, in the current directory, and the text names it.
#[test]
fn the_default_file_is_the_rest_download_name() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PCAP);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(dir.path())
        .arg("-I")
        .arg(&pcap)
        .args(["--export-audio", CALL, "--no-cli-print", "--quiet"])
        .env("NO_COLOR", "1")
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let wav = dir.path().join("1-1966_10.0.2.20.wav");
    assert!(wav.is_file(), "no {}: {stdout}", wav.display());
    assert!(stdout.contains("1-1966_10.0.2.20.wav"), "{stdout}");
    Ok(())
}

/// An existing file is never replaced: the run exits 1 and the file is as it
/// was.
#[test]
fn an_existing_file_is_not_overwritten() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let wav = dir.path().join("taken.wav");
    std::fs::write(&wav, b"keep me")?;
    let run = run_cli(
        PCAP,
        &[
            "--export-audio",
            CALL,
            "--export-audio-out",
            wav.to_str().ok_or("a UTF-8 temp path")?,
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(1), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("--export-audio:"),
        "stderr:\n{}",
        run.stderr
    );
    assert_eq!(std::fs::read(&wav)?, b"keep me");
    Ok(())
}

/// A Call-ID neither store holds exits 1 with the message REST's 404 carries,
/// and writes nothing.
#[test]
fn an_unknown_call_id_exits_1_and_writes_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let wav = dir.path().join("none.wav");
    let run = run_cli(
        PCAP,
        &[
            "--export-audio",
            "nope@example.com",
            "--export-audio-out",
            wav.to_str().ok_or("a UTF-8 temp path")?,
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(1), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr
            .contains("no SIP dialog and no RTP stream associated with call_id 'nope@example.com'"),
        "stderr:\n{}",
        run.stderr
    );
    assert!(!wav.exists());
    Ok(())
}

/// `--export-audio-out` without `--export-audio` is refused.
#[test]
fn the_out_flag_alone_exits_2() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--export-audio-out", "/tmp/x.wav", "--report"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("--export-audio"),
        "stderr:\n{}",
        run.stderr
    );
    Ok(())
}

/// The flag makes the run headless by itself, and `--cores` writes the same
/// file the single reader writes.
#[test]
fn the_flag_implies_no_tui_and_holds_under_cores() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PCAP);
    let mut files = Vec::new();
    for (name, cores) in [("one.wav", None), ("two.wav", Some("2"))] {
        let wav = dir.path().join(name);
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"));
        cmd.arg("-I")
            .arg(&pcap)
            .args(["--export-audio", CALL, "--no-cli-print", "--quiet"])
            .arg("--export-audio-out")
            .arg(&wav)
            .env("NO_COLOR", "1");
        if let Some(n) = cores {
            cmd.args(["--cores", n]);
        }
        let out = cmd.output()?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        files.push(std::fs::read(&wav)?);
    }
    assert!(files[0] == files[1], "--cores wrote a different WAV");
    Ok(())
}
