// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--compare-captures`: two capture files diffed by dimension on the CLI,
//! held to REST.
//!
//! The same comparison `GET /v1/captures/compare` and the MCP
//! `compare_captures` tool run: `capture::compare::compare` reads both files
//! into scratch stores and, for each dimension, ranks the values by how far
//! they moved from the baseline `a` to `b`. It is a file job: it reads the
//! two files it is given, runs before any capture opens, and needs no `-I`.
//! The CLI prints the REST answer; only the summary's last sentence differs,
//! because a server says the files are not the capture it holds and the
//! command line holds none.
//!
//! The baseline `sip-problem-call.pcap` has five dialogs, four Failed and one
//! Completed; `sip-rtp-g711.pcap` has two, one Completed and one InCall.

#![cfg(all(unix, feature = "full"))]

#[path = "support/server.rs"]
mod server;

type TestError = Box<dyn std::error::Error>;

const ROOT: &str = "tests/pcap-samples";
const A: &str = "sip-problem-call.pcap";
const B: &str = "sip-rtp-g711.pcap";
const SERVER_SENTENCE: &str = " Neither is the capture this server holds.";

/// Run `sipnab <args>` from `tests/pcap-samples`, so a bare filename names
/// the same file it names to a server whose file root is that directory.
fn run(args: &[&str]) -> Result<std::process::Output, TestError> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ROOT))
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

/// `--compare-captures A B --json` is the REST comparison; the summary is
/// REST's without the sentence about the server's own capture.
#[test]
fn the_json_answer_is_the_rest_answer() -> Result<(), TestError> {
    let out = run(&["--compare-captures", A, B, "--json"])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut cli = last_json(&out)?;
    assert_eq!(cli["a"]["dialogs"], 5, "{cli}");
    assert_eq!(cli["b"]["dialogs"], 2, "{cli}");
    assert_eq!(cli["dimensions"][0]["dimension"], "state", "{cli}");
    assert_eq!(
        cli["dimensions"][0]["buckets"][0]["value"], "Failed",
        "{cli}"
    );
    assert_eq!(cli["dimensions"][0]["buckets"][0]["delta"], -4, "{cli}");
    assert!(
        !cli["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("server"),
        "the command line holds no capture: {cli}"
    );

    let srv = server::ApiServer::spawn_with_pcap(
        "tests/pcap-samples/sip-problem-call.pcap",
        &["--api-file-root", ROOT],
    )?;
    let mut rest = srv
        .get(&format!("/v1/captures/compare?a={A}&b={B}"))?
        .json()?;
    let rest_summary = rest["summary"].as_str().unwrap_or_default().to_string();
    let cli_summary = cli["summary"].as_str().unwrap_or_default().to_string();
    assert_eq!(
        rest_summary.replacen(SERVER_SENTENCE, "", 1),
        cli_summary,
        "the summaries differ only by the server's sentence"
    );
    cli["summary"] = serde_json::Value::Null;
    rest["summary"] = serde_json::Value::Null;
    assert_eq!(cli, rest, "CLI --compare-captures --json == REST");
    Ok(())
}

/// Named dimensions and `--top` match REST's `dimensions` and `top_n`.
#[test]
fn dimensions_and_top_match_rest() -> Result<(), TestError> {
    let out = run(&[
        "--compare-captures",
        A,
        B,
        "--compare-dimensions",
        "method,response_code",
        "--top",
        "2",
        "--json",
    ])?;
    assert_eq!(out.status.code(), Some(0));
    let mut cli = last_json(&out)?;
    let srv = server::ApiServer::spawn_with_pcap(
        "tests/pcap-samples/sip-problem-call.pcap",
        &["--api-file-root", ROOT],
    )?;
    let mut rest = srv
        .get(&format!(
            "/v1/captures/compare?a={A}&b={B}&dimensions=method,response_code&top_n=2"
        ))?
        .json()?;
    assert_eq!(
        cli["dimensions"][1]["buckets"].as_array().map(Vec::len),
        Some(2),
        "{cli}"
    );
    cli["summary"] = serde_json::Value::Null;
    rest["summary"] = serde_json::Value::Null;
    assert_eq!(cli, rest);
    Ok(())
}

/// The text names the two sides, then one table per dimension, largest
/// movement first.
#[test]
fn the_text_has_a_table_per_dimension() -> Result<(), TestError> {
    let out = run(&["--compare-captures", A, B])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("A: sip-problem-call.pcap, 23 packets, 5 dialogs, 0 streams"),
        "{stdout}"
    );
    assert!(
        stdout.contains("B: sip-rtp-g711.pcap, 852 packets, 2 dialogs, 2 streams"),
        "{stdout}"
    );
    assert!(stdout.contains("By state:"), "{stdout}");
    assert!(stdout.contains("By response_code:"), "{stdout}");
    let row: Vec<&str> = stdout
        .lines()
        .find(|l| l.starts_with("Failed"))
        .ok_or("the Failed row")?
        .split_whitespace()
        .collect();
    assert_eq!(row, vec!["Failed", "4", "0", "-4"], "{stdout}");
    Ok(())
}

/// The same file twice is a usage error, exit 2; an unknown dimension too.
/// A file that yields nothing exits 1 with REST's reason.
#[test]
fn refusals() -> Result<(), TestError> {
    let out = run(&["--compare-captures", A, A])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("are the same file"), "stderr:\n{stderr}");

    let out = run(&["--compare-captures", A, B, "--compare-dimensions", "bogus"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("bogus"), "stderr:\n{stderr}");

    let out = run(&["--compare-captures", A, "nope.pcap"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("'nope.pcap' yielded no dialogs"),
        "stderr:\n{stderr}"
    );
    Ok(())
}
