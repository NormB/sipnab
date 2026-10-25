// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--talkers`: the busiest participants on the CLI, held to REST and MCP.
//!
//! The same question `GET /v1/talkers` and the MCP `top_talkers` tool answer:
//! who took part in the most dialogs, by sending address (`ip`), banner
//! (`ua`) or the dialed number's leading digits (`prefix`), most dialogs
//! first, then most messages, then the key. The CLI prints the REST answer,
//! so `--talkers --json` and the route agree field for field once
//! `capture_identity` is set aside.
//!
//! `tests/pcap-samples/sip-problem-call.pcap` holds five INVITE dialogs, each
//! between two addresses of its own: ten senders of one dialog each, the
//! answered call's two the busiest by messages (four and three).
//! `tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap` dials 10008 twice and 10009
//! three times.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-problem-call.pcap";
const DIALED: &str = "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap";

/// `value` with `capture_identity` removed.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    value
}

/// Each talker as `(key, dialogs, messages)`, in the answer's order.
fn talkers(v: &serde_json::Value) -> Result<Vec<(String, u64, u64)>, TestError> {
    v["talkers"]
        .as_array()
        .ok_or_else(|| format!("no talkers array: {v}"))?
        .iter()
        .map(|t| {
            Ok((
                t["key"].as_str().ok_or("a key")?.to_string(),
                t["dialogs"].as_u64().ok_or("dialogs")?,
                t["messages"].as_u64().ok_or("messages")?,
            ))
        })
        .collect()
}

/// `--talkers ip --json` is the REST answer for `by=ip`, and its ranking is
/// the MCP tool's.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--talkers", "ip", "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    let t = talkers(&cli)?;
    assert_eq!(t.len(), 10, "{cli}");
    assert_eq!(t[0], ("192.0.2.20".to_string(), 1, 4), "{cli}");
    assert_eq!(t[1], ("192.0.2.10".to_string(), 1, 3), "{cli}");
    assert_eq!(cli["truncated"], false, "{cli}");
    assert_eq!(cli["talkers"][0]["share_pct"], 20.0, "{cli}");

    let rest = surfaces.rest_json("/v1/talkers?by=ip")?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --talkers --json == REST /v1/talkers"
    );

    let mcp = surfaces.mcp_json("top_talkers", serde_json::json!({"by": "ip"}))?;
    assert_eq!(
        talkers(&cli)?,
        talkers(&mcp)?,
        "CLI --talkers == MCP top_talkers"
    );
    Ok(())
}

/// `--top` keeps the busiest, as REST's `limit` does, and says how many
/// talkers it left out.
#[test]
fn top_keeps_the_busiest_and_counts_the_rest() -> Result<(), TestError> {
    let surfaces = Surfaces::start(PCAP)?;
    let run = surfaces.cli(&[
        "--talkers",
        "ip",
        "--top",
        "2",
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(talkers(&cli)?.len(), 2, "{cli}");
    assert_eq!(cli["truncated"], true, "{cli}");
    let rest = surfaces.rest_json("/v1/talkers?by=ip&limit=2")?;
    assert_eq!(without_identity(cli), without_identity(rest));

    let run = run_cli(
        PCAP,
        &["--talkers", "ip", "--top", "2", "--no-cli-print", "--quiet"],
    )?;
    assert!(
        run.stdout.contains("Other: 8 talkers past --top 2"),
        "{}",
        run.stdout
    );
    Ok(())
}

/// The table names the dimension and the counts, one row per talker.
#[test]
fn the_table_lists_each_talker() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--talkers", "ip", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains("Talkers by ip: 10 talkers, 5 dialogs"),
        "{out}"
    );
    let first: Vec<&str> = out
        .lines()
        .find(|l| l.starts_with("192.0.2.20"))
        .ok_or("the busiest row")?
        .split_whitespace()
        .collect();
    assert_eq!(
        first,
        vec!["192.0.2.20", "1", "4", "1", "1", "0", "20"],
        "{out}"
    );
    let header: Vec<&str> = out
        .lines()
        .find(|l| l.starts_with("Talker "))
        .ok_or("a header")?
        .split_whitespace()
        .collect();
    assert_eq!(
        header,
        vec![
            "Talker", "Dialogs", "Messages", "INVITEs", "Answered", "Failed", "Share%"
        ],
        "{out}"
    );
    Ok(())
}

/// `prefix` ranks the dialed number's leading digits, as many as
/// `--prefix-digits` names, the same as REST's `prefix_digits`.
#[test]
fn prefix_ranks_dialed_digits_as_rest_does() -> Result<(), TestError> {
    let surfaces = Surfaces::start(DIALED)?;
    let run = surfaces.cli(&[
        "--talkers",
        "prefix",
        "--prefix-digits",
        "5",
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    let keys: Vec<(String, u64)> = talkers(&cli)?.into_iter().map(|(k, d, _)| (k, d)).collect();
    assert_eq!(
        keys,
        vec![("10009".to_string(), 3), ("10008".to_string(), 2)],
        "{cli}"
    );
    let rest = surfaces.rest_json("/v1/talkers?by=prefix&prefix_digits=5")?;
    assert_eq!(without_identity(cli), without_identity(rest));

    // The default is four digits, which puts both numbers in one bucket.
    let run = surfaces.cli(&["--talkers", "prefix", "--json", "--no-cli-print", "--quiet"])?;
    let keys: Vec<(String, u64)> = talkers(&run.last_json()?)?
        .into_iter()
        .map(|(k, d, _)| (k, d))
        .collect();
    assert_eq!(keys, vec![("1000".to_string(), 5)]);
    Ok(())
}

/// The ranking covers the dialogs the one compiled filter admits.
#[test]
fn the_filter_narrows_the_ranking() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--talkers",
            "ip",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "state == Completed",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(
        talkers(&v)?,
        vec![
            ("192.0.2.20".to_string(), 1, 4),
            ("192.0.2.10".to_string(), 1, 3)
        ],
        "{v}"
    );
    assert_eq!(v["total_matched"], 1, "{v}");
    Ok(())
}

/// An unknown dimension, a zero-digit prefix, and `--prefix-digits` without
/// `--talkers` exit 2, each with REST's reason where REST has one.
#[test]
fn bad_input_exits_2_and_says_why() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--talkers", "bogus"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr
            .contains("cannot rank by 'bogus'; one of: ip, ua, prefix"),
        "stderr:\n{}",
        run.stderr
    );
    let run = run_cli(PCAP, &["--talkers", "prefix", "--prefix-digits", "0"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("must be greater than zero"),
        "stderr:\n{}",
        run.stderr
    );
    let run = run_cli(PCAP, &["--prefix-digits", "3", "--report"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(run.stderr.contains("--talkers"), "stderr:\n{}", run.stderr);
    Ok(())
}

/// The flag makes the run headless by itself, and holds under `--cores`.
#[test]
fn the_flag_implies_no_tui_and_holds_under_cores() -> Result<(), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            PCAP,
            "--talkers",
            "ip",
            "--json",
            "--no-cli-print",
            "--quiet",
        ])
        .env("NO_COLOR", "1")
        .output()?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let run = run_cli(
        PCAP,
        &[
            "--talkers",
            "ip",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(talkers(&run.last_json()?)?.len(), 10);
    Ok(())
}
