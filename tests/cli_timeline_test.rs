// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--timeline`: the call-volume histogram on the CLI, held to REST and MCP.
//!
//! The same question `GET /v1/timeline` and the MCP `timeline` tool answer:
//! how many dialogs opened in each fixed-width interval, epoch-aligned, gaps
//! kept. The CLI prints the REST answer, so `--timeline --json` and the route
//! must agree field for field once `capture_identity` (which names a
//! different process on each side) is set aside.
//!
//! The capture is `tests/pcap-samples/sip-problem-call.pcap`: five INVITE
//! dialogs whose first messages are at 22:13:20Z, :23, :26, :29 and :32 on
//! 2023-11-14. Two-second buckets therefore hold 1, 1, 0, 1, 1, 0, 1: two
//! empty intervals that must be kept, because an empty bucket is exactly
//! what an outage looks like.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

#[path = "support/pcap_build.rs"]
mod pcap_build;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-problem-call.pcap";

/// `value` with `capture_identity` removed: the one member that names the
/// answering process rather than the capture's content.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    value
}

/// The `dialogs` count of each bucket, oldest first.
fn counts(value: &serde_json::Value) -> Result<Vec<u64>, TestError> {
    value["buckets"]
        .as_array()
        .ok_or_else(|| format!("no buckets array: {value}"))?
        .iter()
        .map(|b| {
            b["dialogs"]
                .as_u64()
                .ok_or_else(|| format!("a bucket has no dialogs count: {b}").into())
        })
        .collect()
}

/// `--timeline=2 --json` is the REST answer for `bucket_seconds=2`, and its
/// counts are the MCP tool's, gaps included.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--timeline=2", "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(counts(&cli)?, vec![1, 1, 0, 1, 1, 0, 1], "{cli}");
    assert_eq!(cli["bucket_seconds"], 2, "{cli}");
    assert_eq!(cli["returned"], 7, "{cli}");
    assert!(
        cli["capture_identity"]["instance"].is_string(),
        "the answer names the run it came from: {cli}"
    );

    let rest = surfaces.rest_json("/v1/timeline?bucket_seconds=2")?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --timeline --json == REST /v1/timeline"
    );

    let mcp = surfaces.mcp_json("timeline", serde_json::json!({"bucket_seconds": 2}))?;
    assert_eq!(
        counts(&cli)?,
        counts(&mcp)?,
        "CLI --timeline == MCP timeline"
    );
    Ok(())
}

/// With no value, the width is REST's default of 60 seconds: all five calls
/// fall in the one minute that holds them.
#[test]
fn a_bare_flag_uses_sixty_second_buckets() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--timeline", "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["bucket_seconds"], 60, "{v}");
    assert_eq!(counts(&v)?, vec![5], "{v}");
    assert_eq!(v["buckets"][0]["start"], "2023-11-14T22:13:00+00:00", "{v}");
    Ok(())
}

/// The table names each interval's start and count, empty intervals too.
#[test]
fn the_table_lists_every_interval_with_its_count() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--timeline=2", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains("Call volume: 7 buckets of 2 s, 5 dialogs"),
        "{out}"
    );
    let rows: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("2023-11-14T22:13:"))
        .collect();
    assert_eq!(rows.len(), 7, "{out}");
    assert!(rows[0].starts_with("2023-11-14T22:13:20+00:00"), "{out}");
    assert!(rows[0].trim_end().ends_with(" 1"), "{out}");
    assert!(rows[2].starts_with("2023-11-14T22:13:24+00:00"), "{out}");
    assert!(
        rows[2].trim_end().ends_with(" 0"),
        "an empty interval is kept: {out}"
    );
    Ok(())
}

/// `--markdown` renders the same rows as a Markdown table.
#[test]
fn markdown_renders_the_same_rows_as_a_markdown_table() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &["--timeline=2", "--markdown", "--no-cli-print", "--quiet"],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(out.contains("| Start | Dialogs |"), "{out}");
    assert!(out.contains("|---|---|"), "{out}");
    assert!(out.contains("| 2023-11-14T22:13:24+00:00 | 0 |"), "{out}");
    Ok(())
}

/// The histogram counts the dialogs the one compiled filter admits, so
/// `--filter` narrows it exactly as it narrows `--report`.
#[test]
fn the_filter_narrows_the_histogram() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--timeline=2",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "response_code == 486",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(counts(&v)?, vec![1], "only the 486 call at :23: {v}");
    assert_eq!(v["buckets"][0]["start"], "2023-11-14T22:13:22+00:00", "{v}");
    Ok(())
}

/// A filter that admits nothing is an empty histogram, exit 0, not an error.
#[test]
fn a_filter_admitting_nothing_is_an_empty_histogram() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--timeline",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "response_code == 999",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["returned"], 0, "{v}");
    assert_eq!(counts(&v)?, Vec::<u64>::new(), "{v}");
    Ok(())
}

/// The flag makes the run headless by itself, as `--call-report` does.
#[test]
fn the_flag_implies_no_tui() -> Result<(), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            PCAP,
            "--timeline",
            "--json",
            "--no-cli-print",
            "--quiet",
        ])
        .env("NO_COLOR", "1")
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("\"bucket_seconds\":60"), "{stdout}");
    Ok(())
}

/// A zero width is refused with exit 2 and the reason REST gives for it; a
/// width that is not a number is refused the same way.
#[test]
fn a_zero_or_non_numeric_width_exits_2_and_says_why() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--timeline=0"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("must be greater than zero"),
        "stderr:\n{}",
        run.stderr
    );
    let run = run_cli(PCAP, &["--timeline=minute"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    Ok(())
}

/// The answer rides the report chain, so `--cores` answers it too.
#[test]
fn the_answer_holds_under_cores() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--timeline=2",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(counts(&run.last_json()?)?, vec![1, 1, 0, 1, 1, 0, 1]);
    Ok(())
}

/// Two INVITEs ten years apart: 5,256,001 one-minute intervals, more than
/// one histogram holds (100,000). The run exits 1 with the store's reason on
/// stderr, naming a width that fits, and prints no histogram; asked again at
/// that width, it answers.
#[test]
fn a_span_wider_than_the_bound_exits_1_and_names_a_width_that_fits() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = dir.path().join("decade.pcap");
    const TEN_YEARS_USEC: u64 = 10 * 365 * 24 * 3600 * 1_000_000;
    pcap_build::write_pcap_at(
        &pcap,
        &[
            (pcap_build::invite_with_long_from("first@example.com", 1), 0),
            (
                pcap_build::invite_with_long_from("last@example.com", 1),
                TEN_YEARS_USEC,
            ),
        ],
        1,
    )?;
    let path = pcap.to_str().ok_or("a UTF-8 temp path")?;

    let run = run_cli(path, &["--timeline", "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(1), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("5256001 intervals of 60 s"),
        "stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("a width of 3154 s or more fits"),
        "stderr:\n{}",
        run.stderr
    );
    assert!(
        !run.stdout.contains("\"buckets\""),
        "no histogram: {}",
        run.stdout
    );

    let run = run_cli(
        path,
        &["--timeline=3154", "--json", "--no-cli-print", "--quiet"],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(counts(&v)?.iter().sum::<u64>(), 2, "{v}");
    assert!(v["returned"].as_u64().is_some_and(|n| n <= 100_000), "{v}");
    Ok(())
}
