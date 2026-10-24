// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--count-by`: dialogs counted by one dimension on the CLI, held to REST
//! and MCP.
//!
//! The same question `GET /v1/aggregate` and the MCP `aggregate_dialogs` tool
//! answer: how many dialogs fall in each value of one dimension, largest
//! first, ties broken by value, with everything past the `--top` cut summed
//! in `other_count`. The CLI prints the REST answer, so `--count-by --json`
//! and the route agree field for field once `capture_identity` (which names a
//! different process on each side) is set aside.
//!
//! The capture is `tests/pcap-samples/sip-problem-call.pcap`: five INVITE
//! dialogs, one Completed with a 200 and four Failed, with a 404, a 486, a 503
//! and a 603.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

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

/// Each bucket as `(value, count)`, in the answer's order.
fn buckets(value: &serde_json::Value) -> Result<Vec<(String, u64)>, TestError> {
    value["buckets"]
        .as_array()
        .ok_or_else(|| format!("no buckets array: {value}"))?
        .iter()
        .map(|b| {
            let v = b["value"]
                .as_str()
                .ok_or_else(|| format!("no value: {b}"))?;
            let n = b["count"]
                .as_u64()
                .ok_or_else(|| format!("no count: {b}"))?;
            Ok((v.to_string(), n))
        })
        .collect()
}

/// `--count-by state --json` is the REST answer for `by=state`, and its
/// buckets are the MCP tool's.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--count-by", "state", "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(
        buckets(&cli)?,
        vec![("Failed".to_string(), 4), ("Completed".to_string(), 1)],
        "{cli}"
    );
    assert_eq!(cli["group_by"], "state", "{cli}");
    assert_eq!(cli["total_matched"], 5, "{cli}");
    assert_eq!(cli["other_count"], 0, "{cli}");
    assert!(
        cli["capture_identity"]["instance"].is_string(),
        "the answer names the run it came from: {cli}"
    );

    let rest = surfaces.rest_json("/v1/aggregate?by=state")?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --count-by --json == REST /v1/aggregate"
    );

    let mcp = surfaces.mcp_json(
        "aggregate_dialogs",
        serde_json::json!({"group_by": "state"}),
    )?;
    assert_eq!(
        buckets(&cli)?,
        buckets(&mcp)?,
        "CLI --count-by == MCP aggregate_dialogs"
    );
    Ok(())
}

/// `--top` cuts the buckets as REST's `top_n` does: five values of one call
/// each keep the two smallest values, and the other three calls are summed
/// in `other_count`, so the answer still adds up to every call.
#[test]
fn top_cuts_the_buckets_and_sums_the_rest_as_rest_does() -> Result<(), TestError> {
    let surfaces = Surfaces::start(PCAP)?;
    let run = surfaces.cli(&[
        "--count-by",
        "response_code",
        "--top",
        "2",
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(
        buckets(&cli)?,
        vec![("200".to_string(), 1), ("404".to_string(), 1)],
        "ties broken by value: {cli}"
    );
    assert_eq!(cli["other_count"], 3, "{cli}");
    assert_eq!(cli["distinct_values"], 5, "{cli}");
    let rest = surfaces.rest_json("/v1/aggregate?by=response_code&top_n=2")?;
    assert_eq!(without_identity(cli), without_identity(rest));
    Ok(())
}

/// The table names the dimension, the values and the dialogs, then one row
/// per value; a cut is summed on its own line.
#[test]
fn the_table_lists_each_value_and_sums_the_cut() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--count-by", "state", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains("Dialogs by state: 2 values, 5 dialogs"),
        "{out}"
    );
    assert!(out.contains("Value      Dialogs"), "{out}");
    assert!(out.contains("Failed     4"), "{out}");
    assert!(out.contains("Completed  1"), "{out}");
    assert!(!out.contains("Other:"), "nothing was cut: {out}");

    let run = run_cli(
        PCAP,
        &[
            "--count-by",
            "response_code",
            "--top",
            "2",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(
        run.stdout
            .contains("Other: 3 dialogs in 3 values past --top 2"),
        "{}",
        run.stdout
    );
    Ok(())
}

/// `--markdown` renders the same rows as a Markdown table.
#[test]
fn markdown_renders_the_same_rows_as_a_markdown_table() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--count-by",
            "state",
            "--markdown",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("| Value | Dialogs |"), "{}", run.stdout);
    assert!(run.stdout.contains("| Failed | 4 |"), "{}", run.stdout);
    Ok(())
}

/// The count covers the dialogs the one compiled filter admits.
#[test]
fn the_filter_narrows_the_count() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--count-by",
            "state",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "response_code >= 500",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(buckets(&v)?, vec![("Failed".to_string(), 2)], "{v}");
    assert_eq!(v["total_matched"], 2, "{v}");
    Ok(())
}

/// A dimension outside the groupable set exits 2 with the reason REST gives,
/// which lists the real ones.
#[test]
fn an_unknown_dimension_exits_2_and_lists_the_real_ones() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--count-by", "bogus"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr
            .contains("cannot group by 'bogus'; one of: state, response_code"),
        "stderr:\n{}",
        run.stderr
    );
    Ok(())
}

/// `--top` takes a whole number from one up, and means nothing without a
/// ranked query to cut.
#[test]
fn top_is_refused_at_zero_and_without_a_ranked_query() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--count-by", "state", "--top", "0"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    let run = run_cli(PCAP, &["--top", "3", "--report"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(run.stderr.contains("--count-by"), "stderr:\n{}", run.stderr);
    Ok(())
}

/// The flag makes the run headless by itself, and its answer holds under
/// `--cores`.
#[test]
fn the_flag_implies_no_tui_and_holds_under_cores() -> Result<(), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            PCAP,
            "--count-by",
            "state",
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
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("\"group_by\":\"state\""),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let run = run_cli(
        PCAP,
        &[
            "--count-by",
            "state",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(
        buckets(&run.last_json()?)?,
        vec![("Failed".to_string(), 4), ("Completed".to_string(), 1)]
    );
    Ok(())
}
