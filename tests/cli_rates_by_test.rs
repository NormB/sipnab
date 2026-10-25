// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--rates-by`: carrier metrics per group on the CLI, held to REST and MCP.
//!
//! The same question `GET /v1/dialogs/rates` and the MCP `group_dialogs` tool
//! answer: for each value of one dimension, ASR, NER, ACD, post-dial delay,
//! the 10th-percentile MOS and the retransmit rate, each beside the
//! population it was computed over, and `null` with a reason when that
//! population is empty. The CLI prints the REST answer, so `--rates-by --json`
//! and the route agree field for field once `capture_identity` is set aside.
//!
//! The capture is `tests/pcap-samples/sip-problem-call.pcap`: five INVITE
//! dialogs. One Completed (answered, torn down after 17.9 s, 850 ms of
//! post-dial delay) and four Failed (404, 486, 503, 603), two of which (486
//! and 603) the far end decided, so NER over the Failed group is 50.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-problem-call.pcap";

/// `value` with `capture_identity` removed.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    value
}

/// Each group as `(value, count, metrics)`, in the answer's order.
fn groups(v: &serde_json::Value) -> Result<Vec<(String, u64, serde_json::Value)>, TestError> {
    v["groups"]
        .as_array()
        .ok_or_else(|| format!("no groups array: {v}"))?
        .iter()
        .map(|g| {
            Ok((
                g["value"].as_str().ok_or("a value")?.to_string(),
                g["count"].as_u64().ok_or("a count")?,
                g["metrics"].clone(),
            ))
        })
        .collect()
}

/// `--rates-by state --json` is the REST answer for `by=state`, and its
/// groups and metrics are the MCP tool's.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--rates-by", "state", "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    let g = groups(&cli)?;
    assert_eq!(g.len(), 2, "{cli}");
    assert_eq!((g[0].0.as_str(), g[0].1), ("Failed", 4), "{cli}");
    assert_eq!(g[0].2["asr"], 0.0, "{cli}");
    assert_eq!(g[0].2["ner"], 50.0, "{cli}");
    assert!(
        g[0].2["acd"].is_null(),
        "no call in the group was timed: {cli}"
    );
    assert!(
        cli["groups"][0]["not_grounded"]["acd"].is_string(),
        "a null metric says why: {cli}"
    );
    assert_eq!((g[1].0.as_str(), g[1].1), ("Completed", 1), "{cli}");
    assert_eq!(g[1].2["acd"], 17.9, "{cli}");
    assert_eq!(g[1].2["pdd_p50"], 850.0, "{cli}");
    assert_eq!(cli["units"]["asr"], "percent", "{cli}");

    let rest = surfaces.rest_json("/v1/dialogs/rates?by=state")?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --rates-by --json == REST /v1/dialogs/rates"
    );

    let mcp = surfaces.mcp_json("group_dialogs", serde_json::json!({"by": "state"}))?;
    assert_eq!(
        groups(&cli)?,
        groups(&mcp)?,
        "CLI --rates-by == MCP group_dialogs"
    );
    Ok(())
}

/// The table puts one row per group and one column per metric, `-` where a
/// population could not support the figure, and names the units below.
#[test]
fn the_table_has_a_column_per_metric_and_a_dash_for_a_null() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--rates-by", "state", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains("Carrier metrics by state: 2 values, 5 dialogs"),
        "{out}"
    );
    let words = |prefix: &str| -> Option<Vec<String>> {
        out.lines()
            .find(|l| l.starts_with(prefix))
            .map(|l| l.split_whitespace().map(str::to_string).collect())
    };
    assert_eq!(
        words("Value").ok_or("a header row")?,
        vec![
            "Value",
            "Dialogs",
            "asr",
            "ner",
            "acd",
            "pdd_p50",
            "pdd_p95",
            "mos_p10",
            "retransmit_rate"
        ],
        "{out}"
    );
    assert_eq!(
        words("Failed").ok_or("a Failed row")?,
        vec!["Failed", "4", "0", "50", "-", "-", "-", "-", "0"],
        "{out}"
    );
    assert_eq!(
        words("Completed").ok_or("a Completed row")?,
        vec![
            "Completed",
            "1",
            "100",
            "100",
            "17.9",
            "850",
            "850",
            "-",
            "0"
        ],
        "{out}"
    );
    assert!(
        out.contains("Units: asr percent, ner percent, acd seconds"),
        "{out}"
    );
    assert!(out.contains("not_grounded"), "the dash is explained: {out}");
    Ok(())
}

/// The metrics cover the dialogs the one compiled filter admits.
#[test]
fn the_filter_narrows_the_groups() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--rates-by",
            "state",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "state == Failed",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    let g = groups(&v)?;
    assert_eq!(g.len(), 1, "{v}");
    assert_eq!((g[0].0.as_str(), g[0].1), ("Failed", 4), "{v}");
    assert_eq!(v["total_matched"], 4, "{v}");
    Ok(())
}

/// `--top` cuts the groups as REST's `top_n` does, the rest summed.
#[test]
fn top_cuts_the_groups_as_rest_does() -> Result<(), TestError> {
    let surfaces = Surfaces::start(PCAP)?;
    let run = surfaces.cli(&[
        "--rates-by",
        "state",
        "--top",
        "1",
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(groups(&cli)?.len(), 1, "{cli}");
    assert_eq!(cli["other_count"], 1, "{cli}");
    let rest = surfaces.rest_json("/v1/dialogs/rates?by=state&top_n=1")?;
    assert_eq!(without_identity(cli), without_identity(rest));

    let run = run_cli(
        PCAP,
        &[
            "--rates-by",
            "state",
            "--top",
            "1",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert!(
        run.stdout
            .contains("Other: 1 dialog in 1 value past --top 1"),
        "{}",
        run.stdout
    );
    Ok(())
}

/// The three dimensions only this question has (`to_domain`, `hour`,
/// `next_hop`) are accepted; any other is refused with exit 2 and the list.
#[test]
fn the_extra_dimensions_work_and_an_unknown_one_exits_2() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &["--rates-by", "hour", "--json", "--no-cli-print", "--quiet"],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["group_by"], "hour", "{v}");
    assert_eq!(v["total_matched"], 5, "{v}");

    let run = run_cli(PCAP, &["--rates-by", "bogus"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr
            .contains("cannot group by 'bogus'; one of: state, ")
            && run.stderr.contains("to_domain, hour, next_hop")
            && run.stderr.contains("narrow with --filter"),
        "stderr:\n{}",
        run.stderr
    );
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
            "--rates-by",
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
    let run = run_cli(
        PCAP,
        &[
            "--rates-by",
            "state",
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(groups(&run.last_json()?)?.len(), 2);
    Ok(())
}
