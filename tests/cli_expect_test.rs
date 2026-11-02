// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--expect`: a capture judged against a checked-in suite of expectations
//! on the CLI, held to MCP, with the exit status a CI step gates on.
//!
//! The same judgement the MCP `evaluate_expectations` tool returns:
//! `expect::evaluate`. Its report names the exit status a command line
//! carries (`exit_code`): 0 when every rule that ran passed, 3 when one
//! failed, 2 when no rule ran. `--expect` exits with it, so a suite in a
//! repository can fail a build. 3 is the code every sipnab gate uses for "the
//! tool worked and the input failed a check", so a failed rule is never read
//! as the runtime failure that 1 means.
//!
//! The capture is `tests/pcap-samples/sip-problem-call.pcap`: five INVITE
//! dialogs, one answered.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-problem-call.pcap";

/// A suite of `toml` written to a temporary file, kept alive by the dir.
fn suite(toml: &str) -> Result<(tempfile::TempDir, String), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.expect.toml");
    std::fs::write(&path, toml)?;
    let path = path.to_str().ok_or("a UTF-8 temp path")?.to_string();
    Ok((dir, path))
}

const PASSING: &str = r#"
[[rules]]
name = "five calls"
metric = "count"
op = ">="
value = 5
"#;

const FAILING: &str = r#"
[[rules]]
name = "five calls"
metric = "count"
op = ">="
value = 5

[[rules]]
name = "answered"
metric = "asr"
op = ">="
value = 90
"#;

const UNDER_THE_FLOOR: &str = r#"
[[rules]]
metric = "asr"
op = ">="
value = 90
min_sample = 100
"#;

/// A failing suite exits 3, and its JSON is the MCP tool's report for the
/// same rules.
#[test]
fn a_failing_suite_exits_3_and_matches_mcp() -> Result<(), TestError> {
    let (_dir, path) = suite(FAILING)?;
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--expect", &path, "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(3), "stderr:\n{}", run.stderr);
    let mut cli = run.last_json()?;
    assert_eq!(cli["verdict"], "fail", "{cli}");
    assert_eq!(cli["exit_code"], 3, "{cli}");
    assert_eq!(
        cli["schema_version"], 2,
        "the exit_code values changed, so the report's shape version did: {cli}"
    );
    assert_eq!(cli["passed"], 1, "{cli}");
    assert_eq!(cli["failed"], 1, "{cli}");
    assert_eq!(cli["results"][1]["name"], "answered", "{cli}");
    assert!(cli["capture_identity"]["instance"].is_string(), "{cli}");

    let mut mcp = surfaces.mcp_json(
        "evaluate_expectations",
        serde_json::json!({"rules_toml": FAILING}),
    )?;
    if let Some(obj) = cli.as_object_mut() {
        obj.remove("capture_identity");
    }
    // Set aside what MCP stamps on an answer about the capture it holds: its
    // identity and whether its source has been read to the end.
    if let Some(obj) = mcp.as_object_mut() {
        for field in [
            "capture_identity",
            "source_exhausted",
            "source_stopped_early",
        ] {
            obj.remove(field);
        }
    }
    assert_eq!(cli, mcp, "CLI --expect == MCP evaluate_expectations");
    Ok(())
}

/// A passing suite exits 0, and the text says so rule by rule.
#[test]
fn a_passing_suite_exits_0() -> Result<(), TestError> {
    let (_dir, path) = suite(PASSING)?;
    let run = run_cli(PCAP, &["--expect", &path, "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains("Expectations: pass, 1 of 1 rule passed"),
        "{out}"
    );
    let row: Vec<&str> = out
        .lines()
        .find(|l| l.starts_with("five calls"))
        .ok_or("the rule row")?
        .split_whitespace()
        .collect();
    assert_eq!(row.last(), Some(&"pass"), "{out}");
    Ok(())
}

/// A suite whose every rule skipped judged nothing: exit 2, not 0.
#[test]
fn a_suite_that_judged_nothing_exits_2() -> Result<(), TestError> {
    let (_dir, path) = suite(UNDER_THE_FLOOR)?;
    let run = run_cli(
        PCAP,
        &["--expect", &path, "--json", "--no-cli-print", "--quiet"],
    )?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["verdict"], "not_evaluated", "{v}");
    assert_eq!(v["skipped"], 1, "{v}");
    Ok(())
}

/// A suite that does not parse, or names a metric the engine does not
/// compute, is refused before any capture is read, exit 2, naming the flag.
#[test]
fn a_malformed_suite_is_refused_before_the_capture_is_read() -> Result<(), TestError> {
    for bad in [
        "[[rules]]\nmetric = ",
        "[[rules]]\nmetric = \"bogus\"\nop = \">=\"\nvalue = 1\n",
    ] {
        let (_dir, path) = suite(bad)?;
        let run = run_cli(PCAP, &["--expect", &path])?;
        assert_eq!(run.code, Some(2), "{bad:?} stderr:\n{}", run.stderr);
        // Refused by the parser, before the capture is read: clap's own
        // refusal of the flag's value, not a verdict at the end of the run.
        assert!(
            run.stderr.contains("invalid value") && run.stderr.contains("--expect <FILE>"),
            "stderr:\n{}",
            run.stderr
        );
    }
    let run = run_cli(PCAP, &["--expect", "/nonexistent/sipnab.expect.toml"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    Ok(())
}

/// The gate holds under `--cores`: the same verdict and the same exit.
#[test]
fn the_gate_holds_under_cores() -> Result<(), TestError> {
    let (_dir, path) = suite(FAILING)?;
    let run = run_cli(
        PCAP,
        &[
            "--expect",
            &path,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(3), "stderr:\n{}", run.stderr);
    assert_eq!(run.last_json()?["failed"], 1);
    Ok(())
}

/// A rule that failed and a run that failed exit differently, so a CI step
/// reading only `$?` can tell "the capture broke the rules" (3) from "sipnab
/// could not read the capture" (1).
///
/// The failed run is the same capture cut short in the middle of a packet,
/// judged by a suite that passes on the whole file, so only the read differs.
#[test]
fn a_failed_rule_and_a_failed_run_exit_differently() -> Result<(), TestError> {
    let (_failing_dir, failing) = suite(FAILING)?;
    let failed_rule = run_cli(PCAP, &["--expect", &failing, "--no-cli-print", "--quiet"])?;

    let whole = std::fs::read(PCAP)?;
    let cut = tempfile::tempdir()?;
    let truncated = cut.path().join("truncated.pcap");
    std::fs::write(&truncated, &whole[..whole.len() - 7])?;
    let truncated = truncated.to_str().ok_or("a UTF-8 temp path")?.to_string();
    let (_passing_dir, passing) = suite(PASSING)?;
    let failed_run = run_cli(
        &truncated,
        &["--expect", &passing, "--no-cli-print", "--quiet"],
    )?;

    assert_eq!(
        failed_run.code,
        Some(1),
        "control: a capture not read in full is a runtime failure, exit 1\nstderr:\n{}",
        failed_run.stderr
    );
    assert_eq!(
        failed_rule.code,
        Some(3),
        "a failed rule must not share exit 1 with a failed run\nstderr:\n{}",
        failed_rule.stderr
    );
    Ok(())
}
