// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--call-tree`: every leg of one call across B2BUA, SBC and PBX hops, on
//! the CLI, held to REST and MCP.
//!
//! The same walk `GET /v1/dialogs/{call_id}/tree` and the MCP `get_call_tree`
//! tool answer from. The CLI prints the REST answer, so `--call-tree --json`
//! and the route agree field for field once `capture_identity` is set aside.
//!
//! `tests/pcap-samples/b2bua-asterisk.pcapng` holds a call from alice through
//! an Asterisk B2BUA: the caller's leg and the leg Asterisk opened toward bob
//! share no identifier, so the timing heuristic ties them (score 50), and the
//! walk does not continue through a guess.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/b2bua-asterisk.pcapng";
const CALLER: &str = "b2bua-caller-synth@203.0.113.1";
const B_LEG: &str = "b2bua-leg-synth@203.0.113.101:5060";

/// `value` with `capture_identity` removed.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    value
}

/// `--call-tree <id> --json` is the REST tree, and its legs are the MCP
/// tool's.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--call-tree", CALLER, "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(cli["root_call_id"], CALLER, "{cli}");
    assert_eq!(cli["total_legs"], 2, "{cli}");
    assert_eq!(cli["legs"][1]["call_id"], B_LEG, "{cli}");
    assert_eq!(cli["legs"][1]["strategy"], "timing_heuristic", "{cli}");
    assert_eq!(cli["legs"][1]["followed"], false, "{cli}");
    assert_eq!(cli["heuristic_edges"], 1, "{cli}");

    let rest = surfaces.rest_json(&format!("/v1/dialogs/{CALLER}/tree"))?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --call-tree --json == REST /v1/dialogs/{{id}}/tree"
    );

    let mcp = surfaces.mcp_json("get_call_tree", serde_json::json!({"call_id": CALLER}))?;
    let ids = |v: &serde_json::Value| -> Vec<String> {
        v["legs"]
            .as_array()
            .map(|legs| {
                legs.iter()
                    .filter_map(|l| l["call_id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(
        ids(&cli),
        ids(&mcp),
        "CLI --call-tree == MCP get_call_tree: {mcp}"
    );
    Ok(())
}

/// The table indents each leg by its depth and says how the walk reached
/// it, and the heading counts the guesses.
#[test]
fn the_table_indents_legs_by_depth_and_names_the_strategy() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--call-tree", CALLER, "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains(&format!(
            "Call tree from {CALLER}: 2 legs, depth 1, 28 messages, 1 timing guess"
        )),
        "{out}"
    );
    let root = out
        .lines()
        .find(|l| l.starts_with(CALLER))
        .ok_or("the root row")?;
    assert!(root.split_whitespace().nth(1) == Some("root"), "{out}");
    let leg = out
        .lines()
        .find(|l| l.starts_with(&format!("  {B_LEG}")))
        .ok_or("the B leg row, indented one level")?;
    let words: Vec<&str> = leg.split_whitespace().collect();
    assert_eq!(
        words,
        vec![B_LEG, "timing_heuristic", "50", "guess", "no"],
        "{out}"
    );
    Ok(())
}

/// A Call-ID the run did not track exits 1 with the message `--call-report`
/// gives, and prints no tree.
#[test]
fn an_unknown_call_id_exits_1() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--call-tree",
            "nope@example.com",
            "--json",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(1), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr
            .contains("Call-ID 'nope@example.com' not found in tracked dialogs"),
        "stderr:\n{}",
        run.stderr
    );
    assert!(!run.stdout.contains("root_call_id"), "{}", run.stdout);
    Ok(())
}

/// The named call is the root whatever `--filter` admits, as `--call-report`
/// reads the call it is given.
#[test]
fn the_filter_does_not_hide_the_named_call() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--call-tree",
            CALLER,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "state == Failed",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(run.last_json()?["total_legs"], 2);
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
            "--call-tree",
            CALLER,
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
            "--call-tree",
            CALLER,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(run.last_json()?["total_legs"], 2);
    Ok(())
}
