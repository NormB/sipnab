// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--correlate`: the other legs of one call and the strategy that matched
//! each, on the CLI, held to REST and MCP.
//!
//! The same question `GET /v1/dialogs/{call_id}/correlated` and the MCP
//! `find_correlated` tool answer. The CLI prints the REST answer, so
//! `--correlate --json` and the route agree field for field once
//! `capture_identity` is set aside.
//!
//! `tests/pcap-samples/b2bua-asterisk.pcapng` holds a call through an
//! Asterisk B2BUA whose two legs share no identifier: the timing heuristic
//! ties them, 3 ms apart, at a score of 50.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/b2bua-asterisk.pcapng";
const CALLER: &str = "b2bua-caller-synth@203.0.113.1";
const B_LEG: &str = "b2bua-leg-synth@203.0.113.101:5060";
const ALONE: &str = "b2bua-reg-a-synth@203.0.113.1";

/// `value` with `capture_identity` removed.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    value
}

/// `--correlate <id> --json` is the REST answer, and its legs are the MCP
/// tool's.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--correlate", CALLER, "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(cli["source_call_id"], CALLER, "{cli}");
    assert_eq!(cli["total_matched"], 1, "{cli}");
    assert_eq!(cli["legs"][0]["call_id"], B_LEG, "{cli}");
    assert_eq!(cli["legs"][0]["strategy"], "timing_heuristic", "{cli}");
    assert_eq!(cli["legs"][0]["observed_gap_ms"], 3, "{cli}");
    assert_eq!(cli["heuristic_only"], true, "{cli}");

    let rest = surfaces.rest_json(&format!("/v1/dialogs/{CALLER}/correlated"))?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --correlate --json == REST /v1/dialogs/{{id}}/correlated"
    );

    let mcp = surfaces.mcp_json("find_correlated", serde_json::json!({"call_id": CALLER}))?;
    let legs = |v: &serde_json::Value| -> Vec<(String, String)> {
        v["legs"]
            .as_array()
            .map(|legs| {
                legs.iter()
                    .map(|l| {
                        (
                            l["call_id"].as_str().unwrap_or_default().to_string(),
                            l["strategy"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(
        legs(&cli),
        legs(&mcp),
        "CLI --correlate == MCP find_correlated: {mcp}"
    );
    Ok(())
}

/// The table lists each leg with how it was matched, and warns when every
/// match is a timing guess.
#[test]
fn the_table_lists_each_leg_and_warns_on_guesses_only() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--correlate", CALLER, "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains(&format!("Legs correlated with {CALLER}: 1 leg")),
        "{out}"
    );
    let row: Vec<&str> = out
        .lines()
        .find(|l| l.starts_with(B_LEG))
        .ok_or("the leg row")?
        .split_whitespace()
        .collect();
    assert_eq!(
        row,
        vec![B_LEG, "timing_heuristic", "50", "guess", "3"],
        "{out}"
    );
    assert!(
        out.contains("Every leg here is a timing guess"),
        "the answer says it is only guesses: {out}"
    );
    Ok(())
}

/// A call with no other leg is an empty answer, exit 0: the call is there
/// and stands alone, which is not the same as a call that is not there.
#[test]
fn a_call_standing_alone_is_an_empty_answer() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &["--correlate", ALONE, "--json", "--no-cli-print", "--quiet"],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["total_matched"], 0, "{v}");
    assert_eq!(v["heuristic_only"], false, "{v}");
    let run = run_cli(PCAP, &["--correlate", ALONE, "--no-cli-print", "--quiet"])?;
    assert!(
        run.stdout
            .contains(&format!("Legs correlated with {ALONE}: 0 legs")),
        "{}",
        run.stdout
    );
    Ok(())
}

/// A Call-ID the run did not track exits 1 with `--call-report`'s message.
#[test]
fn an_unknown_call_id_exits_1() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--correlate",
            "nope@example.com",
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
            "--correlate",
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
            "--correlate",
            CALLER,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(run.last_json()?["total_matched"], 1);
    Ok(())
}

/// Two calls carrying one SDP origin are an identifier match: no gap, and
/// no claim that the answer is only guesses.
#[test]
fn an_identifier_match_is_not_called_a_guess() -> Result<(), TestError> {
    let pcap = "tests/pcap-samples/sip-rtp-g711.pcap";
    let run = run_cli(
        pcap,
        &[
            "--correlate",
            "1-1966@10.0.2.20",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let row: Vec<&str> = run
        .stdout
        .lines()
        .find(|l| l.starts_with("1-1968@10.0.2.20"))
        .ok_or("the leg row")?
        .split_whitespace()
        .collect();
    assert_eq!(
        row,
        vec!["1-1968@10.0.2.20", "sdp_origin", "90", "identifier", "-"],
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains("timing guess"), "{}", run.stdout);
    Ok(())
}
