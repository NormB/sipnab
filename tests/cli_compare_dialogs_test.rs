// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--compare-dialogs`: two calls side by side on the CLI, held to REST and
//! MCP.
//!
//! The same comparison `GET /v1/dialogs/compare` and the MCP
//! `compare_dialogs` tool answer: state, final response code, message count
//! and methods for each call, with the fields that differ named, and each
//! call's diagnosis hints. The CLI prints the REST answer, so
//! `--compare-dialogs --json` and the route agree field for field once
//! `capture_identity` is set aside.
//!
//! `tests/pcap-samples/sip-problem-call.pcap` holds an answered call (200,
//! seven messages, ACK, BYE and INVITE) and a busy one (486, four messages,
//! ACK and INVITE), which differ in all four fields, and two failed calls,
//! 486 and 503, which differ only in the response code.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-problem-call.pcap";
const ANSWERED: &str = "completed-9f8e7d@192.0.2.10";
const BUSY: &str = "busy-3a2b1c@192.0.2.30";
const UNAVAILABLE: &str = "unavail-4e5f60@192.0.2.50";

/// `value` with `capture_identity` removed.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    value
}

/// `--compare-dialogs A B --json` is the REST comparison, and names the
/// differences the MCP tool names.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&[
        "--compare-dialogs",
        ANSWERED,
        BUSY,
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(
        cli["differences"],
        serde_json::json!(["state", "final_status_code", "msg_count", "methods"]),
        "{cli}"
    );
    assert_eq!(cli["a"]["final_status_code"], 200, "{cli}");
    assert_eq!(cli["b"]["final_status_code"], 486, "{cli}");

    let rest = surfaces.rest_json(&format!("/v1/dialogs/compare?a={ANSWERED}&b={BUSY}"))?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --compare-dialogs --json == REST /v1/dialogs/compare"
    );

    let mcp = surfaces.mcp_json(
        "compare_dialogs",
        serde_json::json!({"call_id_a": ANSWERED, "call_id_b": BUSY}),
    )?;
    assert_eq!(cli["differences"], mcp["differences"], "{mcp}");
    Ok(())
}

/// The table puts the two calls in columns, one row per field, and marks
/// the rows that differ.
#[test]
fn the_table_puts_the_calls_side_by_side_and_marks_differences() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--compare-dialogs",
            BUSY,
            UNAVAILABLE,
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    assert!(
        out.contains(&format!(
            "Comparing {BUSY} (A) with {UNAVAILABLE} (B): 1 field differs"
        )),
        "{out}"
    );
    let words = |field: &str| -> Option<Vec<&str>> {
        out.lines()
            .find(|l| l.starts_with(field))
            .map(|l| l.split_whitespace().collect())
    };
    assert_eq!(
        words("final_status_code").ok_or("the code row")?,
        vec!["final_status_code", "486", "503", "differs"],
        "{out}"
    );
    assert_eq!(
        words("msg_count").ok_or("the count row")?,
        vec!["msg_count", "4", "4"],
        "{out}"
    );
    assert_eq!(
        words("methods").ok_or("the methods row")?,
        vec!["methods", "ACK,INVITE", "ACK,INVITE"],
        "{out}"
    );
    assert!(
        out.contains("Call failed: 486 Busy Here."),
        "the hints: {out}"
    );
    Ok(())
}

/// A Call-ID the run did not track, on either side, exits 1 with
/// `--call-report`'s message.
#[test]
fn an_unknown_call_id_on_either_side_exits_1() -> Result<(), TestError> {
    for args in [["nope@example.com", BUSY], [BUSY, "nope@example.com"]] {
        let run = run_cli(
            PCAP,
            &[
                "--compare-dialogs",
                args[0],
                args[1],
                "--no-cli-print",
                "--quiet",
            ],
        )?;
        assert_eq!(run.code, Some(1), "{args:?} stderr:\n{}", run.stderr);
        assert!(
            run.stderr
                .contains("Call-ID 'nope@example.com' not found in tracked dialogs"),
            "stderr:\n{}",
            run.stderr
        );
    }
    Ok(())
}

/// One Call-ID is refused by the parser: the flag takes exactly two.
#[test]
fn one_call_id_exits_2() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--compare-dialogs", BUSY])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
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
            "--compare-dialogs",
            ANSWERED,
            BUSY,
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
            "--compare-dialogs",
            ANSWERED,
            BUSY,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(
        run.last_json()?["differences"].as_array().map(Vec::len),
        Some(4)
    );
    Ok(())
}
