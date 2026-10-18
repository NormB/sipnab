// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--since`/`--until`: the CLI's time window, held to REST and MCP.
//!
//! The window is the one REST spells `after`/`before` on `/v1/dialogs` and MCP
//! spells `start`/`end` on `search_by_time`: half-open `[since, until)` over a
//! dialog's first-message instant, evaluated through `cursor::in_time_window`.
//! The CLI cannot reuse REST's names because `-A`/`--after` already means
//! "context lines after a match".
//!
//! The capture is `tests/pcap-samples/sip-problem-call.pcap`: five INVITE
//! dialogs whose first messages are exactly three seconds apart, at
//! 22:13:20Z, :23, :26, :29 and :32 on 2023-11-14. Whole seconds put both
//! boundaries of a window on a real dialog, so the test can see that the
//! lower bound is inclusive and the upper bound is not.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, call_ids, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/sip-problem-call.pcap";

/// The dialog whose first message is AT the window's lower bound.
const AT_SINCE: &str = "busy-3a2b1c@192.0.2.30";
/// The dialog strictly inside the window.
const INSIDE: &str = "decline-7c6d5e@198.51.100.30";
/// The dialog whose first message is AT the window's upper bound.
const AT_UNTIL: &str = "notfound-1b2c3d@203.0.113.30";

const SINCE: &str = "2023-11-14T22:13:23Z";
const UNTIL: &str = "2023-11-14T22:13:29Z";

/// The Call-IDs `--json-dialogs` printed, one per line, with the
/// per-message stream and the summary off so stdout holds only those lines.
fn cli_call_ids(args: &[&str]) -> Result<Vec<String>, TestError> {
    let mut argv = vec!["--no-cli-print", "--quiet"];
    argv.extend_from_slice(args);
    let run = run_cli(PCAP, &argv)?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    run.json_lines()?
        .iter()
        .map(|d| {
            d["call_id"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("a --json-dialogs line has no call_id: {d}").into())
        })
        .collect()
}

/// The window keeps the dialog at `since` and drops the one at `until`, and
/// the CLI, REST and MCP name the same dialogs for it.
#[test]
fn the_window_is_half_open_and_agrees_with_rest_and_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let mut cli = cli_call_ids(&["--json-dialogs", "--since", SINCE, "--until", UNTIL])?;
    cli.sort();
    assert_eq!(cli, vec![AT_SINCE.to_string(), INSIDE.to_string()]);
    assert!(!cli.iter().any(|c| c == AT_UNTIL), "until is exclusive");

    let rest = surfaces.rest_json(&format!("/v1/dialogs?after={SINCE}&before={UNTIL}"))?;
    let mut rest = call_ids(&rest, "dialogs")?;
    rest.sort();
    assert_eq!(cli, rest, "CLI --since/--until == REST after/before");

    let mcp = surfaces.mcp_json(
        "search_by_time",
        serde_json::json!({"start": SINCE, "end": UNTIL}),
    )?;
    let mut mcp = call_ids(&mcp, "dialogs")?;
    mcp.sort();
    assert_eq!(cli, mcp, "CLI --since/--until == MCP search_by_time");
    Ok(())
}

/// The window ANDs with `--filter`: the one compiled filter, not a second.
#[test]
fn the_window_composes_with_a_filter() -> Result<(), TestError> {
    let ids = cli_call_ids(&[
        "--json-dialogs",
        "--since",
        SINCE,
        "--until",
        UNTIL,
        "--filter",
        "response_code == 486",
    ])?;
    assert_eq!(ids, vec![AT_SINCE.to_string()]);
    Ok(())
}

/// One bound alone is a half-line: `--since` only, `--until` only.
#[test]
fn one_bound_alone_is_open_on_the_other_side() -> Result<(), TestError> {
    let after = cli_call_ids(&["--json-dialogs", "--since", "2023-11-14T22:13:29Z"])?;
    assert_eq!(after.len(), 2, "the dialogs at :29 and :32: {after:?}");
    let before = cli_call_ids(&["--json-dialogs", "--until", "2023-11-14T22:13:23Z"])?;
    assert_eq!(before, vec!["completed-9f8e7d@192.0.2.10".to_string()]);
    Ok(())
}

/// `--report` honors the window: the dialog table lists only its dialogs.
#[test]
fn the_report_honors_the_window() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--report", "--since", SINCE, "--until", UNTIL])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains(AT_SINCE), "{}", run.stdout);
    assert!(!run.stdout.contains(AT_UNTIL), "{}", run.stdout);
    Ok(())
}

/// `--cores` reads through the same report chain and the same filter.
#[test]
fn the_window_holds_under_cores() -> Result<(), TestError> {
    let mut ids = cli_call_ids(&[
        "--json-dialogs",
        "--cores",
        "2",
        "--since",
        SINCE,
        "--until",
        UNTIL,
    ])?;
    ids.sort();
    assert_eq!(ids, vec![AT_SINCE.to_string(), INSIDE.to_string()]);
    Ok(())
}

/// A window the capture does not reach is an explicit empty answer, exit 0:
/// no dialog lines, and a report that says no dialog matched.
#[test]
fn a_window_outside_the_capture_is_an_explicit_empty_answer() -> Result<(), TestError> {
    assert!(cli_call_ids(&["--json-dialogs", "--since", "2030-01-01T00:00:00Z"])?.is_empty());
    let run = run_cli(PCAP, &["--report", "--since", "2030-01-01T00:00:00Z"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(!run.stdout.contains("@192.0.2"), "{}", run.stdout);
    assert!(
        run.stderr
            .contains("no dialog's first message falls in [2030-01-01T00:00:00Z, unbounded)")
            && run.stderr.contains("2023-11-14T22:13:20Z")
            && run.stderr.contains("2023-11-14T22:13:32Z"),
        "names the window and the span the capture covers:\n{}",
        run.stderr
    );
    Ok(())
}

/// The refusals exit 2 and name what was wrong.
#[test]
fn refusals_exit_2_and_say_why() -> Result<(), TestError> {
    for (args, says) in [
        (
            &["--report", "--since", UNTIL, "--until", SINCE][..],
            "is not after --since",
        ),
        (
            &["--report", "--since", SINCE, "--until", SINCE][..],
            "is not after --since",
        ),
        (&["--report", "--since", "yesterday"][..], "RFC 3339"),
        (
            &["--report", "--until", "2023-11-14 22:13:29"][..],
            "RFC 3339",
        ),
    ] {
        let run = run_cli(PCAP, args)?;
        assert_eq!(run.code, Some(2), "{args:?}: stderr:\n{}", run.stderr);
        assert!(
            run.stderr.contains(says),
            "{args:?}: stderr:\n{}",
            run.stderr
        );
    }
    Ok(())
}

/// The window narrows the batch outputs, which the TUI does not read, so a
/// run that would raise the TUI refuses it rather than ignore it.
#[test]
fn the_window_without_no_tui_is_refused() -> Result<(), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", PCAP, "--since", SINCE])
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("-N/--no-tui"), "stderr:\n{stderr}");
    Ok(())
}

/// `--export-vcon-when` exports only the matching dialogs inside the window.
#[test]
fn the_vcon_export_honors_the_window() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().to_string_lossy().into_owned();
    let run = run_cli(
        PCAP,
        &[
            "--export-vcon-when",
            "state == 'Failed'",
            "--export-vcon-dir",
            &out,
            "--quiet",
            "--since",
            SINCE,
            "--until",
            UNTIL,
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let written = std::fs::read_dir(dir.path())?.count();
    assert_eq!(written, 2, "the failed calls at :23 and :26 only");
    Ok(())
}

/// `--json-analyze` examines only the window's dialogs, and says which
/// filter it ran: the window written in the DSL.
#[test]
fn the_analysis_honors_the_window_and_names_it() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--json-analyze",
            "--no-cli-print",
            "--quiet",
            "--since",
            SINCE,
            "--until",
            UNTIL,
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["dialogs_examined"], 2, "{v}");
    assert_eq!(
        v["filter"],
        format!("time >= '{SINCE}' AND time < '{UNTIL}'"),
        "{v}"
    );
    Ok(())
}
