// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--endpoint-ip` and `--endpoint-user`: everything one endpoint did, on
//! the CLI, held to REST and MCP.
//!
//! The same rollup `GET /v1/endpoints` and the MCP `describe_endpoint` tool
//! answer: dialogs by method and state, messages sent and received, call
//! outcomes, registration, banners, the signaling stack, media, and the most
//! recent dialogs. The CLI prints the REST answer, so `--endpoint-ip --json`
//! and the route agree field for field once `capture_identity` is set aside.
//!
//! `tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap` holds an Asterisk PBX at
//! 192.168.10.2 that took part in five dialogs (one INVITE, one OPTIONS, one
//! REGISTER, two SUBSCRIBE), sent 14 messages and received 13, and the user
//! 10009 who is in the same five.

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use surface_parity::{Surfaces, run_cli};

type TestError = Box<dyn std::error::Error>;

const PCAP: &str = "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap";
const PBX: &str = "192.168.10.2";

/// `value` with `capture_identity` removed and every path spelled relative
/// to the repository: the REST harness opens the capture by its absolute
/// path and the CLI by the relative one, and each dialog's `frame` names the
/// file it was read from as it was given.
fn without_identity(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("capture_identity");
    }
    let prefix = format!("{}/", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&value.to_string().replace(&prefix, "")).unwrap_or(value)
}

/// `--endpoint-ip <ip> --json` is the REST rollup, and its counts are the
/// MCP tool's.
#[test]
fn the_json_answer_is_the_rest_answer_and_agrees_with_mcp() -> Result<(), TestError> {
    let mut surfaces = Surfaces::start(PCAP)?;

    let run = surfaces.cli(&["--endpoint-ip", PBX, "--json", "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(cli["endpoint_kind"], "ip", "{cli}");
    assert_eq!(cli["dialogs"], 5, "{cli}");
    assert_eq!(cli["messages_sent"], 14, "{cli}");
    assert_eq!(cli["messages_received"], 13, "{cli}");
    assert_eq!(cli["by_method"]["SUBSCRIBE"], 2, "{cli}");

    let rest = surfaces.rest_json(&format!("/v1/endpoints?ip={PBX}"))?;
    assert_eq!(
        without_identity(cli.clone()),
        without_identity(rest),
        "CLI --endpoint-ip --json == REST /v1/endpoints"
    );

    let mcp = surfaces.mcp_json("describe_endpoint", serde_json::json!({"ip": PBX}))?;
    for field in [
        "dialogs",
        "messages_sent",
        "messages_received",
        "by_method",
        "by_state",
    ] {
        assert_eq!(cli[field], mcp[field], "{field}: CLI {cli} MCP {mcp}");
    }
    Ok(())
}

/// A user part selects by URI, and `--top` bounds the recent dialogs as
/// REST's `limit` does while the counts still describe every match.
#[test]
fn a_user_and_top_match_rest() -> Result<(), TestError> {
    let surfaces = Surfaces::start(PCAP)?;
    let run = surfaces.cli(&[
        "--endpoint-user",
        "10009",
        "--top",
        "2",
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let cli = run.last_json()?;
    assert_eq!(cli["endpoint_kind"], "user", "{cli}");
    assert_eq!(cli["dialogs"], 5, "{cli}");
    assert_eq!(
        cli["recent_dialogs"].as_array().map(Vec::len),
        Some(2),
        "{cli}"
    );
    assert_eq!(cli["truncated"], true, "{cli}");
    let rest = surfaces.rest_json("/v1/endpoints?user=10009&limit=2")?;
    assert_eq!(without_identity(cli), without_identity(rest));
    Ok(())
}

/// The text names the endpoint and lists what it did, then its most recent
/// dialogs as a table.
#[test]
fn the_text_lists_what_the_endpoint_did() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--endpoint-ip", PBX, "--no-cli-print", "--quiet"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let out = &run.stdout;
    for line in [
        "Endpoint ip 192.168.10.2: 5 dialogs",
        "Dialogs by method: INVITE 1, OPTIONS 1, REGISTER 1, SUBSCRIBE 2",
        "Dialogs by state: Completed 2, Registered 1, Terminated 2",
        "Messages: 14 sent, 13 received",
        "Calls: 1 INVITE, 1 with a final response, 0 failed (0%); final responses: 200 x1",
        "Registration: 1 dialog, 1 succeeded, 0 failed, 0 authentication loops",
        "Banners: User-Agent Asterisk PBX 1.6.0.6 (4)",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
    assert!(out.contains("Call-ID"), "the recent dialogs table: {out}");
    Ok(())
}

/// Neither selector, both, or an address that does not parse exits 2 with
/// REST's reason.
#[test]
fn bad_selectors_exit_2() -> Result<(), TestError> {
    let run = run_cli(PCAP, &["--endpoint-ip", "bogus"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("ip 'bogus' is not an address"),
        "stderr:\n{}",
        run.stderr
    );
    let run = run_cli(PCAP, &["--endpoint-ip", PBX, "--endpoint-user", "10009"])?;
    assert_eq!(run.code, Some(2), "stderr:\n{}", run.stderr);
    Ok(())
}

/// An endpoint the capture never saw is an answer of zeros, exit 0, as REST
/// answers it.
#[test]
fn an_unseen_endpoint_is_zeros() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--endpoint-ip",
            "192.0.2.99",
            "--json",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let v = run.last_json()?;
    assert_eq!(v["dialogs"], 0, "{v}");
    Ok(())
}

/// The flags make the run headless by themselves, and hold under `--cores`.
#[test]
fn the_flag_implies_no_tui_and_holds_under_cores() -> Result<(), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            PCAP,
            "--endpoint-user",
            "10009",
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
            "--endpoint-ip",
            PBX,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--cores",
            "2",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(run.last_json()?["dialogs"], 5);
    Ok(())
}

/// The rollup describes everything the endpoint did in the capture, as the
/// REST route does: `--filter` does not narrow it.
#[test]
fn the_filter_does_not_narrow_the_rollup() -> Result<(), TestError> {
    let run = run_cli(
        PCAP,
        &[
            "--endpoint-ip",
            PBX,
            "--json",
            "--no-cli-print",
            "--quiet",
            "--filter",
            "state == Failed",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(run.last_json()?["dialogs"], 5);
    Ok(())
}
