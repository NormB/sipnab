// SPDX-License-Identifier: MIT OR Apache-2.0

//! MCP actions go through the journal, the rules and the rate limits
//! (JOURNAL, ACTIONS-HARDEN; approved 2026-09-28).
//!
//! Written before the behavior exists. The same service REST uses: an agent
//! with `tfps_ban` enabled gets no more than a REST caller does. An argument
//! that breaks a rule is an invalid argument (`-32602`), as a bad address
//! already is. A refusal of a well-formed call (a rate limit, a ban sipnab did
//! not place, TFPS failing) is a tool result with `isError`, whose JSON says
//! which refusal it was, so the agent can read it and act on it.

#![cfg(all(unix, feature = "full"))]

use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "support/mcp.rs"]
mod mcp;

use mcp::{McpSession, ok_payload_or_panic};

const PCAP: &str = "tests/fixtures/sip_call.pcap";

#[path = "support/fake_tfps_ctl.rs"]
mod fake_tfps_ctl;

use fake_tfps_ctl::Fake;

fn session(fake: &Fake, journal: &Path) -> McpSession {
    let ctl = fake.path();
    let dir = journal.display().to_string();
    McpSession::start_or_panic(
        PCAP,
        &[
            "--tfps-ctl",
            &ctl,
            "--allow-action",
            "tfps:mcp",
            "--journal-dir",
            &dir,
        ],
    )
}

/// Every record in the journal, in order.
fn records(journal: &Path) -> Vec<serde_json::Value> {
    let mut segments: Vec<PathBuf> = std::fs::read_dir(journal)
        .expect("journal dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    segments.sort();
    segments
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .expect("segment")
                .lines()
                .map(|l| serde_json::from_str(l).expect("record"))
                .collect::<Vec<serde_json::Value>>()
        })
        .collect()
}

/// The JSON body of a tool result marked `isError`.
fn refusal(reply: &serde_json::Value) -> serde_json::Value {
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text: {reply}"));
    serde_json::from_str(text).expect("the refusal is JSON")
}

#[test]
fn a_ban_over_stdio_is_journaled_and_answers_with_its_id() {
    let fake = Fake::new_or_panic();
    let journal = tempfile::tempdir().expect("tempdir");
    let mut s = session(&fake, journal.path());
    let answer = ok_payload_or_panic(
        &s.call_or_panic("tfps_ban", serde_json::json!({"ip": "198.51.100.20"})),
    );
    assert_eq!(answer["applied"], true, "{answer}");
    let id = answer["id"].as_str().expect("an id").to_string();
    drop(s);
    let all = records(journal.path());
    let intent: Vec<_> = all
        .iter()
        .filter(|r| r["kind"] == "action_intent")
        .collect();
    assert_eq!(intent.len(), 1, "{all:?}");
    assert_eq!(intent[0]["id"], id.as_str());
    assert_eq!(intent[0]["surface"], "mcp");
    assert_eq!(intent[0]["caller"], "stdio");
    assert!(
        all.iter()
            .any(|r| r["kind"] == "action_outcome" && r["id"] == id.as_str()),
        "{all:?}"
    );
}

#[test]
fn an_argument_that_breaks_a_rule_is_invalid_and_tfps_is_not_asked() {
    let fake = Fake::new_or_panic();
    let journal = tempfile::tempdir().expect("tempdir");
    let mut s = session(&fake, journal.path());
    for args in [
        serde_json::json!({"ip": "127.0.0.1"}),
        serde_json::json!({"ip": "255.255.255.255"}),
        serde_json::json!({"ip": "198.51.100.20", "ttl_secs": 0}),
        serde_json::json!({"ip": "198.51.100.20", "ttl_secs": 604_801}),
    ] {
        let reply = s.call_or_panic("tfps_ban", args.clone());
        assert_eq!(reply["error"]["code"], -32602, "{args}: {reply}");
    }
    assert_eq!(fake.count("ban"), 0, "{}", fake.calls());
}

#[test]
fn sipnab_will_not_lift_a_ban_it_did_not_place() {
    let fake = Fake::new_or_panic();
    let journal = tempfile::tempdir().expect("tempdir");
    let mut s = session(&fake, journal.path());
    let body = refusal(&s.call_or_panic("tfps_unban", serde_json::json!({"ip": "198.51.100.10"})));
    assert_eq!(body["refusal"], "not_owned", "{body}");
    assert!(
        body["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{body}"
    );
    assert_eq!(fake.count("unban"), 0, "{}", fake.calls());
}

#[test]
fn the_sixth_action_a_minute_is_refused_with_when_to_retry() {
    let fake = Fake::new_or_panic();
    let journal = tempfile::tempdir().expect("tempdir");
    let mut s = session(&fake, journal.path());
    for n in 1..=5 {
        let answer = ok_payload_or_panic(&s.call_or_panic(
            "tfps_ban",
            serde_json::json!({"ip": format!("198.51.100.{n}")}),
        ));
        assert_eq!(answer["applied"], true, "ban {n}: {answer}");
    }
    let body = refusal(&s.call_or_panic("tfps_ban", serde_json::json!({"ip": "198.51.100.6"})));
    assert_eq!(body["refusal"], "rate", "{body}");
    let secs = body["retry_after_secs"].as_u64().expect("retry_after_secs");
    assert!((1..=60).contains(&secs), "{body}");
    assert_eq!(fake.count("ban"), 5, "{}", fake.calls());
}

#[test]
fn a_restart_does_not_refill_an_agents_allowance() {
    let fake = Fake::new_or_panic();
    let journal = tempfile::tempdir().expect("tempdir");
    let mut s = session(&fake, journal.path());
    for n in 1..=5 {
        let _ = ok_payload_or_panic(&s.call_or_panic(
            "tfps_ban",
            serde_json::json!({"ip": format!("198.51.100.{n}")}),
        ));
    }
    drop(s);
    // Restarted on the same journal, it is still the same caller's minute.
    let mut s = session(&fake, journal.path());
    let body = refusal(&s.call_or_panic("tfps_ban", serde_json::json!({"ip": "198.51.100.6"})));
    assert_eq!(body["refusal"], "rate", "{body}");
    assert_eq!(fake.count("ban"), 5, "{}", fake.calls());
}

#[test]
fn without_a_usable_journal_an_mcp_server_refuses_to_start() {
    let fake = Fake::new_or_panic();
    let blocker = tempfile::NamedTempFile::new().expect("a file");
    let bad = blocker.path().join("journal").display().to_string();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--mcp",
            "-N",
            "-I",
            PCAP,
            "--tfps-ctl",
            &fake.path(),
            "--allow-action",
            "tfps:mcp",
            "--journal-dir",
            &bad,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline && child.try_wait().expect("wait").is_none() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let out = child.wait_with_output().expect("output");
    assert!(!out.status.success(), "must refuse to start");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&bad), "names the directory: {stderr}");
}

#[test]
fn an_agent_can_revert_what_it_banned() {
    let fake = Fake::new_or_panic();
    let journal = tempfile::tempdir().expect("tempdir");
    let config_dir = tempfile::tempdir().expect("tempdir");
    let config = config_dir.path().join("sipnab.toml");
    std::fs::write(&config, "[action_limits]\naddress_cooldown_secs = 1\n").expect("config");
    let ctl = fake.path();
    let dir = journal.path().display().to_string();
    let config = config.display().to_string();
    let mut s = McpSession::start_or_panic(
        PCAP,
        &[
            "--tfps-ctl",
            &ctl,
            "--allow-action",
            "tfps:mcp",
            "--journal-dir",
            &dir,
            "--config",
            &config,
        ],
    );
    let id = ok_payload_or_panic(
        &s.call_or_panic("tfps_ban", serde_json::json!({"ip": "198.51.100.20"})),
    )["id"]
        .as_str()
        .expect("id")
        .to_string();
    std::thread::sleep(Duration::from_millis(1100));
    let report =
        ok_payload_or_panic(&s.call_or_panic("actions_revert", serde_json::json!({"id": id})));
    assert_eq!(report["reverted"], serde_json::json!([id]), "{report}");
    assert_eq!(fake.count("unban"), 1, "{}", fake.calls());
    let reply = s.call_or_panic("actions_revert", serde_json::json!({}));
    assert_eq!(
        reply["error"]["code"], -32602,
        "names one id or all: {reply}"
    );
}

#[test]
fn with_actions_off_an_agent_cannot_revert() {
    let fake = Fake::new_or_panic();
    let ctl = fake.path();
    let mut s = McpSession::start_or_panic(PCAP, &["--tfps-ctl", &ctl]);
    let reply = s.call_or_panic("actions_revert", serde_json::json!({"all": true}));
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("--allow-action tfps:mcp")),
        "{reply}"
    );
    assert_eq!(fake.count("unban"), 0);
}
