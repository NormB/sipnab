// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TFPS surfaces, driven through the doors users reach them through.
//!
//! `tests/tfps_contract_test.rs` proves the locator, the argument shapes and
//! the fixtures; `src/mcp/tools/tfps.rs` and `src/output/api.rs` prove each
//! handler against an in-process server. This file is the third layer: the
//! REAL binary, started with `--tfps-ctl` naming a fake, answering over the
//! MCP stdio wire and over HTTP. It is what lets `scripts/coverage-matrix.py`
//! call the six tools and six routes `exercised` rather than `defined only`,
//! and it is the only test here that can catch the flag being parsed, stored
//! and never handed to either server.
//!
//! The fake `tfps_ctl` dispatches on its subcommand and prints the matching
//! fixture, so every surface is driven against the bytes the contract pins.
#![cfg(all(unix, feature = "full"))]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/server.rs"]
mod server;

use mcp::{McpSession, ok_payload};
use server::ApiServer;

const STATUS: &str = include_str!("fixtures/tfps-status-golden.json");
const BANNED: &str = include_str!("fixtures/tfps-banned-golden.jsonl");
const DROPPED: &str = include_str!("fixtures/tfps-dropped-golden.jsonl");
const BAN: &str = include_str!("fixtures/tfps-ban-golden.jsonl");
const UNBAN: &str = include_str!("fixtures/tfps-unban-golden.jsonl");
const LABELS: &str = include_str!("fixtures/tfps-labels-golden.jsonl");

const PCAP: &str = "tests/fixtures/sip_call.pcap";
const KEY: &str = "tfps-surfaces-test-key";

/// A fake `tfps_ctl` that answers each subcommand with its fixture and
/// records every argv it was handed.
struct Fake {
    dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tfps_ctl");
        let here = dir.path().display();
        let ban = BAN.lines().next().expect("a ban line");
        let unban = UNBAN.lines().next().expect("an unban line");
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" >> \"{here}/argv\"\n\
             case \"$1\" in\n\
             status) cat <<'SIPNAB_FIXTURE'\n{STATUS}\nSIPNAB_FIXTURE\n;;\n\
             banned) cat <<'SIPNAB_FIXTURE'\n{BANNED}\nSIPNAB_FIXTURE\n;;\n\
             dropped) cat <<'SIPNAB_FIXTURE'\n{DROPPED}\nSIPNAB_FIXTURE\n;;\n\
             log) cat <<'SIPNAB_FIXTURE'\n{LABELS}\nSIPNAB_FIXTURE\n;;\n\
             ban) cat <<'SIPNAB_FIXTURE'\n{ban}\nSIPNAB_FIXTURE\n;;\n\
             unban) cat <<'SIPNAB_FIXTURE'\n{unban}\nSIPNAB_FIXTURE\n;;\n\
             *) echo \"unknown subcommand $1\" >&2; exit 2;;\n\
             esac\n"
        );
        std::fs::write(&path, script).expect("write the fake");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("tfps_ctl")
    }

    fn path_str(&self) -> String {
        self.path().display().to_string()
    }

    /// Every argv the fake has been handed, one call per line group.
    fn argv_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("argv")).unwrap_or_default()
    }
}

// ── MCP, over stdio ──────────────────────────────────────────────────

#[test]
fn every_tfps_tool_answers_over_the_mcp_wire_with_the_flag_wired_through() {
    let fake = Fake::new();
    let path = fake.path_str();
    let mut session = McpSession::start(PCAP, &["--tfps-ctl", &path]);

    let status = ok_payload(&session.call("tfps_status", serde_json::json!({})));
    assert_eq!(status["installed"], true, "{status}");
    assert_eq!(
        status["tfps_ctl"], path,
        "the flag named the executable that answered"
    );
    assert_eq!(status["status"]["blocked_now"], 3);

    let banned = ok_payload(&session.call("tfps_banned", serde_json::json!({})));
    assert_eq!(banned["total"], 3, "{banned}");
    assert_eq!(banned["rows"][0]["ip"], "198.51.100.10");

    let dropped = ok_payload(&session.call("tfps_dropped", serde_json::json!({})));
    assert_eq!(dropped["rows"][0]["dropped"], 30, "{dropped}");

    let labels = ok_payload(&session.call("tfps_labels", serde_json::json!({"limit": 3})));
    assert_eq!(labels["total"], 5, "{labels}");

    let ban = ok_payload(&session.call(
        "tfps_ban",
        serde_json::json!({"ip": "198.51.100.20", "ttl_secs": 3600}),
    ));
    assert_eq!(ban["action"]["applied"], true, "{ban}");

    let unban = ok_payload(&session.call("tfps_unban", serde_json::json!({"ip": "198.51.100.20"})));
    assert_eq!(unban["action"]["ip"], "198.51.100.20", "{unban}");

    let log = fake.argv_log();
    assert!(log.contains("--limit\n3\n"), "limit passed through: {log}");
    assert!(log.contains("--ttl\n3600\n"), "ttl passed through: {log}");
}

/// An address that is not one is refused by the server, before the fake is
/// asked, with the JSON-RPC code a client can branch on.
#[test]
fn a_bad_address_is_refused_over_the_wire_before_the_peer_is_asked() {
    let fake = Fake::new();
    let path = fake.path_str();
    let mut session = McpSession::start(PCAP, &["--tfps-ctl", &path]);
    let reply = session.call("tfps_ban", serde_json::json!({"ip": "not an address"}));
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    assert!(
        !fake.argv_log().contains("ban"),
        "the fake must not have been asked: {}",
        fake.argv_log()
    );
}

// ── REST, over HTTP ──────────────────────────────────────────────────

#[test]
fn every_tfps_route_answers_over_http_with_the_flag_wired_through() {
    let fake = Fake::new();
    let path = fake.path_str();
    let srv = ApiServer::spawn(&["--api-key", KEY, "--tfps-ctl", &path]);

    let status = srv.get_bearer("/v1/tfps/status", KEY);
    assert_eq!(status.status, 200, "{}", status.body);
    let status = status.json();
    assert_eq!(status["installed"], true, "{status}");
    assert_eq!(status["tfps_ctl"], path);
    assert_eq!(status["status"]["enforcement"], "active");

    let banned = srv.get_bearer("/v1/tfps/banned", KEY).json();
    assert_eq!(
        banned["rows"][0]["detail"], "pplsip",
        "REST returns the text verbatim: {banned}"
    );
    assert_eq!(
        banned["rows"][2]["rule"],
        serde_json::Value::Null,
        "null survives: {banned}"
    );

    let dropped = srv.get_bearer("/v1/tfps/dropped", KEY).json();
    assert_eq!(dropped["rows"][0]["events"], 4, "{dropped}");

    let labels = srv.get_bearer("/v1/tfps/labels?limit=2", KEY).json();
    assert_eq!(labels["total"], 5, "{labels}");

    let ban = srv.post_json_bearer(
        "/v1/tfps/ban",
        r#"{"ip":"198.51.100.20","ttl_secs":600}"#,
        KEY,
    );
    assert_eq!(ban.status, 200, "{}", ban.body);
    assert_eq!(ban.json()["action"]["applied"], true);

    let unban = srv.post_json_bearer("/v1/tfps/unban", r#"{"ip":"198.51.100.20"}"#, KEY);
    assert_eq!(unban.status, 200, "{}", unban.body);
    assert_eq!(unban.json()["action"]["source"], "operator");

    let log = fake.argv_log();
    assert!(log.contains("--limit\n2\n"), "{log}");
    assert!(log.contains("--ttl\n600\n"), "{log}");
}

/// Behind the same guard as every other `/v1/` route: a bare request is
/// `401`, and it is refused before the peer is asked.
#[test]
fn the_tfps_routes_sit_behind_the_bearer_guard() {
    let fake = Fake::new();
    let path = fake.path_str();
    let srv = ApiServer::spawn(&["--api-key", KEY, "--tfps-ctl", &path]);
    for route in [
        "/v1/tfps/status",
        "/v1/tfps/banned",
        "/v1/tfps/dropped",
        "/v1/tfps/labels",
    ] {
        let resp = srv.get(route);
        assert_eq!(
            resp.status, 401,
            "GET {route} without a token: {}",
            resp.body
        );
    }
    for route in ["/v1/tfps/ban", "/v1/tfps/unban"] {
        let resp = srv.post_json(route, r#"{"ip":"198.51.100.20"}"#);
        assert_eq!(
            resp.status, 401,
            "POST {route} without a token: {}",
            resp.body
        );
    }
    assert!(
        fake.argv_log().is_empty(),
        "an unauthenticated request reached the peer: {}",
        fake.argv_log()
    );
}

/// The peer's failure is `502`, with its standard error where a client can
/// read it.
#[test]
fn a_failing_peer_is_a_502_carrying_its_stderr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tfps_ctl");
    std::fs::write(
        &path,
        "#!/bin/sh\necho 'tfps.db: database is locked' >&2\nexit 3\n",
    )
    .expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = path.display().to_string();
    let srv = ApiServer::spawn(&["--api-key", KEY, "--tfps-ctl", &path]);
    let resp = srv.get_bearer("/v1/tfps/status", KEY);
    assert_eq!(resp.status, 502, "{}", resp.body);
    let body = resp.json();
    assert_eq!(body["type"], "https://sipnab.com/problems/bad-gateway");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("tfps.db: database is locked")),
        "{body}"
    );
}
