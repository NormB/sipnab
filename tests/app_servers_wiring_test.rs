// SPDX-License-Identifier: MIT OR Apache-2.0

//! Companion-server wiring that `app_servers_test` does not reach: a metrics
//! credential that cannot be resolved, the REST relay routes on a run that
//! names a relay, and the MCP builder toggles reaching a real server.
//!
//! # Why the binary-driven cases stop their child with SIGTERM
//!
//! A process killed by SIGKILL never writes its coverage profile. SIGTERM is
//! the signal sipnab handles (`signals::install_handlers`): the keep-alive loop
//! sees the shutdown flag, the run exits through its ordinary path, and the
//! exit status itself becomes something to assert. The stopping is the shared
//! `terminate` rule in `support/teardown.rs`, which every spawn harness uses.

#![cfg(feature = "full")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use sipnab::app::servers::{self, Selection};
use sipnab::cli::Cli;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::security::AlertEngine;
use sipnab::sip::dialog_store::DialogStore;

include!("support/timeout.rs");
include!("support/teardown.rs");

/// A selection that asks for the metrics server alone, with every ceiling at
/// its shipped default.
fn metrics_only() -> Selection {
    Selection {
        evidence_ring: None,
        mcp_row_cap: Cli::DEFAULT_MCP_MAX_ROWS as usize,
        mcp_body_cap: Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
        mcp_wait_seconds: Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
        api_row_cap: Cli::DEFAULT_API_MAX_ROWS as usize,
        api_rate_limit_per_peer: Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
        max_tracked_peers: Cli::DEFAULT_MAX_TRACKED_PEERS,
        metrics_max_conn: Cli::DEFAULT_METRICS_MAX_CONN,
        tfps: Default::default(),
        mcp_max_findings: Cli::DEFAULT_MCP_MAX_FINDINGS,
        api: false,
        mcp: false,
        metrics: true,
        armed_detections: Vec::new(),
    }
}

/// Start the servers `cli` configures, metrics only, and return the error
/// text when startup is refused.
fn start_metrics(cli: &Cli) -> Result<bool, String> {
    let ds = Arc::new(RwLock::new(DialogStore::new(16, false)));
    let ss = Arc::new(RwLock::new(StreamStore::new(16)));
    let alerts = Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None)));
    servers::start_servers(cli, &ds, &ss, Some(&alerts), metrics_only(), None, None)
        .map(|handles| handles.is_some())
        .map_err(|e| format!("{e:#}"))
}

// ── A metrics credential that cannot be resolved ──────────────────────────

/// An unreadable `--metrics-auth-file` is a startup error, not a scrape
/// endpoint served without the authentication the operator asked for.
///
/// `resolve_file_or_inline_secret` refuses an unreadable file precisely "so a
/// mis-set secret fails loudly instead of silently disabling authentication",
/// and `--api` / `--mcp` both exit 2 on an unreadable key file. The metrics arm
/// logged the refusal and started anyway with no credential at all, so on a
/// loopback bind the endpoint came up open and the run exited 0.
#[test]
fn an_unreadable_metrics_auth_file_is_a_startup_error_not_an_open_endpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("metrics.cred");
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.metrics = Some("127.0.0.1:0".into());
    cli.listener_args.metrics_auth_file = Some(missing.clone());

    let err = start_metrics(&cli).expect_err("an unreadable credential file must refuse startup");
    assert!(
        err.contains("--metrics-auth-file") && err.contains(&missing.display().to_string()),
        "the refusal must name the flag and the file: {err}"
    );
}

/// An empty credential file is refused the same way: an empty secret is not a
/// secret, and serving with none is the failure being refused.
#[test]
fn an_empty_metrics_auth_file_is_a_startup_error() {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.metrics = Some("127.0.0.1:0".into());
    cli.listener_args.metrics_auth_file = Some(file.path().to_path_buf());

    let err = start_metrics(&cli).expect_err("an empty credential file must refuse startup");
    assert!(err.contains("file is empty"), "{err}");
}

/// The anti-vacuity partner: a readable credential still starts the server,
/// so the refusals above are about the credential and not about `--metrics`.
#[test]
fn a_readable_metrics_auth_file_still_starts_the_server() {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    writeln!(file, "scraper:s3cret").expect("write credential");
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.metrics = Some("127.0.0.1:0".into());
    cli.listener_args.metrics_auth_file = Some(file.path().to_path_buf());

    assert_eq!(
        start_metrics(&cli),
        Ok(false),
        "metrics runs on its own thread; no async server was selected"
    );
}

// ── Binary-driven: REST relay routes and MCP toggles ──────────────────────

/// The capture every binary-driven case reads.
const CAPTURE: &str = "tests/fixtures/sip_call.pcap";

/// A `sipnab` child whose stderr is drained into a channel of lines.
struct Spawned {
    child: Child,
    stderr: mpsc::Receiver<String>,
    /// Every stderr line read so far, for failure messages.
    seen: Vec<String>,
}

impl Spawned {
    /// Spawn the binary with `args`, a private config directory, and stdio as
    /// given. `HOME` and `XDG_CONFIG_HOME` point into `home`, so no user
    /// configuration is read.
    fn start(args: &[&str], home: &std::path::Path, stdin: Stdio, stdout: Stdio) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(args)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home)
            .env_remove("SIPNAB_CONFIG")
            .env("SIPNAB_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipnab");
        let err = child.stderr.take().expect("piped stderr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stderr: rx,
            seen: Vec::new(),
        }
    }

    /// Wait for a stderr line containing `needle` and return the text after it.
    fn after(&mut self, needle: &str, wait: Duration) -> Option<String> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(100)) {
                let hit = line.split(needle).nth(1).map(|s| s.trim().to_string());
                self.seen.push(line);
                if hit.is_some() {
                    return hit;
                }
            }
        }
        None
    }

    /// Send SIGTERM and wait for the exit code, SIGKILLing only on a hang.
    fn terminate(mut self) -> (Option<i32>, String) {
        let code = terminate(&mut self.child)
            .ok()
            .and_then(|status| status.code());
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(200)) {
            self.seen.push(line);
        }
        (code, self.seen.join("\n"))
    }
}

/// A test that fails before `terminate` still reaps its child, so a red run
/// leaves no server behind. A child already reaped is past `try_wait`.
impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = terminate(&mut self.child);
    }
}

/// One HTTP/1.1 GET with a bearer token; returns the status and body.
fn http_get(addr: &str, path: &str, bearer: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {bearer}\r\n\
         Connection: close\r\n\r\n"
    )
    .expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
    (status, body)
}

/// A relay named on a file-backed run is `not_permitted` over REST, and the
/// run still exits cleanly on SIGTERM.
///
/// The address is what `--rtpengine-control` names; the permit is what a live
/// source grants. A file run names the relay but holds no permit, so the
/// answer is the refusal that sends the operator to a live capture -- not the
/// `not_configured` a run that named nothing gets. Nothing is transmitted: the
/// route refuses before any relay is asked.
#[test]
fn a_named_relay_on_a_file_run_answers_not_permitted_over_rest() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut run = Spawned::start(
        &[
            "-N",
            "-I",
            CAPTURE,
            "--api",
            "127.0.0.1:0",
            "--api-key",
            "k",
            "--rtpengine-control",
            "127.0.0.1:9",
            "--api-allow-relay-query",
        ],
        home.path(),
        Stdio::null(),
        Stdio::null(),
    );
    let addr = run
        .after("REST API listening on ", Duration::from_secs(30))
        .unwrap_or_else(|| panic!("no listening line:\n{}", run.seen.join("\n")));
    // The keep-alive loop is where SIGTERM is honored; wait until the capture
    // has drained into it, so the shutdown exercises the whole run.
    assert!(
        run.after("API server active", Duration::from_secs(30))
            .is_some(),
        "the run must reach its keep-alive loop:\n{}",
        run.seen.join("\n")
    );

    let (status, body) = http_get(&addr, "/v1/relay/stats", "k");
    assert_eq!(status, 200, "a refusal is content, not a 4xx: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    assert_eq!(
        v["outcome"], "not_permitted",
        "a relay named on a file run is not_permitted, never not_configured: {body}"
    );

    let (code, log) = run.terminate();
    assert_eq!(code, Some(0), "SIGTERM ends a served run cleanly:\n{log}");
}

/// Write one JSON-RPC message to the server's stdin.
fn send(stdin: &mut std::process::ChildStdin, msg: &serde_json::Value) {
    writeln!(stdin, "{msg}").expect("write JSON-RPC");
    stdin.flush().expect("flush");
}

/// Read JSON-RPC lines until the reply to `id` arrives.
fn reply(reader: &mut BufReader<std::process::ChildStdout>, id: i64) -> serde_json::Value {
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            reader.read_line(&mut line).unwrap_or(0) > 0,
            "sipnab closed stdout while waiting for reply {id}"
        );
        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim())
            && msg["id"] == serde_json::json!(id)
        {
            return msg;
        }
    }
}

/// `--mcp-allow-save-findings` reaches the server the batch path builds, and
/// closing stdin ends the run with exit 0.
///
/// The same session also carries `--mcp-allow-tls-capture` and
/// `--mcp-sampling-budget`, so each toggle's arm of the builder runs on a real
/// process; the write is the one whose effect a client can read back.
#[test]
fn the_mcp_toggles_reach_the_server_and_closing_stdin_ends_the_run() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut run = Spawned::start(
        &[
            "--mcp",
            "-N",
            "-I",
            CAPTURE,
            "--quiet",
            "--mcp-allow-save-findings",
            "--mcp-allow-tls-capture",
            "--mcp-sampling-budget",
            "5",
        ],
        home.path(),
        Stdio::piped(),
        Stdio::piped(),
    );
    let mut stdin = run.child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(run.child.stdout.take().expect("stdout"));
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}
        }),
    );
    let _ = reply(&mut reader, 1);
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "save_findings",
                       "arguments": {"summary": "wiring check"}}
        }),
    );
    let saved = reply(&mut reader, 2);
    let text = saved["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("save_findings must be accepted: {saved}"));
    let v: serde_json::Value = serde_json::from_str(text).expect("payload is JSON");
    assert_eq!(v["recorded_total"], 1, "the flag armed the write: {v}");

    // The stdio client owns the lifetime: closing its end is how it leaves.
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(30);
    let code = loop {
        if let Ok(Some(status)) = run.child.try_wait() {
            break status.code();
        }
        assert!(
            Instant::now() < deadline,
            "closing stdin must end an MCP stdio run"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(code, Some(0), "a client that leaves is a clean exit");
}
