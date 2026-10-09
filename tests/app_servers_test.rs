// SPDX-License-Identifier: MIT OR Apache-2.0

//! Companion-server startup must be a testable library facade (WS2), not
//! three hand-rolled bootstraps in main.rs: one call starts every enabled
//! async server (REST API, MCP stdio, MCP HTTP) on ONE shared tokio runtime,
//! and the caller contains zero feature `cfg`.
#![cfg(feature = "native")]

use std::sync::Arc;

use parking_lot::RwLock;
use sipnab::app::servers::{self, Selection};
use sipnab::cli::Cli;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::security::AlertEngine;
use sipnab::sip::dialog_store::DialogStore;

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

/// Shorthand for the `Arc<RwLock<T>>` shape `start_servers` expects for its
/// shared stores.
type Shared<T> = Arc<RwLock<T>>;

/// Builds a fresh, empty trio of shared stores (dialogs, streams, alerts)
/// sized for tests.
///
/// # Returns
/// `(DialogStore, StreamStore, AlertEngine)` each wrapped in `Arc<RwLock<_>>`.
fn stores() -> (
    Shared<DialogStore>,
    Shared<StreamStore>,
    Shared<AlertEngine>,
) {
    (
        Arc::new(RwLock::new(DialogStore::new(16, false))),
        Arc::new(RwLock::new(StreamStore::new(16))),
        Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
    )
}

/// Nothing enabled → no thread is spawned and the call succeeds. This is the
/// common path for every plain capture invocation.
#[test]
fn nothing_enabled_spawns_nothing() -> Result<(), TestError> {
    let cli = Cli::parse_from_args(["sipnab"]);
    let (ds, ss, alerts) = stores();
    let handle = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: true,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )?;
    assert!(handle.is_none(), "no --api/--mcp flags ⇒ no servers thread");
    Ok(())
}

/// A selection that excludes a configured server must not start it: the TUI
/// path requests API only (MCP stdio would fight the TUI for stdio).
#[cfg(feature = "mcp")]
#[test]
fn selection_gates_configured_servers() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp = true; // configured…
    let (ds, ss, alerts) = stores();
    let handle = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: false, // …but not selected
            // These cases exercise the API/MCP selection; the metrics server
            // has its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )?;
    assert!(handle.is_none(), "unselected MCP must not start a thread");
    Ok(())
}

/// An invalid --api bind address is a startup error the caller can turn into
/// exit(2) — the pre-WS2 behavior, now testable instead of a process exit
/// buried in a helper.
#[cfg(feature = "api")]
#[test]
fn invalid_api_addr_is_an_error() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.api = Some("not-a-bind-addr".into());
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: false,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    );
    assert!(err.is_err(), "junk --api address must be a startup error");
    Ok(())
}

/// A valid API request starts the (single) servers thread.
#[cfg(feature = "api")]
#[test]
fn api_on_ephemeral_port_starts_servers_thread() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.api = Some("127.0.0.1:0".into());
    let (ds, ss, alerts) = stores();
    let handle = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: false,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )?;
    let handle = handle.ok_or("an enabled server must spawn the thread")?;
    // Only an MCP stdio client owns the process lifetime; an API-only run
    // must not hand the caller a flag to wait on.
    assert!(handle.mcp_stdio_done.is_none());
    // The thread runs the servers for the life of the process; it is
    // intentionally detached here (the test process exits and reaps it).
    Ok(())
}

/// A busy --api port must fail `start_servers` synchronously — once the TUI
/// owns the terminal, a bind error logged from the detached servers thread is
/// invisible and the user gets a running TUI with no API.
#[cfg(feature = "api")]
#[test]
fn api_port_in_use_is_a_startup_error() -> Result<(), TestError> {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = occupied.local_addr()?.port();
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.api = Some(format!("127.0.0.1:{port}"));
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: false,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )
    .err()
    .ok_or("busy --api port must be a startup error, not a detached-thread log")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains("bind"),
        "error must name the bind failure: {msg}"
    );
    Ok(())
}

/// Non-loopback --api without auth must be refused at startup for the same
/// reason: the policy error used to fire on the servers thread, hidden by
/// the TUI alternate screen.
#[cfg(feature = "api")]
#[test]
fn api_non_loopback_without_auth_is_a_startup_error() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.api = Some("192.0.2.1:0".into()); // TEST-NET-1; policy fires before any bind
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: false,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )
    .err()
    .ok_or("unauthenticated non-loopback --api must be a startup error")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains("non-loopback"),
        "error must explain the auth policy: {msg}"
    );
    Ok(())
}

/// An API TLS file that cannot be read must surface as a startup error
/// naming it, rather than as an async log from the servers thread.
#[cfg(feature = "api")]
#[test]
fn an_unreadable_api_tls_file_is_a_startup_error_naming_it() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("absent-cert.pem");
    let missing = missing.to_string_lossy().into_owned();
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.api = Some("127.0.0.1:0".into());
    cli.listener_args.api_tls_cert = Some(missing.clone());
    cli.listener_args.api_tls_key = Some(missing.clone());
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            // Resolved the way tui_mode and batch resolve it: the flags,
            // else `[api] tls_cert` / `tls_key` (none here).
            api_tls: cli.api_tls_files(&sipnab::config::Config::default()),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: true,
            mcp: false,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )
    .err()
    .ok_or("an API TLS file that cannot be read must be a startup error")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&missing),
        "the error must name the file it could not read: {msg}"
    );
    Ok(())
}

/// `--mcp-transport http` in a build without the mcp-http feature must be a
/// startup error — the old log-and-skip left the user with a running capture
/// and no server, silently.
#[cfg(all(feature = "mcp", not(feature = "mcp-http")))]
#[test]
fn mcp_http_transport_without_feature_is_a_startup_error() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp = true;
    cli.mcp_args.mcp_transport = "http".into();
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: false,
            mcp: true,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )
    .err()
    .ok_or("http transport without mcp-http must be a startup error")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains("mcp-http"),
        "error must name the missing feature: {msg}"
    );
    Ok(())
}

/// An unknown --mcp-transport is a configuration error, not a log-and-skip.
#[cfg(feature = "mcp")]
#[test]
fn unknown_mcp_transport_is_a_startup_error() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp = true;
    cli.mcp_args.mcp_transport = "carrier-pigeon".into();
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: false,
            mcp: true,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )
    .err()
    .ok_or("unknown --mcp-transport must be a startup error")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains("carrier-pigeon"),
        "error must echo the bad transport: {msg}"
    );
    Ok(())
}

/// A malformed --mcp-bind is a configuration error, not a log-and-skip.
#[cfg(feature = "mcp-http")]
#[test]
fn invalid_mcp_bind_is_a_startup_error() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp = true;
    cli.mcp_args.mcp_transport = "http".into();
    cli.mcp_args.mcp_bind = Some("not-a-bind-addr".into());
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: false,
            mcp: true,
            // These cases exercise the API/MCP selection; the metrics server has
            // its own end-to-end gate in tests/metrics_headless_test.rs.
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    );
    assert!(
        err.is_err(),
        "junk --mcp-bind must be a startup error, not log-and-skip"
    );
    Ok(())
}

/// The API verifier resolution (signing keys + static keys + revocation
/// file) must be a pure, unit-testable Cli→VerifierConfig mapping.
#[cfg(feature = "api")]
#[test]
fn api_verifier_config_resolution_matrix() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.api_signing_key = vec!["k1".into(), "".into(), "k2".into()];
    cli.listener_args.api_key = Some("static1".into());
    cli.listener_args.api_revoked_file = Some("/tmp/revoked.txt".into());
    let cfg = servers::resolve_api_verifier_config(&cli);
    assert_eq!(
        cfg.signing_keys,
        vec![b"k1".to_vec(), b"k2".to_vec()],
        "empty signing keys are dropped"
    );
    assert_eq!(cfg.static_keys, vec!["static1".to_string()]);
    assert_eq!(
        cfg.revoked_file.as_deref(),
        Some(std::path::Path::new("/tmp/revoked.txt"))
    );
    Ok(())
}

/// MCP static-secret precedence: --mcp-token wins over --mcp-token-file,
/// values are trimmed, and an empty token yields no static key.
#[cfg(feature = "mcp")]
#[test]
fn mcp_verifier_token_precedence_and_trim() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let token_file = dir.path().join("token.txt");
    std::fs::write(&token_file, "  file-secret \n")?;

    // File only → trimmed file secret.
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp_token = None;
    cli.mcp_args.mcp_token_file = Some(token_file.to_string_lossy().into_owned());
    let cfg = servers::resolve_mcp_verifier_config(&cli);
    assert_eq!(cfg.static_keys, vec!["file-secret".to_string()]);

    // Inline token wins over the file.
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp_token = Some(" inline-secret ".into());
    cli.mcp_args.mcp_token_file = Some(token_file.to_string_lossy().into_owned());
    let cfg = servers::resolve_mcp_verifier_config(&cli);
    assert_eq!(cfg.static_keys, vec!["inline-secret".to_string()]);

    // Whitespace-only inline token → no static key at all.
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp_token = Some("   ".into());
    cli.mcp_args.mcp_token_file = None;
    let cfg = servers::resolve_mcp_verifier_config(&cli);
    assert!(cfg.static_keys.is_empty());
    Ok(())
}

/// An unauthenticated non-loopback `--metrics` is a startup ERROR, not a log
/// line the run continues past.
///
/// The refusal itself was already right and is not what this pins. What was
/// wrong is what happened next: `start_servers` matched on the result and did
/// `Err(e) => tracing::error!(...)`, so the process carried on and exited 0
/// with nothing listening. `sipnab --metrics 0.0.0.0:9109 && echo up` printed
/// `up`, and a monitoring pipeline that checks exit status believed the
/// scrape endpoint was live. It never arrives, and nothing downstream says so.
///
/// `--api` refuses the same bind and propagates, exiting 2. Two flags with the
/// same policy and opposite exit codes is the part an operator cannot be
/// expected to know.
#[cfg(feature = "metrics")]
#[test]
fn metrics_non_loopback_without_auth_is_a_startup_error() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.metrics = Some("192.0.2.1:0".into()); // TEST-NET-1; policy fires before any bind
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: false,
            mcp: false,
            metrics: true,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    )
    .err()
    .ok_or("unauthenticated non-loopback --metrics must be a startup error")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains("non-loopback"),
        "error must explain the auth policy: {msg}"
    );
    Ok(())
}

/// A loopback `--metrics` on an ephemeral port still starts.
///
/// The anti-vacuity partner: a `start_servers` that failed on every `--metrics`
/// would satisfy the test above.
#[cfg(feature = "metrics")]
#[test]
fn metrics_on_loopback_ephemeral_port_starts() -> Result<(), TestError> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.listener_args.metrics = Some("127.0.0.1:0".into());
    let (ds, ss, alerts) = stores();
    let out = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: false,
            mcp: false,
            metrics: true,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        #[cfg(any(feature = "api", feature = "mcp"))]
        None,
        None,
    );
    assert!(
        out.is_ok(),
        "a loopback metrics bind must still start: {:?}",
        out.err().map(|e| format!("{e:#}"))
    );
    Ok(())
}

/// Start only the MCP HTTP door for `bind`, returning what `start_servers`
/// returned.
#[cfg(feature = "mcp-http")]
fn start_mcp_http(bind: &str) -> anyhow::Result<Option<servers::ServerHandles>> {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_args.mcp = true;
    cli.mcp_args.mcp_transport = "http".into();
    cli.mcp_args.mcp_bind = Some(bind.into());
    let (ds, ss, alerts) = stores();
    servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            evidence_ring: None,
            mcp_tools: sipnab::mcp_profile::ToolSelection::Full,
            mcp_output_schemas: false,
            api_allowed_hosts: Vec::new(),
            api_tls: (None, None),
            mcp_tls: (None, None),
            metrics_tls: (None, None),
            mcp_row_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_ROWS as usize,
            mcp_body_cap: sipnab::cli::Cli::DEFAULT_MCP_MAX_BODY_BYTES as usize,
            mcp_wait_seconds: sipnab::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS,
            mcp_sweep: sipnab::cli::McpSweepLimits::default(),
            mcp_sweep_jobs: sipnab::cli::McpSweepJobLimits::default(),
            api_row_cap: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            api_rate_limit_per_peer: sipnab::cli::Cli::DEFAULT_API_RATE_LIMIT_PER_PEER,
            max_tracked_peers: sipnab::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            metrics_max_conn: sipnab::cli::Cli::DEFAULT_METRICS_MAX_CONN,
            tfps: Default::default(),
            actions: Default::default(),
            mcp_max_findings: sipnab::cli::Cli::DEFAULT_MCP_MAX_FINDINGS,
            api: false,
            mcp: true,
            metrics: false,
            armed_detections: Vec::new(),
            pipeline_options: Default::default(),
        },
        // No transmit permit: none of these cases opens a live source.
        None,
        None,
    )
}

/// A busy --mcp-bind port fails `start_servers` on the caller's thread, as a
/// busy --api port does. MCP over HTTP now serves beside the TUI, and once
/// the TUI owns the terminal a bind error logged from the detached servers
/// thread is invisible: the operator would get a TUI with no MCP and no
/// reason.
#[cfg(feature = "mcp-http")]
#[test]
fn mcp_http_port_in_use_is_a_startup_error() -> Result<(), TestError> {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = occupied.local_addr()?;
    let err = start_mcp_http(&addr.to_string())
        .err()
        .ok_or("busy --mcp-bind port must be a startup error, not a detached-thread log")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&addr.to_string()),
        "error must name the address it could not bind: {msg}"
    );
    Ok(())
}

/// A non-loopback --mcp-bind with no credential is refused on the caller's
/// thread, for the reason above. The rule itself is unchanged.
#[cfg(feature = "mcp-http")]
#[test]
fn mcp_http_non_loopback_without_auth_is_a_startup_error() -> Result<(), TestError> {
    let err = start_mcp_http("0.0.0.0:0")
        .err()
        .ok_or("non-loopback MCP without auth must be a startup error")?;
    let msg = format!("{err:#}");
    assert!(msg.contains("refuses to start"), "{msg}");
    Ok(())
}

/// The handles carry the address the MCP HTTP server bound, and it is
/// listening when `start_servers` returns. With `--mcp-bind 127.0.0.1:0` the
/// port is the kernel's choice, and the TUI shows the operator this address
/// because a TUI run prints no log line to read it from.
#[cfg(feature = "mcp-http")]
#[test]
fn mcp_http_reports_the_address_it_bound() -> Result<(), TestError> {
    let handles = start_mcp_http("127.0.0.1:0")?.ok_or("MCP selected, so a servers thread")?;
    let addr = handles
        .mcp_http_addr
        .ok_or("the handles must carry the bound MCP HTTP address")?;
    assert!(addr.ip().is_loopback(), "{addr}");
    assert_ne!(addr.port(), 0, "the kernel's port, not the requested 0");
    std::net::TcpStream::connect(addr)?;
    Ok(())
}
