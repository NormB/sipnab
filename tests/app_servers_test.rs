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

type Shared<T> = Arc<RwLock<T>>;

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
fn nothing_enabled_spawns_nothing() {
    let cli = Cli::parse_from_args(["sipnab"]);
    let (ds, ss, alerts) = stores();
    let handle = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            api: true,
            mcp: true,
        },
    )
    .expect("no servers requested must succeed");
    assert!(handle.is_none(), "no --api/--mcp flags ⇒ no servers thread");
}

/// A selection that excludes a configured server must not start it: the TUI
/// path requests API only (MCP stdio would fight the TUI for stdio).
#[cfg(feature = "mcp")]
#[test]
fn selection_gates_configured_servers() {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp = true; // configured…
    let (ds, ss, alerts) = stores();
    let handle = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            api: true,
            mcp: false, // …but not selected
        },
    )
    .expect("must succeed");
    assert!(handle.is_none(), "unselected MCP must not start a thread");
}

/// An invalid --api bind address is a startup error the caller can turn into
/// exit(2) — the pre-WS2 behavior, now testable instead of a process exit
/// buried in a helper.
#[cfg(feature = "api")]
#[test]
fn invalid_api_addr_is_an_error() {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.api = Some("not-a-bind-addr".into());
    let (ds, ss, alerts) = stores();
    let err = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            api: true,
            mcp: false,
        },
    );
    assert!(err.is_err(), "junk --api address must be a startup error");
}

/// A valid API request starts the (single) servers thread.
#[cfg(feature = "api")]
#[test]
fn api_on_ephemeral_port_starts_servers_thread() {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.api = Some("127.0.0.1:0".into());
    let (ds, ss, alerts) = stores();
    let handle = servers::start_servers(
        &cli,
        &ds,
        &ss,
        Some(&alerts),
        Selection {
            api: true,
            mcp: false,
        },
    )
    .expect("valid --api must start");
    assert!(handle.is_some(), "an enabled server must spawn the thread");
    // The thread runs the servers for the life of the process; it is
    // intentionally detached here (the test process exits and reaps it).
}

/// The API verifier resolution (signing keys + static keys + revocation
/// file) must be a pure, unit-testable Cli→VerifierConfig mapping.
#[cfg(feature = "api")]
#[test]
fn api_verifier_config_resolution_matrix() {
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.api_signing_key = vec!["k1".into(), "".into(), "k2".into()];
    cli.api_key = Some("static1".into());
    cli.api_revoked_file = Some("/tmp/revoked.txt".into());
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
}

/// MCP static-secret precedence: --mcp-token wins over --mcp-token-file,
/// values are trimmed, and an empty token yields no static key.
#[cfg(feature = "mcp")]
#[test]
fn mcp_verifier_token_precedence_and_trim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let token_file = dir.path().join("token.txt");
    std::fs::write(&token_file, "  file-secret \n").expect("write");

    // File only → trimmed file secret.
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_token = None;
    cli.mcp_token_file = Some(token_file.to_string_lossy().into_owned());
    let cfg = servers::resolve_mcp_verifier_config(&cli);
    assert_eq!(cfg.static_keys, vec!["file-secret".to_string()]);

    // Inline token wins over the file.
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_token = Some(" inline-secret ".into());
    cli.mcp_token_file = Some(token_file.to_string_lossy().into_owned());
    let cfg = servers::resolve_mcp_verifier_config(&cli);
    assert_eq!(cfg.static_keys, vec!["inline-secret".to_string()]);

    // Whitespace-only inline token → no static key at all.
    let mut cli = Cli::parse_from_args(["sipnab"]);
    cli.mcp_token = Some("   ".into());
    cli.mcp_token_file = None;
    let cfg = servers::resolve_mcp_verifier_config(&cli);
    assert!(cfg.static_keys.is_empty());
}
