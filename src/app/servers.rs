// SPDX-License-Identifier: MIT OR Apache-2.0

//! Companion-server startup: REST API, MCP stdio, and MCP HTTP.
//!
//! Every enabled async server runs on ONE background thread driving ONE
//! current-thread tokio runtime (pre-WS2, each server bootstrapped its own
//! thread + runtime in main.rs). The entry point `start_servers` is
//! unconditional — its *body* is feature-swapped, so callers contain zero
//! `#[cfg(feature = ...)]`, following the `pipeline::MediaDecrypt` pattern.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::cli::Cli;
use crate::rtp::stream_store::StreamStore;
use crate::security::AlertEngine;
use crate::sip::dialog_store::DialogStore;

/// Which servers the current run mode wants. The TUI requests the API only
/// (MCP stdio would fight the TUI for stdio); batch mode requests both.
/// Plain booleans — a selected-but-unconfigured (or uncompiled) server is
/// simply not started, so callers need no feature gates.
#[derive(Debug, Clone, Copy)]
pub struct Selection {
    /// Start the REST API server when `--api` is configured.
    pub api: bool,
    /// Start the MCP server when `--mcp` is configured.
    pub mcp: bool,
}

/// Handles to the running servers thread.
pub struct ServerHandles {
    /// The single shared-runtime thread driving every enabled async server.
    /// Detached — it lives for the rest of the process.
    pub thread: std::thread::JoinHandle<()>,
    /// Set once the MCP stdio task finishes (the client closed stdin). The
    /// stdio client owns the process lifetime, so callers exit when this
    /// flips rather than serving nobody forever. `None` when MCP stdio is
    /// not running.
    pub mcp_stdio_done: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Shared flag the MCP `tail_dialogs` tool reports as `source_exhausted`.
    /// The capture owner stores `true` once the packet source drains (pcap
    /// EOF). `None` when MCP is not running.
    pub source_exhausted: Option<Arc<std::sync::atomic::AtomicBool>>,
}

/// A server prepared on the caller's thread (address parsing and auth
/// resolution happen synchronously, so configuration errors surface before
/// capture starts), ready to be awaited on the shared runtime.
enum Prepared {
    /// REST API server, listener already bound.
    #[cfg(feature = "api")]
    Api {
        /// Pre-bound on the caller's thread so a busy port (or any other
        /// bind failure) is fatal before the TUI hides stderr.
        listener: std::net::TcpListener,
        /// Shared stores + verifier + rate limiter the handlers read.
        state: crate::output::api::ApiState,
        /// Connection cap and optional TLS certificate/key paths.
        config: crate::output::api::ApiServerConfig,
    },
    /// MCP server speaking JSON-RPC over the process's stdin/stdout.
    #[cfg(feature = "mcp")]
    McpStdio {
        /// The tool server to expose (boxed to keep the variant small).
        server: Box<crate::mcp::SipnabMcp>,
        /// Flipped to `true` when the stdio task finishes (client closed
        /// stdin); surfaced to callers via `ServerHandles::mcp_stdio_done`.
        done: Arc<std::sync::atomic::AtomicBool>,
    },
    /// MCP server speaking Streamable HTTP on a TCP bind.
    #[cfg(feature = "mcp-http")]
    McpHttp {
        /// The tool server to expose (boxed to keep the variant small).
        server: Box<crate::mcp::SipnabMcp>,
        /// Parsed `--mcp-bind` address (default `127.0.0.1:8731`).
        bind: std::net::SocketAddr,
        /// Bearer-token verifier configuration for the HTTP guard.
        auth: crate::auth::VerifierConfig,
        /// `--mcp-allowed-host` additions to the Host-header allowlist.
        extra_allowed_hosts: Vec<String>,
    },
}

#[cfg(any(feature = "api", feature = "mcp"))]
impl Prepared {
    /// Run this server to completion, logging (not propagating) runtime
    /// errors — one failed server must not tear down the others.
    ///
    /// # Side effects
    ///
    /// Serves network/stdio traffic until the transport finishes; the
    /// stdio variant additionally stores `true` into its `done` flag so
    /// the batch keep-alive loop can exit when the client disconnects.
    async fn run(self) {
        match self {
            #[cfg(feature = "api")]
            Prepared::Api {
                listener,
                state,
                config,
            } => {
                if let Err(e) = crate::output::api::serve_on(listener, state, config).await {
                    tracing::error!("API server error: {e}");
                }
            }
            #[cfg(feature = "mcp")]
            Prepared::McpStdio { server, done } => {
                if let Err(e) = crate::mcp::transport::serve_stdio(*server).await {
                    tracing::error!("MCP stdio server error: {e}");
                }
                done.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            #[cfg(feature = "mcp-http")]
            Prepared::McpHttp {
                server,
                bind,
                auth,
                extra_allowed_hosts,
            } => {
                if let Err(e) =
                    crate::mcp::transport::serve_http(*server, bind, auth, extra_allowed_hosts)
                        .await
                {
                    tracing::error!("MCP HTTP server error: {e}");
                }
            }
        }
    }
}

/// Start every server that is both selected and configured, on one shared
/// runtime thread. Returns `Ok(None)` when nothing is enabled (the common
/// plain-capture path), `Ok(Some(handle))` for the detached servers thread,
/// and `Err` for configuration errors the caller should treat as fatal:
/// an invalid `--api`/`--mcp-bind` address, an unknown or uncompiled
/// `--mcp-transport`, and any API listener failure (port in use,
/// unauthenticated non-loopback bind, unsupported TLS flags) — the API
/// listener is bound HERE, synchronously, so these surface before the TUI
/// takes the terminal instead of dying silently on the servers thread.
///
/// `alerts` feeds the MCP `security_findings` tool; a caller without a
/// detection pipeline passes `None` and MCP runs without findings history.
///
/// # Arguments
///
/// * `cli` — parsed flags supplying `--api`, `--mcp`, transports, and auth.
/// * `dialog_store` / `stream_store` — the LIVE stores the packet loop
///   writes to; servers read the same instances (no mirroring).
/// * `alerts` — optional shared alert engine for MCP findings queries.
/// * `selection` — which servers this run mode permits.
///
/// # Side effects
///
/// Binds the API TCP listener synchronously on the caller's thread, then
/// spawns one detached OS thread named "servers" that builds a
/// current-thread tokio runtime and drives every prepared server as a task
/// until each finishes. Auth resolution may read signing-key/token files
/// from disk (and exits the process on unreadable files — see
/// `read_signing_key_file`).
pub fn start_servers(
    cli: &Cli,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    alerts: Option<&Arc<RwLock<AlertEngine>>>,
    selection: Selection,
) -> anyhow::Result<Option<ServerHandles>> {
    // `Prepared` is empty (uninstantiable) when neither server feature is
    // compiled; the bindings go unused then.
    #[allow(unused_mut)]
    let mut prepared: Vec<Prepared> = Vec::new();
    #[cfg(any(feature = "api", feature = "mcp"))]
    #[allow(unused_mut)]
    let mut mcp_stdio_done: Option<Arc<std::sync::atomic::AtomicBool>> = None;
    #[cfg(any(feature = "api", feature = "mcp"))]
    #[allow(unused_mut)]
    let mut source_exhausted: Option<Arc<std::sync::atomic::AtomicBool>> = None;
    // Every parameter below is consumed only inside the `api`/`mcp` cfg arms.
    // With neither feature compiled those arms vanish and the arguments would
    // read as dead; bind them to `_` so the build stays warning-free without a
    // blanket `#[allow(unused_variables)]` on the whole function.
    let _unused_without_server_features = (dialog_store, stream_store, alerts, &selection, cli);

    #[cfg(feature = "api")]
    if selection.api
        && let Some(addr_str) = cli.api.as_ref()
    {
        use crate::output::api::{self, ApiServerConfig, ApiState, RateLimiter};
        let bind = api::parse_bind_addr(addr_str)
            .map_err(|e| anyhow::anyhow!("Invalid --api address: {e}"))?;
        let verifier = Arc::new(crate::auth::TokenVerifier::new(
            resolve_api_verifier_config(cli),
        ));
        let state = ApiState {
            dialog_store: Arc::clone(dialog_store),
            stream_store: Arc::clone(stream_store),
            verifier,
            rate_limiter: Arc::new(parking_lot::Mutex::new(RateLimiter::new(100))),
        };
        let config = ApiServerConfig {
            max_conn: cli.api_max_conn,
            tls_cert: cli.api_tls_cert.clone(),
            tls_key: cli.api_tls_key.clone(),
        };
        // Vet the config and bind NOW, on the caller's thread: a bind failure
        // (port already in use) logged from the detached servers thread is
        // invisible once the TUI owns the terminal.
        let listener = api::prepare_listener(bind, &state.verifier, &config)?;
        prepared.push(Prepared::Api {
            listener,
            state,
            config,
        });
    }

    #[cfg(feature = "mcp")]
    if selection.mcp && cli.mcp {
        let exhausted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        source_exhausted = Some(Arc::clone(&exhausted));
        // Describe the capture source so `capture_status` reports fact rather
        // than "unknown". Derived from the same flags the capture path uses,
        // not restated — `-I` beats `-d`, exactly as bootstrap resolves it.
        let capture_ctx = {
            let (live, name) = match (cli.primary_input(), cli.device.as_deref()) {
                (Some(path), _) => (false, path.to_string()),
                (None, Some(dev)) => (true, dev.to_string()),
                // No -d and no -I: the capture layer picks a default. On
                // Linux that is the "any" pseudo-device — ALL interfaces at
                // once, loopback included — and on macOS/BSD a single device
                // from the routing table. Name it as the capture layer will
                // resolve it, so an agent is not told "auto" and left to guess
                // whether that means one interface or every one.
                (None, None) => (
                    true,
                    if cfg!(target_os = "linux") {
                        "any (all interfaces)".to_string()
                    } else {
                        "default (one interface, chosen by libpcap)".to_string()
                    },
                ),
            };
            crate::mcp::CaptureContext {
                live,
                name,
                started: std::time::Instant::now(),
                writing_to: cli.output.clone(),
            }
        };
        // What this run is reading, so the file tools cannot write over it.
        // Built from the `-I` specs rather than the resolved set: resolution
        // opens every candidate through libpcap and has already run once in
        // `bootstrap::plan`, and the specs already name every file and
        // directory that matters here.
        let protected_inputs =
            crate::capture::output_guard::ProtectedInputs::new(&cli.input, &[], cli.recursive);
        let new_server = || {
            let s = crate::mcp::SipnabMcp::new(Arc::clone(dialog_store), Arc::clone(stream_store))
                .with_source_exhausted(Arc::clone(&exhausted))
                .with_capture_context(capture_ctx.clone())
                .with_protected_inputs(protected_inputs.clone());
            let s = match cli.mcp_file_root.as_ref() {
                Some(dir) => s.with_file_root(dir),
                None => s,
            };
            let s = if cli.mcp_allow_shutdown {
                s.with_shutdown()
            } else {
                s
            };
            match alerts {
                Some(a) => s.with_alert_engine(Arc::clone(a)),
                None => s,
            }
        };
        match cli.mcp_transport.as_str() {
            "stdio" => {
                let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                mcp_stdio_done = Some(Arc::clone(&done));
                prepared.push(Prepared::McpStdio {
                    server: Box::new(new_server()),
                    done,
                });
            }
            #[cfg(feature = "mcp-http")]
            "http" => {
                let bind_str = cli.mcp_bind.as_deref().unwrap_or("127.0.0.1:8731");
                let bind = crate::output::api::parse_bind_addr(bind_str)
                    .map_err(|e| anyhow::anyhow!("Invalid --mcp-bind address: {e}"))?;
                prepared.push(Prepared::McpHttp {
                    server: Box::new(new_server()),
                    bind,
                    auth: resolve_mcp_verifier_config(cli),
                    extra_allowed_hosts: cli.mcp_allowed_host.clone(),
                });
            }
            #[cfg(not(feature = "mcp-http"))]
            "http" => {
                return Err(anyhow::anyhow!(
                    "--mcp-transport http requires the mcp-http feature; rebuild with \
                     --features mcp-http (or full)."
                ));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown --mcp-transport '{other}', expected stdio or http"
                ));
            }
        }
    }

    if prepared.is_empty() {
        return Ok(None);
    }

    // One thread, one runtime, every async server as a task on it.
    #[cfg(any(feature = "api", feature = "mcp"))]
    {
        let handle = std::thread::Builder::new()
            .name("servers".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!("Failed to build the shared server runtime: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let mut set = tokio::task::JoinSet::new();
                    for server in prepared {
                        set.spawn(server.run());
                    }
                    while set.join_next().await.is_some() {}
                });
            })
            .map_err(|e| anyhow::anyhow!("Failed to spawn the servers thread: {e}"))?;
        Ok(Some(ServerHandles {
            thread: handle,
            mcp_stdio_done,
            source_exhausted,
        }))
    }
    #[cfg(not(any(feature = "api", feature = "mcp")))]
    unreachable!("prepared is uninstantiable without the api/mcp features")
}

/// Read a signing-key file for `flag`, trimming surrounding whitespace.
///
/// # Side effects
///
/// Reads `path` from disk; on failure logs the error (naming the offending
/// `flag`) and exits the process with code 2 — a misconfigured key file is
/// always fatal.
#[cfg(any(feature = "api", feature = "mcp"))]
fn read_signing_key_file(path: &str, flag: &str) -> Vec<u8> {
    match std::fs::read_to_string(path) {
        Ok(s) => s.trim().as_bytes().to_vec(),
        Err(e) => {
            tracing::error!("{flag} '{path}': {e}");
            std::process::exit(2);
        }
    }
}

/// Resolve the REST API auth config (signing keys + static secret +
/// revocation file) from the CLI into a `crate::auth::VerifierConfig`.
/// The `--api-signing-key-file` key is loaded first so it becomes the
/// minting key.
///
/// # Side effects
///
/// May read the signing-key file from disk and exit the process (code 2)
/// when it is unreadable.
#[cfg(feature = "api")]
pub fn resolve_api_verifier_config(cli: &Cli) -> crate::auth::VerifierConfig {
    let mut signing_keys: Vec<Vec<u8>> = Vec::new();
    // File key first so it is the minting key.
    if let Some(ref path) = cli.api_signing_key_file {
        signing_keys.push(read_signing_key_file(path, "--api-signing-key-file"));
    }
    for k in &cli.api_signing_key {
        if !k.is_empty() {
            signing_keys.push(k.as_bytes().to_vec());
        }
    }
    let static_keys: Vec<String> = cli
        .api_key
        .iter()
        .filter(|k| !k.is_empty())
        .cloned()
        .collect();
    crate::auth::VerifierConfig {
        signing_keys,
        static_keys,
        revoked_file: cli.api_revoked_file.as_ref().map(std::path::PathBuf::from),
        audience: crate::auth::AUDIENCE_API.to_string(),
    }
}

/// Resolve the HTTP MCP auth config from the CLI. The MCP token resolution
/// order (`--mcp-token` > `--mcp-token-file` > env) is preserved for the
/// static-secret fallback.
///
/// # Side effects
///
/// May read the signing-key and token files from disk and exit the process
/// (code 2) when either is unreadable.
#[cfg(feature = "mcp")]
pub fn resolve_mcp_verifier_config(cli: &Cli) -> crate::auth::VerifierConfig {
    let mut signing_keys: Vec<Vec<u8>> = Vec::new();
    if let Some(ref path) = cli.mcp_signing_key_file {
        signing_keys.push(read_signing_key_file(path, "--mcp-signing-key-file"));
    }
    for k in &cli.mcp_signing_key {
        if !k.is_empty() {
            signing_keys.push(k.as_bytes().to_vec());
        }
    }

    // Static secret: --mcp-token > --mcp-token-file > SIPNAB_MCP_TOKEN (env is
    // folded into --mcp-token by clap). Trim file contents.
    let mut static_keys: Vec<String> = Vec::new();
    if let Some(t) = cli.mcp_token.as_ref() {
        let t = t.trim();
        if !t.is_empty() {
            static_keys.push(t.to_string());
        }
    } else if let Some(path) = cli.mcp_token_file.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let s = s.trim();
                if !s.is_empty() {
                    static_keys.push(s.to_string());
                }
            }
            Err(e) => {
                tracing::error!("--mcp-token-file '{path}': {e}");
                std::process::exit(2);
            }
        }
    }

    crate::auth::VerifierConfig {
        signing_keys,
        static_keys,
        revoked_file: cli.mcp_revoked_file.as_ref().map(std::path::PathBuf::from),
        audience: crate::auth::AUDIENCE_MCP.to_string(),
    }
}
