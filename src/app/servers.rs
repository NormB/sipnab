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
///
/// `Clone` but not `Copy`: `armed_detections` is a list, and a run arms a
/// variable number of detectors.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Ceiling on rows in one list-style MCP response.
    ///
    /// Resolved by the caller with `cli.mcp_row_cap(config)`, because config is
    /// in scope there and not here. Carried on Selection rather than added as a
    /// parameter for the same reason the flags above are: this struct is where
    /// per-run decisions about the servers already live.
    pub mcp_row_cap: usize,
    /// Ceiling on body/snippet bytes in one MCP response.
    ///
    /// Resolved by the caller with `cli.mcp_body_cap(config)`, and carried here
    /// for the same reason `mcp_row_cap` is.
    pub mcp_body_cap: usize,
    /// Ceiling on rows in one list-style REST response.
    ///
    /// Resolved by the caller with `cli.api_row_cap(config)`, and carried here
    /// for the same reason `mcp_row_cap` is.
    pub api_row_cap: usize,
    /// REST requests one client IP may make per second (`0` = uncapped).
    ///
    /// Resolved by the caller with `cli.api_peer_rate_limit(config)`, and
    /// carried here for the same reason `mcp_row_cap` is.
    pub api_rate_limit_per_peer: u32,
    /// Distinct peers one rate-limit window may hold, for the MCP per-peer
    /// limiter. Resolved by the caller with `cli.tracked_peer_capacity(config)`.
    pub max_tracked_peers: usize,
    /// Findings `save_findings` accepts before refusing further writes.
    ///
    /// Resolved by the caller with `cli.mcp_findings_cap(config)`, and carried
    /// here for the same reason `mcp_row_cap` is.
    pub mcp_max_findings: u64,
    /// Metrics scrapes served at once before further ones get `503`.
    ///
    /// Resolved by the caller with `cli.metrics_conn_cap(config)`, and carried
    /// here for the same reason `mcp_row_cap` is: this function is handed a
    /// `Cli` and no `Config`, so every resolved ceiling arrives on Selection.
    pub metrics_max_conn: usize,
    /// Start the REST API server when `--api` is configured.
    pub api: bool,
    /// Start the MCP server when `--mcp` is configured.
    pub mcp: bool,
    /// Start the Prometheus metrics server when `--metrics` is configured.
    ///
    /// BOTH run modes want this, and that is the point. It used to be started
    /// from `tui_mode.rs` alone, so `sipnab -N --metrics ...` bound nothing —
    /// which is how every server, container and systemd deployment runs. The
    /// flag still parsed and still refused a non-loopback bind without auth, so
    /// it read as wired while scraping returned nothing.
    pub metrics: bool,
    /// The detection rules this run armed, by the name each files findings
    /// under (`scanner`, `fraud`, `digest`, `reg_flood`). Empty when none is.
    ///
    /// Reported by the MCP `security_findings` tool, and it is the caller that
    /// knows: an `AlertEngine` is built on every headless run whether or not a
    /// detector was armed, so the engine's presence answers a different
    /// question. Carried on Selection for the same reason `mcp_row_cap` is —
    /// this struct is where per-run decisions about the servers already live.
    pub armed_detections: Vec<&'static str>,
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
    /// The gate the REST door moves, handed back so the exporter reads the
    /// SAME one. Present whether or not the API is running: a gate that
    /// appeared only alongside a listener would mean the exporter consulted
    /// nothing on the runs that have no listener, and those are most of them.
    pub persistence_gate: Arc<crate::output::persistence::PersistenceGate>,
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
    #[cfg(feature = "metrics")] capture_meter: Option<crate::capture::channel::CaptureMeter>,
) -> anyhow::Result<Option<ServerHandles>> {
    // Metrics first, and on its OWN thread rather than the shared async
    // runtime below: `start_metrics_server` spawns a blocking accept loop, and
    // it must come up whether or not any async server was selected.
    #[cfg(feature = "metrics")]
    if selection.metrics
        && let Some(addr_str) = cli.listener_args.metrics.as_deref()
    {
        let bind_addr = crate::output::prometheus_server::parse_metrics_addr(addr_str)?;
        let auth = cli.resolve_metrics_auth().unwrap_or_else(|e| {
            tracing::error!("metrics auth: {e}");
            None
        });
        // Propagated, not logged. `--metrics` is an explicit request for a
        // scrape endpoint, and a run that cannot provide one has not done what
        // it was asked. Logging it and continuing meant
        // `sipnab --metrics 0.0.0.0:9109 && echo up` printed `up` with nothing
        // listening: monitoring never arrives, and the exit status says it did.
        //
        // `--api` already fails the run on the SAME policy — measured, exit 2
        // against 0 — so this is consistency with its sibling rather than a new
        // opinion about how strict startup should be.
        //
        // The handle is dropped deliberately: the server lives for the rest of
        // the process and nothing joins it. The bound address is already logged
        // by the server, which matters for `--metrics 127.0.0.1:0`.
        let (_bound, _handle) = crate::output::prometheus_server::start_metrics_server(
            bind_addr,
            Arc::clone(dialog_store),
            Arc::clone(stream_store),
            auth,
            capture_meter,
            selection.metrics_max_conn,
        )
        .map_err(|e| anyhow::anyhow!("Failed to start metrics server: {e}"))?;
    }

    // `Prepared` is empty (uninstantiable) when neither server feature is
    // compiled; the bindings go unused then.
    #[allow(unused_mut)]
    let mut prepared: Vec<Prepared> = Vec::new();
    #[cfg(any(feature = "api", feature = "mcp"))]
    #[allow(unused_mut)]
    let mut mcp_stdio_done: Option<Arc<std::sync::atomic::AtomicBool>> = None;
    // Every parameter below is consumed only inside the `api`/`mcp` cfg arms.
    // With neither feature compiled those arms vanish and the arguments would
    // read as dead; bind them to `_` so the build stays warning-free without a
    // blanket `#[allow(unused_variables)]` on the whole function.
    let _unused_without_server_features = (dialog_store, stream_store, alerts, &selection, cli);

    // The capture both doors describe, created HERE so neither server owns it.
    //
    // It used to be built inside the `mcp` arm below, which is why
    // `GET /v1/stats` could not say which capture its counts came from: the
    // object existed only when MCP was running, and even then only MCP held
    // it. Sharing a copy would have been worse than the gap -- the identity
    // rotates when `open_capture` swaps the file underneath, and two copies
    // disagree from that moment on.
    //
    // Derived from the same flags the capture path uses, not restated: `-I`
    // beats `-d`, exactly as bootstrap resolves it.
    #[cfg(any(feature = "api", feature = "mcp"))]
    let capture_state = {
        let (live, name) = match (cli.primary_input(), cli.capture_args.device.as_deref()) {
            (Some(path), _) => (false, path.to_string()),
            (None, Some(dev)) => (true, dev.to_string()),
            // No -d and no -I: the capture layer picks a default. On Linux
            // that is the "any" pseudo-device -- ALL interfaces at once,
            // loopback included -- and on macOS/BSD a single device from the
            // routing table. Name it as the capture layer will resolve it, so
            // a reader is not told "auto" and left to guess whether that means
            // one interface or every one.
            (None, None) => (
                true,
                if cfg!(target_os = "linux") {
                    "any (all interfaces)".to_string()
                } else {
                    "default (one interface, chosen by libpcap)".to_string()
                },
            ),
        };
        let state = crate::capture::session::CaptureState::describing(
            crate::capture::session::CaptureContext {
                live,
                name,
                started: std::time::Instant::now(),
                writing_to: cli.capture_args.output.clone(),
            },
        );
        Arc::new(parking_lot::RwLock::new(state))
    };
    // One flag, flipped by the capture owner and read by both doors. A copy
    // would let one of them report a finished file as still running.
    #[cfg(any(feature = "api", feature = "mcp"))]
    let exhausted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Handed back to the capture owner, which is what flips it. Bound from
    // `exhausted` rather than declared as `None` and reassigned in one arm:
    // the flag is created unconditionally now that both doors read it, so
    // there is no state in which it is absent.
    #[cfg(any(feature = "api", feature = "mcp"))]
    let source_exhausted = Some(Arc::clone(&exhausted));
    // The gate the REST door moves and the exporter reads, built from the
    // command line ONCE. Its ceiling is what the operator asked for, and no
    // later reader recomputes it: two readings of `persists_content` could
    // disagree after a flag was added to one of them.
    //
    // Gated like `source_exhausted` above, and for the same reason: it is
    // carried out on `ServerHandles`, which does not exist in a build with
    // neither door. CI compiles those builds with `-Dwarnings`, so an ungated
    // binding is a hard error there and merely an unused value here.
    #[cfg(any(feature = "api", feature = "mcp"))]
    let persistence_gate = Arc::new(crate::output::persistence::PersistenceGate::new(
        cli.persists_content(),
    ));

    #[cfg(feature = "api")]
    if selection.api
        && let Some(addr_str) = cli.listener_args.api.as_ref()
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
            rate_limiter: Arc::new(parking_lot::Mutex::new(RateLimiter::new(
                selection.api_rate_limit_per_peer,
            ))),
            max_rows: selection.api_row_cap,
            // One number across both doors: see `ApiState::max_inline_media_bytes`.
            max_inline_media_bytes: cli
                .output_args
                .vcon_max_inline_media
                .map(|mib| mib.saturating_mul(1024 * 1024)),
            // The same object the MCP arm below is handed, so both doors name
            // one capture and see one rotation.
            capture: Some(Arc::clone(&capture_state)),
            source_exhausted: Some(Arc::clone(&exhausted)),
            persistence_gate: Arc::clone(&persistence_gate),
        };
        let config = ApiServerConfig {
            max_conn: cli.listener_args.api_max_conn,
            tls_cert: cli.listener_args.api_tls_cert.clone(),
            tls_key: cli.listener_args.api_tls_key.clone(),
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
    if selection.mcp && cli.mcp_args.mcp {
        // What this run is reading, so the file tools cannot write over it.
        // Built from the `-I` specs rather than the resolved set: resolution
        // opens every candidate through libpcap and has already run once in
        // `bootstrap::plan`, and the specs already name every file and
        // directory that matters here.
        let protected_inputs = crate::capture::output_guard::ProtectedInputs::new(
            &cli.capture_args.input,
            &[],
            cli.capture_args.recursive,
        );
        let new_server = || {
            let s = crate::mcp::SipnabMcp::new(Arc::clone(dialog_store), Arc::clone(stream_store))
                .with_source_exhausted(Arc::clone(&exhausted))
                // The SAME object REST holds, context already set. Handed in
                // rather than built here, so a rotation one door performs is a
                // rotation the other sees.
                .with_capture_state(Arc::clone(&capture_state))
                .with_protected_inputs(protected_inputs.clone())
                .with_max_concurrent(cli.mcp_args.mcp_max_concurrent as usize)
                .with_rate_limit_per_peer(
                    cli.mcp_args.mcp_rate_limit_per_peer,
                    selection.max_tracked_peers,
                )
                .with_row_cap(selection.mcp_row_cap)
                // One number across both doors: see
                // `SipnabMcp::max_inline_media_bytes`.
                .with_max_inline_media_bytes(
                    cli.output_args
                        .vcon_max_inline_media
                        .map(|mib| mib.saturating_mul(1024 * 1024)),
                )
                .with_body_cap(selection.mcp_body_cap)
                .with_findings_cap(selection.mcp_max_findings);
            let s = match cli.mcp_args.mcp_file_root.as_ref() {
                Some(dir) => s.with_file_root(dir),
                None => s,
            };
            let s = if cli.mcp_args.mcp_allow_shutdown {
                s.with_shutdown()
            } else {
                s
            };
            let s = if cli.mcp_args.mcp_allow_open_capture {
                s.with_open_capture()
            } else {
                s
            };
            let s = if cli.mcp_args.mcp_allow_tls_capture {
                s.with_tls_capture()
            } else {
                s
            };
            let s = if cli.mcp_args.mcp_allow_save_findings {
                s.with_save_findings()
            } else {
                s
            };
            let s = s.with_armed_detections(selection.armed_detections.iter().copied());
            match alerts {
                Some(a) => s.with_alert_engine(Arc::clone(a)),
                None => s,
            }
        };
        match cli.mcp_args.mcp_transport.as_str() {
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
                let bind_str = cli.mcp_args.mcp_bind.as_deref().unwrap_or("127.0.0.1:8731");
                let bind = crate::output::api::parse_bind_addr(bind_str)
                    .map_err(|e| anyhow::anyhow!("Invalid --mcp-bind address: {e}"))?;
                prepared.push(Prepared::McpHttp {
                    server: Box::new(new_server()),
                    bind,
                    auth: resolve_mcp_verifier_config(cli),
                    extra_allowed_hosts: cli.mcp_args.mcp_allowed_host.clone(),
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
            persistence_gate,
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
    if let Some(ref path) = cli.listener_args.api_signing_key_file {
        signing_keys.push(read_signing_key_file(path, "--api-signing-key-file"));
    }
    for k in &cli.listener_args.api_signing_key {
        if !k.is_empty() {
            signing_keys.push(k.as_bytes().to_vec());
        }
    }
    let static_keys: Vec<String> = cli
        .listener_args
        .api_key
        .iter()
        .filter(|k| !k.is_empty())
        .cloned()
        .collect();
    crate::auth::VerifierConfig {
        signing_keys,
        static_keys,
        revoked_file: cli
            .listener_args
            .api_revoked_file
            .as_ref()
            .map(std::path::PathBuf::from),
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
    if let Some(ref path) = cli.mcp_args.mcp_signing_key_file {
        signing_keys.push(read_signing_key_file(path, "--mcp-signing-key-file"));
    }
    for k in &cli.mcp_args.mcp_signing_key {
        if !k.is_empty() {
            signing_keys.push(k.as_bytes().to_vec());
        }
    }

    // Static secret: --mcp-token > --mcp-token-file > SIPNAB_MCP_TOKEN (env is
    // folded into --mcp-token by clap). Trim file contents.
    let mut static_keys: Vec<String> = Vec::new();
    if let Some(t) = cli.mcp_args.mcp_token.as_ref() {
        let t = t.trim();
        if !t.is_empty() {
            static_keys.push(t.to_string());
        }
    } else if let Some(path) = cli.mcp_args.mcp_token_file.as_ref() {
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
        revoked_file: cli
            .mcp_args
            .mcp_revoked_file
            .as_ref()
            .map(std::path::PathBuf::from),
        audience: crate::auth::AUDIENCE_MCP.to_string(),
    }
}
