// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transports for the MCP server.
//!
//! Stdio mode wires the JSON-RPC stream over `stdin`/`stdout`. HTTP mode
//! mounts an axum service at `/mcp` and accepts Streamable-HTTP requests;
//! both modes share the same `SipnabMcp` server.
//!
//! # Stdio invariant (Gotcha 1)
//!
//! `stdout` is the protocol wire. Any `println!`/`eprintln!` or stray
//! non-tracing logging in this process would corrupt the protocol stream.
//! The tracing-subscriber initializer in `app::bootstrap::init_logging`
//! (`with_writer(stderr)`) is the project-wide guarantee; the
//! `tests/parse_path_test.rs` JSON determinism check picks up regressions.
//!
//! # HTTP transport security (Gotcha 2)
//!
//! - Default bind is `127.0.0.1:8731` (D18 localhost-default).
//! - Non-loopback bind without bearer token is refused.
//! - Bearer tokens verified via `auth::TokenVerifier` (signed `s1.` tokens
//!   with expiry/rotation/revocation, plus constant-time static-secret
//!   fallback).

use super::server::SipnabMcp;
use rmcp::ServiceExt;

/// Run an MCP server over stdio. Returns when the client disconnects.
///
/// # Arguments
///
/// * `server` — the fully-configured tool server to expose.
///
/// # Errors
///
/// Propagates rmcp transport errors from the initial handshake
/// (`serve`) or from the serving task (`waiting`).
///
/// # Side effects
///
/// Takes over the process's `stdin`/`stdout` as the JSON-RPC wire and
/// reads/writes them until the client closes stdin — nothing else in the
/// process may print to stdout while this runs.
pub async fn serve_stdio(server: SipnabMcp) -> anyhow::Result<()> {
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}

/// Streamable-HTTP transport: axum router, bearer-token guard middleware,
/// and the `serve_http` entry point re-exported at the module root.
#[cfg(feature = "mcp-http")]
mod http {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::Router;
    use axum::http::{HeaderMap, StatusCode};
    use axum::middleware::{self, Next};
    use axum::response::Response;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    use super::SipnabMcp;
    use crate::auth::{TokenVerifier, VerifierConfig};

    /// HTTP-server context passed through axum middleware.
    #[derive(Clone)]
    struct McpHttpState {
        /// Bearer-token verifier (signed tokens + static secrets + revocation).
        /// When unconfigured (no signing keys, no static secret) auth is
        /// disabled — only allowed when bind is loopback.
        verifier: Arc<TokenVerifier>,
    }

    /// Bearer-token guard. On loopback with no auth configured the request
    /// passes; otherwise the `Authorization: Bearer` header is required and
    /// verified (signed token or static secret, constant-time).
    ///
    /// # Arguments
    ///
    /// * `state` — shared verifier state installed on the router.
    /// * `headers` — request headers searched for `Authorization: Bearer`.
    /// * `request` / `next` — the guarded request and the rest of the
    ///   middleware chain.
    ///
    /// # Returns
    ///
    /// The downstream response on success; `401 UNAUTHORIZED` when a token
    /// is required but missing, malformed, expired, or revoked.
    async fn auth_layer(
        axum::extract::State(state): axum::extract::State<McpHttpState>,
        headers: HeaderMap,
        request: axum::extract::Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        if !state.verifier.is_unconfigured() {
            let provided = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or(StatusCode::UNAUTHORIZED)?;
            if !state
                .verifier
                .verify(provided, chrono::Utc::now().timestamp())
            {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Ok(next.run(request).await)
    }

    /// Run an MCP server over Streamable HTTP. Binds the listener inside the
    /// caller's tokio runtime, mounts `/mcp` plus `/health`, applies the
    /// bearer-token guard middleware, and serves until SIGINT/SIGTERM trips
    /// the shutdown flag.
    ///
    /// # Arguments
    ///
    /// * `server` — the tool server; cloned per HTTP session.
    /// * `bind` — socket address to listen on (default `127.0.0.1:8731`).
    /// * `auth_config` — signing keys / static secrets for the bearer guard;
    ///   unconfigured auth is only accepted on a loopback bind.
    /// * `extra_allowed_hosts` — `--mcp-allowed-host` additions to rmcp's
    ///   default Host-header allowlist; a literal `*` disables the check.
    ///
    /// # Errors
    ///
    /// Fails when the bind is non-loopback with no auth configured, when the
    /// TCP listener cannot bind, or when axum's serve loop errors.
    ///
    /// # Side effects
    ///
    /// Binds and owns a TCP listener, serves HTTP until shutdown, logs the
    /// effective bind address and Host allowlist, caps request bodies at
    /// 2 MiB, and polls the process-wide shutdown flag every 200 ms for
    /// graceful termination.
    pub async fn serve_http(
        server: SipnabMcp,
        bind: SocketAddr,
        auth_config: VerifierConfig,
        extra_allowed_hosts: Vec<String>,
    ) -> anyhow::Result<()> {
        // Refuse non-loopback bind without auth (D18 + 8.2 rule).
        if !bind.ip().is_loopback() && auth_config.is_unconfigured() {
            anyhow::bail!(
                "MCP HTTP refuses to start: --mcp-bind {bind} is non-loopback \
                 but no --mcp-token / --mcp-token-file / SIPNAB_MCP_TOKEN / \
                 --mcp-signing-key / --mcp-signing-key-file / \
                 SIPNAB_MCP_SIGNING_KEY was supplied. See D18 in the v6 plan."
            );
        }
        if !bind.ip().is_loopback() {
            tracing::warn!(
                "MCP HTTP bound non-loopback ({bind}) without TLS — terminate \
                 TLS in nginx and apply a source-IP allowlist there."
            );
        }

        let session_mgr = Arc::new(LocalSessionManager::default());
        let state = McpHttpState {
            verifier: Arc::new(TokenVerifier::new(auth_config)),
        };

        // Apply --mcp-allowed-host overrides on top of rmcp's defaults
        // (`localhost`, `127.0.0.1`, `::1`). A single literal `*` entry
        // disables host checking entirely.
        let mut http_config = StreamableHttpServerConfig::default();
        if extra_allowed_hosts.iter().any(|h| h == "*") {
            tracing::warn!(
                "MCP HTTP host-header check disabled via --mcp-allowed-host '*' \
                 — pair this with a network-level source-IP allowlist."
            );
            http_config.allowed_hosts.clear();
        } else {
            for host in extra_allowed_hosts {
                http_config.allowed_hosts.push(host);
            }
        }
        tracing::info!(
            "MCP HTTP allowed Host headers: {:?}",
            http_config.allowed_hosts
        );

        let mcp_service: StreamableHttpService<SipnabMcp, LocalSessionManager> =
            StreamableHttpService::new(
                {
                    let server = server.clone();
                    move || Ok(server.clone())
                },
                session_mgr,
                http_config,
            );

        let mcp_router = Router::new()
            .nest_service("/mcp", mcp_service)
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer))
            // Cap the JSON-RPC request body so an oversized POST can't exhaust
            // memory. No blanket request timeout here: the streamable-HTTP
            // transport keeps long-lived connections for server-sent events.
            .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(bind).await?;
        let actual = listener.local_addr().unwrap_or(bind);
        tracing::info!("MCP HTTP server listening on {actual}");
        axum::serve(
            listener,
            mcp_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Poll the project-wide shutdown flag.
            while !crate::signals::shutdown_requested() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        })
        .await?;
        Ok(())
    }
}

#[cfg(feature = "mcp-http")]
pub use http::serve_http;
