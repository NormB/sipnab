//! Phase 8.1/8.2 — transports for the MCP server.
//!
//! Stdio mode (8.1) wires the JSON-RPC stream over `stdin`/`stdout`. HTTP
//! mode (8.2) mounts an axum service at `/mcp` and accepts Streamable-HTTP
//! requests; both modes share the same `SipnabMcp` server.
//!
//! # Stdio invariant (Gotcha 1)
//!
//! `stdout` is the protocol wire. Any `println!`/`eprintln!` or stray
//! non-tracing logging in this process would corrupt the protocol stream.
//! Phase 8.0b's tracing-subscriber initializer (`with_writer(stderr)`) is
//! the project-wide guarantee; the `tests/parse_path_test.rs` JSON
//! determinism check picks up regressions.
//!
//! # HTTP transport security (Gotcha 2)
//!
//! - Default bind is `127.0.0.1:8731` (D18 localhost-default).
//! - Non-loopback bind without bearer token is refused.
//! - Bearer tokens compared via constant-time comparison reusing
//!   `output::api::constant_time_eq`.

use super::server::SipnabMcp;
use rmcp::ServiceExt;

/// Run an MCP server over stdio. Returns when the client disconnects.
pub async fn serve_stdio(server: SipnabMcp) -> anyhow::Result<()> {
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(feature = "mcp-http")]
mod http {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::Router;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderMap, StatusCode};
    use axum::middleware::{self, Next};
    use axum::response::Response;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    use super::SipnabMcp;
    use crate::output::api::constant_time_eq;

    /// HTTP-server context passed through axum middleware.
    #[derive(Clone)]
    struct McpHttpState {
        /// Resolved bearer token. None means "no auth required" — only
        /// allowed when bind is loopback.
        token: Option<Arc<String>>,
    }

    /// Bearer-token guard. On loopback with no token configured the request
    /// passes; otherwise the `Authorization: Bearer` header is required and
    /// compared in constant time.
    async fn auth_layer(
        axum::extract::State(state): axum::extract::State<McpHttpState>,
        ConnectInfo(_addr): ConnectInfo<SocketAddr>,
        headers: HeaderMap,
        request: axum::extract::Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        if let Some(token) = state.token.as_deref() {
            let provided = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or(StatusCode::UNAUTHORIZED)?;
            if !constant_time_eq(provided.as_bytes(), token.as_bytes()) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Ok(next.run(request).await)
    }

    /// Run an MCP server over Streamable HTTP. Binds the listener inside the
    /// caller's tokio runtime, mounts `/mcp` plus `/health`, applies the
    /// bearer-token guard middleware, and serves until SIGINT/SIGTERM trips
    /// the shutdown flag.
    pub async fn serve_http(
        server: SipnabMcp,
        bind: SocketAddr,
        token: Option<String>,
    ) -> anyhow::Result<()> {
        // Refuse non-loopback bind without auth (D18 + 8.2 rule).
        if !bind.ip().is_loopback() && token.is_none() {
            anyhow::bail!(
                "MCP HTTP refuses to start: --mcp-bind {bind} is non-loopback \
                 but no --mcp-token / --mcp-token-file / SIPNAB_MCP_TOKEN was \
                 supplied. See D18 in the v6 plan."
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
            token: token.map(Arc::new),
        };

        let mcp_service: StreamableHttpService<SipnabMcp, LocalSessionManager> =
            StreamableHttpService::new(
                {
                    let server = server.clone();
                    move || Ok(server.clone())
                },
                session_mgr,
                StreamableHttpServerConfig::default(),
            );

        let mcp_router = Router::new()
            .nest_service("/mcp", mcp_service)
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer))
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
