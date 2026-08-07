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
///
/// # Shutdown
///
/// This function handles no signals, deliberately: it returns when the
/// transport ends, and the caller (`app::servers::Prepared::run`) then sets
/// `mcp_stdio_done`. Process exit is the batch loop's job, because the MCP
/// server shares the process with a capture that also has to be stopped.
///
/// That split is worth stating because it hid a leak. This function returning
/// was treated as "the process will now exit", and for a file capture it did:
/// the source drains, the packet loop ends, and the keep-alive loop sees the
/// flag. Under a LIVE capture the packet loop never ends on its own, so the
/// flag was set and nothing ever read it — every disconnected client left a
/// process behind, still capturing. The packet loop now checks the same flag
/// and requests shutdown; see `app::batch::run`.
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

    /// How the auth layer admitted this request — stamped into the request's
    /// extensions so the audit line in `call_tool` can attribute the call and
    /// the per-tool scope check can enforce it.
    ///
    /// The rmcp HTTP service folds the request's `http::request::Parts` into
    /// the per-request MCP `Extensions`, which is the only channel from this
    /// middleware to the tool dispatch layer. Without this stamp the audit
    /// log could name the socket but not whether a credential was presented —
    /// and "came from 10.0.0.9" and "proved it holds the token" are different
    /// claims. The distinction is recorded HERE because after this middleware
    /// returns, nothing downstream can re-derive it: the Authorization header
    /// is gone by design (never forwarded into tool code).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum McpAuth {
        /// A bearer token was presented and verified. `scope` is the claim
        /// the token carried ([`crate::auth::SCOPE_FULL`] when the payload
        /// omits it, and always `full` for static secrets, which carry no
        /// claims). Carried here because dispatch enforces it per TOOL — the
        /// middleware cannot, since the tool name is inside a JSON-RPC body
        /// it does not parse.
        BearerVerified {
            /// The verified token's scope claim.
            scope: String,
            /// The verified token's `id` claim, so the audit line can name
            /// WHICH credential made the call rather than only that one
            /// verified. `None` for a static shared secret, which carries no
            /// claims and so has no id — recorded as absent, never as a
            /// blank id that would read like a real one.
            ///
            /// Stamped here for the same reason `scope` is: after this
            /// middleware returns, the `Authorization` header is gone by
            /// design and nothing downstream can re-derive it.
            token_id: Option<String>,
        },
        /// No verifier is configured (loopback-only mode): the request was
        /// admitted without credentials. This is implicitly FULL access — the
        /// boundary there is network position (only a local process can reach
        /// the socket), and narrowing it would break every existing loopback
        /// deployment that has no tokens configured at all.
        Unauthenticated,
    }

    /// Bearer-token guard. On loopback with no auth configured the request
    /// passes; otherwise the `Authorization: Bearer` header is required and
    /// verified (signed token or static secret, constant-time).
    ///
    /// The guard admits ANY valid token for the MCP audience regardless of
    /// its scope, and stamps the accepted scope into the request. Scope is
    /// enforced per tool at dispatch (`call_tool`), not here: a read-scoped
    /// agent must still be able to initialize and list tools, and the tool
    /// name lives inside a JSON-RPC body this middleware never parses.
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
        mut request: axum::extract::Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        let auth = if state.verifier.is_unconfigured() {
            McpAuth::Unauthenticated
        } else {
            let provided = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or(StatusCode::UNAUTHORIZED)?;
            let accepted = state
                .verifier
                .verify_claims(provided, chrono::Utc::now().timestamp())
                .ok_or(StatusCode::UNAUTHORIZED)?;
            McpAuth::BearerVerified {
                scope: accepted.scope,
                token_id: accepted.id,
            }
        };
        // Stamped AFTER the reject paths: a request that reaches the tools
        // always carries exactly one admission record, and a rejected one
        // never does.
        request.extensions_mut().insert(auth);
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

    /// Middleware-level tests for `auth_layer`: what gets admitted, what gets
    /// 401, and — the part dispatch depends on — exactly what admission
    /// record is stamped into the request. Driven with `oneshot` requests
    /// against a probe route that echoes the stamp back, so the assertions
    /// are on the record downstream code actually receives, not on the
    /// middleware's internals.
    #[cfg(test)]
    mod tests {
        use super::*;
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        /// Test signing key shared between minting and the router's verifier.
        const KEY: &[u8] = b"transport-test-signing-key-0123";

        /// Echo the stamped admission record, so tests assert on what a
        /// downstream consumer would actually see.
        ///
        /// A token id renders as a third segment, and a credential that has
        /// none renders as two — the same rule the audit line follows, so a
        /// build that stamped a blank id could not pass by looking absent.
        async fn probe(axum::Extension(auth): axum::Extension<McpAuth>) -> String {
            match auth {
                McpAuth::BearerVerified {
                    scope,
                    token_id: Some(id),
                } => format!("bearer:{scope}:{id}"),
                McpAuth::BearerVerified {
                    scope,
                    token_id: None,
                } => format!("bearer:{scope}"),
                McpAuth::Unauthenticated => "unauthenticated".to_string(),
            }
        }

        /// A probe router behind `auth_layer` with the given verifier config.
        fn router(config: VerifierConfig) -> Router {
            let state = McpHttpState {
                verifier: Arc::new(TokenVerifier::new(config)),
            };
            Router::new()
                .route("/probe", axum::routing::get(probe))
                .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer))
                .with_state(state)
        }

        /// A GET /probe request with an optional bearer token.
        fn probe_request(bearer: Option<&str>) -> Request<Body> {
            let mut builder = Request::builder().uri("/probe");
            if let Some(token) = bearer {
                builder =
                    builder.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
            }
            builder.body(Body::empty()).expect("build request")
        }

        /// Collect a response body into a UTF-8 string.
        async fn body_string(resp: Response) -> String {
            let bytes = resp
                .into_body()
                .collect()
                .await
                .expect("collect body")
                .to_bytes();
            String::from_utf8(bytes.to_vec()).expect("utf8")
        }

        /// A `read`-scoped token is ADMITTED and stamped with its scope AND
        /// the id it was minted with.
        ///
        /// This is the middleware half of per-tool scoping: the old guard
        /// demanded `full` from every request, so a read token could not even
        /// initialize. Admission and authorization are now different layers —
        /// the middleware proves the credential, dispatch decides per tool.
        ///
        /// The id rides along because this is the last place it exists: the
        /// `Authorization` header is never forwarded past this layer, so a
        /// stamp that drops the id leaves the audit record unable to say which
        /// credential made the call.
        #[tokio::test]
        async fn a_read_scoped_token_is_admitted_and_stamped_with_its_scope_and_id() {
            let app = router(VerifierConfig {
                signing_keys: vec![KEY.to_vec()],
                audience: crate::auth::AUDIENCE_MCP.to_string(),
                ..Default::default()
            });
            let token = crate::auth::mint(
                KEY,
                "agent",
                chrono::Utc::now().timestamp() + 3600,
                crate::auth::AUDIENCE_MCP,
                crate::auth::SCOPE_READ,
            );
            let resp = app
                .oneshot(probe_request(Some(&token)))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(body_string(resp).await, "bearer:read:agent");
        }

        /// A full token (which omits the scope claim) and a static secret
        /// (which cannot carry one) both stamp `full` — and they differ on the
        /// id: the token names itself, the static secret has none to name.
        #[tokio::test]
        async fn full_tokens_and_static_secrets_stamp_full() {
            let app = router(VerifierConfig {
                signing_keys: vec![KEY.to_vec()],
                static_keys: vec!["legacy-static".to_string()],
                audience: crate::auth::AUDIENCE_MCP.to_string(),
                ..Default::default()
            });
            let token = crate::auth::mint(
                KEY,
                "ops",
                chrono::Utc::now().timestamp() + 3600,
                crate::auth::AUDIENCE_MCP,
                crate::auth::SCOPE_FULL,
            );
            let resp = app
                .clone()
                .oneshot(probe_request(Some(&token)))
                .await
                .expect("oneshot");
            assert_eq!(body_string(resp).await, "bearer:full:ops");

            let resp = app
                .oneshot(probe_request(Some("legacy-static")))
                .await
                .expect("oneshot");
            assert_eq!(
                body_string(resp).await,
                "bearer:full",
                "a static secret carries no claims, so it stamps no id — the \
                 absence is the record, not a blank one"
            );
        }

        /// With a verifier configured, a missing or invalid token is 401 and
        /// the probe never runs — no admission record is ever stamped on a
        /// rejected request.
        #[tokio::test]
        async fn missing_or_invalid_tokens_are_rejected_before_the_stamp() {
            let app = router(VerifierConfig {
                signing_keys: vec![KEY.to_vec()],
                audience: crate::auth::AUDIENCE_MCP.to_string(),
                ..Default::default()
            });
            let resp = app
                .clone()
                .oneshot(probe_request(None))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

            let resp = app
                .oneshot(probe_request(Some("not-a-real-token")))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        /// With no verifier configured (loopback-only mode), the request is
        /// admitted and stamped `Unauthenticated` — which dispatch treats as
        /// full access, because the boundary there is network position.
        #[tokio::test]
        async fn unconfigured_verifier_stamps_unauthenticated() {
            let app = router(VerifierConfig::default());
            let resp = app.oneshot(probe_request(None)).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(body_string(resp).await, "unauthenticated");
        }
    }
}

#[cfg(feature = "mcp-http")]
pub(crate) use http::McpAuth;
#[cfg(feature = "mcp-http")]
pub use http::serve_http;
