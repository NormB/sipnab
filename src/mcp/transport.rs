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
//!
//! # Discovery (RFC 9728 / RFC 6750)
//!
//! Every `401` carries a `WWW-Authenticate: Bearer` challenge, and — when
//! `--mcp-resource-url` names the public URL — a `resource_metadata` parameter
//! pointing at an OAuth 2.0 protected-resource metadata document served
//! unauthenticated at the well-known path.
//!
//! Discovery only. sipnab neither issues nor validates OAuth access tokens: it
//! verifies its own HMAC and static bearer tokens exactly as it always has, and
//! the metadata document deliberately advertises no `authorization_servers`,
//! because a client that followed one would come back holding a token this
//! server cannot accept.

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
    use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
    use axum::middleware::{self, Next};
    use axum::response::{IntoResponse, Response};
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    use super::SipnabMcp;
    use crate::auth::{TokenVerifier, VerifierConfig};

    /// The well-known URI path suffix RFC 9728 §3 registers for OAuth 2.0
    /// protected-resource metadata, with its leading `/.well-known/`.
    ///
    /// Not configurable. §3 permits an application to register its own suffix,
    /// but also says the default "is the right choice for general-purpose OAuth
    /// protected resources", and a client that has to be told which suffix to
    /// try has learned nothing discovery did not already owe it.
    const WELL_KNOWN_PREFIX: &str = "/.well-known/oauth-protected-resource";

    /// The protection space named in every challenge (RFC 9110 §11.5).
    ///
    /// A constant, and deliberately uninformative: the realm is echoed to an
    /// unauthenticated caller, so it names the program and nothing about the
    /// deployment, the capture, or the credential.
    const REALM: &str = "sipnab";

    /// RFC 6750 §3.1 error code for a credential that was presented and failed
    /// verification — expired, revoked, forged, or minted for the other
    /// audience. One code for all of them on purpose: telling an attacker
    /// *which* turns the challenge into an oracle.
    const ERROR_INVALID_TOKEN: &str = "invalid_token";

    /// Human-readable companion to [`ERROR_INVALID_TOKEN`] (RFC 6750 §3.1
    /// `error_description`, US-ASCII). Constant, so it can carry no detail
    /// about the presented token.
    const ERROR_DESCRIPTION: &str = "The access token is invalid or has expired";

    /// The public identity of this MCP server, as an OAuth 2.0 protected
    /// resource (RFC 9728).
    ///
    /// Built once at startup from `--mcp-resource-url` so a malformed value is
    /// a startup failure rather than a per-request surprise, and so the derived
    /// strings — the well-known path, the absolute metadata URL, the
    /// `WWW-Authenticate` parameter — are computed from the identifier exactly
    /// once. They are three renderings of one fact, and deriving each at its
    /// own call site is how they would come to disagree.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ProtectedResource {
        /// RFC 9728 `resource`: the normalized resource identifier, with any
        /// terminating slash removed per §3.1.
        resource: String,
        /// Path the metadata document is published at, e.g.
        /// `/.well-known/oauth-protected-resource/mcp`.
        path: String,
        /// Absolute URL of that document — the `resource_metadata` value
        /// RFC 9728 §5.1 puts in the challenge.
        metadata_url: String,
    }

    impl ProtectedResource {
        /// Validate a public URL and derive the RFC 9728 identifiers from it.
        ///
        /// # Arguments
        ///
        /// * `raw` — the `--mcp-resource-url` value: the absolute URL clients
        ///   reach this server at, e.g. `https://sipnab.example.com/mcp`.
        ///
        /// # Errors
        ///
        /// Rejects anything that is not an absolute `http`/`https` URL, and
        /// anything carrying userinfo, a query, or a fragment — none of which
        /// a resource identifier has any use for, and each of which would make
        /// the derived well-known path ambiguous. The path is held to an
        /// unreserved-character charset for the same reason: the derived route
        /// is registered verbatim with axum, whose path syntax gives `{`, `}`
        /// and `*` their own meaning.
        ///
        /// Also rejects a value whose challenge parameter would not be a legal
        /// header value. That check cannot fire given the rules above, which is
        /// exactly why it is here rather than assumed: it fails at startup if
        /// one of them is ever loosened.
        pub fn parse(raw: &str) -> anyhow::Result<Self> {
            // Checked before parsing rather than after: `http::Uri` treats a
            // fragment as part of the path, so `https://h/mcp#x` would
            // otherwise reach the charset check and be reported as a bad path
            // character instead of as the thing it is.
            if raw.contains('#') {
                anyhow::bail!(
                    "--mcp-resource-url {raw:?}: a resource identifier carries \
                     no fragment"
                );
            }
            let uri: Uri = raw
                .parse()
                .map_err(|e| anyhow::anyhow!("--mcp-resource-url {raw:?}: {e}"))?;
            let Some(scheme) = uri.scheme_str() else {
                anyhow::bail!(
                    "--mcp-resource-url {raw:?}: must be an absolute URL \
                     including the scheme, e.g. https://sipnab.example.com/mcp"
                );
            };
            if !matches!(scheme, "http" | "https") {
                anyhow::bail!("--mcp-resource-url {raw:?}: scheme must be http or https");
            }
            let Some(authority) = uri.authority() else {
                anyhow::bail!("--mcp-resource-url {raw:?}: must name a host");
            };
            if authority.as_str().contains('@') {
                anyhow::bail!(
                    "--mcp-resource-url {raw:?}: a resource identifier carries \
                     no credentials"
                );
            }
            if uri.query().is_some() {
                anyhow::bail!("--mcp-resource-url {raw:?}: a resource identifier carries no query");
            }
            // RFC 9728 §3.1: "any terminating slash (/) following the host
            // component MUST be removed before inserting /.well-known/".
            let path = uri.path().trim_end_matches('/');
            let ok = path.is_empty()
                || path.split('/').skip(1).all(|seg| {
                    !seg.is_empty()
                        && seg
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
                });
            if !ok {
                anyhow::bail!(
                    "--mcp-resource-url {raw:?}: path segments must be \
                     non-empty and use only letters, digits, '-', '.' and '_'"
                );
            }
            let origin = format!("{scheme}://{}", authority.as_str().to_ascii_lowercase());
            let resource = format!("{origin}{path}");
            let metadata_path = format!("{WELL_KNOWN_PREFIX}{path}");
            let metadata_url = format!("{origin}{metadata_path}");
            let probe = Self {
                resource,
                path: metadata_path,
                metadata_url,
            };
            HeaderValue::from_str(&probe.challenge_with(None)).map_err(|e| {
                anyhow::anyhow!("--mcp-resource-url {raw:?}: unusable in a challenge header: {e}")
            })?;
            Ok(probe)
        }

        /// The metadata document RFC 9728 §2 describes, as JSON.
        ///
        /// Served unauthenticated, so the interesting question is what it
        /// leaves out. It names no bind address, no `Host` allowlist, no token,
        /// no signing-key material, no capture and no version — nothing an
        /// unauthenticated caller could not already state itself, except the
        /// scope names, which §7.2 exists to permit ("the list of scopes the
        /// resource server is willing to disclose that it supports").
        ///
        /// `authorization_servers` is absent, and its absence is a decision
        /// rather than an omission: §2 makes the field OPTIONAL precisely for
        /// resources whose authorization servers "will not be enumerable", and
        /// sipnab has none — it validates its own bearer tokens, so a client
        /// sent to fetch one elsewhere would return holding a credential this
        /// server rejects.
        fn document(&self) -> serde_json::Value {
            serde_json::json!({
                "resource": self.resource,
                "resource_name": "sipnab MCP server",
                "scopes_supported": [crate::auth::SCOPE_FULL, crate::auth::SCOPE_READ],
                "bearer_methods_supported": ["header"],
                "resource_documentation": "https://sipnab.com/docs/mcp-deploy/",
            })
        }

        /// The `WWW-Authenticate` value for this resource, with an optional
        /// RFC 6750 error code.
        fn challenge_with(&self, error: Option<&str>) -> String {
            format!(
                "{}, resource_metadata=\"{}\"",
                bare_challenge(error),
                self.metadata_url
            )
        }
    }

    /// The `WWW-Authenticate` value used when no resource identifier is
    /// configured.
    ///
    /// Still a complete challenge: RFC 9110 §15.5.2 makes the header mandatory
    /// on any 401, and RFC 6750 §3 requires the `Bearer` scheme to be "followed
    /// by one or more auth-param values" — so `realm` is emitted even when
    /// there is nothing to discover. RFC 6750 §3.1 is why `error` is optional
    /// here rather than always present: a request that "lacks any
    /// authentication information" SHOULD NOT be answered with an error code.
    fn bare_challenge(error: Option<&str>) -> String {
        match error {
            Some(code) => {
                format!(
                    "Bearer realm=\"{REALM}\", error=\"{code}\", \
                     error_description=\"{ERROR_DESCRIPTION}\""
                )
            }
            None => format!("Bearer realm=\"{REALM}\""),
        }
    }

    /// HTTP-server context passed through axum middleware.
    #[derive(Clone)]
    struct McpHttpState {
        /// Bearer-token verifier (signed tokens + static secrets + revocation).
        /// When unconfigured (no signing keys, no static secret) auth is
        /// disabled — only allowed when bind is loopback.
        verifier: Arc<TokenVerifier>,
        /// Public identity published for discovery, when `--mcp-resource-url`
        /// supplied one. `None` narrows the challenge to `realm` and mounts no
        /// well-known route.
        resource: Option<Arc<ProtectedResource>>,
    }

    impl McpHttpState {
        /// A `401` carrying the challenge this deployment can honestly make.
        ///
        /// Built here rather than at the two rejection sites so that the reject
        /// paths cannot drift apart: whichever one fires, the response differs
        /// only in the RFC 6750 error code.
        fn unauthorized(&self, error: Option<&str>) -> Response {
            let value = match &self.resource {
                Some(r) => r.challenge_with(error),
                None => bare_challenge(error),
            };
            // Infallible for every value this builds — `REALM`, the error
            // constants and a `ProtectedResource` are all validated ASCII — and
            // a challenge that could not be rendered must still leave a 401
            // rather than fall through to the handler.
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            if let Ok(header) = HeaderValue::from_str(&value) {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, header);
            }
            resp
        }
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
    ///
    /// Every rejection carries a `WWW-Authenticate` challenge, and the two
    /// rejections are told apart the way RFC 6750 §3.1 tells them apart: a
    /// request with no bearer credentials at all "lacks any authentication
    /// information" and SHOULD NOT be answered with an error code, while one
    /// that presented a token which failed verification is `invalid_token`.
    /// Both are still `401`, and both still admit nothing.
    async fn auth_layer(
        axum::extract::State(state): axum::extract::State<McpHttpState>,
        headers: HeaderMap,
        mut request: axum::extract::Request,
        next: Next,
    ) -> Response {
        let auth = if state.verifier.is_unconfigured() {
            McpAuth::Unauthenticated
        } else {
            let Some(provided) = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
            else {
                return state.unauthorized(None);
            };
            let Some(accepted) = state
                .verifier
                .verify_claims(provided, chrono::Utc::now().timestamp())
            else {
                return state.unauthorized(Some(ERROR_INVALID_TOKEN));
            };
            McpAuth::BearerVerified {
                scope: accepted.scope,
                token_id: accepted.id,
            }
        };
        // Stamped AFTER the reject paths: a request that reaches the tools
        // always carries exactly one admission record, and a rejected one
        // never does.
        request.extensions_mut().insert(auth);
        next.run(request).await
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
    /// * `resource` — the validated `--mcp-resource-url`, when one was given.
    ///   `Some` mounts the RFC 9728 metadata document and adds
    ///   `resource_metadata` to every challenge; `None` leaves both off.
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
        resource: Option<ProtectedResource>,
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
            resource: resource.map(Arc::new),
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

        let mut mcp_router = Router::new()
            .nest_service("/mcp", mcp_service)
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer));

        // The metadata document is UNAUTHENTICATED by design — a client fetches
        // it precisely because it does not yet hold a credential (RFC 9728 §5,
        // steps 2-4). That is why it is registered HERE and not above: axum
        // applies `route_layer` only to routes declared before the call, so
        // this line's POSITION is the whole of the exemption. Moving it up
        // would put the bearer guard back in front of the one document whose
        // purpose is to be readable without one; moving `route_layer` down
        // would strip the guard from `/mcp` and `/health` instead, and both
        // mistakes look like working code.
        if let Some(r) = &state.resource {
            // Serialized once. The document is a constant for the lifetime of
            // the process — every field comes from startup configuration — so
            // re-rendering it per request would only add a way for two
            // responses to differ.
            let body = serde_json::to_string(&r.document())
                .map_err(|e| anyhow::anyhow!("protected-resource metadata is not JSON: {e}"))?;
            tracing::info!(
                "MCP HTTP publishing OAuth protected-resource metadata for {} at {}",
                r.resource,
                r.path
            );
            mcp_router = mcp_router.route(
                &r.path,
                axum::routing::get(move || {
                    let body = body.clone();
                    // RFC 9728 §3.2: "a JSON object using the application/json
                    // content type".
                    async move {
                        (
                            [(
                                axum::http::header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            )],
                            body,
                        )
                    }
                }),
            );
        }

        let mcp_router = mcp_router
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

        /// A probe router behind `auth_layer` with the given verifier config
        /// and no published resource identifier.
        fn router(config: VerifierConfig) -> Router {
            router_with(config, None)
        }

        /// A probe router behind `auth_layer` with an optional published
        /// resource identifier, so the challenge can be inspected both ways.
        fn router_with(config: VerifierConfig, resource: Option<ProtectedResource>) -> Router {
            let state = McpHttpState {
                verifier: Arc::new(TokenVerifier::new(config)),
                resource: resource.map(Arc::new),
            };
            Router::new()
                .route("/probe", axum::routing::get(probe))
                .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer))
                .with_state(state)
        }

        /// The `WWW-Authenticate` value of a response, or `""` when absent.
        ///
        /// Absent renders as the empty string rather than panicking so a
        /// failing assertion reports what the challenge WAS — "expected
        /// `Bearer …`, got `\"\"`" locates a missing header, where a panic
        /// inside the helper only says the helper ran.
        fn challenge_of(resp: &Response) -> String {
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
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

        /// A verifier config that requires a token, for the challenge tests.
        fn guarded() -> VerifierConfig {
            VerifierConfig {
                signing_keys: vec![KEY.to_vec()],
                audience: crate::auth::AUDIENCE_MCP.to_string(),
                ..Default::default()
            }
        }

        /// RFC 9728 §3.1's two worked examples, verbatim.
        ///
        /// The spec gives the answers, so this asserts against THEM rather
        /// than against the derivation: `https://resource.example.com` is
        /// queried at `GET /.well-known/oauth-protected-resource` and
        /// `https://resource.example.com/resource1` at
        /// `GET /.well-known/oauth-protected-resource/resource1`.
        #[test]
        fn the_rfc9728_worked_examples_derive_the_paths_the_rfc_prints() {
            let bare = ProtectedResource::parse("https://resource.example.com").expect("parse");
            assert_eq!(bare.path, "/.well-known/oauth-protected-resource");
            assert_eq!(bare.resource, "https://resource.example.com");
            assert_eq!(
                bare.metadata_url,
                "https://resource.example.com/.well-known/oauth-protected-resource"
            );

            let with_path =
                ProtectedResource::parse("https://resource.example.com/resource1").expect("parse");
            assert_eq!(
                with_path.path,
                "/.well-known/oauth-protected-resource/resource1"
            );
            assert_eq!(with_path.resource, "https://resource.example.com/resource1");
        }

        /// §3.1: "any terminating slash (/) following the host component MUST
        /// be removed before inserting /.well-known/". Both the identifier and
        /// the derived path have to lose it, and a slash after a real path
        /// segment is the case that would otherwise leave an empty segment in
        /// the middle of the route.
        #[test]
        fn a_terminating_slash_is_removed_before_the_well_known_insert() {
            for (raw, resource, path) in [
                (
                    "https://resource.example.com/",
                    "https://resource.example.com",
                    "/.well-known/oauth-protected-resource",
                ),
                (
                    "https://resource.example.com/mcp/",
                    "https://resource.example.com/mcp",
                    "/.well-known/oauth-protected-resource/mcp",
                ),
            ] {
                let r = ProtectedResource::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
                assert_eq!(r.resource, resource, "{raw}");
                assert_eq!(r.path, path, "{raw}");
            }
        }

        /// The scheme and host are normalized to lowercase, so the identifier
        /// this server publishes is the canonical form a client compares
        /// against (RFC 9728 §6 string operations; the MCP canonical-URI rules
        /// say the same).
        #[test]
        fn the_identifier_is_normalized_to_lowercase_scheme_and_host() {
            let r = ProtectedResource::parse("HTTPS://Resource.Example.COM:8443/MCP")
                .expect("parse mixed case");
            assert_eq!(r.resource, "https://resource.example.com:8443/MCP");
            assert_eq!(r.path, "/.well-known/oauth-protected-resource/MCP");
        }

        /// Every value that cannot become a resource identifier is a startup
        /// error, one message per reason.
        ///
        /// The path charset is in here because the derived path is registered
        /// with axum verbatim: `{` and `*` are axum route syntax, so a value
        /// carrying them would silently become a wildcard route rather than a
        /// document.
        #[test]
        fn a_value_that_cannot_be_a_resource_identifier_is_rejected() {
            for raw in [
                "sipnab.example.com/mcp",           // no scheme
                "/mcp",                             // relative
                "ftp://sipnab.example.com/mcp",     // wrong scheme
                "https://user:pw@sipnab.test/mcp",  // userinfo
                "https://sipnab.test/mcp?tenant=1", // query
                "https://sipnab.test/mcp#frag",     // fragment
                "https://sipnab.test/{tenant}",     // axum route syntax
                "https://sipnab.test/a//b",         // empty segment
                "https://sipnab.test/a b",          // space
            ] {
                assert!(
                    ProtectedResource::parse(raw).is_err(),
                    "{raw:?} must be rejected as a resource identifier"
                );
            }
        }

        /// The published document carries what RFC 9728 §2 asks of it and
        /// nothing that would betray the deployment.
        ///
        /// `resource` is REQUIRED; `scopes_supported` is RECOMMENDED and is
        /// read from the `auth` scope constants rather than spelled again here,
        /// so a renamed scope cannot leave the document advertising the old
        /// name. `authorization_servers` is absent on purpose — see
        /// [`ProtectedResource::document`].
        #[test]
        fn the_document_carries_the_required_fields_and_no_authorization_server() {
            let doc = ProtectedResource::parse("https://sipnab.example.com/mcp")
                .expect("parse")
                .document();
            assert_eq!(doc["resource"], "https://sipnab.example.com/mcp");
            assert_eq!(
                doc["scopes_supported"],
                serde_json::json!([crate::auth::SCOPE_FULL, crate::auth::SCOPE_READ])
            );
            assert_eq!(
                doc["bearer_methods_supported"],
                serde_json::json!(["header"])
            );
            assert!(
                doc.get("authorization_servers").is_none(),
                "sipnab validates no OAuth tokens, so it advertises no \
                 authorization server: {doc}"
            );
            assert!(
                doc.get("jwks_uri").is_none() && doc.get("signed_metadata").is_none(),
                "nothing here is keyed or signed: {doc}"
            );
        }

        /// The challenge on a request that presented nothing, with and without
        /// a published identifier.
        ///
        /// RFC 6750 §3 requires at least one auth-param, which is why `realm`
        /// survives the unconfigured case; §3.1 is why neither carries an
        /// error code.
        #[tokio::test]
        async fn a_credential_less_request_is_challenged_without_an_error_code() {
            let app = router(guarded());
            let resp = app.oneshot(probe_request(None)).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenge_of(&resp), "Bearer realm=\"sipnab\"");

            let app = router_with(
                guarded(),
                Some(ProtectedResource::parse("https://sipnab.example.com/mcp").expect("parse")),
            );
            let resp = app.oneshot(probe_request(None)).await.expect("oneshot");
            assert_eq!(
                challenge_of(&resp),
                "Bearer realm=\"sipnab\", resource_metadata=\"https://sipnab.example.com/.well-known/oauth-protected-resource/mcp\""
            );
        }

        /// A presented-but-rejected credential is `invalid_token`, and the
        /// description says nothing about WHY.
        ///
        /// An expired token, a revoked one, a forgery and one minted for the
        /// REST API audience must be indistinguishable from the outside: the
        /// challenge is the one thing an attacker gets back for free, and a
        /// challenge that differentiated them would answer "is this id known?"
        /// and "has this key ever signed?" for anyone who asked.
        #[tokio::test]
        async fn every_rejected_credential_gets_the_same_invalid_token_challenge() {
            let app = router(guarded());
            let now = chrono::Utc::now().timestamp();
            let expired = crate::auth::mint(
                KEY,
                "old",
                now - 1,
                crate::auth::AUDIENCE_MCP,
                crate::auth::SCOPE_FULL,
            );
            let wrong_audience = crate::auth::mint(
                KEY,
                "api-side",
                now + 3600,
                crate::auth::AUDIENCE_API,
                crate::auth::SCOPE_FULL,
            );
            let forged = crate::auth::mint(
                b"a-completely-different-signing-key",
                "forged",
                now + 3600,
                crate::auth::AUDIENCE_MCP,
                crate::auth::SCOPE_FULL,
            );
            for token in ["not-a-token", &expired, &wrong_audience, &forged] {
                let resp = app
                    .clone()
                    .oneshot(probe_request(Some(token)))
                    .await
                    .expect("oneshot");
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{token}");
                assert_eq!(
                    challenge_of(&resp),
                    "Bearer realm=\"sipnab\", error=\"invalid_token\", \
                     error_description=\"The access token is invalid or has expired\"",
                    "{token}: every rejection must look identical"
                );
            }
        }

        /// An `Authorization` header in some other scheme is "lacks any
        /// authentication information", not a bad token.
        ///
        /// RFC 6750 §3.1 puts an unsupported authentication method in the same
        /// bucket as no credentials at all, and it matters here because a
        /// `Basic` header is what a browser or a misconfigured proxy sends —
        /// answering it with `invalid_token` would tell the operator to go look
        /// at a token that was never presented.
        #[tokio::test]
        async fn a_non_bearer_authorization_header_is_challenged_as_credential_less() {
            let app = router(guarded());
            let request = Request::builder()
                .uri("/probe")
                .header(axum::http::header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .body(Body::empty())
                .expect("build request");
            let resp = app.oneshot(request).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenge_of(&resp), "Bearer realm=\"sipnab\"");
        }

        /// Publishing a document does not add a challenge to a response that
        /// was never a rejection: an admitted request stays clean.
        #[tokio::test]
        async fn an_admitted_request_carries_no_challenge() {
            let app = router_with(
                guarded(),
                Some(ProtectedResource::parse("https://sipnab.example.com/mcp").expect("parse")),
            );
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
            assert_eq!(challenge_of(&resp), "");
        }
    }
}

#[cfg(feature = "mcp-http")]
pub(crate) use http::McpAuth;
#[cfg(feature = "mcp-http")]
pub use http::{ProtectedResource, serve_http};
