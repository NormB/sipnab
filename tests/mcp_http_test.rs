// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(unix, feature = "mcp-http"))]
//! Phase 8.2 — end-to-end HTTP MCP integration test.
//!
//! Spawns `sipnab --mcp --mcp-transport http --mcp-bind 127.0.0.1:0` against
//! a fixture pcap, then issues HTTP JSON-RPC requests to verify:
//! - non-loopback bind without token is refused
//! - missing/invalid bearer token returns 401
//! - valid token round-trips initialize → tools/list

#[path = "support/mcp.rs"]
mod mcp;

use mcp::{post_json, shutdown, spawn_http};

/// Binding `0.0.0.0` without `--mcp-token` refuses to start (decision D18) —
/// `spawn_http` observes the refusal and returns `None`.
#[test]
fn http_mcp_non_loopback_without_token_refuses_to_start() {
    let result = spawn_http(&["--mcp-bind", "0.0.0.0:0"]);
    assert!(
        result.is_none(),
        "non-loopback bind without --mcp-token must refuse to start (D18)"
    );
}

/// On loopback with no token configured, an unauthenticated JSON-RPC
/// `initialize` POST returns 200.
#[test]
fn http_mcp_loopback_no_auth_initialize_succeeds() {
    let (child, addr) = match spawn_http(&["--mcp-bind", "127.0.0.1:0"]) {
        Some(p) => p,
        None => panic!("failed to start MCP HTTP server"),
    };
    let url = format!("http://{addr}/mcp");

    // Send an initialize request with no auth header — loopback + no token
    // configured = no auth required.
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    });
    let resp = post_json(&url, None, &payload);
    assert_eq!(
        resp.status, 200,
        "initialize should succeed; body: {}",
        resp.body
    );

    shutdown(child);
}

/// With `--mcp-token` set: missing and wrong bearer tokens get 401, the
/// correct token gets 200 on `initialize`.
#[test]
fn http_mcp_with_token_rejects_missing_and_wrong_tokens() {
    let token = "supersecret-test-token";
    let (child, addr) = match spawn_http(&["--mcp-bind", "127.0.0.1:0", "--mcp-token", token]) {
        Some(p) => p,
        None => panic!("failed to start MCP HTTP server with token"),
    };
    let url = format!("http://{addr}/mcp");

    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}
    });

    // No auth header → 401
    let resp = post_json(&url, None, &payload);
    assert_eq!(resp.status, 401, "missing token must be 401");

    // Wrong token → 401
    let resp = post_json(&url, Some("wrong-token-value"), &payload);
    assert_eq!(resp.status, 401, "wrong token must be 401");

    // Right token → 200
    let resp = post_json(&url, Some(token), &payload);
    assert_eq!(
        resp.status, 200,
        "correct token must succeed; body: {}",
        resp.body
    );

    shutdown(child);
}

// ── RFC 9728 / RFC 6750 discovery ───────────────────────────────────────
//
// Two deliverables, asserted against the specifications rather than against
// this implementation:
//
// * RFC 9110 §15.5.2 — "The server generating a 401 response MUST send a
//   WWW-Authenticate header field containing at least one challenge".
// * RFC 6750 §3 — the challenge's auth-scheme "MUST be Bearer" and "MUST be
//   followed by one or more auth-param values"; §3.1 — a request that "lacks
//   any authentication information" SHOULD NOT carry an error code, while an
//   invalid/expired token is `error="invalid_token"`.
// * RFC 9728 §5.1 — `resource_metadata` names "the URL of the protected
//   resource metadata"; §3.1 — that URL inserts `/.well-known/
//   oauth-protected-resource` between the host and path components of the
//   resource identifier; §3.2 — the response is `200` `application/json`;
//   §3.3 — the `resource` value "MUST be identical to the URL that the client
//   used to make the request to the resource server".

/// The public resource identifier the discovery tests configure. Deliberately
/// an `https` URL on a hostname this process does not bind: the identifier is
/// what a client reaches through a TLS-terminating proxy, and deriving it from
/// the listening socket would be wrong for every hosted deployment.
const RESOURCE_URL: &str = "https://sipnab.example.com/mcp";

/// The metadata URL RFC 9728 §3.1 derives from [`RESOURCE_URL`] — spelled out
/// rather than computed, so a test cannot agree with a broken derivation by
/// repeating it.
const METADATA_URL: &str = "https://sipnab.example.com/.well-known/oauth-protected-resource/mcp";

/// Pull one `name="value"` auth-param out of a `WWW-Authenticate` challenge.
///
/// Deliberately naive: RFC 9110 permits unquoted `token` values, but this
/// server emits quoted-string values for every parameter, and a helper that
/// silently accepted both would let an unquoted (and, for a URL containing a
/// comma or a space, unparsable) value pass the assertions.
fn auth_param<'a>(challenge: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = challenge.find(&needle)? + needle.len();
    let rest = &challenge[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// A 401 from a token-protected server carries a `Bearer` challenge, and —
/// because the request presented no credentials at all — no error code.
///
/// The before-state this replaces was a bodyless `401` with NO
/// `WWW-Authenticate` whatsoever, which RFC 9110 §15.5.2 forbids outright and
/// which leaves a client unable to tell "present a bearer token" from "this
/// server is broken".
#[test]
fn an_unauthenticated_401_carries_a_bearer_challenge_without_an_error_code() {
    let token = "supersecret-test-token";
    let (child, addr) = spawn_http(&["--mcp-bind", "127.0.0.1:0", "--mcp-token", token])
        .expect("failed to start MCP HTTP server with token");
    let url = format!("http://{addr}/mcp");

    let resp = post_json(&url, None, &mcp::initialize_payload());
    assert_eq!(resp.status, 401, "missing token must stay 401");
    assert_eq!(
        resp.header_count("WWW-Authenticate"),
        1,
        "RFC 9110 §15.5.2: a 401 MUST send exactly one WWW-Authenticate here; \
         got headers {:?}",
        resp.headers
    );
    let challenge = resp.header("WWW-Authenticate").expect("challenge present");
    assert!(
        challenge.starts_with("Bearer "),
        "RFC 6750 §3: the auth-scheme MUST be Bearer and MUST be followed by \
         at least one auth-param; got {challenge:?}"
    );
    assert_eq!(
        auth_param(challenge, "realm"),
        Some("sipnab"),
        "the challenge must name a protection space; got {challenge:?}"
    );
    assert!(
        !challenge.contains("error="),
        "RFC 6750 §3.1: a request that lacks any authentication information \
         SHOULD NOT be answered with an error code; got {challenge:?}"
    );

    shutdown(child);
}

/// A token that was presented and failed verification is `invalid_token`.
///
/// The distinction is the whole value of the header to an operator: "you sent
/// nothing" and "the thing you sent is expired, revoked or forged" are
/// different problems and were previously the same empty 401.
#[test]
fn a_rejected_token_401_names_the_rfc6750_invalid_token_error() {
    let token = "supersecret-test-token";
    let (child, addr) = spawn_http(&["--mcp-bind", "127.0.0.1:0", "--mcp-token", token])
        .expect("failed to start MCP HTTP server with token");
    let url = format!("http://{addr}/mcp");

    let resp = post_json(&url, Some("wrong-token-value"), &mcp::initialize_payload());
    assert_eq!(resp.status, 401, "wrong token must stay 401");
    let challenge = resp.header("WWW-Authenticate").expect("challenge present");
    assert_eq!(
        auth_param(challenge, "error"),
        Some("invalid_token"),
        "RFC 6750 §3.1: a token that failed verification is invalid_token; \
         got {challenge:?}"
    );

    shutdown(child);
}

/// With a resource identifier configured, the challenge points at the metadata
/// document and the document is there, unauthenticated, in the shape RFC 9728
/// §3.2 requires.
#[test]
fn the_challenge_points_at_an_rfc9728_metadata_document() {
    let token = "supersecret-test-token";
    let (child, addr) = spawn_http(&[
        "--mcp-bind",
        "127.0.0.1:0",
        "--mcp-token",
        token,
        "--mcp-resource-url",
        RESOURCE_URL,
    ])
    .expect("failed to start MCP HTTP server with a resource URL");

    let resp = post_json(
        &format!("http://{addr}/mcp"),
        None,
        &mcp::initialize_payload(),
    );
    let challenge = resp.header("WWW-Authenticate").expect("challenge present");
    assert_eq!(
        auth_param(challenge, "resource_metadata"),
        Some(METADATA_URL),
        "RFC 9728 §5.1 + §3.1: the challenge must carry the well-known URL \
         formed by inserting /.well-known/oauth-protected-resource between the \
         host and path components of {RESOURCE_URL}; got {challenge:?}"
    );

    // The client now fetches that document. It reaches this process on the
    // loopback socket rather than through the proxy the identifier names, so
    // the path is what is replayed — which is exactly the part §3.1 specifies.
    let doc = mcp::get(
        &format!("http://{addr}/.well-known/oauth-protected-resource/mcp"),
        None,
    );
    assert_eq!(
        doc.status, 200,
        "RFC 9728 §3.2: a successful response MUST use 200 OK; body {}",
        doc.body
    );
    assert!(
        doc.header("content-type")
            .is_some_and(|c| c.starts_with("application/json")),
        "RFC 9728 §3.2: the response MUST use the application/json content \
         type; got {:?}",
        doc.header("content-type")
    );
    let v: serde_json::Value = serde_json::from_str(&doc.body).expect("metadata is JSON");
    assert_eq!(
        v["resource"], RESOURCE_URL,
        "RFC 9728 §3.3: the resource value MUST be identical to the URL the \
         client used to reach the resource server; got {}",
        doc.body
    );
    assert_eq!(
        v["bearer_methods_supported"],
        serde_json::json!(["header"]),
        "the only method this server accepts a token by is the Authorization \
         header; got {}",
        doc.body
    );
    let scopes = v["scopes_supported"]
        .as_array()
        .unwrap_or_else(|| panic!("scopes_supported must be a JSON array; got {}", doc.body));
    assert!(
        scopes.iter().any(|s| s == "full") && scopes.iter().any(|s| s == "read"),
        "scopes_supported must list the scopes this surface understands; got {}",
        doc.body
    );
    assert!(
        v.get("authorization_servers").is_none(),
        "sipnab issues and validates no OAuth tokens, so advertising an \
         authorization server would send a client on a journey that ends in \
         another 401; got {}",
        doc.body
    );

    shutdown(child);
}

/// The metadata document is public by design, so what it does NOT contain is
/// the assertion worth having: not the token, not the signing key, not the
/// bind address, not the Host allowlist, not the capture.
#[test]
fn the_metadata_document_discloses_no_credentials_or_internals() {
    let token = "supersecret-test-token";
    let signing_key = "metadata-leak-probe-signing-key";
    let (child, addr) = spawn_http(&[
        "--mcp-bind",
        "127.0.0.1:0",
        "--mcp-token",
        token,
        "--mcp-signing-key",
        signing_key,
        "--mcp-allowed-host",
        "internal-capture-host.corp",
        "--mcp-resource-url",
        RESOURCE_URL,
    ])
    .expect("failed to start MCP HTTP server for the disclosure probe");

    let doc = mcp::get(
        &format!("http://{addr}/.well-known/oauth-protected-resource/mcp"),
        None,
    );
    assert_eq!(
        doc.status, 200,
        "metadata must be served; body {}",
        doc.body
    );
    for secret in [
        token,
        signing_key,
        "internal-capture-host.corp",
        addr.as_str(),
        "sip_call.pcap",
    ] {
        assert!(
            !doc.body.contains(secret),
            "the unauthenticated metadata document leaks {secret:?}: {}",
            doc.body
        );
    }

    shutdown(child);
}

/// Mounting an unauthenticated route must not unmount the guard on the routes
/// that had one.
///
/// The failure this exists for is a one-line ordering mistake: axum's
/// `route_layer` applies only to routes declared BEFORE it, so registering the
/// well-known route in the wrong place silently drops the bearer guard from
/// every route registered alongside it. Nothing about the 200 that would
/// follow looks wrong.
#[test]
fn the_metadata_route_does_not_unauthenticate_the_mcp_surface() {
    let token = "supersecret-test-token";
    let (child, addr) = spawn_http(&[
        "--mcp-bind",
        "127.0.0.1:0",
        "--mcp-token",
        token,
        "--mcp-resource-url",
        RESOURCE_URL,
    ])
    .expect("failed to start MCP HTTP server with a resource URL");

    assert_eq!(
        post_json(
            &format!("http://{addr}/mcp"),
            None,
            &mcp::initialize_payload()
        )
        .status,
        401,
        "/mcp must still require the bearer token"
    );
    assert_eq!(
        mcp::get(&format!("http://{addr}/health"), None).status,
        401,
        "/health must still require the bearer token"
    );
    assert_eq!(
        post_json(
            &format!("http://{addr}/mcp"),
            Some(token),
            &mcp::initialize_payload()
        )
        .status,
        200,
        "the configured token must still be accepted"
    );

    shutdown(child);
}

/// A resource identifier with no path component publishes at the bare
/// well-known path, and the identifier keeps no terminating slash.
///
/// RFC 9728 §3.1 spells both halves out: the request for
/// `https://resource.example.com` is `GET /.well-known/oauth-protected-resource`,
/// and "any terminating slash (/) following the host component MUST be removed
/// before inserting /.well-known/".
#[test]
fn a_resource_identifier_without_a_path_publishes_at_the_bare_well_known_path() {
    let token = "supersecret-test-token";
    let (child, addr) = spawn_http(&[
        "--mcp-bind",
        "127.0.0.1:0",
        "--mcp-token",
        token,
        "--mcp-resource-url",
        "https://sipnab.example.com/",
    ])
    .expect("failed to start MCP HTTP server with a path-less resource URL");

    let challenge_resp = post_json(
        &format!("http://{addr}/mcp"),
        None,
        &mcp::initialize_payload(),
    );
    let challenge = challenge_resp
        .header("WWW-Authenticate")
        .expect("challenge present");
    assert_eq!(
        auth_param(challenge, "resource_metadata"),
        Some("https://sipnab.example.com/.well-known/oauth-protected-resource"),
        "RFC 9728 §3.1: with no path component the well-known URL carries no \
         suffix; got {challenge:?}"
    );

    let doc = mcp::get(
        &format!("http://{addr}/.well-known/oauth-protected-resource"),
        None,
    );
    assert_eq!(
        doc.status, 200,
        "metadata must be served; body {}",
        doc.body
    );
    let v: serde_json::Value = serde_json::from_str(&doc.body).expect("metadata is JSON");
    assert_eq!(
        v["resource"], "https://sipnab.example.com",
        "the terminating slash MUST be removed from the resource identifier; \
         got {}",
        doc.body
    );

    shutdown(child);
}

/// Without a resource identifier there is nothing to publish, so no well-known
/// route is mounted — but the challenge still appears, because RFC 9110's
/// requirement does not depend on RFC 9728 being configured.
///
/// Guessing the identifier from the listening socket or the `Host` header is
/// what this refuses to do: `tests/security_test.rs` H2 already establishes
/// that a forwarded header is not trusted here, and a guessed scheme produces
/// a document a conformant client MUST reject under §3.3.
#[test]
fn without_a_resource_url_the_challenge_stands_alone_and_nothing_is_published() {
    let token = "supersecret-test-token";
    let (child, addr) = spawn_http(&["--mcp-bind", "127.0.0.1:0", "--mcp-token", token])
        .expect("failed to start MCP HTTP server with token");

    let resp = post_json(
        &format!("http://{addr}/mcp"),
        None,
        &mcp::initialize_payload(),
    );
    let challenge = resp.header("WWW-Authenticate").expect("challenge present");
    assert!(
        auth_param(challenge, "resource_metadata").is_none(),
        "an unconfigured resource identifier must not be guessed; got \
         {challenge:?}"
    );
    assert_eq!(
        mcp::get(
            &format!("http://{addr}/.well-known/oauth-protected-resource"),
            None
        )
        .status,
        404,
        "nothing is published when no resource identifier is configured"
    );

    shutdown(child);
}
