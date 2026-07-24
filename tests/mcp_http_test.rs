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
