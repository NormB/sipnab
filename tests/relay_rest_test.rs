// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST5: the relay-statistics REST routes, end to end against a running server.
//!
//! The spawn harness runs a file-backed server (`-N -I <pcap>`), which has no
//! `--rtpengine-control` and can hold no transmit permit -- so these drive the
//! reachable half of ST-S4: the routes exist, require auth, and answer the
//! invocation refusals with HTTP 200 and a classification (never a 4xx, and
//! never a transmit). The live `ok`/`unreachable`/`refused` paths need a real
//! relay and are exercised against the harness rtpengine, not here; the pure
//! classification and envelope are unit-tested in `src/output/api.rs` and
//! `tests/relay_rest_envelope_test.rs`.

#![cfg(feature = "api")]

#[path = "support/server.rs"]
mod server;

use server::ApiServer;

const RELAY_ROUTES: &[&str] = &[
    "/v1/relay/stats",
    "/v1/relay/stats/names",
    "/v1/relay/stats/call/1-7@203.0.113.9",
    "/v1/relay/compare/1-7@203.0.113.9",
];

/// Every relay route exists and, on a run with no relay configured, answers
/// HTTP 200 with `outcome: not_configured` -- a classification in the body, not
/// a 404, because the route is real and the relay is what is missing.
#[test]
fn relay_routes_answer_not_configured_without_a_relay() {
    let srv = ApiServer::spawn(&["--api-key", "k"]);
    for route in RELAY_ROUTES {
        let resp = srv.get_bearer(route, "k");
        assert_eq!(
            resp.status, 200,
            "{route} must be 200 (a refusal is content, not a 4xx)"
        );
        let v = resp.json();
        assert_eq!(
            v["outcome"], "not_configured",
            "{route} with no --rtpengine-control classifies not_configured: {}",
            resp.body
        );
        assert_eq!(
            v["responsibility"], "invocation",
            "{route} whose problem: the invocation"
        );
        assert!(
            v.get("statistics").is_none() && v.get("packets").is_none(),
            "{route} refusal carries no data payload: {}",
            resp.body
        );
    }
}

/// The relay routes are behind the bearer gate like every other data route: an
/// unauthenticated request is 401, never a relay query.
#[test]
fn relay_routes_require_auth() {
    let srv = ApiServer::spawn(&["--api-key", "k"]);
    for route in RELAY_ROUTES {
        let resp = srv.get(route);
        assert_eq!(resp.status, 401, "{route} must require a bearer credential");
    }
}

/// A wrong bearer is rejected too -- the gate is the credential, not merely its
/// presence.
#[test]
fn relay_routes_reject_a_wrong_key() {
    let srv = ApiServer::spawn(&["--api-key", "right"]);
    let resp = srv.get_bearer("/v1/relay/stats", "wrong");
    assert_eq!(resp.status, 401, "a wrong key is no key");
}

/// The response is always a single JSON object carrying a top-level `outcome`,
/// so a client branches on one field regardless of which route it called.
#[test]
fn every_relay_route_carries_an_outcome() {
    let srv = ApiServer::spawn(&["--api-key", "k"]);
    for route in RELAY_ROUTES {
        let v = srv.get_bearer(route, "k").json();
        assert!(
            v["outcome"].as_str().is_some(),
            "{route} must carry a string outcome: {v}"
        );
    }
}
