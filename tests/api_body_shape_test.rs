// SPDX-License-Identifier: GPL-3.0-or-later
//! A request body the server cannot read is never permission to act.
//!
//! These live in `tests/` rather than beside the handlers on purpose.
//! `scripts/coverage-matrix.py` scans `src/output/api.rs` for route
//! registrations followed by a quoted path, and it matches loosely enough that
//! a test which reads that file for the same pattern invents routes just by
//! containing the bytes it looks for -- in code or in a comment. Three drafts
//! in place tripped the surface-parity gate. The scanner does not read
//! `tests/`, so the coupling disappears rather than being worked around.
#![cfg(all(feature = "api", feature = "vcon"))]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use parking_lot::{Mutex, RwLock};
use tower::ServiceExt;

use sipnab::output::api::{ApiState, RateLimiter, build_router};
use sipnab::output::persistence::PersistenceGate;

/// The bearer key these tests authenticate with.
const KEY: &str = "body-shape-test-key";

fn state_with(gate: &Arc<PersistenceGate>) -> ApiState {
    ApiState {
        dialog_store: Arc::new(RwLock::new(sipnab::sip::dialog_store::DialogStore::new(
            1000, false,
        ))),
        stream_store: Arc::new(RwLock::new(sipnab::rtp::stream_store::StreamStore::new(
            1000,
        ))),
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(
            sipnab::auth::VerifierConfig {
                static_keys: vec![KEY.to_string()],
                ..Default::default()
            },
        )),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1000))),
        max_inline_media_bytes: None,
        max_rows: 50,
        capture: None,
        source_exhausted: None,
        persistence_gate: Arc::clone(gate),
        tfps: Default::default(),
    }
}

fn post(uri: &str, body: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .body(Body::from(body.to_owned()))
        .expect("build request");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        12345,
    )));
    req
}

/// The POST routes the API registers, read from its own source.
///
/// Derived rather than hand-listed: a list would be correct on the day it was
/// written and silently short every day after, which is the failure mode this
/// whole test exists to prevent.
fn post_routes() -> Vec<String> {
    let src = include_str!("../src/output/api.rs");
    let lines: Vec<&str> = src.lines().collect();
    let mut routes = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains(".post(") {
            continue;
        }
        // The path sits on this line or the two above: the registration wraps
        // when the handler pair is long.
        for candidate in lines.iter().skip(i.saturating_sub(2)).take(3) {
            let b = candidate.as_bytes();
            for k in 0..b.len().saturating_sub(1) {
                if b[k] != b'"' || b[k + 1] != b'/' {
                    continue;
                }
                let Some(path) = candidate[k + 1..].split('"').next() else {
                    continue;
                };
                if path.contains('{') || path.is_empty() {
                    continue;
                }
                if !routes.iter().any(|r: &String| r == path) {
                    routes.push(path.to_string());
                }
            }
        }
    }
    routes
}

/// EVERY POST route refuses a body that is not a JSON object.
///
/// Scoped to the router rather than to one route, so a POST route added later
/// inherits the check instead of having to remember it. The defect this
/// generalizes was not a typo: a derived `Deserialize` reads a struct from a
/// SEQUENCE as happily as from a map, filling fields in declaration order, and
/// `deny_unknown_fields` cannot see it because a sequence has no field names to
/// be unknown. `[true]` reopened a closed persistence gate. Any future
/// one-field request struct has the same hole, and its array is one token long.
#[tokio::test]
async fn every_post_route_refuses_a_body_that_is_not_an_object() {
    let routes = post_routes();
    assert!(
        !routes.is_empty(),
        "no POST route was read out of api.rs, so this test is checking \
         nothing -- the scan stopped matching"
    );

    for route in &routes {
        for body in ["[true]", "[]", "true", "5", r#""text""#, "null", "{}"] {
            let gate = Arc::new(PersistenceGate::new(true));
            let app = build_router(state_with(&gate));
            let resp = app.oneshot(post(route, body)).await.expect("oneshot");
            assert!(
                resp.status().is_client_error(),
                "POST {route} accepted the non-object body {body:?} with status \
                 {} -- a body the handler cannot read is never permission to act",
                resp.status()
            );
            assert!(
                gate.writes_permitted(),
                "POST {route} with body {body:?} moved shared state while being \
                 refused"
            );
        }
    }
}

/// No handler extracts a typed body straight from the request.
///
/// The static half of the pair. The test above proves the CURRENT routes refuse
/// a sequence; this refuses the construct that makes a sequence readable at
/// all, so the hole cannot be reintroduced and then found by whoever it happens
/// to. A body goes through `Json<Value>`, an `is_object` check, and only then
/// `serde_json::from_value`.
#[test]
fn no_handler_extracts_a_typed_body_straight_from_the_request() {
    let src = include_str!("../src/output/api.rs");
    let mut offenders = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") || code.starts_with('*') {
            continue;
        }
        let Some(rest) = code.split_once("Json<") else {
            continue;
        };
        let Some(ty) = rest.1.split('>').next() else {
            continue;
        };
        if !code.contains("body") || ty.contains("Value") {
            continue;
        }
        offenders.push(format!("line {}: Json<{ty}>", i + 1));
    }
    assert!(
        offenders.is_empty(),
        "a request body must be extracted as `Json<Value>`, checked with \
         `is_object()`, and only then deserialized -- a derived `Deserialize` \
         also accepts a JSON SEQUENCE, which is how `[true]` once reopened a \
         closed persistence gate: {offenders:?}"
    );
}
