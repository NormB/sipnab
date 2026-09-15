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

// ── ST-S3: the REST arm of the cross-surface capability matrix ────────────────
//
// The capability-matrix acceptance test (`relay_stats_matrix_test`) reads the
// contract FROM the spec and grounds the TUI cells by driving a real view. This
// is the same grounding for REST, which the matrix test could not carry: the
// REST spellings the spec claims for C1--C4 are REAL, reachable routes on a
// running server, and C5 (poll) is the one deliberate REST omission. If the doc
// renames a route the server does not have, or the server drops one the doc
// still lists, the derived request 404s and this fails -- the drift PAR exists
// to catch. It was blocked until MCP (ST6) and the TUI (ST8) existed so the
// matrix could be complete on all four surfaces at once; both now exist.

/// The surface contract, read here so a doc/route divergence fails a test.
const SURFACES_SPEC: &str = include_str!("../docs/design/relay-statistics-surfaces.md");

/// The REST cell the spec gives capability `cap` (e.g. `C2`), read from the
/// `| Surface | Spelling |` table under that capability's `### C… ` heading.
fn rest_cell(cap: &str) -> String {
    let heading = format!("### {cap} ");
    let start = SURFACES_SPEC
        .find(&heading)
        .unwrap_or_else(|| panic!("no `{heading}` section in the surfaces spec"));
    let rest = &SURFACES_SPEC[start + heading.len()..];
    let end = rest
        .find("\n### ")
        .or_else(|| rest.find("\n## "))
        .unwrap_or(rest.len());
    rest[..end]
        .lines()
        .find(|l| l.starts_with("| REST | "))
        .map(|l| {
            l.trim_start_matches("| REST | ")
                .trim_end_matches(" |")
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| panic!("no REST row under `{cap}` in the surfaces spec"))
}

/// The `GET /path` a REST cell names, pulled out of its backticks and prose.
fn rest_path(cell: &str) -> String {
    let at = cell
        .find("GET /")
        .unwrap_or_else(|| panic!("REST cell names no `GET /path`: {cell:?}"));
    cell[at + "GET ".len()..]
        .chars()
        .take_while(|&c| c != '`')
        .collect::<String>()
        .trim()
        .to_string()
}

/// Every REST capability the spec lists (C1--C4) is a real route on a running
/// server, and C5 is the one deliberate REST omission. This grounds the REST
/// arm of the ST-S3 matrix the way the matrix test grounds the TUI arm.
#[test]
fn st_s3_the_rest_capability_cells_are_backed_by_real_routes() {
    let srv = ApiServer::spawn(&["--api-key", "k"]);
    for cap in ["C1", "C2", "C3", "C4"] {
        let cell = rest_cell(cap);
        let path = rest_path(&cell).replace("{call_id}", "1-7@203.0.113.9");
        let resp = srv.get_bearer(&path, "k");
        assert_eq!(
            resp.status, 200,
            "{cap}: the spec's REST route {path} must be a REAL route answering \
             with a classification, not a 404 -- doc and router have drifted: {}",
            resp.body
        );
        assert!(
            resp.json()["outcome"].as_str().is_some(),
            "{cap}: {path} answers with an outcome like every relay route: {}",
            resp.body
        );
    }

    // C5 (poll on an interval) is the single REST omission in the whole spec: a
    // standing instruction to transmit has no owner over a stateless request.
    // The running server therefore exposes the four routes above and no poll
    // route, and the doc cell must say so -- an omission with no marker reads as
    // a capability someone forgot.
    let c5 = rest_cell("C5");
    assert!(
        c5.eq_ignore_ascii_case("not offered"),
        "C5's REST cell must be the deliberate omission `not offered`, not {c5:?}"
    );
}
