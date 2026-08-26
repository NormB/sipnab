// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end REST API tests (verification plan M3 — T3.2/T3.3).
//!
//! Unlike the in-process tower tests in `src/output/api.rs`, these spawn a real
//! `sipnab --api` process and drive it over HTTP, so they exercise the full
//! bind → serve → JSON path. Every endpoint is checked for **status + schema**;
//! the dialog/stream schemas authored in T1.3 get their first *live-output*
//! validation here (their CLI surfaces don't emit these shapes).
#![cfg(feature = "api")]

#[path = "support/server.rs"]
mod server;
#[path = "support/mod.rs"]
mod support;

use server::{ApiServer, run_and_capture_stderr};
use support::schema::{assert_valid, load_validator};

include!("support/timeout.rs");

/// The Call-ID of the single dialog in the default `sip_call.pcap` fixture,
/// used to address per-dialog endpoints.
const CALL_ID: &str = "test-call-1@10.0.0.1";

/// `GET /health` returns 200 with the literal body `ok`.
#[test]
fn health_returns_ok() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/health");
    assert_eq!(resp.status, 200, "/health status");
    assert_eq!(resp.body.trim(), "ok");
}

/// The server accepts `--api-max-conn` (the in-flight-request cap) and still
/// serves — keeps the flag under test coverage.
#[test]
fn api_max_conn_flag_accepted_and_serves() {
    let srv = ApiServer::spawn(&["--api-max-conn", "8"]);
    let resp = srv.get("/health");
    assert_eq!(
        resp.status, 200,
        "server started with --api-max-conn should serve /health"
    );
    assert_eq!(resp.body.trim(), "ok");
}

/// `GET /v1/dialogs` returns the versioned list wrapper (schema_version/total/
/// offset/limit) and each summary validates against `dialog.schema.json`.
#[test]
fn list_dialogs_wrapper_and_summaries_validate() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/dialogs");
    assert_eq!(resp.status, 200, "/v1/dialogs status");
    let body = resp.json();

    // List wrapper shape.
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["total"], 1);
    assert!(body.get("offset").is_some() && body.get("limit").is_some());

    // Each dialog summary validates against the T1.3 dialog schema.
    let dialog_schema = load_validator("dialog.schema.json");
    let dialogs = body["dialogs"].as_array().expect("dialogs array");
    assert_eq!(dialogs.len(), 1, "fixture has one dialog");
    for (i, d) in dialogs.iter().enumerate() {
        assert_valid(&dialog_schema, d, &format!("dialog summary {i}"));
    }
}

/// Both `GET /v1/dialogs/{id}` and `/v1/dialogs/{id}/report` return 200 and
/// validate against `call_report.schema.json`.
#[test]
fn get_dialog_and_report_validate_call_report_schema() {
    let srv = ApiServer::spawn(&[]);
    let cr = load_validator("call_report.schema.json");

    for path in [
        format!("/v1/dialogs/{CALL_ID}"),
        format!("/v1/dialogs/{CALL_ID}/report"),
    ] {
        let resp = srv.get(&path);
        assert_eq!(resp.status, 200, "{path} status");
        assert_valid(&cr, &resp.json(), &path);
    }
}

/// Requesting a Call-ID that is not in the store returns 404.
#[test]
fn unknown_dialog_returns_404() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/dialogs/does-not-exist@nowhere");
    assert_eq!(resp.status, 404, "unknown dialog must 404");
}

/// `GET /v1/dialogs/{call_id}/vcon` is served by the binary that ships, and an
/// unknown Call-ID is a 404 there too.
///
/// Driven through `ApiServer::spawn` rather than the in-process router, for
/// the reason `/v1/report` is: a handler can be correct, and tested, and still
/// not be wired into the shipping binary. That is a live risk here in a way it
/// is not elsewhere, because both the route registration and the handler sit
/// behind `#[cfg(feature = "vcon")]` — a build that silently lost the feature
/// would keep every in-process test compiling and stop answering.
///
/// The caveat assertions are the point of the route rather than decoration.
/// A sipnab vCon is an OBSERVER's record: it carries signaling only, nothing
/// in it is signed, and a capture that lost messages to compaction or a port
/// gate has to say so. A container that reached a consumer without that text
/// would read as a recording of the call.
#[cfg(feature = "vcon")]
#[test]
fn vcon_route_is_served_by_the_shipping_binary() {
    let srv = ApiServer::spawn(&[]);

    let resp = srv.get(&format!("/v1/dialogs/{CALL_ID}/vcon"));
    assert_eq!(resp.status, 200, "/v1/dialogs/{CALL_ID}/vcon status");
    let body = resp.json();
    assert!(
        body.is_object(),
        "the container must arrive as an object, not a stringified blob: {body}"
    );
    assert_eq!(
        body["vcon"], "0.4.0",
        "the syntax version a consumer keys its parser on: {body}"
    );
    assert_eq!(
        body["dialog"][0]["sip_call_id"], CALL_ID,
        "the container must name the Call-ID it was built from: {body}"
    );

    // draft-ietf-vcon-vcon-core §2.3.2 makes `body` a String, so the read goes
    // through a parse. A `Value` index here would silently yield `null` against
    // a spec-conforming container and pass against a non-conforming one.
    let analysis_body: serde_json::Value = serde_json::from_str(
        body["analysis"][0]["body"]
            .as_str()
            .unwrap_or_else(|| panic!("an analysis body must be a string: {body}")),
    )
    .unwrap_or_else(|e| panic!("the analysis body must parse: {e}: {body}"));
    let note = analysis_body["capture_completeness"]["note"]
        .as_str()
        .unwrap_or_else(|| panic!("no completeness note: {body}"));
    // NOT "SIGNALING ONLY". This door attempts media like the CLI and MCP
    // doors since 0.5.125, so the caveat reports what this run MEASURED about
    // media instead of a fixed claim that the container carries none. The two
    // clauses below are the ones that must never soften: they are what stops a
    // reader taking an observation for a recording of the call.
    for clause in ["OBSERVED", "nothing here is signed"] {
        assert!(
            note.contains(clause),
            "the caveat must say `{clause}` — without it the container reads \
             as a recording of the call: {note}"
        );
    }
    assert!(
        note.contains("not a finding that the call was silent"),
        "an absence of media must read as a fact about this RUN, never about \
         the conversation: {note}"
    );

    let unknown = srv.get("/v1/dialogs/does-not-exist@nowhere/vcon");
    assert_eq!(
        unknown.status, 404,
        "an unknown Call-ID must 404 here as it does on every other per-call \
         route, rather than return an empty container"
    );
}

/// The persistence gate is reachable on the shipping binary, and a run with no
/// persistence flags reports no authority.
///
/// The unit tests build a router in-process. This drives the real binary,
/// because a handler can be correct and still not be wired into what ships --
/// and this route is the one an operator reaches for when they want recording
/// to stop, so "the route exists" is part of the promise.
#[test]
fn the_persistence_gate_answers_on_the_shipping_binary() {
    let srv = ApiServer::spawn(&[]);

    let resp = srv.get("/v1/persistence");
    assert_eq!(resp.status, 200, "/v1/persistence status");
    let body = resp.json();
    assert_eq!(
        body["authorized"], false,
        "this run carries no persistence flags: {body}"
    );
    assert_eq!(
        body["enabled"], false,
        "so nothing is being written: {body}"
    );
}

/// Enabling persistence over REST on a run the command line never authorized
/// changes nothing, through the real binary.
///
/// The narrow-only property is the one an operator has to be able to trust
/// without reading the source: starting sipnab without a persistence flag
/// means no API key can turn recording on. Proved end to end rather than
/// against an in-process gate, because the ceiling is computed in one place
/// during startup and this is the only test that runs that code.
#[test]
fn rest_cannot_enable_persistence_the_command_line_never_authorized() {
    let srv = ApiServer::spawn(&[]);

    let resp = srv.post_json("/v1/persistence", r#"{"enabled":true}"#);
    assert_eq!(resp.status, 200, "/v1/persistence POST status");
    let body = resp.json();
    assert_eq!(
        body["enabled"], false,
        "a REST caller enabled content on a run started without the flags: {body}"
    );
    assert_eq!(
        body["authorized"], false,
        "and the reason is visible: {body}"
    );

    assert_eq!(
        srv.get("/v1/persistence").json(),
        body,
        "the next read must agree with what the POST reported"
    );
}

/// A run started WITH a persistence flag reports authority, and can be closed.
///
/// The mirror of the test above, and the one that proves the ceiling is read
/// from the flags rather than hardcoded: a `persists_content` that always
/// answered `false` would pass every other test in this file.
#[test]
fn a_run_started_with_export_flags_reports_authority_and_can_be_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let srv = ApiServer::spawn(&[
        "--export-vcon-when",
        "response_code >= 200",
        "--export-vcon-dir",
        dir.path().to_str().expect("utf-8 temp path"),
    ]);

    let body = srv.get("/v1/persistence").json();
    assert_eq!(
        body["authorized"], true,
        "--export-vcon-when authorizes content: {body}"
    );
    assert_eq!(body["enabled"], true, "and it starts open: {body}");

    let closed = srv
        .post_json("/v1/persistence", r#"{"enabled":false}"#)
        .json();
    assert_eq!(closed["enabled"], false, "the close landed: {closed}");
    assert_eq!(
        closed["authorized"], true,
        "closing does not erase the authority it was closed against: {closed}"
    );
}

/// A body the server cannot read is refused, and moves nothing.
///
/// Driven over a real socket so the refusal is the SERVER's and not axum's
/// extractor answering before the route was reached. `[true]` is the shape
/// that got through in development: a derived `Deserialize` reads a struct
/// from a sequence as happily as from a map.
#[test]
fn a_malformed_persistence_body_is_refused_by_the_shipping_binary() {
    let dir = tempfile::tempdir().expect("temp dir");
    let srv = ApiServer::spawn(&[
        "--export-vcon-when",
        "response_code >= 200",
        "--export-vcon-dir",
        dir.path().to_str().expect("utf-8 temp path"),
    ]);

    assert_eq!(
        srv.post_json("/v1/persistence", r#"{"enabled":false}"#)
            .json()["enabled"],
        false,
        "the fixture starts from a closed gate"
    );

    for body in ["[true]", "{}", "not json", r#"{"enabled":"true"}"#] {
        let resp = srv.post_json("/v1/persistence", body);
        assert_eq!(
            resp.status, 400,
            "body {body:?} was accepted: {}",
            resp.body
        );
        assert_eq!(
            srv.get("/v1/persistence").json()["enabled"],
            false,
            "body {body:?} reopened a closed gate"
        );
    }
}

/// `GET /v1/stats` returns 200 with schema_version 2, correct dialog counts
/// for the fixture, and a `timing` object.
///
/// The fixture's one dialog is completed, so `dialogs.active` and
/// `dialogs.in_call` are both 0 here and this asserts the KEY exists rather
/// than a value. The two are proved to be different computations in
/// `sip::dialog_store::tests::active_call_count_excludes_setup_and_subscriptions`.
#[test]
fn stats_returns_structured_json() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/stats");
    assert_eq!(resp.status, 200, "/v1/stats status");
    let body = resp.json();
    assert_eq!(body["schema_version"], 2);
    assert_eq!(body["dialogs"]["total"], 1);
    assert_eq!(body["dialogs"]["completed"], 1);
    assert!(
        body["dialogs"]["in_call"].is_number(),
        "the concurrent-call figure must be its own key: {body}"
    );
    assert!(body["timing"].is_object(), "stats has a timing block");
}

/// `/v1/report` answers for the whole capture, through a real server.
///
/// The per-call route answers for one Call-ID. This is the only REST route that
/// can speak for the capture: orphaned media, STUN and ICMP evidence, and what
/// the retention caps shed belong to no single dialog, so every other route is
/// blind to them. MCP has answered this as `get_capture_report` and the CLI as
/// `--report`; a REST client had to reimplement the analysis it came here for.
///
/// Driven through `ApiServer::spawn` rather than an in-process router, like
/// every other route in this file — a handler can be correct and still not be
/// wired into the binary that ships.
#[test]
fn capture_report_answers_for_the_whole_capture() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/report");
    assert_eq!(resp.status, 200, "/v1/report status");

    let body = resp.json();
    assert!(
        body.is_object(),
        "the report must be an object a client reads fields out of, not a \
         stringified blob it parses a second time: {body}"
    );
    // What it looked at, and whether it saw all of it. `complete` is the
    // honesty flag: a findings list from a capture that lost packets is a
    // FLOOR, and a reader who does not know that reads it as a total.
    for key in ["dialogs_examined", "streams_examined", "complete"] {
        assert!(
            body.get(key).is_some(),
            "`{key}` missing — the report must say what it examined and whether \
             it saw all of it: {body}"
        );
    }
    assert_eq!(
        body["dialogs_examined"], 1,
        "the report must describe the capture it was built from: {body}"
    );
}

/// `/v1/stats` carries the capture-quality block on every response, with the
/// three losses under three names and one flag rolling them up.
///
/// The counters behind these fields have existed for a while and reached only
/// a `warn` line on stderr. A client polling `/v1/stats` — which is what the
/// support recipes in `docs/rest-api.md` tell an operator to do — could read
/// dialog and stream totals off a run that had dropped part of the wire with
/// nothing in the payload to say so.
#[test]
fn stats_reports_capture_quality() {
    let srv = ApiServer::spawn(&[]);
    let body = srv.get("/v1/stats").json();

    let q = &body["capture_quality"];
    assert!(
        q.is_object(),
        "capture_quality must be present on every /v1/stats response: {body}"
    );
    // A file replay has no capture ring and no NIC in the path, so all three
    // are legitimately zero — and must be present AT zero, because a key that
    // shows up only on a bad run is a key no client learns exists.
    for field in [
        "kernel_dropped_packets",
        "interface_dropped_packets",
        "invalid_timestamps",
    ] {
        assert_eq!(
            q[field], 0,
            "capture_quality.{field} must be present and zero for a file \
             replay: {q}"
        );
    }
    assert_eq!(
        q["degraded"], false,
        "nothing was observed wrong on a file replay, so degraded must be \
         false rather than absent: {q}"
    );
}

/// With an RTP fixture loaded, `/v1/streams` summaries carry all expected keys
/// and the `/v1/streams/{ssrc}` detail validates against `stream.schema.json`.
#[test]
fn streams_endpoints_validate_against_stream_schema() {
    // sip_call.pcap has no RTP; use an RTP fixture so streams are non-empty.
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/sip-rtp-g711.pcap", &[]);

    // List: wrapper + non-empty summary items (summary shape carries `mos`).
    let resp = srv.get("/v1/streams");
    assert_eq!(resp.status, 200, "/v1/streams status");
    let body = resp.json();
    assert_eq!(body["schema_version"], 2);
    // Present at zero on every response, not only on the ones that held
    // something back: a key that shows up only when a filter bites is a key no
    // client learns exists.
    assert_eq!(
        body["ungrounded_excluded"], 0,
        "an unfiltered list bounded nothing, so it held nothing back: {body}"
    );
    let streams = body["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty(), "RTP fixture must yield streams");
    let ssrc = streams[0]["ssrc"]
        .as_str()
        .expect("ssrc string")
        .to_string();
    for s in streams {
        for k in [
            "ssrc",
            "src",
            "dst",
            "packets",
            "jitter_ms",
            "loss_pct",
            "mos",
            // What that `mos` is worth, on the same row and never optional.
            // A summary carrying the number without its grounding is the
            // shape that let a placeholder pass for a measurement.
            "mos_grounded",
            "mos_grounding",
        ] {
            assert!(s.get(k).is_some(), "stream summary missing `{k}`");
        }
    }

    // The fixture is G.711, which G.113 publishes an impairment value for, so
    // this is the grounded arm end to end -- through a real server, a real
    // pcap and a real HTTP response rather than a hand-built struct.
    assert_eq!(
        streams[0]["mos_grounding"], "published",
        "sip-rtp-g711.pcap is PCMU: {}",
        streams[0]
    );
    assert!(
        streams[0]["mos_note"].is_null(),
        "a published score has no caveat to disclose: {}",
        streams[0]
    );

    // Detail: the full StreamJson validates against the T1.3 stream schema.
    let stream_schema = load_validator("stream.schema.json");
    let resp = srv.get(&format!("/v1/streams/{ssrc}"));
    assert_eq!(resp.status, 200, "/v1/streams/{{ssrc}} status");
    assert_valid(&stream_schema, &resp.json(), "stream detail");
}

// ── auth (T3.3) ──────────────────────────────────────────────────────────

/// With `--api-key` set, the correct Bearer token gets 200 while a missing
/// token, wrong token, Basic scheme, and prefix-less raw key each get 401.
#[test]
fn auth_accepts_correct_bearer_and_rejects_everything_else() {
    let srv = ApiServer::spawn(&["--api-key", "s3cret-key"]);

    // Correct token → 200.
    assert_eq!(
        srv.get_bearer("/v1/dialogs", "s3cret-key").status,
        200,
        "correct bearer must be accepted"
    );

    // Negative cases (auth bypass = critical): each must be 401.
    assert_eq!(srv.get("/v1/dialogs").status, 401, "missing token");
    assert_eq!(
        srv.get_bearer("/v1/dialogs", "wrong-key").status,
        401,
        "wrong token"
    );
    assert_eq!(
        srv.get_with_auth("/v1/dialogs", "Basic czNjcmV0").status,
        401,
        "non-Bearer scheme"
    );
    assert_eq!(
        srv.get_with_auth("/v1/dialogs", "s3cret-key").status,
        401,
        "raw key without Bearer prefix"
    );
}

/// The per-IP rate limiter rejects once a source IP exceeds its request budget:
/// an initial burst of same-IP requests to a guarded endpoint is served (200),
/// and past the 100 rps cap further requests are rejected (503). This assertion
/// FAILS if the limiter is broken — with it removed every request would 200 and
/// no rejection would ever appear.
#[test]
fn rate_limiter_rejects_when_per_ip_budget_exhausted() {
    // `/v1/dialogs` runs the auth+rate-limit guard even when auth is
    // unconfigured, so a same-IP burst is charged against the per-IP budget
    // (RateLimiter::new(100), a one-second window). Fire a tight burst and stop
    // at the first rejection — which lands just past the cap (~request 101),
    // well inside the one-second window, keeping the test deterministic. The
    // limiter rejects with 503 SERVICE_UNAVAILABLE (not 429).
    let srv = ApiServer::spawn(&[]);
    let mut served = false;
    let mut rejected = false;
    for _ in 0..250 {
        match srv.get("/v1/dialogs").status {
            200 => served = true,
            503 => {
                rejected = true;
                break;
            }
            other => panic!("unexpected status {other} from /v1/dialogs during rate-limit burst"),
        }
    }
    assert!(
        served,
        "requests under the per-IP budget must be served (200)"
    );
    assert!(
        rejected,
        "the per-IP rate limiter must reject with 503 once the 100 rps budget is exhausted"
    );
}

/// Passing `--api-tls-cert`/`--api-tls-key` fails fast with the documented
/// "requires the axum-server crate" error and the API never starts listening.
#[test]
fn tls_flags_fail_fast_and_do_not_serve() {
    // Reality check: API TLS is NOT implemented — run_server returns an error
    // and the REST API never starts. This test pins that documented behavior
    // (HTTPS serving is a known gap; use a TLS-terminating proxy). If TLS is
    // ever implemented, this test must change to assert HTTPS works instead.
    let logs = run_and_capture_stderr(
        &[
            "--api-tls-cert",
            "/tmp/none.pem",
            "--api-tls-key",
            "/tmp/none.pem",
        ],
        test_timeout(3),
    );
    assert!(
        logs.contains("requires the axum-server crate"),
        "expected the documented TLS-not-implemented error, got:\n{logs}"
    );
    assert!(
        !logs.contains("REST API listening on"),
        "TLS flags must prevent the API from serving"
    );
}

/// `GET /metrics` returns 200 and contains the `sipnab_dialogs_total` counter
/// TYPE line, proving the Prometheus exposition endpoint serves.
#[test]
fn metrics_endpoint_serves_prometheus_text() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/metrics");
    assert_eq!(resp.status, 200, "/metrics status");
    // Detailed Prometheus parsing lives in T3.4; here just prove it serves.
    assert!(resp.body.contains("# TYPE sipnab_dialogs_total counter"));
}
