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

/// A recorded call's SIPREC metadata reaches the REST surface.
///
/// Not a second projection: `GET /v1/dialogs/{id}` serves `dialog_to_json`, so
/// this asserts that the one definition really does feed every surface rather
/// than each having grown its own copy of the dialog shape. If REST ever stops
/// carrying a field the CLI JSON has, it is because someone forked that
/// projection, and this is the test that says so.
#[test]
fn a_recorded_dialog_carries_its_siprec_metadata_over_http() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/siprec-opensips-invite.pcap", &[]);
    let resp = srv.get("/v1/dialogs/4f1c0a2e-siprec@172.28.0.31");
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).expect("valid JSON");
    let sr = &v["siprec"];
    assert_eq!(sr["session_id"], "4f1c0a2e", "body: {}", resp.body);
    assert_eq!(sr["mode"], "complete");
    assert_eq!(
        sr["streams"][0]["participant_id"], "9b2d1f00",
        "stream ownership must survive the HTTP projection: {sr}"
    );
}

/// The per-dialog report carries the recording metadata too.
///
/// `/report` is a second projection of the same dialog, and an operator
/// escalating a call reaches for the report rather than the raw object. A
/// field that reached one and not the other would be found by whoever needed
/// it least.
#[test]
fn the_dialog_report_endpoint_carries_siprec() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/siprec-opensips-invite.pcap", &[]);
    let resp = srv.get("/v1/dialogs/4f1c0a2e-siprec@172.28.0.31/report");
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    assert!(
        resp.body.contains("4f1c0a2e"),
        "the report must name the recording session: {}",
        resp.body
    );
}

/// The recorded dialog is listed like any other over HTTP.
///
/// The same claim the MCP surface makes, asserted here because the listing is
/// a different code path: SIPREC is a property of a call, not a separate kind
/// of object, and an operator filtering the list must not have to know that a
/// recorded call needs asking for differently.
#[test]
fn a_recorded_dialog_is_listed_like_any_other_over_http() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/siprec-opensips-invite.pcap", &[]);
    let resp = srv.get("/v1/dialogs");
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    assert!(
        resp.body.contains("4f1c0a2e-siprec@172.28.0.31"),
        "the recording dialog must appear in the ordinary listing: {}",
        resp.body
    );
}

/// A call with no SIPREC omits the key over HTTP too.
#[test]
fn an_ordinary_dialog_omits_siprec_over_http() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get(&format!("/v1/dialogs/{CALL_ID}"));
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).expect("valid JSON");
    assert!(
        v.get("siprec").is_none(),
        "an unrecorded call must omit the key, not send null: {}",
        resp.body
    );
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

/// `GET /v1/dialogs` reports what its `total` is made of, split by the method
/// that opened each dialog.
///
/// The MCP `DialogPage` gained this in AS4 because a triage page is dominated
/// by whatever the fleet does most — on a real capture, 98 of 110 rows were
/// OPTIONS — and a caller reading the first page could not tell. REST answers
/// the same question from the same store and must not answer it differently:
/// a statistic reachable over one surface and not the other is the parity
/// defect this project has already fixed twice.
///
/// `b2bua-asterisk.pcapng` is used rather than the default fixture because the
/// default holds one dialog, and a breakdown over a single method cannot
/// distinguish a correct implementation from one that emits the first row it
/// sees.
#[test]
fn dialog_list_says_what_its_total_is_made_of() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/b2bua-asterisk.pcapng", &[]);
    let body = srv.get("/v1/dialogs").json();

    let rows = body["by_method"]
        .as_array()
        .unwrap_or_else(|| panic!("by_method must be an array, got: {}", body["by_method"]));
    assert!(
        !rows.is_empty(),
        "a capture with dialogs must report at least one method"
    );

    // The breakdown covers the FILTERED set, which is what `total` counts —
    // not the page. Summing to `returned` instead would make the field agree
    // with itself while describing a different population.
    let summed: u64 = rows.iter().map(|r| r["count"].as_u64().unwrap()).sum();
    assert_eq!(
        summed,
        body["total"].as_u64().unwrap(),
        "by_method must account for every dialog in total, got {rows:?}"
    );

    // Descending count, then method name, so the dominant class is first and
    // two runs over the same capture cannot disagree about the order.
    let mut expected = rows.clone();
    expected.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .unwrap()
            .cmp(&a["count"].as_u64().unwrap())
            .then_with(|| {
                a["method"]
                    .as_str()
                    .unwrap()
                    .cmp(b["method"].as_str().unwrap())
            })
    });
    assert_eq!(rows, &expected, "by_method must be ordered, got {rows:?}");

    // More than one method, or the ordering assertion above is vacuous.
    assert!(
        rows.len() > 1,
        "fixture must hold more than one opening method for this test to \
         discriminate, got {rows:?}"
    );
}

/// `by_method` follows the `state` filter rather than describing the store.
///
/// The field's whole contract is that it covers the FILTERED set. Nothing
/// exercised that: the one existing test asks for the unfiltered list, where a
/// breakdown of the store and a breakdown of the filter are the same answer.
#[test]
fn dialog_list_by_method_follows_the_state_filter() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/b2bua-asterisk.pcapng", &[]);
    let all = srv.get("/v1/dialogs?limit=1000").json();
    let state = all["dialogs"][0]["state"]
        .as_str()
        .expect("the fixture must produce a dialog")
        .to_string();

    let filtered = srv.get(&format!("/v1/dialogs?state={state}")).json();
    let f_total = filtered["total"].as_u64().expect("total");
    assert!(
        f_total >= 1,
        "the state taken from a real row must match it"
    );
    assert!(
        f_total < all["total"].as_u64().expect("total"),
        "the fixture must hold more than one state, or this proves nothing"
    );

    let summed: u64 = filtered["by_method"]
        .as_array()
        .expect("by_method")
        .iter()
        .map(|r| r["count"].as_u64().expect("count"))
        .sum();
    assert_eq!(
        summed, f_total,
        "by_method must describe the filtered set: {}",
        filtered["by_method"]
    );
}

/// `by_method` follows the `from` regex filter too.
///
/// A second filter, because `state` and `from` are applied by different code —
/// a string compare and a compiled regex — and a breakdown wired to only one
/// of them would still pass the test above.
#[test]
fn dialog_list_by_method_follows_the_from_filter() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/b2bua-asterisk.pcapng", &[]);
    let all = srv.get("/v1/dialogs?limit=1000").json();
    let from = all["dialogs"]
        .as_array()
        .expect("rows")
        .iter()
        .find_map(|d| d["from_user"].as_str())
        .expect("some dialog carries a From user")
        .to_string();

    let filtered = srv.get(&format!("/v1/dialogs?from=^{from}$")).json();
    let f_total = filtered["total"].as_u64().expect("total");
    assert!(
        f_total >= 1,
        "an anchored match on a real From user must match"
    );

    let summed: u64 = filtered["by_method"]
        .as_array()
        .expect("by_method")
        .iter()
        .map(|r| r["count"].as_u64().expect("count"))
        .sum();
    assert_eq!(summed, f_total, "got {}", filtered["by_method"]);
}

/// The page bounds do not touch `by_method`.
///
/// The other half of the contract, and the one a naive implementation gets
/// wrong: tallying the rows it is about to return is the obvious thing to
/// write, and it produces a breakdown that shrinks as `limit` shrinks. An
/// operator would read the composition of a page and believe it was the
/// composition of the capture.
#[test]
fn dialog_list_by_method_ignores_the_page_bounds() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/b2bua-asterisk.pcapng", &[]);
    let whole = srv.get("/v1/dialogs?limit=1000").json();
    let one_row = srv.get("/v1/dialogs?limit=1").json();

    assert_eq!(
        one_row["dialogs"].as_array().expect("rows").len(),
        1,
        "the page really is bounded"
    );
    assert!(
        whole["dialogs"].as_array().expect("rows").len() > 1,
        "and the unbounded page really is bigger, or this proves nothing"
    );
    assert_eq!(
        one_row["by_method"], whole["by_method"],
        "by_method describes the filtered set, not the page"
    );
    assert_eq!(one_row["total"], whole["total"]);
}

/// A filter matching nothing gives an empty breakdown, not the whole store.
///
/// The negative case. A tally computed before the filter, or one that fell back
/// to the unfiltered set when the filter matched nothing, would answer here
/// with the store's composition beside a `total` of zero — two fields
/// contradicting each other in the same response.
#[test]
fn dialog_list_by_method_is_empty_when_nothing_matches() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/b2bua-asterisk.pcapng", &[]);
    let none = srv.get("/v1/dialogs?from=^definitely-no-such-user$").json();

    assert_eq!(
        none["total"].as_u64(),
        Some(0),
        "the filter matches nothing"
    );
    assert_eq!(
        none["by_method"].as_array().map(Vec::len),
        Some(0),
        "an empty result set has an empty breakdown, got {}",
        none["by_method"]
    );
}

/// Each method appears once, and no row claims zero.
///
/// A tally keyed on something other than the method — or one that pushed a row
/// per dialog instead of per bucket — still sums to `total`, so the sum
/// assertions above cannot see it. This is the shape check they need beside
/// them.
#[test]
fn dialog_list_by_method_has_one_row_per_method() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/b2bua-asterisk.pcapng", &[]);
    let body = srv.get("/v1/dialogs?limit=1000").json();
    let rows = body["by_method"].as_array().expect("by_method");

    let mut names: Vec<&str> = rows
        .iter()
        .map(|r| r["method"].as_str().expect("method is a string"))
        .collect();
    let before = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        before,
        names.len(),
        "a method must not get two rows: {rows:?}"
    );
    assert!(
        rows.iter().all(|r| r["count"].as_u64().unwrap_or(0) >= 1),
        "a bucket with nothing in it must not be reported: {rows:?}"
    );
}

// Reads `/proc`, which exists on Linux and nowhere else. Guarded rather than
// loosened: an assertion weakened until it passes on every platform stops
// proving the values are readable on the one platform that has them. The other
// arm is `off_linux_runtime_reports_absence_rather_than_zero`.
#[cfg(target_os = "linux")]
/// `GET /v1/runtime` answers with the envelope both surfaces share.
///
/// sipnab exports 32 Prometheus metrics and the listener that serves them is
/// off by default, so on most deployments those numbers exist in-process and
/// nothing can read them. This route answers without one.
#[test]
fn runtime_reports_the_process_and_the_host() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/runtime");
    assert_eq!(resp.status, 200, "/v1/runtime status");
    let body = resp.json();

    assert_eq!(body["schema_version"], 1);
    assert!(
        body["process"]["rss_bytes"]
            .as_u64()
            .expect("Linux exposes VmRSS")
            > 0,
        "a running process holds memory"
    );
    assert!(body["process"]["threads"].as_u64().expect("Threads") >= 1);
    assert!(
        body["host"]["memory_total_bytes"]
            .as_u64()
            .expect("MemTotal")
            > 0
    );
    assert!(
        matches!(body["host"]["basis"].as_str(), Some("host" | "cgroup")),
        "the denominator names itself: {}",
        body["host"]["basis"]
    );
}

/// Occupancy is reported against the cap, not as a bare count.
///
/// `dialogs.used` alone is a number; beside `capacity` it is a decision. An
/// operator who cannot see occupancy learns about eviction by noticing that
/// calls have gone missing.
#[test]
fn runtime_reports_occupancy_against_the_caps() {
    let srv = ApiServer::spawn(&[]);
    let body = srv.get("/v1/runtime").json();

    for store in ["dialogs", "streams"] {
        let cap = body[store]["capacity"].as_u64().expect("a cap");
        let used = body[store]["used"].as_u64().expect("a count");
        assert!(cap > 0, "{store} must report the cap it evicts against");
        assert!(used <= cap, "{store}: {used} held against a cap of {cap}");
        let pct = body[store]["pct"].as_f64().expect("a percentage");
        assert!(
            (0.0..=100.0).contains(&pct),
            "{store} pct {pct} out of range"
        );
    }
}

// Reads `/proc`, which exists on Linux and nowhere else. Guarded rather than
// loosened: an assertion weakened until it passes on every platform stops
// proving the values are readable on the one platform that has them. The other
// arm is `off_linux_runtime_reports_absence_rather_than_zero`.
#[cfg(target_os = "linux")]
/// The impact verdict is computed and stated, with its threshold.
///
/// A capture that is itself the reason a proxy started dropping calls is the
/// worst failure this tool can have, and it used to be invisible.
#[test]
fn runtime_states_whether_sipnab_is_load_bearing() {
    let srv = ApiServer::spawn(&[]);
    let body = srv.get("/v1/runtime").json();

    assert!(
        body["impact"]["significant"].is_boolean(),
        "the verdict is present: {}",
        body["impact"]
    );
    let note = body["impact"]["note"].as_str().expect("a note");
    assert!(
        note.contains("threshold"),
        "the note states the threshold so a reader can disagree with the \
         setting rather than the finding: {note}"
    );
}

/// Off Linux, the route answers with absence rather than with zeros.
///
/// A macOS or BSD reader gets the same envelope, and every field sourced from
/// `/proc` is simply not there. Reporting `0` where nothing was read would
/// tell that reader sipnab costs their host nothing, which is a stronger claim
/// than "not measurable here" and a false one.
#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_runtime_reports_absence_rather_than_zero() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/runtime");
    assert_eq!(resp.status, 200, "the route still answers");
    let body = resp.json();

    assert_eq!(body["schema_version"], 1);
    for absent in [
        "rss_bytes",
        "virtual_bytes",
        "threads",
        "open_fds",
        "cpu_seconds",
    ] {
        assert!(
            body["process"].get(absent).is_none() || body["process"][absent].is_null(),
            "process.{absent} must be absent, not zero: {}",
            body["process"]
        );
    }
    assert!(
        body["host"].get("memory_total_bytes").is_none()
            || body["host"]["memory_total_bytes"].is_null(),
        "there is no /proc/meminfo here: {}",
        body["host"]
    );
    assert_eq!(
        body["host"]["basis"], "host",
        "with no control group to read, the machine is the honest basis"
    );
    assert!(
        body["impact"].get("significant").is_none() || body["impact"]["significant"].is_null(),
        "no denominator means no verdict, not a false negative: {}",
        body["impact"]
    );

    // The platform-independent half still answers, which is what makes this a
    // degraded reply rather than a broken route.
    assert!(body["dialogs"]["capacity"].as_u64().expect("a cap") > 0);
    assert!(body["capture_packets_total"].is_u64());
}

/// A requested window is sampled and the window actually used is reported.
///
/// The rate half of the runtime answer is the half an operator asked for:
/// "1,284,301 messages" answers nothing, "312 messages/second, of which 190
/// are OPTIONS" answers the question they have. It has to be reachable from
/// REST and not only from MCP, or the two surfaces answer different questions.
#[test]
fn runtime_samples_a_rate_when_a_window_is_requested() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/runtime?sample_seconds=1");
    assert_eq!(resp.status, 200, "a one-second window is inside the cap");
    let body = resp.json();

    let rates = &body["rates"];
    assert!(!rates.is_null(), "a window was requested: {body}");
    assert!(
        rates["window_seconds"].as_u64().expect("the window used") >= 1,
        "the window that was applied is reported, not the one requested: \
         {rates}"
    );
    assert!(
        rates["packets_per_second"].as_f64().expect("a rate") >= 0.0,
        "a rate is never negative: {rates}"
    );
    assert!(
        rates["calls_per_second_by_method"].is_array(),
        "the breakdown is the point — an undifferentiated total describes the \
         keepalive plane rather than the calls: {rates}"
    );
}

/// A zero window is refused rather than answered with zero deltas.
///
/// Zero deltas is exactly what a healthy quiet capture reports, so answering
/// an empty window hands back a number the caller cannot tell from silence.
/// The refusal is the same one MCP gives, from the same function.
#[test]
fn runtime_refuses_a_zero_sample_window() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/runtime?sample_seconds=0");
    assert_eq!(resp.status, 400, "a zero window is refused: {}", resp.body);
    assert!(
        resp.body.contains("at least 1"),
        "the refusal says what to send instead: {}",
        resp.body
    );
}

/// A window that is not a number is refused, not read as no window at all.
///
/// Silently ignoring an unparseable parameter would answer with the cumulative
/// counters and no `rates` key — indistinguishable from a caller who never
/// asked, which is the failure mode this route exists to avoid.
#[test]
fn runtime_refuses_a_sample_window_that_is_not_a_number() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/runtime?sample_seconds=soon");
    assert_eq!(
        resp.status, 400,
        "an unparseable window is an error, not an absent one: {}",
        resp.body
    );
}

/// Rates are absent unless asked for, and the counters are cumulative.
///
/// Measuring a rate costs a wait, so it is opt-in over MCP. The REST route
/// answers with the cumulative counters, and they must be present.
#[test]
fn runtime_reports_cumulative_counters_without_a_sampling_wait() {
    let srv = ApiServer::spawn(&[]);
    let body = srv.get("/v1/runtime").json();

    assert!(body["capture_packets_total"].is_u64(), "a cumulative total");
    // Present because `start_servers` hands this process's capture meter to
    // the API door. It used to be present because the field was a `u64`
    // hardcoded to `meter.map_or(0, ..)` with `None` always passed — a
    // confident "the queue is clear" on a box whose queue was full. The unit
    // test `without_a_meter_the_queue_counters_are_absent_rather_than_zero`
    // holds the other half: no meter, no number.
    assert!(
        body["capture_queue_depth_packets"].is_u64(),
        "the capture meter must reach the API door, or this field would be \
         absent: {body}"
    );
    assert!(
        body["capture_backpressure_blocks_total"].is_u64(),
        "and its sibling, from the same meter: {body}"
    );
    assert!(body["uptime_seconds"].is_u64());
    assert!(
        body.get("rates").is_none() || body["rates"].is_null(),
        "no sampling window was requested, so no rate is claimed"
    );
}
