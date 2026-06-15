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

const CALL_ID: &str = "test-call-1@10.0.0.1";

#[test]
fn health_returns_ok() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/health");
    assert_eq!(resp.status, 200, "/health status");
    assert_eq!(resp.body.trim(), "ok");
}

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

#[test]
fn unknown_dialog_returns_404() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/dialogs/does-not-exist@nowhere");
    assert_eq!(resp.status, 404, "unknown dialog must 404");
}

#[test]
fn stats_returns_structured_json() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/v1/stats");
    assert_eq!(resp.status, 200, "/v1/stats status");
    let body = resp.json();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["dialogs"]["total"], 1);
    assert_eq!(body["dialogs"]["completed"], 1);
    assert!(body["timing"].is_object(), "stats has a timing block");
}

#[test]
fn streams_endpoints_validate_against_stream_schema() {
    // sip_call.pcap has no RTP; use an RTP fixture so streams are non-empty.
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/sip-rtp-g711.pcap", &[]);

    // List: wrapper + non-empty summary items (summary shape carries `mos`).
    let resp = srv.get("/v1/streams");
    assert_eq!(resp.status, 200, "/v1/streams status");
    let body = resp.json();
    assert_eq!(body["schema_version"], 1);
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
        ] {
            assert!(s.get(k).is_some(), "stream summary missing `{k}`");
        }
    }

    // Detail: the full StreamJson validates against the T1.3 stream schema.
    let stream_schema = load_validator("stream.schema.json");
    let resp = srv.get(&format!("/v1/streams/{ssrc}"));
    assert_eq!(resp.status, 200, "/v1/streams/{{ssrc}} status");
    assert_valid(&stream_schema, &resp.json(), "stream detail");
}

// ── auth (T3.3) ──────────────────────────────────────────────────────────

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

#[test]
fn max_conn_limiter_active_still_serves() {
    // A low connection cap must not break normal serving. (Deterministic
    // exhaustion of the semaphore would need a slow endpoint, which the API
    // does not expose; the limiter mechanism itself is library-level.)
    let srv = ApiServer::spawn(&["--api-max-conn", "2"]);
    for _ in 0..5 {
        assert_eq!(srv.get("/health").status, 200);
    }
}

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
        std::time::Duration::from_secs(3),
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

#[test]
fn metrics_endpoint_serves_prometheus_text() {
    let srv = ApiServer::spawn(&[]);
    let resp = srv.get("/metrics");
    assert_eq!(resp.status, 200, "/metrics status");
    // Detailed Prometheus parsing lives in T3.4; here just prove it serves.
    assert!(resp.body.contains("# TYPE sipnab_dialogs_total counter"));
}
