// SPDX-License-Identifier: MIT OR Apache-2.0

//! One HEP sender roster, one answer: `GET /v1/hep/senders` and the MCP
//! `hep_senders` tool return the same bytes (invariant 9, "one wire shape per
//! concept").
//!
//! Both doors read the roster the listener hung on the capture meter, through
//! one builder, and serialize the same struct. This drives both over ONE
//! roster on a frozen clock, so "idle for 40 seconds" cannot tick between the
//! two reads and the comparison is exact.
//!
//! In `tests/` rather than beside either door, because it needs both: the
//! REST router and the MCP server are each private to a module that cannot
//! see the other's test fixtures.
#![cfg(all(feature = "api", feature = "mcp", feature = "hep"))]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use http_body_util::BodyExt;
use parking_lot::{Mutex, RwLock};
use rmcp::handler::server::wrapper::Parameters;
use tower::ServiceExt;

use sipnab::capture::hep_roster::{
    HepRefusal, HepRoster, RosterState, SenderTrust, hep_source_label,
};
use sipnab::mcp::server::SipnabMcp;
use sipnab::mcp::tools::hep::HepSendersParams;
use sipnab::output::api::{ApiState, RateLimiter, build_router};
use sipnab::output::persistence::PersistenceGate;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// The bearer key the REST side authenticates with.
const KEY: &str = "hep-senders-parity-key";

/// A roster with a live sender, a silent one and a refused address, on a
/// clock frozen forty seconds after the last packet.
fn roster() -> HepRoster {
    let t = std::time::Instant::now();
    let wall = chrono::DateTime::parse_from_rfc3339("2026-09-21T12:00:00Z")
        .map(|w| w.with_timezone(&chrono::Utc))
        .unwrap_or_default();
    let mut state = RosterState::new(
        SenderTrust::SharedSecretPlain,
        4096,
        std::time::Duration::from_secs(30),
        t,
        wall,
    );
    let admit = |state: &mut RosterState, id: u32, peer: &str, at: std::time::Instant| {
        let peer: IpAddr = peer.parse().expect("literal");
        state.admitted(Some(id), peer, &hep_source_label(Some(id), peer), at);
    };
    admit(&mut state, 7, "192.0.2.7", t);
    admit(
        &mut state,
        9,
        "192.0.2.9",
        t + std::time::Duration::from_secs(35),
    );
    admit(
        &mut state,
        7,
        "192.0.2.7",
        t + std::time::Duration::from_millis(1500),
    );
    let bad: IpAddr = "203.0.113.66".parse().expect("literal");
    state.refused(HepRefusal::AuthMismatch, bad, t);
    state.refused(HepRefusal::Allowlist, bad, t);
    let frozen = t + std::time::Duration::from_secs(40);
    HepRoster::with_clock(state, Arc::new(move || frozen))
}

/// A REST state whose capture meter carries `meter`, like a live `-L` run's.
fn rest_state(meter: sipnab::capture::channel::CaptureMeter) -> ApiState {
    ApiState {
        relay_query: Default::default(),
        dialog_store: Arc::new(RwLock::new(DialogStore::new(100, false))),
        stream_store: Arc::new(RwLock::new(StreamStore::new(100))),
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(
            sipnab::auth::VerifierConfig {
                static_keys: vec![KEY.to_string()],
                ..Default::default()
            },
        )),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1000, 1024))),
        max_inline_media_bytes: None,
        max_rows: 1000,
        capture: None,
        source_exhausted: None,
        capture_interfaces: Vec::new(),
        capture_meter: Some(meter),
        started_at: std::time::Instant::now(),
        persistence_gate: Arc::new(PersistenceGate::new(false)),
        tfps: Default::default(),
        alert_engine: None,
        armed_detections: Vec::new(),
        file_root: None,
    }
}

/// The REST body for `uri`.
async fn rest_body(state: ApiState, uri: &str) -> String {
    let mut req = Request::builder()
        .uri(uri)
        .header("Authorization", format!("Bearer {KEY}"))
        .body(Body::empty())
        .expect("build request");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        40000,
    )));
    let resp = build_router(state).oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), 200, "the route must answer");
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

/// The MCP tool's JSON text for `limit`.
async fn mcp_text(meter: sipnab::capture::channel::CaptureMeter, limit: Option<u32>) -> String {
    let srv = SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(100, false))),
        Arc::new(RwLock::new(StreamStore::new(100))),
    )
    .with_capture_meter(Some(meter));
    let result = srv
        .hep_senders(Parameters(HepSendersParams { limit }))
        .await
        .expect("the tool answers");
    result
        .content
        .iter()
        .find_map(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a JSON block")
}

/// **REST and MCP return byte-identical JSON for one roster**, with and
/// without a row limit.
#[tokio::test]
async fn rest_and_mcp_return_the_same_bytes_for_one_roster() {
    let (_tx, rx) = sipnab::capture::channel::packet_channel(8);
    let meter = rx.meter();
    assert!(meter.attach_hep_roster(roster()), "a fresh meter");

    let rest = rest_body(rest_state(meter.clone()), "/v1/hep/senders").await;
    let mcp = mcp_text(meter.clone(), None).await;
    assert_eq!(
        rest, mcp,
        "one roster, two doors, two answers:\n REST {rest}\n MCP  {mcp}"
    );
    // The comparison proved something only if the roster is not empty.
    let parsed: serde_json::Value = serde_json::from_str(&rest).expect("json");
    assert_eq!(
        parsed["senders"].as_array().map(Vec::len),
        Some(2),
        "{parsed}"
    );
    assert_eq!(parsed["senders"][0]["silent"], true, "{parsed}");
    assert_eq!(parsed["refused_sources"][0]["packets"], 2, "{parsed}");

    let rest_one = rest_body(rest_state(meter.clone()), "/v1/hep/senders?limit=1").await;
    let mcp_one = mcp_text(meter, Some(1)).await;
    assert_eq!(rest_one, mcp_one, "the same limit gives the same bytes");
}

/// **`GET /v1/runtime` and `runtime_stats` report the same `hep_export`** for
/// one exporter — they share one collector — and neither carries the key on
/// a run with no exporter.
#[tokio::test]
async fn rest_runtime_and_mcp_runtime_stats_agree_on_the_exporter() {
    use sipnab::capture::hep_export::{ExportFailure, HepExportCounters};
    use sipnab::mcp::server::RuntimeStatsParams;

    async fn both(
        meter: sipnab::capture::channel::CaptureMeter,
    ) -> (serde_json::Value, serde_json::Value) {
        let rest: serde_json::Value =
            serde_json::from_str(&rest_body(rest_state(meter.clone()), "/v1/runtime").await)
                .expect("json");
        let srv = SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
        .with_capture_meter(Some(meter));
        let result = srv
            .runtime_stats(
                Parameters(RuntimeStatsParams {
                    sample_seconds: None,
                }),
                rmcp::handler::server::tool::Extension(sipnab::mcp::progress::Progress::silent()),
            )
            .await
            .expect("the tool answers");
        let text = result
            .content
            .iter()
            .find_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("a JSON block");
        (rest, serde_json::from_str(&text).expect("json"))
    }

    let counters = HepExportCounters::new("tcp");
    for _ in 0..3 {
        counters.record_sent();
    }
    counters.record_failure(ExportFailure::Connect);
    counters.record_failure(ExportFailure::Connect);
    counters.record_failure(ExportFailure::TlsHandshake);
    counters.record_reconnect();
    let (_tx, rx) = sipnab::capture::channel::packet_channel(8);
    let meter = rx.meter();
    assert!(meter.attach_hep_export(counters), "a fresh meter");

    let (rest, mcp) = both(meter).await;
    assert_eq!(
        rest["hep_export"], mcp["hep_export"],
        "one collector, one answer"
    );
    let export = &rest["hep_export"];
    assert_eq!(export["transport"], "tcp", "{rest}");
    assert_eq!(export["packets_sent"], 3);
    assert_eq!(export["failures"]["connect"], 2);
    assert_eq!(export["failures"]["tls_handshake"], 1);
    assert_eq!(
        export["failures"]["write"], 0,
        "every kind is present, zeros included"
    );
    assert_eq!(export["reconnects"], 1);

    let (_tx2, rx2) = sipnab::capture::channel::packet_channel(8);
    let (rest, mcp) = both(rx2.meter()).await;
    assert!(
        rest.get("hep_export").is_none(),
        "no exporter, no key: {rest}"
    );
    assert!(
        mcp.get("hep_export").is_none(),
        "no exporter, no key: {mcp}"
    );
}
