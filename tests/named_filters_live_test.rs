// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A name the terminal UI saves with `F2` (to the config file, or for the
//! session only) is published to the process's live `[filters]` table
//! (`named_filters::publish`), and the REST API and MCP server of the same
//! process use it at once: the list answers it, `named=` selects by it, and
//! a filter expression resolves `@name`.
//!
//! The process's table is global, so this binary holds ONE test that walks
//! the whole sequence: a second test in the same process would race it. The
//! terminal UI's own call of `publish` is tested in the lib
//! (`filter_dialog` session tests, with a recording publisher); this binary
//! starts from that call.

#![cfg(all(feature = "api", feature = "mcp", feature = "vcon"))]

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use parking_lot::{Mutex, RwLock};
use serde_json::Value;
use tower::ServiceExt;

use sipnab::mcp::SipnabMcp;
use sipnab::output::api::{ApiState, RateLimiter, build_router};
use sipnab::output::persistence::PersistenceGate;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::dsl::{AliasThresholds, parse_filter, resolve_filter_text};
use sipnab::sip::named_filters::{NamedFilters, install, installed, publish};

type TestError = Box<dyn std::error::Error>;

/// `pairs` resolved as a `[filters]` table.
fn table(pairs: &[(&str, &str)]) -> Result<NamedFilters, TestError> {
    let defs: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Ok(NamedFilters::resolve(&defs, &AliasThresholds::default())?)
}

/// The dialog and stream stores both surfaces read: empty, since only
/// whether a name compiles is in question.
type Stores = (Arc<RwLock<DialogStore>>, Arc<RwLock<StreamStore>>);

fn stores() -> Stores {
    (
        Arc::new(RwLock::new(DialogStore::new(100, false))),
        Arc::new(RwLock::new(StreamStore::new(100))),
    )
}

/// An API state over `stores` that needs no credential.
fn api_state((ds, ss): Stores) -> ApiState {
    ApiState {
        relay_query: Default::default(),
        alias_thresholds: Default::default(),
        dialog_store: ds,
        stream_store: ss,
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(Default::default())),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1000, 1024))),
        max_inline_media_bytes: None,
        content_deny_header: None,
        max_rows: 50,
        capture: None,
        source_exhausted: None,
        capture_interfaces: Vec::new(),
        capture_meter: None,
        started_at: std::time::Instant::now(),
        persistence_gate: Arc::new(PersistenceGate::new(false)),
        tfps: Default::default(),
        actions: Default::default(),
        alert_engine: None,
        armed_detections: Vec::new(),
        scanner_response: Default::default(),
        file_root: None,
        vcon_spools: Vec::new(),
        vcon_fetch: Default::default(),
        live_audio: Arc::default(),
        pipeline_options: Default::default(),
        archive: sipnab::output::api::ArchivePasswordPolicy::default(),
    }
}

/// GET `uri` through the router: the status and the JSON body.
async fn get(state: &ApiState, uri: &str) -> Result<(StatusCode, Value), TestError> {
    let mut req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .map_err(|e| format!("build request: {e}"))?;
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        12345,
    )));
    let resp = build_router(state.clone())
        .oneshot(req)
        .await
        .map_err(|e| format!("oneshot: {e:?}"))?;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .map_err(|e| format!("body: {e}"))?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// The JSON payload block of an MCP tool result.
fn payload(result: &rmcp::model::CallToolResult) -> Result<Value, TestError> {
    let note = sipnab::mcp::shape::untrusted_note();
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.clone())
        .find(|t| *t != note)
        .ok_or("a payload block")?;
    Ok(serde_json::from_str(&text)?)
}

/// The names a `/v1/filters` (or `list_named_filters`) body lists.
fn listed(body: &Value) -> Vec<String> {
    body["filters"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Startup table, a publish, and what REST, MCP and every later compile
/// see.
#[tokio::test]
async fn a_published_name_is_used_at_once_by_rest_mcp_and_filters() -> Result<(), TestError> {
    let t = AliasThresholds::default();
    assert!(
        install(table(&[("big", "msg_count > 5")])?),
        "startup install"
    );
    let state = api_state(stores());

    // Before the save: no surface knows the name.
    let before = parse_filter("@large", &t)
        .err()
        .ok_or("@large must be unknown before the save")?
        .to_string();
    assert!(before.contains("big"), "lists the run's names: {before}");
    let (status, body) = get(&state, "/v1/dialogs?named=large").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown before: {body}");
    let (_, body) = get(&state, "/v1/filters").await?;
    assert_eq!(listed(&body), ["big"], "the startup list");

    // The save publishes the run's new table.
    publish(installed().with_added("large", "msg_count > 9", &t)?);

    // REST: listed with its definition, and selectable by name.
    let (status, body) = get(&state, "/v1/filters").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(listed(&body), ["big", "large"], "listed at once");
    assert_eq!(
        body["filters"][1]["definition"], "msg_count > 9",
        "the definition as saved"
    );
    let (status, body) = get(&state, "/v1/dialogs?named=large").await?;
    assert_eq!(status, StatusCode::OK, "named= takes it at once: {body}");
    let (status, body) = get(&state, "/v1/dialogs?filter=%40large").await?;
    assert_eq!(status, StatusCode::OK, "@large takes it at once: {body}");

    // MCP: the same list.
    let (ds, ss) = stores();
    let mcp = payload(
        &SipnabMcp::new(ds, ss)
            .list_named_filters()
            .await
            .map_err(|e| format!("list_named_filters: {e:?}"))?,
    )?;
    assert_eq!(listed(&mcp), ["big", "large"], "MCP lists it at once");

    // Every later compile resolves it.
    assert!(
        parse_filter("@large AND @big", &t).is_ok(),
        "the new name beside a startup name"
    );
    assert_eq!(
        resolve_filter_text("@large", &t),
        "(msg_count > 9)",
        "expanded to its definition"
    );

    // A second startup install cannot replace the live table.
    assert!(
        !install(table(&[("other", "msg_count > 1")])?),
        "install after start is refused"
    );
    assert!(
        parse_filter("@large", &t).is_ok(),
        "the published name survives a late install"
    );
    Ok(())
}
