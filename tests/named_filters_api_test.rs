// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Named filters over REST and MCP, with a `[filters]` table installed.
//!
//! The lib tests run with the process's installed table empty, so they can
//! drive `named` only with the built-in aliases. This binary installs a table
//! the way startup does (`named_filters::install`, once, first call wins) and
//! drives the REST router and the MCP tools against it: the list answers, a
//! `named` selection equals the `@name` selection, and an unknown name's
//! refusal lists the names the table defines. Every test installs the same
//! table, so the order the tests run in does not matter.

#![cfg(all(feature = "api", feature = "mcp", feature = "vcon"))]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use parking_lot::{Mutex, RwLock};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use tower::ServiceExt;

use sipnab::mcp::SipnabMcp;
use sipnab::mcp::server::ListDialogsParams;
use sipnab::output::api::{ApiState, RateLimiter, build_router};
use sipnab::output::persistence::PersistenceGate;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::dsl::AliasThresholds;
use sipnab::sip::named_filters::{self, NamedFilters};

type TestError = Box<dyn std::error::Error>;

/// The table every test installs: one entry, one that references it, and
/// one that references a built-in alias.
const TABLE: [(&str, &str); 3] = [
    ("bad-media", "@one-way OR rtp.loss > 5.0"),
    ("sales", "to.user =~ '^5550'"),
    ("sales-failed", "@sales AND response_code >= 400"),
];

/// Install [`TABLE`] for this process. The first call installs it; a later
/// call finds the same table there.
fn install_table() -> Result<&'static NamedFilters, TestError> {
    let defs = TABLE
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let resolved = NamedFilters::resolve(&defs, &AliasThresholds::default())?;
    named_filters::install(resolved.clone());
    let installed = named_filters::installed();
    assert_eq!(*installed, resolved, "this binary installs one table");
    Ok(installed)
}

/// One INVITE and its final response, from `from_user` to `to_user`.
fn call(ds: &mut DialogStore, call_id: &str, to_user: &str, code: u16) -> Result<(), TestError> {
    let at = chrono::DateTime::from_timestamp(1_718_452_800, 0).ok_or("an instant")?;
    let host = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
    let peer = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 20));
    let invite = format!(
        "INVITE sip:{to_user}@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{call_id}\r\n\
         From: <sip:alice@example.com>;tag=f-{call_id}\r\n\
         To: <sip:{to_user}@example.com>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let reply = format!(
        "SIP/2.0 {code} Reason\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{call_id}\r\n\
         From: <sip:alice@example.com>;tag=f-{call_id}\r\n\
         To: <sip:{to_user}@example.com>;tag=t-{call_id}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    for (raw, src, dst) in [(invite, host, peer), (reply, peer, host)] {
        let msg = sipnab::sip::parser::parse_sip(
            raw.as_bytes(),
            at,
            src,
            dst,
            5060,
            5060,
            sipnab::capture::parse::TransportProto::Udp,
        )
        .map_err(|e| format!("the fixture parses: {e:?}"))?;
        ds.process_message(msg);
    }
    Ok(())
}

/// The dialog and stream stores both surfaces read.
type Stores = (Arc<RwLock<DialogStore>>, Arc<RwLock<StreamStore>>);

/// Stores holding four calls: two to `5550` numbers (one failed), two not.
fn stores() -> Result<Stores, TestError> {
    let mut ds = DialogStore::new(100, false);
    call(&mut ds, "sale-ok@example.com", "5550100", 200)?;
    call(&mut ds, "sale-busy@example.com", "5550101", 486)?;
    call(&mut ds, "other-ok@example.com", "5551234", 200)?;
    call(&mut ds, "other-busy@example.com", "5551235", 486)?;
    Ok((
        Arc::new(RwLock::new(ds)),
        Arc::new(RwLock::new(StreamStore::new(100))),
    ))
}

/// An API state over `ds` and `ss` that needs no credential.
fn api_state(ds: Arc<RwLock<DialogStore>>, ss: Arc<RwLock<StreamStore>>) -> ApiState {
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

/// Percent-encode a query value.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
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

/// The Call-IDs of a `/v1/dialogs` body, sorted.
fn call_ids(body: &Value) -> Vec<String> {
    let mut ids: Vec<String> = body["dialogs"]
        .as_array()
        .map(|d| {
            d.iter()
                .filter_map(|r| r["call_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

#[tokio::test]
async fn rest_lists_the_installed_table_as_written() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let (status, body) = get(&api_state(ds, ss), "/v1/filters").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let want: Vec<Value> = TABLE
        .iter()
        .map(|(n, d)| serde_json::json!({"name": n, "definition": d}))
        .collect();
    assert_eq!(
        body["filters"],
        Value::Array(want),
        "name order, as written"
    );
    Ok(())
}

#[tokio::test]
async fn rest_named_selects_what_the_reference_selects() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let state = api_state(ds, ss);
    for name in ["sales", "sales-failed", "bad-media"] {
        let (s1, by_name) = get(&state, &format!("/v1/dialogs?named={name}")).await?;
        let (s2, by_ref) = get(
            &state,
            &format!("/v1/dialogs?filter={}", encode(&format!("@{name}"))),
        )
        .await?;
        assert_eq!(
            (s1, s2),
            (StatusCode::OK, StatusCode::OK),
            "{by_name} {by_ref}"
        );
        assert_eq!(call_ids(&by_name), call_ids(&by_ref), "named={name}");
    }
    Ok(())
}

#[tokio::test]
async fn rest_named_sales_selects_the_two_sales_calls() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let (_, body) = get(&api_state(ds, ss), "/v1/dialogs?named=sales").await?;
    assert_eq!(
        call_ids(&body),
        vec!["sale-busy@example.com", "sale-ok@example.com"],
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn rest_named_follows_a_nested_reference() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let (_, body) = get(&api_state(ds, ss), "/v1/dialogs?named=sales-failed").await?;
    assert_eq!(call_ids(&body), vec!["sale-busy@example.com"], "{body}");
    Ok(())
}

#[tokio::test]
async fn rest_named_narrows_every_filter_route() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let state = api_state(ds, ss);
    for (route, count) in [
        ("/v1/aggregate?by=state&", "total_matched"),
        ("/v1/dialogs/rates?by=method&", "total_matched"),
        ("/v1/talkers?by=ip&", "total_matched"),
    ] {
        let (status, body) = get(&state, &format!("{route}named=sales")).await?;
        assert_eq!(status, StatusCode::OK, "{route}: {body}");
        assert_eq!(body[count], 2, "{route}: the two sales calls: {body}");
    }
    Ok(())
}

#[tokio::test]
async fn rest_unknown_name_lists_the_defined_names() -> Result<(), TestError> {
    let table = install_table()?;
    let (ds, ss) = stores()?;
    let (status, body) = get(&api_state(ds, ss), "/v1/dialogs?named=support").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["detail"],
        format!(
            "named: {}",
            named_filters::unknown_reference_message("support", table)
        ),
        "the reason"
    );
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("bad-media, sales, sales-failed")),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn rest_validation_resolves_the_installed_names() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let state = api_state(ds, ss);
    let (_, ok) = get(
        &state,
        &format!("/v1/filters/validate?expr={}", encode("@sales-failed")),
    )
    .await?;
    assert_eq!(ok["valid"], true, "{ok}");
    let (_, bad) = get(
        &state,
        &format!("/v1/filters/validate?expr={}", encode("@sales )")),
    )
    .await?;
    assert_eq!(bad["valid"], false, "{bad}");
    assert_eq!(
        bad["position"],
        Value::Null,
        "a column in the expansion: {bad}"
    );
    Ok(())
}

#[tokio::test]
async fn mcp_lists_what_rest_lists() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let (_, rest) = get(&api_state(Arc::clone(&ds), Arc::clone(&ss)), "/v1/filters").await?;
    let mcp = payload(
        &SipnabMcp::new(ds, ss)
            .list_named_filters()
            .await
            .map_err(|e| format!("list_named_filters: {e:?}"))?,
    )?;
    assert_eq!(mcp, rest, "one answer on both surfaces");
    Ok(())
}

#[tokio::test]
async fn mcp_named_selects_what_the_reference_selects() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let srv = SipnabMcp::new(ds, ss);
    let by_name = payload(
        &srv.list_dialogs(Parameters(ListDialogsParams {
            named: Some("sales".into()),
            ..Default::default()
        }))
        .await
        .map_err(|e| format!("named: {e:?}"))?,
    )?;
    let by_ref = payload(
        &srv.list_dialogs(Parameters(ListDialogsParams {
            filter: Some("@sales".into()),
            ..Default::default()
        }))
        .await
        .map_err(|e| format!("filter: {e:?}"))?,
    )?;
    assert_eq!(
        by_name["total_matched"], 2,
        "the two sales calls: {by_name}"
    );
    assert_eq!(by_name, by_ref, "named=sales is filter=@sales");
    Ok(())
}

#[tokio::test]
async fn mcp_unknown_name_offers_the_defined_names() -> Result<(), TestError> {
    install_table()?;
    let (ds, ss) = stores()?;
    let e = match SipnabMcp::new(ds, ss)
        .list_dialogs(Parameters(ListDialogsParams {
            named: Some("support".into()),
            ..Default::default()
        }))
        .await
    {
        Ok(r) => return Err(format!("answered: {:?}", payload(&r)).into()),
        Err(e) => e,
    };
    let data = e.data.ok_or("data")?;
    let values: Vec<&str> = data["valid_values"]
        .as_array()
        .ok_or("valid_values")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        values.get(..3),
        Some(&["bad-media", "sales", "sales-failed"][..]),
        "the table's names first: {data}"
    );
    assert!(values.contains(&"problems"), "then the aliases: {data}");
    Ok(())
}
