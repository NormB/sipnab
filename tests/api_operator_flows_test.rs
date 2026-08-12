// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every identifier the REST API RETURNS must work in the URL that takes it.
//!
//! # The gap this exists to close
//!
//! The API tests hit `/v1/dialogs/{id}` and `/v1/streams/{id}` — with a
//! hardcoded `CALL_ID` constant and an SSRC lifted from a fixture. No test ever
//! took an identifier out of a LIST response and put it in a DETAIL URL, which
//! is the only thing a client does: you fetch the collection, you follow a row.
//!
//! That seam is where identifiers get quietly mangled. A Call-ID contains `@`
//! and often `+`, `%` or `;`; a path segment is percent-decoded before it
//! reaches the handler. A list that emits one spelling and a detail route that
//! expects another gives a client 404s on rows the server just told it exist,
//! and no per-endpoint test can see it because each endpoint is correct in
//! isolation.
//!
//! The MCP surface had exactly this class of defect — `show_evidence` could not
//! follow a pointer another tool had just produced — and it read as covered.
//! This file is the REST half of the same property.

#![cfg(all(feature = "api", feature = "native"))]

#[path = "support/server.rs"]
mod server;

use server::ApiServer;

/// A capture with real dialogs AND real media, so both collections are non-empty.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
/// 1334 dialogs: the only fixture where paging is not a no-op.
const BRANCH: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";

/// Percent-encode a path segment the way a correct client must.
///
/// Call-IDs carry `@` routinely and may carry `;`, `+` or `/`. A client that
/// pastes one straight into a URL is wrong, so the test encodes — and that is
/// precisely why this seam needs covering: the list hands back a RAW id and the
/// route consumes an ENCODED one, so something has to agree about the mapping.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// **Follow a row.** Every Call-ID `/v1/dialogs` lists resolves on the detail
/// route, and on the report route beside it.
///
/// Asserted for EVERY row, not the first: a defect that only affects ids
/// carrying a particular character would hide behind a well-behaved first row.
#[test]
fn every_dialog_the_list_returns_can_be_fetched_by_its_own_id() {
    let srv = ApiServer::spawn_with_pcap(G711, &[]);

    let list = srv.get("/v1/dialogs");
    assert_eq!(list.status, 200, "/v1/dialogs must serve");
    let body = list.json();
    let rows = body["dialogs"].as_array().cloned().unwrap_or_default();
    assert!(
        !rows.is_empty(),
        "the fixture must produce dialogs or this proves nothing: {body}"
    );

    for row in &rows {
        let id = row["call_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a listed dialog carries no call_id: {row}"));
        let enc = encode_segment(id);

        for suffix in ["", "/report"] {
            let path = format!("/v1/dialogs/{enc}{suffix}");
            let resp = srv.get(&path);
            assert_eq!(
                resp.status, 200,
                "the list returned call_id '{id}', and GET {path} answered {}. \
                 A client can only follow what the collection hands it — an id \
                 that lists but does not fetch is a dead row.",
                resp.status
            );
        }
    }
}

/// **Follow a stream.** Every id `/v1/streams` lists resolves on its detail route.
#[test]
fn every_stream_the_list_returns_can_be_fetched_by_its_own_id() {
    let srv = ApiServer::spawn_with_pcap(G711, &[]);

    let list = srv.get("/v1/streams");
    assert_eq!(list.status, 200, "/v1/streams must serve");
    let body = list.json();
    let rows = body["streams"].as_array().cloned().unwrap_or_default();
    assert!(
        !rows.is_empty(),
        "the fixture must produce RTP streams or this proves nothing: {body}"
    );

    for row in &rows {
        // The detail route is keyed on the SSRC the list prints.
        let ssrc = row["ssrc"]
            .as_str()
            .unwrap_or_else(|| panic!("a listed stream carries no ssrc: {row}"));
        let path = format!("/v1/streams/{}", encode_segment(ssrc));
        let resp = srv.get(&path);
        assert_eq!(
            resp.status, 200,
            "the list returned ssrc '{ssrc}', and GET {path} answered {}. The \
             `0x` prefix the list prints has to be the spelling the route \
             accepts, or every client has to guess a transformation.",
            resp.status
        );
    }
}

/// **A dialog's stream and a stream's dialog agree.**
///
/// `/v1/streams` names an owning dialog in `associated_dialog`. That id must be
/// fetchable on the dialog route — the two collections have to describe one
/// world, or a client walking from media to signalling lands on a 404.
#[test]
fn a_stream_owning_dialog_is_fetchable_on_the_dialog_route() {
    let srv = ApiServer::spawn_with_pcap(G711, &[]);
    let streams = srv.get("/v1/streams").json();

    let mut checked = 0;
    for row in streams["streams"].as_array().cloned().unwrap_or_default() {
        let Some(owner) = row["associated_dialog"].as_str() else {
            continue; // an orphaned stream legitimately names no dialog
        };
        let path = format!("/v1/dialogs/{}", encode_segment(owner));
        let resp = srv.get(&path);
        assert_eq!(
            resp.status, 200,
            "a stream says it belongs to dialog '{owner}', and GET {path} \
             answered {}. Media and signalling must describe one capture.",
            resp.status
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no stream in the fixture named an owning dialog, so this test compared \
         nothing — pick a fixture where media is attributed"
    );
}

/// **Paging returns different rows, and `total` describes the filtered set.**
///
/// A `limit`/`offset` pair that is parsed and ignored gives page 2 == page 1,
/// which a client reads as "the capture is small" rather than "paging is
/// broken". The fixture is the 1334-dialog one because every smaller capture
/// fits in one page, where a broken pager and a correct one look identical.
#[test]
fn paging_advances_and_the_total_describes_what_is_being_paged() {
    let srv = ApiServer::spawn_with_pcap(BRANCH, &[]);

    let p1 = srv.get("/v1/dialogs?limit=5").json();
    let p2 = srv.get("/v1/dialogs?limit=5&offset=5").json();

    let ids = |v: &serde_json::Value| -> Vec<String> {
        v["dialogs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|d| d["call_id"].as_str().map(str::to_string))
            .collect()
    };
    let (a, b) = (ids(&p1), ids(&p2));
    assert_eq!(a.len(), 5, "limit=5 must return 5 rows: {p1}");
    assert!(!b.is_empty(), "offset=5 must return more rows: {p2}");
    assert!(
        a.iter().all(|id| !b.contains(id)),
        "offset did not advance — page 2 repeats page 1, which a client reads \
         as the end of the capture.\n  page 1: {a:?}\n  page 2: {b:?}"
    );

    let total = p1["total"].as_u64().unwrap_or(0);
    assert!(
        total > 5,
        "`total` must describe the whole matching set, not the page: {p1}"
    );
}

/// **An id that does not exist gets 404, not 200 with an empty body.**
///
/// The inverse property. Without it, every assertion above could be satisfied
/// by a route that answers 200 to anything, and "the row is fetchable" would
/// mean nothing at all.
#[test]
fn an_unknown_identifier_is_refused_rather_than_answered_emptily() {
    let srv = ApiServer::spawn_with_pcap(G711, &[]);
    for path in [
        "/v1/dialogs/definitely-not-a-call%40nowhere.invalid",
        "/v1/streams/0xDEADBEEF",
    ] {
        let resp = srv.get(path);
        assert_eq!(
            resp.status, 404,
            "GET {path} must 404. If unknown ids answered 200, every \
             follow-the-row test above would pass against a route that reads \
             nothing at all: got {}",
            resp.status
        );
    }
}
