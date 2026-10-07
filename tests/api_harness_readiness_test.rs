// SPDX-License-Identifier: MIT OR Apache-2.0

//! When the `ApiServer` harness calls a capture settled.
//!
//! The REST API serves while the capture file is still being read, so a test
//! that queries a freshly spawned server can see an empty store. The harness
//! used to wait for two identical `/v1/stats` reads. Under load the reader can
//! stall for longer than one poll interval before it has stored anything, so
//! two reads of an empty store matched and the harness returned early:
//! `every_stream_the_list_returns_can_be_fetched_by_its_own_id` then failed
//! with an empty stream list. `/v1/stats` reports `source_exhausted`, which
//! turns `true` once the reader has reached the end of the file, and the rule
//! now requires it.
#![cfg(feature = "api")]

#[path = "support/server.rs"]
mod server;

use serde_json::json;
use server::capture_settled;

use server::TestError;

/// Two identical reads of a file still being read: not settled.
#[test]
fn identical_reads_before_the_end_of_the_file_are_not_settled() -> Result<(), TestError> {
    let read = json!({ "source_exhausted": false, "dialogs": { "total": 0 } });
    assert!(!capture_settled(Some(&read), &read));
    Ok(())
}

/// The reader reached the end of the file and the store stopped changing.
#[test]
fn identical_reads_after_the_end_of_the_file_are_settled() -> Result<(), TestError> {
    let read = json!({ "source_exhausted": true, "dialogs": { "total": 1 } });
    assert!(capture_settled(Some(&read), &read));
    Ok(())
}

/// The reader reached the end of the file but the store is still changing.
#[test]
fn a_store_still_changing_after_the_end_of_the_file_is_not_settled() -> Result<(), TestError> {
    let before = json!({ "source_exhausted": true, "dialogs": { "total": 1 } });
    let after = json!({ "source_exhausted": true, "dialogs": { "total": 2 } });
    assert!(!capture_settled(Some(&before), &after));
    Ok(())
}

/// The first read has nothing to compare with.
#[test]
fn a_first_read_is_not_settled() -> Result<(), TestError> {
    let read = json!({ "source_exhausted": true });
    assert!(!capture_settled(None, &read));
    Ok(())
}

/// The real server, read to the end: the harness returns only once the
/// streams in the RTP fixture are in the store.
#[test]
fn a_spawned_server_has_read_its_whole_capture() -> Result<(), TestError> {
    let srv = server::ApiServer::spawn_with_pcap("tests/pcap-samples/sip-rtp-g711.pcap", &[])?;
    let stats: serde_json::Value = serde_json::from_str(&srv.get("/v1/stats")?.body)?;
    assert_eq!(stats["source_exhausted"], true, "{stats}");
    assert_eq!(stats["streams"]["total"], 2, "{stats}");
    Ok(())
}
