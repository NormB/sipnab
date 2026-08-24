// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a real vCon store REQUIRES, measured against one and held to here.
//!
//! `docs/design/vcon.md` §4a records a probe of a running backend on
//! 2026-08-24. Two of its findings are contracts an emitter can break silently,
//! and this file is the gate for both.
//!
//! # `uuid` and `created_at` are not optional
//!
//! The store answers **422** when any of `uuid`, `created_at` or `vcon` is
//! missing or malformed, and defaults everything else to an empty collection.
//!
//! A 422 is the worst outcome available, and not because of the status code.
//! The bridge's documented failure table retries a 5xx, a 429 and an
//! unreachable conserver, and **drops a 4xx** -- correctly, since retrying a
//! malformed container cannot help. So a missing field is not a delayed
//! delivery. The container is logged and gone, and the producer's own queue
//! shows it acknowledged.
//!
//! Sipnab guarantees all three, and this asserts it against a container built
//! from a real capture rather than a fixture.
//!
//! # The size ceiling is a fact about the CONSUMER, and it does not report
//!
//! The same probe sent a container carrying about 12 MB of inline base64. The
//! HTTP layer answered **204**, Postgres stored it, and the file spool rejected
//! it -- `16777749 > 10485760`. The bridge acknowledges on that 204, so the
//! message leaves the queue and neither transport surfaces the partial write.
//!
//! A producer is told "accepted" while a storage backend dropped the payload.
//! That makes the ceiling sipnab's to enforce, because the acknowledgement
//! cannot be trusted to carry the failure back -- which is why the constant
//! below lives here and is asserted rather than remembered.
//!
//! Phase 1 emits no media, so today's containers are far beneath it. The gate
//! exists now so that VCON9 cannot add media without meeting a number that was
//! measured rather than guessed.
#![cfg(feature = "vcon")]

use sipnab::analysis::CaptureFacts;
use sipnab::output::vcon::{ExportContext, VCON_SYNTAX_VERSION, export_dialog};
use sipnab::sip::dialog_store::DialogStore;

/// Path to a checked-in capture fixture.
fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Read a fixture capture and return the store plus the first `Call-ID` in it.
///
/// Driven through `capture::file` + `pipeline::classify_packet` rather than by
/// hand, so the dialog under test is the one sipnab's own ingest produces.
///
/// The STORE is returned rather than the dialog: `SipDialog` is deliberately
/// not `Clone` (it owns every retained message), so a borrow is the only way
/// out of the store that does not copy a ladder.
fn capture_of(capture: &str) -> (DialogStore, String) {
    use sipnab::capture::parse::parse_packet;
    use sipnab::pipeline::{self, PacketAction, PipelineOptions};
    use sipnab::rtp::heuristic::RtpHeuristic;

    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let files = vec![fixture(capture)];
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&files, &cfg, tx, None);
    });

    let mut store = DialogStore::new(10_000, true);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    while let Ok(pkt) = rx.recv_timeout(std::time::Duration::from_secs(60)) {
        let Ok(parsed) = parse_packet(&pkt) else {
            continue;
        };
        let mut decrypt = pipeline::MediaDecrypt::default();
        if let PacketAction::Sip { msg, .. } =
            pipeline::classify_packet(&parsed, &mut heuristic, &opts, &mut decrypt)
        {
            store.process_message(msg);
        }
    }
    let _ = reader.join();

    let call_id = store
        .iter()
        .next()
        .map(|d| d.call_id.clone())
        .expect("the fixture carries at least one dialog");
    (store, call_id)
}

/// A dialog off a real capture exports a container with every part Phase 1
/// promises, reachable entirely through the public API.

/// The largest encoded container the probed store accepted into EVERY backend.
///
/// 10 MiB, from the file spool's own refusal: `16777749 > 10485760`. Named
/// rather than inlined because the number is evidence, and a bare literal in an
/// assertion is a number nobody can trace back to the measurement that produced
/// it.
const STORE_CEILING_BYTES: usize = 10_485_760;

/// A container built from a real capture carries both required fields.
///
/// The store defaults everything else and answers 422 for these two. Asserted
/// on the SERIALIZED form, because that is what crosses the wire: a struct with
/// a populated field that serde skips is a struct that satisfies a Rust
/// assertion and fails at ingest.
#[test]
fn every_container_carries_the_two_fields_the_store_requires() {
    let (store, call_id) = capture_of("sip_call.pcap");
    let dialog = store.get(&call_id).expect("the dialog is retrievable");
    let facts = CaptureFacts::default();
    let vcon = export_dialog(
        dialog,
        &ExportContext {
            capture_id: "sip_call.pcap",
            facts: &facts,
            analysis: None,
        },
    );
    let json: serde_json::Value =
        serde_json::from_str(&vcon.to_json().expect("a container serializes"))
            .expect("valid JSON");

    let uuid = json["uuid"].as_str().expect("uuid is present and a string");
    // "Must parse as a UUID" is the store's rule, so check the SHAPE rather
    // than merely that the key exists. 8-4-4-4-12 hex, and a version nibble
    // that says 8 -- a uuid the store rejects is a container that never lands.
    let groups: Vec<&str> = uuid.split('-').collect();
    assert_eq!(groups.len(), 5, "uuid must be 8-4-4-4-12: {uuid}");
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "uuid group lengths are wrong: {uuid}"
    );
    assert!(
        uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
        "uuid must be hex and dashes: {uuid}"
    );
    assert_eq!(
        groups[2].as_bytes()[0], b'8',
        "the version nibble must say 8 (UUIDv8): {uuid}"
    );

    let created = json["created_at"]
        .as_str()
        .expect("created_at is present and a string");
    assert!(
        !created.is_empty(),
        "an empty created_at is a 422 at ingest, and an empty string satisfies \
         a presence check that only asks for the key"
    );

    // The THIRD required field. The probe's own table lists `vcon` alongside
    // `uuid` and `created_at`; everything else defaults to an empty collection.
    assert_eq!(
        json["vcon"], VCON_SYNTAX_VERSION,
        "the syntax version is required and must be the one this build emits: {json}"
    );
}

/// Two dialogs get two uuids, and one dialog gets one.
///
/// The half that discriminates. A container that always carried the same uuid
/// would pass the shape assertions above and then collide in the store, where
/// the second arrival either overwrites the first or is refused -- and either
/// way one capture's record is gone.
///
/// The stability half matters as much: the uuid is derived so that re-exporting
/// one dialog from one capture is idempotent. An emitter minting a fresh uuid
/// per call would make every re-export a new record.
#[test]
fn the_uuid_identifies_the_dialog_and_not_the_moment_of_export() {
    let (store, call_id) = capture_of("sip_call.pcap");
    let dialog = store.get(&call_id).expect("the dialog is retrievable");
    let facts = CaptureFacts::default();
    let ctx = |capture: &'static str| ExportContext {
        capture_id: capture,
        facts: &facts,
        analysis: None,
    };
    let uuid_of = |v: &sipnab::output::vcon::Vcon| {
        serde_json::from_str::<serde_json::Value>(&v.to_json().expect("serializes"))
            .expect("valid JSON")["uuid"]
            .as_str()
            .expect("uuid")
            .to_string()
    };

    let once = uuid_of(&export_dialog(dialog, &ctx("sip_call.pcap")));
    let again = uuid_of(&export_dialog(dialog, &ctx("sip_call.pcap")));
    assert_eq!(
        once, again,
        "one dialog from one capture must export under one uuid, or every \
         re-export becomes a separate record in the store"
    );

    // A different capture is a different observation of the same call, and the
    // store must be able to hold both.
    let elsewhere = uuid_of(&export_dialog(dialog, &ctx("some-other-capture.pcap")));
    assert_ne!(
        once, elsewhere,
        "two captures of one call must not collide on one uuid: the second to \
         arrive would overwrite or be refused, and one record would be lost"
    );
}

/// A signaling-only container is far beneath the store's silent ceiling.
///
/// The ceiling does not report. A container over it returns 204, lands in
/// Postgres, and is dropped by the file spool with nothing said to the
/// producer -- so the refusal has to happen here.
///
/// Phase 1 emits no media, so this passes with enormous headroom today. It is
/// written now because VCON9 adds inline base64 at four-thirds inflation, and a
/// ceiling discovered after that lands is a ceiling discovered from a support
/// ticket.
#[test]
fn a_signaling_only_container_is_far_beneath_the_store_ceiling() {
    let (store, call_id) = capture_of("sip_call.pcap");
    let dialog = store.get(&call_id).expect("the dialog is retrievable");
    let facts = CaptureFacts::default();
    let vcon = export_dialog(
        dialog,
        &ExportContext {
            capture_id: "sip_call.pcap",
            facts: &facts,
            analysis: None,
        },
    );
    let encoded = vcon.to_json().expect("a container serializes");

    assert!(
        encoded.len() < STORE_CEILING_BYTES,
        "a signaling-only container is {} bytes, at or over the {} byte ceiling \
         one probed store enforces in its file spool while answering 204. If \
         signaling alone can reach this, media certainly can, and the emitter \
         must refuse rather than trust the acknowledgement",
        encoded.len(),
        STORE_CEILING_BYTES
    );
    // Not vacuous: a container that serialized to nothing would satisfy the
    // bound above and be useless.
    assert!(
        encoded.len() > 200,
        "the container is {} bytes, which is too small to be a real one -- the \
         ceiling assertion above would pass for the wrong reason",
        encoded.len()
    );
}
