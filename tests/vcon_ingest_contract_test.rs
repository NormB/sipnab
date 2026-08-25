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

mod support;

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
        serde_json::from_str(&vcon.to_json().expect("a container serializes")).expect("valid JSON");

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
        groups[2].as_bytes()[0],
        b'8',
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

/// An `encoding: "json"` body is a STRING, the way `base64url` bodies are.
///
/// Measured, not reasoned. A container exported from a committed fixture was
/// posted to a live conserver-backed store and read back: every attachment and
/// analysis body sipnab sent as a JSON OBJECT came back as a JSON STRING, with
/// the content identical once parsed.
///
/// The store is right and sipnab was wrong. `draft-ietf-vcon-vcon-core-03`
/// §2.3 pairs `body` with an `encoding` of `base64url`, `json` or `none`, and
/// that pairing only means anything if the body is a string the encoding tells
/// you how to read. sipnab already agreed with itself on half of it -- the
/// recording object's `base64url` body has always been a string -- and
/// disagreed on the other half.
///
/// The cost of the disagreement is not cosmetic. A consumer reaching for
/// `body.blind_spots` on an object gets a field; on a string it gets nothing,
/// with no error. The completeness caveat is the one thing §4 says a reader
/// must not miss, so a shape that silently fails the obvious access is the
/// worst possible field to be wrong about.
#[test]
fn a_json_body_is_a_string_a_consumer_parses() {
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
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");

    // Every array that can carry a body, `dialog` included: §2.3.2 makes `body`
    // a String whatever the encoding, so a media body must satisfy the rule
    // even though the `json` filter below never reaches it.
    let mut any_body = 0usize;
    for node in [&json["attachments"], &json["analysis"], &json["dialog"]] {
        for item in node.as_array().unwrap_or(&Vec::new()) {
            let Some(body) = item.get("body") else {
                continue;
            };
            any_body += 1;
            assert!(
                body.is_string(),
                "§2.3.2 makes `body` a String whatever the encoding, and this                  one is a {}: {item}",
                if body.is_object() {
                    "object"
                } else {
                    "non-string"
                }
            );
        }
    }
    assert!(
        any_body > 0,
        "no body was examined at all, so this test would pass against a          container that carried none: {json}"
    );

    let mut checked = 0usize;
    for (label, node) in [
        ("attachments", &json["attachments"]),
        ("analysis", &json["analysis"]),
    ] {
        for item in node.as_array().unwrap_or(&Vec::new()) {
            if item["encoding"] != "json" {
                continue;
            }
            checked += 1;
            let body = &item["body"];
            let text = body.as_str().unwrap_or_else(|| {
                panic!(
                    "{label} body declares `encoding: \"json\"` and is a {}, not a string. \
                     A store normalizes it to a string on the way in, so a consumer that \
                     reads it back gets a shape sipnab never sent: {item}",
                    if body.is_object() {
                        "object"
                    } else {
                        "non-string"
                    }
                )
            });
            // A string that is not parseable JSON would satisfy the assertion
            // above and be useless to the consumer it exists for.
            serde_json::from_str::<serde_json::Value>(text).unwrap_or_else(|e| {
                panic!("a `json`-encoded body must parse as JSON: {e}: {text}")
            });
        }
    }
    assert!(
        checked >= 2,
        "only {checked} json-encoded bodies were examined -- this container is \
         expected to carry the message trace, the completeness caveat and the \
         report, so the scan found less than it claims to check"
    );
}

/// Every container sipnab emits validates against the WORKING GROUP's schema.
///
/// The 100%-conformance gate, and it is a gate rather than a claim because the
/// schema is machine-checkable. `tests/schemas/vcon.schema.json` is
/// `https://ietf.org/vcon/schemas/unsigned-vcon.json`, committed so this runs
/// with no network and cannot silently start passing because a fetch failed.
///
/// It earns its place. Running it the first time found SIX violations in a
/// container that every hand-written test in this repository already passed:
/// both attachments were missing the required `start` and `dialog`, and the
/// Dialog Object was missing the required `type` and `start`. None of it was
/// reachable by reading the prose, because the prose blesses an empty Dialog
/// Object (§4.3) that the schema rejects.
///
/// Where they disagree, this repository satisfies BOTH where it can and the
/// SCHEMA where it cannot: a consumer validating a container is the reader who
/// actually rejects it, and being right about the prose is no comfort when the
/// container bounces.
#[test]
fn a_container_validates_against_the_working_group_schema() {
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
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");

    let validator = support::schema::load_validator("vcon.schema.json");
    support::schema::assert_valid(&validator, &json, "signaling-only vCon");
}

/// An object typed `recording` always carries content a consumer can reach.
///
/// This guards a SIGNALING-ONLY container, which is the case where the hazard
/// lives: a container that carries audio has a body on every object by
/// construction, so the same assertion over a media fixture passes vacuously.
/// A mutation that types the signaling object `recording` survives there and
/// dies here.
///
/// The failure is not cosmetic. A conserver chain link that selects
/// `type == "recording"` reads `dialog["url"]` with a bracket rather than a
/// `get`; an object typed `recording` with neither `url` nor `body` raises
/// inside the link, and the conserver moves the WHOLE container to the
/// dead-letter queue — not just the step that raised.
#[test]
fn nothing_is_typed_a_recording_without_content_to_reach() {
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
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");

    let objects = json["dialog"].as_array().expect("dialog is an array");
    assert!(
        !objects.is_empty(),
        "no dialog object at all, so this test would pass against a container \
         that described nothing: {json}"
    );
    for object in objects {
        if object["type"] == "recording" {
            assert!(
                object.get("body").is_some() || object.get("url").is_some(),
                "typed `recording` with neither `body` nor `url`: a consumer \
                 that reaches for the content finds none, and the conserver \
                 dead-letters the container: {object}"
            );
        }
    }
}

/// The caller party's `sip` and `tel`, for one synthetic `From` user part.
///
/// Goes through the public export rather than calling the URI helper, so a
/// helper that is right while nothing wires it up cannot pass.
fn party_sip_and_tel(from_user: &str) -> (Option<String>, Option<String>) {
    use sipnab::net::TransportProto;
    use sipnab::sip::parser::parse_sip;

    let raw = format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         From: <sip:{from_user}@example.com>;tag=caller-tag\r\n\
         To: <sip:bob@example.net>\r\n\
         Call-ID: tel-fixture@example.com\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let mut store = DialogStore::new(8, true);
    store.process_message(
        parse_sip(
            raw.as_bytes(),
            chrono::Utc::now(),
            "10.0.0.1".parse().expect("a caller address"),
            "10.0.0.2".parse().expect("a callee address"),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("the INVITE fixture parses"),
    );
    let dialog = store.iter().next().expect("the fixture produced a dialog");
    let facts = CaptureFacts::default();
    let vcon = export_dialog(
        dialog,
        &ExportContext {
            capture_id: "tel-fixture",
            facts: &facts,
            analysis: None,
        },
    );
    let json: serde_json::Value =
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");
    let caller = &json["parties"][0];
    (
        caller["sip"].as_str().map(str::to_string),
        caller
            .get("tel")
            .and_then(|t| t.as_str())
            .map(str::to_string),
    )
}

/// A global number reaches the conserver's party index; an extension does not.
///
/// Both directions matter and the failure case is the important one. The
/// conserver indexes parties by `tel`, `mailto` and `name` only, so a `tel`
/// makes a container findable — but a SIP user part of `1001` is an extension,
/// not a telephone number, and indexing it as one puts a WRONG answer in a
/// search index rather than no answer.
#[test]
fn a_tel_is_emitted_for_a_global_number_and_never_invented_from_an_extension() {
    // Success: a global number, and the container becomes findable.
    let global = party_sip_and_tel("+14155550123");
    assert_eq!(
        global.1,
        Some("tel:+14155550123".to_string()),
        "an RFC 3966 global number must reach the conserver's party index"
    );

    // Failure: everything that is not unambiguously a telephone number.
    for not_a_number in ["1001", "alice", "+", "+1415call", "+1-415-555-0123"] {
        let (sip, tel) = party_sip_and_tel(not_a_number);
        assert_eq!(
            tel, None,
            "`{not_a_number}` is not an RFC 3966 global number; emitting a \
             `tel` for it indexes a wrong answer. sip was {sip:?}"
        );
    }
}

/// The observer is never indexable as a party to the call.
#[test]
fn the_observer_carries_no_tel() {
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
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");
    let parties = json["parties"].as_array().expect("parties is an array");
    let observer = parties
        .iter()
        .find(|p| p.get("role").is_some())
        .expect("the observer party is present");
    assert!(
        observer.get("tel").is_none(),
        "the observer is not reachable at a number, and supplying one enters \
         sipnab in the conserver's party index as a participant: {observer}"
    );
}

/// The dialog object names the tags that tell forked legs apart.
///
/// A Call-ID does not: every fork of one INVITE shares it. sipnab has held
/// both tags all along.
#[test]
fn the_dialog_object_names_the_tags_that_distinguish_a_forked_leg() {
    let (store, call_id) = capture_of("sip_call.pcap");
    let dialog = store.get(&call_id).expect("the dialog is retrievable");
    let expected_from = dialog.from_tag.clone();
    let expected_to = dialog.to_tag.clone();
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
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");
    let object = &json["dialog"][0];

    assert!(
        expected_from.is_some(),
        "this fixture must carry a From tag, or the assertion below passes \
         vacuously and the field could be dropped without a test noticing"
    );
    assert_eq!(
        object["sip_from_tag"].as_str().map(str::to_string),
        expected_from,
        "the container must carry the From tag the capture observed: {object}"
    );
    assert_eq!(
        object["sip_to_tag"].as_str().map(str::to_string),
        expected_to,
        "the container must carry the To tag the capture observed: {object}"
    );
}

/// Two dialogs opening in the same millisecond on one node get DIFFERENT uuids.
///
/// §4.1.2 makes the uuid globally unique, and a store keys on it: a collision
/// does not error anywhere, it OVERWRITES the record already there and one
/// capture is silently lost.
///
/// The two Call-IDs below are not arbitrary. They were found by brute force
/// because they land in the same 12-bit bucket, which was the only entropy the
/// identifier carried for a given node and millisecond — the other 62 bits
/// were a digest of the node name alone, identical for every dialog on the
/// box. Roughly one pair in 4096 collided.
///
/// The precondition is asserted rather than assumed: if the seed ever changes
/// so these two stop sharing a bucket, this test would pass while testing
/// nothing, so it fails loudly instead.
#[test]
fn two_dialogs_in_one_millisecond_on_one_node_get_different_uuids() {
    const CAPTURE: &str = "collision.pcap";
    const A: &str = "call-82@example.com";
    const B: &str = "call-110@example.com";

    assert_eq!(
        legacy_bucket(A, CAPTURE),
        legacy_bucket(B, CAPTURE),
        "these Call-IDs were chosen because they SHARE the 12-bit bucket that \
         used to be the identifier's only entropy. They no longer do, so this \
         test proves nothing — find a fresh colliding pair rather than \
         deleting the assertion."
    );

    let at = one_instant();
    let a = uuid_of(A, CAPTURE, at);
    let b = uuid_of(B, CAPTURE, at);
    assert_ne!(
        a, b,
        "two dialogs, one node, one millisecond, one identifier: a store \
         keyed on it keeps ONE of these captures and reports no error"
    );
}

/// The identifier is still a function of the dialog, not of the moment.
///
/// The fix above must not be bought with randomness: re-exporting one dialog
/// has to keep its identifier, or a store sees a second copy rather than the
/// same record.
#[test]
fn one_dialog_exported_twice_keeps_one_uuid() {
    let at = one_instant();
    assert_eq!(
        uuid_of("stable@example.com", "same.pcap", at),
        uuid_of("stable@example.com", "same.pcap", at),
        "the identifier must be derived, never minted"
    );
    assert_ne!(
        uuid_of("stable@example.com", "same.pcap", at),
        uuid_of("stable@example.com", "other.pcap", at),
        "the capture the dialog came from is part of its identity"
    );
}

/// The 12-bit bucket the identifier used to depend on, computed independently.
///
/// Deliberately NOT calling into the exporter: a helper that shared its code
/// would agree with it however the exporter changed.
fn legacy_bucket(call_id: &str, capture_id: &str) -> u16 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(call_id.as_bytes());
    h.update([0x1e]);
    h.update(capture_id.as_bytes());
    let d = h.finalize();
    u16::from_be_bytes([d[0], d[1]]) >> 4
}

/// One fixed instant, so every dialog in these tests shares a millisecond.
fn one_instant() -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_millis_opt(1_700_000_000_123)
        .single()
        .expect("a valid instant")
}

/// The uuid of a one-message dialog, through the public export.
fn uuid_of(call_id: &str, capture_id: &str, at: chrono::DateTime<chrono::Utc>) -> String {
    use sipnab::net::TransportProto;
    use sipnab::sip::parser::parse_sip;

    let raw = format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         From: <sip:alice@example.com>;tag=caller-tag\r\n\
         To: <sip:bob@example.net>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let mut store = DialogStore::new(8, true);
    store.process_message(
        parse_sip(
            raw.as_bytes(),
            at,
            "10.0.0.1".parse().expect("a caller address"),
            "10.0.0.2".parse().expect("a callee address"),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("the INVITE fixture parses"),
    );
    let dialog = store.iter().next().expect("the fixture produced a dialog");
    let facts = CaptureFacts::default();
    let vcon = export_dialog(
        dialog,
        &ExportContext {
            capture_id,
            facts: &facts,
            analysis: None,
        },
    );
    let json: serde_json::Value =
        serde_json::from_str(&vcon.to_json().expect("serializes")).expect("valid JSON");
    json["uuid"].as_str().expect("a uuid").to_string()
}
