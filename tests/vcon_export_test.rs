// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vCon export, driven the way a library consumer drives it.
//!
//! The unit tests in `src/output/vcon.rs` reach private helpers and hand-built
//! [`CaptureFacts`]. This binary proves two things they structurally cannot:
//!
//! * the whole export is reachable through the crate's PUBLIC surface — a
//!   `pub fn` returning a type whose fields are `pub(crate)` compiles fine and
//!   is unusable, and this repository has shipped a handler that was correct
//!   and never wired into the binary;
//! * a container built from a dialog that came off a REAL capture — parsed
//!   packets, a real ladder, a real `Call-ID` — carries what the fixture-built
//!   ones carry. A projection can agree with a synthetic dialog and disagree
//!   with the parser.
//!
//! The whole file is gated: `vcon` is a non-default feature, so without it
//! there is nothing here to build.

#![cfg(feature = "vcon")]

use sipnab::analysis::CaptureFacts;
use sipnab::output::vcon::{
    COMPLETENESS_PURPOSE, CREDENTIAL_HEADERS, ExportContext, MESSAGE_TRACE_PURPOSE,
    VCON_SYNTAX_VERSION, export_dialog,
};
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
#[test]
fn a_real_capture_exports_a_complete_signaling_only_container() {
    let (store, call_id) = capture_of("sip_call.pcap");
    let dialog = store.get(&call_id).expect("the dialog is retrievable");
    let facts = CaptureFacts {
        frames_read: 42,
        ..CaptureFacts::default()
    };
    let vcon = export_dialog(
        dialog,
        &ExportContext {
            capture_id: "sip_call.pcap",
            facts: &facts,
            max_inline_media_bytes: None,
            analysis: None,
        },
    );

    let json = vcon.to_json().expect("a container serializes");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    assert_eq!(v["vcon"], VCON_SYNTAX_VERSION);
    // `CC` rides beside `sip-signaling` because `Party.role` is a CC-extension
    // parameter, not one of the thirteen core-03 §4.2 defines. A container that
    // uses the field must declare what defines it.
    assert_eq!(v["extensions"], serde_json::json!(["sip-signaling", "CC"]));
    assert!(v["uuid"].as_str().is_some_and(|u| u.len() == 36));
    assert!(v["created_at"].as_str().is_some());

    // Parties: the observed two, then the observer. A `name` may appear, and
    // `validation: "none"` is what keeps it readable as what a header said
    // rather than as an identity anyone established.
    let parties = v["parties"].as_array().expect("parties");
    assert_eq!(parties.len(), 3);
    for party in parties {
        assert_eq!(party["validation"], "none");
        assert!(
            party.get("validation").is_some(),
            "a party carrying a name without its disclaimer asserts an \
             identity: {party}"
        );
    }
    assert!(
        parties[2].get("name").is_none(),
        "the observer is not a named participant: {}",
        parties[2]
    );
    assert_eq!(vcon.observer_index(), 2);
    assert_eq!(parties[2]["role"], "observer");

    // The dialog object names the call it came from.
    assert_eq!(v["dialog"][0]["sip_call_id"], dialog.call_id);

    // Both attachments, both attributed to the observer.
    let attachments = v["attachments"].as_array().expect("attachments");
    assert_eq!(attachments.len(), 2);
    for attachment in attachments {
        assert_eq!(attachment["party"], 2);
    }
    assert_eq!(attachments[0]["purpose"], MESSAGE_TRACE_PURPOSE);
    assert_eq!(attachments[1]["purpose"], COMPLETENESS_PURPOSE);
    assert_eq!(
        body_of(&attachments[0])["messages"]
            .as_array()
            .map(Vec::len)
            .unwrap_or_default(),
        dialog.messages.len(),
        "the trace lost or duplicated a message from a real ladder"
    );

    // One report, carrying the caveat the attachment carries.
    assert_eq!(v["analysis"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        body_of(&v["analysis"][0])["capture_completeness"],
        body_of(&attachments[1]),
        "the two completeness surfaces describe one capture and must agree"
    );

    // No credential, and nothing signed.
    let lowered = json.to_ascii_lowercase();
    for header in CREDENTIAL_HEADERS {
        assert!(
            !lowered.contains(header),
            "{header} reached a container built to be handed to somebody else"
        );
    }
    for banned in ["signatures", "payload", "protected", "consent"] {
        assert!(
            v.get(banned).is_none(),
            "an observer vCon must carry no {banned}"
        );
    }
    // `subject` is emitted, and bounded rather than banned: it names the
    // dialog so a store can find the container by an identifier an operator
    // has, and it must carry no verdict about the call -- those belong on the
    // two completeness surfaces asserted above.
    let subject = v["subject"].as_str().expect("a subject is present");
    assert!(
        subject.contains(&dialog.call_id),
        "the subject must identify the dialog it stands for: {subject:?}"
    );
    for verdict in ["SIGNALING ONLY", "incomplete", "PARTIAL", "failed"] {
        assert!(
            !subject.contains(verdict),
            "the subject carries a verdict ({verdict:?}) that belongs on the \
             completeness surfaces: {subject:?}"
        );
    }
}

/// Two exports of one dialog from one capture agree on the uuid, and a
/// different capture id does not.
///
/// Re-stated here against a REAL dialog because idempotency is the property a
/// consumer deduplicating on `uuid` depends on, and the unit test proves it
/// only for a hand-built fixture whose `created_at` is a literal.
#[test]
fn re_exporting_one_dialog_from_one_capture_keeps_its_identifier() {
    let (store, call_id) = capture_of("sip_call.pcap");
    let dialog = store.get(&call_id).expect("the dialog is retrievable");
    let facts = CaptureFacts::default();
    let export = |capture_id: &str| {
        export_dialog(
            dialog,
            &ExportContext {
                capture_id,
                facts: &facts,
                max_inline_media_bytes: None,
                analysis: None,
            },
        )
        .uuid
    };

    assert_eq!(export("sip_call.pcap"), export("sip_call.pcap"));
    assert_ne!(
        export("sip_call.pcap"),
        export("a-different-capture.pcap"),
        "one dialog observed in two captures must not share an identifier"
    );
}

/// A `json`-encoded body, parsed.
///
/// §2.3.2 makes `body` a STRING, so every read of one goes through here rather
/// than indexing a `Value` that is not an object. The conserver's own model
/// says the same in a comment: a caller handing it a dict gets it JSON-encoded
/// before anything else touches the attachment.
fn body_of(node: &serde_json::Value) -> serde_json::Value {
    let text = node["body"]
        .as_str()
        .unwrap_or_else(|| panic!("a json body must be a string: {node}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("body must parse: {e}: {text}"))
}
