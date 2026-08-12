// SPDX-License-Identifier: MIT OR Apache-2.0

// The file reader, the resolver, the pipeline and `output::model` are all
// behind `native`. Gating the whole file is right here rather than gating
// items: every test in it reads a capture off disk, so under a build without
// `native` there is nothing left to check.
#![cfg(feature = "native")]

//! Stage 4 of #128: the surfaces emit the frame pointer.
//!
//! Stages 1-3 got a resolvable pointer as far as `SipMessage`. That is invisible
//! to every consumer -- `--json-dialogs`, `--report`, REST and MCP all project a
//! dialog through `DialogSummary`, and it had no way to say which frame the
//! dialog opened in. A pointer nothing emits is a pointer nobody can follow.
//!
//! One field on `DialogSummary` reaches all four surfaces, because they share
//! that projection: `tui::save` for `--json-dialogs`, `output::api::dialog_summary`
//! for REST, and `mcp::server` re-exports the same type.
//!
//! The design constraint that shapes this is the honesty rule: a pointer that
//! resolves to the *wrong* frame is worse than no pointer, because it
//! manufactures confidence. Two ways that could happen here, and both are
//! tested rather than argued:
//!
//! 1. Deriving the pointer from `d.messages.first()`. Compaction keeps *anchor*
//!    messages, not position 0, so after it runs `messages.first()` can be a
//!    later message. The dialog would then cite a real frame that is not the
//!    one it opened in. The code stores the pointer at creation instead, for
//!    the same reason `src_port` is stored rather than re-read.
//! 2. Emitting a placeholder when there is no frame. An empty string or a zero
//!    ordinal both read as a genuine pointer to frame 0, so the key is omitted
//!    entirely.
//!
//! Media streams arrived later and are held to exactly the same two rules. A
//! stream is not a child of a dialog in this tree (design decision D13), so it
//! could not borrow the dialog's pointer even where one exists — and the
//! orphaned streams, the ones no `Call-ID` explains, are precisely the streams
//! an operator most needs to trace back to the wire.

use sipnab::capture::packet::Packet;
use sipnab::capture::resolve::{parse_pointer, resolve};
use sipnab::output::json::stream_to_json;
use sipnab::output::model::{DialogSummary, StreamSummary};
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::{DialogStore, idle_compact_after, keep_messages_per_idle_dialog};

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// The three checked-in fixtures carry signalling only, so the media half of
/// this suite reads from the synthetic sample corpus instead.
fn sample(name: &str) -> String {
    format!("{}/tests/pcap-samples/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Read every packet through the real file reader, in order, so ordinals here
/// are the ordinals production would assign.
fn read_all(path: &str) -> Vec<Packet> {
    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = vec![std::path::PathBuf::from(path)];
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&owned, &cfg, tx, None);
    });
    let mut out = Vec::new();
    while let Ok(p) = rx.recv_timeout(std::time::Duration::from_secs(60)) {
        out.push(p);
    }
    reader.join().expect("file reader thread");
    out
}

/// Feed a capture through the real classification path into a store, so the
/// dialogs under test are built the way production builds them.
///
/// `strip_origin` drops each packet's `FrameOrigin` before parsing, which is
/// the state live capture leaves packets in: bytes, no file position to point
/// back to. It exercises the real no-provenance path rather than reaching in
/// and blanking a field afterwards.
fn store_with(path: &str, strip_origin: bool) -> DialogStore {
    use sipnab::capture::parse::parse_packet;
    use sipnab::pipeline::{self, PacketAction, PipelineOptions};
    use sipnab::rtp::heuristic::RtpHeuristic;

    let mut store = DialogStore::new(100_000, false);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    for mut pkt in read_all(path) {
        if strip_origin {
            pkt.origin = None;
        }
        let Ok(pp) = parse_packet(&pkt) else { continue };
        let mut decrypt = pipeline::MediaDecrypt::default();
        if let PacketAction::Sip { msg, .. } =
            pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt)
        {
            store.process_message(msg);
        }
    }
    store
}

fn store_from(path: &str) -> DialogStore {
    store_with(path, false)
}

/// The media analogue of [`store_with`]: the same real classification path,
/// applied to a stream store instead of a dialog store.
///
/// Deliberately not `pipeline::process_packet`, which would need the two
/// `Arc<RwLock<_>>` stores and a dialog store this suite has no use for. The
/// classification is the part under test — everything a stream knows about its
/// provenance has to survive `classify_packet` and `process_rtp`.
fn stream_store_with(path: &str, strip_origin: bool) -> StreamStore {
    use sipnab::capture::parse::parse_packet;
    use sipnab::pipeline::{self, PacketAction, PipelineOptions};
    use sipnab::rtp::heuristic::RtpHeuristic;

    let mut store = StreamStore::new(100_000);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    for mut pkt in read_all(path) {
        if strip_origin {
            pkt.origin = None;
        }
        let Ok(pp) = parse_packet(&pkt) else { continue };
        let mut decrypt = pipeline::MediaDecrypt::default();
        if let PacketAction::Rtp { hdr, .. } =
            pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt)
        {
            store.process_rtp(&pp, &hdr, pp.timestamp);
        }
    }
    store
}

/// The dialog knows where it began.
#[test]
fn a_dialog_records_the_frame_it_opened_in() {
    let store = store_from(&fixture("sip_call.pcap"));
    let dialogs: Vec<_> = store.iter().collect();
    assert!(
        !dialogs.is_empty(),
        "fixture produced no dialogs -- this suite would prove nothing"
    );
    for d in &dialogs {
        assert!(
            d.first_frame.is_some(),
            "a dialog built from a capture file must know its opening frame; \
             call_id={}",
            d.call_id
        );
    }
}

/// The whole point: the emitted pointer leads back to the right bytes.
///
/// Asserts the round trip rather than the presence of a string. A populated
/// field pointing one frame off would satisfy `is_some()` and be exactly the
/// failure this feature exists to prevent.
#[test]
fn the_summary_pointer_resolves_to_the_frame_the_dialog_opened_in() {
    let path = fixture("sip_call.pcap");
    let packets = read_all(&path);
    let store = store_from(&path);

    let mut checked = 0;
    for d in store.iter() {
        let summary = DialogSummary::from(d);
        let pointer = summary
            .frame
            .as_ref()
            .unwrap_or_else(|| panic!("summary carried no frame for {}", d.call_id));

        let got = resolve(&parse_pointer(pointer).expect("the emitted pointer must parse"))
            .expect("the emitted pointer must resolve");
        assert!(
            got.is_verified(),
            "the reader recorded a digest, so a followed pointer must verify"
        );

        // The frame it resolves to must be the one the opening message was
        // parsed from -- compare bytes, not ordinals, so an off-by-one in the
        // ordinal cannot pass by matching itself.
        let ordinal = d
            .first_frame
            .as_ref()
            .expect("first_frame present")
            .origin
            .ordinal as usize;
        assert_eq!(
            got.bytes(),
            &packets[ordinal].data[..],
            "the dialog's pointer resolved to bytes other than its opening frame"
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no dialog was checked; the assertions are vacuous"
    );
}

/// The case that decides the design.
///
/// `compact_idle` keeps anchor messages, so it can evict position 0. A pointer
/// derived from `messages.first()` would then name a real frame that is not the
/// frame the dialog opened in -- a confident wrong answer. This asserts the
/// stored pointer is unchanged across compaction, and that the derived one
/// would in fact have been different, so the test still means something if
/// somebody "simplifies" the field away later.
#[test]
fn the_opening_frame_survives_losing_the_opening_message() {
    let path = fixture("sip_call.pcap");
    let mut store = store_from(&path);

    // Pick a dialog with at least two messages carrying *different* frames, so
    // dropping the first genuinely changes what a derived implementation would
    // report. Without that, the assertion below could pass while `first_frame`
    // and `messages.first()` happen to agree.
    let target = store
        .iter()
        .find(|d| {
            let mut frames = d.messages.iter().filter_map(|m| m.frame.as_ref());
            match (frames.next(), frames.next()) {
                (Some(a), Some(b)) => a.origin.ordinal != b.origin.ordinal,
                _ => false,
            }
        })
        .map(|d| d.call_id.clone())
        .expect("fixture must contain a dialog with two distinctly-framed messages");

    let opened_in = {
        let d = store.get_mut(&target).expect("dialog");
        let opened_in = d.first_frame.clone().expect("opening frame recorded");
        assert_eq!(
            d.messages.first().and_then(|m| m.frame.clone()),
            Some(opened_in.clone()),
            "precondition: before eviction the two agree, which is why only the \
             post-eviction state can tell the implementations apart"
        );
        // Exactly what `compact_idle` does when position 0 is not an anchor:
        // the message goes, the dialog stays.
        d.messages.drain(..1);
        opened_in
    };

    let d = store.iter().find(|d| d.call_id == target).expect("dialog");

    // The derived implementation would now be wrong -- assert that explicitly,
    // so this test keeps its teeth if someone later "simplifies" the stored
    // field away in favour of reading `messages.first()`.
    let derived_now = d.messages.first().and_then(|m| m.frame.clone());
    assert_ne!(
        derived_now,
        Some(opened_in.clone()),
        "the survivor now carries the same frame as the evicted opener, so this \
         test cannot distinguish stored from derived"
    );

    assert_eq!(
        d.first_frame.as_ref(),
        Some(&opened_in),
        "losing the opening message changed the dialog's recorded opening frame"
    );
    assert_eq!(
        DialogSummary::from(d).frame,
        Some(opened_in.to_string()),
        "the summary followed the surviving message instead of the dialog's own \
         record, and now cites a frame the dialog did not open in"
    );
}

/// The real `compact_idle`, on a dialog long enough for it to bite.
///
/// The test above drains position 0 directly, which is precise but is a
/// simulation. This one drives the production path. It is separate because it
/// needs a dialog longer than the keep-limit, and the fixture's dialogs are
/// short -- the first version of this test ran `compact_idle` over the fixture,
/// evicted 0 messages, and passed while proving nothing. Hence the
/// `messages_evicted > 0` assertion: without it the test can go quiet again.
///
/// It does NOT discriminate stored-vs-derived, and that is measured rather than
/// assumed: mutating the projection to read `messages.first()` leaves this test
/// green, because `retained_indices` keeps the opening request as an anchor
/// here. `the_opening_frame_survives_losing_the_opening_message` is the one
/// with teeth on that question. This one guards a different property -- that
/// compaction does not itself corrupt the recorded frame.
#[test]
fn the_real_compaction_path_leaves_the_opening_frame_alone() {
    let path = fixture("sip_call.pcap");
    let mut store = store_from(&path);
    let call_id = store.iter().next().expect("a dialog").call_id.clone();

    let (opened_in, grown_to) = {
        let d = store.get_mut(&call_id).expect("dialog");
        let opened_in = d.first_frame.clone().expect("opening frame");
        // Grow past the keep-limit by repeating messages the dialog already
        // has. Content does not matter here; length does, because that is what
        // makes `retained_indices` return Some and eviction actually run.
        let seed: Vec<_> = d.messages.clone();
        while d.messages.len() <= keep_messages_per_idle_dialog() * 2 {
            d.messages.extend(seed.iter().cloned());
        }
        (opened_in, d.messages.len())
    };

    let future = chrono::Utc::now() + idle_compact_after() + chrono::TimeDelta::minutes(1);
    let stats = store.compact_idle(future);
    assert!(
        stats.messages_evicted > 0,
        "compaction evicted nothing from a {grown_to}-message dialog against a \
         keep-limit of {}; this test would prove \
         nothing about compaction",
        keep_messages_per_idle_dialog()
    );

    let d = store.iter().find(|d| d.call_id == call_id).expect("dialog");
    assert_eq!(
        d.first_frame.as_ref(),
        Some(&opened_in),
        "compact_idle changed the dialog's recorded opening frame"
    );
    assert_eq!(
        DialogSummary::from(d).frame,
        Some(opened_in.to_string()),
        "after real compaction the summary no longer cites the opening frame"
    );
}

/// The digest has to survive being written down.
///
/// Stage 4 found this: `Display` rendered `<source>#<ordinal>` and
/// `parse_pointer` hard-coded `digest: None`, so a pointer could carry a digest
/// in memory and never once carry it through a string. Every pointer a user
/// ever saw was therefore unverifiable, and following one after the capture
/// rotated returned bytes with no warning -- the exact confident wrong answer
/// the design forbids, reintroduced at the serialization boundary.
#[test]
fn an_emitted_pointer_still_verifies_after_a_round_trip_through_text() {
    let path = fixture("sip_call.pcap");
    let store = store_from(&path);
    let d = store.iter().next().expect("one dialog");
    let emitted = DialogSummary::from(d).frame.expect("pointer emitted");

    let reparsed = parse_pointer(&emitted).expect("the emitted form must parse");
    assert_eq!(
        reparsed.origin.digest,
        d.first_frame.as_ref().expect("first_frame").origin.digest,
        "the digest did not survive the trip through text, so nothing that \
         reads this pointer can tell a changed capture from an intact one"
    );
    assert!(
        resolve(&reparsed).expect("resolve").is_verified(),
        "a pointer emitted by a surface must verify when followed"
    );
}

/// End to end: follow an emitted pointer at a capture that changed underneath.
///
/// This is the property the whole feature is for. It is not enough that the
/// digest is carried; following the pointer against different bytes has to
/// refuse rather than hand back whatever now sits at that ordinal.
#[test]
fn following_an_emitted_pointer_at_a_changed_capture_is_refused() {
    let src = fixture("sip_call.pcap");
    let store = store_from(&src);
    let d = store.iter().next().expect("one dialog");
    let emitted = DialogSummary::from(d).frame.expect("pointer emitted");

    let tail = emitted
        .rsplit_once('#')
        .map(|(_, t)| t.to_string())
        .expect("pointer has a tail");

    // A byte-identical copy must still resolve: the refusal below has to come
    // from the contents differing, not merely from the path differing.
    let dir = std::env::temp_dir().join(format!("sipnab-prov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let copy = dir.join("same.pcap");
    std::fs::copy(&src, &copy).expect("copy");
    assert!(
        resolve(&parse_pointer(&format!("{}#{tail}", copy.display())).expect("parse")).is_ok(),
        "a byte-identical copy must still resolve"
    );

    // Now aim the same ordinal and digest at a capture holding different frames
    // -- the "someone rotated the file under you" case, without hand-computing
    // offsets into the pcap to corrupt exactly the right frame.
    let other = fixture("udp_5060.pcap");
    match resolve(&parse_pointer(&format!("{other}#{tail}")).expect("parse")) {
        Err(sipnab::capture::resolve::ResolveError::Changed { .. }) => {}
        Ok(r) => panic!(
            "a changed capture returned bytes ({} of them, verified={}) instead \
             of refusing",
            r.bytes().len(),
            r.is_verified()
        ),
        Err(other) => panic!("expected Changed, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Absent means unknown. It must not become a pointer to frame 0.
#[test]
fn a_dialog_with_no_frame_omits_the_key_rather_than_emitting_a_default() {
    let path = fixture("sip_call.pcap");

    // Same capture, read with the frame origin stripped -- what live capture
    // produces. The dialogs are otherwise identical, so the only difference in
    // the emitted JSON should be the pointer.
    let live_like = store_with(&path, true);
    let d = live_like.iter().next().expect("one dialog");
    assert!(
        d.first_frame.is_none(),
        "a packet with no origin must not yield a dialog that claims a frame"
    );
    let json = serde_json::to_value(DialogSummary::from(d)).expect("serialize");
    assert!(
        !json.as_object().expect("object").contains_key("frame"),
        "a dialog with no frame must omit the key entirely, not emit null or a \
         placeholder that reads as a pointer to frame 0; got {json}"
    );

    // And the populated case really does emit it, so the check above is not
    // passing because the field never serializes under any circumstances.
    let from_file = store_from(&path);
    let d = from_file.iter().next().expect("one dialog");
    let with = serde_json::to_value(DialogSummary::from(d)).expect("serialize");
    assert!(
        with.as_object().expect("object").contains_key("frame"),
        "a dialog that knows its frame must emit the key; got {with}"
    );
}

// ── media streams ─────────────────────────────────────────────────────
//
// Everything above is about signalling. A stream reached every surface with
// no pointer at all: `grep -rn frame_ref src/rtp/` matched nothing, so
// `rtp_stats`, `/v1/streams`, `--json` and the TUI's stream export each named
// an SSRC, a jitter figure and a loss percentage that no reader could tie to a
// single byte of the capture. A stream is also the one object here that cannot
// fall back on a dialog's pointer: streams peer with dialogs rather than
// nesting under them, and an orphaned stream has no dialog at all.

/// The stream knows which frame it began in.
#[test]
fn a_stream_records_the_frame_its_first_packet_arrived_in() {
    let store = stream_store_with(&sample("sip-rtp-g711.pcap"), false);
    let streams: Vec<_> = store.iter().collect();
    assert!(
        !streams.is_empty(),
        "fixture produced no RTP streams -- these assertions would be vacuous"
    );
    for s in &streams {
        assert!(
            s.first_frame.is_some(),
            "a stream built from a capture file must know the frame its first \
             packet arrived in; ssrc=0x{:08x} {}->{}",
            s.key.ssrc,
            s.key.src,
            s.key.dst
        );
    }
}

/// The whole point: the emitted pointer leads back to the right bytes.
///
/// Asserts the round trip through the emitted *string*, not the presence of a
/// field. A populated pointer aimed one frame off would satisfy `is_some()`
/// and be exactly the confident wrong answer this feature exists to prevent —
/// and `resolve` checks the digest, so a neighbouring frame is refused rather
/// than quietly returned.
#[test]
fn the_stream_pointer_resolves_to_the_frame_the_stream_opened_in() {
    let path = sample("sip-rtp-g711.pcap");
    let packets = read_all(&path);
    let store = stream_store_with(&path, false);

    let mut checked = 0;
    for s in store.iter() {
        let emitted: serde_json::Value =
            serde_json::from_str(&stream_to_json(s)).expect("stream JSON parses");
        let pointer = emitted["frame"]
            .as_str()
            .unwrap_or_else(|| panic!("stream JSON carried no frame: {emitted}"))
            .to_string();

        let got = resolve(&parse_pointer(&pointer).expect("the emitted pointer must parse"))
            .expect("the emitted pointer must resolve");
        assert!(
            got.is_verified(),
            "the reader recorded a digest, so a followed pointer must verify \
             rather than report UNVERIFIED"
        );

        // Compare bytes, not ordinals, so an off-by-one in the ordinal cannot
        // pass by matching itself.
        let ordinal = s
            .first_frame
            .as_ref()
            .expect("first_frame present")
            .origin
            .ordinal as usize;
        assert_eq!(
            got.bytes(),
            &packets[ordinal].data[..],
            "the stream's pointer resolved to bytes other than the frame its \
             first packet arrived in"
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no stream was checked; the assertions are vacuous"
    );
}

/// Absent means unknown. It must not become a pointer to frame 0.
///
/// Checked on both stream projections, because they are separate types with
/// separate `#[serde]` attributes: `StreamJson` carries `--json`, the
/// call-report `streams` array and MCP `rtp_stats`; `StreamSummary` carries
/// REST `/v1/streams` and the TUI's stream export. One of the two defaulting
/// to `null` would put a placeholder on half the surfaces.
#[test]
fn a_stream_with_no_frame_omits_the_key_rather_than_emitting_a_default() {
    let path = sample("sip-rtp-g711.pcap");

    // Same capture, read with the frame origin stripped -- what live capture
    // produces. The streams are otherwise identical, so the only difference in
    // the emitted JSON should be the pointer.
    let live_like = stream_store_with(&path, true);
    let s = live_like.iter().next().expect("one stream");
    assert!(
        s.first_frame.is_none(),
        "a packet with no origin must not yield a stream that claims a frame"
    );
    let json: serde_json::Value =
        serde_json::from_str(&stream_to_json(s)).expect("stream JSON parses");
    assert!(
        !json.as_object().expect("object").contains_key("frame"),
        "a stream with no frame must omit the key entirely, not emit null or a \
         placeholder that reads as a pointer to frame 0; got {json}"
    );
    let summary = serde_json::to_value(StreamSummary::from(s)).expect("serialize");
    assert!(
        !summary.as_object().expect("object").contains_key("frame"),
        "the compact stream projection must omit the key too; got {summary}"
    );

    // And the populated case really does emit it, so the checks above are not
    // passing because the field never serializes under any circumstances.
    let from_file = stream_store_with(&path, false);
    let s = from_file.iter().next().expect("one stream");
    let with: serde_json::Value =
        serde_json::from_str(&stream_to_json(s)).expect("stream JSON parses");
    assert!(
        with.as_object().expect("object").contains_key("frame"),
        "a stream that knows its frame must emit the key; got {with}"
    );
    let with_summary = serde_json::to_value(StreamSummary::from(s)).expect("serialize");
    assert!(
        with_summary
            .as_object()
            .expect("object")
            .contains_key("frame"),
        "the compact stream projection must emit it too; got {with_summary}"
    );
}
