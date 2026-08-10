// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every frame read from a file knows which file, and where in it.
//!
//! This is the first half of packet-level provenance: a fact sipnab emits
//! should carry a pointer back to the bytes that produced it, and a pointer
//! needs both a source and a position. `Packet::interface` has named the
//! source since the pcapng interface fix. This pins the position, and pins the
//! property that makes the pair usable — the ordinal counts within ONE file,
//! so the same frame gets the same name no matter how the run was invoked.
//!
//! That last point is the whole design. A run-global counter would be simpler
//! and useless: frame 40 of the second file would be "packet 4,212" when read
//! as a set and "packet 40" when read alone, so two runs could never be
//! compared, which is the one thing a provenance pointer exists for.
#![cfg(all(unix, feature = "native"))]

use sipnab::capture::packet::{FrameOrigin, FrameRef, Packet};
use std::sync::Arc;

/// A packet with both halves reports a pointer; either half alone reports
/// nothing.
///
/// The `None` cases are the point. A source with no ordinal cannot name a
/// frame, and an ordinal with no source does not say which file it counts
/// within. Returning a half-pointer would hand a reader something that looks
/// resolvable and is not, which is the failure the pcapng interface bug
/// already demonstrated one layer down: frames that named a file they never
/// came from were worse than frames naming no file at all.
#[test]
fn a_frame_ref_needs_both_halves_or_it_is_not_offered() {
    let base = Packet::new(
        chrono::Utc::now(),
        vec![0u8; 64],
        64,
        64,
        Some("capture.pcap".to_string()),
        1,
    );

    let mut both = base.clone();
    both.origin = Some(FrameOrigin {
        ordinal: 41,
        digest: None,
    });
    let r = both
        .frame_ref()
        .expect("source and ordinal are both present");
    assert_eq!(
        r,
        FrameRef {
            source: Arc::from("capture.pcap"),
            origin: FrameOrigin {
                ordinal: 41,
                digest: None
            },
        }
    );

    let mut source_only = base.clone();
    source_only.origin = None;
    assert!(
        source_only.frame_ref().is_none(),
        "a source with no ordinal names a file, not a frame, and must not be \
         offered as a pointer to one"
    );

    let mut ordinal_only = base;
    ordinal_only.interface = None;
    ordinal_only.origin = Some(FrameOrigin {
        ordinal: 41,
        digest: None,
    });
    assert!(
        ordinal_only.frame_ref().is_none(),
        "an ordinal with no source does not say which file it counts within, \
         so it resolves against nothing"
    );
}

/// The rendered form is `<source>#<ordinal>`, which is what output carries and
/// what a resolver will accept.
#[test]
fn a_frame_ref_renders_as_source_hash_ordinal() {
    let r = FrameRef {
        source: Arc::from("/captures/tg.pcap0"),
        origin: FrameOrigin {
            ordinal: 4211,
            digest: None,
        },
    };
    assert_eq!(r.to_string(), "/captures/tg.pcap0#4211");
}

/// The digest is really computed over the frame, and really discriminates.
///
/// Written because the digest measured as FREE — 0.41s against a 0.42s
/// baseline over a 100 MB capture — and "costs nothing" and "does nothing"
/// are indistinguishable from outside. This makes them distinguishable: a
/// digest that was never computed shows up as `None`, and one computed over
/// a constant shows up as every frame agreeing.
#[test]
fn the_digest_is_computed_over_the_frame_and_tells_frames_apart() {
    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let packets = read_all(&pcap);

    let digests: Vec<u64> = packets
        .iter()
        .map(|p| {
            p.origin
                .and_then(|o| o.digest)
                .expect("a frame read from a file must carry a digest")
        })
        .collect();

    // Recomputing from the bytes must reproduce it exactly, or the stored
    // value describes something other than the frame.
    for (i, p) in packets.iter().enumerate() {
        assert_eq!(
            digests[i],
            sipnab::capture::packet::frame_digest(&p.data),
            "frame {i}'s stored digest does not match a digest of its own bytes"
        );
    }

    // Distinct frames must mostly differ. A hash that returned a constant, or
    // one applied to an empty slice, would pass every assertion above.
    let distinct: std::collections::BTreeSet<u64> = digests.iter().copied().collect();
    assert!(
        distinct.len() > 1,
        "all {} frames hashed to the same value ({:?}) — the digest is not \
         reading the frame",
        digests.len(),
        digests.first()
    );
}

/// FNV-1a is pinned to its specification, not to whatever the toolchain does.
///
/// `DefaultHasher` would have been one line shorter and is explicitly not
/// stable across Rust releases, so a digest stored today would stop matching
/// after a toolchain upgrade — silently, and in the direction that refuses
/// valid frames. These are the published FNV-1a 64-bit vectors.
#[test]
fn the_digest_matches_the_published_fnv1a_vectors() {
    use sipnab::capture::packet::frame_digest;
    assert_eq!(frame_digest(b""), 0xcbf2_9ce4_8422_2325, "empty");
    assert_eq!(frame_digest(b"a"), 0xaf63_dc4c_8601_ec8c, "a");
    assert_eq!(frame_digest(b"foobar"), 0x85944171f73967e8, "foobar");
}

/// Ordinals are 0-based and dense: the *n*th packet of a file reports *n*.
///
/// Read through the real file reader rather than constructed by hand, because
/// the assertion is about the reader's counting and a hand-built packet would
/// only test the struct literal.
#[test]
fn the_nth_packet_of_a_file_reports_ordinal_n() {
    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let packets = read_all(&pcap);
    assert!(
        packets.len() >= 2,
        "fixture must hold at least two packets for this to say anything; \
         it held {}",
        packets.len()
    );

    for (i, p) in packets.iter().enumerate() {
        let r = p.frame_ref().unwrap_or_else(|| {
            panic!("packet {i} came from a file and must carry a pointer to it")
        });
        assert_eq!(
            r.origin.ordinal, i as u64,
            "packet {i} reported ordinal {}; ordinals must be 0-based and \
             dense, because a reader counting frames in Wireshark is counting \
             the same way",
            r.origin.ordinal
        );
        assert!(
            r.source.ends_with("sip_call.pcap"),
            "packet {i} named {:?} as its source",
            r.source
        );
    }
}

/// Reading two files restarts the ordinal at zero for the second.
///
/// This is the assertion the design turns on. If it ever reports a continuing
/// count, the pointer has become run-relative and every comparison built on it
/// is silently wrong — the numbers still look plausible, which is what makes
/// it worth a test rather than a comment.
#[test]
fn each_file_of_a_set_numbers_its_own_frames_from_zero() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let packets = read_all_multi(&[dir.join("sip_call.pcap"), dir.join("udp_5060.pcap")]);
    let per_source = group_by_source(&packets);

    assert_eq!(
        per_source.len(),
        2,
        "two distinct captures must produce two distinct sources, or this test \
         is not measuring what it claims; saw {:?}",
        per_source.keys().collect::<Vec<_>>()
    );

    for (source, ordinals) in &per_source {
        let expected: Vec<u64> = (0..ordinals.len() as u64).collect();
        assert_eq!(
            ordinals, &expected,
            "{source} numbered its frames {ordinals:?}, expected {expected:?} — \
             a second file that continues the first file's count has made every \
             pointer run-relative"
        );
    }

    // Both files really were read. Without this the assertion above passes
    // vacuously on a run where the second file yielded nothing.
    for ordinals in per_source.values() {
        assert!(!ordinals.is_empty(), "a source contributed no frames");
    }
}

/// The PARALLEL reader must give each file's frames that file's own source.
///
/// `each_file_of_a_set_numbers_its_own_frames_from_zero` above asserts exactly
/// this property — and drives `capture::file::capture_files`, the
/// single-threaded reader. Nothing exercised `run_offline_parallel_file` with a
/// multi-file set, which is the gap this closes.
///
/// It is not a hypothetical gap. `9e12653` had to fix the parallel reader
/// silently producing NO provenance at all while the single-threaded path
/// looked fine, and every test passed throughout. The same blind spot would
/// hide a reader that stamped one source for every packet: pointers would still
/// resolve, still carry plausible ordinals, and name the wrong file. A pointer
/// that names the wrong file is worse than no pointer, because it manufactures
/// confidence — which is the failure this whole subsystem exists to prevent.
///
/// Read as: reconstruct a two-file set through the `--cores` path, then require
/// that the dialogs between them name BOTH files. One source means the reader
/// collapsed them.
#[test]
fn the_parallel_reader_gives_each_file_of_a_set_its_own_source() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples");
    let a = dir.join("invite-opus-bye.pcap");
    let b = dir.join("codec-negotiation.pcap");
    assert!(a.is_file() && b.is_file(), "both fixtures must exist");

    let cc = sipnab::capture::CaptureConfig::default();
    let cfg = sipnab::parallel::ParallelConfig {
        cores: 2,
        max_streams: 100_000,
        max_dialogs: 100_000,
        rotate: false,
        max_reassembly: 1024,
        reassembly: Default::default(),
        parse_limit: Default::default(),
        portrange: (1, 65535),
        no_dialog: false,
        dialog_tracking: Default::default(),
        no_rtp: false,
        quiet_bad_parse: false,
        xcid_headers: Vec::new(),
    };
    let r = sipnab::parallel::run_offline_parallel_file(&[a.clone(), b.clone()], &cc, cfg)
        .expect("the two-file set reconstructs");

    let mut sources: std::collections::BTreeSet<String> = Default::default();
    let mut dialogs = 0usize;
    for d in r.dialog_store.iter() {
        dialogs += 1;
        if let Some(f) = d.first_frame.as_ref() {
            sources.insert(f.source.to_string());
        }
    }

    // Without this the source assertion could pass vacuously on a run that
    // reconstructed nothing at all.
    assert!(
        dialogs > 0,
        "the set reconstructed no dialogs, so this test asserted nothing about \
         provenance — the fixtures or the reader changed, not the property"
    );
    assert!(
        !sources.is_empty(),
        "{dialogs} dialogs and not one carried a frame pointer: the parallel \
         path has stopped stamping provenance, which is what 9e12653 fixed"
    );
    assert_eq!(
        sources.len(),
        2,
        "a two-file set produced {} distinct source(s) {:?}, expected 2. One \
         means the reader stamped a single source for every packet, so a \
         pointer from one file now names the other — plausible, resolvable, and \
         wrong",
        sources.len(),
        sources
    );
    for want in [&a, &b] {
        let want = want.display().to_string();
        assert!(
            sources.contains(&want),
            "no dialog names {want}; sources were {sources:?}"
        );
    }
}

// ── helpers ───────────────────────────────────────────────────────────

/// Read every packet of one capture through the real file reader.
fn read_all(path: &str) -> Vec<Packet> {
    read_all_multi(&[std::path::PathBuf::from(path)])
}

/// Read every packet of a set through the real file reader, in order.
fn read_all_multi(paths: &[std::path::PathBuf]) -> Vec<Packet> {
    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = paths.to_vec();
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

/// Ordinals seen per source, in arrival order.
fn group_by_source(packets: &[Packet]) -> std::collections::BTreeMap<String, Vec<u64>> {
    let mut out: std::collections::BTreeMap<String, Vec<u64>> = std::collections::BTreeMap::new();
    for p in packets {
        if let Some(r) = p.frame_ref() {
            out.entry(r.source.to_string())
                .or_default()
                .push(r.origin.ordinal);
        }
    }
    out
}

// ── following a pointer back to the bytes ─────────────────────────────

use sipnab::capture::resolve::{Resolution, ResolveError, parse_pointer, resolve};

/// `<source>#<ordinal>` round-trips, and nonsense is refused rather than
/// guessed at.
///
/// Splitting on the LAST `#` matters: a capture path may contain one and an
/// ordinal never does, so `rsplit_once` is the only split that survives a
/// path like `/captures/run#3/tg.pcap0`.
#[test]
fn a_pointer_parses_from_its_rendered_form() {
    let r = parse_pointer("/captures/tg.pcap0#4211").expect("well formed");
    assert_eq!(r.source.as_ref(), "/captures/tg.pcap0");
    assert_eq!(r.origin.ordinal, 4211);
    assert_eq!(
        r.origin.digest, None,
        "text carries no digest, so a parsed pointer must not claim one"
    );

    let odd = parse_pointer("/captures/run#3/tg.pcap0#7").expect("path containing a hash");
    assert_eq!(odd.source.as_ref(), "/captures/run#3/tg.pcap0");
    assert_eq!(odd.origin.ordinal, 7);

    for bad in [
        "capture.pcap",
        "#4",
        "capture.pcap#",
        "capture.pcap#-1",
        "capture.pcap#x",
    ] {
        assert!(
            matches!(parse_pointer(bad), Err(ResolveError::Malformed(_))),
            "{bad:?} is not a pointer and must be refused, not interpreted"
        );
    }
}

/// A pointer with no digest resolves, and says nothing was checked.
#[test]
fn a_pointer_without_a_digest_resolves_as_unverified() {
    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let packets = read_all(&pcap);
    let want = packets[2].data.to_vec();

    let got = resolve(&parse_pointer(&format!("{pcap}#2")).expect("parse")).expect("resolve");
    assert_eq!(got.bytes(), &want[..], "resolved the wrong frame");
    assert!(
        !got.is_verified(),
        "nothing was checked, so this must report UNVERIFIED — reporting it as \
         verified is how an unchecked byte string becomes evidence"
    );
    assert!(matches!(got, Resolution::Unverified(_)));
}

/// A pointer carrying the digest the run recorded resolves as verified.
#[test]
fn a_pointer_carrying_its_digest_resolves_as_verified() {
    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let packets = read_all(&pcap);
    let pointer = packets[3].frame_ref().expect("frame 3 has a pointer");
    assert!(
        pointer.origin.digest.is_some(),
        "the reader must have recorded a digest, or this test proves nothing"
    );

    let got = resolve(&pointer).expect("resolve");
    assert!(got.is_verified(), "digest matched, so this is verified");
    assert_eq!(got.bytes(), &packets[3].data[..]);
}

/// An ordinal past the end of the capture is refused, and says how many
/// frames are really there.
#[test]
fn an_ordinal_past_the_end_is_refused_with_the_real_count() {
    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let present = read_all(&pcap).len() as u64;

    let err = resolve(&parse_pointer(&format!("{pcap}#100000")).expect("parse"))
        .expect_err("there is no frame 100000");
    match err {
        ResolveError::NoSuchFrame {
            frames_present,
            ordinal,
            ..
        } => {
            assert_eq!(frames_present, present);
            assert_eq!(ordinal, 100_000);
        }
        other => panic!("expected NoSuchFrame, got {other:?}"),
    }
}

/// A capture that changed under the pointer is refused, not returned.
///
/// This is the assertion the whole module exists for. The frame IS there and
/// the read succeeds — returning it would look completely normal, and would
/// hand back bytes that are not the ones the finding was about. Proven by
/// pointing a real digest at a real capture whose frame differs.
#[test]
fn a_capture_that_changed_is_refused_rather_than_returned() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let a = dir.join("sip_call.pcap");
    let b = dir.join("udp_5060.pcap");

    // A pointer made against one capture, aimed at another. Frame 0 exists in
    // both, so nothing about the read fails — only the digest disagrees.
    let mut pointer = read_all(a.to_str().expect("utf-8"))[0]
        .frame_ref()
        .expect("frame 0 has a pointer");
    pointer.source = std::sync::Arc::from(b.to_str().expect("utf-8"));

    match resolve(&pointer) {
        Err(ResolveError::Changed { ordinal, .. }) => assert_eq!(ordinal, 0),
        Ok(r) => panic!(
            "returned {} bytes for a frame that is not the one the pointer was \
             made against — this is the fabrication the digest exists to stop",
            r.bytes().len()
        ),
        Err(other) => panic!("expected Changed, got {other}"),
    }
}

/// A source that will not open is refused, naming the source.
#[test]
fn an_unreadable_source_is_refused_by_name() {
    let err = resolve(&parse_pointer("/nonexistent/nowhere.pcap#0").expect("parse"))
        .expect_err("that file does not exist");
    match err {
        ResolveError::Unreadable { source, .. } => {
            assert_eq!(source, "/nonexistent/nowhere.pcap");
        }
        other => panic!("expected Unreadable, got {other:?}"),
    }
}

// ── the pointer survives the parse boundary ───────────────────────────

/// A SIP message read from a capture knows which frame it came from, and that
/// frame resolves back to the bytes.
///
/// This is the join that makes provenance usable rather than theoretical.
/// `ParsedPacket` is where the packet's identity used to die: the SIP parser
/// takes bytes and addressing and has no business knowing about captures, so
/// without an explicit hand-off every dialog, diagnosis and lint finding built
/// downstream is an assertion with nothing behind it.
///
/// Asserts the round trip, not just the presence of a field. A `FrameRef` that
/// is populated but points at the wrong frame would satisfy "is_some()" and be
/// worse than none at all.
#[test]
fn a_sip_message_carries_a_frame_ref_that_resolves_to_its_own_bytes() {
    use sipnab::capture::parse::parse_packet;
    use sipnab::pipeline::{self, PacketAction, PipelineOptions};
    use sipnab::rtp::heuristic::RtpHeuristic;

    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let packets = read_all(&pcap);

    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    let mut checked = 0;

    for pkt in &packets {
        let Ok(pp) = parse_packet(pkt) else { continue };
        // The parser now carries a Copy locator rather than an owned
        // FrameRef, so compare what it MATERIALISES to. That is the stronger
        // claim and the one the change rests on: the cheap form must round-trip
        // to exactly the pointer the old path built, or every stored pointer
        // shifts meaning.
        assert_eq!(
            pp.frame.map(|l| l.to_frame_ref()),
            pkt.frame_ref(),
            "the parse boundary dropped or altered the frame pointer"
        );
        let mut decrypt = pipeline::MediaDecrypt::default();
        if let PacketAction::Sip { msg, .. } =
            pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt)
        {
            let r = msg.frame.clone().unwrap_or_else(|| {
                panic!("a SIP message parsed from a capture must know its frame")
            });

            // The pointer must lead back to the frame this message was in --
            // and `resolve` verifies the digest, so a pointer aimed one frame
            // off is refused rather than quietly returning a neighbour.
            let got = resolve(&r).expect("the message's own frame must resolve");
            assert!(
                got.is_verified(),
                "the reader recorded a digest, so following the pointer must \
                 verify rather than report UNVERIFIED"
            );
            assert_eq!(
                got.bytes(),
                &pkt.data[..],
                "the pointer resolved to bytes other than the frame this \
                 message was parsed from"
            );
            checked += 1;
        }
    }

    assert!(
        checked >= 2,
        "the fixture must yield at least two SIP messages for this to say \
         anything; it yielded {checked}"
    );
}

/// An exported pcapng says, in the file, that its frames were rebuilt (#106).
///
/// The audience for this is not the agent that asked for the export. It is
/// whoever opens the file afterwards — in a carrier's ticket queue, in a
/// regulator's evidence pile — who never saw the tool description that #103
/// corrected and has no reason to suspect the packets are synthetic.
///
/// Asserted against the BYTES ON DISK rather than the writer API, because the
/// only version of this claim that matters is the one that survives into the
/// artifact. A note the code passes and the format drops would satisfy any
/// test written against the call.
#[test]
fn an_exported_pcapng_carries_its_own_synthesis_caveat() {
    use sipnab::capture::{PcapExportMode, PcapWriter};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("evidence.pcapng");
    let note = "THE FRAMES IN THIS FILE WERE REBUILT, NOT COPIED. \
                Produced by sipnab for test purposes.";

    let mut w = PcapWriter::with_provenance(
        &path,
        1,
        None,
        None,
        true,
        PcapExportMode::Raw,
        None,
        Some(note.to_string()),
    )
    .expect("writer");
    w.finish().expect("finish");

    let bytes = std::fs::read(&path).expect("read the export");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("WERE REBUILT, NOT COPIED"),
        "the caveat must be IN the file -- a reader with only the file and \
         capinfos has nothing else to go on"
    );

    // And the negative: without a note, no stray comment appears. Otherwise
    // this test would pass against a writer that embeds a fixed string
    // regardless of what the caller asked for.
    let plain = dir.path().join("plain.pcapng");
    let mut w2 =
        PcapWriter::with_provenance(&plain, 1, None, None, true, PcapExportMode::Raw, None, None)
            .expect("writer");
    w2.finish().expect("finish");
    let plain_bytes = std::fs::read(&plain).expect("read");
    let plain_text = String::from_utf8_lossy(&plain_bytes);
    assert!(
        !plain_text.contains("REBUILT"),
        "a writer given no note must embed none"
    );
}

/// A truncated frame written to `-O` is reported, not silently shortened
/// (#149).
///
/// The output keeps the right frame COUNT and short payloads, so nothing
/// downstream — a codec analysis, a replay, a carrier's vendor opening the
/// file — can tell it is incomplete. That is the same confident-wrong shape as
/// a capture reporting zero SIP messages it never decoded.
///
/// Asserted on the writer's own accounting rather than on log text, so a
/// reworded warning cannot quietly turn this green while the loss goes
/// unreported.
#[test]
fn a_truncated_frame_written_to_output_is_counted() {
    use sipnab::capture::packet::Packet;
    use sipnab::capture::{PcapExportMode, PcapWriter};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("short.pcap");
    let mut w =
        PcapWriter::with_format(&path, 1, None, None, false, PcapExportMode::Raw).expect("writer");

    // caplen < origlen is the kernel saying "there was more".
    let whole = Packet::new(
        chrono::Utc::now(),
        vec![0u8; 64],
        64,
        64,
        Some("t".to_string()),
        1,
    );
    let cut = Packet::new(
        chrono::Utc::now(),
        vec![0u8; 64],
        64,
        1500,
        Some("t".to_string()),
        1,
    );
    w.write(&whole).expect("write whole");
    w.write(&cut).expect("write truncated");
    w.finish().expect("finish");

    assert_eq!(
        w.truncated_frames_written(),
        1,
        "exactly the frame whose caplen was under its origlen must count -- a \
         whole frame must not, or the warning fires on every capture and means \
         nothing"
    );
}
