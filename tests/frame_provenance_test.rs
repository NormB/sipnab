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
