//! What PERF1 changed, and the three ways it went wrong on the way.
//!
//! The digest is no longer computed for every frame as it is read. It is
//! computed where a pointer is RETAINED -- ~7% of frames on a carrier corpus --
//! which measured +29% at two cores. That is a change to WHEN a digest exists,
//! and each of the three defects below came from getting the "when" wrong in a
//! different way. Each is pinned here, because a defect described in a commit
//! message is a defect that comes back.

use sipnab::capture::packet::{FrameCounter, FrameOrigin, Packet, frame_digest};

fn file_packet(bytes: Vec<u8>, ordinal: u64) -> Packet {
    let n = bytes.len();
    let mut p = Packet::new(
        chrono::Utc::now(),
        bytes,
        n,
        n,
        Some("capture.pcap".to_string()),
        1,
    );
    p.origin = Some(FrameOrigin {
        ordinal,
        digest: None,
        verifiable: true,
    });
    p
}

/// DEFECT 1. Hashing at retention began stamping LIVE-captured frames.
///
/// A digest answers "did the capture change under you", which only a source
/// that can be read again can be asked. A device cannot be rewound, so the live
/// reader left `digest: None` and a pointer rendered as `eth9#0`. Moving the
/// hash to retention lost that distinction and started rendering
/// `eth9#0@<hash>` -- a pointer that looks checkable and is not.
#[test]
fn a_live_captured_frame_never_acquires_a_digest() {
    let mut counter = FrameCounter::new();
    let mut p = Packet::new(
        chrono::Utc::now(),
        vec![0xAA; 64],
        64,
        64,
        Some("eth9".to_string()),
        1,
    );
    p.origin = Some(counter.next_origin());
    assert!(
        !p.origin.expect("origin").verifiable,
        "the live counter must not claim a re-readable source; if it does, \
         every live pointer starts claiming verifiability it cannot deliver"
    );
    let r = p.frame_ref().expect("source and ordinal are both present");
    assert_eq!(
        r.origin.digest, None,
        "a live-captured frame acquired a digest. Nothing can re-read a device, \
         so the digest could never be checked against anything -- it renders as \
         eth9#0@<hash> and reads as verifiable when it is not"
    );
    assert_eq!(
        r.to_string(),
        "eth9#0",
        "the RENDERED pointer is the thing a reader sees, and it must carry no \
         @digest suffix for a source that cannot be re-read"
    );
}

/// DEFECT 1, the other half: a file-sourced frame MUST still get one.
///
/// Without this, "never stamp a live frame" is satisfiable by never stamping
/// anything, which would silently turn every stored pointer UNVERIFIED while
/// this file went green.
#[test]
fn a_file_sourced_frame_still_gets_a_digest_over_its_own_bytes() {
    let bytes = vec![0x11, 0x22, 0x33, 0x44];
    let p = file_packet(bytes.clone(), 7);
    let r = p.frame_ref().expect("pointer");
    assert_eq!(
        r.origin.digest,
        Some(frame_digest(&bytes)),
        "a capture file can be reopened, so its pointer must carry a digest of \
         the frame's OWN bytes -- and it must be the same FNV-1a value the \
         resolver will recompute, or every stored pointer refuses to resolve"
    );
}

/// DEFECT 2. `verifiable` became part of a pointer's IDENTITY.
///
/// Putting it in `FrameOrigin` and deriving `PartialEq` meant two pointers to
/// the same frame of the same source compared unequal when one was minted by a
/// reader and the other parsed from text. A pointer's text form -- `eth9#0`,
/// `capture.pcap#4@beef` -- has an ordinal and an optional digest and nowhere
/// to record re-readability, so a round-trip could never equal itself.
#[test]
fn verifiability_is_not_part_of_a_pointers_identity() {
    let minted = FrameOrigin {
        ordinal: 41,
        digest: Some(0xDEAD_BEEF),
        verifiable: true,
    };
    let parsed_back = FrameOrigin {
        ordinal: 41,
        digest: Some(0xDEAD_BEEF),
        verifiable: false,
    };
    assert_eq!(
        minted, parsed_back,
        "the same frame of the same source with the same digest is the SAME \
         pointer. Text cannot carry `verifiable`, so making it part of equality \
         means a pointer written out and read back is unequal to itself"
    );
    assert_eq!(
        minted.cmp(&parsed_back),
        std::cmp::Ordering::Equal,
        "ordering must ignore it too, or a sorted set of pointers gets a second \
         entry for a frame it already holds"
    );
}

/// DEFECT 2, the discriminating half: equality must still SEE the real fields.
///
/// A `PartialEq` that ignored too much would satisfy the test above by
/// declaring every origin equal, which would make a pointer to frame 4
/// indistinguishable from one to frame 900.
#[test]
fn pointer_identity_still_separates_ordinal_and_digest() {
    let base = FrameOrigin {
        ordinal: 41,
        digest: Some(0xDEAD_BEEF),
        verifiable: true,
    };
    let other_frame = FrameOrigin {
        ordinal: 42,
        ..base
    };
    let other_bytes = FrameOrigin {
        digest: Some(0x0BAD_F00D),
        ..base
    };
    assert_ne!(
        base, other_frame,
        "two different frames must not compare equal -- following a pointer to \
         the wrong frame manufactures confidence, which is the whole failure \
         this mechanism exists to prevent"
    );
    assert_ne!(
        base, other_bytes,
        "a digest mismatch means the capture changed under the pointer; if that \
         compares equal, the resolver stops being able to refuse"
    );
}

/// DEFECT 3. Test fixtures were given `verifiable: false` wholesale.
///
/// Filling every construction site mechanically made file-backed fixtures claim
/// their source could not be re-read, so three provenance tests that assert a
/// real capture yields a verified pointer failed. The rule is not "tests get
/// false" -- it is that the value describes the SOURCE.
#[test]
fn the_flag_follows_the_source_not_whether_it_is_a_test() {
    let from_file = file_packet(vec![0x01, 0x02], 0);
    assert!(
        from_file
            .frame_ref()
            .expect("pointer")
            .origin
            .digest
            .is_some(),
        "a fixture standing in for a capture FILE must behave like one. Marking \
         it unverifiable because it happens to live in a test made three \
         provenance tests fail for a reason that had nothing to do with them"
    );

    let mut synthetic = Packet::new(
        chrono::Utc::now(),
        vec![0x01, 0x02],
        2,
        2,
        Some("synthetic".to_string()),
        1,
    );
    synthetic.origin = Some(FrameOrigin {
        ordinal: 0,
        digest: None,
        verifiable: false,
    });
    assert_eq!(
        synthetic.frame_ref().expect("pointer").origin.digest,
        None,
        "a packet built by hand names no re-readable source, so it must get no \
         digest -- otherwise the flag means nothing and every fixture claims \
         verifiability"
    );
}

/// The hot path must not hash. This is the whole point of the change.
///
/// `frame_locator` is the `Copy` form the parser carries for every packet, and
/// it exists so ~93% of frames pay no hash and no refcount. If it ever starts
/// materialising a digest, the +29% goes away silently and only a benchmark
/// would notice.
#[test]
fn the_per_packet_locator_hashes_nothing() {
    let p = file_packet(vec![0x11; 512], 3);
    let loc = p.frame_locator().expect("locator");
    assert_eq!(
        loc.origin.digest, None,
        "the Copy locator carried for EVERY packet must not compute a digest. \
         Hashing here is what cost 29% of two-core throughput, and it would \
         come back with the gate still green because the value is correct -- \
         only its timing is wrong"
    );
    assert!(
        loc.origin.verifiable,
        "it must still carry the source's re-readability, or the retention site \
         has nothing to decide with and stops hashing anything at all"
    );
}
