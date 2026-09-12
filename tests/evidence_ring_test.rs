// SPDX-License-Identifier: MIT OR Apache-2.0

//! A bounded ring of raw frames, so a live capture can answer a pointer.
//!
//! # The difference this must not paper over
//!
//! A capture file can seek back and hand over the real bytes. A live device or
//! a HEP listener cannot: sipnab holds parsed messages and not frames, which is
//! why the export path re-synthesizes them, and why a pointer into one is
//! refused today rather than answered with something plausible.
//!
//! A ring closes that gap for recent frames without pretending it closed it for
//! all of them. So the interesting behavior is not the hit — it is the three
//! different misses, which prompt three different responses:
//!
//! * **evicted** — this frame was real and the ring has moved past it. Ask for
//!   a bigger ring, or ask sooner.
//! * **not seen** — the ring has not reached that ordinal. Either the pointer
//!   is from another run, or the frame has not arrived.
//! * **not retained** — nothing is being kept for that source at all.
//!
//! Collapsing those into one "no" is the same mistake as a check that answers
//! `0` for five different situations.

#![cfg(feature = "full")]

use sipnab::capture::evidence_ring::{EvidenceRing, Lookup};

/// A frame of `len` bytes whose first byte names it.
fn frame(tag: u8, len: usize) -> bytes::Bytes {
    let mut v = vec![tag; len];
    v[0] = tag;
    bytes::Bytes::from(v)
}

/// A retained frame comes back byte for byte.
#[test]
fn a_retained_frame_comes_back_exactly() {
    let mut ring = EvidenceRing::with_capacity_bytes(4096);
    ring.insert("eth0", 7, frame(0xAB, 100));
    match ring.lookup("eth0", 7) {
        Lookup::Retained(bytes) => {
            assert_eq!(bytes.len(), 100);
            assert_eq!(bytes[0], 0xAB);
        }
        other => panic!("expected the frame back, got {other:?}"),
    }
}

/// A frame the ring has moved past says EVICTED, not "no".
///
/// The distinction an operator acts on. Evicted means the pointer was good and
/// the answer is a bigger ring or a faster question; "not seen" means something
/// else entirely.
#[test]
fn a_frame_the_ring_moved_past_is_evicted_not_unknown() {
    let mut ring = EvidenceRing::with_capacity_bytes(1000);
    for ordinal in 0..20u64 {
        ring.insert("eth0", ordinal, frame(ordinal as u8, 100));
    }
    assert!(
        matches!(ring.lookup("eth0", 0), Lookup::Evicted { .. }),
        "the oldest frame must be reported as evicted: {:?}",
        ring.lookup("eth0", 0)
    );
    assert!(
        matches!(ring.lookup("eth0", 19), Lookup::Retained(_)),
        "the newest frame must still be there"
    );
}

/// An ordinal the ring has not reached is NOT SEEN, which is a different fact.
#[test]
fn an_ordinal_beyond_the_ring_is_not_seen_rather_than_evicted() {
    let mut ring = EvidenceRing::with_capacity_bytes(4096);
    ring.insert("eth0", 3, frame(1, 100));
    assert!(
        matches!(ring.lookup("eth0", 900), Lookup::NotSeen { .. }),
        "an ordinal past the newest retained frame was reported as evicted, \
         which tells an operator to buy memory for a frame that never existed"
    );
}

/// A source the ring holds nothing for says so in its own words.
#[test]
fn an_unknown_source_is_not_retained_rather_than_evicted() {
    let mut ring = EvidenceRing::with_capacity_bytes(4096);
    ring.insert("eth0", 1, frame(1, 100));
    assert!(
        matches!(ring.lookup("eth9", 1), Lookup::NotRetained),
        "a pointer into a source nothing is kept for must not borrow another \
         source's eviction story"
    );
}

/// The budget is a byte budget, and it is honored.
///
/// A ring that counted frames rather than bytes would be unbounded in the one
/// dimension that matters: an operator sets this to protect memory on a live
/// capture, and jumbo frames are two orders of magnitude larger than a SIP
/// datagram.
#[test]
fn the_budget_is_in_bytes_and_is_never_exceeded() {
    let mut ring = EvidenceRing::with_capacity_bytes(1000);
    for ordinal in 0..50u64 {
        ring.insert("eth0", ordinal, frame(ordinal as u8, 300));
    }
    assert!(
        ring.retained_bytes() <= 1000,
        "the ring holds {} bytes against a 1000 byte budget",
        ring.retained_bytes()
    );
    assert!(
        ring.retained_bytes() > 0,
        "a ring that evicted everything protects memory by being useless"
    );
}

/// A frame larger than the whole budget is refused, not obeyed.
///
/// Inserting it would evict every other frame and still overrun, so the ring
/// would end up holding one frame it cannot afford. Refusing keeps the budget
/// the operator set.
#[test]
fn a_frame_larger_than_the_budget_is_refused() {
    let mut ring = EvidenceRing::with_capacity_bytes(500);
    ring.insert("eth0", 1, frame(1, 100));
    ring.insert("eth0", 2, frame(2, 5000));
    assert!(
        ring.retained_bytes() <= 500,
        "an oversized frame broke the budget: {}",
        ring.retained_bytes()
    );
    assert!(
        matches!(ring.lookup("eth0", 1), Lookup::Retained(_)),
        "and it must not have evicted the frames that DO fit on its way in"
    );
}

/// Two sources are kept apart.
///
/// Ordinals are per-source by construction — a frame's identity is its source
/// plus its position — so a ring keyed on the ordinal alone would answer one
/// source's question with another's bytes, which is the single worst outcome
/// this mechanism can produce.
#[test]
fn two_sources_never_answer_for_each_other() {
    let mut ring = EvidenceRing::with_capacity_bytes(4096);
    ring.insert("eth0", 5, frame(0xE0, 100));
    ring.insert("hep:9060", 5, frame(0x4E, 100));
    let Lookup::Retained(a) = ring.lookup("eth0", 5) else {
        panic!("eth0 frame missing");
    };
    let Lookup::Retained(b) = ring.lookup("hep:9060", 5) else {
        panic!("hep frame missing");
    };
    assert_eq!(a[0], 0xE0);
    assert_eq!(b[0], 0x4E, "one source answered with another's bytes");
}

/// A zero budget retains nothing and says so.
#[test]
fn a_zero_budget_retains_nothing_and_admits_it() {
    let mut ring = EvidenceRing::with_capacity_bytes(0);
    ring.insert("eth0", 1, frame(1, 10));
    assert_eq!(ring.retained_bytes(), 0);
    assert!(matches!(ring.lookup("eth0", 1), Lookup::NotRetained));
}
