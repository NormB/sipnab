// SPDX-License-Identifier: MIT OR Apache-2.0

//! A pointer that names bytes WITHIN a frame, not just the frame.
//!
//! # What this is for
//!
//! A lint finding cites a message. The malformed thing is usually one header,
//! and a reader handed a whole INVITE still has to find it. Field granularity
//! is what turns "this message is wrong" into "these bytes are wrong", and it
//! became possible when the parser started recording a span per header.
//!
//! # Why the encoder and the parser land together
//!
//! The backlog entry is explicit, and it is the whole design constraint:
//! minting a suffix the single `parse_pointer` cannot read would be a
//! fabricated pointer. A ref that renders and does not parse is worse than no
//! ref, because it resolves in a reader's head and nowhere else. So every test
//! here goes through BOTH halves — render, then parse back, then compare.

#![cfg(feature = "full")]

use sipnab::capture::packet::{FrameOrigin, FrameRef, FrameSource};
use sipnab::capture::resolve::parse_pointer;

/// A pointer naming a whole frame, as before.
fn whole(source: &str, ordinal: u64, digest: Option<u64>) -> FrameRef {
    FrameRef {
        source: std::sync::Arc::from(source),
        origin: FrameOrigin {
            ordinal,
            digest,
            verifiable: digest.is_some(),
        },
        kind: FrameSource::from_source_name(source),
        bytes: None,
    }
}

/// The existing forms still render and parse exactly as they did.
///
/// The compatibility half, and it is not a formality: every pointer already
/// minted, every doc example and every stored finding is one of these. A
/// format change that broke them would strand the provenance it was meant to
/// improve.
#[test]
fn the_forms_that_already_exist_are_unchanged() {
    for (source, ordinal, digest, want) in [
        ("calls.pcap", 41u64, None, "calls.pcap#41"),
        (
            "calls.pcap",
            41,
            Some(0x6d1f_4c0a_9b2e_7a53),
            "calls.pcap#41@6d1f4c0a9b2e7a53",
        ),
        ("eth0", 7, None, "eth0#7"),
    ] {
        let rendered = whole(source, ordinal, digest).to_string();
        assert_eq!(rendered, want, "the text form moved");
        let back = parse_pointer(&rendered).expect("and it must still parse");
        assert_eq!(back.origin.ordinal, ordinal);
        assert_eq!(back.origin.digest, digest);
        assert!(
            back.bytes.is_none(),
            "no range was named, so none is invented"
        );
    }
}

/// A byte range renders and parses back to the same range.
#[test]
fn a_byte_range_survives_a_round_trip() {
    let mut with_range = whole("calls.pcap", 41, Some(0x6d1f_4c0a_9b2e_7a53));
    with_range.bytes = Some(120..168);
    let rendered = with_range.to_string();
    assert_eq!(rendered, "calls.pcap#41@6d1f4c0a9b2e7a53+120-168");

    let back = parse_pointer(&rendered).expect("the encoder's own output must parse");
    assert_eq!(back.bytes, Some(120..168));
    assert_eq!(back.origin.ordinal, 41);
    assert_eq!(back.origin.digest, Some(0x6d1f_4c0a_9b2e_7a53));
}

/// A range without a digest is legal too, because a human types that.
#[test]
fn a_range_does_not_require_a_digest() {
    let mut p = whole("calls.pcap", 41, None);
    p.bytes = Some(0..16);
    let rendered = p.to_string();
    assert_eq!(rendered, "calls.pcap#41+0-16");
    assert_eq!(parse_pointer(&rendered).expect("parses").bytes, Some(0..16));
}

/// A malformed range is refused, never silently dropped.
///
/// Dropping it would turn a pointer at one header into a pointer at the whole
/// message, which still resolves and answers a different question than the one
/// asked. That is the failure this whole mechanism exists to prevent, so the
/// pointer is refused instead.
#[test]
fn a_malformed_range_is_refused_rather_than_ignored() {
    for bad in [
        "calls.pcap#41+",
        "calls.pcap#41+120",
        "calls.pcap#41+120-",
        "calls.pcap#41+-168",
        "calls.pcap#41+abc-def",
        "calls.pcap#41+168-120",
        "calls.pcap#41+120-120",
    ] {
        assert!(
            parse_pointer(bad).is_err(),
            "{bad} was accepted; a range that cannot be read must not become \
             a pointer at the whole frame"
        );
    }
}

/// A source containing `+` keeps it.
///
/// The tail after the last `#` belongs to the pointer format; everything
/// before it is a path somebody chose, and paths contain surprising
/// characters. `@` already had this rule and `+` gets the same one.
#[test]
fn a_plus_in_the_source_is_not_a_range() {
    let p = parse_pointer("/var/captures/a+b.pcap#9").expect("parses");
    assert_eq!(&*p.source, "/var/captures/a+b.pcap");
    assert_eq!(p.origin.ordinal, 9);
    assert!(p.bytes.is_none());
}

/// A lint finding narrows its own citation, when the bytes sit in one place.
///
/// The consumer that justifies the range existing at all. A finding cites a
/// message; the malformed thing is one header, and a reader handed a whole
/// INVITE still has to go and find it.
#[test]
fn a_finding_cites_the_bytes_it_observed() {
    let raw = concat!(
        "INVITE sip:bob@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=nope\r\n",
        "From: <sip:alice@example.com>;tag=a1\r\n",
        "To: <sip:bob@example.com>\r\n",
        "Call-ID: range-fixture\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n\r\n",
    );
    // The branch value is wire text and appears exactly once.
    let needle = "branch=nope";
    let start = raw.find(needle).expect("the fixture contains it");
    let mut pointer = whole("calls.pcap", 3, None);
    pointer.bytes = Some(
        u32::try_from(start).expect("fits")..u32::try_from(start + needle.len()).expect("fits"),
    );

    let rendered = pointer.to_string();
    let back = parse_pointer(&rendered).expect("a narrowed pointer parses");
    let range = back.bytes.expect("and keeps its range");
    assert_eq!(
        &raw[range.start as usize..range.end as usize],
        needle,
        "the range must quote the text the finding observed"
    );
}

/// Text that appears twice narrows nothing.
///
/// A second match makes the anchor a coin toss, and a finding pointed at the
/// wrong header still resolves — which is exactly what would make it read as
/// evidence. The whole-message pointer is the honest answer there.
#[test]
fn ambiguous_observed_text_leaves_the_pointer_at_the_whole_frame() {
    use sipnab::capture::packet::unique_offset;
    assert_eq!(
        unique_offset(b"aXbXc", b"X"),
        None,
        "two matches, no anchor"
    );
    assert_eq!(unique_offset(b"aXbYc", b"X"), Some(1));
    assert_eq!(unique_offset(b"abc", b"zz"), None, "absent, no anchor");
    assert_eq!(unique_offset(b"abc", b""), None, "empty, no anchor");
}
