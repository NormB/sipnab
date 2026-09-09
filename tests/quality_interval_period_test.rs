// SPDX-License-Identifier: MIT OR Apache-2.0

//! The quality-snapshot period, declared once for a whole process.
//!
//! Its own test binary, and that is the point. The period is a process-wide
//! atomic — streams are created by the batch runner, the TUI, every `--cores`
//! shard and the WASM entry point, so a value threaded to some of them is a
//! setting honored on some surfaces and ignored on others. A test that MOVES
//! that atomic cannot live in the library test binary beside five thousand
//! tests that create streams, because it would move the period under them.
//!
//! Everything that can be tested without moving it is tested there, against
//! [`RtpStream::with_quality_period`]. What is left is the one line those
//! tests cannot reach: whether `RtpStream::new` consults the declaration at
//! all, or quietly uses the shipped constant. Replacing that read with
//! `DEFAULT_QUALITY_INTERVAL_SECS` passes every test in the library, because
//! the declaration is at its default there.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::stream::{
    DEFAULT_QUALITY_INTERVAL_SECS, RtpStream, StreamKey, quality_interval_cap,
    quality_interval_secs, set_quality_interval_secs,
};

/// The declaration is process-wide, so the tests that move it take turns.
///
/// Not for correctness of the atomic — it is atomic — but so one test's
/// period cannot be observed by the other's stream. Poisoning is ignored
/// deliberately: a panic in one test must not turn the other into a second
/// failure that hides it.
static DECLARATION: Mutex<()> = Mutex::new(());

fn header() -> RtpHeader {
    RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 0,
        sequence: 1,
        timestamp: 0,
        ssrc: 0x0BAD_CAFE,
        payload_offset: 12,
    }
}

fn key() -> StreamKey {
    let addr = |port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port);
    StreamKey {
        ssrc: 0x0BAD_CAFE,
        src: addr(20000),
        dst: addr(30000),
    }
}

/// A stream created after the declaration carries the declared period, and
/// the retention derived from it.
#[test]
fn a_stream_created_after_the_declaration_carries_it() {
    let _turn = DECLARATION.lock().unwrap_or_else(|e| e.into_inner());
    let declared = 30;
    assert_ne!(
        declared, DEFAULT_QUALITY_INTERVAL_SECS,
        "the fixture must differ from the shipped period or it proves nothing"
    );

    set_quality_interval_secs(declared);
    assert_eq!(quality_interval_secs(), declared);

    let stream = RtpStream::new(key(), &header(), chrono::Utc::now());
    // Read through the public derivation rather than a literal, so the
    // assertion moves with the span if the span ever does.
    let expected = quality_interval_cap(declared);
    assert_eq!(
        stream.quality_interval_cap(),
        expected,
        "a stream built while a {declared}s period was declared must retain \
         {expected} snapshots"
    );
    assert_eq!(stream.quality_interval_secs(), declared);

    set_quality_interval_secs(DEFAULT_QUALITY_INTERVAL_SECS);
}

/// A period outside the permitted range falls back to the shipped one rather
/// than being stored.
///
/// The operator-facing refusal happens earlier, in the config validator. This
/// is the last line of defense, and it is the one every stream constructor
/// runs behind: a zero stored here would divide the retained span by nothing.
#[test]
fn an_impossible_period_falls_back_to_the_shipped_one() {
    let _turn = DECLARATION.lock().unwrap_or_else(|e| e.into_inner());

    for absurd in [0, -1, 301, i64::MAX] {
        set_quality_interval_secs(absurd);
        assert_eq!(
            quality_interval_secs(),
            DEFAULT_QUALITY_INTERVAL_SECS,
            "a declared period of {absurd}s must not be stored"
        );
        let stream = RtpStream::new(key(), &header(), chrono::Utc::now());
        assert_eq!(
            stream.quality_interval_cap(),
            quality_interval_cap(DEFAULT_QUALITY_INTERVAL_SECS),
            "and the stream built under it must retain the shipped hour"
        );
    }

    set_quality_interval_secs(DEFAULT_QUALITY_INTERVAL_SECS);
}
