// SPDX-License-Identifier: MIT OR Apache-2.0

//! One keypress is one DTMF event, however many times its end packet arrives.
//!
//! RFC 4733 §2.5.1.4 requires a sender to transmit the final packet of a
//! telephone event **three times**, keeping the E bit set on each: *"The final
//! packet for each event and for each segment SHOULD be sent a total of three
//! times"*, and *"Once the sender has set the E bit for a packet, it MUST
//! continue to set the E bit for any further retransmissions of that packet."*
//!
//! sipnab reported an event per E-bit packet, so a conformant sender's single
//! keypress was counted three times. The unit tests in `src/rtp/dtmf.rs` pin
//! the dedupe rule; this pins that the counting path actually consults it,
//! which no unit test can show.
#![cfg(feature = "native")]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use pcap_build::{udp_frame, write_pcap};
use std::process::Command;

/// An RTP packet carrying an RFC 4733 telephone-event payload.
///
/// `end` sets the E bit. The RTP timestamp is the event's START and does not
/// advance across retransmissions, which is what makes it usable as part of
/// the dedupe key.
fn telephone_event(seq: u16, rtp_ts: u32, event: u8, end: bool, duration: u16) -> Vec<u8> {
    let mut p = vec![0x80, 101]; // V=2, PT=101 (the default telephone-event PT)
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&rtp_ts.to_be_bytes());
    p.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // SSRC
    p.push(event);
    p.push(if end { 0x8A } else { 0x0A }); // E bit + volume 10
    p.extend_from_slice(&duration.to_be_bytes());
    p
}

/// Count the DTMF lines sipnab traces for a capture.
fn dtmf_lines(frames: &[Vec<u8>]) -> usize {
    let dir = tempfile::tempdir().expect("temp dir");
    let pcap = dir.path().join("dtmf.pcap");
    write_pcap(&pcap, frames);
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-t", "-I"])
        .arg(&pcap)
        .output()
        .expect("sipnab runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines().filter(|l| l.contains("DTMF digit")).count()
}

/// Three retransmissions of one end packet report one keypress.
#[test]
fn one_keypress_sent_three_times_is_reported_once() {
    // 20 ms updates, then the end packet three times per §2.5.1.4 — identical
    // SSRC, RTP timestamp and event code, exactly as the RFC requires.
    let mut frames = Vec::new();
    for (i, dur) in [160u16, 320, 480].iter().enumerate() {
        frames.push(udp_frame(
            [192, 0, 2, 1],
            [192, 0, 2, 2],
            40000,
            40002,
            &telephone_event(u16::try_from(i).expect("fits"), 160_000, 7, false, *dur),
        ));
    }
    for i in 3..6u16 {
        frames.push(udp_frame(
            [192, 0, 2, 1],
            [192, 0, 2, 2],
            40000,
            40002,
            &telephone_event(i, 160_000, 7, true, 640),
        ));
    }

    assert_eq!(
        dtmf_lines(&frames),
        1,
        "RFC 4733 2.5.1.4 sends the end packet three times; that is one keypress"
    );
}

/// Two genuinely different keypresses are still two.
///
/// The negative case, and the one that matters most: a dedupe that collapsed
/// real digits would silently lose dialed input, which is worse than
/// over-counting it.
#[test]
fn two_keypresses_are_still_two() {
    let mut frames = Vec::new();
    for (i, (ts, ev)) in [(160_000u32, 7u8), (176_000, 1)].iter().enumerate() {
        // Each digit's end packet, sent three times as the RFC requires.
        for r in 0..3u16 {
            frames.push(udp_frame(
                [192, 0, 2, 1],
                [192, 0, 2, 2],
                40000,
                40002,
                &telephone_event(u16::try_from(i).expect("fits") * 3 + r, *ts, *ev, true, 640),
            ));
        }
    }

    assert_eq!(dtmf_lines(&frames), 2, "two digits pressed, two reported");
}
