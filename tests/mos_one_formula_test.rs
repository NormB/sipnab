// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

//! sipnab reports ONE MOS, whichever door the operator came through.
//!
//! It used to report two. `estimate_mos` is the G.107 E-model — codec
//! impairment, loss, delay. `approximate_mos` in the filter path was
//! `93.2 - min(jitter,100) - 2.5*loss`, with no codec term and no delay term,
//! and it drove the REST `mos_below` filter, the Prometheus MOS histogram and
//! the DSL's `rtp.mos`.
//!
//! Measured divergence on the same stream:
//!
//! | jitter / loss | E-model | approximate | gap  |
//! |---------------|---------|-------------|------|
//! | 20 ms / 1%    | 4.09    | 3.63        | 0.46 |
//! | 40 ms / 3%    | 3.50    | 2.35        | 1.15 |
//! | 60 ms / 5%    | 2.98    | 1.27        | 1.71 |
//!
//! So `--filter "rtp.mos < 3"` selected streams the detail view called 3.5 and
//! healthy, and a Grafana alert on the histogram fired on a scale the interface
//! never displayed. An operator investigating that alert opened sipnab and saw
//! a different number for the same stream, which is the worst way to learn that
//! a tool disagrees with itself.

use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::quality::estimate_mos;
use sipnab::rtp::stream::{RtpStream, StreamKey};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Build a stream with the given jitter, loss and codec.
fn stream(jitter: f64, lost: u64, received: u64, codec: Option<&str>) -> RtpStream {
    let key = StreamKey {
        ssrc: 0x1234_5678,
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
    };
    let hdr = RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 0,
        sequence: 100,
        timestamp: 0,
        ssrc: 0x1234_5678,
        payload_offset: 12,
    };
    let mut s = RtpStream::new(key, &hdr, chrono::Utc::now());
    s.jitter = jitter;
    s.lost_packets = lost;
    s.packet_count = received;
    s.codec = codec.map(str::to_string);
    s
}

/// The filter path and the display path agree, at every quality level.
///
/// Asserted across the range where the two formulas used to diverge most, so a
/// reintroduced approximation cannot hide in the healthy end of the scale.
#[test]
fn the_filter_scores_a_stream_exactly_as_the_display_does() {
    for (jitter, lost, total, codec) in [
        (0.0_f64, 0_u64, 1000_u64, Some("PCMU")),
        (5.0, 0, 1000, Some("PCMU")),
        (20.0, 10, 1000, Some("PCMU")),
        (40.0, 30, 1000, Some("G729")),
        (60.0, 50, 1000, Some("PCMU")),
        (80.0, 100, 1000, None),
        (150.0, 200, 1000, Some("opus")),
    ] {
        let s = stream(jitter, lost, total - lost, codec);
        let displayed = {
            let received = total - lost;
            let loss_pct = lost as f64 / (received + lost) as f64 * 100.0;
            estimate_mos(jitter, loss_pct, codec)
        };
        let filtered = sipnab::sip::dsl::stream_mos(&s);
        assert!(
            (displayed - filtered).abs() < 1e-9,
            "jitter {jitter} loss {lost}/{total} codec {codec:?}: the filter \
             scored {filtered:.4} and the display {displayed:.4}. One tool, \
             one number."
        );
    }
}

/// The codec matters, which is half of what the approximation threw away.
///
/// G.729 carries a published equipment impairment factor and G.711 does not;
/// a formula that ignores the codec cannot tell a compressed leg from a clean
/// one, and rated them identically.
#[test]
fn the_filter_now_distinguishes_codecs() {
    let g711 = sipnab::sip::dsl::stream_mos(&stream(10.0, 10, 990, Some("PCMU")));
    let g729 = sipnab::sip::dsl::stream_mos(&stream(10.0, 10, 990, Some("G729")));
    assert!(
        g711 > g729,
        "G.729 compression impairment must score below G.711 on identical \
         network conditions; got {g711:.2} vs {g729:.2}"
    );
}

/// A stream that has seen nothing scores as unknown, not as perfect.
#[test]
fn an_empty_stream_does_not_score_as_flawless() {
    let mos = sipnab::sip::dsl::stream_mos(&stream(0.0, 0, 0, None));
    assert!(
        (1.0..=4.5).contains(&mos),
        "an empty stream produced {mos}, which is not a MOS"
    );
}
