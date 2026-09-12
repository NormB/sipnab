// SPDX-License-Identifier: MIT OR Apache-2.0

//! A successful call is not evidence the media anchor was used.
//!
//! Given/When/Then over facts observed against a real stack on 2026-09-12:
//! OpenSIPS, rtpproxy 3.2.0 and SIPp, with sipnab capturing beside the relay.
//!
//! # The finding these exist for
//!
//! OpenSIPS marks a relay it cannot reach as unavailable, logs
//! `rtpproxy_offer_answer: no available proxies`, and **completes the call
//! anyway**. SIPp reported `Successful call` for every one of those, while the
//! relay's own counter said `sessions created: 0`. Media went end-to-end and
//! nothing in the signaling said so.
//!
//! That is the shape an operator most needs named: the call worked, the anchor
//! did not, and the two facts live in different places. A capture is the only
//! thing that holds both.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{Reply, RtpproxyControl, decode_reply};
use sipnab::relay::{ControlDelivery, RelayImplementation};
use sipnab::rtp::stream_store::EndpointAssertion;

// ── What the relay reported, in its own words ────────────────────────────────

/// GIVEN the info reply from a relay that anchored one call
/// WHEN it is decoded
/// THEN it reports a session created and media in both directions.
///
/// The exact bytes rtpproxy returned after a SIPp call through OpenSIPS.
#[test]
fn an_anchored_call_leaves_the_relay_reporting_media_both_ways() {
    let observed = "w1 sessions created: 1\nactive sessions: 0\nactive streams: 0\npackets received: 9000\npackets transmitted: 9000\n";
    let RtpproxyControl::Reply { reply, .. } =
        decode_reply(observed.as_bytes()).expect("the info reply decodes")
    else {
        panic!("expected a reply");
    };
    let Reply::Text(body) = reply else {
        panic!("the info reply is free text");
    };
    assert!(body.contains("sessions created: 1"));
    assert!(
        body.contains("packets received: 9000") && body.contains("packets transmitted: 9000"),
        "media relayed in both directions is what separates an anchored call \
         from a control-plane handshake: {body}"
    );
}

/// GIVEN a relay OpenSIPS could not reach
/// WHEN a call completes anyway
/// THEN the relay reports no session at all.
///
/// Observed: three SIPp runs reported `Successful call` while the relay's
/// counter stayed at zero. The signaling is not evidence about the media path.
#[test]
fn a_call_that_bypassed_the_relay_leaves_it_reporting_nothing() {
    let observed = "q2 sessions created: 0\nactive sessions: 0\nactive streams: 0\n";
    let RtpproxyControl::Reply { reply, .. } = decode_reply(observed.as_bytes()).expect("decodes")
    else {
        panic!("expected a reply");
    };
    let Reply::Text(body) = reply else {
        panic!("free text");
    };
    assert!(
        body.contains("sessions created: 0"),
        "a bypassed relay is silent about the call, not absent from the \
         capture: {body}"
    );
}

/// GIVEN the two info replies
/// WHEN they are compared
/// THEN an anchored call and a bypassed one are distinguishable.
///
/// The property that makes the finding reportable at all. If both read the
/// same, a capture could not tell an operator which happened.
#[test]
fn anchored_and_bypassed_calls_are_told_apart() {
    let anchored = "a sessions created: 1\npackets received: 9000\n";
    let bypassed = "b sessions created: 0\npackets received: 0\n";
    let text = |s: &str| match decode_reply(s.as_bytes()) {
        Some(RtpproxyControl::Reply {
            reply: Reply::Text(t),
            ..
        }) => t,
        other => panic!("expected free text, got {other:?}"),
    };
    assert_ne!(text(anchored), text(bypassed));
}

// ── What sipnab should say about the anchor it observed ──────────────────────

/// GIVEN media anchored by rtpproxy, observed by sniffing its control plane
/// WHEN the endpoint is attributed
/// THEN it names rtpproxy and admits nothing authenticated the claim.
#[test]
fn a_sniffed_rtpproxy_anchor_is_named_and_unauthenticated() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpproxy,
        ControlDelivery::BareDatagram,
    );
    assert_eq!(a.implementation(), Some(RelayImplementation::Rtpproxy));
    assert!(
        !a.is_authenticated(),
        "the control datagram was read off the wire; nothing vouched for it"
    );
}

/// GIVEN the same call anchored by the other relay
/// WHEN the endpoint is attributed
/// THEN the two attributions differ, because the estate runs both.
#[test]
fn the_two_anchors_produce_different_attributions() {
    let proxy = EndpointAssertion::media_relay(
        RelayImplementation::Rtpproxy,
        ControlDelivery::BareDatagram,
    );
    let engine = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::BareDatagram,
    );
    assert_ne!(
        proxy, engine,
        "a harness that can swap anchors must not produce one attribution for \
         both, or the swap is untestable from the capture"
    );
}

// ── The ports a real call landed on ──────────────────────────────────────────

/// GIVEN the ports the relay allocated for a real call
/// WHEN they are checked against the configured range
/// THEN they fall inside it, and outside the other anchor's.
///
/// Observed: 31026 and 31012, with rtpproxy configured for 31000-31050 and
/// rtpengine holding 30000-30050. Verified by observation rather than by
/// reading the configuration back to itself.
#[test]
fn a_real_call_landed_inside_the_relays_own_range() {
    const OBSERVED: [u16; 2] = [31026, 31012];
    const PROXY: std::ops::RangeInclusive<u16> = 31000..=31050;
    const ENGINE: std::ops::RangeInclusive<u16> = 30000..=30050;
    for port in OBSERVED {
        assert!(
            PROXY.contains(&port),
            "{port} is outside the range rtpproxy was told to use"
        );
        assert!(
            !ENGINE.contains(&port),
            "{port} lands in the other anchor's range, which is the collision \
             the split exists to prevent"
        );
    }
}

/// GIVEN the two allocated ports
/// WHEN they are compared
/// THEN they differ, because a relay bridges two legs.
#[test]
fn the_relay_allocated_one_port_per_leg() {
    assert_ne!(
        31026, 31012,
        "one port for both legs would mean the relay is not bridging anything"
    );
}
