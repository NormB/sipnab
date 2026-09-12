// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which relay asserted an endpoint, and what that assertion is worth (RP3).
//!
//! Written before the behavior exists, in Given/When/Then, because the point
//! of the entry is a distinction that does not yet appear anywhere in the
//! output: sipnab can say "a relay said so" and cannot say WHICH relay or HOW
//! the claim arrived.
//!
//! # Why that is not cosmetic
//!
//! The two relays have different trust properties and different failure modes.
//! VAL8 established that a sniffed assertion is authenticated by nothing and
//! gated it on destination port; that gate is keyed on an rtpengine-shaped
//! port, so its meaning for an rtpproxy deployment is UNDEFINED rather than
//! safe. An estate running both gets one word, `relay`, covering two claims
//! worth different amounts.

#![cfg(feature = "full")]

use sipnab::relay::{ControlDelivery, RelayImplementation};
use sipnab::rtp::stream_store::EndpointAssertion;

// ── The assertion names its author ───────────────────────────────────────────

/// GIVEN an endpoint rtpengine asserted over its encapsulated control plane
/// WHEN the assertion is reported
/// THEN it names rtpengine, and says the claim arrived encapsulated.
#[test]
fn an_encapsulated_rtpengine_assertion_names_its_author_and_its_path() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::Encapsulated,
    );
    assert_eq!(a.implementation(), Some(RelayImplementation::Rtpengine));
    assert_eq!(a.delivery(), Some(ControlDelivery::Encapsulated));
}

/// GIVEN an endpoint rtpproxy asserted in a sniffed datagram
/// WHEN the assertion is reported
/// THEN it names rtpproxy, and says the claim arrived as a bare datagram.
#[test]
fn a_sniffed_rtpproxy_assertion_names_its_author_and_its_path() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpproxy,
        ControlDelivery::BareDatagram,
    );
    assert_eq!(a.implementation(), Some(RelayImplementation::Rtpproxy));
    assert_eq!(a.delivery(), Some(ControlDelivery::BareDatagram));
}

/// GIVEN an endpoint the parties advertised in SDP
/// WHEN the assertion is reported
/// THEN it names no relay and no delivery path, because neither exists.
#[test]
fn a_signaled_endpoint_names_no_relay() {
    let a = EndpointAssertion::Signaled;
    assert_eq!(a.implementation(), None, "SDP has no relay behind it");
    assert_eq!(a.delivery(), None, "and no control path to describe");
}

// ── What a claim is worth ────────────────────────────────────────────────────

/// GIVEN an assertion that arrived as a bare datagram
/// WHEN its trustworthiness is asked for
/// THEN it reports that nothing authenticated it.
///
/// The whole reason the delivery path travels with the assertion. A reader
/// deciding how much to lean on a media anchor needs to know whether anything
/// vouched for the claim, and "a relay said so" does not answer that.
#[test]
fn a_bare_datagram_assertion_admits_nothing_authenticated_it() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpproxy,
        ControlDelivery::BareDatagram,
    );
    assert!(
        !a.is_authenticated(),
        "a datagram read off the wire carries no credential"
    );
}

/// GIVEN an assertion that arrived encapsulated
/// WHEN its trustworthiness is asked for
/// THEN it may report authentication, because the transport can carry it.
#[test]
fn an_encapsulated_assertion_may_be_authenticated() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::Encapsulated,
    );
    assert!(a.is_authenticated());
}

/// GIVEN two assertions differing only in delivery path
/// WHEN they are compared
/// THEN they are not equal, because they are not worth the same.
#[test]
fn delivery_path_is_part_of_the_claim_not_a_footnote() {
    let bare = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::BareDatagram,
    );
    let wrapped = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::Encapsulated,
    );
    assert_ne!(
        bare, wrapped,
        "collapsing these loses the only fact that says how much to lean on \
         the anchor"
    );
}

/// GIVEN two assertions from different relays over the same path
/// WHEN they are compared
/// THEN they are not equal, because the estate runs both.
#[test]
fn two_relays_over_one_path_are_still_two_claims() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::BareDatagram,
    );
    let b = EndpointAssertion::media_relay(
        RelayImplementation::Rtpproxy,
        ControlDelivery::BareDatagram,
    );
    assert_ne!(a, b);
}

// ── One spelling, in one place ───────────────────────────────────────────────

/// GIVEN each relay implementation
/// WHEN it is written to an output surface
/// THEN it has exactly one spelling, and the two differ.
#[test]
fn each_relay_has_one_spelling_and_they_differ() {
    assert_eq!(RelayImplementation::Rtpengine.as_str(), "rtpengine");
    assert_eq!(RelayImplementation::Rtpproxy.as_str(), "rtpproxy");
    assert_ne!(
        RelayImplementation::Rtpengine.as_str(),
        RelayImplementation::Rtpproxy.as_str()
    );
}

/// GIVEN a relay assertion
/// WHEN it is written to an output surface
/// THEN the existing `asserted_by` word is unchanged.
///
/// RP3 extends RV1 rather than replacing it. A consumer reading `media_relay`
/// today must keep reading it, or this is a breaking rename wearing a feature's
/// clothes.
#[test]
fn the_existing_assertion_word_is_not_renamed() {
    let a = EndpointAssertion::media_relay(
        RelayImplementation::Rtpproxy,
        ControlDelivery::BareDatagram,
    );
    assert_eq!(
        a.as_str(),
        EndpointAssertion::media_relay(
            RelayImplementation::Rtpengine,
            ControlDelivery::Encapsulated
        )
        .as_str(),
        "the assertion KIND is one word; which relay is a separate field"
    );
}
