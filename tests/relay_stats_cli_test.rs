// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST7 / C1: `--relay-stats` decides what to do before it transmits.
//!
//! The fetch itself transmits and is exercised against the live harness, not
//! here. What IS testable in the sandbox is the decision that precedes it: not
//! asked, no relay named, no permit, or fetch -- and the first three map to
//! ST-S4's `not_configured` and `not_permitted`. `relay_stats_action` is that
//! decision as a pure function.

#![cfg(feature = "full")]

use sipnab::app::bootstrap::{RelayStatsAction, relay_stats_action};

/// The flag off is a skip, whatever else is true -- nothing transmits unbidden.
#[test]
fn without_the_flag_nothing_is_asked() {
    assert_eq!(
        relay_stats_action(false, Some("127.0.0.1:22222"), true),
        RelayStatsAction::Skip
    );
    assert_eq!(
        relay_stats_action(false, None, false),
        RelayStatsAction::Skip
    );
}

/// Asked with no relay named is not_configured -- the operator names one.
#[test]
fn asked_with_no_relay_is_not_configured() {
    assert_eq!(
        relay_stats_action(true, None, true),
        RelayStatsAction::NotConfigured,
        "no relay to ask; the fix is to name one"
    );
}

/// Asked with a relay but no permit is not_permitted -- a file-backed run.
///
/// Ordered after the no-relay case on purpose: an operator who named no relay
/// has a different fix than one whose run cannot transmit, so the two are never
/// collapsed.
#[test]
fn asked_with_a_relay_but_no_permit_is_not_permitted() {
    assert_eq!(
        relay_stats_action(true, Some("127.0.0.1:22222"), false),
        RelayStatsAction::NotPermitted,
        "asking transmits; a file-backed run may not"
    );
}

/// Asked, a relay named, and a permit in hand: fetch, carrying the address.
#[test]
fn asked_with_a_relay_and_a_permit_is_a_fetch() {
    assert_eq!(
        relay_stats_action(true, Some("10.0.0.2:22222"), true),
        RelayStatsAction::Fetch("10.0.0.2:22222".to_owned()),
        "the address the operator named is carried to the fetch verbatim"
    );
}

/// The `--relay-stats` flag parses and sets its field; without it the field is
/// off. This is also where the flag token is referenced, so the coverage gate
/// sees the flag has a test.
#[test]
fn the_relay_stats_flag_parses() {
    use clap::Parser;
    let on = sipnab::cli::Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap", "--relay-stats"])
        .expect("--relay-stats parses");
    assert!(on.rtp_args.relay_stats, "--relay-stats sets the flag");

    let off =
        sipnab::cli::Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap"]).expect("bare parse");
    assert!(!off.rtp_args.relay_stats, "the flag is off unless given");
}
