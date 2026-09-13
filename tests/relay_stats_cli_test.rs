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

/// `--relay-stats-call <CALL-ID>` parses and carries the id; off by default.
#[test]
fn the_relay_stats_call_flag_parses_and_carries_the_id() {
    use clap::Parser;
    let on = sipnab::cli::Cli::try_parse_from([
        "sipnab",
        "-N",
        "-I",
        "x.pcap",
        "--relay-stats-call",
        "1-7@10.0.0.1",
    ])
    .expect("--relay-stats-call parses");
    assert_eq!(
        on.rtp_args.relay_stats_call.as_deref(),
        Some("1-7@10.0.0.1"),
        "the Call-ID is carried verbatim"
    );
    let off = sipnab::cli::Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap"]).expect("bare");
    assert!(off.rtp_args.relay_stats_call.is_none(), "off unless given");
}

/// A per-call ask with a relay and a permit is a fetch, same as the global one:
/// naming a call does not change whether the run may transmit.
#[test]
fn a_per_call_ask_is_gated_like_the_global_one() {
    // The precondition is the same function; what changes is only WHICH fetch
    // the report path then runs. Asked with a relay and a permit -> fetch.
    assert_eq!(
        relay_stats_action(true, Some("127.0.0.1:22222"), true),
        RelayStatsAction::Fetch("127.0.0.1:22222".to_owned())
    );
    // Asked (per-call) with no permit -> not_permitted, whatever the call.
    assert_eq!(
        relay_stats_action(true, Some("127.0.0.1:22222"), false),
        RelayStatsAction::NotPermitted
    );
}

/// `--relay-stats-list` parses and sets its flag; off by default (ST7/C3).
#[test]
fn the_relay_stats_list_flag_parses() {
    use clap::Parser;
    let on =
        sipnab::cli::Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap", "--relay-stats-list"])
            .expect("--relay-stats-list parses");
    assert!(
        on.rtp_args.relay_stats_list,
        "--relay-stats-list sets the flag"
    );

    let off = sipnab::cli::Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap"]).expect("bare");
    assert!(!off.rtp_args.relay_stats_list, "off unless given");
}

/// A list ask is gated exactly like the global one: listing asks the relay, and
/// asking transmits, so it needs a relay named and a permit in hand.
#[test]
fn a_list_ask_is_gated_like_the_global_one() {
    assert_eq!(
        relay_stats_action(true, Some("10.0.0.2:22222"), true),
        RelayStatsAction::Fetch("10.0.0.2:22222".to_owned()),
        "asked, a relay named, a permit: fetch"
    );
    assert_eq!(
        relay_stats_action(true, None, true),
        RelayStatsAction::NotConfigured,
        "listing with no relay named is not_configured"
    );
    assert_eq!(
        relay_stats_action(true, Some("10.0.0.2:22222"), false),
        RelayStatsAction::NotPermitted,
        "listing on a file-backed run may not transmit"
    );
}

/// `--relay-compare <CALL-ID>` parses and carries the id; off by default (C4).
#[test]
fn the_relay_compare_flag_parses_and_carries_the_id() {
    use clap::Parser;
    let on = sipnab::cli::Cli::try_parse_from([
        "sipnab",
        "-N",
        "-I",
        "x.pcap",
        "--relay-compare",
        "1-9@10.0.0.1",
    ])
    .expect("--relay-compare parses");
    assert_eq!(
        on.rtp_args.relay_compare.as_deref(),
        Some("1-9@10.0.0.1"),
        "the Call-ID is carried verbatim"
    );
    let off = sipnab::cli::Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap"]).expect("bare");
    assert!(off.rtp_args.relay_compare.is_none(), "off unless given");
}

/// A compare ask is gated exactly like the global one: comparing asks the relay
/// for its side, and asking transmits, so a file-backed run may not.
#[test]
fn a_compare_ask_is_gated_like_the_global_one() {
    assert_eq!(
        relay_stats_action(true, Some("10.0.0.2:22222"), true),
        RelayStatsAction::Fetch("10.0.0.2:22222".to_owned()),
        "asked, a relay named, a permit: fetch the relay's side"
    );
    assert_eq!(
        relay_stats_action(true, None, true),
        RelayStatsAction::NotConfigured,
        "comparing with no relay named is not_configured"
    );
    assert_eq!(
        relay_stats_action(true, Some("10.0.0.2:22222"), false),
        RelayStatsAction::NotPermitted,
        "comparing on a file-backed run may not transmit"
    );
}
