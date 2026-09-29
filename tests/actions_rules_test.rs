// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an action may ask for, checked before anything reaches TFPS
//! (ACTIONS-HARDEN, JOURNAL; approved 2026-09-28).
//!
//! Written before the behavior exists. Two rules from the approved journal
//! spec and Norm's hardening requirement:
//!
//! * some addresses are never banned, whoever asks: banning the unspecified
//!   address, broadcast, loopback or a multicast group harms the network
//!   rather than a source;
//! * every ban sipnab asks for expires: 1 hour unless the caller says
//!   otherwise, 7 days at most, and never "forever", so a stale ban ends on
//!   its own even if nobody reverts it.

#![cfg(feature = "full")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sipnab::security::actions::{ActionLimits, BanRule, ban_ttl, check_ban_address, token_caller};

#[test]
fn addresses_that_are_never_banned() {
    for (ip, rule) in [
        (Ipv4Addr::UNSPECIFIED, BanRule::Unspecified),
        (Ipv4Addr::BROADCAST, BanRule::Broadcast),
        (Ipv4Addr::new(127, 0, 0, 1), BanRule::Loopback),
        (Ipv4Addr::new(127, 9, 9, 9), BanRule::Loopback),
        (Ipv4Addr::new(224, 0, 0, 1), BanRule::Multicast),
        (Ipv4Addr::new(239, 255, 255, 250), BanRule::Multicast),
    ] {
        assert_eq!(check_ban_address(IpAddr::V4(ip)), Err(rule), "{ip}");
    }
}

#[test]
fn an_ordinary_source_may_be_banned() {
    for ip in [
        Ipv4Addr::new(198, 51, 100, 20),
        Ipv4Addr::new(203, 0, 113, 7),
        Ipv4Addr::new(10, 1, 2, 3),
    ] {
        assert_eq!(check_ban_address(IpAddr::V4(ip)), Ok(()), "{ip}");
    }
}

#[test]
fn an_ipv6_address_is_refused_because_tfps_bans_ipv4_only() {
    assert_eq!(
        check_ban_address(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        Err(BanRule::NotIpv4)
    );
}

#[test]
fn a_refusal_names_the_rule_in_words_an_operator_reads() {
    let text = BanRule::Loopback.to_string();
    assert!(text.contains("loopback"), "{text}");
    assert!(text.contains("never"), "{text}");
}

#[test]
fn a_ban_with_no_lifetime_given_lasts_an_hour() {
    assert_eq!(ban_ttl(None, &ActionLimits::default()), Ok(3600));
}

#[test]
fn a_lifetime_within_the_bounds_is_kept() {
    let l = ActionLimits::default();
    assert_eq!(ban_ttl(Some(60), &l), Ok(60));
    assert_eq!(ban_ttl(Some(7 * 86_400), &l), Ok(7 * 86_400));
}

#[test]
fn a_ban_that_never_expires_is_refused() {
    let err = ban_ttl(Some(0), &ActionLimits::default()).expect_err("forever");
    assert_eq!(err, BanRule::Forever);
    assert!(err.to_string().contains("expire"), "{err}");
}

#[test]
fn a_lifetime_over_the_maximum_is_refused_not_trimmed() {
    // Trimming would ban for a time nobody asked for; refusing says why.
    let err = ban_ttl(Some(7 * 86_400 + 1), &ActionLimits::default()).expect_err("too long");
    assert_eq!(
        err,
        BanRule::TooLong {
            max_secs: 7 * 86_400
        }
    );
}

/// The journal names a caller by its token's id, never by the token, and on
/// every surface the same way.
#[test]
fn a_token_caller_is_named_by_its_id() {
    assert_eq!(token_caller(Some("ops-console")), "token:ops-console");
    assert_eq!(
        token_caller(None),
        "token",
        "a static key has no id to name"
    );
}

/// The id comes from a signed claim with no length limit; one record per
/// action must not carry an unbounded field.
#[test]
fn a_long_token_id_is_bounded_and_marked() {
    let id = "x".repeat(500);
    let named = token_caller(Some(&id));
    assert!(named.starts_with("token:"), "{named}");
    assert!(named.ends_with("(truncated)"), "{named}");
    assert!(named.chars().count() <= 6 + 64 + 12, "{}", named.len());
    assert_eq!(
        token_caller(Some(&"y".repeat(64))),
        format!("token:{}", "y".repeat(64))
    );
}
