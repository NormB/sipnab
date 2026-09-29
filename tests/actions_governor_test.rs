// SPDX-License-Identifier: MIT OR Apache-2.0

//! The action rate limit: always on, and not the read limit (ACTIONS-HARDEN).
//!
//! Written before the behavior exists. Norm, 2026-09-28: "rate limiting tests
//! and rate limiting must be enabled". An action changes another system, so a
//! caller holding a stolen `actions` token must not be able to ban at the rate
//! the REST read limit allows (100 a second, per peer).
//!
//! Three limits, checked on every action:
//!
//! * server-wide actions per minute, across every caller and surface;
//! * actions per minute from one caller;
//! * one action per address per cooldown, so an address cannot be banned and
//!   unbanned in a loop.
//!
//! Every test drives the clock itself, so none of them sleeps.

#![cfg(feature = "full")]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use sipnab::security::actions::{ActionGovernor, ActionLimits, ActionThrottle};

fn addr(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
}

fn limits(per_minute: u64, per_caller: u64, cooldown_secs: u64) -> ActionLimits {
    ActionLimits::new(per_minute, per_caller, Duration::from_secs(cooldown_secs))
        .expect("valid limits")
}

#[test]
fn the_shipped_limits_are_on_and_modest() {
    let d = ActionLimits::default();
    assert_eq!(d.per_minute(), 10);
    assert_eq!(d.per_caller_per_minute(), 5);
    assert_eq!(d.address_cooldown(), Duration::from_secs(60));
}

#[test]
fn the_server_wide_limit_holds_across_callers() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 10, 60), 1024, t0);
    for i in 0..10u8 {
        g.admit(&format!("caller-{i}"), addr(i), t0)
            .expect("within the limit");
    }
    let refused = g
        .admit("caller-99", addr(99), t0)
        .expect_err("the eleventh");
    assert!(
        matches!(refused, ActionThrottle::ServerWide { .. }),
        "{refused:?}"
    );
}

#[test]
fn one_caller_cannot_spend_everyone_elses_allowance() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 5, 60), 1024, t0);
    for i in 0..5u8 {
        g.admit("stolen-token", addr(i), t0)
            .expect("within the caller's limit");
    }
    let refused = g
        .admit("stolen-token", addr(50), t0)
        .expect_err("the sixth");
    assert!(
        matches!(refused, ActionThrottle::PerCaller { .. }),
        "{refused:?}"
    );
    g.admit("operator", addr(60), t0)
        .expect("another caller still has its own allowance");
}

#[test]
fn an_address_cannot_flap() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 5, 60), 1024, t0);
    g.admit("operator", addr(1), t0).expect("the ban");
    let refused = g
        .admit("operator", addr(1), t0 + Duration::from_secs(10))
        .expect_err("the unban ten seconds later");
    match refused {
        ActionThrottle::Address { retry_after } => {
            assert_eq!(retry_after, Duration::from_secs(50), "{refused:?}");
        }
        other => panic!("expected an address cooldown, got {other:?}"),
    }
    g.admit("operator", addr(1), t0 + Duration::from_secs(60))
        .expect("after the cooldown");
}

#[test]
fn the_window_resets_after_a_minute() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(2, 2, 1), 1024, t0);
    g.admit("a", addr(1), t0).expect("one");
    g.admit("a", addr(2), t0).expect("two");
    g.admit("a", addr(3), t0).expect_err("three is over");
    g.admit("a", addr(3), t0 + Duration::from_secs(60))
        .expect("a new minute");
}

#[test]
fn a_refused_action_does_not_spend_allowance() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 2, 60), 1024, t0);
    g.admit("a", addr(1), t0).expect("one");
    // Refused for the address cooldown: must not count against the caller.
    for _ in 0..5 {
        g.admit("a", addr(1), t0).expect_err("cooling down");
    }
    g.admit("a", addr(2), t0)
        .expect("the refusals did not use up the caller's second action");
}

#[test]
fn a_refusal_says_when_to_retry() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(1, 1, 1), 1024, t0);
    g.admit("a", addr(1), t0).expect("one");
    let refused = g
        .admit("a", addr(2), t0 + Duration::from_secs(20))
        .expect_err("over");
    assert_eq!(
        refused.retry_after(),
        Duration::from_secs(40),
        "the rest of the minute: {refused:?}"
    );
}

#[test]
fn the_limits_cannot_be_turned_off() {
    for (per_minute, per_caller, cooldown) in [(0, 5, 60), (10, 0, 60), (10, 5, 0)] {
        let err = ActionLimits::new(per_minute, per_caller, Duration::from_secs(cooldown))
            .expect_err("zero would disable a limit");
        assert!(err.contains("cannot be turned off"), "{err}");
    }
}

#[test]
fn a_per_caller_limit_above_the_server_limit_is_refused() {
    let err = ActionLimits::new(5, 10, Duration::from_secs(60)).expect_err("unreachable limit");
    assert!(err.contains("per caller"), "{err}");
}

#[test]
fn a_flood_of_callers_cannot_grow_memory_without_bound() {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(600, 1, 1), 64, t0);
    let mut too_many = 0;
    for i in 0..500u32 {
        let a = IpAddr::V4(Ipv4Addr::from(0xC633_6400 + i));
        if let Err(ActionThrottle::TooManyCallers) = g.admit(&format!("forged-{i}"), a, t0) {
            too_many += 1;
        }
    }
    assert!(too_many > 0, "the tracking bound refused nobody");
    assert!(g.tracked_callers() <= 64, "{}", g.tracked_callers());
    assert!(g.tracked_addresses() <= 64, "{}", g.tracked_addresses());
}

#[test]
fn one_caller_touching_many_addresses_cannot_grow_memory_without_bound() {
    // The caller bound cannot help here: there is only one caller. The
    // address cooldowns are their own map and need their own bound.
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(600, 600, 60), 8, t0);
    let mut admitted = 0;
    let mut refused = 0;
    for i in 0..20u8 {
        match g.admit("operator", addr(i), t0) {
            Ok(()) => admitted += 1,
            Err(ActionThrottle::TooManyCallers) => refused += 1,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(admitted, 8, "the bound admits exactly as many as it tracks");
    assert_eq!(refused, 12);
    assert!(g.tracked_addresses() <= 8, "{}", g.tracked_addresses());
    // Once the cooldowns have run out, the map makes room again.
    g.admit("operator", addr(100), t0 + Duration::from_secs(61))
        .expect("expired cooldowns are dropped to make room");
    assert!(g.tracked_addresses() <= 8, "{}", g.tracked_addresses());
}
