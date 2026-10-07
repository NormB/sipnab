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

type TestError = Box<dyn std::error::Error>;

fn addr(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
}

fn limits(per_minute: u64, per_caller: u64, cooldown_secs: u64) -> Result<ActionLimits, TestError> {
    Ok(
        ActionLimits::new(per_minute, per_caller, Duration::from_secs(cooldown_secs))
            .map_err(|e| format!("valid limits: {e}"))?,
    )
}

#[test]
fn the_shipped_limits_are_on_and_modest() -> Result<(), TestError> {
    let d = ActionLimits::default();
    assert_eq!(d.per_minute(), 10);
    assert_eq!(d.per_caller_per_minute(), 5);
    assert_eq!(d.address_cooldown(), Duration::from_secs(60));
    Ok(())
}

#[test]
fn the_server_wide_limit_holds_across_callers() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 10, 60)?, 1024, t0);
    for i in 0..10u8 {
        g.admit(&format!("caller-{i}"), addr(i), t0)
            .map_err(|e| format!("within the limit: {e:?}"))?;
    }
    let refused = g
        .admit("caller-99", addr(99), t0)
        .err()
        .ok_or("expected an error: the eleventh")?;
    assert!(
        matches!(refused, ActionThrottle::ServerWide { .. }),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn one_caller_cannot_spend_everyone_elses_allowance() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 5, 60)?, 1024, t0);
    for i in 0..5u8 {
        g.admit("stolen-token", addr(i), t0)
            .map_err(|e| format!("within the caller's limit: {e:?}"))?;
    }
    let refused = g
        .admit("stolen-token", addr(50), t0)
        .err()
        .ok_or("expected an error: the sixth")?;
    assert!(
        matches!(refused, ActionThrottle::PerCaller { .. }),
        "{refused:?}"
    );
    g.admit("operator", addr(60), t0)
        .map_err(|e| format!("another caller still has its own allowance: {e:?}"))?;
    Ok(())
}

#[test]
fn an_address_cannot_flap() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 5, 60)?, 1024, t0);
    g.admit("operator", addr(1), t0)
        .map_err(|e| format!("the ban: {e:?}"))?;
    let refused = g
        .admit("operator", addr(1), t0 + Duration::from_secs(10))
        .err()
        .ok_or("expected an error: the unban ten seconds later")?;
    match refused {
        ActionThrottle::Address { retry_after } => {
            assert_eq!(retry_after, Duration::from_secs(50), "{refused:?}");
        }
        other => return Err(format!("expected an address cooldown, got {other:?}").into()),
    }
    g.admit("operator", addr(1), t0 + Duration::from_secs(60))
        .map_err(|e| format!("after the cooldown: {e:?}"))?;
    Ok(())
}

#[test]
fn the_window_resets_after_a_minute() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(2, 2, 1)?, 1024, t0);
    g.admit("a", addr(1), t0)
        .map_err(|e| format!("one: {e:?}"))?;
    g.admit("a", addr(2), t0)
        .map_err(|e| format!("two: {e:?}"))?;
    g.admit("a", addr(3), t0)
        .err()
        .ok_or("expected an error: three is over")?;
    g.admit("a", addr(3), t0 + Duration::from_secs(60))
        .map_err(|e| format!("a new minute: {e:?}"))?;
    Ok(())
}

#[test]
fn a_refused_action_does_not_spend_allowance() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(10, 2, 60)?, 1024, t0);
    g.admit("a", addr(1), t0)
        .map_err(|e| format!("one: {e:?}"))?;
    // Refused for the address cooldown: must not count against the caller.
    for _ in 0..5 {
        g.admit("a", addr(1), t0)
            .err()
            .ok_or("expected an error: cooling down")?;
    }
    g.admit("a", addr(2), t0)
        .map_err(|e| format!("the refusals did not use up the caller's second action: {e:?}"))?;
    Ok(())
}

#[test]
fn a_refusal_says_when_to_retry() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(1, 1, 1)?, 1024, t0);
    g.admit("a", addr(1), t0)
        .map_err(|e| format!("one: {e:?}"))?;
    let refused = g
        .admit("a", addr(2), t0 + Duration::from_secs(20))
        .err()
        .ok_or("expected an error: over")?;
    assert_eq!(
        refused.retry_after(),
        Duration::from_secs(40),
        "the rest of the minute: {refused:?}"
    );
    Ok(())
}

#[test]
fn the_limits_cannot_be_turned_off() -> Result<(), TestError> {
    for (per_minute, per_caller, cooldown) in [(0, 5, 60), (10, 0, 60), (10, 5, 0)] {
        let err = ActionLimits::new(per_minute, per_caller, Duration::from_secs(cooldown))
            .err()
            .ok_or("expected an error: zero would disable a limit")?;
        assert!(err.contains("cannot be turned off"), "{err}");
    }
    Ok(())
}

#[test]
fn a_per_caller_limit_above_the_server_limit_is_refused() -> Result<(), TestError> {
    let err = ActionLimits::new(5, 10, Duration::from_secs(60))
        .err()
        .ok_or("expected an error: unreachable limit")?;
    assert!(err.contains("per caller"), "{err}");
    Ok(())
}

#[test]
fn a_flood_of_callers_cannot_grow_memory_without_bound() -> Result<(), TestError> {
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(600, 1, 1)?, 64, t0);
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
    Ok(())
}

#[test]
fn one_caller_touching_many_addresses_cannot_grow_memory_without_bound() -> Result<(), TestError> {
    // The caller bound cannot help here: there is only one caller. The
    // address cooldowns are their own map and need their own bound.
    let t0 = Instant::now();
    let mut g = ActionGovernor::new(limits(600, 600, 60)?, 8, t0);
    let mut admitted = 0;
    let mut refused = 0;
    for i in 0..20u8 {
        match g.admit("operator", addr(i), t0) {
            Ok(()) => admitted += 1,
            Err(ActionThrottle::TooManyCallers) => refused += 1,
            Err(other) => return Err(format!("unexpected {other:?}").into()),
        }
    }
    assert_eq!(admitted, 8, "the bound admits exactly as many as it tracks");
    assert_eq!(refused, 12);
    assert!(g.tracked_addresses() <= 8, "{}", g.tracked_addresses());
    // Once the cooldowns have run out, the map makes room again.
    g.admit("operator", addr(100), t0 + Duration::from_secs(61))
        .map_err(|e| format!("expired cooldowns are dropped to make room: {e:?}"))?;
    assert!(g.tracked_addresses() <= 8, "{}", g.tracked_addresses());
    Ok(())
}
