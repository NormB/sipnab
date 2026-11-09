// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The control transactions one engine may spend: a burst that refills.
//!
//! [`crate::relay::reconcile::Reconciler`] once held a ceiling for the whole
//! run, [`crate::relay::reconcile::DEFAULT_BUDGET`] (66) transactions per
//! engine. The ceiling does not depend
//! on the traffic, which is the point of it: a capture full of streams nothing
//! explains cannot turn into a flood of control traffic. But a run that lasts
//! days spends it, and from then on a call the engine set up later is never
//! named.
//!
//! [`TransactionBudget`] keeps the same burst and refills it over time, a
//! token bucket:
//!
//! - **The burst is unchanged.** A full budget holds [`crate::relay::reconcile::DEFAULT_BUDGET`]
//!   transactions, as the ceiling did, and never more however long it sits
//!   unspent. So the most an engine can be asked in one go is what it could be
//!   asked before.
//! - **The refill is [`DEFAULT_REFILL`]: 33 transactions an hour**, one every
//!   109 s. The burst was sized as a startup snapshot (one `list` and a
//!   `query` per call at the default list limit, 33) plus one comparable
//!   refresh (33 more). Startup happens once, so what a long run needs after
//!   it is refreshes, and one refresh's worth an hour lets a call set up later
//!   be named within the hour, while holding the long-run rate to one
//!   transaction every 109 s per engine. Each engine has its own budget, so
//!   a busy engine cannot spend a standby engine's.
//! - **A refill never asks anything.** It only lets a later question be
//!   asked. The only thing that spends is a stream nothing explains, as
//!   before.
//! - **Monotonic time.** The budget reads [`std::time::Instant`], so a wall
//!   clock stepped by NTP or by hand neither fills nor drains it. A reading
//!   earlier than the last one adds nothing.

use std::fmt;
use std::time::{Duration, Instant};

/// How fast a budget refills: one refresh's worth (a `list` and a `query` per
/// call at the default limit) an hour. See the module documentation for why.
pub const DEFAULT_REFILL: Refill = Refill {
    tokens: crate::relay::reconcile::DEFAULT_LIST_LIMIT + 1,
    per: Duration::from_secs(3600),
};

/// A refill rate: `tokens` transactions every `per`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refill {
    /// Transactions added each period.
    pub tokens: u32,
    /// The period.
    pub per: Duration,
}

impl Refill {
    /// The time one token takes, rounded up to the nanosecond: a token is
    /// whole only once this much time has passed.
    #[must_use]
    pub fn token_time(&self) -> Duration {
        let ns = self.per.as_nanos().div_ceil(u128::from(self.tokens.max(1)));
        Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
    }
}

impl fmt::Display for Refill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let per = match self.per.as_secs() {
            3600 if self.per.subsec_nanos() == 0 => "hour".to_owned(),
            60 if self.per.subsec_nanos() == 0 => "minute".to_owned(),
            _ => format!("{:?}", self.per),
        };
        write!(f, "{} per {per}", self.tokens)
    }
}

/// One engine's control transactions: up to a burst, refilled over time.
#[derive(Debug, Clone)]
pub struct TransactionBudget {
    /// The most it holds.
    burst: u32,
    /// What it holds as of `last`.
    tokens: u32,
    /// How fast it refills; `None` never refills.
    refill: Option<Refill>,
    /// The instant `tokens` was last brought up to date.
    last: Instant,
}

impl TransactionBudget {
    /// A full budget of `burst`, refilled at `refill`, as of `now`.
    ///
    /// A refill of no tokens or over no time is read as no refill: the first
    /// adds nothing, and the second would add without bound, which is the
    /// flood the burst exists to prevent.
    #[must_use]
    pub fn new(burst: u32, refill: Option<Refill>, now: Instant) -> Self {
        Self {
            burst,
            tokens: burst,
            refill: refill.filter(|r| r.tokens > 0 && !r.per.is_zero()),
            last: now,
        }
    }

    /// The most it holds.
    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    /// How fast it refills, `None` when it does not.
    #[must_use]
    pub const fn refill(&self) -> Option<Refill> {
        self.refill
    }

    /// What it holds at `now`.
    #[must_use]
    pub fn available(&self, now: Instant) -> u32 {
        self.topped_up(now).0
    }

    /// Spend one transaction at `now`, or refuse when none is left.
    pub fn try_spend(&mut self, now: Instant) -> bool {
        (self.tokens, self.last) = self.topped_up(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// How long after `now` the next transaction is added, `None` when it is
    /// full or never refills.
    #[must_use]
    pub fn next_in(&self, now: Instant) -> Option<Duration> {
        let refill = self.refill?;
        let (tokens, last) = self.topped_up(now);
        if tokens >= self.burst {
            return None;
        }
        let whole = refill.token_time();
        Some(whole.saturating_sub(now.saturating_duration_since(last)))
    }

    /// What it holds at `now`, and the instant its refill is counted from.
    ///
    /// The one rule for the refill, read by both [`Self::available`] and
    /// [`Self::try_spend`]. Whole tokens only: the part of a token already
    /// earned stays earned, because the instant counted from moves forward
    /// by exactly the time the whole tokens took. A full budget counts from
    /// `now`, so time spent full earns nothing. An earlier `now` than the last
    /// reading earns nothing and moves nothing back.
    fn topped_up(&self, now: Instant) -> (u32, Instant) {
        let Some(refill) = self.refill else {
            return (self.tokens, self.last);
        };
        if self.tokens >= self.burst {
            return (self.tokens, self.last.max(now));
        }
        let per = refill.per.as_nanos();
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        let earned = elapsed.saturating_mul(u128::from(refill.tokens)) / per;
        if earned == 0 {
            return (self.tokens, self.last);
        }
        let room = u128::from(self.burst - self.tokens);
        if earned >= room {
            return (self.burst, now);
        }
        // `earned` < `room` <= u32::MAX, and the time it took is at most
        // `elapsed`, so neither conversion can fail.
        let took = earned.saturating_mul(per) / u128::from(refill.tokens);
        let took = Duration::from_nanos(u64::try_from(took).unwrap_or(u64::MAX));
        (
            self.tokens + u32::try_from(earned).unwrap_or(0),
            self.last.checked_add(took).unwrap_or(now),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::reconcile::DEFAULT_BUDGET;

    type TestError = Box<dyn std::error::Error>;

    /// The time one token of the default refill takes: 3600 s / 33, rounded
    /// up to the nanosecond, since a token is whole only once that much time
    /// has passed.
    fn one_token() -> Duration {
        let per = DEFAULT_REFILL.per.as_nanos();
        let ns = per.div_ceil(u128::from(DEFAULT_REFILL.tokens));
        Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
    }

    /// `start` moved forward by `by`, failing the test rather than panicking
    /// when the platform cannot represent it.
    fn later(start: Instant, by: Duration) -> Result<Instant, TestError> {
        Ok(start
            .checked_add(by)
            .ok_or("the instant cannot be represented")?)
    }

    /// A default budget, full at `now`.
    fn default_at(now: Instant) -> TransactionBudget {
        TransactionBudget::new(DEFAULT_BUDGET, Some(DEFAULT_REFILL), now)
    }

    /// Spend until refused at `now`, and say how many were granted.
    fn drain(b: &mut TransactionBudget, now: Instant) -> u32 {
        let mut n = 0;
        while b.try_spend(now) {
            n += 1;
            assert!(n < 1_000_000, "a budget that never refuses");
        }
        n
    }

    // ── SUCCESS ────────────────────────────────────────────────────────

    /// A new budget is full: the whole burst is available at once.
    #[test]
    fn a_new_budget_holds_the_whole_burst() {
        let now = Instant::now();
        let mut b = default_at(now);
        assert_eq!(b.available(now), DEFAULT_BUDGET, "a new budget is full");
        assert_eq!(drain(&mut b, now), DEFAULT_BUDGET, "66 granted, as before");
    }

    /// One token's worth of time after it was spent, one is back.
    #[test]
    fn one_token_of_time_refills_one() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        let t = later(start, one_token())?;
        assert_eq!(b.available(t), 1, "one token of time refills exactly one");
        assert!(b.try_spend(t), "the refilled transaction can be spent");
        assert!(!b.try_spend(t), "and only that one");
        Ok(())
    }

    /// A run longer than the refill period: demand every second for three
    /// hours is granted the burst plus three hours of refill, no more.
    #[test]
    fn a_run_longer_than_the_refill_period_gets_burst_plus_refill() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let mut granted = 0_u32;
        for s in 0..=3 * 3600 {
            if b.try_spend(later(start, Duration::from_secs(s))?) {
                granted += 1;
            }
        }
        assert_eq!(
            granted,
            DEFAULT_BUDGET + 3 * DEFAULT_REFILL.tokens,
            "the burst plus three hours of refill, no more"
        );
        Ok(())
    }

    /// The wait for the next transaction is what is left of one token's time.
    #[test]
    fn next_in_says_how_long_until_the_next_transaction() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        assert_eq!(
            b.next_in(start),
            Some(one_token()),
            "empty at start, so the wait is one whole token"
        );
        let t = later(start, Duration::from_secs(9))?;
        assert_eq!(
            b.next_in(t),
            Some(one_token() - Duration::from_secs(9)),
            "nine seconds of the token have passed"
        );
        Ok(())
    }

    /// The default rate is one refresh's worth an hour, as the burst's two
    /// halves are each one refresh's worth.
    #[test]
    fn the_default_refill_is_one_refresh_an_hour() {
        assert_eq!(
            DEFAULT_REFILL.tokens * 2,
            DEFAULT_BUDGET,
            "the burst is two refreshes and the refill one"
        );
        assert_eq!(
            DEFAULT_REFILL.per,
            Duration::from_secs(3600),
            "the refill period is an hour"
        );
        assert_eq!(
            DEFAULT_REFILL.to_string(),
            "33 per hour",
            "the rate as the closing line prints it"
        );
    }

    // ── FAILURE ────────────────────────────────────────────────────────

    /// An empty budget refuses.
    #[test]
    fn an_empty_budget_refuses() {
        let now = Instant::now();
        let mut b = default_at(now);
        let _ = drain(&mut b, now);
        assert_eq!(
            b.available(now),
            0,
            "every transaction of the burst was spent"
        );
        assert!(!b.try_spend(now), "an empty budget refuses");
    }

    /// The transaction after the burst is refused at the same instant.
    #[test]
    fn the_burst_plus_one_is_refused() {
        let now = Instant::now();
        let mut b = default_at(now);
        for i in 0..DEFAULT_BUDGET {
            assert!(b.try_spend(now), "transaction {i} of the burst");
        }
        assert!(!b.try_spend(now), "transaction 67 is refused");
    }

    /// Short of one token's time after it emptied, it is still empty.
    #[test]
    fn just_short_of_a_token_it_is_still_empty() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        let t = later(start, one_token() - Duration::from_nanos(1))?;
        assert_eq!(
            b.available(t),
            0,
            "a nanosecond short of a token adds nothing"
        );
        assert!(!b.try_spend(t), "so the spend is refused");
        Ok(())
    }

    /// A budget of no transactions grants none, however long it waits.
    #[test]
    fn a_budget_of_nothing_never_grants() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = TransactionBudget::new(0, Some(DEFAULT_REFILL), start);
        assert!(
            !b.try_spend(start),
            "a budget of nothing grants nothing at once"
        );
        assert!(
            !b.try_spend(later(start, Duration::from_secs(86_400))?),
            "or a day later"
        );
        Ok(())
    }

    /// A refused spend takes nothing: refusing does not push the refill back.
    #[test]
    fn a_refused_spend_does_not_delay_the_refill() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        for s in 1..100 {
            assert!(
                !b.try_spend(later(start, Duration::from_secs(s))?),
                "a refused spend before the refill is still refused"
            );
        }
        assert!(b.try_spend(later(start, one_token())?), "refilled on time");
        Ok(())
    }

    // ── EDGE ───────────────────────────────────────────────────────────

    /// The part of a token earned beyond a whole one is carried: at one and
    /// a half tokens' time one is spent, and at two tokens' time the second
    /// is there, not half a token later.
    #[test]
    fn a_part_token_already_earned_is_carried() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        let one_and_a_half = later(start, one_token() * 3 / 2)?;
        assert!(b.try_spend(one_and_a_half), "one token earned");
        assert!(!b.try_spend(one_and_a_half), "and only one");
        assert!(
            b.try_spend(later(start, one_token() * 2)?),
            "the half was kept"
        );
        Ok(())
    }

    /// A long idle fills it to the burst and no further.
    #[test]
    fn a_long_idle_fills_to_the_burst_and_no_further() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        let week = later(start, Duration::from_secs(7 * 86_400))?;
        assert_eq!(b.available(week), DEFAULT_BUDGET, "at the cap");
        assert_eq!(drain(&mut b, week), DEFAULT_BUDGET, "never above the burst");
        Ok(())
    }

    /// A full budget banks nothing: an hour full, then a burst, then nothing
    /// until the refill.
    #[test]
    fn a_full_budget_banks_no_credit() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let t = later(start, Duration::from_secs(3600))?;
        assert_eq!(
            drain(&mut b, t),
            DEFAULT_BUDGET,
            "the full hour banked nothing beyond the burst"
        );
        assert_eq!(b.available(t), 0, "the full hour earned nothing extra");
        assert_eq!(b.next_in(t), Some(one_token()), "refill counts from t");
        Ok(())
    }

    /// A reading earlier than the last one adds nothing and does not move the
    /// refill point back.
    #[test]
    fn a_reading_earlier_than_the_last_adds_nothing() -> Result<(), TestError> {
        let start = Instant::now();
        let t = later(start, Duration::from_secs(1000))?;
        let mut b = default_at(t);
        let _ = drain(&mut b, t);
        assert!(!b.try_spend(start), "an earlier reading earns nothing");
        assert_eq!(
            b.available(start),
            0,
            "an earlier reading reports nothing added"
        );
        assert!(
            !b.try_spend(later(t, one_token() - Duration::from_secs(1))?),
            "the refill is still counted from the later reading"
        );
        assert!(
            b.try_spend(later(t, one_token())?),
            "the refill counted from the later reading arrives on time"
        );
        Ok(())
    }

    /// A jump of a century fills it to the burst without overflowing.
    #[test]
    fn a_century_jump_fills_to_the_burst_without_overflow() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = default_at(start);
        let _ = drain(&mut b, start);
        let Some(century) = start.checked_add(Duration::from_secs(100 * 365 * 86_400)) else {
            // The platform cannot represent it; nothing to test.
            return Ok(());
        };
        assert_eq!(
            b.available(century),
            DEFAULT_BUDGET,
            "a century fills to the burst"
        );
        assert_eq!(b.next_in(century), None, "full");
        Ok(())
    }

    /// No refill never refills: the ceiling for the run, as before.
    #[test]
    fn no_refill_is_a_ceiling_for_the_run() -> Result<(), TestError> {
        let start = Instant::now();
        let mut b = TransactionBudget::new(DEFAULT_BUDGET, None, start);
        let _ = drain(&mut b, start);
        let day = later(start, Duration::from_secs(86_400))?;
        assert_eq!(b.available(day), 0, "no refill leaves it empty a day later");
        assert_eq!(b.next_in(day), None, "and has nothing to wait for");
        Ok(())
    }

    /// A refill of no tokens or over no time is read as no refill.
    #[test]
    fn a_refill_of_nothing_or_over_no_time_is_no_refill() {
        let now = Instant::now();
        for refill in [
            Refill {
                tokens: 0,
                per: Duration::from_secs(3600),
            },
            Refill {
                tokens: 33,
                per: Duration::ZERO,
            },
        ] {
            let mut b = TransactionBudget::new(2, Some(refill), now);
            assert_eq!(b.refill(), None, "{refill:?}");
            let _ = drain(&mut b, now);
            assert_eq!(b.available(now), 0, "{refill:?} adds nothing");
        }
    }

    /// A full budget has no next transaction to wait for.
    #[test]
    fn a_full_budget_has_nothing_to_wait_for() {
        let now = Instant::now();
        assert_eq!(
            default_at(now).next_in(now),
            None,
            "a full budget has no next transaction"
        );
    }
}
