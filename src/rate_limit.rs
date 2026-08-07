// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-window rate limiting: a global ceiling plus a per-peer cap.
//!
//! # Why one implementation
//!
//! Two surfaces need the same answer to the same question — "has this peer
//! already had its allowance for this window, and has everybody together had
//! theirs?" The HEP receiver asks it about packets from a source IP; the MCP
//! server asks it about tool calls from a caller. Written twice, the two
//! copies drift: one grows the memory bound the other lacks, one fixes an
//! off-by-one at the boundary and the other keeps it, and the deployment that
//! reads the same knob on two surfaces gets two behaviours. This tree has
//! already paid for one concept with two implementations more than once, so
//! the counting lives here and the callers keep only what is genuinely theirs
//! — the wording of their own log lines and the shape of their own refusal.
//!
//! # What this is, precisely
//!
//! A **fixed** window, not a sliding one and not a token bucket: the counters
//! reset once a whole window has elapsed since they last did. The consequence
//! is worth stating rather than discovering — a peer may spend its entire
//! allowance at the end of one window and its entire next allowance at the
//! start of the next, so a short burst can reach twice the nominal rate across
//! a boundary. That is accepted here. What this exists to stop is the caller
//! that loops indefinitely, and against that the fixed window is exact: the
//! sustained rate cannot exceed the cap. A sliding window would buy the
//! boundary smoothness at the cost of per-key timestamp history, which is the
//! unbounded memory the peer bound below exists to avoid.
//!
//! # The clock belongs to the caller
//!
//! Every decision takes `now` rather than reading the clock itself. That keeps
//! the type pure, and it is what lets a test step across a window boundary
//! without sleeping — a limiter whose tests sleep a second each is a limiter
//! whose tests get skipped.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Upper bound on the number of distinct peers tracked within one window.
///
/// Bounds memory against a source-address flood: without it, one packet or one
/// call from each of a million forged sources would size the tracking map. When
/// the bound is reached, a peer that is not already tracked is refused rather
/// than admitted — see [`FixedWindowLimiter::check`] for why that direction is
/// the safe one.
pub const MAX_TRACKED_PEERS: usize = 4096;

/// Length of one counting window. Both caps are expressed per second, which is
/// the unit every operator-facing knob that feeds this type uses
/// (`--hep-rate-limit`, `--hep-rate-limit-per-peer`,
/// `--mcp-rate-limit-per-peer`).
const WINDOW: Duration = Duration::from_secs(1);

/// Why a limiter refused, so the caller can say so in its own words.
///
/// The caller owns the message: HEP drops a packet and logs at debug, MCP
/// returns a JSON-RPC error to the agent that made the call. Returning the
/// reason rather than a bare `false` is what lets both do that without this
/// module knowing anything about either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This peer has used its whole per-peer allowance for the window.
    PerPeer,
    /// Every peer together has used the global ceiling for the window.
    Global,
    /// The per-peer tracking map is full and this peer is not in it.
    TrackingFull,
}

/// Fixed-window counter with a global ceiling and a per-peer cap.
///
/// The global ceiling bounds total load; the per-peer cap adds fairness, so a
/// single reachable sender cannot consume the whole allowance and starve
/// everyone else. Either may be `0`, which **disables** that half — `0` never
/// means "refuse everything", on any knob that feeds this type.
#[derive(Debug)]
pub struct FixedWindowLimiter<K> {
    /// Maximum events per window across all peers (`0` = disabled).
    global_max: u64,
    /// Maximum events per window from any single peer (`0` = disabled).
    per_peer_max: u64,
    /// Events counted against the global ceiling in the current window.
    count_this_window: u64,
    /// Per-peer counts for the current window, bounded by [`MAX_TRACKED_PEERS`]
    /// and cleared when the window resets.
    per_peer: HashMap<K, u64>,
    /// Start of the current window.
    window_start: Instant,
    /// Lifetime count of events either cap refused, for log lines and audit.
    refused_total: u64,
}

impl<K: Eq + Hash> FixedWindowLimiter<K> {
    /// Build a limiter whose first window starts now.
    ///
    /// # Arguments
    ///
    /// * `global_max` — events per second across all peers; `0` disables the
    ///   global ceiling.
    /// * `per_peer_max` — events per second from one peer; `0` disables the
    ///   per-peer cap.
    ///
    /// # Returns
    ///
    /// A limiter that has refused nothing yet.
    pub fn new(global_max: u64, per_peer_max: u64) -> Self {
        Self {
            global_max,
            per_peer_max,
            count_this_window: 0,
            per_peer: HashMap::new(),
            window_start: Instant::now(),
            refused_total: 0,
        }
    }

    /// Count one event from `key` and decide whether it may proceed.
    ///
    /// The per-peer cap is consulted FIRST, so a noisy peer's refusals do not
    /// eat the global budget that the quiet peers are counted against.
    ///
    /// # Arguments
    ///
    /// * `key` — the peer this event came from.
    /// * `now` — the caller's monotonic clock reading for this event.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the event may proceed.
    ///
    /// # Errors
    ///
    /// [`Refusal::PerPeer`], [`Refusal::Global`] or [`Refusal::TrackingFull`],
    /// naming which bound stopped it. Every refusal increments
    /// [`Self::refused_total`].
    pub fn check(&mut self, key: K, now: Instant) -> Result<(), Refusal> {
        if now.duration_since(self.window_start) >= WINDOW {
            self.window_start = now;
            self.count_this_window = 0;
            self.per_peer.clear();
        }

        if self.per_peer_max > 0 {
            // Memory bound: the tracking map may not grow past
            // MAX_TRACKED_PEERS. When it is full, a *new* peer cannot be
            // accounted for — and letting it through is exactly the
            // many-source flood the per-peer cap exists to resist. Fail
            // closed: refuse the untracked newcomer rather than grant it free
            // budget. Already-tracked peers keep being counted normally.
            if self.per_peer.len() >= MAX_TRACKED_PEERS && !self.per_peer.contains_key(&key) {
                self.refused_total += 1;
                return Err(Refusal::TrackingFull);
            }
            let peer_count = self.per_peer.entry(key).or_insert(0);
            *peer_count += 1;
            if *peer_count > self.per_peer_max {
                self.refused_total += 1;
                return Err(Refusal::PerPeer);
            }
        }

        self.count_this_window += 1;
        // A ceiling of 0 means DISABLED (consistent with the per-peer knob),
        // not "refuse everything".
        if self.global_max > 0 && self.count_this_window > self.global_max {
            self.refused_total += 1;
            return Err(Refusal::Global);
        }
        Ok(())
    }

    /// Events either cap has refused over this limiter's lifetime.
    ///
    /// A running total rather than a per-window one on purpose: the number an
    /// operator acts on is "how much has been turned away", and a counter that
    /// resets every second answers that for nobody.
    pub fn refused_total(&self) -> u64 {
        self.refused_total
    }

    /// The configured per-peer cap, for the caller's own message.
    pub fn per_peer_max(&self) -> u64 {
        self.per_peer_max
    }

    /// The configured global ceiling, for the caller's own message.
    pub fn global_max(&self) -> u64 {
        self.global_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer over its per-peer cap is refused, and the refusal names the cap
    /// that stopped it.
    #[test]
    fn the_per_peer_cap_refuses_the_event_that_exceeds_it() {
        let mut lim = FixedWindowLimiter::new(0, 2);
        let now = Instant::now();
        assert_eq!(lim.check("a", now), Ok(()));
        assert_eq!(lim.check("a", now), Ok(()));
        assert_eq!(
            lim.check("a", now),
            Err(Refusal::PerPeer),
            "the third event in a 2/s window must be refused"
        );
    }

    /// A flooding peer is throttled without spending a quiet peer's allowance.
    #[test]
    fn one_noisy_peer_does_not_spend_another_peers_allowance() {
        let mut lim = FixedWindowLimiter::new(1000, 1);
        let now = Instant::now();
        assert_eq!(lim.check("noisy", now), Ok(()));
        assert_eq!(lim.check("noisy", now), Err(Refusal::PerPeer));
        assert_eq!(
            lim.check("quiet", now),
            Ok(()),
            "a quiet peer keeps its own allowance"
        );
    }

    /// The window resets, and only after a whole window has elapsed.
    #[test]
    fn a_new_window_restores_the_allowance() {
        let mut lim = FixedWindowLimiter::new(0, 1);
        let now = Instant::now();
        assert_eq!(lim.check("a", now), Ok(()));
        assert_eq!(
            lim.check("a", now + Duration::from_millis(999)),
            Err(Refusal::PerPeer),
            "still inside the window, so still refused"
        );
        assert_eq!(
            lim.check("a", now + WINDOW),
            Ok(()),
            "a whole window later the allowance is back"
        );
    }

    /// The global ceiling bounds every peer together, whichever one arrives.
    #[test]
    fn the_global_ceiling_bounds_every_peer_together() {
        let mut lim = FixedWindowLimiter::new(2, 100);
        let now = Instant::now();
        assert_eq!(lim.check("a", now), Ok(()));
        assert_eq!(lim.check("b", now), Ok(()));
        assert_eq!(
            lim.check("a", now),
            Err(Refusal::Global),
            "the third event hits the global ceiling of 2 whoever sends it"
        );
    }

    /// Zero disables a cap rather than refusing everything — the property both
    /// CLI knobs document, pinned here where the behaviour actually lives.
    #[test]
    fn zero_disables_a_cap_rather_than_refusing_everything() {
        let mut lim = FixedWindowLimiter::new(0, 0);
        let now = Instant::now();
        for _ in 0..10_000 {
            assert_eq!(lim.check("a", now), Ok(()), "0 and 0 must limit nothing");
        }
        assert_eq!(lim.refused_total(), 0);
    }

    /// Once the tracking map is full, a brand-new peer is refused rather than
    /// bypassing the per-peer cap — a many-source flood must not get a free
    /// pass by exhausting the table it would otherwise be counted in.
    #[test]
    fn a_full_tracking_map_refuses_a_new_peer() {
        // Effectively unlimited ceiling so only the per-peer path can refuse.
        let mut lim = FixedWindowLimiter::new(u64::MAX, 1);
        let now = Instant::now();
        for i in 0..MAX_TRACKED_PEERS {
            assert_eq!(
                lim.check(i, now),
                Ok(()),
                "first event from fresh peer {i} is allowed"
            );
        }
        assert_eq!(
            lim.check(MAX_TRACKED_PEERS, now),
            Err(Refusal::TrackingFull),
            "a new peer past the tracking bound must be refused, not waved through"
        );
    }

    /// Every refusal is counted, and an admitted event is not.
    #[test]
    fn refusals_are_counted_and_admissions_are_not() {
        let mut lim = FixedWindowLimiter::new(0, 1);
        let now = Instant::now();
        assert_eq!(lim.check("a", now), Ok(()));
        assert_eq!(lim.refused_total(), 0, "an admitted event is not a refusal");
        assert!(lim.check("a", now).is_err());
        assert!(lim.check("a", now).is_err());
        assert_eq!(lim.refused_total(), 2, "both refusals counted");
    }
}
