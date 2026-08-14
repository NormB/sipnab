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

/// Shipped upper bound on the number of distinct peers tracked within one
/// window.
///
/// Bounds memory against a source-address flood: without it, one packet or one
/// call from each of a million forged sources would size the tracking map. When
/// the bound is reached, a peer that is not already tracked is refused rather
/// than admitted — see [`FixedWindowLimiter::check`] for why that direction is
/// the safe one.
///
/// How many peers a deployment actually has is not something sipnab can know,
/// so this is the shipped starting point and not a law: raise it with
/// `[limits] max_tracked_peers` on a collector that aggregates from more
/// agents than this.
///
/// The number itself lives on [`crate::cli::Cli::DEFAULT_MAX_TRACKED_PEERS`],
/// beside the other defaults: this module is compiled only for a `hep` or
/// `mcp` build, while the resolver and the config floor must answer in every
/// feature combination.
pub const DEFAULT_MAX_TRACKED_PEERS: usize = crate::cli::Cli::DEFAULT_MAX_TRACKED_PEERS;

/// Smallest tracking map an operator may configure.
///
/// Not a memory figure — it is the point at which the mechanism inverts. With
/// room for one peer, the first sender in a window takes the only slot and
/// every other peer is refused for the rest of that window, whatever its rate:
/// a per-peer cap that exists to stop one sender starving the others becomes
/// the thing that starves them. Two is the smallest map that still admits a
/// second peer, so it is the smallest map the setting means anything on.
///
/// Read from [`crate::config::MIN_TRACKED_PEERS`] for the reason
/// [`DEFAULT_MAX_TRACKED_PEERS`] records: `crate::config` refuses a value
/// below the floor in every build, and this module is not compiled in all of
/// them.
pub const MIN_TRACKED_PEERS: usize = crate::config::MIN_TRACKED_PEERS as usize;

/// Length of one counting window. Both caps are expressed per second, which is
/// the unit every operator-facing knob that feeds this type uses
/// (`--hep-rate-limit`, `--hep-rate-limit-per-peer`,
/// `--mcp-rate-limit-per-peer`).
///
/// That sentence is why this stays one second. The caps carry a count and this
/// constant supplies the "per what", so changing it redefines every one of
/// those flags at once and in silence: `--hep-rate-limit 100` keeps its name,
/// its value and its help text while meaning a fifth of the rate it meant
/// before. Raising it lets a burst five times the documented size through
/// before anything refuses; lowering it starves a deployment that sized its
/// number against the old meaning. Neither shows up as a flag that changed,
/// because no flag did.
///
/// An operator who wants a different rate changes the cap. A surface that
/// genuinely needs a different window wants its own limiter, with the window
/// named in its own knob, so the flag and the behaviour still agree.
///
/// Public so the `[limits]` wiring probes in `tests/config_wiring_test.rs` can
/// assert their own premise against it — those probes send a burst and read the
/// refusals, which only means anything if the burst lands inside ONE window.
/// They must derive that bound from here rather than restate it: a second copy
/// would agree today and drift the moment this changes.
pub const WINDOW: Duration = Duration::from_secs(1);

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
    /// Per-peer counts for the current window, bounded by the
    /// `max_tracked_peers` field below and cleared when the window resets.
    per_peer: HashMap<K, u64>,
    /// How many distinct peers `per_peer` may hold at once.
    max_tracked_peers: usize,
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
    /// * `max_tracked_peers` — distinct peers the window may hold at once,
    ///   clamped up to [`MIN_TRACKED_PEERS`]. Passed rather than defaulted so
    ///   a call site cannot acquire the shipped figure by omission: it is a
    ///   deployment property, and the surface that meters HEP agents and the
    ///   one that meters MCP callers both read it from the operator.
    ///
    /// # Returns
    ///
    /// A limiter that has refused nothing yet.
    pub fn new(global_max: u64, per_peer_max: u64, max_tracked_peers: usize) -> Self {
        Self {
            global_max,
            per_peer_max,
            count_this_window: 0,
            per_peer: HashMap::new(),
            max_tracked_peers: max_tracked_peers.max(MIN_TRACKED_PEERS),
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
            // `max_tracked_peers`. When it is full, a *new* peer cannot be
            // accounted for — and letting it through is exactly the
            // many-source flood the per-peer cap exists to resist. Fail
            // closed: refuse the untracked newcomer rather than grant it free
            // budget. Already-tracked peers keep being counted normally.
            if self.per_peer.len() >= self.max_tracked_peers && !self.per_peer.contains_key(&key) {
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

    /// The tracking-map bound this limiter is enforcing, after the floor was
    /// applied. The caller's warning quotes it, so an operator who raised
    /// `[limits] max_tracked_peers` and is still being refused reads the
    /// number in force rather than the shipped one.
    pub fn max_tracked_peers(&self) -> usize {
        self.max_tracked_peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer over its per-peer cap is refused, and the refusal names the cap
    /// that stopped it.
    #[test]
    fn the_per_peer_cap_refuses_the_event_that_exceeds_it() {
        let mut lim = FixedWindowLimiter::new(0, 2, DEFAULT_MAX_TRACKED_PEERS);
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
        let mut lim = FixedWindowLimiter::new(1000, 1, DEFAULT_MAX_TRACKED_PEERS);
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
        let mut lim = FixedWindowLimiter::new(0, 1, DEFAULT_MAX_TRACKED_PEERS);
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
        let mut lim = FixedWindowLimiter::new(2, 100, DEFAULT_MAX_TRACKED_PEERS);
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
        let mut lim = FixedWindowLimiter::new(0, 0, DEFAULT_MAX_TRACKED_PEERS);
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
        let mut lim = FixedWindowLimiter::new(u64::MAX, 1, DEFAULT_MAX_TRACKED_PEERS);
        let now = Instant::now();
        for i in 0..DEFAULT_MAX_TRACKED_PEERS {
            assert_eq!(
                lim.check(i, now),
                Ok(()),
                "first event from fresh peer {i} is allowed"
            );
        }
        assert_eq!(
            lim.check(DEFAULT_MAX_TRACKED_PEERS, now),
            Err(Refusal::TrackingFull),
            "a new peer past the tracking bound must be refused, not waved through"
        );
    }

    /// The tracking bound is the one the CALLER passed, not the shipped
    /// figure: a limiter built with room for three peers refuses the fourth
    /// while the default would have admitted it.
    #[test]
    fn the_configured_capacity_is_what_bounds_the_map() {
        let mut lim = FixedWindowLimiter::new(u64::MAX, 1, 3);
        let now = Instant::now();
        for i in 0..3 {
            assert_eq!(lim.check(i, now), Ok(()), "peer {i} fits in a map of 3");
        }
        assert_eq!(
            lim.check(3, now),
            Err(Refusal::TrackingFull),
            "the fourth peer must be refused by a map of 3, which the shipped \
             default would have admitted"
        );
        assert_eq!(
            lim.max_tracked_peers(),
            3,
            "the caller's figure is reported"
        );
    }

    /// A map of one is clamped up to the floor rather than accepted, so the
    /// per-peer cap cannot be turned into a global lock by a small number.
    #[test]
    fn a_map_of_one_is_clamped_up_to_the_floor() {
        let mut lim = FixedWindowLimiter::new(u64::MAX, 1, 1);
        let now = Instant::now();
        assert_eq!(lim.max_tracked_peers(), MIN_TRACKED_PEERS);
        assert_eq!(lim.check("first", now), Ok(()));
        assert_eq!(
            lim.check("second", now),
            Ok(()),
            "at the floor a second peer still gets its own allowance; at 1 the \
             first sender would have taken the whole window"
        );
    }

    /// Every refusal is counted, and an admitted event is not.
    #[test]
    fn refusals_are_counted_and_admissions_are_not() {
        let mut lim = FixedWindowLimiter::new(0, 1, DEFAULT_MAX_TRACKED_PEERS);
        let now = Instant::now();
        assert_eq!(lim.check("a", now), Ok(()));
        assert_eq!(lim.refused_total(), 0, "an admitted event is not a refusal");
        assert!(lim.check("a", now).is_err());
        assert!(lim.check("a", now).is_err());
        assert_eq!(lim.refused_total(), 2, "both refusals counted");
    }
}
