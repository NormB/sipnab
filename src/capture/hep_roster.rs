// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a HEP listener knows about the packets it turned away, and about the
//! senders that went quiet.
//!
//! # Why this is its own module
//!
//! `capture::hep` is compiled only with the `hep` feature, and the listener is
//! the only thing that WRITES this state. The things that READ it are not all
//! behind that feature: the TUI, the MCP server and the REST server each ask
//! "who is feeding this collector" from their own module, and a type they can
//! only name under `hep` would put a feature gate on every one of their fields.
//! So the state and its vocabulary live here, under `native`, and the listener
//! maps its own reasons onto them.
//!
//! # The refusal vocabulary is one list
//!
//! [`HepRefusal`] is every reason a received HEP packet can be turned away.
//! The listener's log line, the silence warning and every count keyed by
//! reason read it from here, so a reason cannot be counted under one name and
//! logged under another. The rate limiter's and the HMAC verifier's own enums
//! map onto it in `capture::hep`, where both of those types live, and a test
//! there holds the mapping to cover every one of their variants.

use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long a HEP listener may go without ADMITTING a packet before it warns
/// the operator, unless `--hep-silence-warn` says otherwise.
///
/// UDP is connectionless: a dead upstream sender produces no error, just
/// silence, so without this a stalled feed is indistinguishable from a quiet
/// one.
pub const HEP_IDLE_WARN_AFTER: Duration = Duration::from_secs(30);

/// Why a received HEP packet was turned away.
///
/// One variant per distinct thing an operator would fix, in the order the
/// listener asks its questions: who sent it, how fast, whether it parses, and
/// whether it proves it came from a trusted producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HepRefusal {
    /// The outer source address is not on `--hep-allow`.
    Allowlist,
    /// Every peer together used the global `--hep-rate-limit` ceiling.
    RateLimitGlobal,
    /// This peer used its whole `--hep-rate-limit-per-peer` allowance.
    RateLimitPerPeer,
    /// The per-peer tracking table was full and this peer was not in it.
    PeerTrackingFull,
    /// The bytes are not a HEP packet this listener can parse.
    Malformed,
    /// The listener requires a key and the packet carried no auth chunk.
    AuthMissing,
    /// `plain` mode: the auth chunk did not equal the shared secret.
    AuthMismatch,
    /// `hmac` mode: the token has the wrong length or names no scheme.
    HmacBadFormat,
    /// `hmac` mode: a superseded version-1 token, refused by design.
    HmacUnsupportedVersion,
    /// `hmac` mode: the token's timestamp is outside the acceptance window.
    HmacTimestampOutOfWindow,
    /// `hmac` mode: the MAC did not verify (wrong key, or a tampered packet).
    HmacBadMac,
    /// `hmac` mode: a token with this nonce was already accepted.
    HmacReplay,
}

impl HepRefusal {
    /// Every reason, in declaration order. [`Self::index`] is each one's
    /// position here, and a test holds the two together.
    pub const ALL: [Self; 12] = [
        Self::Allowlist,
        Self::RateLimitGlobal,
        Self::RateLimitPerPeer,
        Self::PeerTrackingFull,
        Self::Malformed,
        Self::AuthMissing,
        Self::AuthMismatch,
        Self::HmacBadFormat,
        Self::HmacUnsupportedVersion,
        Self::HmacTimestampOutOfWindow,
        Self::HmacBadMac,
        Self::HmacReplay,
    ];

    /// How many reasons there are, for arrays indexed by [`Self::index`].
    pub const COUNT: usize = Self::ALL.len();

    /// This reason's slot in [`Self::ALL`] and in every per-reason array.
    ///
    /// An exhaustive match rather than a cast, so a new variant fails to
    /// compile here until it is given a slot.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Allowlist => 0,
            Self::RateLimitGlobal => 1,
            Self::RateLimitPerPeer => 2,
            Self::PeerTrackingFull => 3,
            Self::Malformed => 4,
            Self::AuthMissing => 5,
            Self::AuthMismatch => 6,
            Self::HmacBadFormat => 7,
            Self::HmacUnsupportedVersion => 8,
            Self::HmacTimestampOutOfWindow => 9,
            Self::HmacBadMac => 10,
            Self::HmacReplay => 11,
        }
    }

    /// The machine name: what a log line, a JSON key and a Prometheus label
    /// all say.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowlist => "allowlist",
            Self::RateLimitGlobal => "rate_limit_global",
            Self::RateLimitPerPeer => "rate_limit_per_peer",
            Self::PeerTrackingFull => "peer_tracking_full",
            Self::Malformed => "malformed",
            Self::AuthMissing => "auth_missing",
            Self::AuthMismatch => "auth_mismatch",
            Self::HmacBadFormat => "hmac_bad_format",
            Self::HmacUnsupportedVersion => "hmac_unsupported_version",
            Self::HmacTimestampOutOfWindow => "hmac_timestamp_out_of_window",
            Self::HmacBadMac => "hmac_bad_mac",
            Self::HmacReplay => "hmac_replay",
        }
    }

    /// What the reason means, and where an operator would look, in words.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Allowlist => "the source address is not on --hep-allow",
            Self::RateLimitGlobal => "over the global --hep-rate-limit ceiling",
            Self::RateLimitPerPeer => "over the per-peer rate limit",
            Self::PeerTrackingFull => {
                "the peer tracking table is full ([limits] max_tracked_peers)"
            }
            Self::Malformed => "not a HEP packet this listener can parse",
            Self::AuthMissing => "no auth key, and this listener requires one",
            Self::AuthMismatch => "the auth key does not match this listener's secret",
            Self::HmacBadFormat => "a malformed HMAC token",
            Self::HmacUnsupportedVersion => "a version-1 HMAC token; upgrade the sending sipnab",
            Self::HmacTimestampOutOfWindow => {
                "the HMAC timestamp is outside the acceptance window; check the \
                 sender's clock"
            }
            Self::HmacBadMac => "the HMAC does not verify (wrong key, or a tampered packet)",
            Self::HmacReplay => "a replayed HMAC token",
        }
    }
}

/// Detects silent stalls in a packet feed.
///
/// Pure state machine over caller-supplied [`Instant`]s so it is testable
/// without sleeping: [`IdleWatch::check`] returns `Some(idle)` exactly once
/// per idle period when the threshold is crossed, and
/// [`IdleWatch::on_packet`] returns `Some(outage)` on the first packet
/// after a warned period. A zero threshold disables the watch.
pub struct IdleWatch {
    /// Idle duration that triggers a warning (zero disables the watch).
    threshold: Duration,
    /// When the last packet was observed (or when the watch was created).
    last_packet: Instant,
    /// Whether the current idle period has already been warned about.
    warned: bool,
}

impl IdleWatch {
    /// Create a watch; `now` starts the first idle period.
    pub fn new(threshold: Duration, now: Instant) -> Self {
        Self {
            threshold,
            last_packet: now,
            warned: false,
        }
    }

    /// Record traffic at time `now`. Returns `Some(outage_duration)` if this
    /// packet ends a previously-warned idle period (i.e., the feed
    /// recovered), else `None`. Mutates the watch: resets the idle clock and
    /// clears the warned flag.
    pub fn on_packet(&mut self, now: Instant) -> Option<Duration> {
        let idle = now.duration_since(self.last_packet);
        self.last_packet = now;
        if std::mem::take(&mut self.warned) {
            Some(idle)
        } else {
            None
        }
    }

    /// Poll the watch at time `now`. Returns `Some(idle_duration)` the first
    /// time the idle threshold is crossed; `None` on subsequent polls until
    /// traffic resumes (no log spam). Mutates the watch: sets the warned
    /// flag when the threshold is crossed.
    pub fn check(&mut self, now: Instant) -> Option<Duration> {
        if self.threshold.is_zero() || self.warned {
            return None;
        }
        let idle = now.duration_since(self.last_packet);
        if idle >= self.threshold {
            self.warned = true;
            Some(idle)
        } else {
            None
        }
    }
}

/// The listener-wide half of silence: nothing ADMITTED for the threshold.
///
/// # Why it is fed admitted packets only
///
/// It used to be reset by every datagram that arrived, before the allowlist,
/// the rate limiter, the parser or authentication had looked at it. A sender
/// whose every packet failed authentication therefore kept the "no packets"
/// warning quiet for as long as it kept sending, and the operator it existed
/// for saw a collector that said nothing and received nothing. The watch now
/// hears only what was admitted, and the refusals are counted beside it so
/// the warning can say WHY nothing got through.
pub struct ListenerSilence {
    /// Measures the gap since the last admitted packet.
    watch: IdleWatch,
    /// Refusals since the last admitted packet, indexed by
    /// [`HepRefusal::index`]. Fixed size: bounded whatever arrives.
    refused: [u64; HepRefusal::COUNT],
    /// The peer most recently refused for each reason, same indexing.
    last_peer: [Option<IpAddr>; HepRefusal::COUNT],
}

impl ListenerSilence {
    /// A listener that has admitted nothing yet; `now` starts the clock.
    ///
    /// # Arguments
    ///
    /// * `threshold` — how long without an admitted packet before warning;
    ///   zero disables the warning.
    /// * `now` — when the listener started.
    #[must_use]
    pub fn new(threshold: Duration, now: Instant) -> Self {
        Self {
            watch: IdleWatch::new(threshold, now),
            refused: [0; HepRefusal::COUNT],
            last_peer: [None; HepRefusal::COUNT],
        }
    }

    /// A packet was admitted at `now`.
    ///
    /// # Returns
    ///
    /// How long the listener had gone without one, when this ends a period it
    /// already warned about.
    ///
    /// # Side effects
    ///
    /// Restarts the watch and forgets the refusals counted since the last
    /// admission: they described an outage that is now over.
    pub fn on_admitted(&mut self, now: Instant) -> Option<Duration> {
        self.refused = [0; HepRefusal::COUNT];
        self.last_peer = [None; HepRefusal::COUNT];
        self.watch.on_packet(now)
    }

    /// A packet from `peer` was turned away for `reason`.
    ///
    /// Counted, and deliberately NOT treated as traffic: the watch keeps
    /// running, which is the whole point.
    pub fn on_refused(&mut self, reason: HepRefusal, peer: IpAddr) {
        let slot = reason.index();
        self.refused[slot] = self.refused[slot].saturating_add(1);
        self.last_peer[slot] = Some(peer);
    }

    /// Poll at `now`.
    ///
    /// # Returns
    ///
    /// A warning the first time the threshold is crossed in one quiet period,
    /// then `None` until a packet is admitted again.
    pub fn check(&mut self, now: Instant) -> Option<SilenceWarning> {
        let idle = self.watch.check(now)?;
        let refused = self.refused.iter().copied().fold(0u64, u64::saturating_add);
        // The reason with the most refusals, ties to the earlier reason in the
        // listener's own order, paired with the peer last refused for it.
        let dominant = HepRefusal::ALL
            .iter()
            .copied()
            .filter(|r| self.refused[r.index()] > 0)
            .max_by(|a, b| {
                self.refused[a.index()]
                    .cmp(&self.refused[b.index()])
                    .then_with(|| b.index().cmp(&a.index()))
            })
            .and_then(|r| self.last_peer[r.index()].map(|peer| (r, peer)));
        Some(SilenceWarning {
            idle,
            refused,
            dominant,
        })
    }
}

/// What the listener-wide silence warning reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilenceWarning {
    /// How long since the last admitted packet (or since the listener
    /// started, when none has been).
    pub idle: Duration,
    /// Packets that arrived in that time and were turned away.
    pub refused: u64,
    /// The reason most of them were refused for, and the peer last refused
    /// for it. `None` when nothing arrived at all.
    pub dominant: Option<(HepRefusal, IpAddr)>,
}

impl SilenceWarning {
    /// The line the listener logs.
    ///
    /// Two different situations with two different fixes, so two different
    /// sentences. Nothing arriving is a routing or sender problem; packets
    /// arriving and every one refused means the sender IS reaching the port
    /// and the listener is turning it away, which is a key, mode or allowlist
    /// problem. Both keep the "no packets" wording an operator greps for.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` — the listener's address, as the operator gave it.
    /// * `datagram` — whether the listener is UDP, where a dead peer produces
    ///   no error at all and the line says so.
    #[must_use]
    pub fn render(&self, bind_addr: &str, datagram: bool) -> String {
        let secs = self.idle.as_secs();
        match self.dominant {
            Some((reason, peer)) => format!(
                "HEP listener on {bind_addr}: no packets admitted for {secs}s — {refused} \
                 arrived and every one was refused, mostly {name} ({why}), the last of \
                 those from {peer}; the sender is reaching this port and being turned \
                 away; capture is still listening",
                refused = self.refused,
                name = reason.as_str(),
                why = reason.describe(),
            ),
            None if datagram => format!(
                "HEP listener on {bind_addr}: no packets for {secs}s — upstream sender \
                 may be down (UDP gives no error for a dead peer); capture is still \
                 listening"
            ),
            None => format!(
                "HEP listener on {bind_addr}: no packets for {secs}s — upstream sender \
                 may be down; capture is still listening"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reason sits at its own index, so a per-reason array never
    /// counts two reasons in one slot.
    #[test]
    fn every_reason_sits_at_its_own_index() {
        for (i, r) in HepRefusal::ALL.iter().enumerate() {
            assert_eq!(
                r.index(),
                i,
                "{r:?} is listed at {i} but indexes {}",
                r.index()
            );
        }
    }

    /// No two reasons share a machine name: a JSON key or a Prometheus label
    /// that two reasons wrote would sum things an operator fixes differently.
    #[test]
    fn no_two_reasons_share_a_name() {
        let names: std::collections::BTreeSet<&str> =
            HepRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            names.len(),
            HepRefusal::COUNT,
            "duplicate reason names: {names:?}"
        );
    }

    // ── IdleWatch: silent-stall detection ────────────────────────────

    /// Helper: a fresh `Instant` origin for the idle-watch tests (offsets
    /// are added to it, so no sleeping is needed).
    fn t0() -> Instant {
        Instant::now()
    }

    /// Below the threshold, `check` stays quiet.
    #[test]
    fn idle_watch_quiet_below_threshold() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert_eq!(w.check(start + Duration::from_secs(29)), None);
    }

    /// Crossing the threshold warns exactly once — repeated polls during
    /// the same idle period stay silent.
    #[test]
    fn idle_watch_warns_once_when_threshold_crossed() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        let idle = w.check(start + Duration::from_secs(31));
        assert_eq!(idle, Some(Duration::from_secs(31)));
        // Repeated checks while still idle must NOT warn again (no log spam).
        assert_eq!(w.check(start + Duration::from_secs(60)), None);
        assert_eq!(w.check(start + Duration::from_secs(600)), None);
    }

    /// The first packet after a warned idle period reports the full outage
    /// duration; steady traffic afterwards is silent.
    #[test]
    fn idle_watch_reports_recovery_with_total_idle_time() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert!(w.check(start + Duration::from_secs(40)).is_some());
        // First packet after a warned idle period reports the outage length.
        let recovered = w.on_packet(start + Duration::from_secs(100));
        assert_eq!(recovered, Some(Duration::from_secs(100)));
        // Steady traffic afterwards is silent.
        assert_eq!(w.on_packet(start + Duration::from_secs(101)), None);
    }

    /// Each packet restarts the idle clock; the threshold is measured from
    /// the last packet, not from creation.
    #[test]
    fn idle_watch_packet_resets_idle_clock() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert_eq!(w.on_packet(start + Duration::from_secs(20)), None);
        // 29s after the last packet (49s after start): still quiet.
        assert_eq!(w.check(start + Duration::from_secs(49)), None);
        // 31s after the last packet: warn.
        assert!(w.check(start + Duration::from_secs(51)).is_some());
    }

    /// After a recovery, a second outage produces a second warning.
    #[test]
    fn idle_watch_can_warn_again_after_recovery() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert!(w.check(start + Duration::from_secs(31)).is_some());
        assert!(w.on_packet(start + Duration::from_secs(40)).is_some());
        // A second outage warns again.
        assert!(w.check(start + Duration::from_secs(80)).is_some());
    }

    /// A zero threshold disables the watch entirely: no warnings, no
    /// recovery reports.
    #[test]
    fn idle_watch_zero_threshold_is_disabled() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::ZERO, start);
        assert_eq!(w.check(start + Duration::from_secs(3600)), None);
        assert_eq!(w.on_packet(start + Duration::from_secs(7200)), None);
    }
}
