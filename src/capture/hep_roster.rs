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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::capture::packet::{FrameCounter, FrameOrigin};
use crate::lru::LruMap;
use crate::output::model::{HepRefusedSourceRow, HepSenderRow, HepSendersReport};

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

/// Identify the SENDER of a HEP packet — the node whose traffic this is —
/// rather than the listener that received it.
///
/// The listener used to record its own bind address, so a collector fed by an
/// SBC and two PBXes labeled every dialog `hep:0.0.0.0:9060`. Every node
/// collapsed into one identity, and "which node did this leg come from" had no
/// answer even though the answer arrived in the packet: HEP chunk 0x000c
/// carries the sender's capture-agent id (`--hep-id`), and the datagram's peer
/// address says where it came from. Both were parsed and discarded.
///
/// The id alone is not enough — it defaults to 1, so an estate that never sets
/// it would collapse again — and the address alone is not enough either, since
/// two sipnab instances can share a host. Both, so neither collision hides a
/// node.
///
/// Lives here, beside the roster keyed on it, so the roster and every frame
/// pointer name a sender with one function.
#[must_use]
pub fn hep_source_label(capture_id: Option<u32>, peer: IpAddr) -> String {
    match capture_id {
        Some(id) => format!("{id}@{peer}"),
        None => peer.to_string(),
    }
}

/// Distinct addresses the refused-source table remembers.
///
/// A constant rather than a knob: the table answers "who am I turning away",
/// and a misconfigured estate turns away tens of senders, not hundreds. It is
/// keyed by an address a spoofing attacker chooses, so it evicts the address
/// refused least recently rather than refusing new ones: a flood rotates it,
/// and a real sender refused a moment ago is still in it.
pub const HEP_REFUSED_SOURCES_TRACKED: usize = 256;

/// Silent senders one sweep logs by name. The rest are counted in one line,
/// so a spoofed flood that filled the table and then stopped cannot turn the
/// silence warning into a journal flood of its own.
pub const HEP_SILENCE_LINES_PER_SWEEP: usize = 8;

/// How often the per-sender silence sweep may walk the table. The
/// listener-wide check is O(1) and runs on every pass; this one is O(senders).
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// What `identity` says on every row: the capture id is the sender's claim.
const IDENTITY_CLAIMED: &str = "claimed_by_sender";

/// The trust a HEP listener admits packets under, taken from its
/// configuration. One per listener: a shared secret, when there is one,
/// serves every sender alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderTrust {
    /// No secret configured: anything that passes the allowlist is admitted.
    Unauthenticated,
    /// `--hep-auth-mode plain`: packets carry the shared secret verbatim.
    SharedSecretPlain,
    /// `--hep-auth-mode hmac`: packets carry a per-message token over the
    /// whole datagram.
    SharedSecretHmac,
}

impl SenderTrust {
    /// The machine name every surface reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::SharedSecretPlain => "shared_secret_plain",
            Self::SharedSecretHmac => "shared_secret_hmac",
        }
    }
}

/// One sender the listener has admitted packets from.
struct SenderEntry {
    /// The capture-agent id it claims, when its packets carry one.
    capture_id: Option<u32>,
    /// The address its packets came from.
    peer: IpAddr,
    /// Its own frame numbering (see `capture::hep`'s ordinal notes).
    frames: FrameCounter,
    /// Packets admitted from it.
    packets: u64,
    /// When the first of them arrived.
    first_seen: Instant,
    /// When the latest of them arrived.
    last_seen: Instant,
    /// Its own silence watch, fed only by its admitted packets.
    watch: IdleWatch,
}

impl SenderEntry {
    /// Count one admitted packet at `now`.
    ///
    /// # Returns
    ///
    /// Its ordinal, the listener's resumption (passed through), and this
    /// sender's own, when the packet ends a silence it was reported for.
    fn admit(&mut self, now: Instant, listener_resumed: Option<Duration>) -> Admission {
        self.packets = self.packets.saturating_add(1);
        self.last_seen = now;
        Admission {
            origin: Some(self.frames.next_origin()),
            listener_resumed,
            sender_resumed: self.watch.on_packet(now),
        }
    }
}

/// One address the listener has been refusing.
struct RefusedSource {
    /// Refusals from it by reason, indexed by [`HepRefusal::index`].
    by_reason: [u64; HepRefusal::COUNT],
    /// When the first of them arrived.
    first_seen: Instant,
    /// When the latest of them arrived.
    last_seen: Instant,
}

/// What admitting one packet did to the roster.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admission {
    /// The packet's place in its sender's own stream, or `None` when the
    /// sender arrived after the tracking table was full.
    pub origin: Option<FrameOrigin>,
    /// How long the whole listener had admitted nothing, when this packet ends
    /// a quiet period it already warned about.
    pub listener_resumed: Option<Duration>,
    /// How long THIS sender had been silent, when this packet ends a silence
    /// it was already reported for.
    pub sender_resumed: Option<Duration>,
}

/// One sender newly found silent by a sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderSilence {
    /// The sender, as [`hep_source_label`] names it.
    pub source: String,
    /// How long since its last admitted packet.
    pub idle: Duration,
}

/// What one poll of the roster found to report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sweep {
    /// The listener-wide warning, when nothing at all was admitted for the
    /// threshold.
    pub listener: Option<SilenceWarning>,
    /// Senders newly silent, by name, at most [`HEP_SILENCE_LINES_PER_SWEEP`].
    pub silent: Vec<SenderSilence>,
    /// Senders newly silent beyond those listed.
    pub silent_not_listed: usize,
}

/// Everything one HEP listener knows about its senders. Pure: every method
/// takes the time it happens at, so a test drives it on a made-up clock.
///
/// # One map, one bound
///
/// The per-sender entries are the listener's frame-ordinal table and the
/// roster at once, keyed by [`hep_source_label`], so the roster and the frame
/// pointers cannot disagree about who a sender is. The bound is the ordinal
/// table's: at `max_senders` a NEW sender is refused an entry rather than
/// given a recycled one — a recycled counter would mint a second frame 0 for
/// a source that already had one. Its packets are still admitted and are
/// counted in `untracked_packets`.
pub struct RosterState {
    /// The trust every admitted packet was accepted under.
    trust: SenderTrust,
    /// The most senders tracked at once.
    max_senders: usize,
    /// Silence threshold for each sender and for the listener.
    threshold: Duration,
    /// Tracked senders by label.
    senders: HashMap<String, SenderEntry>,
    /// Packets admitted from senders past the bound.
    untracked_packets: u64,
    /// Refused addresses, least recently refused first out.
    refused: LruMap<IpAddr, RefusedSource>,
    /// Addresses evicted from `refused` to make room.
    refused_evicted: u64,
    /// Every refusal by reason. Outside `refused`, so nothing evicts it.
    refused_by_reason: [u64; HepRefusal::COUNT],
    /// Every admitted packet, tracked sender or not.
    admitted_total: u64,
    /// The listener-wide watch.
    listener: ListenerSilence,
    /// When the per-sender sweep last walked the table.
    last_sweep: Option<Instant>,
    /// A monotonic instant and the wall-clock time it corresponds to, for
    /// turning `Instant`s into the timestamps the surfaces report.
    origin: (Instant, DateTime<Utc>),
}

impl RosterState {
    /// A roster with nobody in it yet.
    ///
    /// # Arguments
    ///
    /// * `trust` — what the listener admits packets under.
    /// * `max_senders` — the tracking bound (`[limits] max_tracked_peers`).
    /// * `threshold` — the silence threshold; zero turns silence off.
    /// * `now`, `wall` — the same moment on the monotonic and the wall clock.
    #[must_use]
    pub fn new(
        trust: SenderTrust,
        max_senders: usize,
        threshold: Duration,
        now: Instant,
        wall: DateTime<Utc>,
    ) -> Self {
        Self {
            trust,
            max_senders,
            threshold,
            senders: HashMap::new(),
            untracked_packets: 0,
            refused: LruMap::new(HEP_REFUSED_SOURCES_TRACKED),
            refused_evicted: 0,
            refused_by_reason: [0; HepRefusal::COUNT],
            admitted_total: 0,
            listener: ListenerSilence::new(threshold, now),
            last_sweep: None,
            origin: (now, wall),
        }
    }

    /// A packet from `source` was admitted at `now`.
    ///
    /// # Arguments
    ///
    /// * `capture_id` — the id its packet claimed, if any.
    /// * `peer` — the address it came from.
    /// * `source` — [`hep_source_label`] of the two, computed once by the
    ///   caller, which also names the packet's frame pointer with it.
    /// * `now` — when it arrived.
    ///
    /// # Returns
    ///
    /// The packet's ordinal in its sender's stream, and any quiet period this
    /// packet ends — the listener's or the sender's own.
    ///
    /// # Side effects
    ///
    /// Adds the sender when there is room, restarts its watch and the
    /// listener's, and counts the packet.
    pub fn admitted(
        &mut self,
        capture_id: Option<u32>,
        peer: IpAddr,
        source: &str,
        now: Instant,
    ) -> Admission {
        self.admitted_total = self.admitted_total.saturating_add(1);
        let listener_resumed = self.listener.on_admitted(now);
        if let Some(entry) = self.senders.get_mut(source) {
            return entry.admit(now, listener_resumed);
        }
        // Refuse rather than recycle: see the type's own notes.
        if self.senders.len() >= self.max_senders {
            self.untracked_packets = self.untracked_packets.saturating_add(1);
            return Admission {
                origin: None,
                listener_resumed,
                sender_resumed: None,
            };
        }
        let threshold = self.threshold;
        self.senders
            .entry(source.to_string())
            .or_insert_with(|| SenderEntry {
                capture_id,
                peer,
                frames: FrameCounter::new(),
                packets: 0,
                first_seen: now,
                last_seen: now,
                watch: IdleWatch::new(threshold, now),
            })
            .admit(now, listener_resumed)
    }

    /// A packet from `peer` was refused for `reason` at `now`.
    ///
    /// Keyed by address alone: a refused packet proved nothing, so the id it
    /// claimed names nobody. It touches no sender's entry either — a refused
    /// packet is not traffic, for a sender any more than for the listener.
    ///
    /// # Side effects
    ///
    /// Counts the refusal by reason (a count nothing evicts), records the
    /// address in the refused table, evicting the least recently refused
    /// address when it is full, and tallies it for the listener's warning.
    pub fn refused(&mut self, reason: HepRefusal, peer: IpAddr, now: Instant) {
        let slot = reason.index();
        self.refused_by_reason[slot] = self.refused_by_reason[slot].saturating_add(1);
        self.listener.on_refused(reason, peer);
        if !self.refused.contains_key(&peer) && self.refused.len() >= self.refused.capacity() {
            self.refused_evicted = self.refused_evicted.saturating_add(1);
        }
        let source = self.refused.get_or_insert_with(peer, || RefusedSource {
            by_reason: [0; HepRefusal::COUNT],
            first_seen: now,
            last_seen: now,
        });
        source.by_reason[slot] = source.by_reason[slot].saturating_add(1);
        source.last_seen = now;
    }

    /// Poll for silence at `now`.
    ///
    /// The listener-wide check runs on every call. The per-sender walk runs at
    /// most once per second, because it visits every tracked sender.
    ///
    /// # Returns
    ///
    /// The listener's warning, if nothing at all was admitted for the
    /// threshold, and the senders newly silent — each reported once per
    /// silence, never again until it sends.
    pub fn sweep(&mut self, now: Instant) -> Sweep {
        let listener = self.listener.check(now);
        let due = self
            .last_sweep
            .is_none_or(|last| now.saturating_duration_since(last) >= SWEEP_INTERVAL);
        if !due {
            return Sweep {
                listener,
                ..Sweep::default()
            };
        }
        self.last_sweep = Some(now);
        let mut silent: Vec<SenderSilence> = self
            .senders
            .iter_mut()
            .filter_map(|(source, entry)| {
                entry.watch.check(now).map(|idle| SenderSilence {
                    source: source.clone(),
                    idle,
                })
            })
            .collect();
        // Named in a stable order, so two sweeps of one state say the same.
        silent.sort_by(|a, b| a.source.cmp(&b.source));
        let silent_not_listed = silent.len().saturating_sub(HEP_SILENCE_LINES_PER_SWEEP);
        silent.truncate(HEP_SILENCE_LINES_PER_SWEEP);
        Sweep {
            listener,
            silent,
            silent_not_listed,
        }
    }

    /// The aggregate counts the Prometheus exposition publishes. O(1): no
    /// walk of either table.
    #[must_use]
    pub fn counters(&self) -> HepListenerCounts {
        let refused = self
            .refused_by_reason
            .iter()
            .copied()
            .fold(0u64, u64::saturating_add);
        HepListenerCounts {
            senders: self.senders.len() as u64,
            received: self.admitted_total.saturating_add(refused),
            refused_by_reason: self.refused_by_reason,
        }
    }

    /// The monotonic instant this roster started at.
    #[must_use]
    pub fn started(&self) -> Instant {
        self.origin.0
    }

    /// Senders tracked now.
    #[must_use]
    pub fn senders_tracked(&self) -> usize {
        self.senders.len()
    }

    /// Addresses the refused-source table holds now.
    #[must_use]
    pub fn refused_sources_tracked(&self) -> usize {
        self.refused.len()
    }

    /// The report every surface returns.
    ///
    /// # Arguments
    ///
    /// * `now` — the moment "idle" and "silent" are measured to.
    /// * `limit` — the most rows either list may carry. The totals beside
    ///   each list always count everything.
    #[must_use]
    pub fn report(&self, now: Instant, limit: usize) -> HepSendersReport {
        let refused_total = self
            .refused_by_reason
            .iter()
            .copied()
            .fold(0u64, u64::saturating_add);
        let is_silent = |entry: &SenderEntry| {
            !self.threshold.is_zero()
                && now.saturating_duration_since(entry.last_seen) >= self.threshold
        };

        let mut senders: Vec<&SenderEntry> = self.senders.values().collect();
        // By address, then id: a reader scanning for one host finds all of its
        // senders together, and the order does not depend on the hash map.
        senders.sort_by(|a, b| {
            a.peer
                .cmp(&b.peer)
                .then_with(|| a.capture_id.cmp(&b.capture_id))
        });
        let senders_silent = senders.iter().filter(|e| is_silent(e)).count();
        let rows = senders
            .into_iter()
            .take(limit)
            .map(|entry| HepSenderRow {
                source: format!("hep:{}", hep_source_label(entry.capture_id, entry.peer)),
                capture_id: entry.capture_id,
                peer: entry.peer.to_string(),
                identity: IDENTITY_CLAIMED.to_string(),
                trust: self.trust.as_str().to_string(),
                packets: entry.packets,
                first_seen: self.wall(entry.first_seen),
                last_seen: self.wall(entry.last_seen),
                idle_seconds: now.saturating_duration_since(entry.last_seen).as_secs(),
                silent: is_silent(entry),
            })
            .collect();

        let mut refused: Vec<(IpAddr, &RefusedSource)> = self
            .refused
            .iter()
            .map(|(peer, src)| (*peer, src))
            .collect();
        let total_of = |src: &RefusedSource| {
            src.by_reason
                .iter()
                .copied()
                .fold(0u64, u64::saturating_add)
        };
        // Most refused first: the address an operator is looking for is the
        // one sending the most, and a spoofed flood spreads thin.
        refused.sort_by(|(pa, a), (pb, b)| total_of(b).cmp(&total_of(a)).then_with(|| pa.cmp(pb)));
        let refused_rows = refused
            .into_iter()
            .take(limit)
            .map(|(peer, src)| HepRefusedSourceRow {
                peer: peer.to_string(),
                packets: total_of(src),
                by_reason: HepRefusal::ALL
                    .iter()
                    .filter(|r| src.by_reason[r.index()] > 0)
                    .map(|r| (r.as_str().to_string(), src.by_reason[r.index()]))
                    .collect(),
                first_seen: self.wall(src.first_seen),
                last_seen: self.wall(src.last_seen),
            })
            .collect();

        HepSendersReport {
            schema_version: 1,
            listening: true,
            trust: Some(self.trust.as_str().to_string()),
            silence_threshold_seconds: self.threshold.as_secs(),
            packets_received: self.admitted_total.saturating_add(refused_total),
            packets_admitted: self.admitted_total,
            packets_refused: refused_total,
            refused_by_reason: HepRefusal::ALL
                .iter()
                .map(|r| (r.as_str().to_string(), self.refused_by_reason[r.index()]))
                .collect(),
            senders_tracked: self.senders.len() as u64,
            senders_limit: self.max_senders as u64,
            senders_silent: senders_silent as u64,
            untracked_packets: self.untracked_packets,
            senders: rows,
            refused_sources_tracked: self.refused.len() as u64,
            refused_sources_limit: self.refused.capacity() as u64,
            refused_sources_evicted: self.refused_evicted,
            refused_sources: refused_rows,
            note: None,
        }
    }

    /// `at` on the wall clock, as RFC 3339 with milliseconds.
    fn wall(&self, at: Instant) -> String {
        let (mono, wall) = self.origin;
        let offset = chrono::Duration::from_std(at.saturating_duration_since(mono))
            .unwrap_or_else(|_| chrono::Duration::zero());
        (wall + offset).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

/// The senders report for a run: the listener's roster when one hung it on
/// the capture meter, the "not listening" answer otherwise.
///
/// The ONE function every surface calls — `--hep-senders`, `GET
/// /v1/hep/senders`, the MCP `hep_senders` tool and the TUI view — so the
/// "no listener" case cannot be answered four ways.
///
/// # Arguments
///
/// * `roster` — the roster, from [`crate::capture::channel::CaptureMeter::hep_roster`].
/// * `limit` — the most rows either list may carry.
#[must_use]
pub fn senders_report(roster: Option<&HepRoster>, limit: usize) -> HepSendersReport {
    roster.map_or_else(HepSendersReport::not_listening, |r| r.report(limit))
}

/// A listener's aggregate counts, for the Prometheus exposition: no
/// addresses, no ids, and a fixed label set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HepListenerCounts {
    /// Senders tracked now.
    pub senders: u64,
    /// Packets received, admitted or refused.
    pub received: u64,
    /// Refusals by reason, indexed by [`HepRefusal::index`].
    pub refused_by_reason: [u64; HepRefusal::COUNT],
}

/// A shared handle on one listener's [`RosterState`]: the listener writes
/// through it, and every surface that reports senders reads through it.
///
/// Carries a clock so a surface asks "as of now" without choosing what now
/// is — which is what lets a test freeze it and compare two surfaces byte for
/// byte.
#[derive(Clone)]
pub struct HepRoster {
    /// The state, behind the one lock both sides take briefly.
    state: Arc<parking_lot::Mutex<RosterState>>,
    /// Where "now" comes from for a report.
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl std::fmt::Debug for HepRoster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HepRoster").finish_non_exhaustive()
    }
}

impl HepRoster {
    /// A handle on `state`, reporting as of the monotonic clock.
    #[must_use]
    pub fn new(state: RosterState) -> Self {
        Self::with_clock(state, Arc::new(Instant::now))
    }

    /// A handle on `state` whose reports read `clock` for "now".
    #[must_use]
    pub fn with_clock(state: RosterState, clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(state)),
            clock,
        }
    }

    /// The state, locked. Held for one packet's bookkeeping or one report,
    /// never across I/O.
    pub fn lock(&self) -> parking_lot::MutexGuard<'_, RosterState> {
        self.state.lock()
    }

    /// The aggregate counts, for the Prometheus exposition.
    #[must_use]
    pub fn counters(&self) -> HepListenerCounts {
        self.state.lock().counters()
    }

    /// The report every surface returns, at most `limit` rows per list.
    #[must_use]
    pub fn report(&self, limit: usize) -> HepSendersReport {
        let now = (self.clock)();
        self.state.lock().report(now, limit)
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

    // ── The roster ───────────────────────────────────────────────────

    /// A fixed wall-clock origin, so the timestamps a report renders are
    /// known in advance.
    fn wall0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-21T12:00:00Z")
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_default()
    }

    /// A roster with a thirty-second threshold, unauthenticated, bounded at
    /// `max`, starting at `t`.
    fn roster(max: usize, t: Instant) -> RosterState {
        RosterState::new(
            SenderTrust::Unauthenticated,
            max,
            Duration::from_secs(30),
            t,
            wall0(),
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }

    /// Admit one packet from `id@peer` at `t`.
    fn admit(r: &mut RosterState, id: Option<u32>, peer: &str, t: Instant) -> Admission {
        let peer = ip(peer);
        r.admitted(id, peer, &hep_source_label(id, peer), t)
    }

    /// **One peer with two capture ids is two senders, and one id from two
    /// peers is two senders** — the key is the whole of `hep_source_label`,
    /// so neither the default id 1 nor a shared host collapses two nodes.
    #[test]
    fn a_sender_is_its_capture_id_and_its_address_together() {
        let t = t0();
        let mut r = roster(64, t);
        for _ in 0..3 {
            admit(&mut r, Some(7), "10.0.0.5", t);
        }
        admit(&mut r, Some(9), "10.0.0.5", t);
        admit(&mut r, Some(1), "10.0.0.6", t);
        admit(&mut r, Some(1), "10.0.0.7", t);

        let rep = r.report(t, usize::MAX);
        let rows: Vec<(&str, u64)> = rep
            .senders
            .iter()
            .map(|s| (s.source.as_str(), s.packets))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("hep:7@10.0.0.5", 3),
                ("hep:9@10.0.0.5", 1),
                ("hep:1@10.0.0.6", 1),
                ("hep:1@10.0.0.7", 1),
            ],
            "four senders, by address then id, each with its own count"
        );
        assert_eq!(rep.senders_tracked, 4);
        assert_eq!(rep.packets_admitted, 6);
        assert_eq!(rep.packets_received, 6);
        let first = &rep.senders[0];
        assert_eq!(first.capture_id, Some(7));
        assert_eq!(first.peer, "10.0.0.5");
        assert_eq!(first.identity, "claimed_by_sender", "the id is a claim");
        assert_eq!(first.trust, "unauthenticated");
    }

    /// **Every refusal lands under its own reason**, for every reason there
    /// is: the loop walks [`HepRefusal::ALL`] rather than a list typed here,
    /// so a new reason is covered the day it is added.
    #[test]
    fn every_refusal_reason_is_counted_under_its_own_name() {
        let t = t0();
        let mut r = roster(64, t);
        let peer = ip("192.0.2.9");
        // A distinct count per reason, so a reason counted under a
        // neighbor's name shows up as a wrong number, not a coincidence.
        for reason in HepRefusal::ALL {
            for _ in 0..=reason.index() {
                r.refused(reason, peer, t);
            }
        }
        let rep = r.report(t, usize::MAX);
        let total: u64 = (1..=HepRefusal::COUNT as u64).sum();
        assert_eq!(rep.packets_refused, total);
        assert_eq!(rep.packets_received, total, "nothing was admitted");
        assert_eq!(rep.packets_admitted, 0);
        assert_eq!(
            rep.refused_by_reason.len(),
            HepRefusal::COUNT,
            "every reason is reported, zeros included: {:?}",
            rep.refused_by_reason
        );
        for reason in HepRefusal::ALL {
            assert_eq!(
                rep.refused_by_reason.get(reason.as_str()).copied(),
                Some(reason.index() as u64 + 1),
                "{} miscounted: {:?}",
                reason.as_str(),
                rep.refused_by_reason
            );
        }
        assert!(
            rep.senders.is_empty(),
            "a refused packet makes nobody a sender"
        );
        assert_eq!(rep.refused_sources.len(), 1, "one address was refused");
        let src = &rep.refused_sources[0];
        assert_eq!(src.peer, "192.0.2.9");
        assert_eq!(src.packets, total);
        assert_eq!(src.by_reason, rep.refused_by_reason);
    }

    /// **Past the bound a new sender is untracked and counted, and nothing is
    /// recycled** — the roster half of the ordinal table's rule, on the same
    /// map. The senders already tracked keep their entries and their counts.
    #[test]
    fn past_the_bound_a_new_sender_is_counted_but_never_given_an_entry() {
        let t = t0();
        let mut r = roster(2, t);
        admit(&mut r, Some(1), "10.0.0.1", t);
        admit(&mut r, Some(2), "10.0.0.1", t);
        for _ in 0..5 {
            let third = admit(&mut r, Some(3), "10.0.0.1", t);
            assert_eq!(third.origin, None, "an untracked sender gets no ordinal");
        }
        admit(&mut r, Some(1), "10.0.0.1", t);

        let rep = r.report(t, usize::MAX);
        assert_eq!(rep.senders_tracked, 2);
        assert_eq!(rep.senders_limit, 2);
        assert_eq!(
            rep.untracked_packets, 5,
            "the third sender's packets are counted, not lost from the account"
        );
        assert_eq!(rep.packets_admitted, 8, "and they were still admitted");
        let counts: Vec<(&str, u64)> = rep
            .senders
            .iter()
            .map(|s| (s.source.as_str(), s.packets))
            .collect();
        assert_eq!(
            counts,
            vec![("hep:1@10.0.0.1", 2), ("hep:2@10.0.0.1", 1)],
            "the first two keep their entries; the third never displaced one"
        );
    }

    /// The sender table is bounded, and at the bound it withholds an ordinal
    /// rather than recycling one.
    ///
    /// The label carries a capture-agent id an unauthenticated peer chooses,
    /// so one host can mint unbounded labels. Recycling a counter would give a
    /// source a SECOND frame 0 — two datagrams with one name — so a new sender
    /// past the bound gets nothing, and `frame_ref` then reports unknown,
    /// which is true.
    #[test]
    fn a_new_hep_sender_past_the_bound_gets_no_ordinal_rather_than_a_recycled_one() {
        let t = t0();
        let mut r = roster(2, t);
        let ord = |a: Admission| a.origin.map(|o| o.ordinal);
        assert_eq!(ord(admit(&mut r, Some(1), "10.0.0.1", t)), Some(0));
        assert_eq!(ord(admit(&mut r, Some(2), "10.0.0.1", t)), Some(0));
        assert_eq!(
            ord(admit(&mut r, Some(3), "10.0.0.1", t)),
            None,
            "a third sender past a bound of two must be left unnumbered"
        );
        // The senders already being counted keep counting: the bound must not
        // turn into a denial of provenance for the nodes that were there
        // first.
        assert_eq!(ord(admit(&mut r, Some(1), "10.0.0.1", t)), Some(1));
        assert_eq!(ord(admit(&mut r, Some(2), "10.0.0.1", t)), Some(1));
    }

    /// **The refused table evicts the least recently refused address, and
    /// the reason totals still equal every refusal.** A spoofed flood rotates
    /// the table; it cannot freeze it, and it cannot erase the count.
    #[test]
    fn the_refused_table_rotates_but_the_reason_totals_never_lose_a_refusal() {
        let t = t0();
        let mut r = roster(64, t);
        let flood = HEP_REFUSED_SOURCES_TRACKED + 40;
        // The address that keeps being refused, touched between every flood
        // address, is the one a real operator would be looking for.
        let persistent = ip("198.51.100.1");
        for i in 0..flood {
            let spoofed = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i as u32));
            r.refused(HepRefusal::Malformed, spoofed, t);
            r.refused(HepRefusal::AuthMismatch, persistent, t);
            assert!(r.refused_sources_tracked() <= HEP_REFUSED_SOURCES_TRACKED);
        }
        let rep = r.report(t, usize::MAX);
        assert_eq!(
            rep.refused_sources_tracked,
            HEP_REFUSED_SOURCES_TRACKED as u64
        );
        assert_eq!(
            rep.refused_sources_limit,
            HEP_REFUSED_SOURCES_TRACKED as u64
        );
        assert_eq!(
            rep.refused_sources_evicted,
            (flood + 1 - HEP_REFUSED_SOURCES_TRACKED) as u64,
            "every address past the bound displaced exactly one"
        );
        assert_eq!(rep.packets_refused, 2 * flood as u64);
        assert_eq!(
            rep.refused_by_reason.get("malformed").copied(),
            Some(flood as u64)
        );
        assert_eq!(
            rep.refused_by_reason.get("auth_mismatch").copied(),
            Some(flood as u64)
        );
        assert_eq!(
            rep.refused_sources[0].peer, "198.51.100.1",
            "the persistently refused address survived the flood and leads"
        );
        assert_eq!(rep.refused_sources[0].packets, flood as u64);
    }

    /// **A silent sender is reported while the others keep sending, and its
    /// return reports the outage.** The listener-wide warning cannot say this:
    /// it stays quiet while anyone at all is sending.
    #[test]
    fn one_silent_sender_among_live_ones_is_reported_and_its_return_is_too() {
        let t = t0();
        let mut r = roster(64, t);
        admit(&mut r, Some(1), "10.0.0.1", t);
        admit(&mut r, Some(2), "10.0.0.2", t);
        let mut silent = Vec::new();
        let mut listener = Vec::new();
        for s in 1..=40 {
            let now = t + Duration::from_secs(s);
            // B keeps sending; A said nothing after t.
            admit(&mut r, Some(2), "10.0.0.2", now);
            let sweep = r.sweep(now);
            silent.extend(sweep.silent.into_iter().map(|x| (s, x.source, x.idle)));
            listener.extend(sweep.listener);
        }
        assert_eq!(
            silent,
            vec![(30, "1@10.0.0.1".to_string(), Duration::from_secs(30))],
            "A is reported once, when its own threshold is crossed"
        );
        assert!(
            listener.is_empty(),
            "the listener as a whole was never quiet"
        );
        let rep = r.report(t + Duration::from_secs(40), usize::MAX);
        let a = &rep.senders[0];
        assert_eq!(a.source, "hep:1@10.0.0.1");
        assert!(a.silent, "A is silent");
        assert_eq!(a.idle_seconds, 40);
        assert!(!rep.senders[1].silent, "B is not");
        assert_eq!(rep.senders_silent, 1);

        let back = admit(&mut r, Some(1), "10.0.0.1", t + Duration::from_secs(45));
        assert_eq!(
            back.sender_resumed,
            Some(Duration::from_secs(45)),
            "A's first packet back reports how long it was gone"
        );
        assert_eq!(back.listener_resumed, None, "the listener never went quiet");
        let rep = r.report(t + Duration::from_secs(45), usize::MAX);
        assert_eq!(rep.senders_silent, 0);
    }

    /// **Refused packets do not keep a known sender from going silent.** A
    /// sender whose key was rotated on the collector and not on the sender
    /// still arrives from the same address; nothing it sends is admitted, so
    /// it IS silent, and it must be reported so.
    #[test]
    fn a_known_sender_whose_packets_are_now_refused_still_goes_silent() {
        let t = t0();
        let mut r = roster(64, t);
        admit(&mut r, Some(4), "10.0.0.4", t);
        admit(&mut r, Some(5), "10.0.0.5", t);
        let mut reported = Vec::new();
        for s in 1..=31 {
            let now = t + Duration::from_secs(s);
            r.refused(HepRefusal::AuthMismatch, ip("10.0.0.4"), now);
            admit(&mut r, Some(5), "10.0.0.5", now);
            reported.extend(r.sweep(now).silent.into_iter().map(|x| x.source));
        }
        assert_eq!(reported, vec!["4@10.0.0.4".to_string()]);
    }

    /// Timestamps are wall-clock renderings of when packets arrived, and a
    /// row limit caps each list without changing the totals beside it.
    #[test]
    fn a_report_renders_arrival_times_and_honors_its_row_limit() {
        let t = t0();
        let mut r = roster(64, t);
        admit(&mut r, Some(1), "10.0.0.1", t + Duration::from_millis(1500));
        admit(&mut r, Some(1), "10.0.0.1", t + Duration::from_secs(5));
        admit(&mut r, Some(2), "10.0.0.2", t + Duration::from_secs(6));
        r.refused(
            HepRefusal::Allowlist,
            ip("203.0.113.1"),
            t + Duration::from_secs(7),
        );
        r.refused(
            HepRefusal::Allowlist,
            ip("203.0.113.2"),
            t + Duration::from_secs(8),
        );

        let rep = r.report(t + Duration::from_secs(10), 1);
        assert_eq!(rep.senders.len(), 1, "the row limit caps the list");
        assert_eq!(rep.senders_tracked, 2, "but not the total beside it");
        assert_eq!(rep.refused_sources.len(), 1);
        assert_eq!(rep.refused_sources_tracked, 2);
        let a = &rep.senders[0];
        assert_eq!(a.first_seen, "2026-09-21T12:00:01.500Z");
        assert_eq!(a.last_seen, "2026-09-21T12:00:05.000Z");
        assert_eq!(a.idle_seconds, 5);
        assert!(!a.silent);
        assert_eq!(rep.silence_threshold_seconds, 30);
        assert_eq!(rep.trust.as_deref(), Some("unauthenticated"));
        assert!(rep.listening);
        assert_eq!(rep.note, None);
    }

    /// A zero threshold turns silence off for senders as it does for the
    /// listener: nobody is ever reported silent.
    #[test]
    fn a_zero_threshold_reports_no_sender_silent() {
        let t = t0();
        let mut r = RosterState::new(
            SenderTrust::SharedSecretHmac,
            64,
            Duration::ZERO,
            t,
            wall0(),
        );
        admit(&mut r, Some(1), "10.0.0.1", t);
        let later = t + Duration::from_secs(3600);
        assert_eq!(r.sweep(later), Sweep::default());
        let rep = r.report(later, usize::MAX);
        assert!(!rep.senders[0].silent);
        assert_eq!(rep.senders[0].trust, "shared_secret_hmac");
    }

    /// A sweep names at most [`HEP_SILENCE_LINES_PER_SWEEP`] senders and
    /// counts the rest, so a flood that filled the table and stopped cannot
    /// flood the journal with silence lines.
    #[test]
    fn a_sweep_names_a_bounded_number_of_silent_senders() {
        let t = t0();
        let mut r = roster(4096, t);
        let many = HEP_SILENCE_LINES_PER_SWEEP + 25;
        for id in 0..many as u32 {
            admit(&mut r, Some(id), "10.0.0.1", t);
        }
        // Someone else keeps the listener as a whole awake.
        admit(
            &mut r,
            Some(99_999),
            "10.0.0.2",
            t + Duration::from_secs(31),
        );
        let sweep = r.sweep(t + Duration::from_secs(31));
        assert_eq!(sweep.silent.len(), HEP_SILENCE_LINES_PER_SWEEP);
        assert_eq!(sweep.silent_not_listed, many - HEP_SILENCE_LINES_PER_SWEEP);
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
