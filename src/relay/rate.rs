// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The rate media arrived at, from two counter samples: the one rule the
//! relay's counters and the capture's counters both use.
//!
//! A relay answers `query` with running totals per socket: packets and bytes
//! received since the call began. A rate needs two such totals of the same
//! socket of the same call, and the time between them. [`rate`] is that rule,
//! and [`RateMemory`] keeps the previous sample so a later ask can apply it.
//!
//! # The rule
//!
//! - The divisor is the measured gap between the two samples, on sipnab's
//!   own monotonic clock ([`monotonic_now`]), never the configured interval:
//!   a refresh that ran late divides by the time it really took.
//! - A sample of another incarnation of the call (the relay's `created`
//!   stamp changed: the Call-ID was set up again) is a reset, even when every
//!   counter grew.
//! - A counter that went backwards is a reset, never a negative or wrapped
//!   rate.
//! - A rate above [`MAX_BITS_PER_SECOND`] is a reset: no one socket receives
//!   more than a 10 Gbit/s link carries, so such a jump is a counter that
//!   restarted elsewhere, not media.
//! - A counter the sample does not carry is `not_reported`, and a socket the
//!   capture holds no stream for is `not_captured`; neither is ever 0.
//!
//! # Units
//!
//! Every rate is given twice: packets per second, which means the same on
//! both tiers, and kbit/s (1000 bits per second), whose byte basis differs and
//! is named ([`ByteBasis`]): the relay counts the UDP payload, the RTP header
//! included (172 bytes per 20 ms G.711 packet), and the capture counts the RTP
//! payload only (160 bytes). The same 50 packets per second read 68.8 kbit/s
//! from the relay and 64.0 kbit/s from the capture, and that difference is
//! the basis, not a disagreement.
//!
//! # Memory
//!
//! [`RateMemory`] holds at most [`RATE_MEMORY_SOCKETS`] previous samples,
//! keyed by engine, Call-ID and socket, each kept with the call's incarnation,
//! and forgets the least recently sampled socket first.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde::{Serialize, Serializer};

/// The fastest rate one socket is believed to receive, in bits per second.
///
/// 10 Gbit/s, the line rate of the fastest interface a relay host commonly
/// has. A delta that needs more than this in the gap between two samples did
/// not arrive as media; it is reported as a reset.
pub const MAX_BITS_PER_SECOND: u64 = 10_000_000_000;

/// The most sockets one [`RateMemory`] remembers.
///
/// The scan ceiling of 1024 calls ([`crate::relay::scan_cap::SCAN_CAP_CEILING`])
/// times four RTP sockets per call (two parties, audio and video).
pub const RATE_MEMORY_SOCKETS: usize = 4096;

/// Which call, of the ones that used a Call-ID, a sample belongs to: the
/// relay's `created` stamp of the call, whole seconds and microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Incarnation {
    /// `created`: whole seconds on the relay's clock.
    pub created_s: i64,
    /// `created_us`: the microseconds within that second.
    pub created_us: u32,
}

/// What a kbit/s figure counts per packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum ByteBasis {
    /// The UDP payload: the RTP header and its payload. What a relay counts.
    UdpPayload,
    /// The RTP payload only, without the RTP header. What the capture counts.
    RtpPayload,
}

impl ByteBasis {
    /// The basis in words, for the text answers.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::UdpPayload => "UDP payload, RTP header included",
            Self::RtpPayload => "RTP payload only",
        }
    }
}

/// Why two samples gave no rate although both carried counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum ResetReason {
    /// The relay's `created` stamp changed: the Call-ID was set up again.
    IncarnationChanged,
    /// A counter is lower than in the previous sample.
    CounterBackwards,
    /// The delta needs more than [`MAX_BITS_PER_SECOND`].
    OutOfRange,
}

impl ResetReason {
    /// The reason in words.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::IncarnationChanged => "the relay set the call up again",
            Self::CounterBackwards => "a counter went backwards",
            Self::OutOfRange => "the counters jumped by more than 10 Gbit/s carries",
        }
    }
}

/// One reading of one socket's running totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// When the reading was taken, on sipnab's monotonic clock.
    pub at: Duration,
    /// The call incarnation it belongs to, when the source reports one.
    pub incarnation: Option<Incarnation>,
    /// Packets received so far, when reported.
    pub packets: Option<u64>,
    /// Bytes received so far, when reported.
    pub bytes: Option<u64>,
}

/// A rate: what arrived between two samples, and over how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Packets that arrived in the gap.
    pub packets: u64,
    /// Bytes that arrived in the gap, on `basis`.
    pub bytes: u64,
    /// The measured gap.
    pub over: Duration,
    /// What `bytes` counts per packet.
    pub basis: ByteBasis,
}

impl Rate {
    /// Packets per second, in tenths, rounded half up.
    #[must_use]
    pub fn packets_per_s_tenths(&self) -> u64 {
        // packets / s * 10 = packets * 10 * 1e9 / nanos.
        per_gap(u128::from(self.packets) * 10_000_000_000, self.over)
    }

    /// kbit/s (1000 bits per second), in tenths, rounded half up.
    #[must_use]
    pub fn kbps_tenths(&self) -> u64 {
        // kbit/s * 10 = bytes * 8 / 1000 * 10 / s; with the gap in
        // nanoseconds that is bytes * 8e7 / nanos.
        per_gap(u128::from(self.bytes) * 80_000_000, self.over)
    }
}

/// `scaled / gap_in_nanoseconds`, rounded half up, saturating at `u64::MAX`.
fn per_gap(scaled: u128, over: Duration) -> u64 {
    let nanos = over.as_nanos().max(1);
    u64::try_from((scaled + nanos / 2) / nanos).unwrap_or(u64::MAX)
}

/// What two samples say about the rate on one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateOutcome {
    /// A rate over the measured gap.
    Rate(Rate),
    /// Only one sample so far.
    NoRateYet,
    /// The counters restarted between the samples.
    Reset(ResetReason),
    /// The source did not report the counters.
    NotReported,
    /// The clock did not advance between the samples.
    NoInterval,
    /// An RTCP socket: only RTP is rated.
    RtcpNotCounted,
    /// The capture holds no stream on this socket for this call.
    NotCaptured,
}

/// The rate between `previous` and `current`, on `basis`.
///
/// Pure: the timestamps are in the samples, so tests drive the clock.
#[must_use]
pub fn rate(previous: Option<&Sample>, current: &Sample, basis: ByteBasis) -> RateOutcome {
    let (Some(packets), Some(bytes)) = (current.packets, current.bytes) else {
        return RateOutcome::NotReported;
    };
    let Some(previous) = previous else {
        return RateOutcome::NoRateYet;
    };
    if previous.incarnation != current.incarnation {
        return RateOutcome::Reset(ResetReason::IncarnationChanged);
    }
    let (Some(packets_then), Some(bytes_then)) = (previous.packets, previous.bytes) else {
        return RateOutcome::NoRateYet;
    };
    let Some(over) = current.at.checked_sub(previous.at).filter(|d| !d.is_zero()) else {
        return RateOutcome::NoInterval;
    };
    let (Some(packets), Some(bytes)) = (
        packets.checked_sub(packets_then),
        bytes.checked_sub(bytes_then),
    ) else {
        return RateOutcome::Reset(ResetReason::CounterBackwards);
    };
    // bits / s > MAX  <=>  bytes * 8 * 1e9 > MAX * nanos.
    if u128::from(bytes) * 8 * 1_000_000_000 > u128::from(MAX_BITS_PER_SECOND) * over.as_nanos() {
        return RateOutcome::Reset(ResetReason::OutOfRange);
    }
    RateOutcome::Rate(Rate {
        packets,
        bytes,
        over,
        basis,
    })
}

/// Which socket a remembered sample is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateKey {
    /// The engine that answered, as the answer names it.
    pub engine: String,
    /// The Call-ID.
    pub call_id: String,
    /// The relay socket's address.
    pub address: String,
    /// The relay socket's port.
    pub port: u16,
}

/// The previous sample of each socket, bounded.
#[derive(Debug, Clone)]
pub struct RateMemory {
    /// The most sockets kept.
    capacity: usize,
    /// Each socket's previous sample, with the sequence number it was kept at.
    entries: HashMap<RateKey, (u64, Sample), ahash::RandomState>,
    /// Every kept socket by sequence number, oldest first, for eviction.
    order: BTreeMap<u64, RateKey>,
    /// The sequence number the next kept sample takes.
    next: u64,
}

impl RateMemory {
    /// An empty memory holding at most `capacity` sockets (at least 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::with_hasher(ahash::RandomState::new()),
            order: BTreeMap::new(),
            next: 0,
        }
    }

    /// How many sockets it remembers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it remembers nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether it remembers `key`.
    #[must_use]
    pub fn remembers(&self, key: &RateKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Apply [`rate`] to the remembered sample of `key` and `sample`, then
    /// remember `sample` as the next one's previous.
    ///
    /// A sample without counters, and one whose clock did not advance, is
    /// not remembered: the next sample is rated against the last one that
    /// can be. At capacity, the least recently sampled socket is forgotten.
    pub fn observe(&mut self, key: RateKey, sample: Sample, basis: ByteBasis) -> RateOutcome {
        let kept =
            |o: RateOutcome| !matches!(o, RateOutcome::NotReported | RateOutcome::NoInterval);
        let seq = self.next;
        // One hash lookup on the common path, a socket asked again; its key
        // moves into the order index instead of being copied.
        if let Some(entry) = self.entries.get_mut(&key) {
            let outcome = rate(Some(&entry.1), &sample, basis);
            if kept(outcome) {
                self.next += 1;
                self.order.remove(&entry.0);
                *entry = (seq, sample);
                self.order.insert(seq, key);
            }
            return outcome;
        }
        let outcome = rate(None, &sample, basis);
        if kept(outcome) {
            self.next += 1;
            self.entries.insert(key.clone(), (seq, sample));
            if self.entries.len() > self.capacity
                && let Some((_, oldest)) = self.order.pop_first()
            {
                self.entries.remove(&oldest);
            }
            self.order.insert(seq, key);
        }
        outcome
    }
}

impl Default for RateMemory {
    fn default() -> Self {
        Self::new(RATE_MEMORY_SOCKETS)
    }
}

/// One memory per tier: what the relay counted, and what the capture saw.
#[derive(Debug, Clone, Default)]
pub struct RateMemories {
    /// The relay's counters.
    pub relay: RateMemory,
    /// The capture's counters.
    pub capture: RateMemory,
}

/// sipnab's monotonic clock, as the time since this process first read it.
#[must_use]
pub fn monotonic_now() -> Duration {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now).elapsed()
}

/// A tenth-precision number, serialized as a JSON number with one decimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tenths(pub u64);

impl Serialize for Tenths {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[allow(clippy::cast_precision_loss)]
        let v = self.0 as f64 / 10.0;
        s.serialize_f64(v)
    }
}

impl std::fmt::Display for Tenths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.0 / 10, self.0 % 10)
    }
}

/// A rate as every surface shows it: the state, and for a rate its numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum RateView {
    /// A rate over the measured gap.
    Rate {
        /// Packets per second.
        #[cfg_attr(feature = "api", schema(value_type = f64))]
        #[cfg_attr(feature = "mcp", schemars(with = "f64"))]
        packets_per_s: Tenths,
        /// kbit/s (1000 bits per second) on `byte_basis`.
        #[cfg_attr(feature = "api", schema(value_type = f64))]
        #[cfg_attr(feature = "mcp", schemars(with = "f64"))]
        kbps: Tenths,
        /// What a byte of `kbps` counts.
        byte_basis: ByteBasis,
        /// The measured gap between the two samples, in milliseconds.
        over_ms: u64,
    },
    /// Only one sample so far: ask again for a rate.
    NoRateYet,
    /// The counters restarted between the samples.
    Reset {
        /// Why.
        reason: ResetReason,
    },
    /// The source did not report the counters.
    NotReported,
    /// The clock did not advance between the samples.
    NoInterval,
    /// An RTCP socket: only RTP is rated.
    RtcpNotCounted,
    /// The capture holds no stream on this socket for this call.
    NotCaptured,
}

impl From<RateOutcome> for RateView {
    fn from(o: RateOutcome) -> Self {
        match o {
            RateOutcome::Rate(r) => Self::Rate {
                packets_per_s: Tenths(r.packets_per_s_tenths()),
                kbps: Tenths(r.kbps_tenths()),
                byte_basis: r.basis,
                over_ms: u64::try_from(r.over.as_millis()).unwrap_or(u64::MAX),
            },
            RateOutcome::NoRateYet => Self::NoRateYet,
            RateOutcome::Reset(reason) => Self::Reset { reason },
            RateOutcome::NotReported => Self::NotReported,
            RateOutcome::NoInterval => Self::NoInterval,
            RateOutcome::RtcpNotCounted => Self::RtcpNotCounted,
            RateOutcome::NotCaptured => Self::NotCaptured,
        }
    }
}

impl RateView {
    /// The rate in words, the same on every text surface.
    #[must_use]
    pub fn words(&self) -> String {
        match self {
            Self::Rate {
                packets_per_s,
                kbps,
                byte_basis,
                over_ms,
            } => format!(
                "{packets_per_s} pps, {kbps} kbps ({}) over {}.{:03} s",
                byte_basis.words(),
                over_ms / 1000,
                over_ms % 1000
            ),
            Self::NoRateYet => "no rate yet: one answer so far".to_string(),
            Self::Reset { reason } => format!("reset: {}", reason.words()),
            Self::NotReported => "not reported by the relay".to_string(),
            Self::NoInterval => "no rate: the clock did not advance".to_string(),
            Self::RtcpNotCounted => "RTCP, not rated".to_string(),
            Self::NotCaptured => "not captured".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: ByteBasis = ByteBasis::UdpPayload;
    const CAPTURE: ByteBasis = ByteBasis::RtpPayload;
    const FIRST: Incarnation = Incarnation {
        created_s: 1_787_517_788,
        created_us: 160_191,
    };
    const SECOND: Incarnation = Incarnation {
        created_s: 1_789_316_560,
        created_us: 132_898,
    };

    fn sample(ms: u64, packets: u64, bytes: u64) -> Sample {
        Sample {
            at: Duration::from_millis(ms),
            incarnation: Some(FIRST),
            packets: Some(packets),
            bytes: Some(bytes),
        }
    }

    type TestError = Box<dyn std::error::Error>;

    fn rated(o: RateOutcome) -> Result<Rate, TestError> {
        match o {
            RateOutcome::Rate(r) => Ok(r),
            other => Err(format!("expected a rate, got {other:?}").into()),
        }
    }

    fn key(call: &str, port: u16) -> RateKey {
        RateKey {
            engine: "192.0.2.10:2223".to_string(),
            call_id: call.to_string(),
            address: "192.0.2.11".to_string(),
            port,
        }
    }

    // ---- success ----

    #[test]
    fn success_one_second_of_g711_at_the_relay_is_50_pps_and_68_8_kbps() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(1000, 931, 160_132)),
            &sample(2000, 981, 168_732),
            RELAY,
        ))?;
        assert_eq!(r.packets, 50, "packet delta");
        assert_eq!(r.bytes, 8600, "byte delta");
        assert_eq!(r.packets_per_s_tenths(), 500, "50.0 pps");
        assert_eq!(r.kbps_tenths(), 688, "172 B x 50 x 8 = 68.8 kbit/s");
        Ok(())
    }

    #[test]
    fn success_the_same_packets_at_the_capture_are_64_0_kbps() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(0, 0, 0)),
            &sample(1000, 50, 8000),
            CAPTURE,
        ))?;
        assert_eq!(r.packets_per_s_tenths(), 500, "50.0 pps");
        assert_eq!(r.kbps_tenths(), 640, "160 B x 50 x 8 = 64.0 kbit/s");
        assert_eq!(r.basis, ByteBasis::RtpPayload, "the basis is carried");
        Ok(())
    }

    #[test]
    fn success_a_late_refresh_divides_by_the_measured_gap() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(0, 0, 0)),
            &sample(1500, 100, 17_200),
            RELAY,
        ))?;
        assert_eq!(r.over, Duration::from_millis(1500), "the measured gap");
        assert_eq!(r.packets_per_s_tenths(), 667, "100 / 1.5 s = 66.7 pps");
        assert_eq!(r.kbps_tenths(), 917, "17200 B x 8 / 1.5 s = 91.7 kbit/s");
        Ok(())
    }

    #[test]
    fn success_a_two_second_refresh_halves_the_deltas() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(10_000, 1000, 172_000)),
            &sample(12_000, 1100, 189_200),
            RELAY,
        ))?;
        assert_eq!(r.packets_per_s_tenths(), 500, "100 packets over 2 s");
        assert_eq!(r.kbps_tenths(), 688, "17200 B over 2 s");
        Ok(())
    }

    #[test]
    fn success_no_new_packets_is_a_measured_zero_rate() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(0, 500, 86_000)),
            &sample(2000, 500, 86_000),
            RELAY,
        ))?;
        assert_eq!(r.packets_per_s_tenths(), 0, "silence is a measured 0");
        assert_eq!(r.kbps_tenths(), 0, "silence is a measured 0");
        Ok(())
    }

    #[test]
    fn success_both_samples_without_an_incarnation_compare_equal() -> Result<(), TestError> {
        let mut a = sample(0, 0, 0);
        let mut b = sample(1000, 50, 8000);
        a.incarnation = None;
        b.incarnation = None;
        let r = rated(rate(Some(&a), &b, CAPTURE))?;
        assert_eq!(r.packets, 50, "the capture tier has no incarnation");
        Ok(())
    }

    #[test]
    fn success_memory_gives_a_rate_from_the_second_sample() -> Result<(), TestError> {
        let mut m = RateMemory::new(8);
        let first = m.observe(key("a@example.invalid", 30000), sample(0, 0, 0), RELAY);
        assert_eq!(first, RateOutcome::NoRateYet, "first sample");
        let second = m.observe(
            key("a@example.invalid", 30000),
            sample(1000, 50, 8600),
            RELAY,
        );
        assert_eq!(rated(second)?.packets_per_s_tenths(), 500, "second sample");
        Ok(())
    }

    #[test]
    fn success_memory_chains_each_rate_off_the_previous_sample() -> Result<(), TestError> {
        let mut m = RateMemory::new(8);
        let k = key("a@example.invalid", 30000);
        m.observe(k.clone(), sample(0, 0, 0), RELAY);
        m.observe(k.clone(), sample(1000, 50, 8600), RELAY);
        let third = rated(m.observe(k, sample(2000, 150, 25_800), RELAY))?;
        assert_eq!(third.packets, 100, "delta from the second, not the first");
        Ok(())
    }

    #[test]
    fn success_memory_keeps_sockets_apart() -> Result<(), TestError> {
        let mut m = RateMemory::new(8);
        m.observe(key("a@example.invalid", 30000), sample(0, 0, 0), RELAY);
        m.observe(key("a@example.invalid", 30002), sample(0, 10, 1720), RELAY);
        let r = rated(m.observe(
            key("a@example.invalid", 30002),
            sample(1000, 60, 10_320),
            RELAY,
        ))?;
        assert_eq!(r.packets, 50, "port 30002 against its own sample");
        assert_eq!(m.len(), 2, "two sockets remembered");
        Ok(())
    }

    #[test]
    fn success_memory_keeps_engines_apart() {
        let mut m = RateMemory::new(8);
        let mut other = key("a@example.invalid", 30000);
        other.engine = "192.0.2.20:2223".to_string();
        m.observe(key("a@example.invalid", 30000), sample(0, 0, 0), RELAY);
        let o = m.observe(other, sample(1000, 50, 8600), RELAY);
        assert_eq!(
            o,
            RateOutcome::NoRateYet,
            "a call on another engine has its own counters"
        );
    }

    #[test]
    fn success_view_of_a_rate_carries_both_units_and_the_basis() -> Result<(), TestError> {
        let view = RateView::from(rate(
            Some(&sample(0, 0, 0)),
            &sample(2000, 100, 17_200),
            RELAY,
        ));
        let v = serde_json::to_value(view)?;
        assert_eq!(v["state"], "rate", "{v}");
        assert_eq!(v["packets_per_s"], 50.0, "{v}");
        assert_eq!(v["kbps"], 68.8, "{v}");
        assert_eq!(v["byte_basis"], "udp_payload", "{v}");
        assert_eq!(v["over_ms"], 2000, "{v}");
        Ok(())
    }

    #[test]
    fn success_words_of_a_rate_name_both_units_and_the_basis() {
        let view = RateView::from(rate(
            Some(&sample(0, 0, 0)),
            &sample(1000, 50, 8000),
            CAPTURE,
        ));
        assert_eq!(
            view.words(),
            "50.0 pps, 64.0 kbps (RTP payload only) over 1.000 s",
            "text form"
        );
    }

    #[test]
    fn success_tenths_print_with_one_decimal() {
        assert_eq!(Tenths(688).to_string(), "68.8", "68.8");
        assert_eq!(Tenths(5).to_string(), "0.5", "below one");
        assert_eq!(Tenths(500).to_string(), "50.0", "a whole number");
    }

    // ---- failure ----

    #[test]
    fn failure_no_previous_sample_is_no_rate_yet_never_zero() {
        assert_eq!(
            rate(None, &sample(1000, 50, 8600), RELAY),
            RateOutcome::NoRateYet,
            "one sample gives no rate"
        );
    }

    #[test]
    fn failure_a_packet_counter_going_backwards_is_a_reset() {
        assert_eq!(
            rate(
                Some(&sample(0, 1000, 172_000)),
                &sample(1000, 10, 172_500),
                RELAY
            ),
            RateOutcome::Reset(ResetReason::CounterBackwards),
            "never a negative or wrapped rate"
        );
    }

    #[test]
    fn failure_a_byte_counter_going_backwards_is_a_reset() {
        assert_eq!(
            rate(
                Some(&sample(0, 1000, 172_000)),
                &sample(1000, 1050, 1_720),
                RELAY
            ),
            RateOutcome::Reset(ResetReason::CounterBackwards),
            "bytes are checked too"
        );
    }

    #[test]
    fn failure_a_new_incarnation_is_a_reset_although_every_counter_grew() {
        let mut later = sample(1000, 2000, 344_000);
        later.incarnation = Some(SECOND);
        assert_eq!(
            rate(Some(&sample(0, 1000, 172_000)), &later, RELAY),
            RateOutcome::Reset(ResetReason::IncarnationChanged),
            "the Call-ID was set up again"
        );
    }

    #[test]
    fn failure_an_incarnation_that_appears_is_a_reset() {
        let mut before = sample(0, 0, 0);
        before.incarnation = None;
        assert_eq!(
            rate(Some(&before), &sample(1000, 50, 8600), RELAY),
            RateOutcome::Reset(ResetReason::IncarnationChanged),
            "None then Some is another call"
        );
    }

    #[test]
    fn failure_a_jump_above_10_gbit_s_is_out_of_range() {
        // 1.25e9 bytes in 1 s is exactly 10 Gbit/s; one byte more is out.
        assert_eq!(
            rate(
                Some(&sample(0, 0, 0)),
                &sample(1000, 50, 1_250_000_001),
                RELAY
            ),
            RateOutcome::Reset(ResetReason::OutOfRange),
            "more than a 10 Gbit/s link carries"
        );
    }

    #[test]
    fn failure_missing_packets_now_is_not_reported() {
        let mut now = sample(1000, 0, 8600);
        now.packets = None;
        assert_eq!(
            rate(Some(&sample(0, 0, 0)), &now, RELAY),
            RateOutcome::NotReported,
            "never 0"
        );
    }

    #[test]
    fn failure_missing_bytes_now_is_not_reported() {
        let mut now = sample(1000, 50, 0);
        now.bytes = None;
        assert_eq!(
            rate(Some(&sample(0, 0, 0)), &now, RELAY),
            RateOutcome::NotReported,
            "never 0"
        );
    }

    #[test]
    fn failure_missing_counters_in_the_previous_sample_is_no_rate_yet() {
        let mut before = sample(0, 0, 0);
        before.packets = None;
        before.bytes = None;
        assert_eq!(
            rate(Some(&before), &sample(1000, 50, 8600), RELAY),
            RateOutcome::NoRateYet,
            "nothing to subtract from"
        );
    }

    #[test]
    fn failure_an_equal_timestamp_is_no_interval() {
        assert_eq!(
            rate(Some(&sample(1000, 0, 0)), &sample(1000, 50, 8600), RELAY),
            RateOutcome::NoInterval,
            "never a division by zero"
        );
    }

    #[test]
    fn failure_a_timestamp_going_backwards_is_no_interval() {
        assert_eq!(
            rate(Some(&sample(2000, 0, 0)), &sample(1000, 50, 8600), RELAY),
            RateOutcome::NoInterval,
            "never a negative gap"
        );
    }

    #[test]
    fn failure_memory_after_a_reset_rates_from_the_new_baseline() -> Result<(), TestError> {
        let mut m = RateMemory::new(8);
        let k = key("a@example.invalid", 30000);
        m.observe(k.clone(), sample(0, 1000, 172_000), RELAY);
        let reset = m.observe(k.clone(), sample(1000, 10, 1720), RELAY);
        assert_eq!(
            reset,
            RateOutcome::Reset(ResetReason::CounterBackwards),
            "reset"
        );
        let after = rated(m.observe(k, sample(2000, 60, 10_320), RELAY))?;
        assert_eq!(after.packets, 50, "rated from the sample at the reset");
        Ok(())
    }

    #[test]
    fn failure_memory_keeps_the_previous_sample_when_the_clock_did_not_advance()
    -> Result<(), TestError> {
        let mut m = RateMemory::new(8);
        let k = key("a@example.invalid", 30000);
        m.observe(k.clone(), sample(1000, 0, 0), RELAY);
        let stuck = m.observe(k.clone(), sample(1000, 50, 8600), RELAY);
        assert_eq!(stuck, RateOutcome::NoInterval, "no interval");
        let later = rated(m.observe(k, sample(2000, 50, 8600), RELAY))?;
        assert_eq!(later.packets, 50, "still against the first sample");
        Ok(())
    }

    #[test]
    fn failure_memory_does_not_remember_a_sample_without_counters() {
        let mut m = RateMemory::new(8);
        let k = key("a@example.invalid", 30000);
        let mut none = sample(0, 0, 0);
        none.packets = None;
        assert_eq!(
            m.observe(k.clone(), none, RELAY),
            RateOutcome::NotReported,
            "not reported"
        );
        assert!(!m.remembers(&k), "nothing to rate against was kept");
    }

    #[test]
    fn failure_view_of_no_rate_yet_has_no_numbers() -> Result<(), TestError> {
        let v = serde_json::to_value(RateView::from(RateOutcome::NoRateYet))?;
        assert_eq!(v, serde_json::json!({"state": "no_rate_yet"}), "{v}");
        Ok(())
    }

    #[test]
    fn failure_view_of_a_reset_names_the_reason() -> Result<(), TestError> {
        let v = serde_json::to_value(RateView::from(RateOutcome::Reset(
            ResetReason::IncarnationChanged,
        )))?;
        assert_eq!(
            v,
            serde_json::json!({"state": "reset", "reason": "incarnation_changed"}),
            "{v}"
        );
        Ok(())
    }

    #[test]
    fn failure_view_of_not_captured_is_never_zero() -> Result<(), TestError> {
        let v = serde_json::to_value(RateView::from(RateOutcome::NotCaptured))?;
        assert_eq!(v, serde_json::json!({"state": "not_captured"}), "{v}");
        assert_eq!(
            RateView::NotCaptured.words(),
            "not captured",
            "the text form"
        );
        Ok(())
    }

    #[test]
    fn failure_words_of_each_state_without_a_rate() {
        assert_eq!(
            RateView::NoRateYet.words(),
            "no rate yet: one answer so far",
            "no rate yet"
        );
        assert_eq!(
            RateView::NotReported.words(),
            "not reported by the relay",
            "not reported"
        );
        assert_eq!(
            RateView::NoInterval.words(),
            "no rate: the clock did not advance",
            "no interval"
        );
        assert_eq!(RateView::RtcpNotCounted.words(), "RTCP, not rated", "rtcp");
        assert_eq!(
            RateView::Reset {
                reason: ResetReason::CounterBackwards
            }
            .words(),
            "reset: a counter went backwards",
            "reset"
        );
    }

    // ---- edge ----

    #[test]
    fn edge_exactly_10_gbit_s_is_still_a_rate() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(0, 0, 0)),
            &sample(1000, 1, 1_250_000_000),
            RELAY,
        ))?;
        assert_eq!(r.kbps_tenths(), 100_000_000, "10,000,000.0 kbit/s");
        Ok(())
    }

    #[test]
    fn edge_a_one_nanosecond_gap_is_a_rate_or_out_of_range_never_a_panic() {
        let a = Sample {
            at: Duration::from_nanos(1),
            ..sample(0, 0, 0)
        };
        let b = Sample {
            at: Duration::from_nanos(2),
            ..sample(0, 1, 172)
        };
        assert_eq!(
            rate(Some(&a), &b, RELAY),
            RateOutcome::Reset(ResetReason::OutOfRange),
            "172 B in 1 ns is far above 10 Gbit/s"
        );
    }

    #[test]
    fn edge_counters_near_u64_max_do_not_overflow() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(0, u64::MAX - 100, u64::MAX - 17_200)),
            &sample(2000, u64::MAX, u64::MAX),
            RELAY,
        ))?;
        assert_eq!(r.packets_per_s_tenths(), 500, "u128 arithmetic");
        assert_eq!(r.kbps_tenths(), 688, "u128 arithmetic");
        Ok(())
    }

    #[test]
    fn edge_a_huge_gap_still_divides() -> Result<(), TestError> {
        let r = rated(rate(
            Some(&sample(0, 0, 0)),
            &sample(3_600_000, 180_000, 30_960_000),
            RELAY,
        ))?;
        assert_eq!(r.packets_per_s_tenths(), 500, "an hour at 50 pps");
        Ok(())
    }

    #[test]
    fn edge_rounding_is_half_up() -> Result<(), TestError> {
        // 1 packet over 3 s = 0.333 pps -> 0.3; 2 over 3 s = 0.667 -> 0.7.
        let one = rated(rate(Some(&sample(0, 0, 0)), &sample(3000, 1, 0), RELAY))?;
        let two = rated(rate(Some(&sample(0, 0, 0)), &sample(3000, 2, 0), RELAY))?;
        assert_eq!(one.packets_per_s_tenths(), 3, "0.333 rounds down");
        assert_eq!(two.packets_per_s_tenths(), 7, "0.667 rounds up");
        // 1 packet over 20 s is 0.05 pps: exactly half a tenth rounds up.
        let half = rated(rate(Some(&sample(0, 0, 0)), &sample(20_000, 1, 0), RELAY))?;
        assert_eq!(half.packets_per_s_tenths(), 1, "0.05 rounds up to 0.1");
        Ok(())
    }

    #[test]
    fn edge_the_incarnation_is_checked_before_the_counters() {
        let mut later = sample(1000, 1, 1);
        later.incarnation = Some(SECOND);
        assert_eq!(
            rate(Some(&sample(0, 1000, 172_000)), &later, RELAY),
            RateOutcome::Reset(ResetReason::IncarnationChanged),
            "a new call explains the lower counters"
        );
    }

    #[test]
    fn edge_microseconds_alone_tell_incarnations_apart() {
        let mut later = sample(1000, 50, 8600);
        later.incarnation = Some(Incarnation {
            created_us: FIRST.created_us + 1,
            ..FIRST
        });
        assert_eq!(
            rate(Some(&sample(0, 0, 0)), &later, RELAY),
            RateOutcome::Reset(ResetReason::IncarnationChanged),
            "same second, other microsecond"
        );
    }

    #[test]
    fn edge_memory_forgets_the_least_recently_sampled_socket_at_capacity() {
        let mut m = RateMemory::new(2);
        m.observe(key("a@example.invalid", 1), sample(0, 0, 0), RELAY);
        m.observe(key("b@example.invalid", 2), sample(0, 0, 0), RELAY);
        // Touch a, so b is the least recently sampled.
        m.observe(key("a@example.invalid", 1), sample(1000, 50, 8600), RELAY);
        m.observe(key("c@example.invalid", 3), sample(1000, 0, 0), RELAY);
        assert_eq!(m.len(), 2, "bounded");
        assert!(m.remembers(&key("a@example.invalid", 1)), "a was touched");
        assert!(!m.remembers(&key("b@example.invalid", 2)), "b was oldest");
        assert!(m.remembers(&key("c@example.invalid", 3)), "c is new");
    }

    #[test]
    fn edge_memory_at_the_default_capacity_holds_4096_and_no_more() {
        let mut m = RateMemory::default();
        for n in 0..=4096u16 {
            m.observe(key("a@example.invalid", n), sample(0, 0, 0), RELAY);
        }
        assert_eq!(m.len(), RATE_MEMORY_SOCKETS, "4096 sockets");
        assert!(!m.remembers(&key("a@example.invalid", 0)), "the first went");
        assert_eq!(m.order.len(), m.entries.len(), "the order index agrees");
    }

    #[test]
    fn edge_memory_of_capacity_zero_holds_one() {
        let mut m = RateMemory::new(0);
        m.observe(key("a@example.invalid", 1), sample(0, 0, 0), RELAY);
        let r = m.observe(key("a@example.invalid", 1), sample(1000, 50, 8600), RELAY);
        assert!(matches!(r, RateOutcome::Rate(_)), "capacity 0 is 1: {r:?}");
    }

    #[test]
    fn edge_memory_resampling_a_socket_does_not_grow_the_order_index() {
        let mut m = RateMemory::new(4);
        let k = key("a@example.invalid", 1);
        for n in 0..100u64 {
            m.observe(k.clone(), sample(n * 1000, n * 50, n * 8600), RELAY);
        }
        assert_eq!(m.len(), 1, "one socket");
        assert_eq!(m.order.len(), 1, "one order entry");
    }

    #[test]
    fn edge_monotonic_now_never_goes_backwards() {
        let a = monotonic_now();
        let b = monotonic_now();
        assert!(b >= a, "{b:?} before {a:?}");
    }

    #[test]
    fn edge_view_of_rtcp_and_no_interval_and_not_reported() -> Result<(), TestError> {
        for (o, state) in [
            (RateOutcome::RtcpNotCounted, "rtcp_not_counted"),
            (RateOutcome::NoInterval, "no_interval"),
            (RateOutcome::NotReported, "not_reported"),
        ] {
            let v = serde_json::to_value(RateView::from(o))?;
            assert_eq!(v, serde_json::json!({ "state": state }), "{v}");
        }
        Ok(())
    }

    #[test]
    fn edge_over_ms_rounds_down_to_whole_milliseconds() -> Result<(), TestError> {
        let a = Sample {
            at: Duration::from_micros(0),
            ..sample(0, 0, 0)
        };
        let b = Sample {
            at: Duration::from_micros(1_999_999),
            ..sample(0, 100, 17_200)
        };
        let v = serde_json::to_value(RateView::from(rate(Some(&a), &b, RELAY)))?;
        assert_eq!(v["over_ms"], 1999, "{v}");
        Ok(())
    }
}
