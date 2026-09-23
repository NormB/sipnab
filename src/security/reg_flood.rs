// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registration flood detection.
//!
//! Counts, per source, the REGISTERs that carried credentials and were
//! refused by the registrar, and alerts when those FAILURES cross the
//! configured threshold inside the configured counting window (one second of
//! capture time unless `--reg-flood-window` says otherwise).
//!
//! The evidence is an outcome, never a volume. This detector shipped for a
//! long time firing on the REGISTER count alone, and the peer that produces
//! the most REGISTERs on any network is the operator's own SBC re-registering
//! every phone it fronts after a registrar restart -- every one of them
//! answered `200 OK`, every one of them counted, and `--fail2ban` handed the
//! trunk to the firewall. A count of requests says nothing about whether the
//! registrar accepted them, so it decides nothing here; only a challenge
//! answering a REGISTER that already carried credentials is a failure, and any
//! successful registration clears the count. Section 5 of
//! `docs/design/threat-mitigation-hooks.md`,
//! ["The evidence threshold: act, or tell a human"](https://github.com/NormB/sipnab/blob/main/docs/design/threat-mitigation-hooks.md#5-the-evidence-threshold-act-or-tell-a-human),
//! is the rule this follows.

use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};

use crate::lru::LruMap;
use crate::sip::{SipMessage, SipMethod};

/// Default challenged-failures-per-window threshold.
const DEFAULT_THRESHOLD: u32 = 50;

/// What decides a registration flood: how many challenged failures, inside how
/// wide a window, and how long a REGISTER's transaction stays open to the
/// challenge that makes it one.
///
/// Resolved from `--reg-flood-threshold` / `--reg-flood-window` /
/// `--reg-flood-transaction-timeout` and their `[security]` keys by
/// `Cli::reg_flood_policy`; [`Self::BUILT_IN`] is what a run that sets none of
/// them gets, and is what the detector shipped with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegFloodPolicy {
    /// Challenged failures from one source inside one window, above which the
    /// source is reported.
    pub threshold: u32,
    /// How much capture time one counting window spans, in seconds.
    pub window_secs: u64,
    /// How long a credentialed REGISTER stays open to the challenge that
    /// answers it, in milliseconds: the observer's Timer F. See
    /// [`BUILT_IN_TRANSACTION_TIMEOUT_MS`].
    pub transaction_timeout_ms: u64,
}

/// Widest counting window an operator may declare, in seconds: one hour.
///
/// Past an hour the count is no longer a rate of refusals but a tally of
/// them, and a phone with a stale password re-registering every minute
/// crosses any threshold given enough of the day.
pub const MAX_WINDOW_SECS: u64 = 3_600;

/// Shortest transaction timeout an operator may declare, in milliseconds.
///
/// One second is 64*T1 at a T1 of about 16 ms. Below it the timeout is shorter
/// than an ordinary registrar's answer, so every challenge would arrive after
/// its transaction had "ended" and the detector would count nothing.
pub const MIN_TRANSACTION_TIMEOUT_MS: u64 = 1_000;

/// Longest transaction timeout an operator may declare, in milliseconds: ten
/// minutes.
///
/// That is 64*T1 at a T1 above nine seconds, far past any round trip SIP
/// runs over, and five times the longest `fr_inv_timeout` default the proxies
/// ship. Past it a pending REGISTER is not waiting on an answer.
pub const MAX_TRANSACTION_TIMEOUT_MS: u64 = 600_000;

impl RegFloodPolicy {
    /// The shipped policy: 50 failures inside one second, and a 32-second
    /// transaction timeout.
    pub const BUILT_IN: Self = Self {
        threshold: DEFAULT_THRESHOLD,
        window_secs: 1,
        transaction_timeout_ms: BUILT_IN_TRANSACTION_TIMEOUT_MS,
    };
}

/// Cap on credentialed REGISTER transactions awaiting an answer, per source.
///
/// A source that sends credentials and is never answered accumulates open
/// transactions and no evidence; past this many, the oldest is forgotten. The
/// same figure as the scanner detector's transaction cap, and for the same
/// reason: reaching it degrades toward reporting nothing, which is the right
/// direction for a detector that feeds a firewall.
const MAX_PENDING_PER_SOURCE: usize = 1024;

/// Per-source registration flood tracking state.
struct RegFloodState {
    /// Number of REGISTER requests in the current window.
    ///
    /// Carried into the alert so the operator can see the shape of the
    /// traffic. It never decides anything: see the module doc.
    register_count: u32,
    /// Challenged failures in the current window -- a REGISTER that carried
    /// `Authorization` or `Proxy-Authorization` and was answered 401 or 407 on
    /// the same transaction. This is the count the threshold applies to.
    auth_fail_count: u32,
    /// Start of the current counting window, in capture time.
    window_start: DateTime<Utc>,
    /// Capture time of the newest message from or to this source, which is
    /// what [`RegFloodDetector::sweep`] ages against.
    last_seen: DateTime<Utc>,
    /// Credentialed REGISTER transactions this source has open, keyed by
    /// [`transaction_key`], oldest first, each with the capture time it was
    /// sent. A challenge is a failure only when it names one of these that is
    /// younger than the detector's transaction timeout. Bounded by
    /// [`MAX_PENDING_PER_SOURCE`]; past it the oldest is forgotten, in
    /// constant time.
    pending: LruMap<String, DateTime<Utc>>,
}

impl RegFloodState {
    /// A source first seen at `now`, with nothing counted yet.
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            register_count: 0,
            auth_fail_count: 0,
            window_start: now,
            last_seen: now,
            pending: LruMap::new(MAX_PENDING_PER_SOURCE),
        }
    }

    /// Start a fresh counting window of width `window` at `now` if the current one has
    /// elapsed. Both counts restart; the open transactions do not, because a
    /// REGISTER sent late in one window is answered in the next.
    fn roll_window(&mut self, now: DateTime<Utc>, window: TimeDelta) {
        if window_elapsed(self.window_start, now, window) {
            self.register_count = 0;
            self.auth_fail_count = 0;
            self.window_start = now;
        }
    }
}

/// Why this run cannot establish whether REGISTERs failed on credentials.
///
/// The detector's evidence is the registrar's answer, so a capture that never
/// shows the answer leaves it with nothing to count, and silence would read as
/// "no credential failures". This is what it reports instead. It is advisory:
/// it names no source, files no finding, and never reaches a jail line or a
/// kill, because a REGISTER count with no outcome behind it is a volume, and a
/// volume is exactly the evidence the module doc refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeGap {
    /// REGISTERs were seen and no final response to any of them was: the
    /// capture holds one direction only, or the replies travel a path the
    /// capture does not see. Every REGISTER's outcome is unknown.
    NoAnswers {
        /// REGISTER requests seen.
        registers: u64,
    },
    /// Some credentialed REGISTERs drew no final response before their
    /// transaction ended (the transaction timeout elapsed in capture time,
    /// or the capture ended first), so the detector could not count them as
    /// failures or as successes.
    Unanswered {
        /// Credentialed REGISTERs whose outcome the capture never showed.
        unestablished: u64,
        /// Credentialed REGISTERs seen, retransmissions counted once.
        credentialed: u64,
    },
}

/// Alert produced when a registration flood is detected.
#[derive(Debug, Clone)]
pub struct RegFloodAlert {
    /// Source IP address of the flood.
    pub src_ip: IpAddr,
    /// Number of REGISTER requests in the current window. Context for the
    /// operator; the decision was made on `auth_fail_count`.
    pub register_count: u32,
    /// Challenged failures in the current window: the figure that crossed
    /// `threshold`.
    pub auth_fail_count: u32,
    /// Configured threshold that was exceeded.
    pub threshold: u32,
}

/// Maximum entries in the sources map. Past it, admitting a new source
/// evicts the least recently touched one, in constant time: see [`LruMap`].
const MAX_SOURCE_ENTRIES: usize = 10_000;

/// Whether the `window`-wide counting window that opened at `window_start` has elapsed
/// at `now`, both in capture time.
///
/// Capture time, not the wall clock. A file is read as fast as the disk
/// delivers it, so a window paced by `Instant::now()` never expires offline:
/// a phone re-registering once a minute for an hour became sixty REGISTERs in
/// one wall-clock second, and `--fail2ban` banned it from a replay of
/// yesterday's traffic. The scanner detector moved for the same reason.
fn window_elapsed(window_start: DateTime<Utc>, now: DateTime<Utc>, window: TimeDelta) -> bool {
    now.signed_duration_since(window_start) >= window
}

/// How long a REGISTER's transaction stays open to a challenge, by default:
/// Timer F, in milliseconds.
///
/// [RFC 3261 section 17.1.2.2](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.2.2) ends a non-INVITE client transaction at Timer F,
/// 64*T1, and [section 17.1.1.1](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.1.1) puts T1 at 500 ms by default, so 32 seconds.
/// A 401 that names a REGISTER older than that answers a transaction that has
/// already ended, and counting it would let every unanswered REGISTER wait in
/// the map to be charged by a stray. Not the failure window: a REGISTER sent
/// late in one window is routinely answered in the next.
///
/// Only a default. Section 17.1.1.1 RECOMMENDS a larger T1 on a link known to
/// have a longer round trip, which stretches Timer F with it, and a stateful
/// proxy in the path keeps relaying a late answer until its own final-response
/// timer fires: `fr_timeout` in the OpenSIPS `tm` module (seconds, default
/// 30) and `fr_timer` in the Kamailio `tm` module (milliseconds, default
/// 30000). An operator who raised either sets
/// `[security] reg_flood_transaction_timeout_ms` to match.
pub const BUILT_IN_TRANSACTION_TIMEOUT_MS: u64 = 32_000;

/// The client transaction a REGISTER or its response belongs to.
///
/// [RFC 3261 section 17.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.3) matches a response to its request by the top `Via`
/// branch, and that is the key whenever there is one. An RFC 2543 client puts
/// no branch in its `Via`, and a response copies the request's `Via`, so
/// neither side has one. RFC 2543 identified the transaction by `Call-ID` and
/// `CSeq`, and that is the fallback: the `Call-ID`, the `CSeq` number and its
/// method. A branch is a token and cannot hold a space, so the two forms of
/// key cannot collide.
fn transaction_key(msg: &SipMessage) -> Option<String> {
    if let Some(branch) = msg.top_via_branch() {
        return Some(branch.to_owned());
    }
    let (number, method) = msg.cseq()?;
    Some(format!("call-id {} cseq {number} {method}", msg.call_id()?))
}

/// Whether a REGISTER carried the credentials a challenge asks for.
///
/// A REGISTER without them is the first half of every registration on the
/// network, and the 401 it draws is the registrar asking, not refusing.
fn carries_credentials(msg: &SipMessage) -> bool {
    msg.header("Authorization").is_some() || msg.header("Proxy-Authorization").is_some()
}

/// Whether a final response is a credential challenge.
fn is_challenge(status: u16) -> bool {
    matches!(status, 401 | 407)
}

/// Whether a response completes a registration: a 2xx whose `CSeq` names
/// REGISTER. Read the `CSeq` rather than trust the code alone, because a 2xx
/// to an OPTIONS says nothing about whether the sender may register.
fn completes_registration(msg: &SipMessage) -> bool {
    msg.status_code.is_some_and(|c| (200..300).contains(&c))
        && msg
            .cseq()
            .is_some_and(|(_, method)| method.eq_ignore_ascii_case("REGISTER"))
}

/// The decision, and the only input it takes: challenged failures against the
/// threshold. The REGISTER count is deliberately not a parameter, so it cannot
/// re-enter the verdict without changing this signature.
fn is_flood(auth_fail_count: u32, threshold: u32) -> bool {
    auth_fail_count > threshold
}

/// Detects registration floods by counting, per source, the credentialed
/// REGISTERs the registrar refused.
pub struct RegFloodDetector {
    /// Per-source tracking state, least recently touched first.
    sources: LruMap<IpAddr, RegFloodState>,
    /// Challenged-failures-per-window alert threshold.
    threshold: u32,
    /// Width of one counting window, in capture time.
    window: TimeDelta,
    /// How long a credentialed REGISTER stays open to its challenge.
    transaction_timeout: TimeDelta,
    /// Capture time of the newest message seen, which is the clock `sweep`
    /// reads. `None` before the first message.
    latest_packet: Option<DateTime<Utc>>,
    /// What the capture has shown of REGISTER outcomes, run-wide. Read by
    /// [`Self::outcome_gap`]; never by the flood decision.
    observed: Observed,
}

/// Run-wide accounting of what the capture showed about REGISTER outcomes.
///
/// Counters only, bounded by construction: nothing here is keyed by anything
/// an attacker chooses.
#[derive(Debug, Default)]
struct Observed {
    /// REGISTER requests seen, retransmissions included.
    registers: u64,
    /// Capture time of the first REGISTER, which is when a capture holding no
    /// answers at all first becomes decidable on a live run.
    first_register: Option<DateTime<Utc>>,
    /// Final responses (200-699) whose `CSeq` names REGISTER, sent to a source
    /// this detector tracks.
    register_answers: u64,
    /// Credentialed REGISTER transactions opened, each counted once however
    /// often it was retransmitted.
    credentialed: u64,
    /// Credentialed REGISTER transactions a final response settled inside the
    /// transaction timeout: the ones whose outcome the capture showed.
    settled: u64,
}

impl RegFloodDetector {
    /// Create a new registration flood detector with the given threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` — Challenged failures from one source inside the
    ///   built-in one-second window before alerting. Use `0` for the default
    ///   threshold of 50. [`Self::with_policy`] sets the window and the
    ///   transaction timeout as well.
    pub fn new(threshold: u32) -> Self {
        Self::with_policy(RegFloodPolicy {
            threshold,
            ..RegFloodPolicy::BUILT_IN
        })
    }

    /// Create a detector that applies `policy`: its threshold, its counting
    /// window and its transaction timeout.
    ///
    /// A zero in any field selects the built-in value for that field. The
    /// configuration layer refuses zero before it gets here, so this is only
    /// the last guard against a window that would reset on every packet.
    pub fn with_policy(policy: RegFloodPolicy) -> Self {
        let built_in = RegFloodPolicy::BUILT_IN;
        let pick = |v: u64, d: u64| if v == 0 { d } else { v };
        Self {
            sources: LruMap::new(MAX_SOURCE_ENTRIES),
            threshold: if policy.threshold == 0 {
                DEFAULT_THRESHOLD
            } else {
                policy.threshold
            },
            window: TimeDelta::seconds(
                i64::try_from(pick(policy.window_secs, built_in.window_secs)).unwrap_or(i64::MAX),
            ),
            transaction_timeout: TimeDelta::milliseconds(
                i64::try_from(pick(
                    policy.transaction_timeout_ms,
                    built_in.transaction_timeout_ms,
                ))
                .unwrap_or(i64::MAX),
            ),
            latest_packet: None,
            observed: Observed::default(),
        }
    }

    /// Check a SIP message for registration flood conditions.
    ///
    /// A REGISTER is recorded against its sender and never itself returns an
    /// alert. A 401 or 407 answering a credentialed REGISTER from a source,
    /// on the same transaction, is one failure for that source, and the
    /// failure that crosses the threshold returns the alert. A 2xx to a
    /// REGISTER clears the source's failures.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage) -> Option<RegFloodAlert> {
        // Capture time. Advance the clock before any early return, so `sweep`
        // still ages state out over a stretch of capture that held only
        // messages this detector ignores.
        let now = msg.timestamp;
        if self.latest_packet.is_none_or(|latest| now > latest) {
            self.latest_packet = Some(now);
        }

        if msg.is_request {
            if msg.method.as_ref() == Some(&SipMethod::Register) {
                self.observe_register(msg, now);
            }
            return None;
        }
        self.observe_response(msg, now)
    }

    /// Record a REGISTER against its sender.
    fn observe_register(&mut self, msg: &SipMessage, now: DateTime<Utc>) {
        // The map is capped (H4). Admitting a new source past
        // MAX_SOURCE_ENTRIES evicts the least recently touched one, in
        // constant time, so a spoofed-source flood that fills the map does
        // not make every packet after it pay for a scan of the whole map on
        // the capture thread.
        let state = self
            .sources
            .get_or_insert_with(msg.src_addr, || RegFloodState::new(now));
        state.last_seen = now;
        state.roll_window(now, self.window);
        state.register_count += 1;
        self.observed.registers += 1;
        self.observed.first_register.get_or_insert(now);

        if carries_credentials(msg)
            && let Some(key) = transaction_key(msg)
        {
            // Past MAX_PENDING_PER_SOURCE the oldest open transaction is
            // forgotten, in constant time as well. A key already open is a
            // retransmission of the same transaction, not a new REGISTER.
            if state.pending.insert(key, now).is_none() {
                self.observed.credentialed += 1;
            }
        }
    }

    /// Settle a response against the source it answers.
    ///
    /// The peer is the response's DESTINATION: a response travels back the
    /// way the request came, so `dst_addr` is the source whose REGISTER this
    /// settles.
    ///
    /// Only an existing entry is updated -- a response never creates one. A
    /// response whose REGISTER was never seen anchors nothing, and the cap
    /// on tracked sources is applied where entries are created, so a flood
    /// of 401s toward a /16 of destinations must not be a second way in.
    fn observe_response(&mut self, msg: &SipMessage, now: DateTime<Utc>) -> Option<RegFloodAlert> {
        let status = msg.status_code?;
        let state = self.sources.get_mut(&msg.dst_addr)?;
        state.last_seen = now;
        let timeout = self.transaction_timeout;
        let open_in_time = |sent: DateTime<Utc>| now.signed_duration_since(sent) <= timeout;

        // Every final answer to a REGISTER is an outcome the capture showed,
        // whatever its code: it ends the transaction, and it is what
        // `outcome_gap` needs to have seen.
        let answers_register = status >= 200
            && msg
                .cseq()
                .is_some_and(|(_, method)| method.eq_ignore_ascii_case("REGISTER"));
        if answers_register {
            self.observed.register_answers += 1;
        }

        if completes_registration(msg) {
            state.auth_fail_count = 0;
            if let Some(key) = transaction_key(msg)
                && let Some(sent) = state.pending.remove(&key)
                && open_in_time(sent)
            {
                self.observed.settled += 1;
            }
            return None;
        }
        if !is_challenge(status) {
            // A 403, a 5xx: not a credential challenge, so no failure, but
            // the transaction is over and its outcome was seen.
            if answers_register
                && let Some(key) = transaction_key(msg)
                && let Some(sent) = state.pending.remove(&key)
                && open_in_time(sent)
            {
                self.observed.settled += 1;
            }
            return None;
        }
        // A challenge is evidence only against the credentialed REGISTER it
        // answers. One that names no open transaction from this source is
        // the ordinary first half of a registration, or a retransmission,
        // or an answer to somebody else's request behind the same address.
        // One sent longer ago than Timer F answers a transaction that has
        // already ended.
        let sent = state.pending.remove(&transaction_key(msg)?)?;
        if !open_in_time(sent) {
            return None;
        }
        self.observed.settled += 1;

        state.roll_window(now, self.window);
        state.auth_fail_count += 1;
        is_flood(state.auth_fail_count, self.threshold).then_some(RegFloodAlert {
            src_ip: msg.dst_addr,
            register_count: state.register_count,
            auth_fail_count: state.auth_fail_count,
            threshold: self.threshold,
        })
    }

    /// Whether this run can establish REGISTER outcomes, as of the newest
    /// message seen: `None` when it can, else the [`OutcomeGap`] saying why
    /// not.
    ///
    /// `input_ended` is true once the capture has delivered its last packet.
    /// Before then a REGISTER still inside its transaction timeout may yet be
    /// answered, so it is neither reported nor excused; after it, nothing
    /// more can arrive and every open transaction is unestablished.
    #[must_use]
    pub fn outcome_gap(&mut self, input_ended: bool) -> Option<OutcomeGap> {
        let now = self.latest_packet?;
        let timeout = self.transaction_timeout;
        let observed = &self.observed;

        // Forget the transactions whose timeout has passed: they are decided,
        // unanswered. Each source's open transactions sit oldest first, since
        // a (re)send makes its key the most recent, so only the expired ones
        // are visited. The flood decision loses nothing: a challenge naming
        // one of them is refused as a stray anyway.
        let mut open: u64 = 0;
        for state in self.sources.values_mut() {
            while let Some(sent) = state.pending.iter().next().map(|(_, sent)| *sent) {
                if now.signed_duration_since(sent) <= timeout {
                    break;
                }
                state.pending.pop_lru();
            }
            open += state.pending.len() as u64;
        }
        // Once the capture has ended nothing more can be answered, so what is
        // still open is as unestablished as what expired.
        if input_ended {
            open = 0;
        }

        let no_answers_decidable = input_ended
            || observed
                .first_register
                .is_some_and(|first| now.signed_duration_since(first) > timeout);
        if observed.registers > 0 && observed.register_answers == 0 && no_answers_decidable {
            return Some(OutcomeGap::NoAnswers {
                registers: observed.registers,
            });
        }
        let unestablished = observed
            .credentialed
            .saturating_sub(observed.settled)
            .saturating_sub(open);
        (unestablished > 0).then_some(OutcomeGap::Unanswered {
            unestablished,
            credentialed: observed.credentialed,
        })
    }

    /// [`Self::outcome_gap`], as the statement the alert engine files for the
    /// findings surfaces: a reason code, the counts, and a sentence saying
    /// what is missing and what to change.
    #[must_use]
    pub fn observation_gap(
        &mut self,
        input_ended: bool,
    ) -> Option<crate::security::alerting::ObservationGap> {
        let timeout_ms = self.transaction_timeout.num_milliseconds();
        let gap = self.outcome_gap(input_ended)?;
        let (reason, seen, unestablished, detail) = match gap {
            OutcomeGap::NoAnswers { registers } => (
                "no_answers",
                registers,
                registers,
                format!(
                    "reg_flood cannot establish credential failures: {registers} REGISTER \
                     request(s) seen and no final response to any of them captured, so the \
                     401/407 challenges this detector counts are not in the capture. \
                     Capture both directions of the registrar's traffic. No source is \
                     reported on REGISTER volume alone."
                ),
            ),
            OutcomeGap::Unanswered {
                unestablished,
                credentialed,
            } => (
                "unanswered",
                credentialed,
                unestablished,
                format!(
                    "reg_flood cannot establish the outcome of {unestablished} of \
                     {credentialed} credentialed REGISTER(s): no final response was \
                     captured within the {timeout_ms} ms transaction timeout, so they \
                     count as neither failures nor successes. If the registrar answers \
                     later than that, raise --reg-flood-transaction-timeout; if replies \
                     are missing from the capture, capture both directions."
                ),
            ),
        };
        Some(crate::security::alerting::ObservationGap {
            rule_name: "reg_flood".to_string(),
            reason: reason.to_string(),
            seen,
            unestablished,
            detail,
        })
    }

    /// Remove tracking entries whose last activity is older than `max_age`
    /// **in capture time**, measured from the newest message seen.
    ///
    /// A no-op before the first message: with no capture time there is
    /// nothing to measure against, and nothing tracked to remove.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let Some(now) = self.latest_packet else {
            return;
        };
        let Ok(max_age) = TimeDelta::from_std(max_age) else {
            return;
        };
        self.sources
            .retain(|_, state| now.signed_duration_since(state.last_seen) < max_age);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for per-source registration flood detection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// A fixed capture timestamp for the parsed messages.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// The loopback address used as registrar/destination.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// The source IP used to simulate a flooding attacker.
    fn attacker_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    /// A second, independent source IP.
    fn other_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100))
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// A registrar that is down answers nothing, and nothing is not evidence:
    /// sixty credentialed REGISTERs with no response at all raise no alert.
    #[test]
    fn unanswered_registers_are_not_failures() {
        let mut detector = RegFloodDetector::new(50);
        for i in 0..60 {
            let msg = register_at(attacker_ip(), &format!("z9hG4bK-silent-{i}"), true, ts());
            assert!(
                detector.check(&msg).is_none(),
                "REGISTER {} fired with no answer from the registrar",
                i + 1
            );
        }
    }

    /// Staying under the threshold raises no alert.
    #[test]
    fn below_threshold_no_alert() {
        let mut detector = RegFloodDetector::new(50);
        for i in 0..40 {
            let branch = format!("z9hG4bK-ok-{i}");
            let _ = detector.check(&register_at(attacker_ip(), &branch, true, ts()));
            assert!(
                detector
                    .check(&response_at(401, attacker_ip(), &branch, ts()))
                    .is_none(),
                "should not alert at {} failures (threshold 50)",
                i + 1
            );
        }
    }

    /// Two sources each below the threshold are tracked independently: thirty
    /// failures apiece do not add up to sixty.
    #[test]
    fn different_sources_independent() {
        let mut detector = RegFloodDetector::new(50);
        for i in 0..30 {
            for src in [attacker_ip(), other_ip()] {
                let branch = format!("z9hG4bK-{src}-{i}");
                let _ = detector.check(&register_at(src, &branch, true, ts()));
                assert!(
                    detector
                        .check(&response_at(401, src, &branch, ts()))
                        .is_none(),
                    "failure {} from {src} fired: the two sources are being summed",
                    i + 1
                );
            }
        }
    }

    /// A 401 answering a credentialed REGISTER is one failure for its
    /// sender; the same 401 answering a bare REGISTER is none.
    #[test]
    fn auth_failure_tracking() {
        let mut detector = RegFloodDetector::new(50);

        let _ = detector.check(&register_at(attacker_ip(), "z9hG4bK-cred", true, ts()));
        let _ = detector.check(&response_at(401, attacker_ip(), "z9hG4bK-cred", ts()));
        let state = detector.sources.peek(&attacker_ip()).expect("state exists");
        assert_eq!(
            state.auth_fail_count, 1,
            "should track the challenged failure"
        );

        let _ = detector.check(&register_at(other_ip(), "z9hG4bK-bare", false, ts()));
        let _ = detector.check(&response_at(401, other_ip(), "z9hG4bK-bare", ts()));
        let state = detector.sources.peek(&other_ip()).expect("state exists");
        assert_eq!(
            state.auth_fail_count, 0,
            "a challenge to a REGISTER that carried no credentials is not a failure"
        );
    }

    /// A threshold of 0 selects the built-in default (50/sec).
    #[test]
    fn default_threshold() {
        let detector = RegFloodDetector::new(0);
        assert_eq!(
            detector.threshold, DEFAULT_THRESHOLD,
            "threshold=0 should use default"
        );
    }

    /// The customer's SBC, seen from the registrar it re-registers against.
    fn sbc_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))
    }

    /// A REGISTER from `src` on transaction `branch`, stamped `at`, carrying
    /// an `Authorization` header when `with_credentials` is set.
    ///
    /// The branch is what ties the registrar's answer back to this request:
    /// a REGISTER and the response that settles it share the top `Via`.
    fn register_at(
        src: IpAddr,
        branch: &str,
        with_credentials: bool,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let via = format!("Via: SIP/2.0/UDP 10.0.0.7:5060;branch={branch}");
        let call_id = format!("Call-ID: {branch}@test");
        let mut headers = vec![
            via.as_str(),
            "From: <sip:user@example.com>;tag=r1",
            "To: <sip:user@example.com>",
            call_id.as_str(),
            "CSeq: 1 REGISTER",
        ];
        if with_credentials {
            headers.push(
                "Authorization: Digest username=\"user\", realm=\"example.com\", \
                 nonce=\"abc\", uri=\"sip:example.com\", response=\"0000\"",
            );
        }
        headers.push("Content-Length: 0");
        let raw = build_sip("REGISTER sip:registrar@example.com SIP/2.0", &headers, b"");
        parse_sip(&raw, at, src, localhost(), 5060, 5060, TransportProto::Udp).expect("parse")
    }

    /// The registrar's answer to a REGISTER on transaction `branch`, sent
    /// back to `dst`, stamped `at`.
    fn response_at(code: u16, dst: IpAddr, branch: &str, at: DateTime<Utc>) -> SipMessage {
        let reason = match code {
            200 => "OK",
            401 => "Unauthorized",
            407 => "Proxy Authentication Required",
            _ => "Other",
        };
        let via = format!("Via: SIP/2.0/UDP 10.0.0.7:5060;branch={branch}");
        let call_id = format!("Call-ID: {branch}@test");
        let raw = build_sip(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                via.as_str(),
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>;tag=r2",
                call_id.as_str(),
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, at, localhost(), dst, 5060, 5060, TransportProto::Udp).expect("parse")
    }

    /// The failure this detector shipped with. A registrar restarts, the
    /// customer's SBC re-registers two hundred phones inside one second, and
    /// the registrar accepts every one of them. A count of REGISTERs is a
    /// volume, the peer that produces the most of it is the operator's own
    /// SBC, and `--fail2ban` bans whatever this returns.
    #[test]
    fn a_re_register_storm_answered_200_is_not_a_flood() {
        let mut det = RegFloodDetector::new(50);
        let mut fired = 0usize;
        for i in 0..200 {
            let branch = format!("z9hG4bK-storm-{i}");
            if det
                .check(&register_at(sbc_ip(), &branch, true, ts()))
                .is_some()
            {
                fired += 1;
            }
            if det
                .check(&response_at(200, sbc_ip(), &branch, ts()))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "{fired} alert(s) for 200 registrations the registrar ACCEPTED: the detector \
             is counting REGISTERs rather than failures, and this source is the customer's SBC"
        );
    }

    /// The ordinary shape of every registration: a bare REGISTER, a 401
    /// challenge, the same REGISTER again with credentials, a 200. The
    /// challenge is the first half of a registration that WORKED, and the
    /// storm is a hundred phones doing it at once.
    #[test]
    fn an_ordinary_challenged_registration_is_not_a_failure() {
        let mut det = RegFloodDetector::new(50);
        let mut fired = 0usize;
        for i in 0..100 {
            let first = format!("z9hG4bK-first-{i}");
            let second = format!("z9hG4bK-second-{i}");
            for msg in [
                register_at(sbc_ip(), &first, false, ts()),
                response_at(401, sbc_ip(), &first, ts()),
                register_at(sbc_ip(), &second, true, ts()),
                response_at(200, sbc_ip(), &second, ts()),
            ] {
                if det.check(&msg).is_some() {
                    fired += 1;
                }
            }
        }
        assert_eq!(
            fired, 0,
            "{fired} alert(s) across 100 registrations that each completed: a challenge \
             answered with working credentials is not a failure"
        );
    }

    /// The negative control: a credential-stuffing run is fifty-one
    /// REGISTERs that each carried credentials and were each refused, inside
    /// one second. The threshold is crossed by the 51st FAILURE, never by a
    /// REGISTER on its own.
    #[test]
    fn a_credential_stuffing_run_answered_401_still_fires() {
        let mut det = RegFloodDetector::new(50);
        let mut fired_on_failure = None;
        for i in 0..60 {
            let branch = format!("z9hG4bK-stuff-{i}");
            assert!(
                det.check(&register_at(attacker_ip(), &branch, true, ts()))
                    .is_none(),
                "REGISTER {} raised the alert on its own: a request is a volume, and only \
                 the registrar's answer to it is an outcome",
                i + 1
            );
            let alert = det.check(&response_at(401, attacker_ip(), &branch, ts()));
            if let Some(alert) = alert
                && fired_on_failure.is_none()
            {
                assert_eq!(alert.src_ip, attacker_ip());
                assert_eq!(alert.threshold, 50);
                assert_eq!(alert.auth_fail_count, i + 1);
                fired_on_failure = Some(i + 1);
            }
        }
        assert_eq!(
            fired_on_failure,
            Some(51),
            "51 challenged failures inside one second must fire at threshold 50"
        );
    }

    /// A 407 is the proxy's form of the same refusal.
    #[test]
    fn a_407_to_a_credentialed_register_is_a_failure_too() {
        let mut det = RegFloodDetector::new(2);
        let mut fired = 0usize;
        for i in 0..3 {
            let branch = format!("z9hG4bK-proxy-{i}");
            let _ = det.check(&register_at(attacker_ip(), &branch, true, ts()));
            if det
                .check(&response_at(407, attacker_ip(), &branch, ts()))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 1,
            "the third 407 to a credentialed REGISTER crosses threshold 2"
        );
    }

    /// Sixty challenges to REGISTERs that carried no credentials count for
    /// nothing: every phone in the building is challenged before it
    /// registers, and this is what that looks like from the wire.
    #[test]
    fn a_challenge_to_a_register_without_credentials_is_not_a_failure() {
        let mut det = RegFloodDetector::new(5);
        for i in 0..60 {
            let branch = format!("z9hG4bK-bare-{i}");
            assert!(
                det.check(&register_at(sbc_ip(), &branch, false, ts()))
                    .is_none(),
                "REGISTER {} fired on its own",
                i + 1
            );
            assert!(
                det.check(&response_at(401, sbc_ip(), &branch, ts()))
                    .is_none(),
                "challenge {} to an uncredentialed REGISTER was counted as a failure",
                i + 1
            );
        }
    }

    /// A challenge is a failure only for the transaction it answers. A 401
    /// whose top `Via` names no credentialed REGISTER from this source settles
    /// somebody else's request, or a retransmission, and counts for nothing.
    #[test]
    fn a_challenge_on_another_branch_is_not_this_registers_failure() {
        let mut det = RegFloodDetector::new(1);
        for (reg, resp) in [("a", "x"), ("b", "y"), ("c", "z")] {
            let _ = det.check(&register_at(
                attacker_ip(),
                &format!("z9hG4bK-{reg}"),
                true,
                ts(),
            ));
            assert!(
                det.check(&response_at(
                    401,
                    attacker_ip(),
                    &format!("z9hG4bK-{resp}"),
                    ts()
                ))
                .is_none(),
                "a 401 on branch {resp} was charged to the REGISTER on branch {reg}"
            );
        }
        // Control: the same three, answered on their own branches, fire from
        // the second -- else the assertion above is satisfied by a detector
        // that never counts anything.
        let mut control = RegFloodDetector::new(1);
        let mut fired = 0usize;
        for b in ["p", "q", "r"] {
            let branch = format!("z9hG4bK-{b}");
            let _ = control.check(&register_at(attacker_ip(), &branch, true, ts()));
            if control
                .check(&response_at(401, attacker_ip(), &branch, ts()))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 2,
            "control: matched branches must fire from the 2nd failure"
        );
    }

    /// A REGISTER, or the registrar's answer to one, whose top `Via` carries
    /// no `branch` parameter: what an RFC 2543 client sends.
    ///
    /// `code` of `None` builds the request from `src`, `Some` builds the
    /// response back to it.
    fn branchless(
        code: Option<u16>,
        peer: IpAddr,
        call_id: &str,
        cseq: u32,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let call_id = format!("Call-ID: {call_id}");
        let cseq = format!("CSeq: {cseq} REGISTER");
        let mut headers = vec![
            "Via: SIP/2.0/UDP 10.0.0.7:5060",
            "From: <sip:user@example.com>;tag=r1",
            call_id.as_str(),
            cseq.as_str(),
        ];
        let raw = match code {
            None => {
                headers.push("To: <sip:user@example.com>");
                headers.push(
                    "Authorization: Digest username=\"user\", realm=\"example.com\", \
                     nonce=\"abc\", uri=\"sip:example.com\", response=\"0000\"",
                );
                headers.push("Content-Length: 0");
                build_sip("REGISTER sip:registrar@example.com SIP/2.0", &headers, b"")
            }
            Some(code) => {
                headers.push("To: <sip:user@example.com>;tag=r2");
                headers.push("Content-Length: 0");
                build_sip(&format!("SIP/2.0 {code} Unauthorized"), &headers, b"")
            }
        };
        let (src, dst) = match code {
            None => (peer, localhost()),
            Some(_) => (localhost(), peer),
        };
        parse_sip(&raw, at, src, dst, 5060, 5060, TransportProto::Udp).expect("parse")
    }

    /// A challenge with no `Via` branch still settles the REGISTER it answers.
    ///
    /// [RFC 3261 section 17.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.3) matches a response to its client transaction
    /// by the top `Via` branch and the `CSeq` method, and the branch is only
    /// there when the client put one in. An RFC 2543 client does not, and a
    /// response copies the request's `Via` (section 8.2.6.2), so neither side
    /// has one. RFC 2543 identified the transaction by `Call-ID` and `CSeq`,
    /// and that is the fallback: the same `Call-ID`, `CSeq` number and method.
    /// Branch-only matching let a branchless credential-stuffing run through
    /// without one failure counted.
    #[test]
    fn a_challenge_without_a_via_branch_matches_on_call_id_and_cseq() {
        let mut det = RegFloodDetector::new(1);
        let mut fired = 0usize;
        for n in 1..=3 {
            let reg = branchless(None, attacker_ip(), "old-ua@test", n, ts());
            assert_eq!(reg.top_via_branch(), None, "the fixture carries a branch");
            let _ = det.check(&reg);
            if det
                .check(&branchless(
                    Some(401),
                    attacker_ip(),
                    "old-ua@test",
                    n,
                    ts(),
                ))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 2,
            "three branchless refusals at threshold 1 fire from the second"
        );

        // The fallback is a match, not a wildcard: a challenge naming another
        // CSeq number, or another Call-ID, answers some other request.
        let mut det = RegFloodDetector::new(1);
        for n in 1..=3 {
            let _ = det.check(&branchless(None, attacker_ip(), "other@test", n, ts()));
            assert!(
                det.check(&branchless(
                    Some(401),
                    attacker_ip(),
                    "other@test",
                    n + 10,
                    ts()
                ))
                .is_none(),
                "a 401 for CSeq {} was charged to the REGISTER with CSeq {n}",
                n + 10
            );
            assert!(
                det.check(&branchless(
                    Some(401),
                    attacker_ip(),
                    "nobody@test",
                    n,
                    ts()
                ))
                .is_none(),
                "a 401 on another Call-ID was charged to this REGISTER"
            );
        }
    }

    /// A challenge that arrives after the REGISTER's transaction has timed
    /// out answers nothing that is still open.
    ///
    /// [RFC 3261 section 17.1.2.2](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.2.2) ends a non-INVITE client transaction at
    /// Timer F, 64*T1, which is 32 seconds. A pending REGISTER older than that
    /// is expired: a 401 naming it forty seconds later is a stray, and
    /// charging it would let one stale REGISTER per branch sit in the map for
    /// the life of the source, waiting to be counted.
    #[test]
    fn a_pending_register_older_than_the_window_is_expired() {
        // One fresh failure, then the stale REGISTER's challenge in the same
        // second. At threshold 1, counting the stale one fires.
        let run = |stale_sent: i64| -> bool {
            let mut det = RegFloodDetector::new(1);
            let _ = det.check(&register_at(
                attacker_ip(),
                "z9hG4bK-stale",
                true,
                at(stale_sent),
            ));
            let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-fresh", true, at(40)));
            assert!(
                det.check(&response_at(401, attacker_ip(), "z9hG4bK-fresh", at(40)))
                    .is_none()
            );
            det.check(&response_at(401, attacker_ip(), "z9hG4bK-stale", at(40)))
                .is_some()
        };
        assert!(
            !run(0),
            "a 401 forty seconds after its REGISTER was counted as a failure: that \
             transaction ended at Timer F, 32 seconds"
        );
        assert!(
            run(10),
            "control: thirty seconds is inside Timer F, so the same 401 counts"
        );
    }

    /// Whether a 401 arriving `answered_after` seconds after its credentialed
    /// REGISTER is charged as a failure under `timeout_ms`.
    ///
    /// One fresh failure is filed first at threshold 1, so the late challenge
    /// fires exactly when it is counted.
    fn late_challenge_counts(timeout_ms: u64, answered_after: i64) -> bool {
        let mut det = RegFloodDetector::with_policy(RegFloodPolicy {
            threshold: 1,
            transaction_timeout_ms: timeout_ms,
            ..RegFloodPolicy::BUILT_IN
        });
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-late", true, at(0)));
        let later = at(answered_after);
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-fresh", true, later));
        assert!(
            det.check(&response_at(401, attacker_ip(), "z9hG4bK-fresh", later))
                .is_none(),
            "fixture: one failure is under threshold 1"
        );
        det.check(&response_at(401, attacker_ip(), "z9hG4bK-late", later))
            .is_some()
    }

    /// The transaction timeout is the operator's Timer F, not a constant.
    ///
    /// A network running T1 at one second has a Timer F of 64 seconds
    /// ([RFC 3261 section 17.1.2.2](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.2.2)), so a registrar's 401 forty seconds after the
    /// REGISTER answers a transaction that is still open, and it is a failure.
    /// Under the shipped 32 seconds the same 401 is a stray.
    #[test]
    fn the_transaction_timeout_decides_whether_a_late_challenge_counts() {
        assert!(
            late_challenge_counts(64_000, 40),
            "a 401 forty seconds after its REGISTER was not counted under a 64 s \
             transaction timeout (T1 = 1 s): the configured Timer F is not reaching \
             the detector"
        );
        assert!(
            !late_challenge_counts(32_000, 40),
            "a 401 forty seconds after its REGISTER was counted under a 32 s \
             transaction timeout: that transaction had already ended"
        );
        assert!(
            !late_challenge_counts(RegFloodPolicy::BUILT_IN.transaction_timeout_ms, 40),
            "the built-in transaction timeout must stay at 32 s"
        );
    }

    /// Whether three challenged failures, `spacing_ms` apart, fire under
    /// `threshold` and a `window_secs` counting window.
    fn three_failures_fire(threshold: u32, window_secs: u64, spacing_ms: i64) -> bool {
        let mut det = RegFloodDetector::with_policy(RegFloodPolicy {
            threshold,
            window_secs,
            ..RegFloodPolicy::BUILT_IN
        });
        let mut fired = false;
        for i in 0..3 {
            let when = ts() + chrono::TimeDelta::milliseconds(i * spacing_ms);
            let branch = format!("z9hG4bK-policy-{i}");
            let _ = det.check(&register_at(attacker_ip(), &branch, true, when));
            fired |= det
                .check(&response_at(401, attacker_ip(), &branch, when))
                .is_some();
        }
        fired
    }

    /// The counting window is the operator's, in both directions: three
    /// failures two seconds apart never share the shipped one-second window,
    /// and all share a ten-second one.
    #[test]
    fn the_counting_window_decides_how_concentrated_the_failures_must_be() {
        assert!(
            !three_failures_fire(2, 1, 2_000),
            "three failures two seconds apart fired under a one-second window"
        );
        assert!(
            three_failures_fire(2, 10, 2_000),
            "three failures two seconds apart did not fire under a ten-second window: \
             the configured window is not reaching the detector"
        );
    }

    /// The threshold from the policy decides, in both directions: three
    /// failures inside one second cross 2 and do not cross 3.
    #[test]
    fn the_policy_threshold_decides_how_many_failures_are_a_flood() {
        assert!(three_failures_fire(2, 1, 10), "three failures must cross 2");
        assert!(
            !three_failures_fire(3, 1, 10),
            "three failures crossed threshold 3: the policy threshold is not applied"
        );
    }

    // ── Outcome gaps: when the capture cannot show a failure ─────────────

    /// A capture that holds REGISTERs and no answer to any of them cannot say
    /// whether a single one failed on credentials: the challenges live in the
    /// direction the capture does not hold. Silence here reads as "nobody was
    /// guessing passwords", which the capture never showed.
    #[test]
    fn registers_with_no_answer_cannot_establish_credential_failures() {
        let mut det = RegFloodDetector::new(50);
        for i in 0..10 {
            let branch = format!("z9hG4bK-oneway-{i}");
            let _ = det.check(&register_at(attacker_ip(), &branch, i % 2 == 0, at(i)));
        }
        assert_eq!(
            det.outcome_gap(true),
            Some(OutcomeGap::NoAnswers { registers: 10 }),
            "ten REGISTERs with no response captured must be reported as unestablished"
        );
    }

    /// The control: when the capture shows the challenges and the acceptances,
    /// every outcome is established and nothing is reported.
    #[test]
    fn observed_challenges_leave_nothing_unestablished() {
        let mut det = RegFloodDetector::new(50);
        for i in 0..5 {
            let first = format!("z9hG4bK-bare-{i}");
            let second = format!("z9hG4bK-cred-{i}");
            let refused = format!("z9hG4bK-refused-{i}");
            for msg in [
                register_at(sbc_ip(), &first, false, at(i)),
                response_at(401, sbc_ip(), &first, at(i)),
                register_at(sbc_ip(), &second, true, at(i)),
                response_at(200, sbc_ip(), &second, at(i)),
                register_at(attacker_ip(), &refused, true, at(i)),
                response_at(401, attacker_ip(), &refused, at(i)),
            ] {
                let _ = det.check(&msg);
            }
        }
        assert_eq!(
            det.outcome_gap(true),
            None,
            "every REGISTER here drew an answer, so nothing is unestablished"
        );
    }

    /// Credentialed REGISTERs that drew no answer are counted, once each: a
    /// retransmission is the same transaction, not a second REGISTER.
    #[test]
    fn unanswered_credentialed_registers_are_counted_once_each() {
        let mut det = RegFloodDetector::new(50);
        for i in 0..3 {
            let branch = format!("z9hG4bK-answered-{i}");
            let _ = det.check(&register_at(attacker_ip(), &branch, true, at(i)));
            let _ = det.check(&response_at(401, attacker_ip(), &branch, at(i)));
        }
        for i in 0..2 {
            let branch = format!("z9hG4bK-lost-{i}");
            // Sent, then retransmitted at T1: one transaction.
            let _ = det.check(&register_at(attacker_ip(), &branch, true, at(i)));
            let _ = det.check(&register_at(attacker_ip(), &branch, true, at(i)));
        }
        assert_eq!(
            det.outcome_gap(true),
            Some(OutcomeGap::Unanswered {
                unestablished: 2,
                credentialed: 5
            })
        );
    }

    /// A final response after the transaction timeout answers nothing that was
    /// still open, so that REGISTER's outcome is unestablished too.
    #[test]
    fn an_answer_after_the_transaction_timeout_leaves_the_outcome_unestablished() {
        let mut det = RegFloodDetector::new(50);
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-slow", true, at(0)));
        let _ = det.check(&response_at(401, attacker_ip(), "z9hG4bK-slow", at(40)));
        assert_eq!(
            det.outcome_gap(true),
            Some(OutcomeGap::Unanswered {
                unestablished: 1,
                credentialed: 1
            })
        );
    }

    /// On a live run a REGISTER inside its transaction timeout may still be
    /// answered, so it is not reported yet. Once the capture clock passes the
    /// timeout, it is.
    #[test]
    fn a_live_run_reports_only_what_the_transaction_timeout_has_decided() {
        let mut det = RegFloodDetector::new(50);
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-live", true, at(0)));
        let _ = det.check(&register_at(other_ip(), "z9hG4bK-other", false, at(10)));
        assert_eq!(
            det.outcome_gap(false),
            None,
            "ten seconds in, inside Timer F, the REGISTERs may still be answered"
        );
        let _ = det.check(&register_at(other_ip(), "z9hG4bK-later", false, at(40)));
        assert_eq!(
            det.outcome_gap(false),
            Some(OutcomeGap::NoAnswers { registers: 3 }),
            "forty seconds in, the first REGISTER's Timer F has fired unanswered"
        );

        // With answers flowing, a single credentialed REGISTER left behind is
        // reported once its own timeout passes.
        let mut det = RegFloodDetector::new(50);
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-behind", true, at(0)));
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-ok", true, at(10)));
        let _ = det.check(&response_at(200, attacker_ip(), "z9hG4bK-ok", at(10)));
        assert_eq!(det.outcome_gap(false), None, "inside Timer F");
        let _ = det.check(&register_at(other_ip(), "z9hG4bK-tick", false, at(40)));
        let _ = det.check(&response_at(401, other_ip(), "z9hG4bK-tick", at(40)));
        assert_eq!(
            det.outcome_gap(false),
            Some(OutcomeGap::Unanswered {
                unestablished: 1,
                credentialed: 2
            })
        );
    }

    /// The statement filed for the findings surfaces names the detector, the
    /// reason, both counts and the remedy, and says no source was reported on
    /// volume alone.
    #[test]
    fn the_observation_gap_says_what_is_missing_and_what_to_change() {
        let mut det = RegFloodDetector::new(50);
        for i in 0..4 {
            let _ = det.check(&register_at(
                attacker_ip(),
                &format!("z9hG4bK-o{i}"),
                true,
                at(i),
            ));
        }
        let gap = det.observation_gap(true).expect("no answers captured");
        assert_eq!(
            (
                gap.rule_name.as_str(),
                gap.reason.as_str(),
                gap.seen,
                gap.unestablished
            ),
            ("reg_flood", "no_answers", 4, 4)
        );
        for needle in ["4 REGISTER", "both directions", "volume"] {
            assert!(
                gap.detail.contains(needle),
                "missing {needle:?}: {}",
                gap.detail
            );
        }

        let mut det = RegFloodDetector::with_policy(RegFloodPolicy {
            transaction_timeout_ms: 64_000,
            ..RegFloodPolicy::BUILT_IN
        });
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-a", true, at(0)));
        let _ = det.check(&response_at(401, attacker_ip(), "z9hG4bK-a", at(0)));
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-b", true, at(1)));
        let gap = det.observation_gap(true).expect("one left unanswered");
        assert_eq!(
            (gap.reason.as_str(), gap.seen, gap.unestablished),
            ("unanswered", 2, 1)
        );
        for needle in ["1 of 2", "64000 ms", "--reg-flood-transaction-timeout"] {
            assert!(
                gap.detail.contains(needle),
                "missing {needle:?}: {}",
                gap.detail
            );
        }
    }

    /// A 2xx to a REGISTER is the registrar saying this source belongs here.
    /// It clears the failure count: a phone that mistyped its password twice
    /// and then got in is not halfway to a ban.
    #[test]
    fn a_2xx_to_a_register_clears_the_failure_count() {
        let mut det = RegFloodDetector::new(5);
        let fail = |det: &mut RegFloodDetector, branch: &str| -> bool {
            let _ = det.check(&register_at(attacker_ip(), branch, true, ts()));
            det.check(&response_at(401, attacker_ip(), branch, ts()))
                .is_some()
        };
        // Five failures: at the threshold, not over it.
        for i in 0..5 {
            assert!(!fail(&mut det, &format!("z9hG4bK-before-{i}")));
        }
        // Then the registrar accepts one.
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-ok", true, ts()));
        assert!(
            det.check(&response_at(200, attacker_ip(), "z9hG4bK-ok", ts()))
                .is_none()
        );
        // Five more inside the same second must not cross the threshold,
        // because the count restarted at the 200.
        for i in 0..5 {
            assert!(
                !fail(&mut det, &format!("z9hG4bK-after-{i}")),
                "failure {} after a successful registration fired: the 200 did not clear \
                 the count",
                i + 1
            );
        }
        // Control: the count is live again -- one more crosses it.
        assert!(
            fail(&mut det, "z9hG4bK-after-5"),
            "control: a sixth failure after the clear must fire, else the clear is \
             indistinguishable from never counting"
        );
    }

    /// Capture time `secs` seconds after the fixed base timestamp.
    fn at(secs: i64) -> DateTime<Utc> {
        ts() + chrono::TimeDelta::seconds(secs)
    }

    /// The window counts what the CAPTURE says, not how long sipnab took to
    /// read it.
    ///
    /// `sipnab -I yesterday.pcap --reg-flood --fail2ban -N` reads a file as
    /// fast as the disk delivers it. A phone with a stale password that
    /// re-registers every sixty seconds and is refused every time is sixty
    /// challenged failures across an hour of capture -- and sixty inside one
    /// wall-clock second, which is a ban, when the window is paced by
    /// `Instant::now()`.
    #[test]
    fn window_is_measured_in_packet_time() {
        let mut det = RegFloodDetector::new(50);
        let mut fired = 0usize;
        for i in 0..60 {
            let branch = format!("z9hG4bK-stale-{i}");
            let when = at(i * 60);
            let _ = det.check(&register_at(attacker_ip(), &branch, true, when));
            if det
                .check(&response_at(401, attacker_ip(), &branch, when))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "one refused registration a minute is one failure per window, far under \
             50 -- {fired} alert(s) means the window is paced by how fast the file was \
             read, not by the capture"
        );
    }

    /// A genuine burst inside one packet-time second still fires: the
    /// packet-time window must not become a way to never detect anything.
    #[test]
    fn a_real_burst_inside_one_packet_time_window_still_fires() {
        let mut det = RegFloodDetector::new(50);
        let mut fired_on = None;
        for i in 0..60 {
            let branch = format!("z9hG4bK-burst-{i}");
            // Ten milliseconds apart: sixty land inside 600 ms of capture.
            let when = ts() + chrono::TimeDelta::milliseconds(i * 10);
            let _ = det.check(&register_at(attacker_ip(), &branch, true, when));
            if det
                .check(&response_at(401, attacker_ip(), &branch, when))
                .is_some()
                && fired_on.is_none()
            {
                fired_on = Some(i + 1);
            }
        }
        assert_eq!(
            fired_on,
            Some(51),
            "51 challenged failures inside one packet-time second must fire at 50"
        );
    }

    /// A source that stops sending is aged out on capture time. Two sources:
    /// one last seen at the base timestamp, one five minutes later. A sweep
    /// of two minutes measured from the newest packet keeps only the second.
    #[test]
    fn sweep_ages_entries_out_on_packet_time() {
        let mut det = RegFloodDetector::new(50);
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-old", true, at(0)));
        let _ = det.check(&register_at(other_ip(), "z9hG4bK-new", true, at(300)));
        assert_eq!(det.sources.len(), 2);
        det.sweep(std::time::Duration::from_secs(120));
        assert!(
            !det.sources.contains_key(&attacker_ip()),
            "a source last seen 300 s of capture before the newest packet survived a \
             120 s sweep: the sweep is measuring wall time"
        );
        assert!(
            det.sources.contains_key(&other_ip()),
            "the source seen at the newest packet must survive the sweep"
        );
    }

    /// A response never creates a source entry; it only settles an existing
    /// one.
    ///
    /// The cap on tracked sources was applied on the REGISTER branch alone,
    /// so a 401 flood aimed at a /16 of destinations -- fifty thousand a
    /// second, none of them answering a REGISTER this detector ever saw --
    /// created an entry per destination, millions before the first sweep,
    /// and none of them evidence of anything.
    #[test]
    fn a_response_never_creates_a_source_entry() {
        let mut det = RegFloodDetector::new(50);
        let n = MAX_SOURCE_ENTRIES + 1;
        for i in 0..n {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0a10_0000 + i as u32));
            let branch = format!("z9hG4bK-unseen-{i}");
            for code in [401, 200] {
                assert!(det.check(&response_at(code, dst, &branch, ts())).is_none());
            }
        }
        assert_eq!(
            det.sources.len(),
            0,
            "{} source entries created by responses alone: a response to a REGISTER \
             this detector never saw anchors nothing, and the map grew past its cap of \
             {MAX_SOURCE_ENTRIES} without a REGISTER in sight",
            det.sources.len()
        );
    }

    /// A source address in the 12.0.0.0/8 test range, distinct per `i`.
    fn probe_ip(i: usize) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0c00_0000 + i as u32))
    }

    /// A detector holding exactly `MAX_SOURCE_ENTRIES` sources, none of them
    /// in the probe range.
    fn full_detector() -> RegFloodDetector {
        let mut det = RegFloodDetector::new(50);
        for i in 0..MAX_SOURCE_ENTRIES {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32));
            let _ = det.check(&register_at(src, "z9hG4bK-fill", false, ts()));
        }
        assert_eq!(
            det.sources.len(),
            MAX_SOURCE_ENTRIES,
            "fixture: the map is full"
        );
        det
    }

    /// The failure this shipped with. A spoofed-source flood fills the map,
    /// and from then on every REGISTER from a new address pays for a scan of
    /// all ten thousand entries to choose a victim -- on the capture thread,
    /// inside `process_parsed_packet`, under both store write locks, while
    /// every MCP and API reader waits and the kernel's drop counter climbs.
    ///
    /// Measured as a ratio rather than a bound: the same thousand messages,
    /// parsed up front so only `check` is timed, into a fresh detector and
    /// into a full one, the minimum of three rounds each so a descheduled
    /// thread cannot inflate either side. Constant-time eviction makes the
    /// two costs alike (measured at 1.3x); the shipped scan made the full one
    /// 371x dearer.
    #[test]
    fn admitting_a_source_at_cap_costs_no_more_than_admitting_one_to_an_empty_map() {
        use std::time::{Duration, Instant};
        let probe: Vec<SipMessage> = (0..1_000)
            .map(|i| register_at(probe_ip(i), &format!("z9hG4bK-probe-{i}"), false, ts()))
            .collect();
        let time_probe = |det: &mut RegFloodDetector| {
            let started = Instant::now();
            for msg in &probe {
                let _ = det.check(msg);
            }
            started.elapsed()
        };

        let mut empty_cost = Duration::MAX;
        let mut full_cost = Duration::MAX;
        for _ in 0..3 {
            let mut fresh = RegFloodDetector::new(50);
            empty_cost = empty_cost.min(time_probe(&mut fresh));
            let mut full = full_detector();
            full_cost = full_cost.min(time_probe(&mut full));
            assert_eq!(
                full.sources.len(),
                MAX_SOURCE_ENTRIES,
                "control: the cap must still hold after a thousand new sources"
            );
        }
        let ratio = full_cost.as_nanos() as f64 / empty_cost.as_nanos().max(1) as f64;
        assert!(
            ratio < 5.0,
            "admitting a source to a full map cost {ratio:.1}x what admitting one to \
             an empty map cost ({full_cost:?} against {empty_cost:?} for 1,000 \
             REGISTERs): eviction is scanning the map"
        );
    }

    /// At the cap the source evicted is the one touched least recently, not
    /// the one inserted first: a REGISTER or a response to a source refreshes
    /// it. The oldest-inserted source is touched again before the map fills,
    /// and it is the second-inserted, untouched since, that goes.
    #[test]
    fn at_cap_the_least_recently_touched_source_is_evicted() {
        let mut det = RegFloodDetector::new(50);
        let first = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        let second = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
        let _ = det.check(&register_at(first, "z9hG4bK-first", true, ts()));
        let _ = det.check(&register_at(second, "z9hG4bK-second", true, ts()));
        for i in 2..MAX_SOURCE_ENTRIES {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a02_0000 + i as u32));
            let _ = det.check(&register_at(src, "z9hG4bK-fill", false, ts()));
        }
        assert_eq!(det.sources.len(), MAX_SOURCE_ENTRIES, "fixture: at the cap");
        // Touch `first` with a response, which is the other path that
        // refreshes a source.
        let _ = det.check(&response_at(401, first, "z9hG4bK-first", ts()));

        let _ = det.check(&register_at(probe_ip(0), "z9hG4bK-new", false, ts()));

        assert_eq!(det.sources.len(), MAX_SOURCE_ENTRIES, "the cap holds");
        assert!(
            !det.sources.contains_key(&second),
            "the least recently touched source must be the one evicted"
        );
        assert!(
            det.sources.contains_key(&first),
            "a source touched after the map filled survived the flood: it was \
             evicted as the oldest INSERTED rather than the least recently USED"
        );
        assert!(
            det.sources.contains_key(&probe_ip(0)),
            "the new source is admitted"
        );
    }

    /// The emitted alert carries the failure count that crossed the
    /// threshold, the REGISTER count for context, the threshold, and the
    /// source.
    #[test]
    fn alert_includes_counts() {
        let mut detector = RegFloodDetector::new(5);

        let mut alert = None;
        for i in 0..6 {
            let branch = format!("z9hG4bK-count-{i}");
            let _ = detector.check(&register_at(attacker_ip(), &branch, true, ts()));
            if let Some(a) = detector.check(&response_at(401, attacker_ip(), &branch, ts())) {
                alert = Some(a);
            }
        }

        let alert = alert.expect("should have triggered");
        assert_eq!(alert.auth_fail_count, 6);
        assert_eq!(alert.register_count, 6);
        assert_eq!(alert.threshold, 5);
        assert_eq!(alert.src_ip, attacker_ip());
    }
}
