// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP scanner and reconnaissance tool detection.
//!
//! Detects SIP scanning activity through two methods:
//! - **User-Agent pattern matching** against known scanner signatures
//!   (friendly-scanner, sipvicious, etc.) and user-defined patterns.
//! - **Behavioral analysis** detecting high-rate REGISTER/OPTIONS/INVITE
//!   probing from a single source, and **extension enumeration** — many
//!   *distinct* target users from one source — which catches a UA-randomized,
//!   INVITE-based, or low-and-slow sweep that signature detection alone would
//!   miss.
//!
//! # What separates a probe from a request
//!
//! Neither behavioural signal is a rate on its own, because rate does not
//! separate reconnaissance from operation. A SIP trunk sends OPTIONS
//! continuously by design — that is how each end learns the other is alive —
//! and an SBC fronting a hunt group reaches dozens of distinct extensions a
//! second. Measured on volume alone, an ordinary eleven-second carrier trunk
//! produced 2719 detections across 14 peers, every one of them the carrier's
//! own PBX or a customer's desk phone, and `--kill-scanner` behind a fail2ban
//! jail bans all of them.
//!
//! What separates the two is the OUTCOME, which the capture already holds:
//!
//! - A keepalive is **answered**. An enumeration sweep is answered with `404`,
//!   `403` — or with nothing at all.
//! - A peer that has completed a registration or a call with us has proved a
//!   relationship no scanner has, and needs four times the evidence before
//!   either signal applies to it.
//!
//! So both behavioural signals are gated on the same probing test: the rate
//! and the spread decide *how much* is happening, and the outcomes decide
//! *whether any of it is reconnaissance*. Raising the thresholds instead would
//! have traded these false positives for false negatives on the same axis, and
//! a scanner that paced itself would walk through untouched.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};
use regex::{Regex, RegexBuilder};

use crate::sip::SipMessage;

/// Known SIP scanner User-Agent patterns (case-insensitive).
const KNOWN_SCANNER_PATTERNS: &[&str] = &[
    "friendly-scanner",
    "sipvicious",
    "sipcli",
    "sipsak",
    "sundayddr",
    "VaxSIPUserAgent",
    "sip-scan",
];

/// Number of probe transactions from the same source within the behavioral
/// window that, **together with** [`BehavioralState::is_probing`], triggers a
/// behavioral detection alert.
const BEHAVIORAL_THRESHOLD: u32 = 10;

/// Number of DISTINCT target extensions probed by one source within the window
/// that, **together with** [`BehavioralState::is_probing`], triggers an
/// enumeration alert. Lower than the rate threshold because hitting many
/// *different* users is a far more specific recon signal than volume alone
/// (svwar's signature) — and it catches a UA-randomized, INVITE-based, or
/// low-and-slow sweep that the rate counter misses.
const ENUMERATION_THRESHOLD: usize = 5;

/// Probe transactions in one window that were rejected, at which a source
/// reads as probing rather than operating.
///
/// Five in [`BEHAVIORAL_WINDOW_SECS`] seconds is one refusal a second. A
/// working peer earns the odd `404` from a wrong number, but not at that rate
/// and not sustained: on an eleven-second carrier trunk carrying 5504
/// requests, the busiest peer's worst window held a single rejected probe.
const REJECTED_PROBE_MIN: u32 = 5;

/// Probe transactions in one window that drew no response of any kind, at
/// which a source reads as sweeping — provided they are also the MAJORITY of
/// what it sent.
///
/// The majority test is what makes this safe on a busy peer: a trunk running
/// hundreds of keepalives a second always has a few transactions outstanding
/// at the edge of the window, and an absolute count alone would eventually
/// catch every one of them.
const UNANSWERED_PROBE_MIN: u32 = 5;

/// How long a probe must go without any response before it counts as
/// unanswered, in milliseconds.
///
/// RFC 3261's T1, the round-trip estimate at which SIP itself gives up waiting
/// and retransmits. Without it "unanswered" meant "not answered YET", which is
/// a fact about the order of the capture rather than about the peer: a source
/// that pipelines faster than the round trip has every request outstanding at
/// the moment the next one arrives, so a client bursting registrations for
/// fifty extensions at boot looked exactly like a sweep into a hole. Whether
/// it tripped came down to link latency and how deeply the peer pipelined —
/// the same kind of accident as measuring the window on the wall clock.
const PROBE_ANSWER_GRACE_MS: u64 = 500;

/// How much more evidence a source needs once it has completed a registration
/// or a call with us.
///
/// A registered endpoint that starts probing is a compromised phone and is
/// worth reporting — but it is also the peer whose ordinary working traffic
/// looks most like probing, and it is the peer a false positive costs most.
const ESTABLISHED_EVIDENCE_FACTOR: u32 = 4;

/// Final-response codes that answer a request without saying anything about
/// whether its sender belongs here.
///
/// `401` and `407` open every registration and most calls, so counting a
/// challenge as a refusal would make every phone in the building a scanner.
/// The rest are the ordinary outcomes of a call that rang out, was cancelled,
/// went to a busy or unavailable extension, or could not agree a codec —
/// `600` and `603` are the same answers given globally. A `5xx` blames the
/// server rather than the sender, so that whole class is excluded too, in
/// [`is_rejection`].
const BENIGN_RESPONSE_CODES: &[u16] = &[401, 407, 408, 480, 486, 487, 488, 491, 600, 603];

/// Whether a final response tells its recipient that what it asked for does
/// not exist or is not allowed.
fn is_rejection(status: u16) -> bool {
    (400..700).contains(&status)
        && !(500..600).contains(&status)
        && !BENIGN_RESPONSE_CODES.contains(&status)
}

/// Cap on tracked distinct targets per source (bounds memory under a flood that
/// also randomizes the target user-part).
const MAX_TARGETS_PER_SOURCE: usize = 1024;

/// Cap on tracked probe transactions per source. Past it the window keeps
/// counting probes but stops keying them, which costs correlation and never
/// costs the count — see [`BehavioralState::unkeyed_probes`].
///
/// Reaching it degrades toward reporting nothing, which is the right
/// direction: a source only gets this far without alerting if its probes are
/// being answered, because a refused or ignored one fires at
/// [`BEHAVIORAL_THRESHOLD`] — two orders of magnitude below the cap.
const MAX_TRANSACTIONS_PER_SOURCE: usize = 1024;

/// Behavioral detection window in seconds.
const BEHAVIORAL_WINDOW_SECS: u64 = 5;

/// The trigger points of the scanner detector's behavioural signals.
///
/// Every field was a private constant with a comment describing when to change
/// it and no way to. They are not universal numbers, and the two deployments
/// they are wrong for pull in opposite directions:
///
/// - Behind an SBC every source collapses to one address, so ordinary
///   aggregated traffic clears ten probes in five seconds and the whole site
///   reads as one scanner. That site needs the COUNTS raised.
/// - A sweep paced at one probe every ten seconds never puts two probes in the
///   same five-second window, so nothing accumulates and no count setting can
///   see it. That site needs the WINDOW widened; the counts are not the binding
///   constraint and tuning them alone leaves the sweep invisible.
///
/// [`Self::window_secs`] is therefore part of this set, unlike the fraud
/// windows in [`crate::security::fraud_detect::FraudThresholds`], which are
/// excluded because the volume window and the baseline decay are one
/// calibration. Nothing here is paired with a decay: the window is simply how
/// long the detector remembers, and how long it remembers is exactly what the
/// low-and-slow case gets wrong.
///
/// The memory caps (`MAX_BEHAVIORAL_ENTRIES`, `MAX_TARGETS_PER_SOURCE`,
/// `MAX_TRANSACTIONS_PER_SOURCE`) are deliberately NOT here: they bound
/// sipnab's own footprint, not the network's behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerThresholds {
    /// Probe transactions from one source in the window, above which the rate
    /// signal reports — see the `BEHAVIORAL_THRESHOLD` constant.
    pub behavioral_probes: u32,
    /// Distinct target extensions from one source in the window, above which
    /// the enumeration signal reports — see the `ENUMERATION_THRESHOLD` constant.
    pub enumeration_targets: usize,
    /// Rejected probes in the window at which a source reads as probing rather
    /// than operating — see the `REJECTED_PROBE_MIN` constant.
    pub rejected_probes: u32,
    /// Unanswered probes in the window at which a source reads as sweeping,
    /// provided they are also the majority of what it sent — see
    /// the `UNANSWERED_PROBE_MIN` constant.
    pub unanswered_probes: u32,
    /// How much capture time one behavioural window spans, in seconds.
    ///
    /// The binding constraint on a paced sweep: a source that probes more
    /// slowly than this never has two probes in one window, so its rate and
    /// its spread both stay at one however low the counts are set.
    pub window_secs: u64,
    /// How much more evidence a source needs once it has completed a
    /// registration or a call with us — see the `ESTABLISHED_EVIDENCE_FACTOR` constant.
    pub established_factor: u32,
    /// How long a probe must go without any response before it counts as
    /// unanswered, in milliseconds — see the `PROBE_ANSWER_GRACE_MS` constant.
    pub answer_grace_ms: u64,
}

impl ScannerThresholds {
    /// The shipped trigger points, used when the operator declares nothing.
    ///
    /// Each field reads the constant that documents WHY that number, rather
    /// than restating the literal: a default and its justification that can
    /// drift apart is a default nobody can check.
    pub const BUILT_IN: Self = Self {
        behavioral_probes: BEHAVIORAL_THRESHOLD,
        enumeration_targets: ENUMERATION_THRESHOLD,
        rejected_probes: REJECTED_PROBE_MIN,
        unanswered_probes: UNANSWERED_PROBE_MIN,
        window_secs: BEHAVIORAL_WINDOW_SECS,
        established_factor: ESTABLISHED_EVIDENCE_FACTOR,
        answer_grace_ms: PROBE_ANSWER_GRACE_MS,
    };
}

impl Default for ScannerThresholds {
    fn default() -> Self {
        Self::BUILT_IN
    }
}

/// What became of one probe transaction inside the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Nothing has come back yet, not even a provisional.
    Pending,
    /// A response came back that carries no reconnaissance signal — a
    /// provisional, a success, a redirect, or one of
    /// [`BENIGN_RESPONSE_CODES`].
    Answered,
    /// A final response told the sender no. See [`is_rejection`].
    Rejected,
}

/// Tracks per-source behavioral state for probe detection.
///
/// Both timestamps are CAPTURE time — the timestamp the packet carries — not
/// wall time. See [`ScannerDetector::latest_packet`] for why.
struct BehavioralState {
    /// Probe transactions this source opened in the current window, keyed by
    /// the top `Via` branch — RFC 3261's transaction identifier, which a
    /// response echoes back.
    ///
    /// Keyed rather than counted so that a RETRANSMISSION is one probe. UDP
    /// resends an unanswered INVITE at 500ms, 1s, 2s and 4s, so two calls into
    /// a peer that is slow to answer reach a rate threshold of ten on their
    /// own — and every one of those copies would also have counted as a
    /// separate unanswered probe, which is the evidence the rate test now
    /// rests on.
    ///
    /// The value carries when the probe opened, so a transaction still inside
    /// [`PROBE_ANSWER_GRACE_MS`] counts as awaiting an answer rather than as
    /// having gone without one.
    transactions: HashMap<String, (DateTime<Utc>, Outcome)>,
    /// Probes this window whose top `Via` carried no branch, or that arrived
    /// once [`MAX_TRANSACTIONS_PER_SOURCE`] was reached.
    ///
    /// They count toward the rate and never toward the evidence: a probe that
    /// cannot be tied to a response cannot be SHOWN unanswered, and inferring
    /// it would hand a source that strips its own `Via` branch a way to look
    /// like a sweep.
    unkeyed_probes: u32,
    /// Distinct target extensions (To/R-URI user-part) seen this window.
    targets: HashSet<String>,
    /// Whether this source has ever completed a registration or a call with
    /// us: a `2xx` to a REGISTER or an INVITE it sent.
    ///
    /// Sticky across window resets — the point of it is that the relationship
    /// outlives any five seconds. A `2xx` to an OPTIONS deliberately does not
    /// count: answering a keepalive is something we do for anyone who asks,
    /// so trusting it would let a scanner earn the exemption with one packet.
    established: bool,
    /// Start of the current behavioral window, in capture time.
    first_seen: DateTime<Utc>,
    /// Most recent activity from this source, in capture time (used for
    /// sweeping).
    last_seen: DateTime<Utc>,
    /// Monotonic counter of when this source was last touched, used to pick
    /// the eviction victim.
    ///
    /// Not a timestamp, because capture timestamps TIE: two packets can share
    /// a microsecond, and a replay of one crafted message repeated is entirely
    /// legitimate input. Under a tie `min_by_key` returns whichever entry the
    /// hash order happened to visit first, so which source the memory cap
    /// evicted became unpredictable — and the source being evicted is the one
    /// whose detection state is discarded.
    last_used: u64,
}

impl BehavioralState {
    /// An empty window opened at `now`, stamped with the use counter.
    fn new(now: DateTime<Utc>, last_used: u64) -> Self {
        Self {
            transactions: HashMap::new(),
            unkeyed_probes: 0,
            targets: HashSet::new(),
            established: false,
            first_seen: now,
            last_seen: now,
            last_used,
        }
    }

    /// Start a fresh window at `now`, keeping what outlives it.
    ///
    /// [`Self::established`] survives: it is a fact about the relationship,
    /// not about the last five seconds.
    fn reset_window(&mut self, now: DateTime<Utc>) {
        self.transactions.clear();
        self.unkeyed_probes = 0;
        self.targets.clear();
        self.first_seen = now;
    }

    /// Probes this source sent in the window: one per transaction, plus the
    /// ones that could not be keyed.
    fn probe_count(&self) -> u32 {
        (self.transactions.len() as u32).saturating_add(self.unkeyed_probes)
    }

    /// Probe transactions in the window that were rejected.
    fn rejected_count(&self) -> u32 {
        self.transactions
            .values()
            .filter(|(_, outcome)| *outcome == Outcome::Rejected)
            .count() as u32
    }

    /// Probes in the window that have now gone without any response for
    /// longer than [`PROBE_ANSWER_GRACE_MS`].
    ///
    /// Probes still inside the grace are excluded rather than counted, so a
    /// peer that pipelines faster than the round trip is not mistaken for one
    /// nothing is answering.
    fn unanswered_count(&self, now: DateTime<Utc>, answer_grace_ms: u64) -> u32 {
        let grace = TimeDelta::milliseconds(answer_grace_ms as i64);
        self.transactions
            .values()
            .filter(|(opened, outcome)| {
                *outcome == Outcome::Pending && now.signed_duration_since(*opened) >= grace
            })
            .count() as u32
    }

    /// How much evidence this source needs before its rate or its spread reads
    /// as reconnaissance.
    fn evidence_factor(&self, established_factor: u32) -> u32 {
        if self.established {
            established_factor
        } else {
            1
        }
    }

    /// Whether this source is probing rather than operating.
    ///
    /// True when we are telling it no, or when its probes are going into a
    /// hole — the two things that separate an enumeration sweep from a trunk
    /// running keepalives at exactly the same rate.
    ///
    /// `responses_seen` is whether the detector has seen ANY SIP response at
    /// all. The unanswered test is a claim about the other direction, and in a
    /// capture that holds one direction only — a `sip.request` filter, a tap
    /// on one leg — every probe ever sent looks unanswered and the peer
    /// reported would be whichever was busiest. That is precisely the failure
    /// this signature replaced, so the test stands down until the other
    /// direction is known to be present.
    fn is_probing(
        &self,
        now: DateTime<Utc>,
        responses_seen: bool,
        thresholds: &ScannerThresholds,
    ) -> bool {
        let factor = self.evidence_factor(thresholds.established_factor);
        if self.rejected_count() >= thresholds.rejected_probes.saturating_mul(factor) {
            return true;
        }
        let unanswered = self.unanswered_count(now, thresholds.answer_grace_ms);
        responses_seen
            && unanswered >= thresholds.unanswered_probes.saturating_mul(factor)
            && unanswered.saturating_mul(2) > self.probe_count()
    }
}

/// Alert produced when scanner activity is detected.
#[derive(Debug, Clone)]
pub struct ScannerAlert {
    /// Source IP address of the scanner.
    pub src_ip: IpAddr,
    /// `User-Agent` from the triggering message, or `None` when it carried
    /// none.
    ///
    /// `Option`, not an empty string: a request with no `User-Agent` is itself
    /// a scanner signal, and collapsing it into `""` made it indistinguishable
    /// from a header present but empty — which an attacker can send.
    pub ua: Option<String>,
    /// SIP method of the triggering message, or `None` when the request line
    /// carried none.
    ///
    /// `Option` for the same reason as [`ua`](Self::ua): the placeholder it
    /// replaced, `"UNKNOWN"`, is a value `SipMethod::Custom` can legitimately
    /// hold, so absence and a peculiar method read identically.
    pub method: Option<String>,
    /// How the scanner was detected: `"ua_pattern"`, `"behavioral"` (rate), or
    /// `"enumeration"` (many distinct targets from one source).
    pub detection_method: String,
}

/// Maximum compiled-program size, in bytes, for a user-supplied pattern.
///
/// Not a ReDoS guard: the `regex` crate matches in linear time and does not
/// backtrack, so there is no catastrophic backtracking here to prevent. What
/// this caps is the memory and compile-time cost of a pathological pattern
/// (a large bounded repetition such as `a{1000}{1000}`), so an untrusted
/// pattern cannot blow up compilation.
const REGEX_SIZE_LIMIT: usize = 1_000_000;

/// Maximum entries in the behavioral tracking map.
const MAX_BEHAVIORAL_ENTRIES: usize = 10_000;

/// Detects SIP scanners via UA signature matching and behavioral heuristics.
pub struct ScannerDetector {
    /// Compiled regex patterns for known scanner User-Agents.
    known_patterns: Vec<Regex>,
    /// Per-source behavioral tracking state.
    behavioral: HashMap<IpAddr, BehavioralState>,
    /// Capture time of the most recent message checked — the detector's
    /// "now". `None` before the first message.
    ///
    /// The rate and enumeration windows used to be paced by
    /// `std::time::Instant`, which is the clock of the machine doing the
    /// reading rather than of the traffic being read. Live those agree, since
    /// a packet is timestamped as it arrives. Offline they do not: a file is
    /// replayed as fast as the disk allows, so several minutes of a busy trunk
    /// land inside one wall-clock second, the
    /// [`BEHAVIORAL_WINDOW_SECS`]-second window never expires, and the
    /// per-source counters accumulate over the WHOLE capture. Every peer that
    /// sent more than [`BEHAVIORAL_THRESHOLD`] requests or reached more than
    /// [`ENUMERATION_THRESHOLD`] extensions — an ordinary carrier SBC does
    /// both in a minute — was then reported as a scanner, and with
    /// `--kill-scanner` that decides whether sipnab answers it. It also made
    /// the verdict a function of machine speed: the same bytes on a slower box
    /// gave a different answer.
    ///
    /// This is the same defect [`crate::app::batch::SweepClock`] fixed for the
    /// dialog and stream sweeps, applied where the clock is already to hand:
    /// every message carries its own capture timestamp, so the detector reads
    /// its "now" off the traffic and needs nothing threaded in from the caller.
    ///
    /// Never moves backwards. Captures do contain out-of-order timestamps, and
    /// one reordered packet must not rewind the sweep horizon.
    latest_packet: Option<DateTime<Utc>>,
    /// Whether any SIP response has been checked yet.
    ///
    /// Gates the unanswered half of [`BehavioralState::is_probing`]; see there
    /// for why a capture of requests alone must not be read as a capture of
    /// probes nobody answered.
    responses_seen: bool,
    /// Ticks once per tracked source touched; the value stamped into
    /// [`BehavioralState::last_used`] to order eviction.
    use_counter: u64,
    /// The trigger points this detector applies.
    thresholds: ScannerThresholds,
}

impl ScannerDetector {
    /// Create a new scanner detector with the shipped trigger points.
    ///
    /// # Arguments
    ///
    /// * `custom_patterns` — Additional User-Agent regex patterns to match
    ///   (e.g., from `--kill-ua`). Invalid or oversized patterns are silently skipped.
    pub fn new(custom_patterns: &[String]) -> Self {
        Self::with_thresholds(custom_patterns, ScannerThresholds::BUILT_IN)
    }

    /// Create a scanner detector with explicit trigger points.
    ///
    /// # Arguments
    ///
    /// * `custom_patterns` — as [`Self::new`].
    /// * `thresholds` — see [`ScannerThresholds`];
    ///   `ScannerThresholds::BUILT_IN` reproduces [`Self::new`].
    pub fn with_thresholds(custom_patterns: &[String], thresholds: ScannerThresholds) -> Self {
        let mut patterns = Vec::with_capacity(KNOWN_SCANNER_PATTERNS.len() + custom_patterns.len());

        // Compile built-in patterns (case-insensitive, size-limited)
        for pat in KNOWN_SCANNER_PATTERNS {
            if let Ok(re) = RegexBuilder::new(&format!("(?i){pat}"))
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                patterns.push(re);
            }
        }

        // Compile user-supplied patterns (size-limited to cap compile cost)
        for pat in custom_patterns {
            match RegexBuilder::new(&format!("(?i){pat}"))
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(re) => patterns.push(re),
                Err(e) => {
                    tracing::warn!("Skipping invalid or oversized --kill-ua pattern '{pat}': {e}");
                }
            }
        }

        Self {
            known_patterns: patterns,
            behavioral: HashMap::new(),
            latest_packet: None,
            responses_seen: false,
            use_counter: 0,
            thresholds,
        }
    }

    /// Check a SIP message for scanner activity.
    ///
    /// Returns a `ScannerAlert` if the message matches a known scanner
    /// pattern or if the source IP's behavioral profile exceeds the
    /// probing threshold.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage) -> Option<ScannerAlert> {
        // Advance the capture clock before any early return, so `sweep` still
        // ages state out over a stretch of capture that held only responses.
        if self
            .latest_packet
            .is_none_or(|latest| msg.timestamp > latest)
        {
            self.latest_packet = Some(msg.timestamp);
        }

        // `None` when the request line carried no recognisable method. It used
        // to substitute the literal "UNKNOWN", which is a value a `Custom`
        // method can also hold — the same collision the `ua` field had.
        let method = if msg.is_request {
            msg.method.as_ref().map(|m| m.as_str())
        } else {
            // A response is never itself an alert — it is the OUTCOME of an
            // earlier probe, and the outcomes are what the behavioural
            // signals now rest on.
            self.observe_response(msg);
            return None;
        };

        let ua = msg.user_agent().map(str::to_string);

        // Check UA pattern match. An absent header matches nothing — the
        // patterns describe what a scanner *says*, and a request that says
        // nothing is caught by the behavioural analysis below instead.
        if let Some(ref ua) = ua
            && !ua.is_empty()
        {
            for pattern in &self.known_patterns {
                if pattern.is_match(ua) {
                    return Some(ScannerAlert {
                        src_ip: msg.src_addr,
                        ua: Some(ua.clone()),
                        method: method.map(str::to_string),
                        detection_method: "ua_pattern".to_string(),
                    });
                }
            }
        }

        // Behavioral analysis: track REGISTER/OPTIONS/INVITE rates
        if matches!(method, Some("REGISTER" | "OPTIONS" | "INVITE")) {
            let now = msg.timestamp;
            let thresholds = self.thresholds;

            // Cap the behavioral map to prevent memory exhaustion (H4)
            if self.behavioral.len() >= MAX_BEHAVIORAL_ENTRIES
                && !self.behavioral.contains_key(&msg.src_addr)
            {
                // Evict the least recently used entry.
                if let Some(oldest_ip) = self
                    .behavioral
                    .iter()
                    .min_by_key(|(_, s)| s.last_used)
                    .map(|(&ip, _)| ip)
                {
                    self.behavioral.remove(&oldest_ip);
                }
            }

            self.use_counter += 1;
            let use_counter = self.use_counter;
            let responses_seen = self.responses_seen;
            let state = self
                .behavioral
                .entry(msg.src_addr)
                .or_insert_with(|| BehavioralState::new(now, use_counter));
            state.last_used = use_counter;

            // Reset window if expired. `signed_duration_since` rather than a
            // subtraction that could go negative: an out-of-order packet
            // yields a negative delta, which must not be read as an expired
            // window (nor panic on an `unsigned_abs` that would read a packet
            // from the past as one far in the future).
            if now.signed_duration_since(state.first_seen)
                > TimeDelta::seconds(thresholds.window_secs as i64)
            {
                state.reset_window(now);
            }

            // Open the transaction this probe belongs to. A branch already
            // present is a retransmission and must not count twice.
            match msg.top_via_branch() {
                Some(branch) if state.transactions.contains_key(branch) => {}
                Some(branch) if state.transactions.len() < MAX_TRANSACTIONS_PER_SOURCE => {
                    state
                        .transactions
                        .insert(branch.to_string(), (now, Outcome::Pending));
                }
                _ => state.unkeyed_probes = state.unkeyed_probes.saturating_add(1),
            }

            // Track distinct probed extensions (To user, falling back to R-URI).
            if let Some(target) = msg.to_user().or_else(|| {
                msg.request_uri
                    .as_deref()
                    .and_then(crate::sip::message::extract_uri_user)
            }) && state.targets.len() < MAX_TARGETS_PER_SOURCE
            {
                state.targets.insert(target);
            }
            state.last_seen = now;

            // Neither rate nor spread is reconnaissance on its own: a trunk
            // running keepalives and an enumeration sweep produce the same
            // numbers, and only the outcomes tell them apart.
            if !state.is_probing(now, responses_seen, &thresholds) {
                return None;
            }

            // Enumeration: many DISTINCT targets from one source, none of them
            // resolving — catches a UA-randomized, INVITE-based, or
            // low-and-slow sweep the rate path misses. Checked first as the
            // more specific signal.
            if state.targets.len() > thresholds.enumeration_targets {
                return Some(ScannerAlert {
                    src_ip: msg.src_addr,
                    ua,
                    method: method.map(str::to_string),
                    detection_method: "enumeration".to_string(),
                });
            }

            // Rate: high volume of REGISTER/OPTIONS/INVITE probes in the
            // window — a same-target flood the enumeration signal won't see.
            if state.probe_count() > thresholds.behavioral_probes {
                return Some(ScannerAlert {
                    src_ip: msg.src_addr,
                    ua,
                    method: method.map(str::to_string),
                    detection_method: "behavioral".to_string(),
                });
            }
        }

        None
    }

    /// Fold a response into the behavioural state of the peer it answers.
    ///
    /// The peer is the response's DESTINATION: a response travels back the way
    /// the request came, so `dst_addr` is the source whose probe this settles.
    ///
    /// Only an existing entry is updated — a response never creates one. A
    /// response whose request was never seen anchors nothing, and letting
    /// responses populate the map would give a flood of them a way to evict
    /// the tracking of a scanner that is mid-sweep.
    fn observe_response(&mut self, msg: &SipMessage) {
        self.responses_seen = true;

        // A PROVISIONAL answers the probe too, and this is not a detail. The
        // unanswered test asks whether anything is there at all, and `100
        // Trying` settles that — while the FINAL response to an INVITE does
        // not arrive until the callee picks up or gives up, which is seconds
        // or minutes later. Waiting for it made every ringing call an
        // unanswered probe: on a real 1900-message customer capture that
        // reported one peer with 47 of 64 "unanswered" probes in five
        // seconds, which was a phone ringing.
        //
        // A scanner sweeping dead space gets no `100` either, and one
        // sweeping a live dialplan is caught by the refusals its `404`s make.
        let Some(status) = msg.status_code else {
            return;
        };
        // A 2xx to a REGISTER or an INVITE is the relationship a scanner does
        // not have; read the CSeq rather than trust the response alone,
        // because a 2xx to an OPTIONS is something we grant anyone.
        let completed = (200..300).contains(&status)
            && msg
                .cseq()
                .is_some_and(|(_, m)| matches!(m, "REGISTER" | "INVITE"));
        let branch = msg.top_via_branch();

        let Some(state) = self.behavioral.get_mut(&msg.dst_addr) else {
            return;
        };
        state.established |= completed;
        // A response whose branch names no probe transaction settles the
        // peer's BYEs, NOTIFYs and SUBSCRIBEs, and is dropped. Only a
        // rejection ON A PROBE is evidence about probing: a `481` refusing a
        // stray NOTIFY is ordinary traffic, and the real corpus is full of
        // them.
        if let Some((_, outcome)) = branch.and_then(|b| state.transactions.get_mut(b)) {
            *outcome = if is_rejection(status) {
                Outcome::Rejected
            } else {
                Outcome::Answered
            };
        }
    }

    /// Remove behavioral tracking entries whose last activity is older than
    /// `max_age` **in capture time**.
    ///
    /// Ages against the most recent packet checked, not `Instant::now()`: the
    /// caller sweeps on a schedule, and offline the wall clock barely moves
    /// between the first packet of a capture and the last, so a wall-clock
    /// sweep held every source it ever saw for the whole run.
    ///
    /// A no-op before the first message: with no capture time there is nothing
    /// to measure against, and nothing tracked to remove.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let Some(now) = self.latest_packet else {
            return;
        };
        let Ok(max_age) = TimeDelta::from_std(max_age) else {
            return;
        };
        self.behavioral
            .retain(|_, state| now.signed_duration_since(state.last_seen) < max_age);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for scanner UA-signature and behavioral/enumeration detection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback address used as a benign source/destination.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// The source IP used to simulate a scanner.
    fn scanner_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    /// A fixed capture timestamp for the parsed messages.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a request of `method` carrying the given User-Agent from `src`.
    fn make_request_with_ua(method: &str, ua: &str, src: IpAddr) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:target@example.com SIP/2.0"),
            &[
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                "Call-ID: scan-test@example.com",
                &format!("CSeq: 1 {method}"),
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            src,
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// A friendly-scanner User-Agent is detected via signature match.
    #[test]
    fn detect_friendly_scanner_ua() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("OPTIONS", "friendly-scanner", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect friendly-scanner");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
        assert_eq!(alert.ua.as_deref(), Some("friendly-scanner"));
    }

    /// A sipvicious User-Agent is detected via signature match.
    #[test]
    fn detect_sipvicious_ua() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("REGISTER", "sipvicious/0.3.4", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect sipvicious");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
    }

    /// A benign User-Agent does not trigger a signature alert.
    #[test]
    fn normal_ua_not_detected() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("INVITE", "Oasis/4.0", localhost());

        let alert = detector.check(&msg);
        assert!(alert.is_none(), "normal UA should not trigger alert");
    }

    /// The rate threshold still bounds the behavioral signal.
    ///
    /// Probing evidence is what makes a rate reportable; it does not replace
    /// the rate. Every probe here is refused, so the evidence is as strong as
    /// it gets, and the only thing separating the two halves of this test is
    /// whether the source crossed [`BEHAVIORAL_THRESHOLD`].
    #[test]
    fn behavioral_detection_high_rate() {
        let src = scanner_ip();
        let refused_registers = |n: i64| {
            let mut msgs = Vec::new();
            for i in 0..n {
                let branch = format!("z9hG4bK-rate-{i}");
                msgs.push(probe_at("REGISTER", "1001", src, &branch, ms(i * 100)));
                msgs.push(answer_at(
                    403,
                    "REGISTER",
                    "1001",
                    src,
                    &branch,
                    ms(i * 100),
                ));
            }
            replay(&msgs)
        };

        let at_threshold = refused_registers(BEHAVIORAL_THRESHOLD as i64);
        assert!(
            at_threshold.is_empty(),
            "the alert needs strictly more than {BEHAVIORAL_THRESHOLD} probes — got {at_threshold:?}"
        );

        let over = refused_registers(BEHAVIORAL_THRESHOLD as i64 + 1);
        assert_eq!(
            over.first().map(String::as_str),
            Some("behavioral"),
            "one probe past the threshold, all of them refused, must fire — got {over:?}"
        );
    }

    /// Build a request probing extension `target` with an arbitrary
    /// (attacker-chosen, here randomized-looking) User-Agent from `src` — the
    /// evasion: no known scanner UA, so `ua_pattern` can never fire.
    ///
    /// `n` names the transaction, so [`answer_at`] can settle it.
    fn enum_request(method: &str, target: &str, ua: &str, src: IpAddr, n: usize) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:{target}@example.com SIP/2.0"),
            &[
                &format!("Via: SIP/2.0/UDP probe.example.com;branch={}", enum_txn(n)),
                &format!("From: <sip:probe@example.com>;tag=t{n}"),
                &format!("To: <sip:{target}@example.com>"),
                &format!("Call-ID: enum-{n}@example.com"),
                &format!("CSeq: 1 {method}"),
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            src,
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// The transaction branch [`enum_request`] number `n` opens.
    fn enum_txn(n: usize) -> String {
        format!("z9hG4bK-enum-{n}")
    }

    /// INVITE-based extension enumeration with a randomized UA is caught by the
    /// distinct-target signal.
    #[test]
    fn detect_invite_extension_enumeration_with_randomized_ua() {
        // EVASION: attacker enumerates extensions over INVITE with a different,
        // innocuous UA each probe. ua_pattern never fires; the old behavioral
        // path only summed REGISTER+OPTIONS, so INVITE enumeration slipped
        // through entirely. The distinct-target signal must catch it.
        let src = scanner_ip();
        let uas = [
            "PolyUA/1",
            "Acme/2",
            "Zoip/3",
            "Xlite/4",
            "Bria/5",
            "Linphone/6",
            "Baresip/7",
            "Csip/8",
        ];
        let mut msgs = Vec::new();
        for (i, ua) in uas.iter().enumerate() {
            let target = format!("ext{i:04}");
            msgs.push(enum_request("INVITE", &target, ua, src, i));
            // None of those extensions exists — which is the whole point of
            // walking them, and the evidence that this is a walk.
            msgs.push(answer_at(404, "INVITE", &target, src, &enum_txn(i), ts()));
        }
        let fired = replay(&msgs);
        assert!(
            fired.contains(&"enumeration".to_string()),
            "extension enumeration over INVITE must be detected — got {fired:?}"
        );
    }

    /// Six distinct targets under the rate threshold still trigger enumeration.
    #[test]
    fn detect_low_and_slow_enumeration_under_rate_threshold() {
        // EVASION: stay UNDER the rate threshold (only 6 probes), but hit 6
        // DISTINCT extensions — a rate-only detector misses it; distinct-target
        // enumeration does not.
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..6 {
            let target = format!("user{i:04}");
            msgs.push(enum_request("OPTIONS", &target, "Normalish/9.0", src, i));
            msgs.push(answer_at(404, "OPTIONS", &target, src, &enum_txn(i), ts()));
        }
        let fired = replay(&msgs);
        assert_eq!(
            fired.first().map(String::as_str),
            Some("enumeration"),
            "6 distinct extensions from one source, none of them found, is \
             enumeration — got {fired:?}"
        );
    }

    /// Repeated requests to only one or two targets are not flagged as
    /// enumeration.
    #[test]
    fn normal_call_to_few_targets_not_flagged_as_enumeration() {
        // FALSE-POSITIVE guard: a normal client placing several requests to the
        // SAME one or two targets (retransmits / re-INVITE / a couple of calls)
        // must NOT be flagged as enumeration.
        let mut det = ScannerDetector::new(&[]);
        let src = localhost();
        for i in 0..12 {
            let target = if i % 2 == 0 { "alice" } else { "bob" };
            let msg = enum_request("INVITE", target, "Linphone/5.1", src, i);
            if let Some(a) = det.check(&msg) {
                assert_ne!(
                    a.detection_method, "enumeration",
                    "two distinct targets must not be enumeration (msg {i})"
                );
            }
        }
    }

    /// A user-supplied `--kill-ua` pattern is matched like a built-in signature.
    #[test]
    fn custom_kill_ua_detected() {
        let custom = vec!["my-scanner".to_string()];
        let mut detector = ScannerDetector::new(&custom);
        let msg = make_request_with_ua("OPTIONS", "my-scanner/1.0", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect custom --kill-ua pattern");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
    }

    // ── Packet time vs wall clock ────────────────────────────────────

    /// Build a request of `method` probing `target` from `src`, stamped with
    /// the capture time `at` — the knob these tests turn.
    ///
    /// `n` names the transaction, so [`answer_at`] can settle it.
    fn request_at(
        method: &str,
        target: &str,
        src: IpAddr,
        n: usize,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:{target}@example.com SIP/2.0"),
            &[
                &format!("Via: SIP/2.0/UDP probe.example.com;branch={}", clock_txn(n)),
                &format!("From: <sip:probe@example.com>;tag=t{n}"),
                &format!("To: <sip:{target}@example.com>"),
                &format!("Call-ID: clock-{n}@example.com"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, at, src, localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse")
    }

    /// The transaction branch [`request_at`] number `n` opens.
    fn clock_txn(n: usize) -> String {
        format!("z9hG4bK-clock-{n}")
    }

    /// Capture time `secs` seconds after the fixed base timestamp.
    fn at(secs: i64) -> DateTime<Utc> {
        ts() + chrono::TimeDelta::seconds(secs)
    }

    /// The behavioural window counts what the CAPTURE says, not how long
    /// sipnab took to read it.
    ///
    /// A file replayed from disk delivers every packet within milliseconds of
    /// wall time, so a window paced by `Instant::now()` never expires offline
    /// and the per-source counters accumulate over the whole capture. A busy
    /// trunk then trips `BEHAVIORAL_THRESHOLD` on volume it never had: here,
    /// one REGISTER every two seconds — three per five-second window against a
    /// threshold of ten — replayed in a tight loop.
    #[test]
    fn behavioural_window_is_measured_in_packet_time() {
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = 0usize;
        for i in 0..60 {
            let msg = request_at("REGISTER", "sameuser", src, i, at(i as i64 * 2));
            if det.check(&msg).is_some() {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "one REGISTER every 2s is 3 per {BEHAVIORAL_WINDOW_SECS}s window, well under \
             the threshold of {BEHAVIORAL_THRESHOLD} — {fired} alerts means the window is \
             being paced by how fast the file was read, not by the capture"
        );
    }

    /// The enumeration window is packet time too.
    ///
    /// Ten seconds between probes is two full windows apart, so no window ever
    /// holds more than one distinct target. Paced by wall time, all sixty land
    /// in one window and the sixth trips `ENUMERATION_THRESHOLD`.
    #[test]
    fn enumeration_window_is_measured_in_packet_time() {
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = 0usize;
        for i in 0..60 {
            let msg = request_at("OPTIONS", &format!("ext{i:04}"), src, i, at(i as i64 * 10));
            if det.check(&msg).is_some() {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "probes {BEHAVIORAL_WINDOW_SECS}s apart put one target in each window, under the \
             enumeration threshold of {ENUMERATION_THRESHOLD} — {fired} alerts means distinct \
             targets are accumulating across the whole capture"
        );
    }

    /// A genuine burst inside one window still fires — the packet-time window
    /// must not become a way to never detect anything.
    #[test]
    fn a_real_burst_inside_one_packet_time_window_still_fires() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..15 {
            // 100ms apart: all fifteen inside one BEHAVIORAL_WINDOW_SECS window.
            let at = ms(i as i64 * 100);
            msgs.push(request_at("REGISTER", "sameuser", src, i, at));
            msgs.push(answer_at(
                403,
                "REGISTER",
                "sameuser",
                src,
                &clock_txn(i),
                at,
            ));
        }
        let fired = replay(&msgs);
        assert_eq!(
            fired.first().map(String::as_str),
            Some("behavioral"),
            "15 refused REGISTERs in 1.5s of capture time is a flood and must \
             fire — got {fired:?}"
        );
    }

    /// A genuine sweep inside one window still fires as enumeration.
    #[test]
    fn a_real_sweep_inside_one_packet_time_window_still_fires() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..8 {
            let target = format!("ext{i:04}");
            let at = ms(i as i64 * 100);
            msgs.push(request_at("OPTIONS", &target, src, i, at));
            msgs.push(answer_at(404, "OPTIONS", &target, src, &clock_txn(i), at));
        }
        let fired = replay(&msgs);
        assert_eq!(
            fired.first().map(String::as_str),
            Some("enumeration"),
            "8 distinct targets in 0.8s of capture time, none of them found, is \
             enumeration — got {fired:?}"
        );
    }

    /// `sweep` ages entries out on capture time as well — in both directions.
    ///
    /// The two assertions pin the two ways a wrong clock goes wrong, and
    /// neither alone is enough. An `Instant`-paced sweep retains everything:
    /// offline the wall clock barely advances between the first packet and the
    /// last, so nothing is ever old enough to drop, however long ago the
    /// capture says the source went quiet. A `Utc::now()`-paced sweep does the
    /// opposite on any capture that is not from today — every source is years
    /// idle the moment it is read, so the sweep empties the map and the
    /// detector forgets a scanner mid-scan.
    #[test]
    fn sweep_ages_entries_out_on_packet_time() {
        let mut det = ScannerDetector::new(&[]);
        let (quiet, active) = (scanner_ip(), localhost());
        let _ = det.check(&request_at("REGISTER", "u", quiet, 0, at(0)));
        assert_eq!(det.behavioral.len(), 1, "the source must be tracked");

        // A packet 10 minutes later in capture time, then a 2-minute sweep.
        let _ = det.check(&request_at("REGISTER", "u", active, 1, at(600)));
        det.sweep(std::time::Duration::from_secs(120));
        assert!(
            !det.behavioral.contains_key(&quiet),
            "a source last seen 600s ago in capture time must not survive a 120s sweep"
        );
        assert!(
            det.behavioral.contains_key(&active),
            "the source that sent the most recent packet is 0s idle in capture time and \
             must survive — a sweep aged against `Utc::now()` drops it, because a capture \
             recorded before today is already older than any max_age"
        );
    }

    // ── Probing evidence, not volume ─────────────────────────────────

    /// A probe of `method` towards `target` from `src`, opening the
    /// transaction named by `branch` at capture time `at`.
    ///
    /// Carries a `Via` because the branch is what ties a response back to the
    /// request it answers — the tie the whole signature rests on.
    fn probe_at(
        method: &str,
        target: &str,
        src: IpAddr,
        branch: &str,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:{target}@example.com SIP/2.0"),
            &[
                &format!("Via: SIP/2.0/UDP peer.example.com;branch={branch}"),
                &format!("From: <sip:peer@example.com>;tag=f-{branch}"),
                &format!("To: <sip:{target}@example.com>"),
                &format!("Call-ID: {branch}@example.com"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, at, src, localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse")
    }

    /// The response `status` we send back to `dst` on transaction `branch`,
    /// answering a `cseq_method` request that was aimed at `target`.
    fn answer_at(
        status: u16,
        cseq_method: &str,
        target: &str,
        dst: IpAddr,
        branch: &str,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} Whatever"),
            &[
                &format!("Via: SIP/2.0/UDP peer.example.com;branch={branch}"),
                &format!("From: <sip:peer@example.com>;tag=f-{branch}"),
                &format!("To: <sip:{target}@example.com>;tag=t-{branch}"),
                &format!("Call-ID: {branch}@example.com"),
                &format!("CSeq: 1 {cseq_method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, at, localhost(), dst, 5060, 5060, TransportProto::Udp)
            .expect("should parse")
    }

    /// Capture time `ms` milliseconds after the fixed base timestamp.
    fn ms(ms: i64) -> DateTime<Utc> {
        ts() + chrono::TimeDelta::milliseconds(ms)
    }

    /// Feed `msgs` to a fresh detector and collect the detection methods it
    /// reported, in order.
    fn replay(msgs: &[SipMessage]) -> Vec<String> {
        replay_with(ScannerThresholds::BUILT_IN, msgs)
    }

    /// [`replay`] against a detector built with `thresholds`.
    fn replay_with(thresholds: ScannerThresholds, msgs: &[SipMessage]) -> Vec<String> {
        let mut det = ScannerDetector::with_thresholds(&[], thresholds);
        msgs.iter()
            .filter_map(|m| det.check(m))
            .map(|a| a.detection_method)
            .collect()
    }

    /// The registration that makes `src` a peer we serve: a REGISTER, its
    /// challenge, the authenticated retry, and the `200 OK`.
    fn register_exchange(src: IpAddr, at: DateTime<Utc>) -> Vec<SipMessage> {
        vec![
            probe_at("REGISTER", "1001", src, "z9hG4bK-reg-a", at),
            answer_at(401, "REGISTER", "1001", src, "z9hG4bK-reg-a", at),
            probe_at("REGISTER", "1001", src, "z9hG4bK-reg-b", at),
            answer_at(200, "REGISTER", "1001", src, "z9hG4bK-reg-b", at),
        ]
    }

    /// A trunk's answered OPTIONS keepalives are not reconnaissance.
    ///
    /// This is the defect the signature was rebuilt for. A SIP trunk sends
    /// OPTIONS continuously by design — it is how each end learns the other is
    /// alive — and a rate counter that treats every OPTIONS as a probe reports
    /// the carrier's own SBC as a scanner within one window. Fed to fail2ban
    /// that bans the trunk, which is every call the box carries.
    ///
    /// What separates the keepalive from a probe is not how many there are: it
    /// is that each one is ANSWERED, by a peer we already registered.
    #[test]
    fn answered_options_keepalives_are_not_a_scanner() {
        let src = scanner_ip();
        let mut msgs = register_exchange(src, ms(0));
        for i in 0..60 {
            // Twelve keepalives a second — a rate no threshold survives.
            let branch = format!("z9hG4bK-ka-{i}");
            let at = ms(100 + i * 80);
            msgs.push(probe_at("OPTIONS", "trunk", src, &branch, at));
            msgs.push(answer_at(200, "OPTIONS", "trunk", src, &branch, at));
        }
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "60 OPTIONS keepalives that were all answered, from a peer already \
             registered with us, are a working trunk — got {fired:?}"
        );
    }

    /// A trunk delivering calls to many distinct extensions is not
    /// enumeration.
    ///
    /// The distinct-target count is the same whether an SBC fronts a hunt
    /// group or a scanner walks the dialplan. What differs is the outcome: the
    /// SBC's calls are answered, the scanner's are not.
    #[test]
    fn calls_delivered_to_many_distinct_extensions_are_not_enumeration() {
        let src = scanner_ip();
        let mut msgs = register_exchange(src, ms(0));
        for i in 0..12 {
            let branch = format!("z9hG4bK-call-{i}");
            let target = format!("ext{i:04}");
            let at = ms(100 + i * 100);
            msgs.push(probe_at("INVITE", &target, src, &branch, at));
            msgs.push(answer_at(200, "INVITE", &target, src, &branch, at));
        }
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "twelve calls to twelve extensions, every one answered, is an SBC \
             fronting a hunt group — got {fired:?}"
        );
    }

    /// A flood that nothing answers still fires.
    ///
    /// The evidence gate must not become a way to never detect anything: a
    /// source whose probes go into a hole is exactly what the rate test is
    /// for.
    #[test]
    fn an_unanswered_flood_still_fires() {
        let src = scanner_ip();
        // A capture with no responses at all cannot tell "unanswered" from "we
        // captured one direction", so the other direction has to exist
        // somewhere in it: here, one working peer's answered keepalive.
        let mut msgs = vec![
            probe_at("OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
            answer_at(200, "OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
        ];
        for i in 0..15 {
            let branch = format!("z9hG4bK-flood-{i}");
            msgs.push(probe_at("REGISTER", "victim", src, &branch, ms(i * 100)));
        }
        let fired = replay(&msgs);
        assert!(
            fired.contains(&"behavioral".to_string()),
            "15 REGISTERs in 1.5s that nothing answered is a flood — got {fired:?}"
        );
    }

    /// A registration sweep we keep rejecting still fires.
    #[test]
    fn a_rejected_registration_sweep_still_fires() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..15 {
            let branch = format!("z9hG4bK-crack-{i}");
            let at = ms(i * 100);
            msgs.push(probe_at("REGISTER", "1001", src, &branch, at));
            msgs.push(answer_at(403, "REGISTER", "1001", src, &branch, at));
        }
        let fired = replay(&msgs);
        assert!(
            fired.contains(&"behavioral".to_string()),
            "15 REGISTERs for one extension, every one forbidden, is a password \
             attack — got {fired:?}"
        );
    }

    /// Extension enumeration we answer `404` to still fires.
    #[test]
    fn enumeration_of_extensions_we_reject_still_fires() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..8 {
            let branch = format!("z9hG4bK-svwar-{i}");
            let target = format!("ext{i:04}");
            let at = ms(i * 100);
            msgs.push(probe_at("INVITE", &target, src, &branch, at));
            msgs.push(answer_at(404, "INVITE", &target, src, &branch, at));
        }
        let fired = replay(&msgs);
        assert!(
            fired.contains(&"enumeration".to_string()),
            "eight extensions probed and eight not found is a dialplan sweep — got {fired:?}"
        );
    }

    /// A source that completed a registration needs far more evidence.
    ///
    /// A registered endpoint that starts probing is a compromised phone, which
    /// is worth reporting — but it is also the peer whose ordinary working
    /// traffic looks most like probing, so the bar is
    /// [`ESTABLISHED_EVIDENCE_FACTOR`] times higher.
    #[test]
    fn an_established_peer_needs_far_more_evidence() {
        let src = scanner_ip();
        let sweep = |n: i64| {
            let mut msgs = register_exchange(src, ms(0));
            for i in 0..n {
                let branch = format!("z9hG4bK-comp-{i}");
                let target = format!("ext{i:04}");
                let at = ms(10 + i * 10);
                msgs.push(probe_at("INVITE", &target, src, &branch, at));
                msgs.push(answer_at(404, "INVITE", &target, src, &branch, at));
            }
            replay(&msgs)
        };

        let modest = sweep(REJECTED_PROBE_MIN as i64 * 2);
        assert!(
            modest.is_empty(),
            "{} rejected probes would report an unknown source, but a registered \
             peer needs {ESTABLISHED_EVIDENCE_FACTOR} times that — got {modest:?}",
            REJECTED_PROBE_MIN * 2
        );

        let blatant = sweep(REJECTED_PROBE_MIN as i64 * ESTABLISHED_EVIDENCE_FACTOR as i64 * 2);
        assert!(
            !blatant.is_empty(),
            "a registered peer walking the dialplan {} times over the bar is a \
             compromised phone and must still be reported",
            2
        );
    }

    /// Retransmissions of one request are one probe, not many.
    ///
    /// UDP retransmits an unanswered INVITE at 500ms, 1s, 2s and 4s, so a
    /// couple of calls into a peer that is slow to answer reach the rate
    /// threshold on their own. They are one transaction each, which is what
    /// the top `Via` branch says.
    #[test]
    fn retransmissions_of_one_request_are_one_probe() {
        let src = scanner_ip();
        // Another source's answered probe FIRST, so the unanswered test is
        // armed before the retransmissions start. Ordered the other way the
        // test passes for the wrong reason, whatever the dedup does.
        let mut msgs = vec![
            probe_at("OPTIONS", "ping", localhost(), "z9hG4bK-o", ms(0)),
            answer_at(200, "OPTIONS", "ping", localhost(), "z9hG4bK-o", ms(0)),
        ];
        for i in 0..20 {
            // Twenty copies of one transaction, over two seconds — well past
            // the answer grace, so each copy would count if they were counted.
            msgs.push(probe_at("INVITE", "1001", src, "z9hG4bK-retx", ms(i * 100)));
        }
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "twenty retransmissions of one INVITE are one unanswered transaction, \
             not twenty probes — got {fired:?}"
        );
    }

    /// A peer that pipelines faster than the round trip is not a sweep.
    ///
    /// "Unanswered" has to mean "we did not answer it", not "we have not
    /// answered it yet". A client that puts fifteen registrations on the wire
    /// before the first reply comes back — a PBX booting, a phone with a long
    /// account list — has every one of them outstanding at the moment the next
    /// is sent, and without a grace period that reads identically to fifteen
    /// probes into a hole. Whether it tripped would come down to link latency
    /// and pipelining depth rather than to anything the peer meant.
    #[test]
    fn a_peer_that_pipelines_faster_than_the_round_trip_is_not_a_sweep() {
        let src = scanner_ip();
        // Another peer's answered keepalive, so the unanswered test is armed.
        let mut msgs = vec![
            probe_at("OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
            answer_at(200, "OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
        ];
        // Fifteen registrations in 150ms, each answered 100ms after it was
        // sent — so every one is still in flight when the next goes out.
        for i in 0..15 {
            let branch = format!("z9hG4bK-boot-{i}");
            msgs.push(probe_at("REGISTER", "1001", src, &branch, ms(i * 10)));
        }
        for i in 0..15 {
            let branch = format!("z9hG4bK-boot-{i}");
            msgs.push(answer_at(
                200,
                "REGISTER",
                "1001",
                src,
                &branch,
                ms(100 + i * 10),
            ));
        }
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "fifteen registrations answered within {PROBE_ANSWER_GRACE_MS}ms each were \
             never unanswered, only in flight — got {fired:?}"
        );
    }

    /// Calls that are ringing are not unanswered probes.
    ///
    /// The final response to an INVITE does not arrive until the callee picks
    /// up or gives up. Counting a probe unanswered until then makes every
    /// ringing call evidence of a sweep, and a busy PBX has a dozen ringing at
    /// once: measured on a real 1900-message customer capture, one peer showed
    /// 47 of 64 probes "unanswered" in five seconds, and all of it was phones
    /// ringing. A `100 Trying` settles the only question the unanswered test
    /// asks — whether anything is there.
    #[test]
    fn calls_that_are_ringing_are_not_unanswered_probes() {
        let src = scanner_ip();
        let mut msgs = register_exchange(src, ms(0));
        for i in 0..20 {
            let branch = format!("z9hG4bK-ring-{i}");
            let target = format!("ext{i:04}");
            let at = ms(100 + i * 100);
            msgs.push(probe_at("INVITE", &target, src, &branch, at));
            // Answered at once by the proxy, then ringing. The `200 OK` comes
            // thirty seconds later, when somebody picks up.
            msgs.push(answer_at(100, "INVITE", &target, src, &branch, at));
            msgs.push(answer_at(180, "INVITE", &target, src, &branch, at));
            msgs.push(answer_at(
                200,
                "INVITE",
                &target,
                src,
                &branch,
                at + chrono::TimeDelta::seconds(30),
            ));
        }
        msgs.sort_by_key(|m| m.timestamp);
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "twenty calls that rang for thirty seconds each are calls, not probes \
             into a hole — got {fired:?}"
        );
    }

    /// A capture holding no responses at all raises no unanswered alert.
    ///
    /// "Unanswered" is a claim about the other direction. In a capture that
    /// holds one direction only — a `sip.request` filter, or a tap on one leg
    /// — every probe ever sent looks unanswered, and the peer reported would
    /// be whichever one was busiest. That is the defect this signature
    /// replaced, so the unanswered test stands down until the detector has
    /// seen a response exist.
    #[test]
    fn a_capture_of_requests_alone_raises_no_unanswered_alert() {
        let src = scanner_ip();
        let msgs: Vec<SipMessage> = (0..40)
            .map(|i| {
                probe_at(
                    "OPTIONS",
                    "trunk",
                    src,
                    &format!("z9hG4bK-1w-{i}"),
                    ms(i * 100),
                )
            })
            .collect();
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "a capture with no responses in it cannot show anything unanswered — got {fired:?}"
        );
    }

    /// A rejection on an unrelated transaction is not evidence.
    ///
    /// A `481 Call/Transaction Does Not Exist` answering a stray `NOTIFY` or a
    /// late `BYE` is ordinary traffic — the real corpus is full of them — and
    /// says nothing about the OPTIONS keepalives running alongside. Only a
    /// rejection on a probe transaction the detector opened counts.
    #[test]
    fn a_rejection_on_an_unrelated_transaction_is_not_evidence() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..20 {
            let branch = format!("z9hG4bK-ka-{i}");
            let at = ms(i * 100);
            msgs.push(probe_at("OPTIONS", "trunk", src, &branch, at));
            msgs.push(answer_at(200, "OPTIONS", "trunk", src, &branch, at));
            // A subscription this peer no longer holds, refused every time.
            let stray = format!("z9hG4bK-notify-{i}");
            msgs.push(probe_at("NOTIFY", "trunk", src, &stray, at));
            msgs.push(answer_at(481, "NOTIFY", "trunk", src, &stray, at));
        }
        let fired = replay(&msgs);
        assert!(
            fired.is_empty(),
            "481s to stray NOTIFYs are not rejected probes — got {fired:?}"
        );
    }

    // ── Trigger points an operator can move ──────────────────────────

    /// A sweep paced slower than the window is invisible at ANY count, and
    /// visible once the window is widened.
    ///
    /// This is the case the counts cannot reach. Every scanner count is "per
    /// window", so a source that probes once every ten seconds has its window
    /// reset before the second probe arrives: its rate is one, its spread is
    /// one, and its rejected count is one, whatever the thresholds say. The
    /// middle assertion is the point of the test — every count pinned to its
    /// floor of 1 with the shipped window still reports nothing.
    #[test]
    fn a_low_and_slow_sweep_needs_a_wider_window_not_a_lower_count() {
        let src = scanner_ip();
        // Eight distinct extensions, one probe every ten seconds, every one
        // answered "not found" — a dialplan walk in slow motion.
        let mut msgs = Vec::new();
        for i in 0..8i64 {
            let branch = format!("z9hG4bK-slow-{i}");
            let target = format!("ext{i:04}");
            let at = ms(i * 10_000);
            msgs.push(probe_at("OPTIONS", &target, src, &branch, at));
            msgs.push(answer_at(
                404,
                "OPTIONS",
                &target,
                src,
                &branch,
                ms(i * 10_000 + 50),
            ));
        }

        let shipped = replay(&msgs);
        assert!(
            shipped.is_empty(),
            "a probe every 10s never puts two in one {}s window, so the shipped \
             detector cannot see this sweep — got {shipped:?}",
            ScannerThresholds::BUILT_IN.window_secs
        );

        // Every count at its floor, the window left alone.
        let floored = replay_with(
            ScannerThresholds {
                behavioral_probes: 1,
                enumeration_targets: 1,
                rejected_probes: 1,
                unanswered_probes: 1,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            floored.is_empty(),
            "with the window unchanged the counts cannot reach this sweep at ANY \
             setting: each probe opens a fresh window holding one probe, one \
             target and no settled outcome — got {floored:?}"
        );

        // The window widened, every count left at its shipped value.
        let widened = replay_with(
            ScannerThresholds {
                window_secs: 60,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert_eq!(
            widened.first().map(String::as_str),
            Some("enumeration"),
            "a 60s window holds all eight probes, so six distinct extensions and \
             five refusals are in it at once — got {widened:?}"
        );
    }

    /// The declared probe count decides when a rate is a scanner.
    ///
    /// The aggregation case: behind an SBC every source collapses to one
    /// address, so ordinary traffic clears the shipped ten in five seconds.
    #[test]
    fn scanner_behavioral_probes_decides_when_a_rate_is_a_scanner() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..15i64 {
            let branch = format!("z9hG4bK-agg-{i}");
            let at = ms(i * 100);
            msgs.push(probe_at("REGISTER", "1001", src, &branch, at));
            msgs.push(answer_at(403, "REGISTER", "1001", src, &branch, at));
        }

        let shipped = replay(&msgs);
        assert_eq!(
            shipped.first().map(String::as_str),
            Some("behavioral"),
            "fifteen refused REGISTERs in 1.5s clears the shipped {} — got {shipped:?}",
            ScannerThresholds::BUILT_IN.behavioral_probes
        );

        let raised = replay_with(
            ScannerThresholds {
                behavioral_probes: 100,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            raised.is_empty(),
            "a site that aggregates behind one address raises the count, and \
             fifteen is under a hundred — got {raised:?}"
        );
    }

    /// The declared target count decides how wide a sweep must be.
    #[test]
    fn scanner_enumeration_targets_decides_how_wide_a_sweep_must_be() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..8i64 {
            let branch = format!("z9hG4bK-wide-{i}");
            let target = format!("ext{i:04}");
            let at = ms(i * 100);
            msgs.push(probe_at("INVITE", &target, src, &branch, at));
            msgs.push(answer_at(404, "INVITE", &target, src, &branch, at));
        }

        let shipped = replay(&msgs);
        assert_eq!(
            shipped.first().map(String::as_str),
            Some("enumeration"),
            "eight extensions, none found, clears the shipped {} — got {shipped:?}",
            ScannerThresholds::BUILT_IN.enumeration_targets
        );

        let raised = replay_with(
            ScannerThresholds {
                enumeration_targets: 50,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            raised.is_empty(),
            "an SBC fronting a large hunt group reaches dozens of extensions a \
             second, so it declares fifty — got {raised:?}"
        );
    }

    /// The declared refusal count decides how much saying no is evidence.
    #[test]
    fn scanner_rejected_probes_decides_how_much_refusal_is_evidence() {
        let src = scanner_ip();
        let mut msgs = Vec::new();
        for i in 0..12i64 {
            let branch = format!("z9hG4bK-crack-{i}");
            let at = ms(i * 100);
            msgs.push(probe_at("REGISTER", "1001", src, &branch, at));
            msgs.push(answer_at(403, "REGISTER", "1001", src, &branch, at));
        }

        let shipped = replay(&msgs);
        assert_eq!(
            shipped.first().map(String::as_str),
            Some("behavioral"),
            "twelve refusals clears the shipped {} — got {shipped:?}",
            ScannerThresholds::BUILT_IN.rejected_probes
        );

        let raised = replay_with(
            ScannerThresholds {
                rejected_probes: 20,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            raised.is_empty(),
            "a registrar that refuses every unauthenticated first attempt earns \
             refusals all day, so it needs twenty before they mean anything — \
             got {raised:?}"
        );
    }

    /// The declared unanswered count decides how much silence is evidence.
    #[test]
    fn scanner_unanswered_probes_decides_how_much_silence_is_evidence() {
        let src = scanner_ip();
        // Another peer's answered keepalive first, so the unanswered test is
        // armed: a capture with no responses in it can show nothing unanswered.
        let mut msgs = vec![
            probe_at("OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
            answer_at(200, "OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
        ];
        for i in 0..15i64 {
            let branch = format!("z9hG4bK-hole-{i}");
            msgs.push(probe_at("REGISTER", "victim", src, &branch, ms(i * 100)));
        }

        let shipped = replay(&msgs);
        assert!(
            shipped.contains(&"behavioral".to_string()),
            "fifteen probes into a hole clears the shipped {} — got {shipped:?}",
            ScannerThresholds::BUILT_IN.unanswered_probes
        );

        let raised = replay_with(
            ScannerThresholds {
                unanswered_probes: 40,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            raised.is_empty(),
            "fifteen is under a declared forty — got {raised:?}"
        );
    }

    /// The declared factor decides how much more a registered peer is trusted.
    #[test]
    fn scanner_established_factor_decides_what_a_registration_buys() {
        let src = scanner_ip();
        let mut msgs = register_exchange(src, ms(0));
        // Twice the shipped refusal minimum: enough for an unknown source, not
        // enough for one that has registered.
        for i in 0..(REJECTED_PROBE_MIN as i64 * 2) {
            let branch = format!("z9hG4bK-comp-{i}");
            let target = format!("ext{i:04}");
            let at = ms(10 + i * 10);
            msgs.push(probe_at("INVITE", &target, src, &branch, at));
            msgs.push(answer_at(404, "INVITE", &target, src, &branch, at));
        }

        let shipped = replay(&msgs);
        assert!(
            shipped.is_empty(),
            "a registered peer needs {} times the evidence, and this is twice — \
             got {shipped:?}",
            ScannerThresholds::BUILT_IN.established_factor
        );

        let no_credit = replay_with(
            ScannerThresholds {
                established_factor: 1,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            !no_credit.is_empty(),
            "a site that grants a registration no extra credit judges this peer \
             like any other, and ten refusals is a dialplan walk — got {no_credit:?}"
        );
    }

    /// The declared answer grace decides how slow a link may be.
    ///
    /// The shipped 500 ms is RFC 3261's Timer T1. A link whose round trip is
    /// longer than that has every probe outstanding when the next goes out, so
    /// an ordinary working peer reads as a sweep into a hole — the same defect
    /// the grace exists to prevent, one round-trip further out.
    #[test]
    fn scanner_answer_grace_ms_decides_how_slow_a_link_may_be() {
        let src = scanner_ip();
        let mut msgs = vec![
            probe_at("OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
            answer_at(200, "OPTIONS", "ping", localhost(), "z9hG4bK-ok", ms(0)),
        ];
        // Fifteen registrations 100 ms apart, every one answered — but two
        // seconds later, because that is what this link costs.
        for i in 0..15i64 {
            let branch = format!("z9hG4bK-slowlink-{i}");
            msgs.push(probe_at("REGISTER", "1001", src, &branch, ms(i * 100)));
            msgs.push(answer_at(
                200,
                "REGISTER",
                "1001",
                src,
                &branch,
                ms(i * 100 + 2_000),
            ));
        }
        msgs.sort_by_key(|m| m.timestamp);

        let shipped = replay(&msgs);
        assert!(
            shipped.contains(&"behavioral".to_string()),
            "under a {} ms grace every probe on a 2s link is 'unanswered', so a \
             working peer is reported — got {shipped:?}",
            ScannerThresholds::BUILT_IN.answer_grace_ms
        );

        let widened = replay_with(
            ScannerThresholds {
                answer_grace_ms: 3_000,
                ..ScannerThresholds::BUILT_IN
            },
            &msgs,
        );
        assert!(
            widened.is_empty(),
            "a 3s grace covers this link's round trip, so nothing here was ever \
             unanswered — got {widened:?}"
        );
    }

    /// SIP responses are ignored (only requests are checked).
    #[test]
    fn response_messages_ignored() {
        let mut detector = ScannerDetector::new(&[]);
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: resp-test@example.com",
                "CSeq: 1 OPTIONS",
                "User-Agent: friendly-scanner",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            scanner_ip(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        assert!(
            detector.check(&msg).is_none(),
            "responses should not trigger scanner alerts"
        );
    }
}
