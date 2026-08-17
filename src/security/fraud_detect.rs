// SPDX-License-Identifier: MIT OR Apache-2.0

//! Toll fraud detection heuristics for SIP traffic.
//!
//! Analyzes call patterns to detect common telecom fraud techniques:
//! - **Volume spikes** — sudden traffic bursts from a single source
//! - **Wangiri** — short-duration calls to premium/international numbers
//! - **Sequential scanning** — calls to consecutive number ranges
//! - **Off-hours** — calls placed outside configured business hours

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Timelike, Utc};

use crate::sip::SipMessage;
use crate::sip::dialog::{DialogState, SipDialog};

/// Shipped width of the volume-spike window, in seconds. Reachable as
/// `FraudThresholds::volume_window_secs`.
const VOLUME_WINDOW_SECS: u64 = 60;

/// Multiplier for volume spike detection: >5x the baseline rate.
const VOLUME_SPIKE_MULTIPLIER: u32 = 5;

/// Minimum calls before a volume spike can be detected.
const VOLUME_SPIKE_MIN_CALLS: u32 = 6;

/// Weight the rolling baseline keeps on its previous value when a new window
/// is folded in. Ten windows of history, so a minute of traffic moves it a
/// little and an hour of it moves it entirely.
///
/// Fixed, while the window beside it is settable, and the reason is that this
/// number is denominated in WINDOWS rather than in seconds. The baseline folds
/// once per window, so "ten windows of history" holds at every width an
/// operator can declare: the baseline stays an order of magnitude slower than
/// the thing it baselines whether that thing spans five seconds or fifteen
/// minutes. Expose it and the two numbers become one calibration with two
/// halves, where widening the window and forgetting the decay leaves a
/// baseline that chases the burst it exists to measure.
const BASELINE_DECAY: f64 = 0.9;

/// Shipped width of the wangiri window, in seconds. Reachable as
/// `FraudThresholds::wangiri_window_secs`.
const WANGIRI_WINDOW_SECS: u64 = 60;

/// Minimum short calls to same prefix for wangiri detection.
const WANGIRI_THRESHOLD: u32 = 3;

/// Call duration below which a call is considered "short" (seconds).
const SHORT_CALL_SECS: u64 = 3;

/// Minimum sequential numbers to trigger sequential scanning detection.
const SEQUENTIAL_THRESHOLD: usize = 3;

/// How much capture time a run of refused numbers may span, in seconds.
///
/// Its own constant rather than the volume window, which is what the refused
/// calls were pruned to before that window became settable. The two shared a
/// helper and therefore shared a number, which was harmless while both were 60
/// — and would have become a silent coupling the moment an operator narrowed
/// the volume window to catch a short burst and, without being told, narrowed
/// the run a dial-plan walk has to make.
///
/// Fixed, because a dial-plan walk is defined by the CONSECUTIVENESS of the
/// numbers rather than by any rate: `sequential_calls` already says how long
/// the run must be, and there is no second question here for a window to
/// answer.
const SEQUENTIAL_WINDOW_SECS: u64 = 60;

/// Cap on short calls remembered per source. The map is already pruned to the
/// configured wangiri window, so this only bounds a source completing thousands
/// of calls inside one window.
const MAX_SHORT_CALLS_PER_SOURCE: usize = 1024;

/// Per-source call tracking state.
///
/// Every timestamp here is CAPTURE time — the timestamp the packet carried —
/// never wall time. See [`FraudDetector::latest_packet`] for why.
struct CallPattern {
    /// Recent calls: (capture time of the INVITE, destination number).
    calls: Vec<(DateTime<Utc>, String)>,
    /// Calls whose MEASURED duration came in under `SHORT_CALL_SECS`, keyed by
    /// Call-ID: `call_id -> (capture time the call ended, destination)`.
    ///
    /// Keyed rather than counted for two reasons. A dialog reaches a terminal
    /// state once but keeps receiving messages afterwards — the `200 OK` to a
    /// `BYE`, a `487` after a `CANCEL` — and each of those would otherwise
    /// count the same call again. And wangiri is a claim about calls to one
    /// PREFIX, which a bare counter cannot support: the count that went into
    /// the alert text has to come from the short calls themselves.
    short_calls: HashMap<String, (DateTime<Utc>, String)>,
    /// Calls the network REFUSED, keyed by Call-ID:
    /// `call_id -> (capture time the call failed, destination)`.
    ///
    /// A run of consecutive numbers is only a scan when the numbers are not
    /// there. A DID block is contiguous by definition, so a carrier delivering
    /// into one walks consecutive numbers all day, and counting every call
    /// whatever became of it reported 39 sequential scans over an ordinary
    /// eleven-second trunk capture. Keyed for the same reason as
    /// [`Self::short_calls`]: a terminal dialog keeps receiving messages.
    refused_calls: HashMap<String, (DateTime<Utc>, String)>,
    /// This source's ordinary call rate, in calls per configured volume
    /// window: a rolling average over the windows it has completed.
    ///
    /// `None` until it has completed one. It used to start at 1.0 — a number
    /// the constructor guessed rather than one the source established — so the
    /// [`VOLUME_SPIKE_MIN_CALLS`]th call any source ever placed was already
    /// [`VOLUME_SPIKE_MULTIPLIER`] times "its baseline", and an ordinary
    /// carrier trunk cleared that in the first minute of every hour it
    /// carried. A rate can only be a departure from what a source normally
    /// does once something is known about what it normally does.
    baseline_rate: Option<f64>,
    /// Capture time the baseline last took a sample.
    ///
    /// Sampled once per window rather than once per call, because a baseline
    /// has to be slower than the thing it baselines. Folded in per call, its
    /// time constant was ten calls — shorter than a burst — so the average
    /// chased the burst upward and suppressed the very alert it exists to
    /// raise.
    baseline_sampled_at: DateTime<Utc>,
    /// Monotonic counter of when this source was last touched, used to pick
    /// the eviction victim.
    ///
    /// Not a timestamp, because capture timestamps TIE: two packets can share
    /// a microsecond. Under a tie `min_by_key` returns whichever entry the
    /// hash order happened to visit first, so which source the memory cap
    /// evicted — whose detection state is discarded — became unpredictable.
    last_used: u64,
}

impl CallPattern {
    /// An empty pattern first seen at `now`, stamped with the use counter.
    fn new(now: DateTime<Utc>, last_used: u64) -> Self {
        Self {
            calls: Vec::new(),
            short_calls: HashMap::new(),
            refused_calls: HashMap::new(),
            baseline_rate: None,
            baseline_sampled_at: now,
            last_used,
        }
    }

    /// Fold the window that has just elapsed into the baseline, if one has.
    ///
    /// Runs before any alert is raised and whatever that alert turns out to
    /// be. The update used to sit below every early return, so the first alert
    /// a source raised froze its baseline at the value that produced it — and
    /// with the baseline frozen, every call it placed afterwards raised the
    /// alert again.
    fn sample_baseline(&mut self, now: DateTime<Utc>, window: TimeDelta) {
        if now.signed_duration_since(self.baseline_sampled_at) < window {
            return;
        }
        let observed = self.calls.len() as f64;
        self.baseline_rate = Some(match self.baseline_rate {
            Some(previous) => previous * BASELINE_DECAY + observed * (1.0 - BASELINE_DECAY),
            None => observed,
        });
        self.baseline_sampled_at = now;
    }
}

/// Classification of detected fraud activity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FraudType {
    /// Sudden volume increase from a single source.
    VolumeSpike,
    /// Short-duration calls to the same number prefix (premium fraud).
    Wangiri,
    /// Calls to sequential number ranges (toll fraud probing).
    SequentialScanning,
    /// Call placed outside configured business hours.
    OffHours,
}

/// Alert produced when fraud activity is detected.
#[derive(Debug, Clone)]
pub struct FraudAlert {
    /// Source IP address of the suspicious traffic.
    pub src_ip: IpAddr,
    /// Type of fraud detected.
    pub alert_type: FraudType,
    /// Human-readable description of the detection.
    pub detail: String,
}

/// Maximum entries in the call patterns map.
const MAX_PATTERN_ENTRIES: usize = 10_000;

/// The trigger points of the four fraud heuristics.
///
/// Every field was a private constant with a comment describing when to change
/// it and no way to. They are not universal numbers: three seconds is under a
/// normal ring-no-answer on some carriers, so a network whose unanswered calls
/// clear in two seconds reported every one of them as a wangiri lure, and a
/// network whose PBX places six calls a minute at shift change reported the
/// shift change as a volume spike.
///
/// The two windows are here for the same reason the counts are: they are
/// deployment properties, and a count is measured inside a window it cannot
/// reach past. Wangiri arriving as three short calls over ten minutes is
/// invisible at every setting of [`Self::wangiri_calls`] but one, and that one
/// reports every short call anywhere as a lure.
///
/// The baseline decay stays fixed beside them, and `BASELINE_DECAY` says why:
/// it is denominated in windows, so it holds its relationship to the window at
/// every width. The memory caps (`MAX_PATTERN_ENTRIES`,
/// `MAX_SHORT_CALLS_PER_SOURCE`) are not here either: they bound sipnab's
/// footprint, not the network's behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FraudThresholds {
    /// Measured duration below which a completed call counts as "short".
    pub short_call_secs: u64,
    /// Short calls to one destination prefix before wangiri is reported.
    pub wangiri_calls: u32,
    /// Consecutive refused numbers before sequential scanning is reported.
    pub sequential_calls: usize,
    /// Multiple of a source's own baseline rate that counts as a spike.
    pub volume_multiplier: u32,
    /// Calls a source must place in the window before a spike can be reported.
    pub volume_min_calls: u32,
    /// Capture time one volume-spike window spans, in seconds.
    ///
    /// The count and the baseline are both measured over this, so a steady
    /// source reads the same at any width. What the width alone decides is how
    /// concentrated a burst has to be: a burst shorter than the window is
    /// averaged into the ordinary traffic beside it.
    pub volume_window_secs: u64,
    /// Capture time one wangiri window spans, in seconds.
    ///
    /// Short calls older than this are forgotten, so this is the outer bound on
    /// how slowly a lure may arrive and still be counted as one pattern.
    pub wangiri_window_secs: u64,
}

impl FraudThresholds {
    /// The shipped trigger points, used when the operator declares nothing.
    pub const BUILT_IN: Self = Self {
        short_call_secs: SHORT_CALL_SECS,
        wangiri_calls: WANGIRI_THRESHOLD,
        sequential_calls: SEQUENTIAL_THRESHOLD,
        volume_multiplier: VOLUME_SPIKE_MULTIPLIER,
        volume_min_calls: VOLUME_SPIKE_MIN_CALLS,
        volume_window_secs: VOLUME_WINDOW_SECS,
        wangiri_window_secs: WANGIRI_WINDOW_SECS,
    };

    /// The volume-spike window as a capture-time span.
    #[must_use]
    pub fn volume_window(&self) -> TimeDelta {
        TimeDelta::seconds(self.volume_window_secs as i64)
    }

    /// The wangiri window as a capture-time span.
    #[must_use]
    pub fn wangiri_window(&self) -> TimeDelta {
        TimeDelta::seconds(self.wangiri_window_secs as i64)
    }

    /// The widest window any of these detections reasons over.
    ///
    /// The caller that sweeps detector state ages it against this: state swept
    /// sooner than the widest window truncates that window to the sweep age,
    /// which would make the two settable windows above settable only up to a
    /// constant somewhere else.
    #[must_use]
    pub fn widest_window_secs(&self) -> u64 {
        self.volume_window_secs
            .max(self.wangiri_window_secs)
            .max(SEQUENTIAL_WINDOW_SECS)
    }
}

impl Default for FraudThresholds {
    fn default() -> Self {
        Self::BUILT_IN
    }
}

/// Detects toll fraud patterns in SIP call traffic.
pub struct FraudDetector {
    /// Per-source call pattern tracking.
    call_patterns: HashMap<IpAddr, CallPattern>,
    /// The trigger points this detector applies.
    thresholds: FraudThresholds,
    /// Configured business hours as `(start_hour, end_hour)` in 24h format.
    /// `None` disables off-hours detection.
    business_hours: Option<(u8, u8)>,
    /// Capture time of the most recent message checked — the detector's
    /// "now". `None` before the first message.
    ///
    /// The volume and wangiri windows used to be paced by
    /// `std::time::Instant`, which is the clock of the machine doing the
    /// reading rather than of the traffic being read. Live the two agree; a
    /// packet is timestamped as it arrives. Offline they do not: a file is
    /// replayed as fast as the disk allows, so the pruning step never dropped
    /// anything, `calls` became every INVITE the source had ever sent, and
    /// "N calls in 60s" was really a lifetime total. Against the real corpus a
    /// source whose busiest minute held four calls was reported as six in
    /// sixty seconds.
    ///
    /// Same defect [`crate::app::batch::SweepClock`] fixed for the dialog and
    /// stream sweeps, applied where the clock is already to hand: every
    /// message carries its capture timestamp.
    ///
    /// Never moves backwards — one reordered packet must not rewind the sweep
    /// horizon.
    latest_packet: Option<DateTime<Utc>>,
    /// Ticks once per tracked source touched; the value stamped into
    /// [`CallPattern::last_used`] to order eviction.
    use_counter: u64,
}

impl FraudDetector {
    /// Create a new fraud detector.
    ///
    /// # Arguments
    ///
    /// * `business_hours` — Optional business hours as `(start_hour, end_hour)`
    ///   in 24-hour format. Calls outside this window trigger off-hours alerts.
    ///   For example, `Some((8, 18))` means 08:00-18:00.
    pub fn new(business_hours: Option<(u8, u8)>) -> Self {
        Self::with_thresholds(business_hours, FraudThresholds::BUILT_IN)
    }

    /// Create a fraud detector with explicit trigger points.
    ///
    /// # Arguments
    ///
    /// * `business_hours` — as [`Self::new`].
    /// * `thresholds` — see [`FraudThresholds`]; `FraudThresholds::BUILT_IN`
    ///   reproduces [`Self::new`].
    pub fn with_thresholds(business_hours: Option<(u8, u8)>, thresholds: FraudThresholds) -> Self {
        Self {
            call_patterns: HashMap::new(),
            business_hours,
            thresholds,
            latest_packet: None,
            use_counter: 0,
        }
    }

    /// The per-source pattern for `src`, first seen at `now`, creating it if
    /// needed and enforcing the entry cap (H4) by evicting the least recently
    /// used source.
    fn pattern_for(&mut self, src: IpAddr, now: DateTime<Utc>) -> &mut CallPattern {
        if self.call_patterns.len() >= MAX_PATTERN_ENTRIES
            && !self.call_patterns.contains_key(&src)
            && let Some(oldest) = self
                .call_patterns
                .iter()
                .min_by_key(|(_, p)| p.last_used)
                .map(|(&ip, _)| ip)
        {
            self.call_patterns.remove(&oldest);
        }
        self.use_counter += 1;
        let use_counter = self.use_counter;
        let pattern = self
            .call_patterns
            .entry(src)
            .or_insert_with(|| CallPattern::new(now, use_counter));
        pattern.last_used = use_counter;
        pattern
    }

    /// Record a finished call whose measured duration was short, and report
    /// wangiri if that pushed a prefix over the threshold.
    ///
    /// A call's duration is not knowable when it starts. The dialog is created
    /// from the INVITE, so at the moment the INVITE is analyzed `created_at`
    /// and `updated_at` are the same timestamp and every call measures zero
    /// seconds — which is how three 200-second conversations were reported as
    /// "3 short calls in 60s". It IS knowable when the call ends, which is
    /// what this reads: the dialog has reached a terminal state, and the span
    /// from its first message to its last is the call.
    ///
    /// # Returns
    ///
    /// A wangiri alert when this call completed a prefix's
    /// [`FraudThresholds::wangiri_calls`], else `None`. `None` for any message that is not
    /// the end of an INVITE dialog, and for a call already recorded — the
    /// `200 OK` to a `BYE` arrives after the dialog is already terminal and
    /// must not count the call twice.
    ///
    /// Only `Completed` and `Canceled` count. Wangiri is a call that CONNECTED
    /// and was cut, or rang and was pulled — the caller's choice either way,
    /// which is what makes it a lure. A `Failed` dialog is one the NETWORK
    /// refused, and a `404` comes back in milliseconds, so counting those made
    /// every run of wrong numbers three short calls to a prefix. It also
    /// masked the sequential-scanning signal, which is what a run of wrong
    /// numbers actually is.
    fn record_if_short_call(&mut self, msg: &SipMessage, dialog: &SipDialog) -> Option<FraudAlert> {
        if dialog.method != crate::sip::SipMethod::Invite
            || !matches!(
                dialog.state(),
                DialogState::Completed | DialogState::Canceled
            )
        {
            return None;
        }
        let call_id = dialog.call_id.as_str();
        let src = dialog.src_addr;
        let now = msg.timestamp;
        let thresholds = self.thresholds;

        // The call's own span, from its first message to its last.
        let duration = dialog.updated_at.signed_duration_since(dialog.created_at);
        if duration >= TimeDelta::seconds(thresholds.short_call_secs as i64) {
            return None;
        }
        let destination = dialog.to_user.clone().unwrap_or_default();

        let pattern = self.pattern_for(src, now);
        pattern
            .short_calls
            .retain(|_, (t, _)| now.signed_duration_since(*t) < thresholds.wangiri_window());
        if pattern.short_calls.contains_key(call_id) {
            return None; // already counted: a later message of a finished call
        }
        if pattern.short_calls.len() >= MAX_SHORT_CALLS_PER_SOURCE {
            return None;
        }
        pattern
            .short_calls
            .insert(call_id.to_string(), (now, destination));

        check_wangiri(src, pattern, now, &thresholds)
    }

    /// Record a call the network refused, and report sequential scanning if
    /// that completed a run of consecutive numbers.
    ///
    /// Whether a number is there is knowable only once the call ends, which is
    /// the same reason [`Self::record_if_short_call`] waits: at the moment the
    /// INVITE is analyzed the dialog has no outcome yet. A `Failed` dialog is
    /// one a final `4xx`, `5xx` or `6xx` ended. `Canceled` deliberately does
    /// not count — the CALLER gave up, which says nothing about the number —
    /// and neither does `Redirected`, where a `3xx` sent the call somewhere
    /// else rather than saying it did not exist.
    ///
    /// # Returns
    ///
    /// A sequential-scanning alert when this refusal completed a run of
    /// [`FraudThresholds::sequential_calls`] consecutive numbers, else `None`.
    fn record_if_refused_call(
        &mut self,
        msg: &SipMessage,
        dialog: &SipDialog,
    ) -> Option<FraudAlert> {
        if dialog.method != crate::sip::SipMethod::Invite || dialog.state() != &DialogState::Failed
        {
            return None;
        }
        let call_id = dialog.call_id.as_str();
        let src = dialog.src_addr;
        let now = msg.timestamp;
        let thresholds = self.thresholds;
        let destination = dialog.to_user.clone().unwrap_or_default();

        let pattern = self.pattern_for(src, now);
        pattern.refused_calls.retain(|_, (t, _)| {
            now.signed_duration_since(*t) < TimeDelta::seconds(SEQUENTIAL_WINDOW_SECS as i64)
        });
        if pattern.refused_calls.contains_key(call_id)
            || pattern.refused_calls.len() >= MAX_SHORT_CALLS_PER_SOURCE
        {
            return None;
        }
        pattern
            .refused_calls
            .insert(call_id.to_string(), (now, destination));

        check_sequential(src, pattern, thresholds.sequential_calls)
    }

    /// Check a SIP message and its associated dialog for fraud indicators.
    ///
    /// Only INVITE requests are analyzed. Returns the first matching fraud
    /// alert, or `None` if no fraud is detected.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage, dialog: &SipDialog) -> Option<FraudAlert> {
        // Advance the capture clock before any early return, so `sweep` still
        // ages state out over a stretch of capture that held no INVITEs.
        if self
            .latest_packet
            .is_none_or(|latest| msg.timestamp > latest)
        {
            self.latest_packet = Some(msg.timestamp);
        }

        // A call that has just ended is the only place its duration can be
        // measured; this is what feeds wangiri.
        if let Some(alert) = self.record_if_short_call(msg, dialog) {
            return Some(alert);
        }
        // Whether a number is there is knowable only once the call ends too.
        if let Some(alert) = self.record_if_refused_call(msg, dialog) {
            return Some(alert);
        }

        // Only analyze INVITE requests
        if !msg.is_request || msg.method.as_ref() != Some(&crate::sip::SipMethod::Invite) {
            return None;
        }

        let destination = msg.to_user().unwrap_or_default();
        let now = msg.timestamp;
        let business_hours = self.business_hours;
        let thresholds = self.thresholds;
        let pattern = self.pattern_for(msg.src_addr, now);

        // Record the call
        pattern.calls.push((now, destination.clone()));

        // Prune calls outside the volume window. Strictly outside: a call
        // exactly VOLUME_WINDOW_SECS old is not one of the calls "in 60s", and
        // the `<=` on a truncated `as_secs()` this replaces made the window 61
        // seconds wide while every alert it produced said 60.
        pattern
            .calls
            .retain(|(t, _)| now.signed_duration_since(*t) < thresholds.volume_window());
        pattern
            .short_calls
            .retain(|_, (t, _)| now.signed_duration_since(*t) < thresholds.wangiri_window());

        // Whatever this call turns out to raise, the baseline moves first.
        pattern.sample_baseline(now, thresholds.volume_window());

        // Off-hours detection
        if let Some((start, end)) = business_hours {
            let hour = msg.timestamp.hour() as u8;
            let outside = if start <= end {
                hour < start || hour >= end
            } else {
                // Wraps midnight: e.g., (22, 6) means 22:00-06:00 is business
                hour < start && hour >= end
            };
            if outside {
                return Some(FraudAlert {
                    src_ip: msg.src_addr,
                    alert_type: FraudType::OffHours,
                    detail: format!(
                        "call at {}:00 outside business hours ({start}:00-{end}:00)",
                        hour
                    ),
                });
            }
        }

        // Volume spike detection. A spike is a departure from what this source
        // normally does, so it needs a baseline the source itself established:
        // no window completed, nothing to depart from. The comparison is in
        // f64 because truncating the baseline to a `u32` judged a source that
        // had worked its way up to 4.9 calls a minute against 4.
        if let Some(baseline) = pattern.baseline_rate {
            let current_count = pattern.calls.len() as u32;
            if current_count >= thresholds.volume_min_calls
                && f64::from(current_count) > baseline * f64::from(thresholds.volume_multiplier)
            {
                return Some(FraudAlert {
                    src_ip: msg.src_addr,
                    alert_type: FraudType::VolumeSpike,
                    detail: format!(
                        "{current_count} calls in {}s (baseline: {baseline:.1}/window)",
                        thresholds.volume_window_secs
                    ),
                });
            }
        }

        // Wangiri detection: short calls to same prefix
        check_wangiri(msg.src_addr, pattern, now, &thresholds)
    }

    /// Remove call pattern entries whose calls are older than `max_age` **in
    /// capture time**.
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
        for pattern in self.call_patterns.values_mut() {
            pattern
                .calls
                .retain(|(t, _)| now.signed_duration_since(*t) < max_age);
            pattern
                .short_calls
                .retain(|_, (t, _)| now.signed_duration_since(*t) < max_age);
            pattern
                .refused_calls
                .retain(|_, (t, _)| now.signed_duration_since(*t) < max_age);
        }
        // Drop sources with nothing left to remember.
        self.call_patterns.retain(|_, p| {
            !p.calls.is_empty() || !p.short_calls.is_empty() || !p.refused_calls.is_empty()
        });
    }
}

/// Check for wangiri pattern: multiple short calls to the same number prefix.
///
/// The tally walks `short_calls` — the calls whose measured duration came in
/// under `SHORT_CALL_SECS`. It used to walk `calls`, every call in the window
/// whatever its duration, gated only on a *count* of short calls that could
/// have come from anywhere: so a source with three short calls to three
/// different destinations had its ordinary conversations counted too, and the
/// prefix the alert named could be one where nothing short had ever happened.
/// The alert says "N short calls to prefix P", and now N and P come from the
/// short calls themselves.
///
/// `now` is capture time — the timestamp of the message being analyzed.
///
/// Iteration order over the prefix map is unspecified, so the alert names the
/// prefix with the most short calls (ties broken by the prefix itself). Two
/// prefixes over the threshold in the same window otherwise produced a
/// different alert run to run over identical input.
fn check_wangiri(
    src_ip: IpAddr,
    pattern: &CallPattern,
    now: DateTime<Utc>,
    thresholds: &FraudThresholds,
) -> Option<FraudAlert> {
    let wangiri_calls = thresholds.wangiri_calls;
    if (pattern.short_calls.len() as u32) < wangiri_calls {
        return None;
    }

    // Group recent short calls by prefix (first 6 characters of the number).
    let mut prefix_counts: HashMap<&str, u32> = HashMap::new();
    for (t, dest) in pattern.short_calls.values() {
        if now.signed_duration_since(*t) >= thresholds.wangiri_window() {
            continue;
        }
        // Slice on a character boundary: a destination is normally digits, but
        // it comes off the wire and `[..6]` on a multi-byte character panics.
        let prefix = dest
            .char_indices()
            .nth(6)
            .map_or(dest.as_str(), |(i, _)| &dest[..i]);
        if !prefix.is_empty() {
            *prefix_counts.entry(prefix).or_insert(0) += 1;
        }
    }

    let (prefix, count) = prefix_counts
        .iter()
        .max_by_key(|(prefix, count)| (**count, std::cmp::Reverse(**prefix)))?;
    if *count < wangiri_calls {
        return None;
    }
    Some(FraudAlert {
        src_ip,
        alert_type: FraudType::Wangiri,
        detail: format!(
            "{count} short calls to prefix '{prefix}' in {}s",
            thresholds.wangiri_window_secs
        ),
    })
}

/// Check for sequential number scanning (N, N+1, N+2, ...).
///
/// The run is taken over the calls the network REFUSED, not over every call in
/// the window. A hunt group, a DID block and a dial-plan walk all produce the
/// same consecutive numbers; only the walk's numbers are not there.
fn check_sequential(
    src_ip: IpAddr,
    pattern: &CallPattern,
    sequential_calls: usize,
) -> Option<FraudAlert> {
    if pattern.refused_calls.len() < sequential_calls {
        return None;
    }

    // Extract numeric destinations and sort
    let mut numbers: Vec<u64> = pattern
        .refused_calls
        .values()
        .filter_map(|(_, dest)| {
            // Strip any leading '+' and parse as integer
            let cleaned: String = dest.chars().filter(|c| c.is_ascii_digit()).collect();
            cleaned.parse::<u64>().ok()
        })
        .collect();

    numbers.sort_unstable();
    numbers.dedup();

    if numbers.len() < sequential_calls {
        return None;
    }

    // Look for runs of sequential numbers
    let mut run_length = 1_usize;
    for window in numbers.windows(2) {
        if window[1] == window[0] + 1 {
            run_length += 1;
            if run_length >= sequential_calls {
                return Some(FraudAlert {
                    src_ip,
                    alert_type: FraudType::SequentialScanning,
                    detail: format!(
                        "sequential dialing detected: {run_length} consecutive numbers ending at {}",
                        window[1]
                    ),
                });
            }
        } else {
            run_length = 1;
        }
    }

    None
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for the toll-fraud detection heuristics.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::dialog::SipDialog;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback address used as the destination in test messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// The source IP used to simulate an attacker.
    fn attacker_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))
    }

    /// A fixed timestamp inside default business hours (14:00 UTC).
    fn ts() -> DateTime<Utc> {
        // Use a time that's within default business hours (14:00 UTC)
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 14, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build an INVITE to `to_user` from `src` with the given Call-ID.
    fn make_invite(to_user: &str, src: IpAddr, call_id: &str) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{to_user}@example.com SIP/2.0"),
            &[
                "From: <sip:attacker@example.com>;tag=f1",
                &format!("To: <sip:{to_user}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
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

    /// Create a dialog from a SIP message.
    fn make_dialog_from_msg(msg: &SipMessage) -> SipDialog {
        SipDialog::new(msg).expect("should create dialog")
    }

    /// Multiple short calls to the same number prefix trigger a wangiri alert.
    ///
    /// Each call is placed and hung up, because that is when a call's duration
    /// becomes knowable. This test used to hand the detector a dialog whose
    /// `created_at` and `updated_at` it had set one second apart by hand — a
    /// dialog no capture produces at the moment an INVITE is analyzed, and the
    /// reason the defect survived: the fixture supplied the very measurement
    /// the code could not make.
    #[test]
    fn wangiri_pattern_detected() {
        // Non-consecutive numbers under one prefix, so sequential scanning
        // cannot fire instead.
        let alerts = replay(
            &[
                call("+44900111", 0, 1),
                call("+44900222", 4, 1),
                call("+44900444", 8, 1),
                call("+44900777", 12, 1),
                call("+44900999", 16, 1),
            ],
            attacker_ip(),
        );
        let wangiri = details(&alerts, &FraudType::Wangiri);
        let first = wangiri.first().expect("should detect wangiri pattern");
        assert!(first.contains("short calls to prefix"), "got {first:?}");
    }

    /// The two wangiri thresholds agree: `WANGIRI_THRESHOLD - 1` short calls
    /// to one prefix raise no alert, the `WANGIRI_THRESHOLD`-th raises one.
    /// (The entry gate and the per-prefix trigger both use the "minimum
    /// short calls" semantics of `WANGIRI_THRESHOLD`.)
    #[test]
    fn wangiri_triggers_exactly_at_threshold() {
        // Same "+44900" prefix, deliberately non-consecutive numbers so
        // sequential-scanning detection cannot fire instead.
        let dests = ["+44900111", "+44900555", "+44900999"];
        assert_eq!(dests.len(), WANGIRI_THRESHOLD as usize);
        let calls: Vec<Call<'_>> = dests
            .iter()
            .enumerate()
            .map(|(i, d)| call(d, i as i64 * 4, 1))
            .collect();

        let below = replay(&calls[..WANGIRI_THRESHOLD as usize - 1], attacker_ip());
        assert!(
            details(&below, &FraudType::Wangiri).is_empty(),
            "{} short calls are below the threshold of {WANGIRI_THRESHOLD}",
            WANGIRI_THRESHOLD - 1
        );

        let at_threshold = replay(&calls, attacker_ip());
        assert!(
            !details(&at_threshold, &FraudType::Wangiri).is_empty(),
            "the WANGIRI_THRESHOLD-th short call to a prefix must raise the alert"
        );
    }

    /// Calls to consecutive numbers that do not exist trigger a
    /// sequential-scanning alert.
    ///
    /// The calls are refused rather than merely placed, because a run of
    /// consecutive numbers is only a scan when the numbers are not there — see
    /// [`a_hunt_group_answered_in_order_is_not_sequential_scanning`]. This test
    /// used to hand the detector a dialog whose duration it had set by hand,
    /// which no capture produces at the moment an INVITE is analyzed.
    #[test]
    fn sequential_scanning_detected() {
        let alerts = replay_refused(&DIDS[..5], attacker_ip());
        let alert = alerts
            .iter()
            .find(|a| a.alert_type == FraudType::SequentialScanning)
            .expect("should detect sequential scanning");
        assert!(alert.detail.contains("sequential dialing"));
    }

    /// Normal calls of realistic duration to distinct numbers raise no alert.
    #[test]
    fn normal_call_pattern_not_detected() {
        let mut detector = FraudDetector::new(None);
        let src = attacker_ip();

        // Two normal calls to different destinations with realistic durations
        let msg1 = make_invite("+18005551234", src, "normal-1@test");
        let mut dialog1 = make_dialog_from_msg(&msg1);
        dialog1.updated_at = dialog1.created_at + TimeDelta::seconds(120);
        assert!(detector.check(&msg1, &dialog1).is_none());

        let msg2 = make_invite("+442071234567", src, "normal-2@test");
        let mut dialog2 = make_dialog_from_msg(&msg2);
        dialog2.updated_at = dialog2.created_at + TimeDelta::seconds(180);
        assert!(
            detector.check(&msg2, &dialog2).is_none(),
            "normal calls should not trigger fraud detection"
        );
    }

    /// A call placed outside configured business hours triggers an off-hours
    /// alert.
    #[test]
    fn off_hours_detection() {
        let mut detector = FraudDetector::new(Some((8, 18)));

        // Create a message at 03:00 (outside business hours)
        let raw = build_sip(
            "INVITE sip:+18005551234@example.com SIP/2.0",
            &[
                "From: <sip:caller@example.com>;tag=f1",
                "To: <sip:+18005551234@example.com>",
                "Call-ID: offhours@test",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let early_ts = chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 3, 0, 0).unwrap();
        let msg = parse_sip(
            &raw,
            early_ts,
            attacker_ip(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        let dialog = make_dialog_from_msg(&msg);

        let alert = detector.check(&msg, &dialog);
        assert!(alert.is_some(), "should detect off-hours call");
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, FraudType::OffHours);
        assert!(alert.detail.contains("outside business hours"));
    }

    // ── Measured call duration, and packet time ──────────────────────

    /// Capture time `secs` seconds after the fixed base timestamp.
    fn at(secs: i64) -> DateTime<Utc> {
        ts() + TimeDelta::seconds(secs)
    }

    /// Parse `raw` as arriving from `src` at capture time `when`.
    fn parse_at(raw: &[u8], src: IpAddr, when: DateTime<Utc>) -> SipMessage {
        parse_sip(raw, when, src, localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse")
    }

    /// An INVITE from the caller opening `call_id` towards `to_user`.
    fn invite_at(to_user: &str, src: IpAddr, call_id: &str, when: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{to_user}@example.com SIP/2.0"),
            &[
                "From: <sip:caller@example.com>;tag=f1",
                &format!("To: <sip:{to_user}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, src, when)
    }

    /// The callee's `200 OK` answering the INVITE of `call_id`.
    fn ok_at(to_user: &str, call_id: &str, when: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:caller@example.com>;tag=f1",
                &format!("To: <sip:{to_user}@example.com>;tag=t1"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, localhost(), when)
    }

    /// The caller's `BYE`, which ends the dialog.
    fn bye_at(to_user: &str, src: IpAddr, call_id: &str, when: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            &format!("BYE sip:{to_user}@example.com SIP/2.0"),
            &[
                "From: <sip:caller@example.com>;tag=f1",
                &format!("To: <sip:{to_user}@example.com>;tag=t1"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, src, when)
    }

    /// Feed one message the way `app::batch` does: through the dialog store
    /// first, then to the detector with the dialog the store now holds.
    ///
    /// The detector is only ever as good as what the caller hands it, and the
    /// whole wangiri defect lived in that seam — so the tests drive the real
    /// seam rather than a hand-built dialog that cannot occur.
    fn feed(
        store: &mut crate::sip::dialog_store::DialogStore,
        det: &mut FraudDetector,
        msg: &SipMessage,
    ) -> Option<FraudAlert> {
        store.process_message(msg.clone());
        let call_id = msg.call_id()?.to_string();
        let dialog = store.get(&call_id)?;
        det.check(msg, dialog)
    }

    /// One call in a scenario: destination, start offset in seconds from the
    /// base timestamp, and how many seconds it lasted.
    struct Call<'a> {
        /// Dialled number, which decides the wangiri prefix.
        dest: &'a str,
        /// Seconds after the base timestamp at which the INVITE was sent.
        start: i64,
        /// Seconds between the INVITE and the BYE.
        secs: i64,
    }

    /// A [`Call`] to `dest`, placed `start` seconds in and lasting `secs`.
    fn call(dest: &str, start: i64, secs: i64) -> Call<'_> {
        Call { dest, start, secs }
    }

    /// Replay `calls` through a dialog store and the detector **in capture
    /// order**, returning every alert raised.
    ///
    /// The messages of overlapping calls are interleaved by timestamp, the way
    /// a capture holds them — a per-call loop would hand the detector a BYE
    /// from one call before the INVITE of an earlier one, which is a timeline
    /// no capture contains and which the pruning logic is entitled to assume
    /// cannot happen.
    fn replay(calls: &[Call<'_>], src: IpAddr) -> Vec<FraudAlert> {
        let mut msgs: Vec<SipMessage> = Vec::new();
        for (i, c) in calls.iter().enumerate() {
            let call_id = format!("call-{i}@test");
            msgs.push(invite_at(c.dest, src, &call_id, at(c.start)));
            msgs.push(ok_at(
                c.dest,
                &call_id,
                at(c.start) + TimeDelta::milliseconds(500),
            ));
            msgs.push(bye_at(c.dest, src, &call_id, at(c.start + c.secs)));
        }
        msgs.sort_by_key(|m| m.timestamp);

        let mut store = crate::sip::dialog_store::DialogStore::new(1000, false);
        let mut det = FraudDetector::new(None);
        let mut alerts = Vec::new();
        for msg in &msgs {
            if let Some(a) = feed(&mut store, &mut det, msg) {
                alerts.push(a);
            }
        }
        alerts
    }

    /// A block of consecutive DIDs, the shape a hunt group and a dial-plan
    /// walk both have.
    const DIDS: &[&str] = &[
        "+15551000",
        "+15551001",
        "+15551002",
        "+15551003",
        "+15551004",
        "+15551005",
        "+15551006",
        "+15551007",
    ];

    /// The callee's final refusal of `call_id`.
    fn refused_at(status: u16, to_user: &str, call_id: &str, when: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} Not Found"),
            &[
                "From: <sip:caller@example.com>;tag=f1",
                &format!("To: <sip:{to_user}@example.com>;tag=t1"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, localhost(), when)
    }

    /// Replay one INVITE per destination, each refused with `404`, and return
    /// every alert raised.
    fn replay_refused(dests: &[&str], src: IpAddr) -> Vec<FraudAlert> {
        let mut store = crate::sip::dialog_store::DialogStore::new(1000, false);
        let mut det = FraudDetector::new(None);
        let mut alerts = Vec::new();
        for (i, dest) in dests.iter().enumerate() {
            let call_id = format!("refused-{i}@test");
            let start = at(i as i64 * 2);
            for msg in [
                invite_at(dest, src, &call_id, start),
                refused_at(404, dest, &call_id, start + TimeDelta::milliseconds(80)),
            ] {
                if let Some(a) = feed(&mut store, &mut det, &msg) {
                    alerts.push(a);
                }
            }
        }
        alerts
    }

    /// The alerts of `kind` in `alerts`, as their detail strings.
    fn details(alerts: &[FraudAlert], kind: &FraudType) -> Vec<String> {
        alerts
            .iter()
            .filter(|a| &a.alert_type == kind)
            .map(|a| a.detail.clone())
            .collect()
    }

    /// Calls that lasted minutes are not short calls.
    ///
    /// The duration was read off the dialog at the moment the INVITE arrived,
    /// when `updated_at` and `created_at` are the same timestamp by
    /// construction — the store has only just created it from this very
    /// message. Every call therefore measured zero seconds and every call was
    /// counted "short", so three ordinary conversations to one destination
    /// prefix were reported as three short calls. A call's duration is not
    /// knowable when it starts; it is knowable when it ends.
    #[test]
    fn calls_that_lasted_minutes_are_not_short_calls() {
        // Non-consecutive numbers so sequential scanning cannot fire instead;
        // three calls, so the volume path cannot either.
        let alerts = replay(
            &[
                call("+44900111", 0, 200),
                call("+44900555", 20, 200),
                call("+44900999", 40, 200),
            ],
            attacker_ip(),
        );
        let wangiri = details(&alerts, &FraudType::Wangiri);
        assert!(
            wangiri.is_empty(),
            "three calls of 200s each are not short calls, got {wangiri:?}"
        );
    }

    /// Three genuinely short calls to one prefix still raise wangiri — the
    /// duration test must not become a way to never detect anything.
    #[test]
    fn three_genuinely_short_calls_to_one_prefix_still_alert() {
        let alerts = replay(
            &[
                call("+44900111", 0, 1),
                call("+44900555", 5, 1),
                call("+44900999", 10, 1),
            ],
            attacker_ip(),
        );
        let wangiri = details(&alerts, &FraudType::Wangiri);
        let first = wangiri
            .first()
            .expect("three 1-second calls to one prefix is wangiri");
        assert!(
            first.contains("+44900"),
            "the alert must name the prefix it counted, got {first:?}"
        );
    }

    /// The per-prefix count is over SHORT calls, not over every call.
    ///
    /// The entry gate looked at a count of short calls, but the prefix
    /// tally that follows it walked `calls` — every call in the window,
    /// whatever its duration. So a source with enough short calls
    /// *anywhere* had its ordinary long calls counted, and the prefix the
    /// alert named could be one where nothing short ever happened.
    ///
    /// The source here has three genuinely short calls, so the entry gate is
    /// legitimately open however the duration is measured — this test is
    /// about the tally that follows it, and fails on the tally alone. Those
    /// three are to three DIFFERENT prefixes, so no prefix has three short
    /// calls. `+11111` reaches three only by counting two 200-second
    /// conversations alongside its one short call.
    #[test]
    fn wangiri_counts_short_calls_not_every_call() {
        let alerts = replay(
            &[
                call("+11111000", 0, 1),
                call("+22222000", 5, 1),
                call("+33333000", 10, 1),
                call("+11111444", 15, 200),
                call("+11111888", 20, 200),
            ],
            attacker_ip(),
        );
        let wangiri = details(&alerts, &FraudType::Wangiri);
        assert!(
            wangiri.is_empty(),
            "no prefix has {WANGIRI_THRESHOLD} SHORT calls — '+11111' has one, plus two \
             200-second conversations — got {wangiri:?}"
        );
    }

    /// The volume window counts what the capture says, not how long sipnab
    /// took to read it.
    ///
    /// Paced by `Instant::now()`, a file replayed from disk never prunes: the
    /// whole capture lands inside one wall-clock second, so `calls` is every
    /// INVITE the source ever sent and the "N calls in 60s" claim is a
    /// lifetime total. Measured against the real corpus, sources whose true
    /// busiest minute held four calls were reported as six in sixty seconds.
    #[test]
    fn volume_window_is_measured_in_packet_time() {
        // One call every 30s: at most three in any 60-second window, against a
        // minimum of VOLUME_SPIKE_MIN_CALLS.
        let dests: Vec<String> = (0..12)
            .map(|i| format!("+1800555{:04}", i * 7 + 1))
            .collect();
        let calls: Vec<Call<'_>> = dests
            .iter()
            .enumerate()
            .map(|(i, d)| call(d, i as i64 * 30, 20))
            .collect();
        let alerts = replay(&calls, attacker_ip());
        let spikes = details(&alerts, &FraudType::VolumeSpike);
        assert!(
            spikes.is_empty(),
            "one call every 30s is 3 per {VOLUME_WINDOW_SECS}s window, under the minimum of \
             {VOLUME_SPIKE_MIN_CALLS} — got {spikes:?}"
        );
    }

    /// The volume window is exactly `VOLUME_WINDOW_SECS` wide, not a second
    /// more.
    ///
    /// Pruning kept every call whose age `as_secs()` was `<=` the window, so a
    /// call 60.9 seconds old survived: the window was really 61 seconds while
    /// the alert text said 60. Six calls spread over exactly sixty seconds are
    /// six in 61 seconds and five in 60, which is the difference between
    /// alerting and not.
    #[test]
    fn the_volume_window_is_exactly_sixty_seconds() {
        let step = VOLUME_WINDOW_SECS as i64 / (VOLUME_SPIKE_MIN_CALLS as i64 - 1);
        let dests: Vec<String> = (0..VOLUME_SPIKE_MIN_CALLS)
            .map(|i| format!("+1800555{:04}", i * 7 + 1))
            .collect();
        let calls: Vec<Call<'_>> = dests
            .iter()
            .enumerate()
            .map(|(i, d)| call(d, i as i64 * step, 5))
            .collect();
        let alerts = replay(&calls, attacker_ip());
        let spikes = details(&alerts, &FraudType::VolumeSpike);
        assert!(
            spikes.is_empty(),
            "the first and last of these are exactly {VOLUME_WINDOW_SECS}s apart, so only \
             {} fall inside a {VOLUME_WINDOW_SECS}s window — got {spikes:?}",
            VOLUME_SPIKE_MIN_CALLS - 1
        );
    }

    // ── A run of numbers is a scan only when the numbers are not there ──

    /// A hunt group answered in order is not sequential scanning.
    ///
    /// A DID block is contiguous by definition, so a carrier delivering to it
    /// walks consecutive numbers all day. What makes a run reconnaissance is
    /// the same thing that makes a rate reconnaissance: the numbers were not
    /// there. Counted over every call whatever became of it, an ordinary
    /// eleven-second trunk capture reported 39 sequential scans.
    #[test]
    fn a_hunt_group_answered_in_order_is_not_sequential_scanning() {
        let calls: Vec<Call<'_>> = (0..8)
            .map(|i| Call {
                dest: DIDS[i],
                start: i as i64 * 2,
                secs: 30,
            })
            .collect();
        let alerts = replay(&calls, attacker_ip());
        let seq = details(&alerts, &FraudType::SequentialScanning);
        assert!(
            seq.is_empty(),
            "eight consecutive DIDs, every call answered and held for 30 seconds, \
             is a hunt group — got {seq:?}"
        );
    }

    /// Consecutive numbers the network refused are still sequential scanning.
    #[test]
    fn consecutive_numbers_the_network_refused_are_still_a_scan() {
        let alerts = replay_refused(&DIDS[..5], attacker_ip());
        let seq = details(&alerts, &FraudType::SequentialScanning);
        assert!(
            !seq.is_empty(),
            "five consecutive numbers, none of which exists, is a dial-plan walk — \
             got {alerts:?}"
        );
    }

    // ── A baseline has to be measured before it can be exceeded ──────

    /// A source calling at a steady, ordinary rate is never a volume spike.
    ///
    /// `baseline_rate` started at 1.0 — a number the constructor guessed, not
    /// one the source established — so the sixth call any source placed
    /// cleared `1 * VOLUME_SPIKE_MULTIPLIER` and was reported as five times
    /// its own baseline. A carrier trunk clears that in the first minute of
    /// every hour it carries.
    ///
    /// Two more things kept it there. The comparison truncated the baseline to
    /// a `u32`, so a source that had worked its way up to 4.9 calls a minute
    /// was still judged against 4. And the moving average that would have
    /// corrected the guess sat below every early return, so the first alert
    /// froze the baseline at the value that produced it, and every later call
    /// from that source alerted too.
    #[test]
    fn a_steady_ordinary_call_rate_is_not_a_spike() {
        // Twelve calls a minute for ten minutes, flat. Destinations are
        // non-consecutive and the calls last longer than SHORT_CALL_SECS, so
        // neither sequential scanning nor wangiri can fire instead.
        let dests: Vec<String> = (0..120)
            .map(|i| format!("+1800555{:04}", i * 7 + 1))
            .collect();
        let calls: Vec<Call<'_>> = dests
            .iter()
            .enumerate()
            .map(|(i, d)| call(d, i as i64 * 5, 4))
            .collect();
        let alerts = replay(&calls, attacker_ip());
        let spikes = details(&alerts, &FraudType::VolumeSpike);
        assert!(
            spikes.is_empty(),
            "a source that has done twelve calls a minute for ten minutes has a \
             baseline of twelve, and twelve is not {VOLUME_SPIKE_MULTIPLIER} times \
             twelve — got {spikes:?}"
        );
    }

    /// A source that was quiet and then bursts is still a volume spike.
    ///
    /// The baseline must be slow enough for a burst to exceed it: sampled once
    /// per call, it chases the burst and suppresses the very alert it exists
    /// to raise.
    #[test]
    fn a_quiet_source_that_bursts_is_still_a_spike() {
        let mut calls: Vec<Call<'_>> = Vec::new();
        let dests: Vec<String> = (0..30)
            .map(|i| format!("+1800555{:04}", i * 7 + 1))
            .collect();
        // Ten minutes at one call a minute, then a dozen inside ten seconds.
        for (i, d) in dests.iter().take(10).enumerate() {
            calls.push(call(d, i as i64 * 60, 30));
        }
        for (i, d) in dests.iter().skip(10).take(12).enumerate() {
            calls.push(call(d, 600 + i as i64, 4));
        }
        let alerts = replay(&calls, attacker_ip());
        let spikes = details(&alerts, &FraudType::VolumeSpike);
        assert!(
            !spikes.is_empty(),
            "a source that placed one call a minute for ten minutes and then twelve \
             in ten seconds is a spike — got {alerts:?}",
        );
    }

    /// Nothing is a spike before the source has completed a window.
    ///
    /// A baseline is a measurement, and there is none to be had until a full
    /// [`VOLUME_WINDOW_SECS`] has passed. Whatever a source does in its first
    /// window is the first thing known about it, so it cannot also be a
    /// departure from what is known about it.
    #[test]
    fn a_source_cannot_spike_before_it_has_a_baseline() {
        let dests: Vec<String> = (0..30)
            .map(|i| format!("+1800555{:04}", i * 7 + 1))
            .collect();
        let calls: Vec<Call<'_>> = dests
            .iter()
            .enumerate()
            .map(|(i, d)| call(d, i as i64, 4))
            .collect();
        let alerts = replay(&calls, attacker_ip());
        let spikes = details(&alerts, &FraudType::VolumeSpike);
        assert!(
            spikes.is_empty(),
            "30 calls inside the first {VOLUME_WINDOW_SECS}s window are the source's \
             whole history, not a departure from it — got {spikes:?}"
        );
    }

    /// A genuine burst inside one window still alerts, and reports a count the
    /// capture can account for.
    ///
    /// The source spends two minutes at one call a minute first, because a
    /// spike is a departure from an established rate and there is no departure
    /// from a rate nobody has established.
    #[test]
    fn a_real_burst_inside_one_minute_still_alerts() {
        let dests: Vec<String> = (0..VOLUME_SPIKE_MIN_CALLS + 2)
            .map(|i| format!("+1800555{:04}", i * 7 + 1))
            .collect();
        let mut calls: Vec<Call<'_>> = dests
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, d)| call(d, i as i64 * 60, 30))
            .collect();
        calls.extend(
            dests
                .iter()
                .skip(2)
                .enumerate()
                .map(|(i, d)| call(d, 120 + i as i64 * 2, 5)),
        );
        let alerts = replay(&calls, attacker_ip());
        let spikes = details(&alerts, &FraudType::VolumeSpike);
        let first = spikes
            .first()
            .expect("6 calls in 10s of capture time, from a source that has been doing one a minute, is a volume spike");
        assert!(
            first.contains(&format!("{VOLUME_SPIKE_MIN_CALLS} calls")),
            "the count must be the calls actually inside the window, got {first:?}"
        );
    }

    /// `sweep` ages call patterns out on capture time — in both directions.
    ///
    /// The two assertions pin the two ways a wrong clock goes wrong, and
    /// neither alone is enough. An `Instant`-paced sweep retains everything:
    /// offline the wall clock barely advances between the first packet of a
    /// capture and the last, so nothing is ever old enough to drop. A
    /// `Utc::now()`-paced sweep does the opposite on any capture not from
    /// today — every source is years idle the moment it is read, so the sweep
    /// empties the map and the detector forgets a source mid-pattern.
    #[test]
    fn sweep_ages_call_patterns_out_on_packet_time() {
        let mut store = crate::sip::dialog_store::DialogStore::new(1000, false);
        let mut det = FraudDetector::new(None);
        let (quiet, active) = (attacker_ip(), localhost());
        let _ = feed(
            &mut store,
            &mut det,
            &invite_at("+18005551234", quiet, "sweep-1@test", at(0)),
        );
        assert_eq!(det.call_patterns.len(), 1, "the source must be tracked");

        // A call 10 minutes later in capture time, then a 2-minute sweep.
        let _ = feed(
            &mut store,
            &mut det,
            &invite_at("+18005559999", active, "sweep-2@test", at(600)),
        );
        det.sweep(std::time::Duration::from_secs(120));
        assert!(
            !det.call_patterns.contains_key(&quiet),
            "a source last active 600s ago in capture time must not survive a 120s sweep"
        );
        assert!(
            det.call_patterns.contains_key(&active),
            "the source that placed the most recent call is 0s idle in capture time and \
             must survive — a sweep aged against `Utc::now()` drops it, because a capture \
             recorded before today is already older than any max_age"
        );
    }

    /// Non-INVITE requests (e.g. REGISTER) are ignored by the detector.
    #[test]
    fn non_invite_ignored() {
        let mut detector = FraudDetector::new(None);
        let raw = build_sip(
            "REGISTER sip:registrar@example.com SIP/2.0",
            &[
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>",
                "Call-ID: reg@test",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            attacker_ip(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        let dialog = make_dialog_from_msg(&msg);

        assert!(
            detector.check(&msg, &dialog).is_none(),
            "REGISTER should not trigger fraud detection"
        );
    }
}
