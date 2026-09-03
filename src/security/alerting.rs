// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rule-based alerting engine with cooldowns and external command execution.
//!
//! The alerting engine evaluates named rules with threshold/window/cooldown
//! parameters and deduplicates alerts per (source IP, rule name) pair.
//!
//! Rule grammar: `<metric>:<threshold>/<window>[:<cooldown>]`
//! - `5xx-rate:10/1m` — 10 events in 1 minute, cooldown auto (2 minutes)
//! - `reg-flood:50/10s:5m` — 50 events in 10 seconds, cooldown 5 minutes
//! - Window suffixes: `s` (seconds), `m` (minutes), `h` (hours)
//! - Default cooldown: window x 2

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::lru::LruMap;

#[cfg(feature = "native")]
use tracing::warn;

/// A single alerting rule with threshold, window, and cooldown.
#[derive(Debug, Clone)]
pub struct AlertRule {
    /// Rule name (e.g., `"5xx-rate"`, `"reg-flood"`).
    pub name: String,
    /// Number of events required to trigger within the window.
    pub threshold: u32,
    /// Time window for counting events.
    pub window: Duration,
    /// Minimum time between repeated alerts for the same source.
    pub cooldown: Duration,
}

impl AlertRule {
    /// Parse a rule from the grammar `<name>:<threshold>/<window>[:<cooldown>]`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sipnab::security::AlertRule;
    ///
    /// let rule = AlertRule::parse("5xx-rate:10/1m").unwrap();
    /// assert_eq!(rule.name, "5xx-rate");
    /// assert_eq!(rule.threshold, 10);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `crate::Error::InvalidAlertRule` if the grammar is invalid.
    pub fn parse(rule_str: &str) -> Result<Self, crate::Error> {
        Self::parse_inner(rule_str).map_err(|reason| crate::Error::InvalidAlertRule {
            input: rule_str.to_string(),
            reason,
        })
    }

    /// Parse the rule grammar, returning a human-readable reason string on
    /// failure (wrapped into a typed error by `parse`).
    ///
    /// # Errors
    ///
    /// Returns an `Err(String)` when the `:` or `/` separators are missing,
    /// the name is empty, the threshold is non-numeric, or a duration has an
    /// invalid suffix.
    fn parse_inner(rule_str: &str) -> Result<Self, String> {
        // Split into name:rest
        let (name, rest) = rule_str
            .split_once(':')
            .ok_or_else(|| format!("missing ':' in rule '{rule_str}' — expected <name>:<threshold>/<window>[:<cooldown>]"))?;

        if name.is_empty() {
            return Err(format!("empty rule name in '{rule_str}'"));
        }

        // Check for optional cooldown after the window
        let (threshold_window, cooldown_str) = if let Some((tw, cd)) = rest.split_once(':') {
            (tw, Some(cd))
        } else {
            (rest, None)
        };

        // Split threshold/window
        let (threshold_str, window_str) = threshold_window.split_once('/').ok_or_else(|| {
            format!("missing '/' in rule '{rule_str}' — expected <threshold>/<window>")
        })?;

        let threshold: u32 = threshold_str
            .parse()
            .map_err(|e| format!("invalid threshold '{threshold_str}': {e}"))?;

        let window = parse_duration(window_str)
            .ok_or_else(|| format!("invalid window '{window_str}' — use suffix s/m/h"))?;

        let cooldown = if let Some(cd) = cooldown_str {
            parse_duration(cd)
                .ok_or_else(|| format!("invalid cooldown '{cd}' — use suffix s/m/h"))?
        } else {
            // Default: window x 2
            window * 2
        };

        Ok(AlertRule {
            name: name.to_string(),
            threshold,
            window,
            cooldown,
        })
    }
}

/// Parse a duration string with suffix: `10s`, `5m`, `2h`.
///
/// Returns `None` if the format is invalid.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Split on the last character, not the last byte — a multibyte final
    // character (e.g. "10µ") would make `split_at(len - 1)` panic.
    let suffix = s.chars().next_back()?;
    let num_part = &s[..s.len() - suffix.len_utf8()];
    let value: u64 = num_part.parse().ok()?;

    match suffix {
        's' => Some(Duration::from_secs(value)),
        'm' => Some(Duration::from_secs(value * 60)),
        'h' => Some(Duration::from_secs(value * 3600)),
        _ => None,
    }
}

// ── Shared tumbling-window rate limiter ──────────────────────────────

/// A clock a [`TumblingWindow`] measures its window against.
///
/// Two paths in this crate spawn a process on the operator's behalf — the
/// alert engine below and [`crate::output::event_exec`] — and they run on
/// different clocks. Alerting measures everything in CAPTURE time, because
/// offline a whole capture elapses in milliseconds of wall time and a
/// wall-clock budget would either never refill or refill instantly. Event
/// exec fires from dialog and stream state and runs on `Instant`.
///
/// The *rule* is the same either way, so it is written once and the clock is
/// a parameter. This repo has twice been bitten by one rule having two
/// implementations that drifted apart; a second copy of a rate limiter would
/// be the third.
#[cfg(feature = "native")]
pub(crate) trait WindowClock: Copy {
    /// Whole seconds from `earlier` to `self`, saturating at zero when `self`
    /// is not after `earlier`.
    ///
    /// Saturating rather than signed is load-bearing, not defensive. Packet
    /// stamps go backwards — out of order on a merged capture, replayed on a
    /// crafted one, and attacker-influenced on a live interface. A window that
    /// rolled on a backwards jump would hand out a fresh budget for every
    /// stale stamp, which is the opposite of a rate limit.
    fn secs_since(self, earlier: Self) -> u64;
}

#[cfg(feature = "native")]
impl WindowClock for DateTime<Utc> {
    fn secs_since(self, earlier: Self) -> u64 {
        u64::try_from(self.signed_duration_since(earlier).num_seconds()).unwrap_or(0)
    }
}

#[cfg(feature = "native")]
impl WindowClock for std::time::Instant {
    fn secs_since(self, earlier: Self) -> u64 {
        self.saturating_duration_since(earlier).as_secs()
    }
}

/// A fixed (tumbling) window rate limiter: at most `limit` events per
/// `window_secs` of the clock `T`.
///
/// Tumbling, not sliding: the count and the window start reset the first time
/// an event arrives `window_secs` or more after the window began, not
/// continuously. That is the same shape the kill worker's `PerDstRateLimiter`
/// already uses, so all three limited paths behave alike under a burst.
///
/// Checking and booking are deliberately separate ([`Self::allows`] then
/// [`Self::record`]) so an action that was allowed but then failed to happen —
/// a spawn that errored — does not spend budget it never used.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct TumblingWindow<T> {
    /// Maximum events per window. Zero disables the limiter entirely.
    limit: u32,
    /// Window length in whole seconds; never zero.
    window_secs: u64,
    /// Start of the current window. `None` until the first event, so a limiter
    /// built long before its first event does not start mid-window.
    start: Option<T>,
    /// Events booked against the current window.
    count: u32,
}

#[cfg(feature = "native")]
impl<T: WindowClock> TumblingWindow<T> {
    /// Create a limiter of `limit` events per `window_secs`.
    ///
    /// A `limit` of 0 disables the limiter — every event is allowed — matching
    /// `--exec-rate-limit 0` on the event-exec path. A `window_secs` of 0 is
    /// clamped to 1: a zero-length window would roll on every event and
    /// silently disable the limit that was asked for.
    pub(crate) const fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            limit,
            window_secs: if window_secs == 0 { 1 } else { window_secs },
            start: None,
            count: 0,
        }
    }

    /// Roll the window if it has expired, then report whether one more event
    /// fits. Does not book the event — call [`Self::record`] once the action
    /// actually happened.
    pub(crate) fn allows(&mut self, now: T) -> bool {
        self.allows_with_reserved(now, 0)
    }

    /// [`Self::allows`], counting `reserved` events that have already been
    /// allowed but not yet booked.
    ///
    /// The gap between "allowed" and "booked" is deliberate: the budget is
    /// spent by [`Self::record`] once the action succeeded, so an allowed-but-
    /// failed spawn does not consume capacity it never used. A caller that
    /// *decides* an action under a lock and *performs* it after the lock drops
    /// widens that gap to hold several decisions at once, and each of them
    /// would consult a count none of them had yet incremented — a limit of N
    /// would let through N plus however many were in flight. Declaring the
    /// in-flight ones here closes that without moving the booking.
    pub(crate) fn allows_with_reserved(&mut self, now: T, reserved: u32) -> bool {
        if self.limit == 0 {
            return true;
        }
        match self.start {
            Some(start) if now.secs_since(start) < self.window_secs => {}
            _ => {
                self.start = Some(now);
                self.count = 0;
            }
        }
        self.count.saturating_add(reserved) < self.limit
    }

    /// Book one event against the current window.
    pub(crate) fn record(&mut self) {
        self.count = self.count.saturating_add(1);
    }

    /// Replace the limit, leaving the current window and its count alone so
    /// raising or lowering the limit mid-run cannot hand out a free window.
    pub(crate) fn set_limit(&mut self, limit: u32) {
        self.limit = limit;
    }
}

/// Maximum entries in the cooldowns map before eviction.
const MAX_COOLDOWN_ENTRIES: usize = 10_000;

/// Default capacity of the in-memory findings ring buffer (Phase 8.3).
pub const DEFAULT_FINDINGS_HISTORY: usize = 1000;

// ── `--alert-exec` budgets ───────────────────────────────────────────

/// Default `--alert-exec` commands per second of CAPTURE time, across all
/// sources.
///
/// Ten is not a new number: it is `--exec-rate-limit`'s default for
/// `--on-dialog-exec`/`--on-quality-exec` (`cli.rs`) and the scanner-kill
/// worker's `DEFAULT_RATE_LIMIT` (`process_isolation.rs`). Three paths that
/// act on the operator's behalf now share one budget shape, so an operator
/// who has tuned one has tuned their intuition for the others.
#[cfg(feature = "native")]
const DEFAULT_EXEC_PER_SECOND: u32 = 10;

/// Maximum `--alert-exec` commands per minute of CAPTURE time for any single
/// source IP.
///
/// This is the kill path's `MAX_PER_DST_PER_MINUTE`, and the reason is the
/// one `docs/design/threat-mitigation-hooks.md` §5(c) gives for it: the
/// failure that actually happens is *one* peer being misidentified, and a
/// global-only limiter would spend its whole budget on that one peer and stay
/// silent about everything else. Bounding per source bounds the blast radius
/// to the peer the signature was wrong about.
///
/// Fixed, with no knob reaching it. `--alert-exec` runs an operator's own
/// command line, so raising this multiplies whatever that command costs by the
/// number of times one misidentified peer may trigger it — and the peer that
/// triggers it is the peer sipnab got wrong, never a peer it got right.
/// Lowering it to zero silences every hook while the flag still reports itself
/// as armed, so an operator watching for alerts sees the same nothing a quiet
/// wire produces.
///
/// An operator who needs more headroom raises the global `--exec-rate-limit`.
/// That spends the extra budget across distinct sources, which is the shape
/// that helps; concentrating it on one source is the shape that hurts.
#[cfg(feature = "native")]
const MAX_EXEC_PER_SOURCE_PER_MINUTE: u32 = 3;

/// Maximum concurrently-running `--alert-exec` children.
///
/// A concurrency cap is not a rate — a command that exits immediately frees
/// its slot immediately — so this is the last line of the three checks, not
/// the only one it used to be. It still matters for a *slow* command, which
/// the budgets above cannot bound.
///
/// Fixed, because this is a fork-bomb bound rather than a tuning number. A
/// hundred children that never exit already hold a hundred process slots on a
/// host whose real job is keeping up with the wire; raising this hands a
/// misfiring signature the rest of the process table, and the capture starves
/// before the hooks do. Lowering it below the burst a legitimate alert storm
/// produces drops hooks that would have run — visibly, as
/// `ExecDropReason::QueueFull`, so the loss reaches a log rather than
/// vanishing.
///
/// An operator who genuinely needs more concurrency makes the hook itself
/// return faster, because a command that exits promptly frees its slot and
/// never reaches this cap at all. Raising the cap instead buys room for
/// commands that hang, which is the case it exists to survive.
#[cfg(feature = "native")]
const MAX_EXEC_CHILDREN: usize = 100;

/// Maximum per-source exec budgets tracked before LRU eviction.
///
/// Deliberately the same bound as the cooldown and event maps: the key is a
/// source IP and is therefore attacker-influenced on a live interface. An
/// attacker with more than this many source addresses can evict a bucket and
/// so reset one source's per-minute count, but reaching that state means
/// firing alerts from 10,000 distinct sources, and the global per-second
/// budget still applies to every one of them.
#[cfg(feature = "native")]
const MAX_EXEC_SOURCE_ENTRIES: usize = MAX_COOLDOWN_ENTRIES;

/// Why one `--alert-exec` invocation did not run.
///
/// Recorded per reason rather than as a single total because the reasons call
/// for different responses: a global-limit drop says the run is noisy overall,
/// a source-limit drop names a single peer, and a spawn failure means the
/// operator's command is broken rather than throttled.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ExecDropCounts {
    /// Suppressed because the global per-second budget was already spent.
    pub rate_limited: u64,
    /// Suppressed because that one source IP had spent its per-minute budget.
    pub source_limited: u64,
    /// Suppressed because `MAX_EXEC_CHILDREN` were still running.
    pub queue_full: u64,
    /// The spawn itself failed — no `sh`, fork limit, or the command is not
    /// executable. Counted here because from the operator's point of view the
    /// action did not happen, which is the question these counts answer.
    pub spawn_failed: u64,
}

#[cfg(feature = "native")]
impl ExecDropCounts {
    /// Total `--alert-exec` invocations that did not run, for any reason.
    pub fn total(&self) -> u64 {
        self.rate_limited
            .saturating_add(self.source_limited)
            .saturating_add(self.queue_full)
            .saturating_add(self.spawn_failed)
    }
}

/// Whether `n` is an exact power of ten (1, 10, 100, …).
///
/// Used to log suppressed execs at each order of magnitude. Warning on every
/// drop would make the log the flood it is reporting; warning once would hide
/// the scale. The exact totals are always available from
/// [`AlertEngine::exec_drops`].
#[cfg(feature = "native")]
fn is_order_of_magnitude(n: u64) -> bool {
    n > 0 && 10u64.checked_pow(n.ilog10()) == Some(n)
}

/// Single emitted finding — recorded in the ring buffer after the cooldown
/// check passes (so deduplicated firings aren't double-counted).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    /// Name of the rule that fired.
    pub rule_name: String,
    /// Source IP the finding is about.
    pub src_ip: IpAddr,
    /// Human-readable detail line.
    pub detail: String,
    /// When the finding fired.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Key an alert is tracked under: the source and the rule it matched.
type AlertKey = (IpAddr, String);

/// Recent event times for one key, newest last.
type EventWindow = std::collections::VecDeque<DateTime<Utc>>;

/// A sink handed each finding as it fires, for optional narration.
///
/// Boxed rather than a generic parameter because `AlertEngine` is stored behind
/// an `Arc<RwLock<..>>` in half a dozen places and making it generic would
/// spread a type parameter across all of them for one optional consumer.
///
/// The engine knows nothing about what narrates. That is deliberate: the MCP
/// server installs a sink that asks its own governor and talks to its own peer,
/// and `src/security/` has no business depending on `src/mcp/`.
pub type FindingSink = Box<dyn Fn(&Finding) + Send + Sync>;

/// Alerting engine that manages rules, cooldowns, and command execution.
pub struct AlertEngine {
    /// Configured alert rules.
    rules: Vec<AlertRule>,
    /// Optional sink notified for every finding this engine records.
    ///
    /// `None` on every run that has not installed one, which is the default and
    /// the common case.
    narrator: Option<FindingSink>,
    /// Per (source IP, rule name) cooldown tracking, in CAPTURE time.
    ///
    /// Packet time, not `Instant::now()`. Offline a whole capture elapses in
    /// milliseconds of wall time, so a wall-clock cooldown never expires and a
    /// wall-clock window never closes — the same defect that made the scanner
    /// detectors treat a replayed trunk as a flood.
    /// Value is when the pair last fired, in capture time. Bounded by
    /// [`MAX_COOLDOWN_ENTRIES`]: admitting a new pair past it evicts the one
    /// that fired least recently, in constant time.
    cooldowns: LruMap<AlertKey, DateTime<Utc>>,
    /// Recent event times per (source IP, rule name), newest last.
    ///
    /// Only the most recent `threshold` stamps are kept: if the oldest of those
    /// still falls inside the window then the threshold is met, and any older
    /// event cannot change that. That caps the memory a noisy source can cost
    /// at the threshold it configured. The map itself is bounded at
    /// [`MAX_COOLDOWN_ENTRIES`] by construction -- it used to be trimmed only
    /// after a key reached its threshold, so sources that never did grew it
    /// without bound -- evicting the least recently seen key in constant time.
    events: LruMap<AlertKey, EventWindow>,
    /// Optional external command template to execute on alert.
    /// After construction, legacy `%variable` placeholders are rewritten to
    /// `$SIPNAB_*` env var references. Values are passed via environment
    /// variables, never interpolated into the command string.
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    exec_cmd: Option<String>,
    /// Whether to send alerts to syslog via `libc::syslog()`.
    syslog_enabled: bool,
    /// Whether to emit each fired alert as a structured JSON line on stderr.
    json_output: bool,
    /// Tracked child processes from exec commands (for reaping).
    #[cfg(feature = "native")]
    children: Vec<std::process::Child>,
    /// Global `--alert-exec` budget, in CAPTURE time.
    ///
    /// The cooldown above bounds repeats against *one* (source, rule) pair and
    /// does nothing against many: a detector naming 180 peers passes 180
    /// cooldowns and used to spawn 180 processes, throttled only by how fast
    /// they exited. This is the bound that is a rate.
    #[cfg(feature = "native")]
    exec_rate: TumblingWindow<DateTime<Utc>>,
    /// Per-source `--alert-exec` budget, in CAPTURE time.
    ///
    /// Bounded by [`MAX_EXEC_SOURCE_ENTRIES`], evicting the source least
    /// recently consulted, in constant time, as the cooldown and event maps
    /// do.
    #[cfg(feature = "native")]
    exec_per_source: LruMap<IpAddr, TumblingWindow<DateTime<Utc>>>,
    /// `--alert-exec` invocations that did not run, by reason.
    #[cfg(feature = "native")]
    exec_drops: ExecDropCounts,
    /// `--alert-exec` commands actually spawned.
    #[cfg(feature = "native")]
    exec_spawned: u64,
    /// Phase 8.3 — bounded ring buffer of post-cooldown findings exposed
    /// via the MCP `security_findings` tool and the future
    /// `GET /v1/security/findings` REST endpoint. In-memory only.
    findings: std::collections::VecDeque<Finding>,
    /// Capacity of the findings ring buffer. Zero disables retention.
    findings_capacity: usize,
}

impl AlertEngine {
    /// Create a new alert engine.
    ///
    /// # Arguments
    ///
    /// * `rules` — Alert rules to evaluate.
    /// * `exec_cmd` — Optional command template. SIP data is passed via
    ///   `SIPNAB_SRC`, `SIPNAB_RULE`, and `SIPNAB_DETAIL` environment
    ///   variables. Legacy `%src`/`%rule`/`%detail` placeholders are
    ///   automatically migrated to `$SIPNAB_*` references.
    pub fn new(rules: Vec<AlertRule>, exec_cmd: Option<String>) -> Self {
        Self {
            rules,
            narrator: None,
            cooldowns: LruMap::new(MAX_COOLDOWN_ENTRIES),
            events: LruMap::new(MAX_COOLDOWN_ENTRIES),
            exec_cmd: exec_cmd.map(|c| migrate_alert_template(&c)),
            syslog_enabled: false,
            json_output: false,
            #[cfg(feature = "native")]
            children: Vec::new(),
            #[cfg(feature = "native")]
            exec_rate: TumblingWindow::new(DEFAULT_EXEC_PER_SECOND, 1),
            #[cfg(feature = "native")]
            exec_per_source: LruMap::new(MAX_EXEC_SOURCE_ENTRIES),
            #[cfg(feature = "native")]
            exec_drops: ExecDropCounts::default(),
            #[cfg(feature = "native")]
            exec_spawned: 0,
            findings: std::collections::VecDeque::with_capacity(DEFAULT_FINDINGS_HISTORY),
            findings_capacity: DEFAULT_FINDINGS_HISTORY,
        }
    }

    /// Override the default findings-history capacity. Setting 0 disables
    /// retention. Existing entries above the new cap are evicted oldest-first.
    /// Install a sink called for every finding this engine records.
    ///
    /// One sink, replaced rather than appended: two narrators is two budgets,
    /// and the one that drifts is the one nobody reads.
    ///
    /// Called with the finding AFTER it is recorded, so a sink that panics or
    /// blocks cannot cost the finding itself. The sink is expected to be cheap
    /// and non-blocking -- the MCP one asks a governor and spawns.
    pub fn set_narrator(&mut self, sink: Option<FindingSink>) {
        self.narrator = sink;
    }

    /// How many findings this engine retains for later retrieval.
    pub fn set_findings_capacity(&mut self, cap: usize) {
        self.findings_capacity = cap;
        while self.findings.len() > cap {
            self.findings.pop_front();
        }
    }

    /// Iterate stored findings filtered by rule kinds (empty = all) and
    /// updated-since timestamp. Returns up to `limit` matches, newest first.
    pub fn iter_findings(
        &self,
        kinds: &[&str],
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: usize,
    ) -> Vec<&Finding> {
        let mut out = Vec::with_capacity(limit.min(self.findings.len()));
        for f in self.findings.iter().rev() {
            if !kinds.is_empty() && !kinds.iter().any(|k| *k == f.rule_name) {
                continue;
            }
            if let Some(s) = since
                && f.timestamp <= s
            {
                continue;
            }
            out.push(f);
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    /// Enable or disable syslog output for alerts.
    ///
    /// When enabled, each alert is also sent to syslog at LOG_WARNING priority
    /// under the LOCAL0 facility. Call `init_syslog` once at startup before
    /// enabling this.
    pub fn set_syslog(&mut self, enabled: bool) {
        self.syslog_enabled = enabled;
    }

    /// Enable or disable the structured JSON alert channel.
    ///
    /// When enabled, each fired alert is also written as one JSON object per
    /// line to **stderr** (stdout is reserved for `--json` message output and
    /// the stdio MCP wire) — a stable machine channel for consumers that
    /// shouldn't have to scrape the human `[ALERT]` line.
    pub fn set_json_output(&mut self, enabled: bool) {
        self.json_output = enabled;
    }

    /// Fire an alert for the given type and source.
    ///
    /// Checks cooldown for the (source, alert_type) pair. If cooled down,
    /// formats the alert, writes to stderr, and optionally executes the
    /// configured command.
    ///
    /// Returns `true` if the alert was actually fired (not suppressed).
    ///
    /// `now` is the CAPTURE time of the event, not wall time. Every threshold
    /// and cooldown below is measured against it, so replaying a capture gives
    /// the same answer as watching it live.
    pub fn fire(
        &mut self,
        alert_type: &str,
        src_ip: IpAddr,
        detail: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let key = (src_ip, alert_type.to_string());

        // The rule's own threshold/window/cooldown, or the defaults for a type
        // nobody wrote a rule for: fire on the first event, then stay quiet for
        // a minute. A threshold of 1 keeps an unruled type behaving as it did.
        let rule = self.rules.iter().find(|r| r.name == alert_type);
        let threshold = rule.map_or(1, |r| r.threshold.max(1));
        let window = rule.map_or(Duration::ZERO, |r| r.window);
        let cooldown = rule.map_or(Duration::from_secs(60), |r| r.cooldown);

        // Record the event, keeping at most `threshold` stamps: if the oldest
        // of those is inside the window the threshold is met, and an older one
        // could not change that. Bounded by the operator's own threshold.
        let seen = self
            .events
            .get_or_insert_with(key.clone(), std::collections::VecDeque::new);
        seen.push_back(now);
        while seen.len() > threshold as usize {
            seen.pop_front();
        }
        let reached = seen.len() >= threshold as usize
            && seen.front().is_some_and(|oldest| {
                window.is_zero()
                    || now.signed_duration_since(*oldest)
                        <= chrono::Duration::from_std(window).unwrap_or(chrono::Duration::MAX)
            });
        if !reached {
            // Counted, not fired. The threshold is the operator's statement of
            // how much evidence is worth an alert, and honoring it is the
            // whole point of the field.
            return false;
        }

        // Check cooldown
        if let Some(last_fired) = self.cooldowns.peek(&key)
            && now.signed_duration_since(*last_fired)
                < chrono::Duration::from_std(cooldown).unwrap_or(chrono::Duration::MAX)
        {
            return false; // Still in cooldown
        }

        // Record this firing. The event and cooldown maps are bounded at
        // MAX_COOLDOWN_ENTRIES by construction -- a source per key is
        // attacker-influenced on a live interface -- and admitting a key
        // past the cap evicts the least recently used one in constant time,
        // which matters because this runs on the capture thread.
        self.cooldowns.insert(key, now);

        // Count it here, past the cooldown, so the metric matches what an
        // operator actually saw. Counting at entry would report every
        // suppressed repeat and make a single noisy source look like a storm —
        // which is the reading `sipnab_security_alerts_total` exists to give.
        super::record_alert(alert_type);

        // Sanitize attacker-controlled values for log output (M3)
        let sanitized_detail = sanitize_log_value(detail);

        let fired_at = chrono::Utc::now();

        // Phase 8.3 — store the finding in the ring buffer (after cooldown,
        // before any logging/syslog/exec) so deduplicated firings are
        // recorded once each.
        if self.findings_capacity > 0 {
            if self.findings.len() >= self.findings_capacity {
                self.findings.pop_front();
            }
            self.findings.push_back(Finding {
                rule_name: alert_type.to_string(),
                src_ip,
                detail: sanitized_detail.clone(),
                timestamp: fired_at,
            });
        }

        // The narrator sees the finding whether or not it was RETAINED: a
        // `findings_capacity` of zero is a retention setting, not a statement
        // that the finding did not happen, and narrating is not retention.
        if let Some(sink) = &self.narrator {
            sink(&Finding {
                rule_name: alert_type.to_string(),
                src_ip,
                detail: sanitized_detail.clone(),
                timestamp: fired_at,
            });
        }

        // Route through tracing so the subscriber controls destination
        // (stderr by default). Phase 8.0b: bare eprintln! would corrupt
        // stdio MCP if it ever fired during a session.
        tracing::warn!(
            target: "sipnab::alert",
            alert_type, %src_ip, %sanitized_detail,
            "{}", alert_log_line(alert_type, src_ip, &sanitized_detail)
        );

        // Structured machine channel: one JSON object per line on STDERR (the
        // MCP/`--json` wire is stdout, so stderr is safe even mid-session).
        if self.json_output {
            eprintln!(
                "{}",
                alert_json_line(alert_type, src_ip, &sanitized_detail, fired_at)
            );
        }

        // Send to syslog if enabled (native only — requires libc)
        #[cfg(feature = "native")]
        if self.syslog_enabled {
            send_to_syslog(&alert_log_line(alert_type, src_ip, &sanitized_detail));
        }

        // Execute command if configured — pass data via env vars, never interpolated
        #[cfg(feature = "native")]
        self.run_alert_exec(alert_type, src_ip, &sanitized_detail, now);

        true
    }

    /// Run the `--alert-exec` command for one fired alert, subject to the
    /// per-source budget, the global budget and the concurrency cap.
    ///
    /// The alert itself has already fired by the time this is called: it is in
    /// the log, on the JSON channel, in syslog and in the findings buffer.
    /// Only the operator's *action* is rate limited here, and that is the
    /// direction the failure has to take — the evidence must survive the
    /// conditions under which alerting matters most.
    ///
    /// # Side effects
    ///
    /// Reaps finished children, then spawns `sh -c <cmd>` without waiting for
    /// it. SIP data is passed exclusively via `SIPNAB_*` environment
    /// variables, never interpolated into the command string. Suppressed and
    /// failed invocations are counted (see [`Self::exec_drops`]).
    #[cfg(feature = "native")]
    fn run_alert_exec(
        &mut self,
        alert_type: &str,
        src_ip: IpAddr,
        detail: &str,
        now: DateTime<Utc>,
    ) {
        if self.exec_cmd.is_none() {
            return;
        }

        // Reap first, so a command that has already exited frees its slot
        // before the concurrency cap is consulted.
        self.children
            .retain_mut(|child| child.try_wait().ok().flatten().is_none());

        // Per-source first, then global. The order is what keeps a single
        // noisy peer from spending the budget every other peer needs: a source
        // that is over its own limit never touches the global window at all.
        if !self.source_allows_exec(src_ip, now) {
            self.note_exec_drop(ExecDropReason::SourceLimited, alert_type, src_ip);
            return;
        }
        if !self.exec_rate.allows(now) {
            self.note_exec_drop(ExecDropReason::RateLimited, alert_type, src_ip);
            return;
        }
        if self.children.len() >= MAX_EXEC_CHILDREN {
            self.note_exec_drop(ExecDropReason::QueueFull, alert_type, src_ip);
            return;
        }

        use std::process::Command;
        let mut command = Command::new("sh");
        if let Some(cmd) = &self.exec_cmd {
            command.arg("-c").arg(cmd);
        }
        command.env("SIPNAB_SRC", src_ip.to_string());
        command.env("SIPNAB_RULE", alert_type);
        command.env("SIPNAB_DETAIL", detail);

        match command.spawn() {
            Ok(child) => {
                // Book the budgets only now: an allowed-but-failed spawn did
                // not use the capacity it was granted.
                self.exec_rate.record();
                if let Some(window) = self.exec_per_source.get_mut(&src_ip) {
                    window.record();
                }
                self.exec_spawned = self.exec_spawned.saturating_add(1);
                self.children.push(child);
            }
            Err(e) => {
                warn!("Failed to execute alert command: {e}");
                self.note_exec_drop(ExecDropReason::SpawnFailed, alert_type, src_ip);
            }
        }
    }

    /// Whether `src_ip` has `--alert-exec` budget left in its own window,
    /// creating and touching its bucket.
    #[cfg(feature = "native")]
    fn source_allows_exec(&mut self, src_ip: IpAddr, now: DateTime<Utc>) -> bool {
        // Bounded like the cooldown and event maps: admitting a new source
        // past MAX_EXEC_SOURCE_ENTRIES evicts the least recently consulted
        // one, in constant time.
        self.exec_per_source
            .get_or_insert_with(src_ip, || {
                TumblingWindow::new(MAX_EXEC_PER_SOURCE_PER_MINUTE, 60)
            })
            .allows(now)
    }

    /// Book one suppressed `--alert-exec`, logging at each order of magnitude.
    ///
    /// Counting rather than only warning is the point: the defect being fixed
    /// is a dropped action whose only trace was one `warn` line, and a rate
    /// limiter that drops silently would move that defect rather than close
    /// it. A run can now say how many operator commands it swallowed and why,
    /// via [`Self::exec_drops`].
    #[cfg(feature = "native")]
    fn note_exec_drop(&mut self, reason: ExecDropReason, alert_type: &str, src_ip: IpAddr) {
        let counts = &mut self.exec_drops;
        let counter = match reason {
            ExecDropReason::RateLimited => &mut counts.rate_limited,
            ExecDropReason::SourceLimited => &mut counts.source_limited,
            ExecDropReason::QueueFull => &mut counts.queue_full,
            ExecDropReason::SpawnFailed => &mut counts.spawn_failed,
        };
        *counter = counter.saturating_add(1);

        let total = self.exec_drops.total();
        if is_order_of_magnitude(total) {
            warn!(
                target: "sipnab::alert",
                %src_ip,
                alert_type,
                reason = reason.as_str(),
                suppressed_total = total,
                rate_limited = self.exec_drops.rate_limited,
                source_limited = self.exec_drops.source_limited,
                queue_full = self.exec_drops.queue_full,
                spawn_failed = self.exec_drops.spawn_failed,
                "--alert-exec suppressed for src={src_ip} rule={alert_type} ({}); \
                 {total} command(s) not run so far. The alerts themselves still \
                 fired — only the command was held back.",
                reason.as_str()
            );
        }
    }

    /// Set the global `--alert-exec` budget in commands per second of CAPTURE
    /// time.
    ///
    /// Zero disables the global budget, matching `--exec-rate-limit 0` on the
    /// event-exec path. The per-source cap still applies, so an unlimited
    /// global budget is not an unlimited fork rate for any one peer.
    #[cfg(feature = "native")]
    pub fn set_exec_rate_limit(&mut self, per_second: u32) {
        self.exec_rate.set_limit(per_second);
    }

    /// `--alert-exec` invocations that did not run, by reason.
    #[cfg(feature = "native")]
    pub fn exec_drops(&self) -> ExecDropCounts {
        self.exec_drops
    }

    /// `--alert-exec` commands actually spawned.
    #[cfg(feature = "native")]
    pub fn exec_spawned(&self) -> u64 {
        self.exec_spawned
    }

    /// Return a reference to the configured rules.
    pub fn rules(&self) -> &[AlertRule] {
        &self.rules
    }
}

/// Why one `--alert-exec` invocation did not run.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy)]
enum ExecDropReason {
    /// The global per-second budget was already spent.
    RateLimited,
    /// The source IP had spent its per-minute budget.
    SourceLimited,
    /// `MAX_EXEC_CHILDREN` commands were still running.
    QueueFull,
    /// The spawn itself failed.
    SpawnFailed,
}

#[cfg(feature = "native")]
impl ExecDropReason {
    /// A short stable token for logs and structured fields.
    fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "global rate limit",
            Self::SourceLimited => "per-source rate limit",
            Self::QueueFull => "concurrent-command cap",
            Self::SpawnFailed => "spawn failed",
        }
    }
}

/// Report the `--alert-exec` totals once, at teardown.
///
/// Without this a run's last word on suppressed commands is whichever
/// order-of-magnitude line happened to be reached, which rounds 4,611 down to
/// "1000". A security tool that swallowed actions has to say exactly how many,
/// because "no entries" and "entries I did not print" are the two answers an
/// operator must never have to distinguish.
#[cfg(feature = "native")]
impl Drop for AlertEngine {
    fn drop(&mut self) {
        let drops = self.exec_drops;
        if drops.total() == 0 {
            return;
        }
        warn!(
            target: "sipnab::alert",
            spawned = self.exec_spawned,
            suppressed_total = drops.total(),
            rate_limited = drops.rate_limited,
            source_limited = drops.source_limited,
            queue_full = drops.queue_full,
            spawn_failed = drops.spawn_failed,
            "--alert-exec ran {} command(s) and suppressed {} \
             (global rate limit {}, per-source rate limit {}, \
             concurrent-command cap {}, spawn failed {}). \
             Every alert still fired; only the commands were held back.",
            self.exec_spawned,
            drops.total(),
            drops.rate_limited,
            drops.source_limited,
            drops.queue_full,
            drops.spawn_failed
        );
    }
}

/// Rewrite legacy `%variable` placeholders to `$SIPNAB_VARIABLE` references.
fn migrate_alert_template(template: &str) -> String {
    template
        .replace("%src", "$SIPNAB_SRC")
        .replace("%rule", "$SIPNAB_RULE")
        .replace("%detail", "$SIPNAB_DETAIL")
}

/// Sanitize attacker-controlled values for log output (CRLF injection prevention).
///
/// Replaces `\r` and `\n` with spaces to prevent log injection attacks.
pub fn sanitize_log_value(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// The one spelling of the human `[ALERT]` line.
///
/// Extracted because it is read as well as written. `security::recommend`
/// generates a fail2ban `failregex` against this exact shape, and a filter
/// whose log line has moved out from under it fails SILENTLY: the jail keeps
/// running, keeps reporting zero bans, and looks precisely like a quiet
/// network. That is the "a fact written twice, and the gate checks one copy"
/// defect, so there is now one copy — the tracing event, the syslog line and
/// the generated regex all derive from here.
///
/// # Arguments
///
/// * `alert_type` — the rule name that fired.
/// * `src_ip` — the source the finding names.
/// * `detail` — the detail string, **already sanitized** by
///   [`sanitize_log_value`]; this function does not sanitize, because its
///   callers hold the sanitized value and re-sanitizing would hide a caller
///   that forgot.
#[must_use]
pub fn alert_log_line(alert_type: &str, src_ip: std::net::IpAddr, detail: &str) -> String {
    format!("[ALERT] {alert_type} src={src_ip} {detail}")
}

/// Format one alert as a single JSON line for the `--alert-json` machine channel.
///
/// Fields: `ts` (RFC 3339), `alert` (type/rule), `src` (source IP), `detail`
/// (the sanitized detail string). serde_json escapes attacker-controlled values,
/// so a crafted UA/Call-ID can't break the line or inject fields.
pub fn alert_json_line(
    alert_type: &str,
    src_ip: IpAddr,
    detail: &str,
    ts: chrono::DateTime<chrono::Utc>,
) -> String {
    serde_json::json!({
        "ts": ts.to_rfc3339(),
        "alert": alert_type,
        "src": src_ip.to_string(),
        "detail": detail,
    })
    .to_string()
}

// ── Syslog support (native only — requires libc) ────────────────────

/// Initialize syslog with the "sipnab" ident.
///
/// Must be called once at startup before any `send_to_syslog()` calls.
/// Uses `LOG_LOCAL0` facility and `LOG_NDELAY | LOG_PID` options.
#[cfg(feature = "native")]
pub fn init_syslog() {
    // SAFETY: openlog with a static string is safe. We use a string literal
    // that lives for the entire program lifetime.
    unsafe {
        libc::openlog(
            c"sipnab".as_ptr(),
            libc::LOG_NDELAY | libc::LOG_PID,
            libc::LOG_LOCAL0,
        );
    }
    tracing::info!("Syslog output enabled (facility=LOCAL0)");
}

/// Send a message to syslog at LOG_WARNING priority.
///
/// The message is sanitized to remove null bytes before sending.
#[cfg(feature = "native")]
pub fn send_to_syslog(message: &str) {
    // Remove null bytes from message to prevent truncation
    let clean = message.replace('\0', "");
    if let Ok(msg) = std::ffi::CString::new(clean) {
        // SAFETY: syslog with a valid CString and %s format is safe.
        // We use "%s" as the format string to prevent format string attacks.
        unsafe {
            libc::syslog(
                libc::LOG_LOCAL0 | libc::LOG_WARNING,
                c"%s".as_ptr(),
                msg.as_ptr(),
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for rule parsing, cooldowns, findings history, and log sanitizing.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::net::Ipv4Addr;

    /// A fixed source IP used across the alerting tests.
    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    /// Capture time `secs` seconds after a fixed base.
    ///
    /// Every threshold, window and cooldown is measured against the packet
    /// timestamp, so a test drives time by choosing stamps rather than by
    /// sleeping. That is what makes these deterministic and what makes the
    /// engine give the same answer on a replay as it did live.
    fn at(secs: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap() + chrono::Duration::seconds(secs)
    }

    /// A multibyte final character is rejected as an invalid suffix instead
    /// of panicking on a non-boundary `split_at`.
    #[test]
    fn parse_duration_multibyte_suffix_is_invalid() {
        assert_eq!(parse_duration("10µ"), None);
        assert_eq!(parse_duration("5秒"), None);
        assert_eq!(parse_duration("µ"), None);
    }

    /// A basic rule parses name/threshold/window and defaults cooldown to 2x.
    #[test]
    fn parse_rule_basic() {
        let rule = AlertRule::parse("5xx-rate:10/1m").expect("should parse");
        assert_eq!(rule.name, "5xx-rate");
        assert_eq!(rule.threshold, 10);
        assert_eq!(rule.window, Duration::from_secs(60));
        assert_eq!(
            rule.cooldown,
            Duration::from_secs(120),
            "default cooldown should be 2x window"
        );
    }

    /// An explicit cooldown segment overrides the 2x-window default.
    #[test]
    fn parse_rule_with_cooldown() {
        let rule = AlertRule::parse("reg-flood:50/10s:5m").expect("should parse");
        assert_eq!(rule.name, "reg-flood");
        assert_eq!(rule.threshold, 50);
        assert_eq!(rule.window, Duration::from_secs(10));
        assert_eq!(rule.cooldown, Duration::from_secs(300));
    }

    /// The `h` suffix parses windows and default cooldown in hours.
    #[test]
    fn parse_rule_hours() {
        let rule = AlertRule::parse("slow-scan:100/1h").expect("should parse");
        assert_eq!(rule.window, Duration::from_secs(3600));
        assert_eq!(rule.cooldown, Duration::from_secs(7200));
    }

    /// A rule without a `:` separator fails to parse.
    #[test]
    fn parse_rule_invalid_no_colon() {
        let result = AlertRule::parse("invalid-rule");
        assert!(result.is_err(), "should fail without colon separator");
    }

    /// A rule without a `/` between threshold and window fails to parse.
    #[test]
    fn parse_rule_invalid_no_slash() {
        let result = AlertRule::parse("bad:10");
        assert!(result.is_err(), "should fail without slash separator");
    }

    /// A non-numeric threshold fails to parse.
    #[test]
    fn parse_rule_invalid_threshold() {
        let result = AlertRule::parse("bad:abc/1m");
        assert!(result.is_err(), "should fail with non-numeric threshold");
    }

    /// An invalid window suffix fails to parse.
    #[test]
    fn parse_rule_invalid_window() {
        let result = AlertRule::parse("bad:10/1x");
        assert!(result.is_err(), "should fail with invalid window suffix");
    }

    /// A rule with an empty name fails to parse.
    #[test]
    fn parse_rule_empty_name() {
        let result = AlertRule::parse(":10/1m");
        assert!(result.is_err(), "should fail with empty name");
    }

    /// A second alert for the same source within the cooldown is suppressed.
    #[test]
    fn cooldown_suppresses_second_alert() {
        let rule = AlertRule::parse("test:1/1s:10m").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        let first = engine.fire("test", test_ip(), "first alert", at(0));
        assert!(first, "first alert should fire");

        let second = engine.fire("test", test_ip(), "second alert", at(0));
        assert!(!second, "second alert within cooldown should be suppressed");
    }

    /// Different source IPs have independent cooldowns.
    #[test]
    fn different_sources_independent_cooldown() {
        let rule = AlertRule::parse("test:1/1s:10m").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(engine.fire("test", ip1, "alert from ip1", at(0)));
        assert!(
            engine.fire("test", ip2, "alert from ip2", at(0)),
            "different source should fire independently"
        );
    }

    /// A threshold of five needs five events before anything fires.
    ///
    /// The grammar is `<name>:<threshold>/<window>[:<cooldown>]` and the
    /// threshold field is documented as "number of events required to trigger
    /// within the window". It was parsed, validated, stored — and never read,
    /// so `fraud:1000000/1h` produced byte-identical output to passing no rule
    /// at all. An operator tuning sensitivity in either direction got no effect
    /// and no error, and concluded the tuning had taken.
    ///
    /// The cooldown is zero here so that suppression cannot be what makes this
    /// pass: every event is eligible to fire, and only the threshold can hold
    /// the first four back.
    #[test]
    fn a_threshold_of_five_needs_five_events() {
        let rule = AlertRule::parse("test:5/60s:0s").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        for i in 1..=4 {
            assert!(
                !engine.fire("test", test_ip(), "event", at(i)),
                "event {i} of 5 must not fire: the threshold is not reached"
            );
        }
        assert!(
            engine.fire("test", test_ip(), "event", at(5)),
            "the fifth event reaches the threshold and must fire"
        );
    }

    /// Events that fall outside the window do not accumulate toward it.
    ///
    /// This is the half of the grammar the threshold alone cannot express: five
    /// events spread across an hour are not "five events in a minute", and a
    /// rule that counted them would alert on ordinary traffic given enough time.
    #[test]
    fn events_older_than_the_window_do_not_count() {
        let rule = AlertRule::parse("test:3/60s:0s").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        // Three events, but 100 seconds apart — never three inside any minute.
        assert!(!engine.fire("test", test_ip(), "event", at(0)));
        assert!(!engine.fire("test", test_ip(), "event", at(100)));
        assert!(
            !engine.fire("test", test_ip(), "event", at(200)),
            "three events spread over 200s are not three events in 60s"
        );

        // Two more inside the window with the last one closes it.
        assert!(!engine.fire("test", test_ip(), "event", at(210)));
        assert!(
            engine.fire("test", test_ip(), "event", at(220)),
            "at(200), at(210) and at(220) are three events inside 60s"
        );
    }

    /// The window is measured in capture time, so a replay behaves like live.
    ///
    /// Offline an entire capture arrives within milliseconds of wall time. A
    /// window on `Instant::now()` would therefore never close, and every event
    /// in a file would count toward every threshold — which is exactly the
    /// defect that made the scanner detectors read a replayed trunk as a flood.
    #[test]
    fn the_window_follows_packet_time_not_wall_time() {
        let rule = AlertRule::parse("test:2/10s:0s").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        // Two events an hour apart in CAPTURE time, delivered back to back in
        // wall time. A wall-clock window would call this two events in 10s.
        assert!(!engine.fire("test", test_ip(), "event", at(0)));
        assert!(
            !engine.fire("test", test_ip(), "event", at(3600)),
            "an hour apart in the capture is not two events in ten seconds, \
             however fast the file was read"
        );
    }

    /// An alert type with no matching rule falls back to the 60s default cooldown.
    #[test]
    fn unknown_rule_uses_default_cooldown() {
        let mut engine = AlertEngine::new(vec![], None);

        let first = engine.fire("unknown-rule", test_ip(), "test", at(0));
        assert!(first, "first alert for unknown rule should fire");

        let second = engine.fire("unknown-rule", test_ip(), "test", at(0));
        assert!(
            !second,
            "second alert should be suppressed by default cooldown"
        );
    }

    // ── Phase 8.3 FindingsHistory ────────────────────────────────────

    /// Each post-cooldown firing is recorded in the ring buffer, newest first.
    #[test]
    fn findings_history_records_each_post_cooldown_fire() {
        let mut engine = AlertEngine::new(vec![], None);
        // Default cooldown is 60s; fire from different IPs so no cooldown.
        engine.fire(
            "scanner",
            "10.0.0.1".parse().unwrap(),
            "ua=friendly-scanner",
            at(0),
        );
        engine.fire(
            "scanner",
            "10.0.0.2".parse().unwrap(),
            "ua=sipvicious",
            at(0),
        );
        engine.fire("fraud", "10.0.0.3".parse().unwrap(), "irsf", at(0));
        let all = engine.iter_findings(&[], None, 100);
        assert_eq!(all.len(), 3);
        // Newest first
        assert_eq!(all[0].rule_name, "fraud");
        assert_eq!(all[2].rule_name, "scanner");
    }

    /// `iter_findings` filters stored findings by rule kind.
    #[test]
    fn findings_history_filter_by_kind() {
        let mut engine = AlertEngine::new(vec![], None);
        engine.fire("scanner", "10.0.0.1".parse().unwrap(), "a", at(0));
        engine.fire("fraud", "10.0.0.2".parse().unwrap(), "b", at(0));
        engine.fire("scanner", "10.0.0.3".parse().unwrap(), "c", at(0));
        let scanner_only = engine.iter_findings(&["scanner"], None, 100);
        assert_eq!(scanner_only.len(), 2);
        assert!(scanner_only.iter().all(|f| f.rule_name == "scanner"));
    }

    /// The bounded ring buffer evicts oldest-first, keeping the most recent.
    #[test]
    fn findings_history_eviction_keeps_most_recent() {
        let mut engine = AlertEngine::new(vec![], None);
        engine.set_findings_capacity(5);
        for i in 0..2000u32 {
            engine.fire(
                "scanner",
                IpAddr::V4(std::net::Ipv4Addr::new(
                    10,
                    0,
                    (i / 256) as u8,
                    (i % 256) as u8,
                )),
                &format!("seq={i}"),
                at(0),
            );
        }
        let all = engine.iter_findings(&[], None, 100);
        assert_eq!(all.len(), 5, "ring buffer must hold exactly 5");
        // The most recent entry should be seq=1999.
        assert!(all[0].detail.contains("seq=1999"));
    }

    /// Cooldown-suppressed firings are not recorded in the findings history.
    #[test]
    fn findings_history_cooldown_suppression_does_not_record() {
        let rule = AlertRule::parse("scanner:1/1s:10m").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let first = engine.fire("scanner", ip, "first", at(0));
        let second = engine.fire("scanner", ip, "second", at(0));
        assert!(first);
        assert!(!second, "cooldown should suppress");
        let all = engine.iter_findings(&[], None, 100);
        assert_eq!(
            all.len(),
            1,
            "suppressed firings must NOT appear in history"
        );
        assert!(all[0].detail.contains("first"));
    }

    /// A zero findings capacity disables retention entirely.
    #[test]
    fn findings_history_zero_capacity_disables_retention() {
        let mut engine = AlertEngine::new(vec![], None);
        engine.set_findings_capacity(0);
        engine.fire("scanner", "10.0.0.1".parse().unwrap(), "x", at(0));
        let all = engine.iter_findings(&[], None, 100);
        assert_eq!(all.len(), 0);
    }

    // ── Security regression tests ────────────────────────────────────

    /// CR and LF in a log value are each replaced with a space.
    #[test]
    fn sanitize_log_value_strips_crlf() {
        let result = sanitize_log_value("hello\r\nworld");
        assert_eq!(
            result, "hello  world",
            "\\r and \\n should each be replaced with a space"
        );
    }

    /// A JSON alert line carries the expected `alert`/`src`/`detail`/`ts` fields.
    #[test]
    fn alert_json_line_has_expected_fields() {
        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 6, 24, 1, 2, 3).unwrap();
        let line = alert_json_line(
            "scanner",
            test_ip(),
            "method=OPTIONS detection=enumeration",
            ts,
        );
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON line");
        assert_eq!(v["alert"], "scanner");
        assert_eq!(v["src"], "10.0.0.1");
        assert_eq!(v["detail"], "method=OPTIONS detection=enumeration");
        assert!(v["ts"].as_str().unwrap().starts_with("2026-06-24T01:02:03"));
    }

    // ── Shared tumbling-window rate limiter ──────────────────────────

    /// The window rolls on the clock, not on the event count: three events
    /// fill a 3-per-second budget, and only the passage of a second refills
    /// it.
    #[cfg(feature = "native")]
    #[test]
    fn the_window_rolls_on_the_clock_not_on_events() {
        let mut w = TumblingWindow::new(3, 1);
        for i in 0..3 {
            assert!(w.allows(at(0)), "event {i} of 3 is inside the budget");
            w.record();
        }
        assert!(!w.allows(at(0)), "the fourth event in one second is over");
        assert!(w.allows(at(1)), "a second later the window has rolled");
    }

    /// A limit of zero disables the limiter, matching `--exec-rate-limit 0`.
    #[cfg(feature = "native")]
    #[test]
    fn a_zero_limit_disables_the_window() {
        let mut w = TumblingWindow::new(0, 1);
        for _ in 0..1000 {
            assert!(w.allows(at(0)), "a zero limit must never deny");
            w.record();
        }
    }

    /// A backwards clock must not roll the window.
    ///
    /// Capture stamps go backwards — out of order on a merged capture,
    /// replayed on a crafted one. Rolling on a backwards jump would refill the
    /// budget once per stale stamp, which is not a rate limit but a way to ask
    /// for one.
    #[cfg(feature = "native")]
    #[test]
    fn a_backwards_clock_does_not_roll_the_window() {
        let mut w = TumblingWindow::new(2, 60);
        assert!(w.allows(at(3600)));
        w.record();
        assert!(w.allows(at(0)), "second event still fits the budget");
        w.record();
        assert!(
            !w.allows(at(0)),
            "an hour-old stamp must not hand out a fresh window"
        );
        assert!(!w.allows(at(-86_400)), "nor must a stamp a day old");
    }

    /// A zero-length window is clamped to one second rather than silently
    /// disabling the limit that was asked for.
    #[cfg(feature = "native")]
    #[test]
    fn a_zero_length_window_is_clamped() {
        let mut w = TumblingWindow::new(1, 0);
        assert!(w.allows(at(0)));
        w.record();
        assert!(!w.allows(at(0)), "a 0s window must not roll on every event");
        assert!(w.allows(at(1)));
    }

    /// Checking does not book: an action that was allowed but never happened
    /// (a spawn that errored) must not spend the budget it was granted.
    #[cfg(feature = "native")]
    #[test]
    fn checking_the_budget_does_not_spend_it() {
        let mut w = TumblingWindow::new(1, 1);
        assert!(w.allows(at(0)));
        assert!(w.allows(at(0)), "an unbooked check must not consume budget");
        w.record();
        assert!(!w.allows(at(0)), "the booked event did consume it");
    }

    /// An event that has been allowed but not yet booked still counts, when
    /// declared, so a caller that decides now and acts later cannot overspend.
    ///
    /// This is what keeps `--exec-rate-limit` meaning the same thing after the
    /// event-exec path moved its `fork`/`exec` out of the batch loop's locked
    /// section: the decision stayed put, the spawn (and so the `record`) moved,
    /// and the in-flight decision is declared here in the meantime.
    #[cfg(feature = "native")]
    #[test]
    fn a_reserved_event_counts_against_the_budget_before_it_is_booked() {
        let mut w = TumblingWindow::new(1, 1);
        assert!(w.allows(at(0)), "the first event fits");
        assert!(
            !w.allows_with_reserved(at(0), 1),
            "one allowed-but-unbooked event fills a limit of 1"
        );

        // Declaring nothing is exactly the old behavior.
        let mut plain = TumblingWindow::new(2, 1);
        assert!(plain.allows_with_reserved(at(0), 0));
        plain.record();
        assert!(plain.allows_with_reserved(at(0), 0));
        assert!(
            !plain.allows_with_reserved(at(0), 1),
            "one booked plus one reserved fills a limit of 2"
        );

        // A zero limit disables the window, reservations included.
        let mut off = TumblingWindow::new(0, 1);
        assert!(off.allows_with_reserved(at(0), u32::MAX));

        // The window still rolls: reservations do not pin an expired window.
        let mut rolls = TumblingWindow::new(1, 1);
        // The first check is what starts the window; booking before it would
        // be wiped by the roll it triggers.
        assert!(rolls.allows(at(0)));
        rolls.record();
        assert!(!rolls.allows_with_reserved(at(0), 0));
        assert!(
            rolls.allows_with_reserved(at(5), 0),
            "a new window starts empty"
        );
    }

    /// Drops are logged at 1, 10, 100, … and nowhere in between.
    #[cfg(feature = "native")]
    #[test]
    fn order_of_magnitude_boundaries() {
        for n in [1u64, 10, 100, 1000, 10_000_000] {
            assert!(is_order_of_magnitude(n), "{n} is a power of ten");
        }
        for n in [0u64, 2, 11, 99, 101, 999, 1001] {
            assert!(!is_order_of_magnitude(n), "{n} is not a power of ten");
        }
    }

    // ── Per-source alert-exec budgets ────────────────────────────────

    /// A source that has spent its per-minute budget is denied, and a source
    /// that has not is unaffected by it.
    #[cfg(feature = "native")]
    #[test]
    fn one_source_exhausting_its_budget_does_not_affect_another() {
        let mut engine = AlertEngine::new(vec![], None);
        let noisy = test_ip();
        let quiet: IpAddr = "10.0.0.2".parse().expect("valid IP");

        for i in 0..MAX_EXEC_PER_SOURCE_PER_MINUTE {
            assert!(
                engine.source_allows_exec(noisy, at(0)),
                "spawn {i} is inside the per-source budget"
            );
            engine
                .exec_per_source
                .get_mut(&noisy)
                .expect("bucket exists after allows")
                .record();
        }
        assert!(
            !engine.source_allows_exec(noisy, at(0)),
            "a fourth spawn in one capture minute is over the per-source budget"
        );
        assert!(
            engine.source_allows_exec(quiet, at(0)),
            "a different source must keep its own budget"
        );
        assert!(
            engine.source_allows_exec(noisy, at(60)),
            "a capture minute later the source's window has rolled"
        );
    }

    /// The per-source exec budget is exactly three spawns per capture minute.
    ///
    /// Written with literal counts rather than with
    /// `MAX_EXEC_PER_SOURCE_PER_MINUTE`, because every other test here loops
    /// `0..MAX_EXEC_PER_SOURCE_PER_MINUTE` and so moves with the constant
    /// instead of guarding it. `--alert-exec` runs an operator's own command
    /// line, and the source that spends this budget is whichever peer a
    /// signature misidentified, so raising the bound multiplies real process
    /// spawns aimed at exactly the wrong peer. An operator who needs more
    /// headroom raises the global `--exec-rate-limit`, which spends the extra
    /// budget across distinct sources instead of concentrating it on one.
    #[cfg(feature = "native")]
    #[test]
    fn the_per_source_exec_budget_is_three_a_minute() {
        let mut engine = AlertEngine::new(vec![], None);
        let misidentified = test_ip();

        for attempt in 1..=3u64 {
            assert!(
                engine.source_allows_exec(misidentified, at(0)),
                "spawn {attempt} of 3 must sit inside the per-source budget; \
                 if this fails MAX_EXEC_PER_SOURCE_PER_MINUTE dropped below 3 \
                 and --alert-exec quietly stops firing for real alerts"
            );
            engine
                .exec_per_source
                .get_mut(&misidentified)
                .expect("bucket exists after allows")
                .record();
        }

        assert!(
            !engine.source_allows_exec(misidentified, at(0)),
            "a 4th spawn for one source inside one capture minute must be \
             refused; if this fails MAX_EXEC_PER_SOURCE_PER_MINUTE was raised, \
             and one misidentified peer now forks more of the operator's \
             command than the blast radius this bound exists to hold"
        );
    }

    /// The per-source budget map is bounded and evicts least-recently-used.
    ///
    /// The key is a source IP, so it is attacker-influenced on a live
    /// interface; an unbounded map would be a memory defect wearing a rate
    /// limiter's clothes. Eviction is on the monotonic tick, not the capture
    /// stamp, because capture stamps tie.
    #[cfg(feature = "native")]
    #[test]
    fn per_source_exec_budgets_are_bounded() {
        let mut engine = AlertEngine::new(vec![], None);
        let victim = test_ip();

        // Spend the victim's whole budget, oldest tick in the map.
        for _ in 0..MAX_EXEC_PER_SOURCE_PER_MINUTE {
            assert!(engine.source_allows_exec(victim, at(0)));
            engine
                .exec_per_source
                .get_mut(&victim)
                .expect("bucket exists after allows")
                .record();
        }
        assert!(
            !engine.source_allows_exec(victim, at(0)),
            "control: the victim is out of budget, else the check below is vacuous"
        );

        // Flood distinct sources until the map has to evict.
        for i in 0..=MAX_EXEC_SOURCE_ENTRIES {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i as u32));
            engine.source_allows_exec(ip, at(0));
        }
        assert!(
            engine.exec_per_source.len() <= MAX_EXEC_SOURCE_ENTRIES,
            "the per-source map must stay bounded: {} entries",
            engine.exec_per_source.len()
        );
        assert!(
            engine.source_allows_exec(victim, at(0)),
            "cap regressed: the victim's spent budget survived the flood"
        );
    }

    /// A crafted detail string stays escaped inside `detail` and cannot inject
    /// sibling JSON fields.
    #[test]
    fn alert_json_line_escapes_adversarial_detail() {
        // a crafted detail (embedded quote/brace) must stay inside the string,
        // not break the line or inject a sibling field.
        let ts = chrono::Utc::now();
        let line = alert_json_line("scanner", test_ip(), r#"ua="evil","injected":1"#, ts);
        let v: serde_json::Value = serde_json::from_str(&line).expect("still valid JSON");
        assert!(v.get("injected").is_none(), "no injected field");
        assert_eq!(v["detail"], r#"ua="evil","injected":1"#);
    }

    /// A source address in the 12.0.0.0/8 test range, distinct per `i`.
    fn flood_ip(i: usize) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(0x0c00_0000 + i as u32))
    }

    /// A flood of distinct sources under a rule whose threshold none of them
    /// reaches must not grow the event map without bound. The map was
    /// trimmed only after a key REACHED its threshold, so ten thousand and
    /// one sources firing once each under `scanner:5/1m` held ten thousand
    /// and one windows, and a spoofed-source flood on a live interface was a
    /// remote allocation with no ceiling.
    #[test]
    fn the_event_map_stays_bounded_when_no_source_reaches_its_threshold() {
        let rule = AlertRule::parse("scanner:5/1m").expect("a valid rule");
        let mut engine = AlertEngine::new(vec![rule], None);
        for i in 0..=MAX_COOLDOWN_ENTRIES {
            assert!(
                !engine.fire("scanner", flood_ip(i), "probe", at(0)),
                "control: one event of the five required never fires"
            );
        }
        assert!(
            engine.events.len() <= MAX_COOLDOWN_ENTRIES,
            "the event map holds {} windows for a cap of {MAX_COOLDOWN_ENTRIES}: \
             a flood of sources that never reach a threshold grew it without bound",
            engine.events.len()
        );
    }

    /// The cooldown map stays bounded under a flood of sources that all
    /// fire, and the source that fired least recently is the one forgotten.
    #[test]
    fn the_cooldown_map_stays_bounded_and_forgets_the_least_recent_firing() {
        let mut engine = AlertEngine::new(vec![], None);
        for i in 0..MAX_COOLDOWN_ENTRIES {
            assert!(engine.fire("scanner", flood_ip(i), "probe", at(0)));
        }
        assert_eq!(
            engine.cooldowns.len(),
            MAX_COOLDOWN_ENTRIES,
            "fixture: at the cap"
        );
        // One more source. The first to fire is the least recently fired.
        assert!(engine.fire("scanner", flood_ip(MAX_COOLDOWN_ENTRIES), "probe", at(0)));
        assert_eq!(
            engine.cooldowns.len(),
            MAX_COOLDOWN_ENTRIES,
            "the cap holds"
        );
        assert!(
            !engine
                .cooldowns
                .contains_key(&(flood_ip(0), "scanner".to_string())),
            "the least recently fired source must be the one forgotten"
        );
        assert!(
            engine
                .cooldowns
                .contains_key(&(flood_ip(1), "scanner".to_string())),
            "the next-oldest firing survives"
        );
    }
}
