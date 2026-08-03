// SPDX-License-Identifier: MIT OR Apache-2.0

//! Event exec hooks for triggering external commands.
//!
//! Fires shell commands when dialog state changes or RTP quality degrades
//! below a threshold. SIP data is passed via environment variables (never
//! interpolated into the command string) to prevent command injection.
//! Supports rate limiting and non-blocking execution with queue depth caps.

use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::time::Instant;

use tracing::{info, warn};

use crate::rtp::quality;
use crate::rtp::stream::RtpStream;
use crate::security::alerting::TumblingWindow;
use crate::sip::dialog::SipDialog;

/// Maximum number of pending child processes before dropping events.
const MAX_QUEUE_DEPTH: usize = 100;

/// Engine for executing external commands on SIP/RTP events.
///
/// Supports two event types:
/// - Dialog events: fired when a dialog changes state.
/// - Quality events: fired when an RTP stream's estimated MOS drops below
///   a threshold.
///
/// SIP data is passed to commands via `SIPNAB_*` environment variables
/// (e.g., `$SIPNAB_CALL_ID`, `$SIPNAB_FROM`). For backwards compatibility,
/// `%variable` placeholders in command templates are rewritten to
/// `$SIPNAB_VARIABLE` references. Values are never interpolated into the
/// shell command string.
pub struct EventExecEngine {
    /// Command template for dialog events. `None` disables dialog hooks.
    /// Stored as `Arc<str>` so cloning for the child process is cheap (pointer bump).
    on_dialog_cmd: Option<Arc<str>>,
    /// Command template for quality events. `None` disables quality hooks.
    /// Stored as `Arc<str>` so cloning for the child process is cheap (pointer bump).
    on_quality_cmd: Option<Arc<str>>,
    /// MOS threshold below which quality events fire.
    quality_threshold: f64,
    /// Maximum command executions per second (0 = unlimited).
    ///
    /// The window itself lives in [`TumblingWindow`], shared with the
    /// `--alert-exec` path in [`crate::security::alerting`] so the two
    /// process-spawning surfaces cannot drift apart. This one runs on the wall
    /// clock; alerting runs on capture time. Same rule, different clock.
    rate_window: TumblingWindow<Instant>,
    /// Tracked child processes for reaping, each with the command that
    /// produced it so a failure can say which command failed.
    children: Vec<TrackedChild>,
    /// What the hook commands actually did. See [`ExecOutcomeCounts`].
    outcomes: ExecOutcomeCounts,
}

/// A spawned hook command, kept alongside the template that produced it.
///
/// The template is what an operator has to be told when a hook fails —
/// "a command exited 7" is not actionable, "`nft add element … ` exited 7" is.
/// It is an `Arc<str>` clone of the engine's stored template, so tracking it
/// costs a pointer bump per spawn, not a string copy.
struct TrackedChild {
    /// The running (or finished) `sh -c` child.
    child: std::process::Child,
    /// The command template it was spawned with.
    cmd: Arc<str>,
}

/// What the configured `--on-dialog` / `--on-quality` hooks actually did.
///
/// This is the *ledger*, in the shape the `--alert-exec` path already uses
/// (see [`crate::security::alerting::AlertEngine::exec_drops`]): every command
/// the engine decided about is counted here, so a run can state how many hooks
/// ran, how many worked, how many failed and how many never ran at all.
///
/// The defect this type exists to close is that a hook's exit status was
/// matched with a wildcard and discarded. These hooks are an automated-response
/// path — an operator wires one to a firewall command — and a failing hook that
/// logs nothing is indistinguishable from a hook that was never needed. Silence
/// there is a false assurance, not a missing nicety.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecOutcomeCounts {
    /// Commands successfully handed to the OS.
    pub spawned: u64,
    /// Spawned commands observed to exit zero.
    pub succeeded: u64,
    /// Spawned commands observed to exit non-zero or die on a signal.
    pub failed: u64,
    /// Spawned commands whose status check errored, so their exit status can
    /// never be known. Counted apart from `failed` because "it went wrong" and
    /// "we cannot say" are different answers.
    pub unknown: u64,
    /// Commands that could not be spawned at all.
    pub spawn_failed: u64,
    /// Events whose command was not run because the per-second budget was
    /// already spent.
    pub rate_limited: u64,
    /// Events whose command was not run because `MAX_QUEUE_DEPTH` children were
    /// still pending.
    pub queue_full: u64,
}

impl ExecOutcomeCounts {
    /// Spawned commands whose exit status has been booked.
    pub fn settled(&self) -> u64 {
        self.succeeded
            .saturating_add(self.failed)
            .saturating_add(self.unknown)
    }

    /// Spawned commands still running when the count was taken.
    ///
    /// Teardown never waits for these — a hook that hangs must not hold up the
    /// process — so a nonzero value at teardown means exactly that: sipnab
    /// cannot say whether those commands worked.
    pub fn unfinished(&self) -> u64 {
        self.spawned.saturating_sub(self.settled())
    }

    /// Events whose command never ran, for any reason.
    pub fn suppressed(&self) -> u64 {
        self.rate_limited
            .saturating_add(self.queue_full)
            .saturating_add(self.spawn_failed)
    }

    /// Whether anything went wrong: a command failed, a status was unknowable,
    /// or an event's command never ran.
    pub fn any_trouble(&self) -> bool {
        self.failed > 0 || self.unknown > 0 || self.suppressed() > 0
    }

    /// Book one observed exit, warning about failures.
    ///
    /// Warning on every failure would make the log the flood it is reporting —
    /// a hook broken at 100 events/sec would emit 100 warn lines a second — and
    /// warning once would hide the scale. Each order of magnitude names the
    /// command and its exit status; the exact totals are stated at teardown.
    fn record_exit(&mut self, status: ExitStatus, cmd: &str) {
        if status.success() {
            self.succeeded = self.succeeded.saturating_add(1);
            return;
        }
        self.failed = self.failed.saturating_add(1);
        if is_order_of_magnitude(self.failed) {
            warn!(
                exit_status = %status,
                command = cmd,
                failed_total = self.failed,
                "Event exec command failed ({status}): `{cmd}`. It is reported, \
                 not retried, and the capture is unaffected — but whatever this \
                 command was supposed to do did NOT happen. {} hook command(s) \
                 have failed so far.",
                self.failed
            );
        }
    }

    /// Book one command whose exit status can never be known.
    fn record_unknown(&mut self, cmd: &str) {
        self.unknown = self.unknown.saturating_add(1);
        if is_order_of_magnitude(self.unknown) {
            warn!(
                command = cmd,
                unknown_total = self.unknown,
                "Error checking event exec command `{cmd}`; killing to reap it. \
                 Its exit status is unknowable, so sipnab cannot say whether it \
                 did what it was asked. {} so far.",
                self.unknown
            );
        }
    }
}

/// Whether `n` is an exact power of ten (1, 10, 100, …).
///
/// Deliberately a duplicate of the identically-named helper in
/// [`crate::security::alerting`], which is private to that module: the two
/// process-spawning surfaces escalate their reporting the same way, and a
/// three-line predicate is a smaller cost than widening that module's surface.
fn is_order_of_magnitude(n: u64) -> bool {
    n > 0 && 10u64.checked_pow(n.ilog10()) == Some(n)
}

/// What to do with a tracked child after a `try_wait` status check.
enum ReapAction {
    /// Still running — keep tracking it.
    Keep,
    /// Exited, and this is the status it exited with. Carrying the status is
    /// the whole point: it used to be matched with a wildcard and dropped, so
    /// a hook that failed and a hook that worked were indistinguishable.
    Exited(ExitStatus),
    /// The status check errored — kill and wait before dropping so the child
    /// is reaped rather than leaked as a zombie.
    Cleanup,
}

/// Decide a child's disposition from its `try_wait` result. Pure, so the
/// error-path decision is testable without forcing an OS-level `try_wait`
/// failure.
fn reap_action(status: &std::io::Result<Option<ExitStatus>>) -> ReapAction {
    match status {
        Ok(Some(status)) => ReapAction::Exited(*status),
        Ok(None) => ReapAction::Keep,
        Err(_) => ReapAction::Cleanup,
    }
}

impl EventExecEngine {
    /// Create a new event exec engine.
    ///
    /// # Arguments
    ///
    /// * `on_dialog_cmd` — Command template for dialog events (e.g.,
    ///   `"curl -X POST http://hook/dialog --data \"$SIPNAB_JSON\""`)
    /// * `on_quality_cmd` — Command template for quality events
    /// * `rate_limit` — Maximum executions per second (0 = unlimited)
    /// * `quality_threshold` — MOS score below which quality events fire
    ///
    /// Legacy `%variable` placeholders in both templates are rewritten to
    /// `$SIPNAB_*` references at construction time.
    pub fn new(
        on_dialog_cmd: Option<String>,
        on_quality_cmd: Option<String>,
        rate_limit: u32,
        quality_threshold: f64,
    ) -> Self {
        Self {
            on_dialog_cmd: on_dialog_cmd.map(|c| Arc::from(migrate_template_vars(&c))),
            on_quality_cmd: on_quality_cmd.map(|c| Arc::from(migrate_template_vars(&c))),
            quality_threshold,
            rate_window: TumblingWindow::new(rate_limit, 1),
            children: Vec::new(),
            outcomes: ExecOutcomeCounts::default(),
        }
    }

    /// What the hook commands have done so far: spawns, exit outcomes, and
    /// events whose command never ran.
    ///
    /// This is the reachable form of a hook's exit status. Statuses observed
    /// since the last reap are already booked here; a command that has exited
    /// but not yet been reaped still counts as [`ExecOutcomeCounts::unfinished`].
    pub fn outcomes(&self) -> ExecOutcomeCounts {
        self.outcomes
    }

    /// Fire a dialog event, passing SIP data via environment variables.
    ///
    /// Environment variables set on the child process:
    /// - `SIPNAB_JSON` — Full dialog JSON
    /// - `SIPNAB_CALL_ID` — The dialog's Call-ID
    /// - `SIPNAB_FROM` — From user
    /// - `SIPNAB_TO` — To user
    /// - `SIPNAB_STATE` — Dialog state (e.g., "Completed")
    /// - `SIPNAB_METHOD` — Initial method (e.g., "INVITE")
    ///
    /// No-op when no `--on-dialog` command is configured or the rate limit is
    /// exceeded; a rate-limited event is counted in [`Self::outcomes`] rather
    /// than dropped without trace.
    ///
    /// # Side effects
    ///
    /// Spawns a `sh -c` child process running the configured command (see
    /// `spawn_command`); reaps finished children and mutates the
    /// rate-limit counters.
    pub fn fire_dialog_event(&mut self, dialog: &SipDialog) {
        let cmd = match self.on_dialog_cmd {
            Some(ref cmd) => cmd.clone(),
            None => return,
        };

        if !self.check_rate_limit() {
            self.outcomes.rate_limited = self.outcomes.rate_limited.saturating_add(1);
            return;
        }

        // Build the JSON for SIPNAB_JSON env var
        let json = super::json::dialog_to_json(
            dialog,
            &[],
            &crate::rtp::diagnosis::MediaDiagnosis::default(),
        );

        let vars: Vec<(&str, String)> = vec![
            ("SIPNAB_CALL_ID", dialog.call_id.clone()),
            (
                "SIPNAB_FROM",
                dialog.from_user.as_deref().unwrap_or("").to_string(),
            ),
            (
                "SIPNAB_TO",
                dialog.to_user.as_deref().unwrap_or("").to_string(),
            ),
            ("SIPNAB_STATE", dialog.state().to_string()),
            ("SIPNAB_METHOD", dialog.method.to_string()),
            ("SIPNAB_JSON", json),
        ];

        self.spawn_command(&cmd, &vars);
    }

    /// Whether a quality-event command is configured. The per-RTP-packet hot path
    /// guards on this so that, with no `--on-quality` (every batch benchmark, most
    /// live runs), it skips rebuilding the `StreamKey` and the second stream-store
    /// lookup — `fire_quality_event` no-ops anyway. Observationally identical.
    pub fn quality_events_enabled(&self) -> bool {
        self.on_quality_cmd.is_some()
    }

    /// Fire a quality event if the stream's estimated MOS is below threshold.
    ///
    /// Environment variables set on the child process:
    /// - `SIPNAB_STREAM_JSON` — Full stream JSON
    /// - `SIPNAB_SSRC` — Stream SSRC in hex
    /// - `SIPNAB_MOS` — Estimated MOS score
    /// - `SIPNAB_JITTER` — Current jitter in ms
    /// - `SIPNAB_LOSS` — Loss percentage
    ///
    /// No-op when no `--on-quality` command is configured, the stream's
    /// estimated MOS is at or above the threshold, or the rate limit is
    /// exceeded; a rate-limited event is counted in [`Self::outcomes`].
    ///
    /// # Side effects
    ///
    /// Spawns a `sh -c` child process running the configured command (see
    /// `spawn_command`); reaps finished children and mutates the
    /// rate-limit counters.
    pub fn fire_quality_event(&mut self, stream: &RtpStream) {
        let cmd = match self.on_quality_cmd {
            Some(ref cmd) => cmd.clone(),
            None => return,
        };

        // Estimate MOS from jitter and loss via the canonical E-model
        let mos = quality::estimate_mos(stream.jitter, loss_pct(stream), stream.codec.as_deref());
        if mos >= self.quality_threshold {
            return;
        }

        if !self.check_rate_limit() {
            self.outcomes.rate_limited = self.outcomes.rate_limited.saturating_add(1);
            return;
        }

        let stream_json = super::json::stream_to_json(stream);

        let vars: Vec<(&str, String)> = vec![
            ("SIPNAB_STREAM_JSON", stream_json),
            ("SIPNAB_SSRC", format!("0x{:08x}", stream.key.ssrc)),
            ("SIPNAB_MOS", format!("{mos:.2}")),
            ("SIPNAB_JITTER", format!("{:.1}", stream.jitter)),
            ("SIPNAB_LOSS", format!("{:.1}", loss_pct(stream))),
        ];

        self.spawn_command(&cmd, &vars);
    }

    /// Check and update rate limiting. Returns `true` if execution is allowed
    /// (always `true` when the configured limit is 0).
    ///
    /// # Side effects
    ///
    /// Resets the one-second window (and its exec count) when a second or more
    /// has elapsed. The count itself is booked by `spawn_command` on
    /// successful spawn, not here, so an allowed-but-failed spawn does not
    /// spend budget it never used.
    fn check_rate_limit(&mut self) -> bool {
        self.rate_window.allows(Instant::now())
    }

    /// Reap completed child processes, booking their exit outcomes, to prevent
    /// zombies and update queue depth.
    ///
    /// A failing hook is recorded and reported here and nothing more: it is
    /// never retried and never allowed to interrupt the capture. The capture is
    /// the evidence, and it has to survive the conditions under which an
    /// automated response matters most.
    ///
    /// # Side effects
    ///
    /// Calls `try_wait` on every tracked child: completed ones are removed and
    /// counted in [`Self::outcomes`] (warning at each order of magnitude of
    /// failures), running ones kept, and a child whose status check errors is
    /// killed and reaped before removal so it does not linger as a zombie.
    fn reap_children(&mut self) {
        // Split the borrow: the ledger and the child list are disjoint fields.
        let outcomes = &mut self.outcomes;
        self.children
            .retain_mut(|tracked| match reap_action(&tracked.child.try_wait()) {
                ReapAction::Keep => true,
                ReapAction::Exited(status) => {
                    outcomes.record_exit(status, &tracked.cmd);
                    false
                }
                ReapAction::Cleanup => {
                    // Dropping a Child neither kills nor waits, so a check error
                    // (were the child simply forgotten) would leak a zombie.
                    // Best-effort kill + wait reaps it before we drop it.
                    outcomes.record_unknown(&tracked.cmd);
                    let _ = tracked.child.kill();
                    let _ = tracked.child.wait();
                    false
                }
            });
    }

    /// Spawn a shell command non-blocking with environment variables.
    ///
    /// SIP data is passed exclusively via environment variables — never
    /// interpolated into the command string — to prevent command injection.
    ///
    /// # Arguments
    ///
    /// * `cmd` — Shell command template, run via `sh -c`.
    /// * `env_vars` — `SIPNAB_*` name/value pairs set on the child.
    ///
    /// # Side effects
    ///
    /// Executes an external command: spawns `sh -c <cmd>` without waiting
    /// for it. First reaps finished children, booking their exit outcomes;
    /// if the pending-child queue is at `MAX_QUEUE_DEPTH` the event is
    /// dropped with a warning. On successful spawn the rate-limit exec count
    /// is incremented and the child is tracked (with its command) for later
    /// reaping; spawn failures are logged and swallowed. Every branch is
    /// counted in [`Self::outcomes`].
    fn spawn_command(&mut self, cmd: &Arc<str>, env_vars: &[(&str, String)]) {
        self.reap_children();

        if self.children.len() >= MAX_QUEUE_DEPTH {
            self.outcomes.queue_full = self.outcomes.queue_full.saturating_add(1);
            warn!(
                "Event exec queue depth ({}) exceeds limit ({}), dropping event",
                self.children.len(),
                MAX_QUEUE_DEPTH
            );
            return;
        }

        let mut command = Command::new("sh");
        command.arg("-c").arg(cmd.as_ref());
        for (key, value) in env_vars {
            command.env(key, value);
        }

        match command.spawn() {
            Ok(child) => {
                self.rate_window.record();
                self.outcomes.spawned = self.outcomes.spawned.saturating_add(1);
                self.children.push(TrackedChild {
                    child,
                    cmd: Arc::clone(cmd),
                });
            }
            Err(e) => {
                self.outcomes.spawn_failed = self.outcomes.spawn_failed.saturating_add(1);
                warn!("Failed to spawn event exec command `{cmd}`: {e}");
            }
        }
    }

    /// Return the current queue depth (number of tracked children).
    pub fn queue_depth(&self) -> usize {
        self.children.len()
    }
}

/// Report the hook totals once, at teardown.
///
/// Without this a run's last word on hook failures is whichever
/// order-of-magnitude line happened to be reached, which rounds 4,611 down to
/// "1000". This is an automated-response path: an operator who wired
/// `--on-dialog` to a firewall command and saw no error assumes the ban landed.
/// A run therefore has to say, exactly, how many of its commands worked and how
/// many did not — "no entries" and "entries I did not print" are the two
/// answers an operator must never have to distinguish.
///
/// Nothing here waits for a running command: a hook that hangs must not hold up
/// the process, so unfinished commands are named as unfinished instead. (Same
/// rule as the `--alert-exec` ledger and the scanner-kill totals.)
impl Drop for EventExecEngine {
    fn drop(&mut self) {
        // One last non-blocking sweep, so a command that finished after the
        // final event is still counted rather than reported as unfinished.
        self.reap_children();
        let counts = self.outcomes;
        if counts.spawned == 0 && counts.suppressed() == 0 {
            return;
        }
        if counts.any_trouble() {
            warn!(
                spawned = counts.spawned,
                succeeded = counts.succeeded,
                failed = counts.failed,
                unknown = counts.unknown,
                unfinished = counts.unfinished(),
                spawn_failed = counts.spawn_failed,
                rate_limited = counts.rate_limited,
                queue_full = counts.queue_full,
                "Event exec totals: {} command(s) run, {} succeeded, {} failed, \
                 {} with an unknowable status, {} still running at teardown; {} \
                 event(s) ran no command at all (rate limit {}, queue full {}, \
                 spawn failed {}). Failing hooks were reported, never retried; \
                 the capture was unaffected.",
                counts.spawned,
                counts.succeeded,
                counts.failed,
                counts.unknown,
                counts.unfinished(),
                counts.suppressed(),
                counts.rate_limited,
                counts.queue_full,
                counts.spawn_failed,
            );
        } else {
            info!(
                spawned = counts.spawned,
                succeeded = counts.succeeded,
                failed = counts.failed,
                unfinished = counts.unfinished(),
                "Event exec totals: {} command(s) run, {} succeeded, {} failed, \
                 {} still running at teardown",
                counts.spawned,
                counts.succeeded,
                counts.failed,
                counts.unfinished(),
            );
        }
    }
}

/// Calculate loss percentage for a stream as `lost / (received + lost)`
/// (0.0 when no packets).
fn loss_pct(stream: &RtpStream) -> f64 {
    let total = stream.packet_count + stream.lost_packets;
    if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    }
}

/// Rewrite legacy `%variable` placeholders to `$SIPNAB_VARIABLE` references.
///
/// This provides backwards compatibility for users who have existing command
/// templates using the old `%call_id`, `%from`, etc. syntax. The values are
/// passed as environment variables, never interpolated into the command string.
fn migrate_template_vars(template: &str) -> String {
    template
        .replace("%json", "$SIPNAB_JSON")
        .replace("%call_id", "$SIPNAB_CALL_ID")
        .replace("%from", "$SIPNAB_FROM")
        .replace("%to", "$SIPNAB_TO")
        .replace("%state", "$SIPNAB_STATE")
        .replace("%method", "$SIPNAB_METHOD")
        .replace("%stream_json", "$SIPNAB_STREAM_JSON")
        .replace("%ssrc", "$SIPNAB_SSRC")
        .replace("%mos", "$SIPNAB_MOS")
        .replace("%jitter", "$SIPNAB_JITTER")
        .replace("%loss", "$SIPNAB_LOSS")
        .replace("%src", "$SIPNAB_SRC")
        .replace("%rule", "$SIPNAB_RULE")
        .replace("%detail", "$SIPNAB_DETAIL")
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for template migration, rate limiting, MOS gating, and the
/// no-command no-op paths (no real hook commands are spawned).
#[cfg(test)]
mod tests {
    use super::*;

    /// A child whose status check errors must be cleaned up (killed and
    /// reaped), not silently forgotten — dropping a `Child` without waiting
    /// leaves a zombie. A still-running child is kept.
    #[test]
    fn reap_action_on_error_cleans_up() {
        use std::io;
        use std::process::ExitStatus;
        assert!(matches!(
            reap_action(&Err(io::Error::other("boom"))),
            ReapAction::Cleanup
        ));
        assert!(matches!(
            reap_action(&Ok::<Option<ExitStatus>, io::Error>(None)),
            ReapAction::Keep
        ));
    }

    /// Run `sh -c <cmd>` to completion and return its real exit status.
    fn status_of(cmd: &str) -> ExitStatus {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .expect("sh should run")
    }

    /// Fire the dialog hook `n` times, pausing so each child has exited before
    /// the next fire reaps it. Returns the ledger after a final reap.
    /// Fire `n` events and wait until every child they spawned has been reaped.
    ///
    /// Waits on the outcome, not on a clock. The previous version slept a fixed
    /// 10 ms per fire and reaped once, which assumes `sh -c` can start, run and
    /// exit inside that window. On a loaded machine it cannot, and the caller
    /// then reads zero outcomes for children that are alive and about to
    /// succeed or fail -- a test that reports "the hook did not fail" when the
    /// hook simply had not finished failing yet.
    ///
    /// That went red in CI while passing 20/20 locally, which is the signature
    /// of this exact bug: a sleep long enough on an idle box and too short on a
    /// busy one. The loop below is bounded, so a genuinely stuck child still
    /// fails the test rather than hanging it.
    fn fire_n(engine: &mut EventExecEngine, n: usize) -> ExecOutcomeCounts {
        let dialog = make_dialog();
        for _ in 0..n {
            engine.fire_dialog_event(&dialog);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            engine.reap_children();
            let out = engine.outcomes();
            // Every child that was spawned has now been accounted for, either
            // as a success or a failure. Cumulative across calls, which is what
            // the callers assert on.
            if out.succeeded + out.failed >= out.spawned {
                return out;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "waited 30s and {} of {} spawned hooks were never reaped",
                out.spawned - (out.succeeded + out.failed),
                out.spawned
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The reaper carries the exit status out instead of matching it with a
    /// wildcard. This is the defect itself: `Ok(Some(_)) => Remove` threw the
    /// status away, so a hook that failed and a hook that worked reached the
    /// same branch with the same (absent) information.
    #[test]
    fn reap_action_carries_the_exit_status() {
        let good = status_of("exit 0");
        let bad = status_of("exit 7");
        let ReapAction::Exited(observed_good) = reap_action(&Ok(Some(good))) else {
            panic!("a finished child must report Exited");
        };
        let ReapAction::Exited(observed_bad) = reap_action(&Ok(Some(bad))) else {
            panic!("a finished child must report Exited");
        };
        assert!(observed_good.success(), "exit 0 is a success");
        assert!(!observed_bad.success(), "exit 7 is a failure");
        assert_eq!(
            observed_bad.code(),
            Some(7),
            "the exact exit code must survive the reaper"
        );
    }

    /// A hook that exits non-zero and a hook that exits zero produce different
    /// ledgers. Before the fix both produced the same one: nothing.
    #[test]
    fn failing_hook_is_counted_separately_from_a_succeeding_one() {
        let mut succeeding = EventExecEngine::new(Some("exit 0".to_string()), None, 0, 3.0);
        let good = fire_n(&mut succeeding, 3);
        let mut failing = EventExecEngine::new(Some("exit 7".to_string()), None, 0, 3.0);
        let bad = fire_n(&mut failing, 3);

        assert_ne!(good, bad, "the two runs must be distinguishable");
        // Positive control on the success side: a fix that counted every
        // reaped child as a failure, or that counted nothing at all, would
        // still satisfy assert_ne alone.
        assert_eq!(good.spawned, 3);
        assert_eq!(good.succeeded, 3, "every `exit 0` is a success");
        assert_eq!(good.failed, 0, "no `exit 0` may be booked as a failure");
        assert_eq!(bad.spawned, 3);
        assert_eq!(bad.failed, 3, "every `exit 7` is a failure");
        assert_eq!(bad.succeeded, 0, "no `exit 7` may be booked as a success");
    }

    /// A failing hook must not change capture behaviour: it is not retried, and
    /// it does not stop later hooks from running.
    #[test]
    fn failing_hook_does_not_disarm_later_hooks() {
        let mut engine = EventExecEngine::new(Some("exit 7".to_string()), None, 0, 3.0);
        let after_first = fire_n(&mut engine, 1);
        assert_eq!(after_first.failed, 1, "the first hook failed");
        let after_more = fire_n(&mut engine, 2);
        assert_eq!(
            after_more.spawned, 3,
            "a failed hook must not stop later events from running theirs"
        );
        assert_eq!(
            after_more.failed, 3,
            "each failure is booked once — no retries"
        );
    }

    /// Every spawned command lands in exactly one bucket, so `unfinished` is
    /// what has not been accounted for yet rather than a free-floating number.
    #[test]
    fn outcome_counts_account_for_every_spawn() {
        let counts = ExecOutcomeCounts {
            spawned: 10,
            succeeded: 4,
            failed: 3,
            unknown: 1,
            spawn_failed: 2,
            rate_limited: 5,
            queue_full: 7,
        };
        assert_eq!(counts.settled(), 8);
        assert_eq!(counts.unfinished(), 2);
        assert_eq!(counts.suppressed(), 14);
        assert!(counts.any_trouble());
        let clean = ExecOutcomeCounts {
            spawned: 3,
            succeeded: 3,
            ..Default::default()
        };
        assert_eq!(clean.unfinished(), 0);
        assert!(!clean.any_trouble(), "an all-success run is not trouble");
    }

    /// Failure reporting escalates by order of magnitude: the first failure is
    /// always reported, and a broken hook firing at packet rate does not turn
    /// the log into the flood it is reporting.
    #[test]
    fn order_of_magnitude_reports_first_then_decades() {
        for n in [1u64, 10, 100, 1000, 10_000] {
            assert!(is_order_of_magnitude(n), "{n} is a power of ten");
        }
        for n in [0u64, 2, 9, 11, 99, 101, 999] {
            assert!(!is_order_of_magnitude(n), "{n} is not a power of ten");
        }
    }

    /// An event whose command is held back by the rate limit is counted, not
    /// dropped without trace — a run that ran no commands has to be able to say
    /// whether that is because none were needed or because all were suppressed.
    #[test]
    fn rate_limited_events_are_counted() {
        let mut engine = EventExecEngine::new(Some("exit 0".to_string()), None, 2, 3.0);
        let dialog = make_dialog();
        for _ in 0..5 {
            engine.fire_dialog_event(&dialog);
        }
        let counts = engine.outcomes();
        assert_eq!(counts.spawned, 2, "the limit of 2 per second is honoured");
        assert_eq!(
            counts.rate_limited, 3,
            "the other 3 events are on the books"
        );
        assert_eq!(counts.suppressed(), 3);
    }

    // The per-RTP-packet hot path guards the quality-event work on this; it must
    // be true iff a command is configured (else fire_quality_event no-ops and the
    // guard lets the hot path skip the StreamKey rebuild + store lookup).
    /// `quality_events_enabled` is true iff an `--on-quality` command is set.
    #[test]
    fn quality_events_enabled_tracks_command() {
        let off = EventExecEngine::new(None, None, 0, 4.0);
        assert!(!off.quality_events_enabled());
        let on = EventExecEngine::new(None, Some("echo hi".to_string()), 0, 4.0);
        assert!(on.quality_events_enabled());
    }

    use crate::capture::parse::TransportProto;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::dialog::SipDialog;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// The loopback IPv4 address used for all synthetic messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed timestamp (2024-06-15 12:00:00 UTC) for determinism.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a minimal dialog from a single INVITE.
    fn make_dialog() -> SipDialog {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: exec-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        SipDialog::new(&msg).expect("should create dialog")
    }

    /// Build a fresh single-packet PCMU RTP stream with SSRC 0xAABBCCDD.
    fn make_stream() -> RtpStream {
        let key = StreamKey {
            ssrc: 0xAABBCCDD,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0xAABBCCDD,
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, ts())
    }

    /// `%call_id` migrates to `$SIPNAB_CALL_ID`.
    #[test]
    fn migrate_template_vars_call_id() {
        let migrated = migrate_template_vars("echo %call_id");
        assert_eq!(migrated, "echo $SIPNAB_CALL_ID");
    }

    /// Multiple `%` placeholders in one template all migrate.
    #[test]
    fn migrate_template_vars_multiple() {
        let migrated = migrate_template_vars("notify --from=%from --to=%to --state=%state");
        assert!(migrated.contains("$SIPNAB_FROM"));
        assert!(migrated.contains("$SIPNAB_TO"));
        assert!(migrated.contains("$SIPNAB_STATE"));
    }

    /// The command template is stored verbatim — values are only ever
    /// passed as env vars, never interpolated (injection defense).
    #[test]
    fn env_var_injection_prevents_command_injection() {
        // A malicious call-id with shell metacharacters should NOT be
        // interpolated into the command string. It is only passed as an env var.
        let engine = EventExecEngine::new(Some("echo $SIPNAB_CALL_ID".to_string()), None, 10, 3.0);
        // The command template should be stored as-is (after migration)
        assert_eq!(
            engine.on_dialog_cmd.as_deref(),
            Some("echo $SIPNAB_CALL_ID")
        );
    }

    /// With rate_limit=10, exactly 10 of 15 exec attempts are allowed.
    #[test]
    fn rate_limiting_blocks_excess() {
        let mut engine = EventExecEngine::new(Some("true".to_string()), None, 10, 3.0);

        let _dialog = make_dialog();
        let mut fired = 0;

        for _ in 0..15 {
            if engine.check_rate_limit() {
                engine.rate_window.record();
                fired += 1;
            }
        }

        assert_eq!(fired, 10, "should only allow 10 execs with rate_limit=10");
    }

    /// Low jitter and zero loss yield an estimated MOS above 4.0.
    #[test]
    fn mos_estimation_good_quality() {
        // Good conditions: low jitter, no loss — uses canonical estimate_mos
        let mos = quality::estimate_mos(5.0, 0.0, Some("PCMU"));
        assert!(
            mos > 4.0,
            "good conditions should give MOS > 4.0: got {mos}"
        );
    }

    /// High jitter and heavy loss yield an estimated MOS below 3.0.
    #[test]
    fn mos_estimation_bad_quality() {
        // Bad conditions: high jitter, significant loss — uses canonical estimate_mos
        let mos = quality::estimate_mos(150.0, 15.0, None);
        assert!(mos < 3.0, "bad conditions should give MOS < 3.0: got {mos}");
    }

    /// Firing events with no commands configured neither panics nor spawns.
    #[test]
    fn no_cmd_configured_noop() {
        let mut engine = EventExecEngine::new(None, None, 10, 3.0);
        // Should not panic or spawn anything
        engine.fire_dialog_event(&make_dialog());

        let stream = make_stream();
        engine.fire_quality_event(&stream);
    }

    /// A fresh engine reports queue depth 0.
    #[test]
    fn queue_depth_tracking() {
        let engine = EventExecEngine::new(None, None, 10, 3.0);
        assert_eq!(engine.queue_depth(), 0);
    }

    /// Both dialog and quality templates are migrated at construction.
    #[test]
    fn legacy_template_migration_at_construction() {
        let engine = EventExecEngine::new(
            Some("echo %call_id %from".to_string()),
            Some("alert %mos %jitter".to_string()),
            10,
            3.0,
        );
        assert_eq!(
            engine.on_dialog_cmd.as_deref(),
            Some("echo $SIPNAB_CALL_ID $SIPNAB_FROM")
        );
        assert_eq!(
            engine.on_quality_cmd.as_deref(),
            Some("alert $SIPNAB_MOS $SIPNAB_JITTER")
        );
    }
}
