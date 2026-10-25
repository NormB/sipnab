// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Which of these files holds the call, asked without destroying the one open.
//!
//! `list_captures` narrows forty rotated files to the two that could hold a
//! call, by time. That is a filter, not an answer. The question an operator
//! actually has — "which of these holds Call-ID X" — could not be asked at
//! all: the only way inside another file is `open_capture`, documented
//! **Destructive**, which replaces every dialog and stream and mints a new
//! `capture_identity` that voids every cursor the caller holds.
//!
//! So this sweeps: a scratch store per file, the filter applied, the active
//! store untouched.
//!
//! # A partial sweep must never read as a complete one
//!
//! A sweep is bounded, and a bounded sweep that reports "no matches" when it
//! stopped early — or when it could not open one of the files — tells the
//! caller the call is not there. It is the same defect CT1 was: a check that
//! skipped its input and reported success.
//!
//! So [`SweepOutcome::complete`] is false whenever ANY file went unexamined,
//! for any reason, and [`SweepOutcome::unreadable`] names each one with why.
//! "Not found" is only trustworthy when `complete` is true.
//!
//! # Why a sweep is a job on its own thread
//!
//! The REST API and the MCP server share ONE thread running one
//! `tokio::runtime::Builder::new_current_thread()` ([`crate::app::servers`]).
//! A sweep read inside the tool handler held that thread for the whole read,
//! so every other MCP call and every REST request waited behind it — the
//! defect [`crate::mcp::load`] records for `open_capture`, in a second tool.
//!
//! So a sweep runs on a plain OS thread, as `open_capture`'s load does, and
//! writes its progress where a handler can read it. `find_in_captures` starts
//! it and waits, asynchronously and for at most `--mcp-max-wait-seconds`, for
//! it to finish. A sweep that finishes inside the wait is answered in that one
//! call. One that does not is answered with its job id, `status: running` and
//! its progress; the agent polls `find_in_captures_status` and may stop it
//! with `cancel_find_in_captures`. The finished result is handed over once.
//!
//! The thread asks [`stop_reason`] before every file and before every packet:
//! a SIGTERM, a cancel and the deadline each stop a sweep inside a file, not
//! only between files. [`crate::cli::McpSweepJobLimits`], from
//! `--mcp-sweep-max-running`, `--mcp-sweep-max-held-results` and
//! `--mcp-sweep-result-retention-secs`, bounds what the jobs hold.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;

pub use crate::capture::sweep::{
    FileMatch, MAX_REASON_CHARS, StoppedBecause, SweepOutcome, UnreadableFile, bound, outcome,
    stop_reason, unreadable_file,
};

/// Files one sweep will open before stopping when the operator has not set
/// `--mcp-sweep-max-files`: [`crate::cli::Cli::DEFAULT_MCP_SWEEP_MAX_FILES`].
///
/// A capture root holds rotated files, and forty is a normal day. Twenty is
/// enough to answer "which of the recent ones" without turning one tool call
/// into a full read of a spool that may hold months. The operator's setting
/// replaces it as the ceiling a per-call `max_files` is clamped to.
pub const DEFAULT_MAX_FILES: u64 = crate::cli::Cli::DEFAULT_MCP_SWEEP_MAX_FILES;

/// Wall-clock a sweep may spend before stopping, in milliseconds, when the
/// operator has not set `--mcp-sweep-deadline-ms`:
/// [`crate::cli::Cli::DEFAULT_MCP_SWEEP_DEADLINE_MS`].
///
/// The bound that actually matters. A file's cost is its size, which the
/// caller cannot see and a file count does not capture: twenty small files and
/// twenty 2 GB files are the same `max_files` and wildly different waits. The
/// sweep checks it before every file and every packet, so it also bounds the
/// last file's read.
pub const DEFAULT_DEADLINE_MS: u64 = crate::cli::Cli::DEFAULT_MCP_SWEEP_DEADLINE_MS;

/// The response `find_in_captures`, `find_in_captures_status` and
/// `cancel_find_in_captures` return: one shape for one job.
///
/// A typed shape rather than an inline `json!`, so the tools declare an output
/// schema: a client written against an untyped answer cannot tell a renamed
/// key from a missing one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct FindInCapturesResponse {
    /// 2: the job fields arrived, and `sweep` is absent while the job runs.
    pub schema_version: u32,
    /// The job's id, for `find_in_captures_status` and
    /// `cancel_find_in_captures`.
    pub job_id: String,
    /// Running, done or canceled.
    pub status: JobStatus,
    /// The limits this sweep runs under, after the caller's request was
    /// clamped to the operator's ceilings.
    pub limits: AppliedLimits,
    /// How far it has got.
    pub progress: SweepProgress,
    /// What the sweep covered and found, once it has finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sweep: Option<SweepOutcome>,
}

/// The limits one sweep ran under.
///
/// Reported so a caller can see the clamp: a `max_files` of 40 against a
/// `--mcp-sweep-max-files` of 20 comes back as 20.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct AppliedLimits {
    /// Files the sweep was allowed to open.
    pub max_files: usize,
    /// Wall-clock the sweep was allowed to spend, in milliseconds.
    pub deadline_ms: u64,
}

impl From<crate::cli::McpSweepLimits> for AppliedLimits {
    fn from(limits: crate::cli::McpSweepLimits) -> Self {
        Self {
            max_files: limits.max_files,
            deadline_ms: limits.deadline_ms,
        }
    }
}

/// Where a sweep job is, as `status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[serde(rename_all = "kebab-case")]
pub enum JobStatus {
    /// Still reading. `progress` moves; there is no `sweep` yet.
    Running,
    /// Finished, for any reason but a cancel. `sweep` holds the result.
    Done,
    /// Stopped by `cancel_find_in_captures`. `sweep` holds what it covered.
    Canceled,
}

/// How far a sweep job has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SweepProgress {
    /// Files opened and read to the end so far.
    pub files_examined: usize,
    /// Candidates the root held when the sweep started.
    pub files_total: usize,
    /// Milliseconds since the sweep started, or that it ran for once finished.
    pub elapsed_ms: u64,
    /// Whether `cancel_find_in_captures` has asked this sweep to stop.
    pub cancel_requested: bool,
}

/// What one sweep reads and how: the inputs a job's thread owns.
pub struct SweepPlan {
    /// The files to open, in the order to open them, already inside the root.
    pub candidates: Vec<PathBuf>,
    /// The filter a dialog must match.
    pub filter: crate::sip::dsl::FilterExpr,
    /// The limits after the clamp.
    pub limits: crate::cli::McpSweepLimits,
    /// Dialog and stream capacity of each file's scratch stores.
    pub row_cap: usize,
    /// The run's pipeline options, which each file is classified with.
    pub options: crate::pipeline::PipelineOptions,
}

/// One sweep, shared between its thread and the tool calls that poll it.
#[derive(Debug)]
struct SweepJob {
    /// The id the tools take, `sweep-<n>`.
    id: String,
    /// The limits it runs under.
    limits: AppliedLimits,
    /// Candidates the root held.
    files_total: usize,
    /// When it started.
    started: Instant,
    /// Set by `cancel_find_in_captures`; read before every file and packet.
    cancel: AtomicBool,
    /// Files read to the end so far.
    files_examined: AtomicUsize,
    /// The result and when it was ready, once the thread is done.
    finished: Mutex<Option<(SweepOutcome, Instant)>>,
    /// Becomes true when `finished` is filled, for waiters.
    done: tokio::sync::watch::Sender<bool>,
    /// The test pause this job's reader stops at.
    #[cfg(test)]
    hold: Option<Arc<TestHold>>,
}

impl SweepJob {
    /// Milliseconds since the start, by this job's clock.
    fn elapsed_ms(&self) -> u64 {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        #[cfg(test)]
        let ms = ms.saturating_add(self.hold.as_ref().map_or(0, |h| h.clock_skew_ms()));
        ms
    }

    /// [`stop_reason`] for this job, now.
    fn stop_reason(&self) -> Option<StoppedBecause> {
        stop_reason(
            crate::signals::shutdown_requested(),
            self.cancel.load(Ordering::Relaxed),
            self.elapsed_ms(),
            self.limits.deadline_ms,
        )
    }

    /// When the result was ready, once it is.
    fn finished_at(&self) -> Option<Instant> {
        self.finished.lock().as_ref().map(|(_, at)| *at)
    }

    /// The answer the tools return for this job now.
    fn report(&self) -> FindInCapturesResponse {
        let finished = self.finished.lock().clone();
        let elapsed_ms = match &finished {
            Some((_, at)) => {
                u64::try_from(at.duration_since(self.started).as_millis()).unwrap_or(u64::MAX)
            }
            None => self.elapsed_ms(),
        };
        let status = match &finished {
            None => JobStatus::Running,
            Some((o, _)) if o.stopped_because == Some(StoppedBecause::Canceled) => {
                JobStatus::Canceled
            }
            Some(_) => JobStatus::Done,
        };
        FindInCapturesResponse {
            schema_version: 2,
            job_id: self.id.clone(),
            status,
            limits: self.limits,
            progress: SweepProgress {
                files_examined: self.files_examined.load(Ordering::Relaxed),
                files_total: self.files_total,
                elapsed_ms,
                cancel_requested: self.cancel.load(Ordering::Relaxed),
            },
            sweep: finished.map(|(o, _)| o),
        }
    }

    /// Read every candidate the plan names, within its limits: the shared
    /// sweep, [`crate::capture::sweep::sweep_files`], told to stop by this
    /// job's cancel, deadline and the process's shutdown.
    fn run(&self, plan: &SweepPlan) -> SweepOutcome {
        let between_files = || self.stop_reason();
        let inside_file = || {
            #[cfg(test)]
            if let Some(h) = &self.hold {
                h.look();
            }
            self.stop_reason()
        };
        let examined = |n: usize| self.files_examined.store(n, Ordering::Relaxed);
        crate::capture::sweep::sweep_files(
            &crate::capture::sweep::SweepInput {
                candidates: &plan.candidates,
                filter: &plan.filter,
                row_cap: plan.row_cap,
                options: &plan.options,
                max_files: plan.limits.max_files,
            },
            &crate::capture::sweep::SweepControl {
                between_files: &between_files,
                inside_file: &inside_file,
                examined: &examined,
            },
        )
    }
}

/// The sweep jobs one MCP server runs and the results it holds.
///
/// Shared by every session clone of the server, for the reason the capture
/// state is: `SipnabMcp` is cloned per HTTP session, and a per-clone table
/// would let a job started in one session be unknown to the next, and would
/// give each session its own running bound.
///
/// A start past [`McpSweepJobLimits::max_running`] running sweeps is refused,
/// naming `cancel_find_in_captures`, rather than queued: a queue is unbounded
/// work deferred. Expired and surplus results are reaped whenever a sweep tool
/// is called.
///
/// [`McpSweepJobLimits::max_running`]: crate::cli::McpSweepJobLimits::max_running
#[derive(Debug, Default)]
pub struct SweepJobs {
    /// The bounds on running sweeps and held results, from the operator's
    /// settings.
    limits: crate::cli::McpSweepJobLimits,
    /// The jobs, running and finished, and the next id.
    table: Mutex<JobTable>,
    /// A pause the next sweep's reader stops at, for a test that needs a sweep
    /// held mid-read without racing it.
    #[cfg(test)]
    hold: Mutex<Option<Arc<TestHold>>>,
}

/// The jobs and the id counter, under one lock so a bound is checked and a
/// job admitted in one step.
#[derive(Debug, Default)]
struct JobTable {
    /// The number the next job's id carries.
    next: u64,
    /// Running jobs and finished results not yet collected, oldest first.
    jobs: Vec<Arc<SweepJob>>,
}

impl JobTable {
    /// Drop results that finished more than `limits.result_retention_secs`
    /// before `now`, then the oldest results past `limits.max_held_results`.
    fn reap(&mut self, now: Instant, limits: crate::cli::McpSweepJobLimits) {
        let retention = Duration::from_secs(limits.result_retention_secs);
        self.jobs.retain(|j| {
            j.finished_at()
                .is_none_or(|at| now.saturating_duration_since(at) <= retention)
        });
        let mut held = self
            .jobs
            .iter()
            .filter(|j| j.finished_at().is_some())
            .count();
        self.jobs.retain(|j| {
            if held > limits.max_held_results && j.finished_at().is_some() {
                held -= 1;
                false
            } else {
                true
            }
        });
    }

    /// The job called `id`.
    fn find(&self, id: &str) -> Option<Arc<SweepJob>> {
        self.jobs.iter().find(|j| j.id == id).cloned()
    }
}

/// The refusal for a job id the table does not hold, reporting the bounds
/// that drop a result and the settings that set them.
fn unknown_job(id: &str, limits: crate::cli::McpSweepJobLimits) -> String {
    format!(
        "unknown sweep job '{}': it was never started, its result was already \
         handed over, it finished more than {} seconds ago \
         (--mcp-sweep-result-retention-secs), or {} newer results were waiting \
         (--mcp-sweep-max-held-results)",
        bound(id),
        limits.result_retention_secs,
        limits.max_held_results
    )
}

impl SweepJobs {
    /// An empty table bounded by `limits`.
    #[must_use]
    pub fn new(limits: crate::cli::McpSweepJobLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Start a sweep of `plan` on its own thread.
    ///
    /// # Returns
    ///
    /// The new job's id.
    ///
    /// # Errors
    ///
    /// A message reporting the configured running bound and naming its
    /// setting when that many already run, or why the thread could not be
    /// spawned.
    ///
    /// # Side effects
    ///
    /// Spawns a detached OS thread named `mcp-sweep` that reads the plan's
    /// files into scratch stores and records the result in this table. The
    /// server runtime never waits on it.
    pub fn start(&self, plan: SweepPlan, now: Instant) -> Result<String, String> {
        let job = {
            let mut table = self.table.lock();
            table.reap(now, self.limits);
            let running = table
                .jobs
                .iter()
                .filter(|j| j.finished_at().is_none())
                .count();
            let max = self.limits.max_running;
            if running >= max {
                return Err(format!(
                    "{running} sweeps are already running, the most one server runs at \
                     once ({max}, set by --mcp-sweep-max-running or [limits] \
                     mcp_sweep_max_running); poll one with find_in_captures_status \
                     or stop one with cancel_find_in_captures, then start this one"
                ));
            }
            table.next += 1;
            let (done, _) = tokio::sync::watch::channel(false);
            let job = Arc::new(SweepJob {
                id: format!("sweep-{}", table.next),
                limits: plan.limits.into(),
                files_total: plan.candidates.len(),
                started: now,
                cancel: AtomicBool::new(false),
                files_examined: AtomicUsize::new(0),
                finished: Mutex::new(None),
                done,
                #[cfg(test)]
                hold: self.hold.lock().take(),
            });
            table.jobs.push(Arc::clone(&job));
            job
        };
        let worker = Arc::clone(&job);
        let spawned = std::thread::Builder::new()
            .name("mcp-sweep".to_string())
            .spawn(move || {
                let outcome = worker.run(&plan);
                *worker.finished.lock() = Some((outcome, Instant::now()));
                worker.done.send_replace(true);
            });
        if let Err(e) = spawned {
            self.table.lock().jobs.retain(|j| !Arc::ptr_eq(j, &job));
            return Err(format!("cannot start the sweep thread: {e}"));
        }
        Ok(job.id.clone())
    }

    /// Wait until job `id` finishes or `wait` passes, without blocking the
    /// thread the caller runs on. Returns at once for an unknown id.
    pub async fn wait(&self, id: &str, wait: Duration) {
        let Some(mut done) = self.table.lock().find(id).map(|j| j.done.subscribe()) else {
            return;
        };
        let _ = tokio::time::timeout(wait, done.wait_for(|d| *d)).await;
    }

    /// The answer for job `id` at `now`: its progress while it runs, and its
    /// result once, after which the job is gone.
    ///
    /// # Errors
    ///
    /// A message naming `id` when the table does not hold it.
    pub fn collect(&self, id: &str, now: Instant) -> Result<FindInCapturesResponse, String> {
        let mut table = self.table.lock();
        table.reap(now, self.limits);
        let job = table.find(id).ok_or_else(|| unknown_job(id, self.limits))?;
        let report = job.report();
        if report.sweep.is_some() {
            table.jobs.retain(|j| !Arc::ptr_eq(j, &job));
        }
        Ok(report)
    }

    /// Ask job `id` to stop. Its thread stops before its next packet or file;
    /// a poll then reports `canceled` with what it covered.
    ///
    /// # Errors
    ///
    /// A message naming `id` when the table does not hold it.
    pub fn cancel(&self, id: &str, now: Instant) -> Result<(), String> {
        let mut table = self.table.lock();
        table.reap(now, self.limits);
        let job = table.find(id).ok_or_else(|| unknown_job(id, self.limits))?;
        job.cancel.store(true, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
impl SweepJobs {
    /// Hold the next sweep this table starts at `hold`.
    pub(crate) fn hold_next(&self, hold: Arc<TestHold>) {
        *self.hold.lock() = Some(hold);
    }

    /// Drop expired and surplus results as at `now`.
    pub(crate) fn reap(&self, now: Instant) {
        self.table.lock().reap(now, self.limits);
    }

    /// Whether the table holds job `id`.
    pub(crate) fn holds(&self, id: &str) -> bool {
        self.table.lock().find(id).is_some()
    }

    /// When job `id`'s result was ready.
    pub(crate) fn finished_at(&self, id: &str) -> Option<Instant> {
        self.table.lock().find(id).and_then(|j| j.finished_at())
    }

    /// Wait, up to [`TestHold::LIVENESS`], for job `id` to finish.
    pub(crate) async fn wait_finished(&self, id: &str) {
        self.wait(id, TestHold::LIVENESS).await;
    }
}

/// The deterministic pause a test holds a sweep at, shared with the other
/// readers a test must hold mid-read.
#[cfg(test)]
pub(crate) use crate::test_utils::TestHold;

#[cfg(test)]
mod tests {
    use super::*;

    /// A sweep that examined everything, found nothing, and says so.
    #[test]
    fn a_complete_sweep_that_found_nothing_is_trustworthy() {
        let o = outcome(vec![], 3, 3, vec![], None);
        assert!(o.complete);
        assert!(o.matches.is_empty());
    }

    /// A sweep that stopped at its file limit is NOT complete.
    ///
    /// The whole reason `complete` exists. An empty `matches` from a truncated
    /// sweep says "I did not find it in what I read", and a caller who reads
    /// it as "it is not there" stops looking in the file that has it.
    #[test]
    fn a_sweep_that_stopped_early_is_never_complete() {
        for stopped in [StoppedBecause::Deadline, StoppedBecause::MaxFiles] {
            let o = outcome(vec![], 2, 40, vec![], Some(stopped));
            assert!(
                !o.complete,
                "a sweep stopped by {stopped:?} examined 2 of 40 and cannot \
                 report absence"
            );
            assert_eq!(o.stopped_because, Some(stopped));
        }
    }

    /// One unreadable file makes the whole sweep incomplete.
    ///
    /// Even when every other file was read to the end. The file nobody could
    /// open is exactly the one that might hold the call, and a sweep that
    /// counted it as examined would be the CT1 defect in a new place.
    #[test]
    fn one_unreadable_file_makes_the_sweep_incomplete() {
        let o = outcome(
            vec![],
            2,
            3,
            vec![UnreadableFile {
                filename: "rotated-07.pcap".to_string(),
                reason: "permission denied".to_string(),
            }],
            None,
        );
        assert!(
            !o.complete,
            "two of three files read and the third refused: absence is not \
             established"
        );
        assert_eq!(o.unreadable.len(), 1);
        assert_eq!(o.unreadable[0].filename, "rotated-07.pcap");
        assert!(
            !o.unreadable[0].reason.is_empty(),
            "a file is never listed as unreadable without saying why"
        );
    }

    /// The unreadable clause decides on its own, with the counts agreeing.
    ///
    /// **First of two tests owed** for a mutation that survived. The original
    /// test for this passed `files_examined: 2, files_total: 3` — so the count
    /// clause had already made `complete` false and deleting
    /// `unreadable.is_empty()` changed nothing. It asserted the right outcome
    /// through the wrong clause, which is a test that cannot fail for the
    /// reason it was written.
    ///
    /// Today's caller cannot produce this shape: it increments `examined` only
    /// on success, so an unreadable file always leaves `examined < total`. The
    /// clause is a guard against that changing — a future caller that counted
    /// an attempted file as examined would otherwise report a sweep with an
    /// unread file in it as exhaustive.
    #[test]
    fn the_unreadable_clause_is_load_bearing_on_its_own() {
        let o = outcome(
            vec![],
            3,
            3,
            vec![unreadable_file("rotated-07.pcap", "permission denied")],
            None,
        );
        assert!(
            !o.complete,
            "every candidate counted as examined and one of them was still \
             unread: absence is not established, and only the unreadable list \
             says so"
        );
    }

    /// **Second of two.** All three conditions, and only their conjunction.
    ///
    /// Driven as a truth table rather than as three separate cases, because
    /// what matters is that `complete` is true in exactly one of the eight
    /// combinations. A clause that stops contributing shows up here as a
    /// second `true`.
    #[test]
    fn completeness_is_the_conjunction_of_all_three() {
        let bad = || vec![unreadable_file("x.pcap", "nope")];
        let mut completes = 0;
        for stopped in [None, Some(StoppedBecause::Deadline)] {
            for unreadable in [Vec::new(), bad()] {
                for (examined, total) in [(3usize, 3usize), (2, 3)] {
                    let o = outcome(vec![], examined, total, unreadable.clone(), stopped);
                    let expected = stopped.is_none() && unreadable.is_empty() && examined == total;
                    assert_eq!(
                        o.complete,
                        expected,
                        "stopped={stopped:?} unreadable={} examined={examined}/{total}",
                        unreadable.len()
                    );
                    if o.complete {
                        completes += 1;
                    }
                }
            }
        }
        assert_eq!(
            completes, 1,
            "exactly one of the eight combinations may report a complete sweep"
        );
    }

    /// Finding a match does not make an incomplete sweep complete.
    ///
    /// The tempting shortcut: the caller got an answer, so the truncation
    /// stopped mattering. It did not — a second file may hold the same
    /// Call-ID, which on a rotated spool is the normal case for a call that
    /// spans a rotation.
    #[test]
    fn a_match_does_not_excuse_an_incomplete_sweep() {
        let o = outcome(
            vec![FileMatch {
                filename: "rotated-03.pcap".to_string(),
                dialogs_matched: 1,
                first_call_id: Some("abc@example.com".to_string()),
            }],
            5,
            40,
            vec![],
            Some(StoppedBecause::Deadline),
        );
        assert!(!o.complete);
        assert_eq!(o.matches.len(), 1);
    }

    /// The stop rule: nothing stops a sweep inside its deadline, the deadline
    /// stops it at the millisecond it is reached, and a shutdown wins over a
    /// cancel, which wins over the deadline.
    #[test]
    fn the_stop_rule_orders_shutdown_then_cancel_then_deadline() {
        assert_eq!(stop_reason(false, false, 999, 1000), None);
        assert_eq!(
            stop_reason(false, false, 1000, 1000),
            Some(StoppedBecause::Deadline)
        );
        assert_eq!(
            stop_reason(false, true, 0, 1000),
            Some(StoppedBecause::Canceled)
        );
        assert_eq!(
            stop_reason(true, false, 0, 1000),
            Some(StoppedBecause::Shutdown)
        );
        assert_eq!(
            stop_reason(true, true, 5000, 1000),
            Some(StoppedBecause::Shutdown)
        );
        assert_eq!(
            stop_reason(false, true, 5000, 1000),
            Some(StoppedBecause::Canceled)
        );
    }

    /// Every reason's response spelling is the one serde writes, so a stopped
    /// read's message and the `stopped_because` field name the same thing.
    #[test]
    fn a_stop_reason_is_spelled_as_serde_spells_it() -> Result<(), Box<dyn std::error::Error>> {
        for r in [
            StoppedBecause::Deadline,
            StoppedBecause::MaxFiles,
            StoppedBecause::Canceled,
            StoppedBecause::Shutdown,
        ] {
            assert_eq!(serde_json::to_value(r)?, r.as_str());
        }
        Ok(())
    }

    /// A reason from the OS cannot spend an agent's context.
    #[test]
    fn an_unreadable_reason_is_bounded() {
        let long = "x".repeat(4096);
        let f = unreadable_file("a.pcap", &long);
        assert!(
            f.reason.chars().count() <= MAX_REASON_CHARS,
            "reason is {} chars, over the {MAX_REASON_CHARS} bound",
            f.reason.chars().count()
        );
    }

    /// Control characters never reach the report.
    ///
    /// A filename comes off the filesystem and a reason comes from libpcap.
    /// Both are written to a terminal and into an agent's context.
    #[test]
    fn control_characters_are_stripped_from_a_reason() {
        let f = unreadable_file("a.pcap", "cannot open\u{1b}[2J\u{7}file");
        assert_eq!(f.reason, "cannot open[2Jfile");
    }
}
