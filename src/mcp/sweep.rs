// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! only between files. [`MAX_RUNNING_SWEEPS`], [`MAX_HELD_RESULTS`] and
//! [`RESULT_RETENTION`] bound what the jobs hold.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::Serialize;

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

/// Longest reason string reported for a file that could not be read.
///
/// The text comes from the OS and from libpcap, and it reaches an agent's
/// context. Bounded for the reason every other borrowed string here is.
pub const MAX_REASON_CHARS: usize = 200;

/// Why a sweep stopped before examining every candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[serde(rename_all = "kebab-case")]
pub enum StoppedBecause {
    /// The wall-clock deadline passed.
    Deadline,
    /// The file limit was reached.
    MaxFiles,
    /// `cancel_find_in_captures` stopped it.
    Canceled,
    /// The process is shutting down.
    Shutdown,
}

impl StoppedBecause {
    /// The name the response spells it with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::MaxFiles => "max-files",
            Self::Canceled => "canceled",
            Self::Shutdown => "shutdown",
        }
    }
}

/// A file the sweep could not examine, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct UnreadableFile {
    /// The file's name, never its path.
    pub filename: String,
    /// What went wrong, bounded to [`MAX_REASON_CHARS`].
    pub reason: String,
}

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

/// What one sweep found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SweepOutcome {
    /// Files with at least one dialog the filter selected.
    pub matches: Vec<FileMatch>,
    /// Files opened and read to the end.
    pub files_examined: usize,
    /// Candidates the root held.
    pub files_total: usize,
    /// Files the sweep could not read, each with its reason. Never a silent
    /// skip: a file nobody looked in is the reason a "not found" can lie.
    pub unreadable: Vec<UnreadableFile>,
    /// Why the sweep stopped early, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_because: Option<StoppedBecause>,
    /// True only when every candidate was examined and every one was readable.
    ///
    /// **Read this before believing an empty `matches`.** A bounded sweep that
    /// stopped early, or that could not open a file, has not shown the call is
    /// absent — only that it did not find it in what it managed to read.
    pub complete: bool,
}

/// One file that held something the filter selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct FileMatch {
    /// The file's name, never its path.
    pub filename: String,
    /// How many dialogs in it the filter selected.
    pub dialogs_matched: usize,
    /// The first matching Call-ID, so a caller can go straight to
    /// `open_capture` with something to look for.
    pub first_call_id: Option<String>,
}

/// Build an outcome, deciding `complete` from the evidence rather than from a
/// caller's opinion of it.
///
/// The one place that decision is made. Two callers computing it separately is
/// how one of them comes to report a truncated sweep as exhaustive — and the
/// whole value of the field is that it can be trusted.
#[must_use]
pub fn outcome(
    matches: Vec<FileMatch>,
    files_examined: usize,
    files_total: usize,
    unreadable: Vec<UnreadableFile>,
    stopped_because: Option<StoppedBecause>,
) -> SweepOutcome {
    // Complete means EVERY candidate was examined and every one was readable.
    // A match does not excuse a truncation: on a rotated spool a call that
    // spans a rotation is in two files, so finding it in one says nothing
    // about the other.
    let complete =
        stopped_because.is_none() && unreadable.is_empty() && files_examined == files_total;
    SweepOutcome {
        matches,
        files_examined,
        files_total,
        unreadable,
        stopped_because,
        complete,
    }
}

/// Record one file the sweep could not read.
///
/// Never a silent skip. The file nobody could open is exactly the one that
/// might hold the call, and counting it as examined would let a "not found"
/// lie.
#[must_use]
pub fn unreadable_file(filename: &str, reason: &str) -> UnreadableFile {
    UnreadableFile {
        filename: bound(filename),
        reason: bound(reason),
    }
}

/// Bound one borrowed string and strip what a terminal would act on.
fn bound(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

/// Sweeps one server runs at once.
///
/// Each sweep is an OS thread reading capture files from one disk, so sweeps
/// past a handful compete for the same disk and finish no sooner together
/// than one after another; four lets an agent run a few questions side by
/// side without letting a loop of calls start a thread per call. A start past
/// it is refused, naming `cancel_find_in_captures`, rather than queued: a
/// queue is unbounded work deferred.
pub const MAX_RUNNING_SWEEPS: usize = 4;

/// Finished results one server keeps for collection at once.
///
/// A result waits for its poll, and an agent that never polls would otherwise
/// leave one behind per sweep. Past this many the oldest finished result is
/// dropped. Sixteen is four rounds of [`MAX_RUNNING_SWEEPS`].
pub const MAX_HELD_RESULTS: usize = 16;

/// How long a finished result waits for its poll before it is dropped: ten
/// minutes from the moment the sweep finished.
///
/// Long enough for an agent that started a sweep, did other work and came
/// back; short enough that results nobody collects do not outlive the
/// conversation that asked for them. Dropped results are reaped whenever a
/// sweep tool is called.
pub const RESULT_RETENTION: Duration = Duration::from_secs(600);

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

/// Why a running sweep must stop now, or `None` to go on.
///
/// The one rule, asked before every file and before every packet. A shutdown
/// wins over a cancel and a cancel over the deadline, so the reason reported
/// is the one the caller can act on least: a process that is stopping is
/// stopping whatever the agent asked.
#[must_use]
pub fn stop_reason(
    shutdown: bool,
    canceled: bool,
    elapsed_ms: u64,
    deadline_ms: u64,
) -> Option<StoppedBecause> {
    if shutdown {
        Some(StoppedBecause::Shutdown)
    } else if canceled {
        Some(StoppedBecause::Canceled)
    } else if elapsed_ms >= deadline_ms {
        Some(StoppedBecause::Deadline)
    } else {
        None
    }
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

    /// Read every candidate the plan names, within its limits.
    fn run(&self, plan: &SweepPlan) -> SweepOutcome {
        let mut matches = Vec::new();
        let mut unreadable = Vec::new();
        let mut examined = 0usize;
        let mut stopped = None;
        for path in &plan.candidates {
            if examined >= plan.limits.max_files {
                stopped = Some(StoppedBecause::MaxFiles);
                break;
            }
            // Before each file as well as inside it: a file the sweep never
            // opens costs nothing to skip.
            if let Some(reason) = self.stop_reason() {
                stopped = Some(reason);
                break;
            }
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            // A scratch pair per file. The active stores are never touched:
            // that is the whole difference between this and `open_capture`,
            // and it is what lets a caller keep every cursor it holds.
            let scratch_dialogs = Arc::new(RwLock::new(
                crate::sip::dialog_store::DialogStore::new(plan.row_cap, false),
            ));
            let scratch_streams = Arc::new(RwLock::new(
                crate::rtp::stream_store::StreamStore::new(plan.row_cap),
            ));
            let stop = || {
                #[cfg(test)]
                if let Some(h) = &self.hold {
                    h.look();
                }
                self.stop_reason()
                    .map(|r| format!("sweep stopped: {}", r.as_str()))
            };
            // The capture layer's reader, not `mcp::load`'s wrapper: that one
            // records a partial read against the LOADED capture's completeness,
            // and a scratch file this sweep stopped reading says nothing about
            // the capture an agent is working in.
            let read = crate::capture::replay::read_into_stores_until(
                path,
                &plan.options,
                &scratch_dialogs,
                &scratch_streams,
                &AtomicU64::new(0),
                &stop,
            );
            if let Some(e) = read.error {
                // A read the sweep itself ended is a stopped sweep, not an
                // unreadable file: the file was fine.
                if let Some(reason) = self.stop_reason() {
                    stopped = Some(reason);
                    break;
                }
                unreadable.push(unreadable_file(&filename, &e));
                continue;
            }
            examined += 1;
            self.files_examined.store(examined, Ordering::Relaxed);

            let ds = scratch_dialogs.read();
            let ss = scratch_streams.read();
            let capture = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);
            // Built from the SCRATCH store, so a MOS filter reads this file's
            // own RTCP rather than the loaded capture's -- the whole point
            // being that the two are never mixed.
            let delay = crate::rtp::quality::MosDelay::from_capture(&ss);
            let mut hits = 0usize;
            let mut first_call_id = None;
            for d in ds.iter() {
                let streams: Vec<&crate::rtp::stream::RtpStream> =
                    ss.streams_for(&d.call_id).collect();
                if plan.filter.matches_dialog(d, &streams, capture, delay) {
                    hits += 1;
                    if first_call_id.is_none() {
                        first_call_id = Some(d.call_id.clone());
                    }
                }
            }
            if hits > 0 {
                matches.push(FileMatch {
                    filename,
                    dialogs_matched: hits,
                    // A Call-ID is attacker-chosen text, and it is also the
                    // handle the caller feeds straight to `open_capture` --
                    // the same trade `MESSAGE_VERBATIM_FIELDS` records for
                    // `call_id`, so it travels verbatim and the response-level
                    // provenance note covers it.
                    first_call_id,
                });
            }
        }
        outcome(
            matches,
            examined,
            plan.candidates.len(),
            unreadable,
            stopped,
        )
    }
}

/// The sweep jobs one MCP server runs and the results it holds.
///
/// Shared by every session clone of the server, for the reason the capture
/// state is: `SipnabMcp` is cloned per HTTP session, and a per-clone table
/// would let a job started in one session be unknown to the next, and would
/// give each session its own [`MAX_RUNNING_SWEEPS`].
#[derive(Debug, Default)]
pub struct SweepJobs {
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
    /// Drop results older than [`RESULT_RETENTION`] at `now`, then the oldest
    /// results past [`MAX_HELD_RESULTS`].
    fn reap(&mut self, now: Instant) {
        self.jobs.retain(|j| {
            j.finished_at()
                .is_none_or(|at| now.saturating_duration_since(at) <= RESULT_RETENTION)
        });
        let mut held = self
            .jobs
            .iter()
            .filter(|j| j.finished_at().is_some())
            .count();
        self.jobs.retain(|j| {
            if held > MAX_HELD_RESULTS && j.finished_at().is_some() {
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

/// The refusal for a job id the table does not hold.
fn unknown_job(id: &str) -> String {
    format!(
        "unknown sweep job '{}': it was never started, its result was already \
         handed over, or it finished more than {} seconds ago",
        bound(id),
        RESULT_RETENTION.as_secs()
    )
}

impl SweepJobs {
    /// Start a sweep of `plan` on its own thread.
    ///
    /// # Returns
    ///
    /// The new job's id.
    ///
    /// # Errors
    ///
    /// A message naming [`MAX_RUNNING_SWEEPS`] when that many already run, or
    /// why the thread could not be spawned.
    ///
    /// # Side effects
    ///
    /// Spawns a detached OS thread named `mcp-sweep` that reads the plan's
    /// files into scratch stores and records the result in this table. The
    /// server runtime never waits on it.
    pub fn start(&self, plan: SweepPlan, now: Instant) -> Result<String, String> {
        let job = {
            let mut table = self.table.lock();
            table.reap(now);
            let running = table
                .jobs
                .iter()
                .filter(|j| j.finished_at().is_none())
                .count();
            if running >= MAX_RUNNING_SWEEPS {
                return Err(format!(
                    "{running} sweeps are already running, the most one server runs at \
                     once ({MAX_RUNNING_SWEEPS}); poll one with find_in_captures_status \
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
        table.reap(now);
        let job = table.find(id).ok_or_else(|| unknown_job(id))?;
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
        table.reap(now);
        let job = table.find(id).ok_or_else(|| unknown_job(id))?;
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
        self.table.lock().reap(now);
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

/// A deterministic pause inside a sweep's read, for tests.
///
/// The reader asks its stop check before every packet; this counts those
/// looks and, on the chosen one, records that the sweep reached it and waits
/// until the test releases it. A test therefore knows the sweep is mid-read
/// without sleeping and hoping. It also carries a clock offset the job adds to
/// its elapsed time, so a test can move a sweep past its deadline without
/// waiting one out. The wait is bounded by [`TestHold::LIVENESS`], so a test
/// that forgets to release cannot leave a thread behind.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct TestHold {
    /// The look to stop at, counted from 1.
    at: u64,
    /// Looks so far.
    looks: AtomicU64,
    /// Milliseconds added to the job's elapsed time.
    skew_ms: AtomicU64,
    /// (reached, released).
    state: Mutex<(bool, bool)>,
    /// Signals both transitions.
    changed: parking_lot::Condvar,
}

#[cfg(test)]
impl TestHold {
    /// The longest a hold waits for its release, and a test for its arrival.
    /// A liveness bound, not a timing assumption: the paths it bounds take
    /// milliseconds, and it only expires when something is stuck.
    pub(crate) const LIVENESS: Duration = Duration::from_secs(30);

    /// A hold at the reader's `at`-th look, counted from 1.
    pub(crate) fn at_look(at: u64) -> Arc<Self> {
        Arc::new(Self {
            at,
            looks: AtomicU64::new(0),
            skew_ms: AtomicU64::new(0),
            state: Mutex::new((false, false)),
            changed: parking_lot::Condvar::new(),
        })
    }

    /// One look by the reader. Blocks on the chosen look until released.
    pub(crate) fn look(&self) {
        if self.looks.fetch_add(1, Ordering::Relaxed) + 1 != self.at {
            return;
        }
        let mut state = self.state.lock();
        state.0 = true;
        self.changed.notify_all();
        let until = Instant::now() + Self::LIVENESS;
        while !state.1 {
            if self.changed.wait_until(&mut state, until).timed_out() {
                break;
            }
        }
    }

    /// Wait until the reader is held, up to [`Self::LIVENESS`]. True when it is.
    pub(crate) fn wait_reached(&self) -> bool {
        let mut state = self.state.lock();
        let until = Instant::now() + Self::LIVENESS;
        while !state.0 {
            if self.changed.wait_until(&mut state, until).timed_out() {
                break;
            }
        }
        state.0
    }

    /// Move the held job's clock forward by `ms`.
    pub(crate) fn advance_clock_ms(&self, ms: u64) {
        self.skew_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// The offset [`Self::advance_clock_ms`] added.
    fn clock_skew_ms(&self) -> u64 {
        self.skew_ms.load(Ordering::Relaxed)
    }

    /// Let the held reader go on.
    pub(crate) fn release(&self) {
        self.state.lock().1 = true;
        self.changed.notify_all();
    }
}

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
