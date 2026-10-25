// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Which of these capture files hold dialogs a filter selects, read without
//! touching the stores of the run that asks.
//!
//! The sweep the MCP `find_in_captures` tool runs on a job thread
//! ([`crate::mcp::sweep`]) and `--find-in-files` runs in the foreground: a
//! scratch store per file, the filter applied, the asking run's stores
//! untouched. What the two surfaces share is here, in one place: the loop
//! ([`sweep_files`]), the outcome and its `complete` rule ([`outcome`]), and
//! the reasons a sweep stops ([`stop_reason`]).
//!
//! # A partial sweep must never read as a complete one
//!
//! A sweep that reports "no matches" when it stopped early, or when it could
//! not open one of the files, tells the caller the call is not there. So
//! [`SweepOutcome::complete`] is false whenever ANY file went unexamined, for
//! any reason, and [`SweepOutcome::unreadable`] names each one with why.
//! "Not found" is only trustworthy when `complete` is true.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use parking_lot::RwLock;
use serde::Serialize;

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
#[must_use]
pub fn bound(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
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

/// What one sweep reads: the files and the filter a dialog must match.
pub struct SweepInput<'a> {
    /// The files to open, in the order to open them.
    pub candidates: &'a [PathBuf],
    /// The filter a dialog must match.
    pub filter: &'a crate::sip::dsl::FilterExpr,
    /// Dialog and stream capacity of each file's scratch stores.
    pub row_cap: usize,
    /// The pipeline options each file is classified with.
    pub options: &'a crate::pipeline::PipelineOptions,
    /// Files to open before stopping with [`StoppedBecause::MaxFiles`].
    pub max_files: usize,
}

/// How a sweep is told to stop, and told about its progress.
pub struct SweepControl<'a> {
    /// Asked before each file: why to stop now, or `None` to go on.
    pub between_files: &'a dyn Fn() -> Option<StoppedBecause>,
    /// Asked before each packet inside a file, so a stop ends a long read too.
    pub inside_file: &'a dyn Fn() -> Option<StoppedBecause>,
    /// Told how many files have been read to the end, after each one.
    pub examined: &'a dyn Fn(usize),
}

/// Read each candidate into scratch stores and count the dialogs the filter
/// selects, within the input's file limit and until the control says stop.
///
/// A file that cannot be read is named in [`SweepOutcome::unreadable`],
/// never skipped in silence; a read the control ended is a stopped sweep,
/// not an unreadable file. [`outcome`] decides `complete`.
#[must_use]
pub fn sweep_files(input: &SweepInput<'_>, control: &SweepControl<'_>) -> SweepOutcome {
    let mut matches = Vec::new();
    let mut unreadable = Vec::new();
    let mut examined = 0usize;
    let mut stopped = None;
    for path in input.candidates {
        if examined >= input.max_files {
            stopped = Some(StoppedBecause::MaxFiles);
            break;
        }
        // Before each file as well as inside it: a file the sweep never
        // opens costs nothing to skip.
        if let Some(reason) = (control.between_files)() {
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
        let scratch_dialogs = Arc::new(RwLock::new(crate::sip::dialog_store::DialogStore::new(
            input.row_cap,
            false,
        )));
        let scratch_streams = Arc::new(RwLock::new(crate::rtp::stream_store::StreamStore::new(
            input.row_cap,
        )));
        let stop = || (control.inside_file)().map(|r| format!("sweep stopped: {}", r.as_str()));
        // The capture layer's reader, not `mcp::load`'s wrapper: that one
        // records a partial read against the LOADED capture's completeness,
        // and a scratch file this sweep stopped reading says nothing about
        // the capture an agent is working in.
        let read = crate::capture::replay::read_into_stores_until(
            path,
            input.options,
            &scratch_dialogs,
            &scratch_streams,
            &AtomicU64::new(0),
            &stop,
        );
        if let Some(e) = read.error {
            // A read the sweep itself ended is a stopped sweep, not an
            // unreadable file: the file was fine.
            if let Some(reason) = (control.between_files)() {
                stopped = Some(reason);
                break;
            }
            unreadable.push(unreadable_file(&filename, &e));
            continue;
        }
        examined += 1;
        (control.examined)(examined);

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
            let streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(&d.call_id).collect();
            if input.filter.matches_dialog(d, &streams, capture, delay) {
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
        input.candidates.len(),
        unreadable,
        stopped,
    )
}
