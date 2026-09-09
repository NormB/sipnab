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

use serde::Serialize;

/// Files one sweep will open before stopping, unless the caller says fewer.
///
/// A capture root holds rotated files, and forty is a normal day. Twenty is
/// enough to answer "which of the recent ones" without turning one tool call
/// into a full read of a spool that may hold months.
pub const DEFAULT_MAX_FILES: usize = 20;

/// Wall-clock a sweep may spend before stopping, in milliseconds.
///
/// The bound that actually matters. A file's cost is its size, which the
/// caller cannot see and a file count does not capture: twenty small files and
/// twenty 2 GB files are the same `max_files` and wildly different waits. An
/// agent blocked on a tool call has no way to interrupt it, so the sweep
/// stops itself.
pub const DEFAULT_DEADLINE_MS: u64 = 30_000;

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

/// The response `find_in_captures` returns.
///
/// A typed shape rather than an inline `json!`, so the tool declares an output
/// schema: a client written against an untyped answer cannot tell a renamed
/// key from a missing one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct FindInCapturesResponse {
    /// Always 1 under the current schema.
    pub schema_version: u32,
    /// What the sweep covered and found.
    pub sweep: SweepOutcome,
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
