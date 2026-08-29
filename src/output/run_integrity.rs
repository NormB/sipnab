// SPDX-License-Identifier: MIT OR Apache-2.0

//! What this run could NOT deliver, in a form a machine can read.
//!
//! sipnab already detects every condition recorded here and describes each one
//! well on stderr. Nothing downstream of stderr could see them: a truncated
//! pcap and a `--plugin` that would not load both printed an accurate error
//! and then exited `0` with a report that looked whole, so `sipnab -I x.pcap
//! --json-dialogs && next-step` ran the next step on a partial answer.
//!
//! [`docs/fault-model.md`](../../docs/fault-model.md) already states the rule
//! for the LIVE capture path: *"a capture that stopped early leaves every
//! report above it resting on a partial read. The exit status is the only
//! place that distinction survives: downgrade that join to a warning and exit
//! 0, and an incomplete run reads exactly like a whole one to anything
//! checking `$?`."* The live path implements it — the batch runner joins the
//! capture thread and exits 1 on an `Err`. The FILE path does not, because
//! reading a set of files deliberately continues past a truncated member and
//! returns `Ok`: losing one file of a set is bad, losing the analysis of the
//! other nine is worse. That decision is right and stays. What was missing is
//! the record that the decision was taken.
//!
//! # Two destinations, one record
//!
//! The exit status alone is not enough, and neither is stdout alone:
//!
//! * A pipeline that only reads `$?` learns that something was wrong and not
//!   what.
//! * A pipeline that only reads stdout — an agent consuming `--json-dialogs`,
//!   for instance — never sees `$?` at all.
//!
//! So the same facts feed both, from one place, and cannot disagree.
//!
//! # What counts as a failure, and what is only a fact
//!
//! Only two conditions here change the exit status, and both mean *sipnab did
//! not do what it was asked*:
//!
//! * **Data was lost from the input.** A file whose read broke mid-way, a file
//!   that would not open, a BPF filter that would not compile against a
//!   member. `ReadTally` in `capture::file` already draws exactly this line
//!   with its `lost` flag: a `--count`/`--duration` limit stopping the
//!   read early is what the operator ASKED for and is not a loss.
//! * **A requested `--plugin` did not load.** The plugin was named on the
//!   command line; findings that plugin would have contributed are absent from
//!   every report, and nothing else says so.
//!
//! Retention is recorded but deliberately does NOT change the exit status.
//! Idle compaction drops captured messages once a dialog has been quiet longer
//! than `[limits] idle_compact_after_secs`, which makes the ladder for that
//! call incomplete — a real fact a reader needs. It is also the configured
//! retention policy working as configured, and it fires on essentially every
//! long-running live capture. An exit code that is non-zero on nearly every
//! live run carries no information, and `-l/--limit` sets the precedent: a
//! limit doing its job is not a failure. It travels in the record instead,
//! where a consumer can weigh it, and the counts are separate from the
//! input-loss counts so the two can never be mistaken for each other.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Files in the resolved `-I` set.
static FILES_GIVEN: AtomicU64 = AtomicU64::new(0);
/// Files read through to their last packet.
static FILES_READ_IN_FULL: AtomicU64 = AtomicU64::new(0);
/// Files whose read stopped before their end.
static FILES_STOPPED_EARLY: AtomicU64 = AtomicU64::new(0);
/// Files that never yielded a packet.
static FILES_SKIPPED: AtomicU64 = AtomicU64::new(0);
/// Files the run never got to, because it stopped inside an earlier one.
static FILES_NOT_REACHED: AtomicU64 = AtomicU64::new(0);
/// Whether anything was LOST from the input rather than left unread on request.
static INPUT_LOST: AtomicBool = AtomicBool::new(false);
/// `--plugin` paths this run was asked to load.
static PLUGINS_REQUESTED: AtomicU64 = AtomicU64::new(0);
/// `--plugin` paths that did not load.
static PLUGINS_FAILED: AtomicU64 = AtomicU64::new(0);
/// Captured messages idle compaction discarded over the whole run.
static RETENTION_MESSAGES_DROPPED: AtomicU64 = AtomicU64::new(0);

/// The outcome of reading one `-I` set, as [`record_files_read`] takes it.
///
/// A plain struct rather than six positional arguments: every field here is a
/// count of files and five of them are `u64`, so positional arguments would be
/// silently reorderable at the call site.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileReadOutcome {
    /// Files in the resolved set.
    pub(crate) given: u64,
    /// Files read through to their last packet.
    pub(crate) read_in_full: u64,
    /// Files whose read stopped before their end.
    pub(crate) stopped_early: u64,
    /// Files that never yielded a packet.
    pub(crate) skipped: u64,
    /// Files the run never got to.
    pub(crate) not_reached: u64,
    /// Whether data was LOST, as opposed to left unread on request.
    pub(crate) lost: bool,
}

/// Everything this run could not deliver, read back as one value.
///
/// A snapshot rather than a set of getters, so a caller that renders several
/// of these fields renders ONE consistent set of them. Nothing writes to the
/// statics after the capture has ended, but a caller reading six atomics one
/// at a time is a shape that invites a later reader to do it during the
/// capture instead.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunIntegrity {
    /// Files in the resolved `-I` set. Zero for a live or HEP source.
    pub files_given: u64,
    /// Files read through to their last packet.
    pub files_read_in_full: u64,
    /// Files whose read stopped before their end.
    pub files_stopped_early: u64,
    /// Files that never yielded a packet.
    pub files_skipped: u64,
    /// Files the run never got to.
    pub files_not_reached: u64,
    /// Whether data was lost from the input, as opposed to left unread on
    /// request. This is the half of the record that moves the exit status.
    pub input_lost: bool,
    /// `--plugin` paths this run was asked to load.
    pub plugins_requested: u64,
    /// `--plugin` paths that did not load.
    pub plugins_failed: u64,
    /// Captured messages idle compaction discarded.
    ///
    /// No companion "dialogs affected" count: the store keeps a lifetime
    /// message counter and no lifetime dialog counter, and inventing one from
    /// the last sweep's `CompactStats` would report the dialogs of ONE sweep
    /// as the dialogs of the run. A number that looks measured and is not is
    /// worse here than a number that is absent.
    pub retention_messages_dropped: u64,
}

impl RunIntegrity {
    /// Whether the input was read in full and every requested plugin loaded.
    ///
    /// The exact condition the exit status reports, so the code and the
    /// `input_complete` field of the emitted record are the same predicate
    /// evaluated once.
    #[must_use]
    pub fn input_complete(&self) -> bool {
        !self.input_lost && self.plugins_failed == 0
    }

    /// Whether anything at all is worth saying about this run.
    ///
    /// Wider than [`input_complete`](Self::input_complete): a run whose input
    /// was whole but whose retention policy dropped captured messages has
    /// nothing wrong with its exit status and still owes the reader that fact.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !self.input_complete() || self.retention_messages_dropped > 0
    }

    /// One sentence per condition, in the words the stderr lines already use.
    ///
    /// Carried in the record rather than left for the consumer to reconstruct
    /// from the counts: a consumer that has only stdout has no stderr to read
    /// the explanation from, and a bare `"input_complete": false` says that
    /// something is wrong without saying what — the same half-answer the exit
    /// code alone gives.
    #[must_use]
    pub fn reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.input_lost {
            out.push(format!(
                "{} of {} capture file(s) was not read to the end; \
                 every report from this run rests on a partial read",
                self.files_given.saturating_sub(self.files_read_in_full),
                self.files_given,
            ));
        }
        if self.plugins_failed > 0 {
            out.push(format!(
                "{} of {} requested --plugin(s) did not load; \
                 findings they would have contributed are absent",
                self.plugins_failed, self.plugins_requested,
            ));
        }
        if self.retention_messages_dropped > 0 {
            out.push(format!(
                "{} captured message(s) were dropped by idle compaction; \
                 ladders for those calls are incomplete",
                self.retention_messages_dropped,
            ));
        }
        out
    }

    /// The record as one JSON value.
    ///
    /// Shape, and why:
    ///
    /// * **One object under `sipnab_run`, not a field on every dialog.** The
    ///   fact is about the RUN. Repeating it per dialog would invite a reader
    ///   to believe it says something about THAT dialog — and the dialogs a
    ///   truncated read never reached are precisely the ones with no object to
    ///   carry it.
    /// * **`sipnab_run` is a top-level key no dialog object has.** In NDJSON a
    ///   consumer decides what a line is by looking at it, so the
    ///   discriminator has to be visible without a schema. A consumer that
    ///   assumes every line is a dialog gets a missing `call_id` and fails
    ///   loudly, which is the correct outcome on a run whose answer is
    ///   partial.
    /// * **`input_complete` is the exit-status predicate, verbatim.** A
    ///   consumer reading stdout and a consumer reading `$?` must not be able
    ///   to reach different verdicts.
    /// * **Counts as well as booleans**, on the standard `--on-dialog-exec`
    ///   sets: it reports how many commands ran, how many succeeded, how many
    ///   failed and how many have an unknowable status, rather than one flag.
    ///   "One of forty files was short" and "thirty-nine of forty were" are
    ///   different situations and the record has to tell them apart.
    /// * **Retention is its own sub-object.** It is a fact, not a failure (see
    ///   the module docs), so it is never summed into the file counts.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sipnab_run": {
                "input_complete": self.input_complete(),
                "reasons": self.reasons(),
                "files": {
                    "given": self.files_given,
                    "read_in_full": self.files_read_in_full,
                    "stopped_early": self.files_stopped_early,
                    "skipped": self.files_skipped,
                    "not_reached": self.files_not_reached,
                },
                "plugins": {
                    "requested": self.plugins_requested,
                    "loaded": self.plugins_requested.saturating_sub(self.plugins_failed),
                    "failed": self.plugins_failed,
                },
                "retention": {
                    "messages_dropped": self.retention_messages_dropped,
                },
            }
        })
    }

    /// The record as one NDJSON line, or `None` when there is nothing to say.
    ///
    /// `None` on a clean run on purpose: a marker emitted on every run changes
    /// the shape of every existing consumer's input to report that nothing
    /// happened. A run with nothing to declare declares nothing, exactly as
    /// today.
    #[must_use]
    pub fn ndjson_line(&self) -> Option<String> {
        // Gated on `input_complete()`, NOT on `is_degraded()`. The two differ
        // on retention: idle compaction is a configured policy doing its job,
        // which is why it deliberately does not move the exit status -- and by
        // the same argument it must not inject a line into an otherwise-clean
        // NDJSON stream. It fires on essentially every long capture, so the
        // difference is most real runs rather than an edge case.
        //
        // This was caught by the corpus gate and by nothing else: a healthy
        // 3 MB capture emitted the trailer for 15 compacted messages, and
        // `tests/filter_corpus_test.rs` -- which reads every `--json-dialogs`
        // line as a dialog, exactly as a consumer would -- saw 335 dialogs
        // where there are 334, with the extra one appearing in both a filter's
        // results and its negation's. Any downstream reader iterating lines
        // would have hit the same thing.
        //
        // Retention still travels INSIDE the trailer when a partial read fires
        // it, and is still reported on stderr and in `--report` regardless. It
        // is only the machine-readable dialog stream that stays clean.
        if self.input_complete() {
            return None;
        }
        let mut line = serde_json::to_string(&self.to_json()).unwrap_or_else(|_| {
            // Unreachable: the value is built from integers, booleans and
            // owned strings, none of which can fail to serialize. Degrading to
            // a minimal object rather than to nothing, because "the run was
            // incomplete" is the message and dropping it on a formatting
            // problem would reintroduce the silence this module exists to end.
            format!(
                "{{\"sipnab_run\":{{\"input_complete\":{}}}}}",
                self.input_complete()
            )
        });
        line.push('\n');
        Some(line)
    }

    /// The record as one line of text for `--report`, or `None` when clean.
    ///
    /// The report is read by a person, so this is a sentence rather than a
    /// field list, and it leads with the word a reader scanning the bottom of
    /// a report is looking for.
    #[must_use]
    pub fn report_notice(&self) -> Option<String> {
        if !self.is_degraded() {
            return None;
        }
        let mut out =
            String::from("\nINCOMPLETE RUN — this report does not describe the whole capture:\n");
        for reason in self.reasons() {
            out.push_str("  - ");
            out.push_str(&reason);
            out.push('\n');
        }
        Some(out)
    }
}

/// Record what became of one `-I` set.
///
/// Called from `ReadTally::report` in `capture::file`, which is the ONE place
/// both the single-threaded and the `--cores` file readers converge on
/// to emit their closing line. Recording here rather than at the two call
/// sites is what makes the machine-readable record and the human sentence
/// incapable of disagreeing — the same reason that function owns the severity
/// of its own log line.
///
/// Additive: a run reading several sets (a composite source) accumulates.
///
/// # Side effects
///
/// Writes process-global counters.
pub(crate) fn record_files_read(outcome: FileReadOutcome) {
    FILES_GIVEN.fetch_add(outcome.given, Ordering::Relaxed);
    FILES_READ_IN_FULL.fetch_add(outcome.read_in_full, Ordering::Relaxed);
    FILES_STOPPED_EARLY.fetch_add(outcome.stopped_early, Ordering::Relaxed);
    FILES_SKIPPED.fetch_add(outcome.skipped, Ordering::Relaxed);
    FILES_NOT_REACHED.fetch_add(outcome.not_reached, Ordering::Relaxed);
    if outcome.lost {
        INPUT_LOST.store(true, Ordering::Relaxed);
    }
}

/// How many `--plugin` paths a run asked for, and how many did not load.
///
/// A struct rather than two positional `usize` arguments for the reason
/// [`FileReadOutcome`] is one, and this time it is not hypothetical: an edit
/// to the call site swapped the two numbers, and the run then reported
/// `"requested": 1, "failed": 2` — a shape no run can produce.
/// `tests/partial_run_exit_code_test.rs` caught it, and the argument list is
/// now one a swap cannot survive.
/// Gated on `plugins`: its only caller is the `--plugin` load in
/// `src/app/batch.rs`, itself `#[cfg(feature = "plugins")]`. Without the gate
/// this is dead code in every build that does not carry the feature, which is
/// 11 of the 13 combinations CI checks.
#[cfg(feature = "plugins")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PluginLoadOutcome {
    /// `--plugin` paths named on the command line.
    pub(crate) requested: usize,
    /// How many of them did not load.
    pub(crate) failed: usize,
}

/// Record how many `--plugin` paths were asked for and how many did not load.
///
/// Takes both numbers rather than one call per failure: "one plugin failed" and
/// "the only plugin failed" are different reports, and a counter of failures
/// alone cannot tell them apart.
///
/// # Side effects
///
/// Writes process-global counters.
#[cfg(feature = "plugins")]
pub(crate) fn record_plugins(outcome: PluginLoadOutcome) {
    PLUGINS_REQUESTED.fetch_add(outcome.requested as u64, Ordering::Relaxed);
    PLUGINS_FAILED.fetch_add(outcome.failed as u64, Ordering::Relaxed);
}

/// Record the run's lifetime count of messages dropped by idle compaction.
///
/// Set rather than added: the store's counter is already a lifetime total, so
/// adding it would double-count a run that reports twice.
///
/// # Side effects
///
/// Writes a process-global counter.
pub(crate) fn record_retention_drops(messages: u64) {
    RETENTION_MESSAGES_DROPPED.store(messages, Ordering::Relaxed);
}

/// Read every counter back as one value.
#[must_use]
pub fn snapshot() -> RunIntegrity {
    RunIntegrity {
        files_given: FILES_GIVEN.load(Ordering::Relaxed),
        files_read_in_full: FILES_READ_IN_FULL.load(Ordering::Relaxed),
        files_stopped_early: FILES_STOPPED_EARLY.load(Ordering::Relaxed),
        files_skipped: FILES_SKIPPED.load(Ordering::Relaxed),
        files_not_reached: FILES_NOT_REACHED.load(Ordering::Relaxed),
        input_lost: INPUT_LOST.load(Ordering::Relaxed),
        plugins_requested: PLUGINS_REQUESTED.load(Ordering::Relaxed),
        plugins_failed: PLUGINS_FAILED.load(Ordering::Relaxed),
        retention_messages_dropped: RETENTION_MESSAGES_DROPPED.load(Ordering::Relaxed),
    }
}

/// Whether this run must exit non-zero because it could not do what was asked.
///
/// The one predicate the exit-code sites read, so `docs/cli-reference.md`'s
/// "Scripts can rely on these" table describes one rule rather than several
/// call sites that happen to agree today.
#[must_use]
pub fn run_failed() -> bool {
    !snapshot().input_complete()
}

/// The `--json-dialogs` trailer for this run, or `None` when there is nothing
/// to declare.
#[must_use]
pub fn ndjson_line() -> Option<String> {
    snapshot().ndjson_line()
}

/// The `--report` footer for this run, or `None` when there is nothing to
/// declare.
#[must_use]
pub fn report_notice() -> Option<String> {
    snapshot().report_notice()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every test here builds a `RunIntegrity` directly and never touches the
    // process-global counters. libtest runs the lib tests of one binary in
    // parallel threads of ONE process, so a test that recorded a failure would
    // set it for every other test in the binary -- permanently, since nothing
    // clears these. The recorders are exercised end to end by
    // `tests/partial_run_exit_code_test.rs`, which runs the real binary.

    #[test]
    fn a_clean_run_declares_nothing() {
        let clean = RunIntegrity {
            files_given: 3,
            files_read_in_full: 3,
            ..RunIntegrity::default()
        };
        assert!(clean.input_complete());
        assert!(!clean.is_degraded());
        assert_eq!(clean.ndjson_line(), None);
        assert_eq!(clean.report_notice(), None);
        assert!(clean.reasons().is_empty());
    }

    #[test]
    fn a_lost_file_is_incomplete_and_says_which_counts() {
        let lost = RunIntegrity {
            files_given: 4,
            files_read_in_full: 3,
            files_stopped_early: 1,
            input_lost: true,
            ..RunIntegrity::default()
        };
        assert!(!lost.input_complete());
        assert!(lost.is_degraded());
        let v = lost.to_json();
        assert_eq!(v["sipnab_run"]["input_complete"], serde_json::json!(false));
        assert_eq!(v["sipnab_run"]["files"]["given"], serde_json::json!(4));
        assert_eq!(
            v["sipnab_run"]["files"]["stopped_early"],
            serde_json::json!(1)
        );
        let line = lost.ndjson_line().unwrap_or_default();
        assert!(line.ends_with('\n'), "NDJSON line must end in a newline");
        assert!(!line[..line.len() - 1].contains('\n'), "one line: {line}");
    }

    #[test]
    fn a_failed_plugin_is_incomplete_and_counts_the_loaded_ones() {
        let p = RunIntegrity {
            plugins_requested: 3,
            plugins_failed: 1,
            ..RunIntegrity::default()
        };
        assert!(!p.input_complete());
        let v = p.to_json();
        assert_eq!(v["sipnab_run"]["plugins"]["loaded"], serde_json::json!(2));
        assert_eq!(v["sipnab_run"]["plugins"]["failed"], serde_json::json!(1));
        assert!(
            p.reasons().iter().any(|r| r.contains("--plugin")),
            "{:?}",
            p.reasons()
        );
    }

    #[test]
    fn retention_is_reported_without_failing_the_run() {
        let r = RunIntegrity {
            files_given: 1,
            files_read_in_full: 1,
            retention_messages_dropped: 2,
            ..RunIntegrity::default()
        };
        // The distinction the exit status rests on: reported, not a failure.
        assert!(r.input_complete(), "retention must not fail the run");
        assert!(r.is_degraded(), "retention must still be declared");
        // ...but declared to a HUMAN, not injected into the dialog stream.
        // Retention fires on most long captures, and a consumer reading each
        // `--json-dialogs` line as a dialog would count the trailer as one.
        assert!(
            r.ndjson_line().is_none(),
            "a complete read must leave the NDJSON stream pure, whatever else \
             it has to declare"
        );
        assert!(
            r.report_notice().is_some(),
            "retention must still reach the human-readable report"
        );
        let v = r.to_json();
        assert_eq!(
            v["sipnab_run"]["retention"]["messages_dropped"],
            serde_json::json!(2)
        );
        assert_eq!(v["sipnab_run"]["input_complete"], serde_json::json!(true));
    }

    /// A partial read still emits the trailer, and retention rides along.
    ///
    /// The pair with `retention_is_reported_without_failing_the_run`: gating
    /// the trailer on `input_complete` must not lose the retention figure when
    /// the trailer fires for a real reason.
    #[test]
    fn a_partial_read_emits_the_trailer_and_carries_retention_inside_it() {
        let r = RunIntegrity {
            files_given: 2,
            files_read_in_full: 1,
            files_stopped_early: 1,
            // `input_complete()` reads this flag, not the file counters: the
            // counters describe the set, and this says whether anything was
            // lost from it.
            input_lost: true,
            retention_messages_dropped: 7,
            ..RunIntegrity::default()
        };
        assert!(
            !r.input_complete(),
            "a stopped-early file is a partial read"
        );
        let line = r
            .ndjson_line()
            .expect("a partial read must declare itself in the stream");
        assert!(
            line.contains("\"sipnab_run\""),
            "the trailer must be keyed so a reader can tell it from a dialog: {line}"
        );
        let v = r.to_json();
        assert_eq!(
            v["sipnab_run"]["retention"]["messages_dropped"],
            serde_json::json!(7),
            "retention must survive inside the trailer it no longer triggers"
        );
    }

    /// A clean run declares nothing at all, in either channel.
    #[test]
    fn a_clean_run_emits_no_trailer_and_no_notice() {
        let r = RunIntegrity {
            files_given: 1,
            files_read_in_full: 1,
            ..RunIntegrity::default()
        };
        assert!(r.input_complete());
        assert!(!r.is_degraded());
        assert!(r.ndjson_line().is_none());
        assert!(r.report_notice().is_none());
    }

    #[test]
    fn a_requested_stop_is_not_a_loss() {
        // `--count 100` over a 27-file set: stopped early, nothing lost.
        let limited = RunIntegrity {
            files_given: 27,
            files_read_in_full: 2,
            files_stopped_early: 1,
            files_not_reached: 24,
            input_lost: false,
            ..RunIntegrity::default()
        };
        assert!(limited.input_complete());
        assert!(!limited.is_degraded());
        assert_eq!(limited.ndjson_line(), None);
    }

    #[test]
    fn the_report_notice_names_every_reason() {
        let both = RunIntegrity {
            files_given: 1,
            files_stopped_early: 1,
            input_lost: true,
            plugins_requested: 1,
            plugins_failed: 1,
            retention_messages_dropped: 5,
            ..RunIntegrity::default()
        };
        let notice = both.report_notice().unwrap_or_default();
        assert!(notice.contains("INCOMPLETE RUN"), "{notice}");
        assert_eq!(
            notice.lines().filter(|l| l.starts_with("  - ")).count(),
            3,
            "{notice}"
        );
    }
}
