// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the operator DID at the terminal, one record per action (AUDIT2).
//!
//! # Actions, not keystrokes
//!
//! The distinction is the whole design. The TUI binds 38 distinct keys and
//! nearly all of them move a cursor; a keystroke log of them is unreadable at
//! review time and is a privacy hazard of its own, because one of those keys
//! opens a SEARCH FIELD and search terms are phone numbers. What an incident
//! review actually opens with is "who exported which calls, when", and the
//! answer to that is a short, fixed set of state-changing acts: which capture
//! was opened, what filter was applied, what was exported and to where, and
//! when the capture was swapped underneath.
//!
//! So this records those and nothing else. **The search query is never
//! written here — not the text, not the fact that one was typed.** That is an
//! assertion `tests/tui_action_trail_test.rs` makes fail if anyone later adds
//! it, because a privacy property nothing checks is a privacy property that
//! lasts until the next feature.
//!
//! The filter IS recorded, and the difference from search is not squeamish.
//! A filter decides what the operator could see and therefore what they could
//! export; it is part of the evidence chain the export record belongs to. A
//! search only moves a cursor within what is already on screen. The filter
//! text can hold a number all the same, which is why this file is `0600` —
//! the same answer `--mcp-audit-file` gives for tool arguments and
//! `--run-provenance-file` gives for `argv`.
//!
//! # One writer
//!
//! Records go through [`crate::app::audit::AuditSink`], the same append-only,
//! sequence-numbered, `0600` sink the MCP tool-call audit and the run
//! provenance record use. Two audit writers for one tool would be two sets of
//! open flags, two locking rules and two numbering schemes to keep true, and
//! the one nobody reads drifts first.
//!
//! # THE DECISION: a refused write does not stop the TUI
//!
//! The MCP rule is that a call whose record cannot be written is refused
//! rather than answered. That is right for a request/response surface, where
//! refusing costs the caller one retry. It is wrong at a terminal, and the
//! cost of being wrong is not inconvenience: an operator mid-incident may be
//! holding a LIVE capture with no output file, whose packets exist nowhere
//! else ([`crate::capture::session::CaptureContext::unsaved`]). Killing the
//! TUI because a log partition filled would destroy the evidence in order to
//! protect the record of it.
//!
//! **So this fails OPEN, and makes the incompleteness impossible to miss
//! rather than silent.** Silently dropping records was never an option; it is
//! the exact failure `--mcp-audit-file` was built to avoid. Four things
//! happen instead, and the first is the one that survives a full disk:
//!
//! 1. **The sequence number is consumed anyway.** [`AuditSink::append_with`]
//!    allocates the number before it writes, so a record that could not be
//!    written leaves a permanent HOLE in the numbering. A reader sees `4, 6`
//!    and knows exactly one action is missing, with no cooperation from a
//!    failing disk required — which is the property any "trail incomplete"
//!    MARKER inside the file could not have, since writing the marker needs
//!    the same disk that just refused the record. It is also why there is no
//!    such marker: the gap is contiguous numbering, so it already carries the
//!    COUNT, and a line restating it would be a second answer to a question
//!    the first one answers exactly.
//! 2. **The session writes a closing record** naming how many actions it was
//!    offered and how many it lost. This is what covers the one case the gap
//!    cannot: records lost at the TAIL leave no upper bound, so a file that
//!    simply stops is indistinguishable from a session that simply ended. A
//!    reader who finds no closing record knows the file is short; one who
//!    finds it can check the count against the numbers present.
//! 3. **The status line says so during the session**, so the operator finds
//!    out while they can still do something about it.
//! 4. **Standard error says so at exit**, after the terminal is restored,
//!    naming the path and the count — because a status line the operator was
//!    not looking at is not a notification.
//!
//! Opening the file is a different question and keeps the MCP rule: a path
//! that cannot be opened stops the run at startup, before the terminal is
//! taken and before a packet has been read. Nothing is lost by refusing
//! there, which is the whole argument above, run in reverse.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::app::audit::AuditSink;

/// One state-changing thing an operator did.
///
/// Borrowed rather than owned for the same reason
/// [`AuditRecord`](crate::app::audit::AuditRecord) is: every field already
/// exists as a string at the call site.
#[derive(Debug, Clone, Copy)]
pub struct ActionRecord<'a> {
    /// What was done, from a fixed set: `capture_opened`, `capture_swapped`,
    /// `filter_applied`, `filter_cleared`, `export`, and the `session_end`
    /// line [`ActionTrail::close_session`] writes.
    ///
    /// A fixed vocabulary and not free text: a reader grepping for every
    /// export in a month's trails is doing so on this value, and one call
    /// site inventing a synonym makes that search quietly incomplete.
    pub action: &'a str,
    /// What the action was done TO or WITH: the capture path, the filter
    /// expression, the export destination. Empty when the action has no
    /// object, which only `filter_cleared` does.
    pub target: &'a str,
    /// Export format (`pcap`, `json`, …), empty for every other action.
    pub format: &'a str,
    /// `ok`, `failed` or `refused`.
    ///
    /// Refusals are recorded for the same reason the MCP sink records them:
    /// "the operator tried to overwrite the capture they were reading" is
    /// exactly the kind of thing a review is looking for, and a trail holding
    /// only what succeeded answers the opposite question.
    pub outcome: &'a str,
    /// Why it failed, empty when it did not.
    pub error: &'a str,
}

impl ActionRecord<'_> {
    /// Render this action as one JSON object, without a trailing newline.
    ///
    /// The same line family the MCP tool-call record uses — one JSON object,
    /// `seq` and `ts` from the sink, `serde_json` escaping every value so an
    /// export path holding a quote or a newline cannot forge a field or end
    /// the line. The FIELDS differ because the facts differ: an operator
    /// action has no request id, no peer and no elapsed time, and calling an
    /// action a `tool` to reuse the key would make the vocabulary a reader
    /// greps for wrong in both files.
    ///
    /// # Arguments
    ///
    /// * `seq` — the sequence number the sink allocated.
    /// * `ts` — when the sink wrote the line.
    /// * `caller` — who was at the terminal, from
    ///   [`ActionTrail::caller`].
    #[must_use]
    pub fn to_line(&self, seq: u64, ts: chrono::DateTime<chrono::Utc>, caller: &str) -> String {
        serde_json::json!({
            "seq": seq,
            "ts": ts.to_rfc3339(),
            // The discriminator the run record carries too, so a reader who
            // has been handed one file can tell what is in it without being
            // told which flag produced it.
            "record": "tui",
            "action": self.action,
            "target": self.target,
            "format": (!self.format.is_empty()).then_some(self.format),
            "caller": caller,
            "outcome": self.outcome,
            // Present and null rather than absent on success, exactly as the
            // MCP record does it: a reader selecting `.error` gets a value for
            // every record and never has to tell a missing key from an action
            // that did not fail.
            "error": (!self.error.is_empty()).then_some(self.error),
        })
        .to_string()
    }
}

/// The open action trail for one TUI session.
#[derive(Debug)]
pub struct ActionTrail {
    /// The one sink type in the tree — see this module's header.
    sink: AuditSink,
    /// Who was at the terminal, rendered once at open.
    caller: String,
    /// Actions this trail was asked to record and could not.
    ///
    /// Reported by the closing record and by the exit message. Never reset:
    /// the session's total is what both of those are about.
    lost: AtomicU64,
    /// Set the first time a write fails and never cleared.
    ///
    /// Sticky on purpose: the trail is incomplete for the rest of the
    /// session's life once one record is missing, and a flag that cleared
    /// when writing resumed would report a complete trail with a hole in it.
    incomplete: AtomicBool,
    /// Total actions this trail has been asked to record, written or not.
    /// Read by the exit message and the tests; nothing on a hot path.
    offered: AtomicU64,
}

impl ActionTrail {
    /// Open `path` for appending, creating it `0600` if absent.
    ///
    /// # Errors
    ///
    /// Whatever the open failed with. Reported rather than swallowed, and the
    /// caller stops the run on it: see this module's header for why the OPEN
    /// keeps the fail-closed rule that the WRITE does not.
    ///
    /// # Side effects
    ///
    /// Creates the file when absent, mode `0600` on Unix, and reads the
    /// effective uid to build the caller identity.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            sink: AuditSink::open(path)?,
            // "a caller identity that is not an MCP peer": there is no socket
            // and no bearer token at a terminal, so what the process can prove
            // about who is acting is the effective user it is running as.
            caller: format!("tui {}", crate::app::run_provenance::effective_user_label()),
            lost: AtomicU64::new(0),
            incomplete: AtomicBool::new(false),
            offered: AtomicU64::new(0),
        })
    }

    /// The path this trail appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.sink.path()
    }

    /// Who this trail attributes its actions to.
    #[must_use]
    pub fn caller(&self) -> &str {
        &self.caller
    }

    /// Whether any record has failed to be written.
    ///
    /// Once true, always true. This is what the exit message and the status
    /// line are driven from.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        self.incomplete.load(Ordering::Relaxed)
    }

    /// How many actions could not be written.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lost.load(Ordering::Relaxed)
    }

    /// How many actions this trail has been offered, written or not.
    #[must_use]
    pub fn offered(&self) -> u64 {
        self.offered.load(Ordering::Relaxed)
    }

    /// Record one action.
    ///
    /// # Returns
    ///
    /// A message for the status line when the record could NOT be written,
    /// `None` when it could. Returned rather than logged only, because in TUI
    /// mode the terminal is in the alternate screen and a `tracing` line
    /// behind it is a line nobody reads until the session ends.
    ///
    /// # Side effects
    ///
    /// Appends one line to the trail file, and emits a `tracing::error!` for
    /// a write that fails. Never returns an error and never panics: this is
    /// the fail-open half of the decision in this module's header.
    pub fn record(&self, action: &ActionRecord<'_>) -> Option<String> {
        self.offered.fetch_add(1, Ordering::Relaxed);
        match self
            .sink
            .append_with(|seq, ts| action.to_line(seq, ts, &self.caller))
        {
            Ok(_) => None,
            Err(e) => {
                self.lost.fetch_add(1, Ordering::Relaxed);
                self.incomplete.store(true, Ordering::Relaxed);
                let path = self.sink.path().display();
                tracing::error!(
                    "action trail {path}: {e}. The '{}' action was NOT recorded; \
                     the trail is now incomplete",
                    action.action
                );
                Some(format!(
                    "AUDIT TRAIL INCOMPLETE: '{}' was not recorded to {path} ({e})",
                    action.action
                ))
            }
        }
    }

    /// Write the session's closing record.
    ///
    /// Point 2 of the decision in this module's header. The sequence gap
    /// covers records lost in the MIDDLE of a session exactly — contiguous
    /// numbering means the gap is the count — but it says nothing about
    /// records lost at the END, where a file that simply stops looks like a
    /// session that simply ended. This line is the difference: a reader who
    /// does not find it knows the trail is short.
    ///
    /// # Returns
    ///
    /// A message for standard error when the closing record itself could not
    /// be written, `None` otherwise. That failure is not fatal either, for the
    /// same reason none of the others are — and its own absence from the file
    /// is exactly the signal a reader needs.
    ///
    /// # Side effects
    ///
    /// Appends one line to the trail file.
    pub fn close_session(&self) -> Option<String> {
        let lost = self.lost();
        let offered = self.offered();
        let caller = &self.caller;
        let result = self.sink.append_with(|seq, ts| {
            serde_json::json!({
                "seq": seq,
                "ts": ts.to_rfc3339(),
                "record": "tui",
                "action": "session_end",
                // The two numbers a reader checks the file's own contents
                // against. `actions_offered` counts what the session tried to
                // record, so `offered - lost` is how many lines should be
                // between this one and the session's first.
                "actions_offered": offered,
                "actions_lost": lost,
                "caller": caller,
                "outcome": if lost == 0 { "ok" } else { "failed" },
                "error": (lost > 0)
                    .then(|| format!("{lost} of {offered} actions could not be written")),
            })
            .to_string()
        });
        match result {
            Ok(_) => None,
            Err(e) => {
                self.incomplete.store(true, Ordering::Relaxed);
                let path = self.sink.path().display();
                Some(format!(
                    "sipnab: the action trail {path} has no closing record ({e}), \
                     so it cannot be told from a truncated one"
                ))
            }
        }
    }

    /// The line to print on standard error at exit, once the terminal is
    /// restored, or `None` when the trail is whole.
    ///
    /// Point 4 of the decision in this module's header: a status line the
    /// operator was not looking at is not a notification, and this is the one
    /// message that is still on screen after the alternate screen is gone.
    #[must_use]
    pub fn exit_notice(&self) -> Option<String> {
        self.is_incomplete().then(|| {
            format!(
                "sipnab: the action trail {} is INCOMPLETE. {} of {} actions could \
                 not be written; the gaps are visible as missing seq numbers in \
                 the file.",
                self.sink.path().display(),
                self.lost(),
                self.offered(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Read a trail file back as lines.
    fn lines(path: &Path) -> Vec<String> {
        let mut s = String::new();
        std::fs::File::open(path)
            .expect("open trail")
            .read_to_string(&mut s)
            .expect("read trail");
        s.lines().map(str::to_string).collect()
    }

    /// An export names its destination, which is the question the trail
    /// exists to answer.
    #[test]
    fn an_export_record_names_its_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trail.jsonl");
        let trail = ActionTrail::open(&path).expect("open");
        assert!(
            trail
                .record(&ActionRecord {
                    action: "export",
                    target: "/tmp/subset.pcap",
                    format: "pcap",
                    outcome: "ok",
                    error: "",
                })
                .is_none(),
            "a writable trail must report no problem"
        );
        let v: serde_json::Value = serde_json::from_str(&lines(&path)[0]).expect("json");
        assert_eq!(v["record"], "tui");
        assert_eq!(v["action"], "export");
        assert_eq!(v["target"], "/tmp/subset.pcap");
        assert_eq!(v["format"], "pcap");
        assert!(
            v["caller"].as_str().is_some_and(|c| c.starts_with("tui ")),
            "the record must say who was at the terminal: {v}"
        );
    }

    /// A newline in an export path cannot forge a second record.
    ///
    /// The save dialog takes a free-form path, so this text is the operator's
    /// and reaches the file verbatim. A forged line reads exactly like a
    /// genuine record of an export that never happened, which is worse than a
    /// missing one.
    #[test]
    fn a_newline_in_the_destination_cannot_forge_a_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trail.jsonl");
        let trail = ActionTrail::open(&path).expect("open");
        trail.record(&ActionRecord {
            action: "export",
            target: "/tmp/a\n{\"seq\":99,\"record\":\"tui\",\"action\":\"export\"}",
            format: "pcap",
            outcome: "ok",
            error: "",
        });
        let out = lines(&path);
        assert_eq!(out.len(), 1, "the destination forged a record: {out:?}");
        let v: serde_json::Value = serde_json::from_str(&out[0]).expect("json");
        assert_eq!(v["seq"], 1, "the forged sequence number was believed: {v}");
    }

    /// A refused action is recorded with its reason.
    #[test]
    fn a_refused_export_is_recorded_with_its_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trail.jsonl");
        let trail = ActionTrail::open(&path).expect("open");
        trail.record(&ActionRecord {
            action: "export",
            target: "/caps/live.pcap",
            format: "pcap",
            outcome: "refused",
            error: "Save to would overwrite the capture being read",
        });
        let v: serde_json::Value = serde_json::from_str(&lines(&path)[0]).expect("json");
        assert_eq!(v["outcome"], "refused");
        assert!(
            v["error"].as_str().expect("error").contains("overwrite"),
            "a refusal with no reason does not answer why: {v}"
        );
    }

    /// A successful action carries `error: null` rather than omitting the key.
    #[test]
    fn a_successful_action_records_a_null_error_rather_than_no_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trail.jsonl");
        let trail = ActionTrail::open(&path).expect("open");
        trail.record(&ActionRecord {
            action: "filter_cleared",
            target: "",
            format: "",
            outcome: "ok",
            error: "",
        });
        let v: serde_json::Value = serde_json::from_str(&lines(&path)[0]).expect("json");
        assert!(
            v.get("error").is_some() && v["error"].is_null(),
            "`.error` must exist on every record: {v}"
        );
    }

    /// A trail that has never failed reports nothing at exit.
    #[test]
    fn a_whole_trail_prints_no_exit_notice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trail.jsonl");
        let trail = ActionTrail::open(&path).expect("open");
        trail.record(&ActionRecord {
            action: "capture_opened",
            target: "/caps/a.pcap",
            format: "",
            outcome: "ok",
            error: "",
        });
        assert!(!trail.is_incomplete());
        assert_eq!(trail.exit_notice(), None);
    }
}
