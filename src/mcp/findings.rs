//! Agent-written annotations — the one place the MCP surface accepts a write.
//!
//! # Why this module is shaped the way it is
//!
//! An LLM agent drives the MCP surface, and every response it reads contains
//! attacker-controlled text: `From` display names, `User-Agent` strings, reason
//! phrases, raw message snippets. That is the tool working, not a flaw. It does
//! mean a write verb reachable from that text must not be able to change what
//! the operator is reading.
//!
//! So an annotation is a **dead end**. It records what the agent concluded and
//! nothing consumes it: no detector, no dialog, no stream, no report, no other
//! tool. An agent cannot read one back — not its own, not another session's —
//! so it cannot launder a conclusion into evidence and then cite it.
//!
//! # There is no annotation store, and that is the design
//!
//! The obvious build here is a retained log of [`Recorded`] findings that a
//! future surface might show. That was written first and then deleted, because
//! the compiler pointed out that every field of it was dead: nothing read the
//! text, the call-id, or the timestamp back, because by construction nothing
//! ever could.
//!
//! Retained state that is written, validated and never read is the exact defect
//! this codebase has hunted repeatedly — parsed-and-ignored config keys,
//! declared-and-never-incremented metrics, a computed report that is dropped.
//! Keeping a copy here to look like a store would have been the same bug
//! wearing a feature's clothes, and `#[allow(dead_code)]` would have hidden the
//! evidence rather than answered it.
//!
//! So the finding goes straight to `tracing` and is gone from this process. The
//! operator's journal already retains, rotates, ships and searches text far
//! better than a `VecDeque` behind a lock. What stays here is what a response
//! must be able to state honestly: how many findings this process has accepted,
//! and how many more it will take.
//!
//! If an operator-facing read is ever wanted, it belongs on a surface whose
//! caller is not the agent, and it should read the log rather than a shadow
//! copy kept here for it.
//!
//! # The dead end is structural, not documentary
//!
//! [`FindingsLog`] and [`Recorded`] are `pub(in crate::mcp)`. No module outside
//! `src/mcp/` can name either, so no analysis path can reach an annotation even
//! by accident. That is the compiler enforcing it rather than this comment,
//! which matters because a comment saying "do not read this" survives exactly
//! as long as everyone reads the comment.

/// Longest summary retained. Past this the text is clipped and the response
/// reports the original length, so a shortened finding is visibly shortened.
pub(in crate::mcp) const MAX_SUMMARY_CHARS: usize = 500;

/// Longest detail retained. Matches `shape::DEFAULT_MAX_BODY_BYTES`, the
/// ceiling every other body on this surface already answers to.
///
/// Fixed rather than settable, unlike the read-side cap: this bounds what an
/// agent WRITES into the operator's journal, and `--mcp-max-body-bytes` is the
/// operator saying how much they want to READ. Widening one must not widen the
/// other.
pub(in crate::mcp) const MAX_DETAIL_CHARS: usize = 4096;

/// How many findings one process will accept by default.
///
/// Not a memory bound — nothing is retained. It bounds how much an agent can
/// write into the operator's journal. A caller in a loop is otherwise an
/// unmetered path from a language model to the host's disk, on a box that is
/// also carrying a live capture, and journald filling up takes far more with it
/// than sipnab.
///
/// Past the cap the write is REFUSED and says so. It is not silently dropped:
/// an agent that believes it recorded a conclusion, on a server that discarded
/// it, is worse off than one told plainly that it did not.
///
/// **Refusal is the design, not the ceiling being in the wrong place.** There
/// is no eviction to prefer over it, because there is nothing to evict — see
/// the module documentation. A finding is a log line and is gone from this
/// process the moment it is written, so "drop the oldest to make room" would
/// mean unwriting a line the operator's journal already has. The budget is what
/// is settable: a long agent session on a large capture legitimately reaches a
/// thousand annotations, so raise it with `--mcp-max-findings` or
/// `[limits] mcp_max_findings` on the deployments where the journal can take
/// it.
///
/// Read from [`crate::cli::Cli::DEFAULT_MCP_MAX_FINDINGS`] rather than stated
/// here, because these types are `pub(in crate::mcp)` and the resolver that
/// answers for the budget is compiled into every native build.
pub(in crate::mcp) const DEFAULT_MAX_FINDINGS_PER_PROCESS: u64 =
    crate::cli::Cli::DEFAULT_MCP_MAX_FINDINGS;

/// What a single [`FindingsLog::record`] did, so the response can say it
/// plainly instead of implying everything was kept verbatim.
#[derive(Debug, Clone, Copy)]
pub(in crate::mcp) struct Recorded {
    /// Sequence number assigned. Monotonic for the process, never reused.
    pub(in crate::mcp) seq: u64,
    /// Original summary length in characters, before any clipping.
    pub(in crate::mcp) summary_chars_submitted: usize,
    /// Original detail length in characters, before any clipping.
    pub(in crate::mcp) detail_chars_submitted: usize,
    /// True when either field was shortened to fit.
    pub(in crate::mcp) truncated: bool,
    /// Findings this process has accepted, including this one.
    pub(in crate::mcp) recorded_total: u64,
    /// Findings this process will still accept after this one.
    pub(in crate::mcp) remaining: u64,
}

/// Counts what has been written. Holds no findings, by design — see the module
/// documentation.
#[derive(Debug)]
pub(in crate::mcp) struct FindingsLog {
    /// Findings accepted so far. Doubles as the next sequence number, which is
    /// why it never decreases: a seq is a name, not an index into anything.
    recorded: u64,
    /// Findings this log will accept before refusing.
    ///
    /// A field rather than the constant it used to read, so one server's budget
    /// is the operator's to set. Held per log rather than in a process global
    /// because a `FindingsLog` belongs to one MCP server and the budget is that
    /// server's — there is no second surface to keep in step.
    cap: u64,
}

impl Default for FindingsLog {
    /// A log that has accepted nothing and carries the shipped budget.
    fn default() -> Self {
        Self {
            recorded: 0,
            cap: DEFAULT_MAX_FINDINGS_PER_PROCESS,
        }
    }
}

/// Clip to `max` CHARACTERS, never bytes.
///
/// Truncating a UTF-8 string on a byte index panics when the index lands inside
/// a multi-byte sequence, and this text is attacker-influenced: a `From`
/// display name an agent quotes back can be any UTF-8 at all. Counting
/// characters makes the operation total.
fn clip(s: &str, max: usize) -> (String, usize) {
    let submitted = s.chars().count();
    if submitted <= max {
        (s.to_string(), submitted)
    } else {
        (s.chars().take(max).collect(), submitted)
    }
}

impl FindingsLog {
    /// A log that has accepted nothing yet, with the shipped budget.
    pub(in crate::mcp) fn new() -> Self {
        Self::default()
    }

    /// A log with an operator-set budget.
    ///
    /// `0` is treated as the shipped default rather than as "accept nothing":
    /// a server that refuses the first write is indistinguishable from one
    /// where `--mcp-allow-save-findings` was never passed, and the config layer
    /// already refuses 0 by name.
    pub(in crate::mcp) fn with_cap(cap: u64) -> Self {
        Self {
            recorded: 0,
            cap: if cap == 0 {
                DEFAULT_MAX_FINDINGS_PER_PROCESS
            } else {
                cap
            },
        }
    }

    /// The budget this log was built with, for the refusal message.
    pub(in crate::mcp) fn cap(&self) -> u64 {
        self.cap
    }

    /// True once this process has taken all the findings it will.
    pub(in crate::mcp) fn is_full(&self) -> bool {
        self.recorded >= self.cap
    }

    /// Record one finding by writing it to the log. The only way in, and there
    /// is deliberately no way out.
    ///
    /// Returns `None` when the process cap is reached, so the caller refuses
    /// out loud rather than accepting a write it will not honor.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::mcp) fn record(
        &mut self,
        written_at: chrono::DateTime<chrono::Utc>,
        call_id: Option<&str>,
        summary: &str,
        detail: Option<&str>,
        capture_instance: &str,
        dialog_generation: u64,
        stream_generation: u64,
    ) -> Option<Recorded> {
        if self.is_full() {
            return None;
        }

        let (summary, summary_chars_submitted) = clip(summary, MAX_SUMMARY_CHARS);
        let (detail, detail_chars_submitted) = match detail {
            Some(d) => {
                let (text, n) = clip(d, MAX_DETAIL_CHARS);
                (Some(text), n)
            }
            None => (None, 0),
        };
        let truncated = summary_chars_submitted > MAX_SUMMARY_CHARS
            || detail_chars_submitted > MAX_DETAIL_CHARS;

        let seq = self.recorded;
        self.recorded += 1;

        // Logged as the AGENT'S claim, never as sipnab's own. An annotation is
        // something a language model concluded from text an attacker may have
        // written; phrasing it as a finding of sipnab's would put it on the same
        // footing as a measured fact, in the one file an operator trusts most.
        tracing::info!(
            seq,
            written_at = %written_at.to_rfc3339(),
            call_id = call_id.unwrap_or("-"),
            capture_instance,
            dialog_generation,
            stream_generation,
            detail = detail.as_deref().unwrap_or(""),
            "MCP agent recorded a finding: {summary}"
        );

        Some(Recorded {
            seq,
            summary_chars_submitted,
            detail_chars_submitted,
            truncated,
            recorded_total: self.recorded,
            remaining: self.cap.saturating_sub(self.recorded),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-08-04T20:00:00Z")
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_default()
    }

    fn rec(log: &mut FindingsLog, summary: &str) -> Option<Recorded> {
        log.record(ts(), None, summary, None, "cap-1", 1, 2)
    }

    #[test]
    fn the_process_cap_refuses_rather_than_dropping_silently() {
        let mut log = FindingsLog::new();
        for i in 0..DEFAULT_MAX_FINDINGS_PER_PROCESS {
            assert!(
                rec(&mut log, &format!("f{i}")).is_some(),
                "everything under the cap must be accepted"
            );
        }
        // The next one is REFUSED, not accepted-and-discarded. An agent told
        // "recorded" about a finding the server threw away is worse off than
        // one told plainly that it was not.
        assert!(
            rec(&mut log, "one too many").is_none(),
            "past the cap the write must fail visibly"
        );
    }

    #[test]
    fn remaining_counts_down_so_the_bound_is_visible_before_it_bites() {
        let mut log = FindingsLog::new();
        let first = rec(&mut log, "first").expect("accepted");
        assert_eq!(first.recorded_total, 1);
        assert_eq!(first.remaining, DEFAULT_MAX_FINDINGS_PER_PROCESS - 1);
        let second = rec(&mut log, "second").expect("accepted");
        assert_eq!(second.remaining, DEFAULT_MAX_FINDINGS_PER_PROCESS - 2);
    }

    #[test]
    fn sequence_numbers_are_monotonic_and_never_reused() {
        let mut log = FindingsLog::new();
        let a = rec(&mut log, "a").expect("accepted");
        let b = rec(&mut log, "b").expect("accepted");
        let c = rec(&mut log, "c").expect("accepted");
        assert_eq!((a.seq, b.seq, c.seq), (0, 1, 2));
    }

    #[test]
    fn over_long_text_is_clipped_and_the_original_length_reported() {
        let mut log = FindingsLog::new();
        let long = "x".repeat(MAX_SUMMARY_CHARS + 250);
        let r = rec(&mut log, &long).expect("accepted");
        assert!(r.truncated, "a clipped finding must say it was clipped");
        assert_eq!(
            r.summary_chars_submitted,
            MAX_SUMMARY_CHARS + 250,
            "the response reports what was SENT, so the writer can tell how much was lost"
        );
    }

    #[test]
    fn text_within_the_ceiling_is_not_flagged_as_truncated() {
        // Mutation guard for the test above: were `truncated` hardcoded true,
        // that test would still pass and this one would fail.
        let mut log = FindingsLog::new();
        let r = rec(&mut log, "short enough").expect("accepted");
        assert!(!r.truncated);
        assert_eq!(r.summary_chars_submitted, "short enough".chars().count());
    }

    #[test]
    fn a_long_detail_alone_still_reports_truncation() {
        // The summary is within bounds, so only the detail can set the flag.
        // Guards against a `truncated` that only ever looks at the summary.
        let mut log = FindingsLog::new();
        let detail = "y".repeat(MAX_DETAIL_CHARS + 10);
        let r = log
            .record(ts(), None, "fine", Some(&detail), "cap-1", 1, 2)
            .expect("accepted");
        assert!(r.truncated);
        assert_eq!(r.detail_chars_submitted, MAX_DETAIL_CHARS + 10);
    }

    #[test]
    fn multibyte_text_clips_on_a_character_boundary_without_panicking() {
        // The text an agent quotes back can be any UTF-8, because it came off
        // the wire. Byte-index truncation would panic mid-sequence.
        let mut log = FindingsLog::new();
        let emoji = "🙂".repeat(MAX_SUMMARY_CHARS + 40);
        let r = rec(&mut log, &emoji).expect("accepted");
        assert!(r.truncated);
        assert_eq!(r.summary_chars_submitted, MAX_SUMMARY_CHARS + 40);
    }
}
