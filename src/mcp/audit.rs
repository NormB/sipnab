// SPDX-License-Identifier: MIT OR Apache-2.0

//! The append-only sink for the MCP tool-call audit record (PB10).
//!
//! # Why this exists beside the log line and not instead of it
//!
//! Every tool call already emits one line under the `mcp_audit` tracing
//! target, and that line is the operator's console view: it interleaves with
//! everything else sipnab says, it is filtered by `SIPNAB_LOG`, and `--quiet`
//! turns it off. Those are the right properties for a console view and the
//! wrong ones for a record somebody has to produce later. The question PB10
//! was written for — *what did the agent look at in this capture* — is asked
//! after the fact, by someone who was not at the console, about a run whose
//! log level they did not choose.
//!
//! So the sink is a second destination, not a replacement. The tracing line
//! keeps its shape and its audience; this writes the same facts to a file the
//! operator names, at a fixed format, unconditionally.
//!
//! # What "append-only" is enforced by
//!
//! - **The file is opened `O_APPEND` and is never truncated.** Every write
//!   lands at the current end of file, decided by the kernel at write time
//!   rather than by a seek this process performs, so a second sipnab writing
//!   the same path interleaves records instead of overwriting them.
//! - **One `write_all` per record, under a mutex.** Serializing this process's
//!   writers means a record is handed to the kernel as one buffer, so two
//!   concurrent tool calls cannot interleave halves of two lines.
//! - **No buffered writer.** A `BufWriter` here would be the classic lost-tail
//!   defect: records would sit in user space and vanish with the process on
//!   exactly the abnormal exit an audit trail is read after.
//! - **A per-record sequence number.** A reader can tell a truncated file from
//!   a complete one without trusting this module, because a gap in `seq` is
//!   visible. Nothing else in the record makes a missing line detectable.
//!
//! # The durability boundary, stated rather than implied
//!
//! A record that has returned from [`AuditSink::append`] has been written to
//! the kernel, so it survives this process dying by any means — panic, signal,
//! `shutdown_server`. It is NOT `fsync`ed, so it does not survive the machine
//! losing power in the window before the page cache is flushed. That line is
//! where it is on purpose: an `fsync` per tool call buys machine-crash
//! durability for a record whose realistic threat is a process that stopped,
//! and it would put a disk round trip in the path of every call.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// One tool call, as the audit file records it.
///
/// Borrowed rather than owned: every field already exists as a string at the
/// call site, and a record that allocated copies of all of them would put an
/// allocation per field in the path of every tool call.
#[derive(Debug, Clone, Copy)]
pub struct AuditRecord<'a> {
    /// The tool the caller named, including one that does not exist — a
    /// probe for tools a server does not serve is the traffic this record is
    /// kept for.
    pub tool: &'a str,
    /// The JSON-RPC request id, so a record pairs with the client's own log.
    pub request_id: &'a str,
    /// What the transport can prove about who called, already rendered by
    /// `caller_of`: `stdio`, or a peer socket plus its admission record.
    pub caller: &'a str,
    /// `ok`, `tool_error` or `refused`.
    pub outcome: &'a str,
    /// Wall time the call took.
    pub elapsed_ms: u64,
    /// The caller's arguments, already bounded by `audit_args`.
    ///
    /// Carried as the rendered STRING rather than re-serialized as JSON, so
    /// the file and the log line say the same thing including where the
    /// bound fell. Re-parsing it here would produce a record that is complete
    /// in the file and truncated in the log, and an auditor comparing the two
    /// would have no way to know which one to believe.
    pub args: &'a str,
    /// The error message when there was one, empty otherwise.
    pub error: &'a str,
}

impl AuditRecord<'_> {
    /// Render this record as one JSON object, without a trailing newline.
    ///
    /// JSON rather than the log line's `key=value` text, matching
    /// [`crate::security::alerting::alert_json_line`] — the house shape for a
    /// machine-read append channel, and for the reason that function gives:
    /// `serde_json` escapes every value, so a crafted `User-Agent` reaching
    /// this record through `args` cannot end the line or forge a field. The
    /// `key=value` line cannot make that promise, which is why it stays the
    /// console view and this is the record.
    ///
    /// # Arguments
    ///
    /// * `seq` — the sequence number this record was allocated.
    /// * `ts` — when the call completed.
    #[must_use]
    pub fn to_line(&self, seq: u64, ts: chrono::DateTime<chrono::Utc>) -> String {
        serde_json::json!({
            "seq": seq,
            "ts": ts.to_rfc3339(),
            "tool": self.tool,
            "id": self.request_id,
            "caller": self.caller,
            "outcome": self.outcome,
            "elapsed_ms": self.elapsed_ms,
            "args": self.args,
            // Present and null rather than absent on success: a reader
            // selecting `.error` gets a value for every record, so a missing
            // key never has to be told apart from a call that did not fail.
            "error": (!self.error.is_empty()).then_some(self.error),
        })
        .to_string()
    }
}

/// An open append-only audit file.
#[derive(Debug)]
pub struct AuditSink {
    /// The open file. The mutex is what makes one record one `write_all`
    /// with respect to this process's other tool calls; `O_APPEND` is what
    /// makes it one with respect to any other process on the same path.
    file: Mutex<std::fs::File>,
    /// The path, for the error a failed append reports.
    path: PathBuf,
    /// Sequence allocated to the next record, so a reader can see a gap.
    next_seq: AtomicU64,
}

impl AuditSink {
    /// Open `path` for appending, creating it if absent.
    ///
    /// # Errors
    ///
    /// Whatever the open failed with — a missing parent directory, a
    /// permission denial, a path that is a directory. Reported to the caller
    /// rather than swallowed: an audit sink the operator asked for and did not
    /// get must stop the run, not start one that silently records nothing.
    ///
    /// # Side effects
    ///
    /// Creates the file when it does not exist, mode `0600` on Unix. An
    /// EXISTING file's mode is left alone — it is the operator's, and this is
    /// the append case rather than the create case.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        // `append`, never `truncate` and never bare `write`: the whole
        // guarantee of this type is that opening the file cannot destroy what
        // is already in it. `create` and not `create_new`, because reopening
        // across restarts is the normal case.
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The record carries tool arguments — Call-IDs, filter
            // expressions, export paths — so it is not for every account on
            // the host.
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            next_seq: AtomicU64::new(1),
        })
    }

    /// The path this sink appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record.
    ///
    /// # Errors
    ///
    /// The `io::Error` from the write, or a message naming the path when the
    /// lock was poisoned by a panic in another writer. Both are returned
    /// rather than logged and discarded: the caller turns a failed append into
    /// a failed tool call, which is what keeps "every answered call is in the
    /// file" true.
    ///
    /// # Side effects
    ///
    /// Writes one line to the file and advances the sequence.
    pub fn append(&self, record: &AuditRecord<'_>) -> std::io::Result<u64> {
        let mut file = self.file.lock().map_err(|_| {
            std::io::Error::other(format!(
                "audit sink {} is unusable: a writer panicked while holding it",
                self.path.display()
            ))
        })?;
        // Allocated under the lock, so the sequence is the file order. Handed
        // out by a counter outside it, two records could reach the file in the
        // opposite order to their numbers and a reader would read a gap that
        // is not one.
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut line = record.to_line(seq, chrono::Utc::now());
        line.push('\n');
        // One call with the newline already attached. Writing the record and
        // the newline separately would let another process's `O_APPEND` write
        // land between them and split the line in two.
        file.write_all(line.as_bytes())?;
        // A no-op on an unbuffered `File`, and kept anyway: it is what makes
        // the intent survive somebody later wrapping this in a `BufWriter`,
        // where its absence would be the lost-tail defect this module's header
        // warns about.
        file.flush()?;
        Ok(seq)
    }

    /// How many records this sink has appended since it was opened.
    ///
    /// The next sequence minus one. Used by the tests to assert no record was
    /// dropped under concurrency, and by nothing on the hot path.
    #[must_use]
    pub fn records_written(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Read a sink file back as lines.
    fn lines(path: &Path) -> Vec<String> {
        let mut s = String::new();
        std::fs::File::open(path)
            .expect("open sink")
            .read_to_string(&mut s)
            .expect("read sink");
        s.lines().map(str::to_string).collect()
    }

    /// A record for tests, with the fields that matter overridable.
    fn rec<'a>(tool: &'a str, args: &'a str) -> AuditRecord<'a> {
        AuditRecord {
            tool,
            request_id: "1",
            caller: "stdio",
            outcome: "ok",
            elapsed_ms: 0,
            args,
            error: "",
        }
    }

    /// The attack: opening the sink must not destroy the record already in it.
    ///
    /// This is the defect that makes an append-only log worthless, and it is
    /// one `OpenOptions` flag away at all times — `truncate(true)` or a bare
    /// `write(true)` on a fresh open would both pass every "the sink writes a
    /// line" test while erasing every previous run.
    #[test]
    fn reopening_the_sink_does_not_truncate_what_is_there() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{\"seq\":1,\"tool\":\"from_an_earlier_run\"}\n").expect("seed");

        let sink = AuditSink::open(&path).expect("open");
        sink.append(&rec("list_dialogs", "{}")).expect("append");
        drop(sink);

        let out = lines(&path);
        assert_eq!(
            out.len(),
            2,
            "the earlier run's record was destroyed by opening the sink: {out:?}"
        );
        assert!(
            out[0].contains("from_an_earlier_run"),
            "the pre-existing record must still be FIRST and intact: {out:?}"
        );
    }

    /// The attack: a hostile value inside the arguments must not be able to
    /// forge a field or a whole record.
    ///
    /// `args` is bounded before it reaches here but it is not sanitized — it
    /// is the caller's own JSON, and over HTTP the caller is whoever holds a
    /// token. A newline in it would append a second line that reads exactly
    /// like a genuine record of a call that never happened, which is worse
    /// than a missing record: it is a false one.
    #[test]
    fn a_newline_in_the_arguments_cannot_forge_a_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");

        let hostile = "{\"q\":\"x\"}\n{\"seq\":99,\"tool\":\"shutdown_server\",\"outcome\":\"ok\"}";
        sink.append(&rec("search_messages", hostile))
            .expect("append");

        let out = lines(&path);
        assert_eq!(
            out.len(),
            1,
            "the arguments forged a second record: {out:?}"
        );
        let v: serde_json::Value = serde_json::from_str(&out[0]).expect("one valid JSON line");
        assert_eq!(
            v["tool"], "search_messages",
            "the forged record replaced the real one: {v}"
        );
        assert_eq!(v["seq"], 1, "the forged sequence number was believed: {v}");
    }

    /// The attack: a quote in the arguments must not end the field.
    ///
    /// The console line writes `caller="…"` and space-separated `key=value`,
    /// where a quote is exactly the character that closes a field. The record
    /// is JSON specifically so this cannot happen, and asserting it is what
    /// stops somebody switching the sink to the console format later.
    #[test]
    fn a_quote_in_the_arguments_cannot_end_a_field() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");
        sink.append(&rec(
            "get_message",
            "{\"call_id\":\"a\\\" outcome=ok caller=\\\"stdio\"}",
        ))
        .expect("append");

        let out = lines(&path);
        let v: serde_json::Value = serde_json::from_str(&out[0]).expect("valid JSON");
        assert_eq!(
            v["outcome"], "ok",
            "outcome must come from the record, not the arguments: {v}"
        );
        assert_eq!(
            v["caller"], "stdio",
            "caller must come from the transport, not the arguments: {v}"
        );
        assert!(
            v["args"].as_str().expect("args").contains("outcome=ok"),
            "the hostile text must still be RECORDED, only defanged: {v}"
        );
    }

    /// No record is lost when many threads append at once, and every sequence
    /// number appears exactly once.
    ///
    /// The property that makes "append-only" mean something under load. A
    /// counter handed out before the lock, or a `BufWriter`, or two writes per
    /// record, each shows up here as a missing or duplicated `seq`.
    #[test]
    fn concurrent_appends_lose_no_record_and_no_sequence_number() {
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 64;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = std::sync::Arc::new(AuditSink::open(&path).expect("open"));

        std::thread::scope(|s| {
            for t in 0..THREADS {
                let sink = std::sync::Arc::clone(&sink);
                s.spawn(move || {
                    for i in 0..PER_THREAD {
                        let args = format!("{{\"t\":{t},\"i\":{i}}}");
                        sink.append(&rec("list_dialogs", &args)).expect("append");
                    }
                });
            }
        });

        let expected = THREADS * PER_THREAD;
        assert_eq!(sink.records_written(), expected);

        let out = lines(&path);
        assert_eq!(
            out.len() as u64,
            expected,
            "records were lost or interleaved under concurrency"
        );
        let mut seen: Vec<u64> = out
            .iter()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l)
                    .unwrap_or_else(|e| panic!("a concurrent write split a line: {e}: {l}"));
                v["seq"].as_u64().expect("seq")
            })
            .collect();
        seen.sort_unstable();
        let want: Vec<u64> = (1..=expected).collect();
        assert_eq!(
            seen, want,
            "sequence numbers must appear exactly once each — a gap is a lost \
             record and a repeat is two records a reader cannot tell apart"
        );
    }

    /// Records land in the file in sequence order, so `seq` describes the
    /// file rather than merely labeling lines.
    #[test]
    fn the_file_order_matches_the_sequence_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = std::sync::Arc::new(AuditSink::open(&path).expect("open"));
        std::thread::scope(|s| {
            for _ in 0..4 {
                let sink = std::sync::Arc::clone(&sink);
                s.spawn(move || {
                    for _ in 0..32 {
                        sink.append(&rec("t", "{}")).expect("append");
                    }
                });
            }
        });
        let seqs: Vec<u64> = lines(&path)
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).expect("json")["seq"]
                    .as_u64()
                    .expect("seq")
            })
            .collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(
            seqs, sorted,
            "a record reached the file out of sequence order, so a reader \
             cannot use seq to find where a gap starts"
        );
    }

    /// A record carries every field an auditor needs, including on a refusal.
    ///
    /// Refusals are the point: "an agent asked for a tool it was not allowed
    /// to call" is what the record is read for, and an audit that only kept
    /// successes would answer the opposite question.
    #[test]
    fn a_refusal_is_recorded_with_its_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");
        sink.append(&AuditRecord {
            tool: "shutdown_server",
            request_id: "42",
            caller: "192.0.2.9:51544 bearer-verified scope=read token=ci-runner-1",
            outcome: "refused",
            elapsed_ms: 1,
            args: "{}",
            error: "tool shutdown_server is not read-only",
        })
        .expect("append");

        let v: serde_json::Value =
            serde_json::from_str(&lines(&path)[0]).expect("valid JSON record");
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["tool"], "shutdown_server");
        assert_eq!(v["id"], "42");
        assert!(
            v["caller"]
                .as_str()
                .expect("caller")
                .contains("token=ci-runner-1"),
            "the record must name the credential to revoke: {v}"
        );
        assert!(
            v["error"]
                .as_str()
                .expect("error")
                .contains("not read-only"),
            "a refusal with no reason does not answer why: {v}"
        );
        assert!(
            v["ts"].as_str().expect("ts").contains('T'),
            "every record is timestamped: {v}"
        );
    }

    /// A successful call carries `error: null` rather than omitting the key.
    #[test]
    fn a_successful_call_records_a_null_error_rather_than_no_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");
        sink.append(&rec("list_dialogs", "{}")).expect("append");
        let v: serde_json::Value = serde_json::from_str(&lines(&path)[0]).expect("json");
        assert!(
            v.get("error").is_some() && v["error"].is_null(),
            "`.error` must exist on every record so a reader never has to tell \
             an absent key from a call that did not fail: {v}"
        );
    }

    /// Opening a path that cannot be a file is an error the caller sees.
    ///
    /// Not a silently disabled sink. An operator who passed `--mcp-audit-file`
    /// and got a run that recorded nothing would find out when they went
    /// looking for the record, which is the one moment it cannot be recreated.
    #[test]
    fn opening_an_impossible_path_is_reported_not_swallowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = AuditSink::open(&dir.path().join("no-such-dir").join("audit.jsonl"))
            .expect_err("a missing parent directory must fail the open");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// A write that fails is REPORTED, not swallowed.
    ///
    /// The defect the whole fail-closed path exists to prevent: a full disk
    /// that leaves the run answering tool calls it has no record of. `/dev/full`
    /// is a real `ENOSPC` on every write, which is the condition itself rather
    /// than a mock of it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_write_that_fails_is_reported_not_swallowed() {
        let dev_full = Path::new("/dev/full");
        if !dev_full.exists() {
            return;
        }
        let sink = AuditSink::open(dev_full).expect("open /dev/full for append");
        let err = sink
            .append(&rec("list_dialogs", "{}"))
            .expect_err("a write to a full device must not report success");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::StorageFull,
            "the caller has to be able to tell a full disk from anything else \
             to decide what to do about it: {err}"
        );
    }

    /// On Unix a freshly created sink is owner-only.
    #[cfg(unix)]
    #[test]
    fn a_new_sink_file_is_not_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");
        sink.append(&rec("list_dialogs", "{}")).expect("append");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the record carries tool arguments, so it is not for every account \
             on the host"
        );
    }
}
