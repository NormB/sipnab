// SPDX-License-Identifier: MIT OR Apache-2.0

//! The operations journal: what sipnab did to other systems, kept across runs.
//!
//! sipnab journals each operation it performs on another system (the first is
//! asking TFPS to ban or unban an address) so that a restarted sipnab knows
//! what it had done, what was still in flight, and which limits it had spent.
//! The design is the approved spec "sipnab Operations Journal" (2026-09-28);
//! this module is the file itself, and callers decide what to write.
//!
//! # The file
//!
//! A directory, mode 0700, holding segments `journal-000001.jsonl`,
//! `journal-000002.jsonl`, … mode 0600. One JSON object per line. Every line
//! carries an envelope: `v` (the format version), `seq` (continuous across
//! runs and segments), `ts` (UTC), `run`, `kind`, and `prev`, the SHA-256 of
//! the previous line's bytes. Editing, removing or reordering a record breaks
//! every link after it, and [`Journal::open`] refuses the journal and names
//! the record where the chain breaks. The chain detects accident and partial
//! tampering; whoever can rewrite the directory as root can also write a new,
//! valid chain.
//!
//! # Durability
//!
//! [`Journal::append`] returns only after the line is written and
//! `fdatasync`ed, unlike the audit files, which deliberately do not sync. A
//! caller that writes an intent before acting can therefore rely on the intent
//! being on disk when the action starts. A crash during a write leaves at most
//! a torn final line; its sync never returned, so nothing it described was
//! done, and [`Journal::open`] discards it and records that it did.
//!
//! # One writer
//!
//! The directory holds a lock file, locked for the life of a [`Journal`]. A
//! second sipnab pointed at the same journal is refused rather than allowed to
//! interleave records.
//!
//! # Size
//!
//! A segment closes at [`JournalLimits::segment_bytes`]; the next one opens
//! with a `checkpoint` record carrying the state still in force, so closed
//! segments older than the retention window can be deleted without losing
//! anything. After pruning, the chain starts at the first remaining
//! checkpoint.

pub mod ledger;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::Digest;

/// The record format version this build writes and reads.
pub const VERSION: u64 = 1;

/// Envelope fields a body may not set.
const ENVELOPE: [&str; 6] = ["v", "seq", "ts", "run", "kind", "prev"];

/// The kind of the record [`Journal::open`] writes after discarding a torn line.
pub const TORN_TAIL_KIND: &str = "torn_tail_discarded";

/// The kind that opens every segment after the first.
pub const CHECKPOINT_KIND: &str = "checkpoint";

/// Size and retention bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    /// A segment closes once it reaches this many bytes.
    pub segment_bytes: u64,
    /// Closed segments older than this are deleted by [`Journal::prune`].
    pub retention: Duration,
}

impl Default for JournalLimits {
    /// 16 MiB segments, 90 days of closed segments.
    fn default() -> Self {
        Self {
            segment_bytes: 16 * 1024 * 1024,
            retention: Duration::from_secs(90 * 86_400),
        }
    }
}

/// One record read back from the journal.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Position in the journal, continuous across runs.
    pub seq: u64,
    /// When it was written, UTC, RFC 3339.
    pub ts: String,
    /// The run that wrote it.
    pub run: String,
    /// What it records.
    pub kind: String,
    /// Every field outside the envelope.
    pub body: serde_json::Value,
}

/// What [`Journal::open`] read back.
#[derive(Debug, Default)]
pub struct Recovered {
    /// Every intact record, in order.
    pub records: Vec<Record>,
    /// Bytes of a torn final line that were discarded; `0` when there was none.
    pub torn_bytes: usize,
}

/// Why the journal could not be opened or written.
#[derive(Debug)]
pub enum JournalError {
    /// A filesystem operation failed; the message names the path.
    Io(String),
    /// Another process holds this journal.
    Locked(PathBuf),
    /// There is no journal here: sipnab has recorded nothing in this
    /// directory.
    Absent(PathBuf),
    /// The chain is broken: a record was edited, removed or reordered.
    Broken {
        /// The segment holding the record where the break shows.
        segment: PathBuf,
        /// The sequence number where it shows.
        seq: u64,
        /// What does not match.
        why: String,
    },
    /// A body tried to set an envelope field.
    ReservedField(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "{m}"),
            Self::Absent(d) => write!(
                f,
                "there is no journal at {}: sipnab has recorded no action there",
                d.display()
            ),
            Self::Locked(d) => write!(
                f,
                "the journal at {} is in use by another sipnab; two writers would interleave records",
                d.display()
            ),
            Self::Broken { segment, seq, why } => write!(
                f,
                "the journal is damaged at record {seq} in {}: {why}. Actions stay off until \
                 an operator has looked; everything that only reads keeps working",
                segment.display()
            ),
            Self::ReservedField(k) => {
                write!(
                    f,
                    "a journal record body may not set the envelope field {k:?}"
                )
            }
        }
    }
}

impl std::error::Error for JournalError {}

/// An I/O failure, naming what was being done and to which path.
fn io(what: &str, path: &Path, e: std::io::Error) -> JournalError {
    JournalError::Io(format!("{what} {}: {e}", path.display()))
}

/// An open, locked journal.
#[derive(Debug)]
pub struct Journal {
    /// The journal directory.
    dir: PathBuf,
    /// Held for the lock's lifetime; dropping it releases the journal.
    _lock: File,
    /// The open segment, appended to.
    file: File,
    /// Its path.
    segment: PathBuf,
    /// Its number.
    segment_no: u64,
    /// Its length in bytes.
    segment_len: u64,
    /// The sequence number of the last record written.
    seq: u64,
    /// The hash of the last line written, chained into the next.
    prev: Option<String>,
    /// This run's identity.
    run: String,
    /// When a segment is full and how many to keep.
    limits: JournalLimits,
}

impl Journal {
    /// Open the journal in `dir` for run `run`, with the shipped limits.
    ///
    /// # Errors
    ///
    /// See [`Self::open_with`].
    pub fn open(dir: &Path, run: &str) -> Result<(Self, Recovered), JournalError> {
        Self::open_with(dir, run, JournalLimits::default())
    }

    /// Open, lock and verify the journal in `dir`, creating it if absent.
    ///
    /// # Errors
    ///
    /// [`JournalError::Locked`] when another process holds it,
    /// [`JournalError::Broken`] when the chain does not verify, and
    /// [`JournalError::Io`] for anything the filesystem refuses.
    pub fn open_with(
        dir: &Path,
        run: &str,
        limits: JournalLimits,
    ) -> Result<(Self, Recovered), JournalError> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| io("creating", dir, e))?;
        let lock_path = dir.join(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| io("opening", &lock_path, e))?;
        adopt_directory_owner(&lock, &lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(JournalError::Locked(dir.to_path_buf()));
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(io("locking", &lock_path, e)),
        }

        let segments = list_segments(dir)?;
        let (recovered, prev, next_seq) = read_segments(&segments, true)?;

        let (segment_no, segment) = match segments.last() {
            Some((n, p)) => (*n, p.clone()),
            None => (1, segment_path(dir, 1)),
        };
        let file = open_segment(&segment, segments.is_empty())?;
        if segments.is_empty() {
            sync_dir(dir)?;
        }
        let segment_len = file
            .metadata()
            .map_err(|e| io("reading the size of", &segment, e))?
            .len();
        let torn = recovered.torn_bytes;
        let mut journal = Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            file,
            segment,
            segment_no,
            segment_len,
            seq: next_seq.map_or(0, |n| n - 1),
            prev,
            run: run.to_string(),
            limits,
        };
        if torn > 0 {
            journal.append(TORN_TAIL_KIND, serde_json::json!({ "bytes": torn }))?;
        }
        Ok((journal, recovered))
    }

    /// Read and verify the journal in `dir` without locking it or changing
    /// it, for looking at while a sipnab holds it. A torn last line is left
    /// for its writer and counted in [`Recovered::torn_bytes`].
    ///
    /// # Errors
    ///
    /// [`JournalError::Absent`] when there is no journal in `dir`,
    /// [`JournalError::Broken`] when the chain does not verify, and
    /// [`JournalError::Io`] for anything the filesystem refuses.
    pub fn read(dir: &Path) -> Result<Recovered, JournalError> {
        if !dir.is_dir() {
            return Err(JournalError::Absent(dir.to_path_buf()));
        }
        let segments = list_segments(dir)?;
        if segments.is_empty() {
            return Err(JournalError::Absent(dir.to_path_buf()));
        }
        read_segments(&segments, false).map(|(recovered, _, _)| recovered)
    }

    /// Append one record and return its sequence number, once it is on disk.
    ///
    /// # Errors
    ///
    /// [`JournalError::ReservedField`] when `body` sets an envelope field or is
    /// not an object, and [`JournalError::Io`] when the write or the sync
    /// fails. A caller that cannot journal an intent must not act on it.
    pub fn append(&mut self, kind: &str, body: serde_json::Value) -> Result<u64, JournalError> {
        let serde_json::Value::Object(fields) = body else {
            return Err(JournalError::ReservedField("(not an object)".to_string()));
        };
        if let Some(k) = ENVELOPE.iter().find(|k| fields.contains_key(**k)) {
            return Err(JournalError::ReservedField((*k).to_string()));
        }
        let seq = self.seq + 1;
        let mut record = serde_json::Map::new();
        record.insert("v".into(), VERSION.into());
        record.insert("seq".into(), seq.into());
        record.insert(
            "ts".into(),
            chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                .into(),
        );
        record.insert("run".into(), self.run.clone().into());
        record.insert("kind".into(), kind.into());
        record.extend(fields);
        if let Some(prev) = &self.prev {
            record.insert("prev".into(), prev.clone().into());
        }
        let line = serde_json::to_string(&record)
            .map_err(|e| JournalError::Io(format!("encoding a journal record: {e}")))?;
        let mut bytes = line.clone().into_bytes();
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .map_err(|e| io("writing", &self.segment, e))?;
        self.file
            .sync_data()
            .map_err(|e| io("syncing", &self.segment, e))?;
        self.seq = seq;
        self.prev = Some(line_hash(line.as_bytes()));
        self.segment_len += bytes.len() as u64;
        Ok(seq)
    }

    /// Whether the current segment has reached its size bound.
    #[must_use]
    pub fn segment_full(&self) -> bool {
        self.segment_len >= self.limits.segment_bytes
    }

    /// Close the current segment and open the next, starting it with a
    /// `checkpoint` record carrying `state`: everything still in force, so the
    /// closed segments can later be pruned without losing it.
    ///
    /// # Errors
    ///
    /// [`JournalError::Io`] when the new segment cannot be created or written.
    pub fn roll_over(&mut self, state: serde_json::Value) -> Result<u64, JournalError> {
        let no = self.segment_no + 1;
        let path = segment_path(&self.dir, no);
        self.file = open_segment(&path, true)?;
        sync_dir(&self.dir)?;
        self.segment = path;
        self.segment_no = no;
        self.segment_len = 0;
        self.append(CHECKPOINT_KIND, serde_json::json!({ "state": state }))
    }

    /// Delete closed segments whose last write is older than `keep`, oldest
    /// first, stopping at the first one inside the window. The current segment
    /// is never deleted, and every segment after the first opens with a
    /// checkpoint, so what remains still verifies. Returns how many were deleted.
    ///
    /// # Errors
    ///
    /// [`JournalError::Io`] naming the first segment that could not be read
    /// or deleted.
    pub fn prune(dir: &Path, keep: Duration) -> Result<usize, JournalError> {
        let segments = list_segments(dir)?;
        let now = std::time::SystemTime::now();
        let mut removed = 0;
        for (_, path) in segments.iter().take(segments.len().saturating_sub(1)) {
            let modified = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .map_err(|e| io("reading the age of", path, e))?;
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
            if age < keep {
                break;
            }
            std::fs::remove_file(path).map_err(|e| io("removing", path, e))?;
            removed += 1;
        }
        if removed > 0 {
            sync_dir(dir)?;
        }
        Ok(removed)
    }

    /// The segment being written.
    #[must_use]
    pub fn segment_path(&self) -> &Path {
        &self.segment
    }

    /// The limits this journal was opened with.
    #[must_use]
    pub fn limits(&self) -> JournalLimits {
        self.limits
    }
}

/// Read and verify `segments` in order. A torn last line is counted; with
/// `repair` it is also cut off the file, which only the lock holder may do.
/// Returns the records, the last line's hash and the next sequence number.
fn read_segments(
    segments: &[(u64, PathBuf)],
    repair: bool,
) -> Result<(Recovered, Option<String>, Option<u64>), JournalError> {
    let mut recovered = Recovered::default();
    let mut prev: Option<String> = None;
    let mut next_seq: Option<u64> = None;
    let last = segments.len().saturating_sub(1);
    for (i, (_, path)) in segments.iter().enumerate() {
        let bytes = std::fs::read(path).map_err(|e| io("reading", path, e))?;
        let mut offset = 0usize;
        while offset < bytes.len() {
            let end = bytes[offset..].iter().position(|b| *b == b'\n');
            let line_end = end.map(|n| offset + n);
            let raw = &bytes[offset..line_end.unwrap_or(bytes.len())];
            let parsed = std::str::from_utf8(raw)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok());
            let is_final_line = i == last && line_end.is_none_or(|e| e + 1 >= bytes.len());
            let Some(value) = parsed.filter(|_| line_end.is_some()) else {
                if is_final_line {
                    // A torn final line: its sync never returned, or a
                    // live writer is still writing it.
                    recovered.torn_bytes = bytes.len() - offset;
                    if !repair {
                        break;
                    }
                    let f = OpenOptions::new()
                        .write(true)
                        .open(path)
                        .map_err(|e| io("opening", path, e))?;
                    f.set_len(offset as u64)
                        .map_err(|e| io("truncating", path, e))?;
                    f.sync_all().map_err(|e| io("syncing", path, e))?;
                    break;
                }
                return Err(JournalError::Broken {
                    segment: path.clone(),
                    seq: next_seq.unwrap_or(0),
                    why: "a line is not a journal record".to_string(),
                });
            };
            let record = check_link(&value, prev.as_deref(), next_seq, path)?;
            next_seq = Some(record.seq + 1);
            prev = Some(line_hash(raw));
            recovered.records.push(record);
            offset = line_end.map_or(bytes.len(), |e| e + 1);
        }
    }
    Ok((recovered, prev, next_seq))
}

/// Check one record's envelope and its link to the record before it.
fn check_link(
    value: &serde_json::Value,
    prev: Option<&str>,
    expected_seq: Option<u64>,
    segment: &Path,
) -> Result<Record, JournalError> {
    let broken = |seq: u64, why: String| JournalError::Broken {
        segment: segment.to_path_buf(),
        seq,
        why,
    };
    let seq = value["seq"].as_u64().ok_or_else(|| {
        broken(
            expected_seq.unwrap_or(0),
            "a record has no sequence number".to_string(),
        )
    })?;
    if value["v"].as_u64() != Some(VERSION) {
        return Err(broken(
            seq,
            format!("unknown format version {}", value["v"]),
        ));
    }
    let kind = value["kind"].as_str().unwrap_or_default().to_string();
    match (expected_seq, prev) {
        (Some(expected), Some(prev)) => {
            if seq != expected {
                return Err(broken(
                    seq,
                    format!("expected record {expected}, found {seq}"),
                ));
            }
            if value["prev"].as_str() != Some(prev) {
                return Err(broken(
                    seq,
                    "it does not follow from the record before it".to_string(),
                ));
            }
        }
        // The first record read: the start of the journal, or, after pruning,
        // the checkpoint that opens the oldest remaining segment.
        _ => {
            if seq != 1 && kind != CHECKPOINT_KIND {
                return Err(broken(
                    seq,
                    "the oldest remaining record is neither the first nor a checkpoint".to_string(),
                ));
            }
        }
    }
    let mut body = value.as_object().cloned().unwrap_or_default();
    for k in ENVELOPE {
        body.remove(k);
    }
    Ok(Record {
        seq,
        ts: value["ts"].as_str().unwrap_or_default().to_string(),
        run: value["run"].as_str().unwrap_or_default().to_string(),
        kind,
        body: serde_json::Value::Object(body),
    })
}

/// A line's hash, as the next record's `prev` names it.
fn line_hash(line: &[u8]) -> String {
    let digest = sha2::Sha256::digest(line);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// The path of segment `no`.
fn segment_path(dir: &Path, no: u64) -> PathBuf {
    dir.join(format!("journal-{no:06}.jsonl"))
}

/// The segments in `dir`, by number.
fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf)>, JournalError> {
    let entries = std::fs::read_dir(dir).map_err(|e| io("listing", dir, e))?;
    let mut out: Vec<(u64, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let n = name.strip_prefix("journal-")?.strip_suffix(".jsonl")?;
            (n.len() == 6 && n.bytes().all(|b| b.is_ascii_digit()))
                .then(|| n.parse().ok().map(|n| (n, e.path())))
                .flatten()
        })
        .collect();
    out.sort();
    Ok(out)
}

/// Open a segment to append to, private to the owner.
fn open_segment(path: &Path, create_new: bool) -> Result<File, JournalError> {
    let mut o = OpenOptions::new();
    o.append(true).mode(0o600);
    if create_new {
        o.create_new(true);
    }
    let file = o.open(path).map_err(|e| io("opening", path, e))?;
    if create_new {
        adopt_directory_owner(&file, path)?;
    }
    Ok(file)
}

/// The owner a file root just created in the journal should be given: the
/// directory's, when root created it in a directory someone else owns.
///
/// The case it exists for: the service runs as `sipnab`, and an operator
/// stops it and runs `sudo sipnab --revert-actions all`, which needs root's
/// privileges for `tfps_ctl`. A segment or lock file that run creates would
/// otherwise stay root's, private (0600), and unreadable by the service when
/// it starts again, which would switch its actions off. Anyone but root can
/// only create files it owns, so nothing else ever needs changing.
fn owner_for_new_file(dir_owner: (u32, u32), file_owner: (u32, u32)) -> Option<(u32, u32)> {
    (file_owner.0 == 0 && file_owner != dir_owner).then_some(dir_owner)
}

/// Give `file`, just created at `path`, its directory's owner when
/// [`owner_for_new_file`] says so.
fn adopt_directory_owner(file: &File, path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::MetadataExt;
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    let d = std::fs::metadata(dir).map_err(|e| io("reading the owner of", dir, e))?;
    let f = file
        .metadata()
        .map_err(|e| io("reading the owner of", path, e))?;
    if let Some((uid, gid)) = owner_for_new_file((d.uid(), d.gid()), (f.uid(), f.gid())) {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid))
            .map_err(|e| io("giving the directory's owner", path, e))?;
    }
    Ok(())
}

/// Make a directory's entries durable.
fn sync_dir(dir: &Path) -> Result<(), JournalError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io("syncing", dir, e))
}

#[cfg(test)]
mod tests {
    use super::owner_for_new_file;

    // The chown itself needs root, which no test here runs as; the rule it
    // follows is driven directly.

    #[test]
    fn a_file_root_creates_in_the_services_directory_goes_to_the_service() {
        assert_eq!(
            owner_for_new_file((998, 998), (0, 0)),
            Some((998, 998)),
            "root's revert must leave files the service can open"
        );
    }

    #[test]
    fn a_file_the_owner_creates_is_left_alone() {
        assert_eq!(owner_for_new_file((998, 998), (998, 998)), None);
        assert_eq!(owner_for_new_file((1000, 1000), (1000, 1000)), None);
    }

    #[test]
    fn a_directory_root_owns_keeps_root_files() {
        assert_eq!(owner_for_new_file((0, 0), (0, 0)), None);
    }

    #[test]
    fn nobody_but_root_is_given_someone_elses_ownership() {
        // A non-root creator cannot chown, and must not try.
        assert_eq!(owner_for_new_file((998, 998), (1000, 1000)), None);
    }
}
