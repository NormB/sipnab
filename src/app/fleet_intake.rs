// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The fleet center's intake: the call records it acknowledged.
//!
//! `sipnab fleet serve` appends every new call record to one sealed log
//! beside its store, `<store>.intake`, and syncs it before it answers the
//! member, so a record the center acknowledged survives a crash. The file
//! is a sealed log of kind intake ([`super::fleet_seal`]): no call record
//! is ever on the center's disk in clear.
//!
//! Like the store, the intake is written by one process only.
//! [`Intake::open`] reads the file and writes it again under a new data key
//! before it returns, so a data key never seals records for two processes.
//!
//! # Bounds
//!
//! The intake keeps a record for the center's retention, and holds at most
//! [`MAX_INTAKE_BYTES`]: past that the oldest records go first, counted and
//! logged. [`first_kept`] is that rule.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::fleet_center::{CallRecord, Registry};
use super::fleet_log::AppendLog;
use super::fleet_seal::{Keys, Kind, SealError};

/// The most bytes of records the intake holds.
///
/// Not a setting: the intake is where records wait, and a bound on what
/// waits keeps a center that receives more than it was sized for from
/// filling its disk.
pub const MAX_INTAKE_BYTES: u64 = 64 * 1024 * 1024;

/// One call record as the intake keeps it: what the member sent, and who
/// sent it when.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntakeRecord {
    /// The member: its token's id.
    pub member: String,
    /// When the center received the record, on the center's clock.
    pub received_at: DateTime<Utc>,
    /// The member's delivery stream.
    pub stream: String,
    /// The record's position in that stream.
    pub seq: u64,
    /// When the member wrote it, on the member's clock.
    pub sent_at: DateTime<Utc>,
    /// What selected the call on the member.
    pub selected_by: String,
    /// The call: the member's own REST answer for the dialog.
    pub call: serde_json::Value,
}

impl IntakeRecord {
    /// `call` from `member`, received at `received_at`.
    #[must_use]
    pub fn new(member: &str, received_at: DateTime<Utc>, call: CallRecord) -> Self {
        Self {
            member: member.to_string(),
            received_at,
            stream: call.stream,
            seq: call.seq,
            sent_at: call.sent_at,
            selected_by: call.selected_by,
            call: call.call,
        }
    }
}

/// The intake file of the store at `store`.
#[must_use]
pub fn path_for(store: &Path) -> PathBuf {
    let mut name = store.as_os_str().to_os_string();
    name.push(".intake");
    PathBuf::from(name)
}

/// The index of the first record the intake keeps, of records received at
/// the times and of the sizes in `records`, oldest first.
///
/// A record received before `now - retention` goes. When what is left is
/// over `max_bytes`, the oldest go until the rest is at most half of
/// `max_bytes`, so a full intake is not rewritten at every append.
#[must_use]
pub fn first_kept(
    records: &[(DateTime<Utc>, usize)],
    now: DateTime<Utc>,
    retention: chrono::Duration,
    max_bytes: u64,
) -> usize {
    let cutoff = now - retention;
    let fresh = records.partition_point(|(received_at, _)| *received_at < cutoff);
    let total: u64 = records[fresh..].iter().map(|(_, len)| *len as u64).sum();
    if total <= max_bytes {
        return fresh;
    }
    let mut kept = 0u64;
    let mut first = records.len();
    while first > fresh {
        let len = records[first - 1].1 as u64;
        if kept + len > max_bytes / 2 {
            break;
        }
        kept += len;
        first -= 1;
    }
    first
}

/// The center's intake file.
pub struct Intake {
    /// The file, open for appends.
    log: AppendLog,
    /// When each record the file holds was received, and its size, oldest
    /// first.
    held: Vec<(DateTime<Utc>, usize)>,
    /// Records the bounds removed since the center started.
    dropped: u64,
    /// How many records left the front of the intake since the center
    /// started, removed or filed: the number of the first record held.
    first: u64,
    /// While a filing is out ([`Intake::filing`]): the lines of the
    /// records taken since it started, which are the last records held.
    since: Option<Vec<Vec<u8>>>,
}

/// How many of the records an intake holds leave it when a filing is done.
///
/// The filing took `count` records at the number `first`; the intake now
/// holds `held` records and its first is the number `now_first`. Records
/// the bounds removed in between are not counted a second time, and
/// records that arrived in between stay.
#[must_use]
pub fn filed_count(first: u64, count: usize, now_first: u64, held: usize) -> usize {
    let end = first.saturating_add(count as u64);
    usize::try_from(end.saturating_sub(now_first)).map_or(held, |left| left.min(held))
}

/// What an intake held at one moment ([`Intake::snapshot`]), not yet read.
#[derive(Debug)]
pub struct Snapshot {
    /// The number of the first record.
    first: u64,
    /// The records, in the file as it was.
    prefix: super::fleet_log::Prefix,
    /// The file, as messages name it.
    shown: String,
}

impl Snapshot {
    /// The number of the first record, for [`Intake::filed`].
    #[must_use]
    pub fn first(&self) -> u64 {
        self.first
    }

    /// How many records [`Snapshot::rows`] returns.
    #[must_use]
    pub fn count(&self) -> usize {
        self.prefix.count()
    }

    /// The records, oldest first: exactly those the intake held when the
    /// snapshot was taken, whatever it took, removed or filed since.
    ///
    /// # Errors
    ///
    /// The file cannot be read, the sealed layer refuses it, or a record
    /// in it does not parse. The message names the file.
    pub fn rows(self) -> Result<Vec<IntakeRecord>, String> {
        let lines = self
            .prefix
            .lines()
            .map_err(|e| format!("the intake '{}': {e}", self.shown))?;
        parsed(&self.shown, &lines)
    }

    /// The prefix, for a test that reads it through a reader of its own.
    #[cfg(test)]
    pub(super) fn prefix_mut(&mut self) -> &mut super::fleet_log::Prefix {
        &mut self.prefix
    }
}

impl std::fmt::Debug for Intake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intake")
            .field("path", &self.log.path())
            .field("records", &self.held.len())
            .finish_non_exhaustive()
    }
}

impl Intake {
    /// Open the intake at `path`, creating it when absent, and return it
    /// with the records it holds. The file is written again under a new
    /// data key, without the records past `retention` at `now` or over
    /// `max_bytes` ([`first_kept`]).
    ///
    /// # Errors
    ///
    /// The file cannot be read or rewritten, other users can read it, or
    /// the sealed layer refuses it: it is not a sealed intake, its key is
    /// not in `keys`, or it was modified or truncated. The message names
    /// the path and the layer. A refused file is left as it was found. A
    /// file in clear is refused too: no release wrote one.
    pub fn open(
        path: &Path,
        keys: Arc<Keys>,
        now: DateTime<Utc>,
        retention: chrono::Duration,
        max_bytes: u64,
    ) -> Result<(Self, Vec<IntakeRecord>), String> {
        let (lines, mut records) = read(path, &keys)?;
        let held: Vec<(DateTime<Utc>, usize)> = records
            .iter()
            .zip(&lines)
            .map(|(record, line)| (record.received_at, line.len()))
            .collect();
        let first = first_kept(&held, now, retention, max_bytes);
        let kept = lines[first..].iter().cloned().map(Ok);
        let log = AppendLog::create(path, keys, Kind::Intake, kept)
            .map_err(|e| format!("the intake '{}': {e}", path.display()))?;
        if first > 0 {
            tracing::warn!(
                "the intake '{}': {first} call record(s) past the retention or the intake's \
                 size were removed",
                path.display()
            );
        }
        records.drain(..first);
        Ok((
            Self {
                log,
                held: held[first..].to_vec(),
                dropped: first as u64,
                first: 0,
                since: None,
            },
            records,
        ))
    }

    /// Append `records` and wait until they are on disk.
    ///
    /// # Errors
    ///
    /// A record cannot be sealed, or the file cannot be opened, written or
    /// synced.
    pub fn append(&mut self, records: &[IntakeRecord]) -> std::io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let lines = records
            .iter()
            .map(|record| serde_json::to_vec(record).map_err(std::io::Error::other))
            .collect::<std::io::Result<Vec<_>>>()?;
        self.log.append(&lines)?;
        self.held.extend(
            records
                .iter()
                .zip(&lines)
                .map(|(record, line)| (record.received_at, line.len())),
        );
        if let Some(since) = &mut self.since {
            since.extend(lines);
        }
        Ok(())
    }

    /// Apply the bounds at `now`: when a record is past `retention` or the
    /// file is over `max_bytes`, rewrite it without the records
    /// [`first_kept`] leaves out. Returns how many went.
    ///
    /// # Errors
    ///
    /// The file cannot be read or rewritten; it is then as it was.
    pub fn trim(
        &mut self,
        now: DateTime<Utc>,
        retention: chrono::Duration,
        max_bytes: u64,
    ) -> Result<usize, String> {
        let first = first_kept(&self.held, now, retention, max_bytes);
        if first == 0 {
            return Ok(0);
        }
        let shown = self.log.path().display().to_string();
        let lines = self
            .log
            .held_lines()
            .map_err(|e| format!("the intake '{shown}': {e}"))?;
        let from = first.min(lines.len());
        self.log
            .rewrite(lines[from..].iter().cloned().map(Ok))
            .map_err(|e| format!("the intake '{shown}': {e}"))?;
        self.held.drain(..first);
        self.first = self.first.saturating_add(first as u64);
        self.dropped = self.dropped.saturating_add(first as u64);
        Ok(first)
    }

    /// The records the intake holds now, to be read later
    /// ([`Snapshot::rows`]): the file is opened and its header read here,
    /// and the records are not. The center takes this under its lock and
    /// reads and parses the records after the lock is released.
    ///
    /// # Errors
    ///
    /// The file cannot be opened, or its header cannot be read. The
    /// message names the file.
    #[cfg(any(feature = "fleet-store", test))]
    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let shown = self.log.path().display().to_string();
        let prefix = self
            .log
            .prefix()
            .map_err(|e| format!("the intake '{shown}': {e}"))?;
        Ok(Snapshot {
            first: self.first,
            prefix,
            shown,
        })
    }

    /// [`Intake::snapshot`] for a filing: from here until
    /// [`Intake::filed`] or [`Intake::not_filed`], the intake also keeps
    /// the lines of the records it takes, so that `filed` writes the file
    /// again from them without reading it.
    ///
    /// # Errors
    ///
    /// As [`Intake::snapshot`]; no line is then kept.
    #[cfg(any(feature = "fleet-store", test))]
    pub fn filing(&mut self) -> Result<Snapshot, String> {
        self.since = None;
        let snapshot = self.snapshot()?;
        self.since = Some(Vec::new());
        Ok(snapshot)
    }

    /// The filing that [`Intake::filing`] started did not file its
    /// records: they stay, and the lines kept for it are let go.
    #[cfg(any(feature = "fleet-store", test))]
    pub fn not_filed(&mut self) {
        self.since = None;
    }

    /// The history store filed the `count` records a snapshot took at the
    /// number `first` ([`Snapshot::first`], [`Snapshot::count`]): those of
    /// them the intake still holds leave it, and the file is written again
    /// with the records that arrived since ([`filed_count`]). Returns how
    /// many left. These are not counted as removed by the bounds
    /// ([`Intake::dropped`]).
    ///
    /// # Errors
    ///
    /// The file cannot be rewritten, or, when no lines were kept for this
    /// filing, cannot be read. The file and the records this intake holds
    /// are then as they were.
    #[cfg(any(feature = "fleet-store", test))]
    pub fn filed(&mut self, first: u64, count: usize) -> Result<usize, String> {
        // The lines kept for this filing are used here or let go: after
        // this call, however it ends, no filing is out.
        let since = self.since.take();
        let leave = filed_count(first, count, self.first, self.held.len());
        if leave == 0 {
            return Ok(0);
        }
        let shown = self.log.path().display().to_string();
        let rest = self.held.len().saturating_sub(leave);
        // The records that stay are those taken since the filing started.
        // Their lines were kept, so the file, which may hold as much as
        // the intake's bound, is not read under the center's lock. Without
        // kept lines for exactly those records, the file is the source,
        // and it is not read either when no record stays.
        let stay = match since {
            Some(lines) if lines.len() == rest => lines,
            _ if rest == 0 => Vec::new(),
            _ => {
                let mut lines = self
                    .log
                    .held_lines()
                    .map_err(|e| format!("the intake '{shown}': {e}"))?;
                lines.drain(..leave.min(lines.len()));
                lines
            }
        };
        self.log
            .rewrite(stay.into_iter().map(Ok))
            .map_err(|e| format!("the intake '{shown}': {e}"))?;
        self.held.drain(..leave);
        self.first = self.first.saturating_add(leave as u64);
        Ok(leave)
    }

    /// The records the intake holds, oldest first, read from the file.
    ///
    /// # Errors
    ///
    /// The file cannot be read, the sealed layer refuses it, or a record
    /// in it does not parse. The message names the file.
    #[cfg(any(feature = "fleet-store", test))]
    pub fn rows(&self) -> Result<Vec<IntakeRecord>, String> {
        self.snapshot()?.rows()
    }

    /// Every record the intake holds leaves it, as after a filing of all
    /// of them. Returns how many it held.
    ///
    /// # Errors
    ///
    /// As [`Intake::filed`].
    #[cfg(test)]
    pub fn clear(&mut self) -> Result<usize, String> {
        self.filed(self.first, self.held.len())
    }

    /// How many records the intake holds.
    #[must_use]
    pub fn records(&self) -> usize {
        self.held.len()
    }

    /// The bytes of the records the intake holds, before sealing.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.held.iter().map(|(_, len)| *len as u64).sum()
    }

    /// Records the bounds removed since the center started.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The file, for a test that makes its appends fail.
    #[cfg(test)]
    pub(super) fn log_mut(&mut self) -> &mut AppendLog {
        &mut self.log
    }
}

/// The records of the intake file at `path`, sealed and parsed, oldest
/// first; none when the file is absent. A last record whose write did not
/// finish is dropped: it was never acknowledged.
fn read(path: &Path, keys: &Keys) -> Result<(Vec<Vec<u8>>, Vec<IntakeRecord>), String> {
    let shown = path.display();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(format!("the intake '{shown}': {e}")),
    };
    check_private(path)?;
    let log =
        super::fleet_seal::open_log(&bytes, keys, Kind::Intake).map_err(|e| refusal(path, &e))?;
    if log.torn_tail {
        tracing::warn!(
            "the intake '{shown}': the last record is incomplete, from a write the center did \
             not finish; it is dropped"
        );
    }
    let records = parsed(&shown.to_string(), &log.records)?;
    Ok((log.records, records))
}

/// The call records the lines `lines` of the intake shown as `shown`
/// spell, in order.
fn parsed(shown: &str, lines: &[Vec<u8>]) -> Result<Vec<IntakeRecord>, String> {
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_slice::<IntakeRecord>(line).map_err(|e| {
                format!(
                    "the intake '{shown}': sealed layer: record {} is not a call record: {e}",
                    index + 1
                )
            })
        })
        .collect()
}

/// Refuse an intake file that another user can read or write.
fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let shown = path.display();
        let meta = std::fs::metadata(path).map_err(|e| format!("the intake '{shown}': {e}"))?;
        if let Some(why) = crate::privilege::permission_refusal(
            meta.uid(),
            crate::privilege::current_uid(),
            meta.mode(),
            meta.file_type().is_file(),
        ) {
            return Err(format!("the intake '{shown}' {why}"));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Move each member's position in `registry` past the records the intake
/// holds, so a record the center stored and then crashed before it noted
/// the position is still a duplicate when the member sends it again.
pub fn replay(registry: &mut Registry, records: &[IntakeRecord]) {
    for record in records {
        registry.note_stored_call(
            &record.member,
            record.received_at,
            (&record.stream, record.seq, record.sent_at),
        );
    }
}

/// Why the sealed layer refused the intake at `path`, as the center says it.
fn refusal(path: &Path, e: &SealError) -> String {
    let shown = path.display();
    match e {
        SealError::KeyNotLoaded(_) => format!(
            "the intake '{shown}': sealed layer: the file {e}; give that key's file with \
             --store-old-key-file"
        ),
        SealError::NotSealed => format!(
            "the intake '{shown}': sealed layer: the file is not a sealed intake; move it away \
             to start with an empty one"
        ),
        _ => format!("the intake '{shown}': sealed layer: the file {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::fleet_seal::MasterKey;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([b; 32]), Vec::new()))
    }

    /// A time `secs` seconds after a fixed start.
    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::seconds(1_800_000_000 + secs)
    }

    /// Three days, the retention the tests use.
    const KEEP: chrono::Duration = chrono::Duration::hours(72);

    /// The record at `seq` of `member`'s stream `s`, received at `at(seq)`.
    fn rec(member: &str, seq: u64) -> IntakeRecord {
        let secs = i64::try_from(seq).unwrap_or(0);
        IntakeRecord {
            member: member.to_string(),
            received_at: at(secs),
            stream: "s".to_string(),
            seq,
            sent_at: at(secs - 1),
            selected_by: "failed".to_string(),
            call: serde_json::json!({
                "call_id": format!("call-{seq}@example.com"),
                "from": "sip:+12025550101@example.com",
            }),
        }
    }

    /// The intake at `path` under key 1, opened at `at(100)` with the
    /// tests' bounds.
    fn open(path: &Path) -> Result<(Intake, Vec<IntakeRecord>), String> {
        Intake::open(path, keys(1), at(100), KEEP, MAX_INTAKE_BYTES)
    }

    /// An intake in a new directory that took records 1 and 2 of `edge-a`
    /// and then failed to take `batch` through a file `open` made, with
    /// the real file back in place after.
    fn intake_after_a_failure(
        files: crate::app::fleet_log::OpenFile,
        batch: &[IntakeRecord],
    ) -> Result<(tempfile::TempDir, PathBuf, Intake), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1), rec("edge-a", 2)])?;
        intake.log_mut().open_with(files);
        if intake.append(batch).is_ok() {
            return Err("the append did not fail".into());
        }
        intake
            .log_mut()
            .open_with(crate::app::fleet_log::faults::real());
        Ok((dir, path, intake))
    }

    /// The sequence numbers of the records the intake at `path` holds at
    /// the next start.
    fn seqs_at(path: &Path) -> Result<Vec<u64>, String> {
        open(path).map(|(_, records)| records.iter().map(|r| r.seq).collect())
    }

    #[test]
    fn success_an_intake_append_after_the_file_was_away_reopens() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let away = dir.path().join("away");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1)])?;
        std::fs::rename(&path, &away)?;
        assert!(
            intake.append(&[rec("edge-a", 2)]).is_err(),
            "the append fails while the file is away"
        );
        std::fs::rename(&away, &path)?;
        intake.append(&[rec("edge-a", 3)])?;
        drop(intake);
        assert_eq!(
            seqs_at(&path),
            Ok(vec![1, 3]),
            "success an intake append after the file was away reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_intake_append_after_a_full_disk_part_way_reopens() -> TestResult {
        use crate::app::fleet_log::faults::stop_at;
        let (_dir, path, mut intake) =
            intake_after_a_failure(stop_at(50, libc::ENOSPC), &[rec("edge-a", 3)])?;
        intake.append(&[rec("edge-a", 4)])?;
        drop(intake);
        assert_eq!(
            seqs_at(&path),
            Ok(vec![1, 2, 4]),
            "success an intake append after a full disk part way reopens"
        );
        Ok(())
    }

    #[test]
    fn failure_a_failed_intake_append_is_not_held() -> TestResult {
        use crate::app::fleet_log::faults::sync_fails;
        let (_dir, _path, mut intake) = intake_after_a_failure(sync_fails(1), &[rec("edge-a", 3)])?;
        assert_eq!(intake.records(), 2, "the failed record is not counted");
        let bytes = intake.bytes();
        intake.append(&[rec("edge-a", 4)])?;
        assert_eq!(intake.records(), 3, "the next record is counted");
        assert!(
            intake.bytes() > bytes,
            "failure a failed intake append is not held: {} then {bytes}",
            intake.bytes()
        );
        Ok(())
    }

    #[test]
    fn failure_a_trim_after_a_failed_append_removes_what_the_append_left() -> TestResult {
        use crate::app::fleet_log::faults::sync_fails;
        // The second sync failed: record 3 is whole in the file, and the
        // center never acknowledged it.
        let (_dir, path, mut intake) = intake_after_a_failure(sync_fails(1), &[rec("edge-a", 3)])?;
        let gone = intake.trim(at(3602), chrono::Duration::hours(1), MAX_INTAKE_BYTES)?;
        assert_eq!(gone, 1, "the trim removes the record past the retention");
        drop(intake);
        assert_eq!(
            seqs_at(&path),
            Ok(vec![2]),
            "failure a trim after a failed append removes what the append left"
        );
        Ok(())
    }

    #[test]
    fn edge_an_intake_batch_that_failed_part_way_leaves_none_of_its_records() -> TestResult {
        use crate::app::fleet_log::faults::sync_fails;
        let batch = [rec("edge-a", 3), rec("edge-a", 4), rec("edge-a", 5)];
        let (_dir, path, mut intake) = intake_after_a_failure(sync_fails(0), &batch)?;
        intake.append(&[rec("edge-a", 6)])?;
        drop(intake);
        assert_eq!(
            seqs_at(&path),
            Ok(vec![1, 2, 6]),
            "edge an intake batch that failed part way leaves none of its records"
        );
        Ok(())
    }

    #[test]
    fn edge_an_intake_stopped_after_a_failed_append_starts_with_the_records_before_it() -> TestResult
    {
        use crate::app::fleet_log::faults::stop_at;
        let (_dir, path, intake) =
            intake_after_a_failure(stop_at(9, libc::EIO), &[rec("edge-a", 3)])?;
        drop(intake);
        assert_eq!(
            seqs_at(&path),
            Ok(vec![1, 2]),
            "edge an intake stopped after a failed append starts with the records before it"
        );
        Ok(())
    }

    /// The intake releases 0.5.245 and 0.5.246 left when an append failed
    /// and a later one worked: the record after the failure is sealed for
    /// a position the file does not reach. It is refused, by file and
    /// layer, and left as found.
    #[test]
    fn failure_an_intake_an_earlier_release_wrote_past_a_failed_append_is_refused() -> TestResult {
        use crate::app::fleet_seal::append_counted;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let mut sealer = crate::app::fleet_center::write_sealed_reading(
            &path,
            &keys(1),
            Kind::Intake,
            std::iter::empty(),
            &|staged| std::fs::read(staged),
        )?;
        let first = sealer.record(&serde_json::to_vec(&rec("edge-a", 1))?)?;
        append_counted(&path, &mut sealer, &first)?;
        // The append of record 2 failed after it was sealed; nothing was
        // written.
        let _ = sealer.record(&serde_json::to_vec(&rec("edge-a", 2))?)?;
        let third = sealer.record(&serde_json::to_vec(&rec("edge-a", 3))?)?;
        append_counted(&path, &mut sealer, &third)?;
        let before = std::fs::read(&path)?;
        assert_eq!(
            open(&path).map(|_| ()),
            Err(format!(
                "the intake '{}': sealed layer: the file has a record 4 that did not \
                 authenticate (the file was modified, or its records were moved)",
                path.display()
            )),
            "failure an intake an earlier release wrote past a failed append is refused"
        );
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "the refused intake is left as found"
        );
        Ok(())
    }

    /// An intake file in a new directory holding records 1 to `n` of
    /// `edge-a`, and the directory.
    fn filled(n: u64) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        let records: Vec<IntakeRecord> = (1..=n).map(|seq| rec("edge-a", seq)).collect();
        intake.append(&records)?;
        Ok((dir, path))
    }

    #[test]
    fn success_the_intake_of_a_store_is_beside_it() {
        assert_eq!(
            path_for(Path::new("/var/lib/sipnab/center.store")),
            PathBuf::from("/var/lib/sipnab/center.store.intake"),
            "success the intake of a store is beside it"
        );
        assert_eq!(
            path_for(Path::new("store")),
            PathBuf::from("store.intake"),
            "success the intake of a store is beside it"
        );
    }

    #[test]
    fn success_a_new_intake_is_a_sealed_private_file_with_no_records() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (intake, records) = open(&path)?;
        assert_eq!(
            (records.len(), intake.records(), intake.bytes()),
            (0, 0, 0),
            "success a new intake is a sealed private file with no records"
        );
        let bytes = std::fs::read(&path)?;
        assert_eq!(
            &bytes[..4],
            b"SNFS",
            "success a new intake is a sealed private file with no records"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600,
                "success a new intake is a sealed private file with no records"
            );
        }
        Ok(())
    }

    #[test]
    fn success_appended_records_are_read_back_in_order_after_a_reopen() -> TestResult {
        let (_dir, path) = filled(3)?;
        let (intake, records) = open(&path)?;
        assert_eq!(
            records,
            vec![rec("edge-a", 1), rec("edge-a", 2), rec("edge-a", 3)],
            "success appended records are read back in order after a reopen"
        );
        assert_eq!(
            intake.records(),
            3,
            "success appended records are read back in order after a reopen"
        );
        assert!(intake.bytes() > 300, "{}", intake.bytes());
        Ok(())
    }

    #[test]
    fn success_the_intake_holds_no_call_in_clear() -> TestResult {
        let (_dir, path) = filled(3)?;
        let bytes = std::fs::read(&path)?;
        assert!(
            bytes.len() > 400,
            "the records are in the file: {}",
            bytes.len()
        );
        for clear in ["2025550101", "example.com", "edge-a", "call_id"] {
            assert!(
                !bytes.windows(clear.len()).any(|w| w == clear.as_bytes()),
                "{clear} is in the intake"
            );
        }
        Ok(())
    }

    #[test]
    fn success_records_appended_after_a_reopen_are_kept_with_the_earlier_ones() -> TestResult {
        let (_dir, path) = filled(2)?;
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-b", 9)])?;
        drop(intake);
        let (_, records) = open(&path)?;
        let seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 2, 9],
            "success records appended after a reopen are kept with the earlier ones"
        );
        Ok(())
    }

    #[test]
    fn edge_each_open_writes_the_intake_under_a_new_data_key() -> TestResult {
        let (_dir, path) = filled(2)?;
        let before = std::fs::read(&path)?;
        let (_, records) = open(&path)?;
        let after = std::fs::read(&path)?;
        assert_eq!(
            records.len(),
            2,
            "edge each open writes the intake under a new data key"
        );
        assert_ne!(before[14..30], after[14..30], "a new file id");
        assert_ne!(
            before[before.len() - 32..],
            after[after.len() - 32..],
            "and new sealed bytes"
        );
        Ok(())
    }

    #[test]
    fn edge_an_append_of_nothing_writes_nothing() -> TestResult {
        let (_dir, path) = filled(1)?;
        let (mut intake, _) = open(&path)?;
        let before = std::fs::read(&path)?;
        intake.append(&[])?;
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "edge an append of nothing writes nothing"
        );
        Ok(())
    }

    #[test]
    fn edge_a_torn_last_append_is_dropped_and_the_rest_kept() -> TestResult {
        // An append the center did not finish: a part of a record after
        // the records it had acknowledged, and no count for it.
        let (_dir, path) = filled(2)?;
        let mut bytes = std::fs::read(&path)?;
        bytes.extend([0, 0, 1, 0, 7, 7, 7, 7, 7]);
        std::fs::write(&path, &bytes)?;
        let (_, records) = open(&path)?;
        let seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 2],
            "the record whose write did not finish was never acknowledged"
        );
        Ok(())
    }

    #[test]
    fn failure_an_acknowledged_record_removed_from_the_end_is_refused() -> TestResult {
        // FLEET-STORE-TAIL-TRUNCATION: this file used to open without the
        // record, and the center then held one call fewer than it had
        // acknowledged, with nothing said.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1)])?;
        let kept = usize::try_from(std::fs::metadata(&path)?.len())?;
        intake.append(&[rec("edge-a", 2)])?;
        drop(intake);
        let bytes = std::fs::read(&path)?;
        std::fs::write(&path, &bytes[..kept])?;
        let e = open(&path).err().unwrap_or_default();
        assert_eq!(
            e,
            format!(
                "the intake '{}': sealed layer: the file was cut at its end: it holds 3 of \
                 the 5 entries it was written with",
                path.display()
            ),
            "failure an acknowledged record removed from the end is refused"
        );
        assert_eq!(
            std::fs::read(&path)?,
            bytes[..kept],
            "and the refused file is left as it was found"
        );
        Ok(())
    }

    #[test]
    fn failure_an_acknowledged_record_cut_in_its_middle_is_refused() -> TestResult {
        let (_dir, path) = filled(3)?;
        let bytes = std::fs::read(&path)?;
        std::fs::write(&path, &bytes[..bytes.len() - 7])?;
        let e = open(&path).err().unwrap_or_default();
        assert!(
            e.ends_with("was cut at its end: it holds 4 of the 5 entries it was written with"),
            "failure an acknowledged record cut in its middle is refused: {e}"
        );
        Ok(())
    }

    #[test]
    fn success_a_format_1_intake_is_read_and_written_again_as_format_2() -> TestResult {
        // The intake a center of release 0.5.245 left: the first start of
        // this build reads it and writes it again with its counts.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let lines: Vec<Vec<u8>> = [rec("edge-a", 1), rec("edge-a", 2)]
            .iter()
            .map(serde_json::to_vec)
            .collect::<Result<_, _>>()?;
        let old = crate::app::fleet_seal::sealed_format_1(
            Kind::Intake,
            keys(1).current(),
            &[&lines[0]],
            &[&lines[1]],
            &crate::app::fleet_seal::system_draw,
        )?;
        std::fs::write(&path, &old)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(old[4], 1, "the file starts as format 1");
        let (_, held) = open(&path)?;
        assert_eq!(
            held.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2],
            "success a format 1 intake is read and written again as format 2"
        );
        assert_eq!(std::fs::read(&path)?[4], 2, "and is format 2 afterwards");
        Ok(())
    }

    #[test]
    fn failure_an_intake_whose_counts_were_damaged_is_refused_by_file_and_layer() -> TestResult {
        use crate::app::fleet_seal::{COUNT_SLOT_BYTES, KEY_HEADER_BYTES};
        let (_dir, path) = filled(2)?;
        let mut bytes = std::fs::read(&path)?;
        bytes[KEY_HEADER_BYTES + 10] ^= 1;
        bytes[KEY_HEADER_BYTES + COUNT_SLOT_BYTES + 10] ^= 1;
        std::fs::write(&path, &bytes)?;
        assert_eq!(
            open(&path).err().unwrap_or_default(),
            format!(
                "the intake '{}': sealed layer: the file has a record count that did not \
                 authenticate (the file was modified, or the key is wrong)",
                path.display()
            ),
            "failure an intake whose counts were damaged is refused by file and layer"
        );
        Ok(())
    }

    #[test]
    fn edge_after_a_trim_a_record_removed_from_the_end_is_still_refused() -> TestResult {
        // A trim writes the file again; the appends after it are counted
        // in the new file as they were in the old.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1), rec("edge-a", 2)])?;
        // Record 1 was received at `at(1)` and record 2 at `at(2)`: an
        // hour of retention at `at(3602)` keeps what came at `at(2)` or
        // later.
        let gone = intake.trim(at(3602), chrono::Duration::hours(1), MAX_INTAKE_BYTES)?;
        assert_eq!(gone, 1, "the trim removed the first record");
        let kept = usize::try_from(std::fs::metadata(&path)?.len())?;
        intake.append(&[rec("edge-a", 3)])?;
        drop(intake);
        let bytes = std::fs::read(&path)?;
        std::fs::write(&path, &bytes[..kept])?;
        let e = open(&path).err().unwrap_or_default();
        assert!(
            e.ends_with("was cut at its end: it holds 2 of the 4 entries it was written with"),
            "edge after a trim a record removed from the end is still refused: {e}"
        );
        Ok(())
    }

    #[test]
    fn edge_an_intake_reopened_after_appends_counts_from_its_new_base() -> TestResult {
        // Every open rewrites the file; the records it held are then in
        // the base, and a cut there is refused as before.
        let (_dir, path) = filled(2)?;
        let (mut intake, held) = open(&path)?;
        assert_eq!(held.len(), 2, "both records are read back");
        intake.append(&[rec("edge-a", 3)])?;
        drop(intake);
        let (_, held) = open(&path)?;
        assert_eq!(
            held.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "edge an intake reopened after appends counts from its new base"
        );
        Ok(())
    }

    #[test]
    fn failure_an_intake_under_a_key_that_is_not_loaded_names_the_key_and_the_flag() -> TestResult {
        let (_dir, path) = filled(1)?;
        let before = std::fs::read(&path)?;
        let e = Intake::open(&path, keys(2), at(100), KEEP, MAX_INTAKE_BYTES)
            .err()
            .unwrap_or_default();
        let id = keys(1).current().id().to_string();
        assert!(e.contains(&format!("was written under key id {id}")), "{e}");
        assert!(
            e.ends_with("give that key's file with --store-old-key-file"),
            "{e}"
        );
        assert!(
            e.starts_with(&format!("the intake '{}': sealed layer: ", path.display())),
            "{e}"
        );
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "a refused file is left as it was"
        );
        Ok(())
    }

    #[test]
    fn failure_a_modified_intake_is_refused_and_left_as_it_was() -> TestResult {
        let (_dir, path) = filled(2)?;
        let mut bytes = std::fs::read(&path)?;
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(&path, &bytes)?;
        let e = open(&path).err().unwrap_or_default();
        assert!(e.contains("sealed layer: the file "), "{e}");
        assert_eq!(
            std::fs::read(&path)?,
            bytes,
            "failure a modified intake is refused and left as it was"
        );
        Ok(())
    }

    #[test]
    fn failure_a_registry_file_in_the_intakes_place_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = dir.path().join("center.store");
        let (_, _) = super::super::fleet_center::Store::open(&store, keys(1))?;
        let path = dir.path().join("center.store.intake");
        std::fs::copy(&store, &path)?;
        let e = open(&path).err().unwrap_or_default();
        assert!(e.contains("sealed layer: the file "), "{e}");
        Ok(())
    }

    #[test]
    fn failure_an_intake_in_clear_is_refused_and_never_imported() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let clear = format!("{}\n", serde_json::to_string(&rec("edge-a", 1))?);
        std::fs::write(&path, &clear)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let e = open(&path).err().unwrap_or_default();
        assert!(
            e.ends_with("the file is not a sealed intake; move it away to start with an empty one"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(&path)?,
            clear,
            "failure an intake in clear is refused and never imported"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn failure_an_intake_other_users_can_read_is_refused() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path) = filled(1)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let e = open(&path).err().unwrap_or_default();
        assert!(e.contains("can be read or written by other users"), "{e}");
        Ok(())
    }

    #[test]
    fn failure_a_sealed_record_that_is_not_a_call_record_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let line = b"{\"member\":1}".to_vec();
        AppendLog::create(&path, keys(1), Kind::Intake, std::iter::once(Ok(line)))?;
        let e = open(&path).err().unwrap_or_default();
        assert!(
            e.contains("sealed layer: record 1 is not a call record"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn success_records_inside_the_bounds_are_all_kept() {
        let held = [(at(0), 10), (at(1), 10), (at(2), 10)];
        assert_eq!(
            first_kept(&held, at(60), KEEP, 30),
            0,
            "success records inside the bounds are all kept"
        );
    }

    #[test]
    fn edge_records_past_the_retention_go_and_one_at_it_stays() {
        let day = 86_400;
        let held = [(at(0), 10), (at(day), 10), (at(2 * day), 10)];
        assert_eq!(
            first_kept(&held, at(3 * day), KEEP, 1000),
            0,
            "exactly three days old"
        );
        assert_eq!(
            first_kept(&held, at(3 * day + 1), KEEP, 1000),
            1,
            "edge records past the retention go and one at it stays"
        );
        assert_eq!(first_kept(&held, at(9 * day), KEEP, 1000), 3, "all of them");
    }

    #[test]
    fn edge_an_intake_over_its_bytes_keeps_the_newest_half() {
        let held = [(at(0), 40), (at(1), 40), (at(2), 40), (at(3), 40)];
        assert_eq!(
            first_kept(&held, at(60), KEEP, 160),
            0,
            "exactly at the bound"
        );
        assert_eq!(
            first_kept(&held, at(60), KEEP, 159),
            3,
            "the newest that fit in 79"
        );
        assert_eq!(
            first_kept(&held, at(60), KEEP, 30),
            4,
            "no record fits in half the bound"
        );
        assert_eq!(
            first_kept(&[], at(60), KEEP, 0),
            0,
            "edge an intake over its bytes keeps the newest half"
        );
    }

    #[test]
    fn edge_opening_drops_the_records_past_the_retention() -> TestResult {
        let (_dir, path) = filled(3)?;
        let later = at(3) + KEEP;
        let (intake, records) = Intake::open(&path, keys(1), later, KEEP, MAX_INTAKE_BYTES)?;
        let seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![3], "received exactly three days before");
        assert_eq!(
            (intake.records(), intake.dropped()),
            (1, 2),
            "edge opening drops the records past the retention"
        );
        drop(intake);
        assert_eq!(open(&path)?.1.len(), 1, "and they are gone from the file");
        Ok(())
    }

    #[test]
    fn success_trimming_rewrites_a_full_intake_to_its_newest_records() -> TestResult {
        let (_dir, path) = filled(4)?;
        let (mut intake, _) = open(&path)?;
        let one = intake.bytes() / 4;
        assert_eq!(
            intake.trim(at(100), KEEP, intake.bytes())?,
            0,
            "at the bound"
        );
        assert_eq!(
            intake.trim(at(100), KEEP, 4 * one - 1)?,
            3,
            "success trimming rewrites a full intake to its newest records"
        );
        assert_eq!(
            (intake.records(), intake.dropped()),
            (1, 3),
            "success trimming rewrites a full intake to its newest records"
        );
        intake.append(&[rec("edge-a", 5)])?;
        drop(intake);
        let seqs: Vec<u64> = open(&path)?.1.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![4, 5], "appends after a trim are kept");
        Ok(())
    }

    #[test]
    fn success_a_replayed_intake_makes_its_records_duplicates() -> TestResult {
        use super::super::fleet_center::Record;
        let mut registry = Registry::default();
        replay(
            &mut registry,
            &[rec("edge-a", 1), rec("edge-a", 2), rec("edge-b", 7)],
        );
        let again = Record::Call(CallRecord {
            stream: "s".to_string(),
            seq: 2,
            sent_at: at(1),
            selected_by: "failed".to_string(),
            call: serde_json::json!({}),
        });
        let plan = registry.plan_records("edge-a", "192.0.2.7", at(50), &[again]);
        assert_eq!(
            (plan.accepted, plan.duplicate),
            (0, 1),
            "success a replayed intake makes its records duplicates"
        );
        let records = registry.records();
        let counts: Vec<(&str, u64, u64)> = records
            .iter()
            .map(|r| (r.member.as_str(), r.cursor.seq, r.call_records))
            .collect();
        assert_eq!(
            counts,
            vec![("edge-a", 2, 2), ("edge-b", 7, 1)],
            "success a replayed intake makes its records duplicates"
        );
        Ok(())
    }

    #[test]
    fn success_the_rows_the_intake_holds_are_read_from_its_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut intake, _) = open(&dir.path().join("center.store.intake"))?;
        intake.append(&[rec("edge-a", 1), rec("edge-b", 2)])?;
        intake.append(&[rec("edge-a", 3)])?;
        assert_eq!(
            intake.rows()?,
            vec![rec("edge-a", 1), rec("edge-b", 2), rec("edge-a", 3)],
            "success every record of every append, oldest first"
        );
        Ok(())
    }

    #[test]
    fn success_a_cleared_intake_holds_nothing_and_takes_records_again() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1), rec("edge-a", 2)])?;
        assert_eq!(intake.clear()?, 2, "success two records were held");
        assert_eq!(
            (intake.records(), intake.bytes(), intake.dropped()),
            (0, 0, 0),
            "success nothing is held, and filed records are not counted as removed"
        );
        assert!(
            intake.rows()?.is_empty(),
            "success the file holds no record"
        );
        intake.append(&[rec("edge-a", 3)])?;
        drop(intake);
        let (_, records) = open(&path)?;
        assert_eq!(
            records,
            vec![rec("edge-a", 3)],
            "success a record taken after the clear is the one record a restart finds"
        );
        Ok(())
    }

    #[test]
    fn failure_a_clear_that_cannot_rewrite_the_file_leaves_the_intake_as_it_was() -> TestResult {
        let dir = tempfile::tempdir()?;
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub)?;
        let path = sub.join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1), rec("edge-a", 2)])?;
        // The directory moves away: the staged file cannot be created.
        let moved = dir.path().join("moved");
        std::fs::rename(&sub, &moved)?;
        let got = intake.clear();
        assert!(
            got.as_ref().is_err_and(|e| e.contains("the intake")),
            "failure the clear fails and names the intake: {got:?}"
        );
        assert_eq!(
            intake.records(),
            2,
            "failure the intake still counts its two records"
        );
        std::fs::rename(&moved, &sub)?;
        assert_eq!(
            intake.rows()?,
            vec![rec("edge-a", 1), rec("edge-a", 2)],
            "failure and its file still holds them"
        );
        Ok(())
    }

    #[test]
    fn failure_rows_of_a_file_that_was_changed_are_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&[rec("edge-a", 1)])?;
        let mut bytes = std::fs::read(&path)?;
        let last = bytes.len() - 40;
        bytes[last] ^= 0x01;
        std::fs::write(&path, bytes)?;
        let got = intake.rows();
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("the intake") && e.contains("sealed layer")),
            "failure a changed intake is not filed: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_rows_do_not_include_what_a_failed_append_left() -> TestResult {
        let (_dir, _path, intake) = intake_after_a_failure(
            crate::app::fleet_log::faults::stop_at(60, 28),
            &[rec("edge-a", 3)],
        )?;
        assert_eq!(
            intake.rows()?,
            vec![rec("edge-a", 1), rec("edge-a", 2)],
            "edge only the records of appends that succeeded are filed"
        );
        Ok(())
    }

    #[test]
    fn edge_clearing_an_empty_intake_is_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut intake, _) = open(&dir.path().join("center.store.intake"))?;
        assert_eq!(intake.clear()?, 0, "edge no record was held");
        assert!(intake.rows()?.is_empty(), "edge and none is");
        Ok(())
    }

    #[test]
    fn edge_a_clear_after_a_failed_append_leaves_a_file_that_takes_appends() -> TestResult {
        let (_dir, path, mut intake) = intake_after_a_failure(
            crate::app::fleet_log::faults::stop_at(60, 28),
            &[rec("edge-a", 3)],
        )?;
        assert_eq!(intake.clear()?, 2, "edge the two whole records were held");
        intake.append(&[rec("edge-a", 4)])?;
        drop(intake);
        let (_, records) = open(&path)?;
        assert_eq!(
            records,
            vec![rec("edge-a", 4)],
            "edge the file was written whole by the clear and opens with the one new record"
        );
        Ok(())
    }

    #[test]
    fn edge_a_replay_does_not_move_a_position_back_or_count_a_record_twice() -> TestResult {
        let mut registry = Registry::default();
        replay(
            &mut registry,
            &[rec("edge-a", 1), rec("edge-a", 2), rec("edge-a", 3)],
        );
        replay(&mut registry, &[rec("edge-a", 2), rec("edge-a", 3)]);
        let records = registry.records();
        assert_eq!(
            (records[0].cursor.seq, records[0].call_records),
            (3, 3),
            "edge a replay does not move a position back or count a record twice"
        );
        Ok(())
    }
}

/// A filing reads the intake without holding it: the tests of
/// [`Intake::snapshot`], [`Intake::filing`], [`Intake::filed`] and
/// [`filed_count`].
#[cfg(test)]
mod filing_tests {
    use super::*;
    use crate::app::fleet_log::faults::{real, stop_at};
    use crate::app::fleet_seal::MasterKey;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Three days, the retention the tests use.
    const KEEP: chrono::Duration = chrono::Duration::hours(72);

    /// The test key.
    fn keys() -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([1; 32]), Vec::new()))
    }

    /// A time `secs` seconds after a fixed start.
    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::seconds(1_800_000_000 + secs)
    }

    /// The record at `seq` of member `edge-a`, received at `at(seq)`.
    fn rec(seq: u64) -> IntakeRecord {
        let secs = i64::try_from(seq).unwrap_or(0);
        IntakeRecord {
            member: "edge-a".to_string(),
            received_at: at(secs),
            stream: "s".to_string(),
            seq,
            sent_at: at(secs - 1),
            selected_by: "failed".to_string(),
            call: serde_json::json!({
                "call_id": format!("call-{seq}@example.com"),
                "from": "sip:+12025550101@example.com",
            }),
        }
    }

    /// The records at `seqs`.
    fn recs(seqs: std::ops::RangeInclusive<u64>) -> Vec<IntakeRecord> {
        seqs.map(rec).collect()
    }

    /// The intake at `path`, opened at `at(100)`.
    fn open(path: &Path) -> Result<(Intake, Vec<IntakeRecord>), String> {
        Intake::open(path, keys(), at(100), KEEP, MAX_INTAKE_BYTES)
    }

    /// An intake in a directory of its own that took the records 1 to `n`:
    /// the directory, the file and the intake.
    fn holding(n: u64) -> Result<(tempfile::TempDir, PathBuf, Intake), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub)?;
        let path = sub.join("center.store.intake");
        let (mut intake, _) = open(&path)?;
        intake.append(&recs(1..=n))?;
        Ok((dir, path, intake))
    }

    /// The sequence numbers of the records the intake at `path` holds at
    /// the next start.
    fn seqs_at(path: &Path) -> Result<Vec<u64>, String> {
        open(path).map(|(_, records)| records.iter().map(|r| r.seq).collect())
    }

    /// Change one byte of the last record of the file at `path`.
    fn damage(path: &Path) -> std::io::Result<()> {
        let mut bytes = std::fs::read(path)?;
        let at = bytes.len().saturating_sub(40);
        bytes[at] ^= 0x01;
        std::fs::write(path, bytes)
    }

    /// The directory of the intake at `path` moved away, so that the file
    /// cannot be written again. Returns where it went.
    fn moved_away(path: &Path) -> std::io::Result<PathBuf> {
        let sub = path.parent().ok_or(std::io::ErrorKind::NotFound)?;
        let moved = sub.with_file_name("moved");
        std::fs::rename(sub, &moved)?;
        Ok(moved)
    }

    #[test]
    fn success_a_snapshot_reads_the_records_the_intake_held() -> TestResult {
        let (_dir, _path, intake) = holding(3)?;
        let snapshot = intake.snapshot()?;
        assert_eq!(
            (snapshot.first(), snapshot.count()),
            (0, 3),
            "success three from number 0"
        );
        assert_eq!(
            snapshot.rows()?,
            recs(1..=3),
            "success a snapshot reads the records the intake held"
        );
        Ok(())
    }

    #[test]
    fn success_a_snapshot_leaves_out_records_taken_after_it() -> TestResult {
        let (_dir, _path, mut intake) = holding(3)?;
        let snapshot = intake.snapshot()?;
        intake.append(&recs(4..=5))?;
        assert_eq!(
            snapshot.rows()?,
            recs(1..=3),
            "success a snapshot leaves out records taken after it"
        );
        assert_eq!(
            intake.rows()?,
            recs(1..=5),
            "success the intake holds all five"
        );
        Ok(())
    }

    #[test]
    fn success_filed_removes_the_filed_records_and_keeps_the_later_ones() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=5))?;
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            3,
            "success the three filed records leave"
        );
        assert_eq!(intake.records(), 2, "success two are held");
        assert_eq!(
            intake.rows()?,
            recs(4..=5),
            "success the file holds the later two"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![4, 5],
            "success filed removes the filed records and keeps the later ones"
        );
        Ok(())
    }

    #[test]
    fn success_filed_with_nothing_new_leaves_an_empty_intake() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            3,
            "success three leave"
        );
        assert_eq!(
            (intake.records(), intake.bytes(), intake.dropped()),
            (0, 0, 0),
            "success nothing is held, and filed records are not counted as removed"
        );
        drop(intake);
        assert!(
            seqs_at(&path)?.is_empty(),
            "success filed with nothing new leaves an empty intake"
        );
        Ok(())
    }

    #[test]
    fn success_filed_writes_the_kept_lines_without_reading_the_file() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=4))?;
        damage(&path)?;
        assert!(
            intake.rows().is_err(),
            "success the file can no longer be read"
        );
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            3,
            "success filed writes the kept lines without reading the file"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![4],
            "success the new file holds the later record"
        );
        Ok(())
    }

    #[test]
    fn success_an_intake_takes_records_after_filed() -> TestResult {
        let (_dir, path, mut intake) = holding(2)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(3..=3))?;
        intake.filed(snapshot.first(), snapshot.count())?;
        intake.append(&recs(4..=4))?;
        assert_eq!(intake.rows()?, recs(3..=4), "success the intake holds both");
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![3, 4],
            "success an intake takes records after filed"
        );
        Ok(())
    }

    #[test]
    fn success_the_next_snapshot_starts_at_the_number_after_the_filed_records() -> TestResult {
        let (_dir, _path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=4))?;
        intake.filed(snapshot.first(), snapshot.count())?;
        let next = intake.filing()?;
        assert_eq!(
            (next.first(), next.count()),
            (3, 1),
            "success the next snapshot starts at the number after the filed records"
        );
        assert_eq!(
            next.rows()?,
            recs(4..=4),
            "success and holds the later record"
        );
        Ok(())
    }

    #[test]
    fn success_filed_after_a_plain_snapshot_reads_the_file_for_the_rest() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.snapshot()?;
        intake.append(&recs(4..=5))?;
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            3,
            "success three leave"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![4, 5],
            "success filed after a plain snapshot reads the file for the rest"
        );
        Ok(())
    }

    #[test]
    fn success_the_bytes_held_follow_a_filing() -> TestResult {
        let (_dir, _path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        let before = intake.bytes();
        intake.append(&recs(4..=4))?;
        let one = intake.bytes().saturating_sub(before);
        intake.filed(snapshot.first(), snapshot.count())?;
        assert!(one > 0, "success a record has bytes");
        assert_eq!(
            intake.bytes(),
            one,
            "success the bytes held follow a filing"
        );
        Ok(())
    }

    #[test]
    fn success_a_snapshot_is_whole_when_a_record_lands_before_its_read() -> TestResult {
        let (_dir, _path, intake) = holding(3)?;
        let intake = Arc::new(parking_lot::Mutex::new(intake));
        let mut snapshot = intake.lock().snapshot()?;
        let writer = Arc::clone(&intake);
        snapshot.prefix_mut().read_through(Box::new(move |file| {
            let _ = writer.lock().append(&recs(4..=6));
            Box::new(file)
        }));
        assert_eq!(
            snapshot.rows()?,
            recs(1..=3),
            "success a snapshot is whole when a record lands before its read"
        );
        assert_eq!(intake.lock().records(), 6, "success the append was taken");
        Ok(())
    }

    #[test]
    fn success_the_rows_of_an_intake_are_the_rows_of_a_snapshot() -> TestResult {
        let (_dir, _path, intake) = holding(4)?;
        assert_eq!(
            intake.rows()?,
            intake.snapshot()?.rows()?,
            "success the rows of an intake are the rows of a snapshot"
        );
        Ok(())
    }

    #[test]
    fn success_filed_count_is_the_count_when_nothing_else_happened() {
        assert_eq!(
            filed_count(0, 3, 0, 3),
            3,
            "success filed count is the count when nothing else happened"
        );
        assert_eq!(filed_count(7, 2, 7, 2), 2, "success at a later number too");
    }

    #[test]
    fn success_filed_count_leaves_the_records_that_arrived() {
        assert_eq!(
            filed_count(0, 3, 0, 5),
            3,
            "success filed count leaves the records that arrived"
        );
    }

    #[test]
    fn failure_a_snapshot_of_an_intake_whose_file_is_away_names_the_intake() -> TestResult {
        let (_dir, path, intake) = holding(2)?;
        std::fs::remove_file(&path)?;
        let got = intake.snapshot();
        assert!(
            got.as_ref().is_err_and(|e| e.starts_with("the intake '")),
            "failure a snapshot of an intake whose file is away names the intake: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_filing_that_cannot_open_the_file_fails_and_the_next_one_works() -> TestResult {
        let (_dir, path, mut intake) = holding(2)?;
        let moved = moved_away(&path)?;
        let got = intake.filing();
        assert!(
            got.as_ref().is_err_and(|e| e.starts_with("the intake '")),
            "failure a filing that cannot open the file fails: {got:?}"
        );
        std::fs::rename(&moved, path.parent().ok_or("no parent")?)?;
        let snapshot = intake.filing()?;
        assert_eq!(
            snapshot.rows()?,
            recs(1..=2),
            "failure and the next one works"
        );
        Ok(())
    }

    #[test]
    fn failure_filed_that_cannot_rewrite_the_file_leaves_every_record() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=4))?;
        let moved = moved_away(&path)?;
        let got = intake.filed(snapshot.first(), snapshot.count());
        assert!(
            got.as_ref().is_err_and(|e| e.starts_with("the intake '")),
            "failure filed fails and names the intake: {got:?}"
        );
        assert_eq!(
            intake.records(),
            4,
            "failure the intake still counts its four records"
        );
        std::fs::rename(&moved, path.parent().ok_or("no parent")?)?;
        assert_eq!(
            intake.rows()?,
            recs(1..=4),
            "failure filed that cannot rewrite the file leaves every record"
        );
        Ok(())
    }

    #[test]
    fn failure_after_a_failed_filed_the_next_filing_takes_every_record() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=4))?;
        let moved = moved_away(&path)?;
        assert!(
            intake.filed(snapshot.first(), snapshot.count()).is_err(),
            "failure filed fails"
        );
        std::fs::rename(&moved, path.parent().ok_or("no parent")?)?;
        let next = intake.filing()?;
        assert_eq!(
            (next.first(), next.count()),
            (0, 4),
            "failure the numbers did not move"
        );
        assert_eq!(
            intake.filed(next.first(), next.count())?,
            4,
            "failure after a failed filed the next filing takes every record"
        );
        drop(intake);
        assert!(
            seqs_at(&path)?.is_empty(),
            "failure and the file is then empty"
        );
        Ok(())
    }

    #[test]
    fn failure_filed_after_a_plain_snapshot_of_a_changed_file_is_refused() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.snapshot()?;
        intake.append(&recs(4..=4))?;
        damage(&path)?;
        let got = intake.filed(snapshot.first(), snapshot.count());
        assert!(
            got.as_ref()
                .is_err_and(|e| e.starts_with("the intake '") && e.contains("sealed layer")),
            "failure filed after a plain snapshot of a changed file is refused: {got:?}"
        );
        assert_eq!(intake.records(), 4, "failure every record is still counted");
        Ok(())
    }

    #[test]
    fn failure_the_rows_of_a_snapshot_whose_file_was_changed_are_refused() -> TestResult {
        let (_dir, path, intake) = holding(3)?;
        let snapshot = intake.snapshot()?;
        damage(&path)?;
        let got = snapshot.rows();
        assert!(
            got.as_ref()
                .is_err_and(|e| e.starts_with("the intake '") && e.contains("sealed layer")),
            "failure the rows of a snapshot whose file was changed are refused: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_line_that_is_not_a_call_record_in_a_snapshot_is_refused() -> TestResult {
        let (_dir, _path, mut intake) = holding(2)?;
        intake.log_mut().append(&[b"not a call record".to_vec()])?;
        let got = intake.log_mut().prefix().map(|prefix| Snapshot {
            first: 0,
            prefix,
            shown: "x".to_string(),
        })?;
        let got = got.rows();
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("record 3 is not a call record")),
            "failure a line that is not a call record in a snapshot is refused: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_failed_append_during_a_filing_is_not_kept() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.log_mut().open_with(stop_at(60, libc::ENOSPC));
        assert!(
            intake.append(&recs(4..=4)).is_err(),
            "failure the append failed"
        );
        intake.log_mut().open_with(real());
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            3,
            "failure three leave"
        );
        assert_eq!(intake.records(), 0, "failure nothing is held");
        drop(intake);
        assert!(
            seqs_at(&path)?.is_empty(),
            "failure a failed append during a filing is not kept"
        );
        Ok(())
    }

    #[test]
    fn failure_a_filing_that_did_not_file_leaves_every_record() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let _snapshot = intake.filing()?;
        intake.append(&recs(4..=4))?;
        intake.not_filed();
        assert_eq!(intake.records(), 4, "failure four are held");
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![1, 2, 3, 4],
            "failure a filing that did not file leaves every record"
        );
        Ok(())
    }

    #[test]
    fn failure_filed_a_second_time_for_the_same_records_removes_nothing() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=5))?;
        let (first, count) = (snapshot.first(), snapshot.count());
        assert_eq!(
            intake.filed(first, count)?,
            3,
            "failure the first time three leave"
        );
        assert_eq!(
            intake.filed(first, count)?,
            0,
            "failure filed a second time for the same records removes nothing"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![4, 5],
            "failure the later two are still held"
        );
        Ok(())
    }

    #[test]
    fn failure_filed_count_is_zero_when_the_bounds_removed_every_filed_record() {
        assert_eq!(
            filed_count(0, 3, 5, 4),
            0,
            "failure filed count is zero when the bounds removed every filed record"
        );
        assert_eq!(
            filed_count(0, 3, 3, 4),
            0,
            "failure and when they removed exactly those"
        );
    }

    #[test]
    fn failure_filed_count_never_passes_what_is_held() {
        assert_eq!(
            filed_count(0, 10, 0, 4),
            4,
            "failure filed count never passes what is held"
        );
    }

    #[test]
    fn failure_filed_count_of_no_records_is_zero() {
        assert_eq!(
            filed_count(4, 0, 4, 9),
            0,
            "failure filed count of no records is zero"
        );
        assert_eq!(
            filed_count(0, 3, 0, 0),
            0,
            "failure and of an intake that holds none"
        );
    }

    #[test]
    fn edge_a_snapshot_of_an_empty_intake_has_no_rows() -> TestResult {
        let (_dir, _path, intake) = holding(0)?;
        let snapshot = intake.snapshot()?;
        assert_eq!(snapshot.count(), 0, "edge the count is zero");
        assert!(
            snapshot.rows()?.is_empty(),
            "edge a snapshot of an empty intake has no rows"
        );
        Ok(())
    }

    #[test]
    fn edge_filed_of_no_records_does_not_write_the_file() -> TestResult {
        let (_dir, path, mut intake) = holding(2)?;
        let before = std::fs::read(&path)?;
        assert_eq!(intake.filed(0, 0)?, 0, "edge nothing leaves");
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "edge filed of no records does not write the file"
        );
        Ok(())
    }

    #[test]
    fn edge_records_the_bounds_removed_during_a_filing_are_not_counted_twice() -> TestResult {
        let (_dir, path, mut intake) = holding(4)?;
        let snapshot = intake.filing()?;
        assert_eq!(
            intake.trim(at(3) + KEEP, KEEP, MAX_INTAKE_BYTES)?,
            2,
            "edge two are removed"
        );
        intake.append(&recs(5..=5))?;
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            2,
            "edge records the bounds removed during a filing are not counted twice"
        );
        assert_eq!(
            (intake.records(), intake.dropped()),
            (1, 2),
            "edge one held, two removed"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![5],
            "edge the file holds the record that arrived"
        );
        Ok(())
    }

    #[test]
    fn edge_bounds_that_pass_the_filed_records_leave_filed_nothing_to_do() -> TestResult {
        let (_dir, path, mut intake) = holding(2)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(3..=4))?;
        assert_eq!(
            intake.trim(at(4) + KEEP, KEEP, MAX_INTAKE_BYTES)?,
            3,
            "edge three removed"
        );
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            0,
            "edge bounds that pass the filed records leave filed nothing to do"
        );
        assert_eq!(intake.records(), 1, "edge one record is held");
        let next = intake.filing()?;
        assert_eq!(
            (next.first(), next.count()),
            (3, 1),
            "edge the next filing starts at 3"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![4],
            "edge the file holds the last record"
        );
        Ok(())
    }

    #[test]
    fn edge_bounds_that_remove_a_part_of_the_filed_records_keep_every_later_one() -> TestResult {
        let (_dir, path, mut intake) = holding(2)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(3..=5))?;
        assert_eq!(
            intake.trim(at(2) + KEEP, KEEP, MAX_INTAKE_BYTES)?,
            1,
            "edge one removed"
        );
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            1,
            "edge record 2 leaves"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![3, 4, 5],
            "edge bounds that remove a part of the filed records keep every later one"
        );
        Ok(())
    }

    #[test]
    fn edge_filed_count_at_the_largest_numbers_does_not_overflow() {
        assert_eq!(
            filed_count(u64::MAX, usize::MAX, 0, 3),
            3,
            "edge filed count at the largest numbers does not overflow"
        );
        assert_eq!(
            filed_count(u64::MAX - 1, 5, u64::MAX, 9),
            0,
            "edge at the last number"
        );
    }

    #[test]
    fn edge_filed_count_of_records_removed_in_part_is_the_rest() {
        assert_eq!(
            filed_count(2, 5, 4, 10),
            3,
            "edge filed count of records removed in part is the rest"
        );
    }

    #[test]
    fn edge_a_repair_during_a_filing_keeps_the_record_that_followed_it() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.log_mut().open_with(stop_at(60, libc::ENOSPC));
        assert!(
            intake.append(&recs(4..=4)).is_err(),
            "edge the append failed"
        );
        intake.log_mut().open_with(real());
        intake.append(&recs(5..=5))?;
        assert_eq!(
            snapshot.rows()?,
            recs(1..=3),
            "edge the snapshot reads the file it opened"
        );
        assert_eq!(intake.filed(0, 3)?, 3, "edge three leave");
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![5],
            "edge a repair during a filing keeps the record that followed it"
        );
        Ok(())
    }

    #[test]
    fn edge_a_question_during_a_filing_reads_every_record() -> TestResult {
        let (_dir, _path, mut intake) = holding(3)?;
        let filing = intake.filing()?;
        intake.append(&recs(4..=4))?;
        assert_eq!(
            intake.snapshot()?.rows()?,
            recs(1..=4),
            "edge a question during a filing reads every record"
        );
        assert_eq!(
            intake.filed(filing.first(), filing.count())?,
            3,
            "edge the filing ends"
        );
        assert_eq!(
            intake.rows()?,
            recs(4..=4),
            "edge and the later record is held"
        );
        Ok(())
    }

    #[test]
    fn edge_a_stop_before_filed_leaves_every_record_for_the_next_start() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.filing()?;
        intake.append(&recs(4..=4))?;
        assert_eq!(
            snapshot.rows()?.len(),
            3,
            "edge the filing read its three records"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![1, 2, 3, 4],
            "edge a stop before filed leaves every record for the next start"
        );
        Ok(())
    }

    #[test]
    fn edge_a_second_filing_before_filed_starts_the_kept_lines_again() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let _abandoned = intake.filing()?;
        intake.append(&recs(4..=4))?;
        let snapshot = intake.filing()?;
        intake.append(&recs(5..=5))?;
        assert_eq!(snapshot.count(), 4, "edge the second filing holds four");
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            4,
            "edge four leave"
        );
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![5],
            "edge a second filing before filed starts the kept lines again"
        );
        Ok(())
    }

    #[test]
    fn edge_filed_for_every_record_held_does_not_read_the_file() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let snapshot = intake.snapshot()?;
        damage(&path)?;
        assert!(
            intake.rows().is_err(),
            "edge the file can no longer be read"
        );
        assert_eq!(
            intake.filed(snapshot.first(), snapshot.count())?,
            3,
            "edge filed for every record held does not read the file"
        );
        drop(intake);
        assert!(
            seqs_at(&path)?.is_empty(),
            "edge the new file holds no record"
        );
        Ok(())
    }

    #[test]
    fn failure_after_a_filing_that_did_not_file_no_kept_line_is_used() -> TestResult {
        let (_dir, path, mut intake) = holding(3)?;
        let _abandoned = intake.filing()?;
        intake.not_filed();
        let snapshot = intake.snapshot()?;
        intake.append(&recs(4..=4))?;
        damage(&path)?;
        // One record stays. Its line is read from the file, which is
        // refused: no line kept for the filing that did not file is used.
        let got = intake.filed(snapshot.first(), snapshot.count());
        assert!(
            got.as_ref().is_err_and(|e| e.contains("sealed layer")),
            "failure after a filing that did not file no kept line is used: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_filed_for_a_part_of_what_is_held_keeps_the_rest_in_order() -> TestResult {
        let (_dir, path, mut intake) = holding(5)?;
        assert_eq!(intake.filed(0, 2)?, 2, "edge the first two leave");
        assert_eq!(intake.filed(2, 1)?, 1, "edge then the third");
        drop(intake);
        assert_eq!(
            seqs_at(&path)?,
            vec![4, 5],
            "edge filed for a part of what is held keeps the rest in order"
        );
        Ok(())
    }
}
