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
use super::fleet_seal::{Keys, Kind, LogSealer, SealError};

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
    /// The file.
    path: PathBuf,
    /// The keys the file is sealed under.
    keys: Arc<Keys>,
    /// Seals the appends to the file as it is now.
    sealer: LogSealer,
    /// When each record the file holds was received, and its size, oldest
    /// first.
    held: Vec<(DateTime<Utc>, usize)>,
    /// Records the bounds removed since the center started.
    dropped: u64,
}

impl std::fmt::Debug for Intake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intake")
            .field("path", &self.path)
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
        let sealer = rewrite(path, &keys, &lines[first..])
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
                path: path.to_path_buf(),
                keys,
                sealer,
                held: held[first..].to_vec(),
                dropped: first as u64,
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
        let mut sealed = Vec::new();
        let mut held = Vec::with_capacity(records.len());
        for record in records {
            let line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
            sealed.extend(self.sealer.record(&line).map_err(std::io::Error::other)?);
            held.push((record.received_at, line.len()));
        }
        super::fleet_seal::append_counted(&self.path, &mut self.sealer, &sealed)?;
        self.held.extend(held);
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
        let (lines, _) = read(&self.path, &self.keys)?;
        let from = first.min(lines.len());
        self.sealer = rewrite(&self.path, &self.keys, &lines[from..])
            .map_err(|e| format!("the intake '{}': {e}", self.path.display()))?;
        self.held.drain(..first);
        self.dropped = self.dropped.saturating_add(first as u64);
        Ok(first)
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
    let records = log
        .records
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
        .collect::<Result<Vec<_>, _>>()?;
    Ok((log.records, records))
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

/// Write the intake at `path` to hold exactly `lines`, under a new data key.
fn rewrite(path: &Path, keys: &Keys, lines: &[Vec<u8>]) -> std::io::Result<LogSealer> {
    super::fleet_center::write_sealed_reading(
        path,
        keys,
        Kind::Intake,
        lines.iter().cloned().map(Ok),
        &|staged| std::fs::read(staged),
    )
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
        // The intake a center of release 0.5.244 left: the first start of
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
        rewrite(&path, &keys(1), &[b"{\"member\":1}".to_vec()])?;
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
