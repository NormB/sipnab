// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A sealed log file the center appends to: the store and the intake.
//!
//! [`AppendLog`] owns the file's sealer and the one rule both files follow
//! when an append fails. A sealer seals each entry at the next position of
//! its file, and a position is used once under a data key. An append that
//! fails after its records were sealed leaves the sealer past what the
//! file holds: the next record would be sealed for a position the file
//! does not reach, and the file would not open again.
//!
//! So a failed append marks the log, and the next append first reads the
//! file, keeps the records of the appends that succeeded, and writes them
//! again under a new data key. No position is sealed twice under one key,
//! and nothing a failed append left in the file stays in it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::fleet_seal::{Keys, Kind, LogFile, LogSealer};

/// Opens the file at a path for one append.
pub(super) type OpenFile = Box<dyn Fn(&Path) -> std::io::Result<Box<dyn LogFile>> + Send + Sync>;

/// A sealed log file, written under a new data key and open for appends.
pub struct AppendLog {
    /// The file.
    path: PathBuf,
    /// The keys: the current one to write under, the old ones to read under.
    keys: Arc<Keys>,
    /// What the file is: a store or an intake.
    kind: Kind,
    /// Seals the appends to the file as it now is.
    sealer: LogSealer,
    /// The records the file holds: those of its last rewrite and of every
    /// append since that succeeded.
    held: usize,
    /// Whether an append failed since the file was last written whole, so
    /// the sealer may be past what the file holds.
    behind: bool,
    /// Opens the file for an append.
    open: OpenFile,
}

impl std::fmt::Debug for AppendLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppendLog")
            .field("path", &self.path)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl AppendLog {
    /// Write the file of `kind` at `path` to hold exactly `lines`, under a
    /// new data key of the current key in `keys`, and return it open for
    /// appends.
    ///
    /// # Errors
    ///
    /// A line is an error, or the file cannot be sealed, written, synced,
    /// read back or renamed into place. The file at `path` is then as it
    /// was.
    pub(super) fn create(
        path: &Path,
        keys: Arc<Keys>,
        kind: Kind,
        lines: impl Iterator<Item = std::io::Result<Vec<u8>>>,
    ) -> std::io::Result<Self> {
        let (sealer, held) = write(path, &keys, kind, lines)?;
        Ok(Self {
            path: path.to_path_buf(),
            keys,
            kind,
            sealer,
            held,
            behind: false,
            open: Box::new(super::fleet_seal::open_for_append),
        })
    }

    /// Write the file again to hold exactly `lines`, under a new data key.
    ///
    /// # Errors
    ///
    /// As [`AppendLog::create`]. The file and this log are then as they
    /// were.
    pub(super) fn rewrite(
        &mut self,
        lines: impl Iterator<Item = std::io::Result<Vec<u8>>>,
    ) -> std::io::Result<()> {
        let (sealer, held) = write(&self.path, &self.keys, self.kind, lines)?;
        self.sealer = sealer;
        self.held = held;
        self.behind = false;
        Ok(())
    }

    /// Append `lines` as one append and wait until they are on disk. When
    /// an append failed before this one, the file is first read and
    /// written again under a new data key, without what that append left.
    ///
    /// # Errors
    ///
    /// A line cannot be sealed, or the file cannot be opened, written or
    /// synced; or, after a failed append, the file cannot be read and
    /// written again ([`AppendLog::held_lines`], [`AppendLog::rewrite`]).
    /// The append is then not in the file as far as a reader of
    /// [`AppendLog::held_lines`] sees, and the next append starts with the
    /// same repair.
    pub(super) fn append(&mut self, lines: &[Vec<u8>]) -> std::io::Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        if self.behind {
            // The file is read and written again under a new data key, and
            // this log is left marked when that fails: nothing is sealed
            // for a file the sealer does not match.
            let held = self.held_lines()?;
            self.rewrite(held.into_iter().map(Ok))?;
        }
        // Marked from before the first record is sealed until the append is
        // on disk whole, so every way out of here in between leaves it
        // marked: a record that cannot be sealed after another was, a file
        // that cannot be opened, a write or a sync that fails.
        self.behind = true;
        let mut frames = Vec::new();
        for line in lines {
            frames.extend(self.sealer.record(line).map_err(std::io::Error::other)?);
        }
        let mut file = (self.open)(&self.path)?;
        super::fleet_seal::append_counted_to(&mut *file, &mut self.sealer, &frames)?;
        self.behind = false;
        self.held += lines.len();
        Ok(())
    }

    /// The records the file holds, oldest first, read from the file: those
    /// of its last rewrite and of every append since that succeeded. What a
    /// failed append left after them is not returned.
    ///
    /// # Errors
    ///
    /// The file cannot be read, the sealed layer refuses it, or it holds
    /// fewer records than were written to it.
    pub(super) fn held_lines(&self) -> std::io::Result<Vec<Vec<u8>>> {
        let bytes = std::fs::read(&self.path)?;
        let log = super::fleet_seal::open_log(&bytes, &self.keys, self.kind)
            .map_err(|e| std::io::Error::other(format!("sealed layer: the file {e}")))?;
        let mut lines = log.records;
        holds_what_was_written(lines.len(), self.held).map_err(std::io::Error::other)?;
        lines.truncate(self.held);
        Ok(lines)
    }

    /// How many records the file holds, for the tests of that count.
    #[cfg(test)]
    pub(super) fn held(&self) -> usize {
        self.held
    }

    /// The file.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Open the file for each append with `open`, which a test uses to put
    /// a file that fails in its place.
    #[cfg(test)]
    pub(super) fn open_with(&mut self, open: OpenFile) {
        self.open = open;
    }
}

/// Check that a file that holds `found` records holds at least the `held`
/// records written to it.
///
/// # Errors
///
/// It holds fewer: something put another file in its place.
fn holds_what_was_written(found: usize, held: usize) -> Result<(), String> {
    if found < held {
        return Err(format!(
            "sealed layer: the file holds {} record(s) where {} were written; it was changed \
             while the center ran",
            found, held
        ));
    }
    Ok(())
}

/// Write the sealed file of `kind` at `path` to hold exactly `lines`, and
/// return the sealer for appends to it and the count of lines.
fn write(
    path: &Path,
    keys: &Keys,
    kind: Kind,
    lines: impl Iterator<Item = std::io::Result<Vec<u8>>>,
) -> std::io::Result<(LogSealer, usize)> {
    let mut held = 0usize;
    let sealer = super::fleet_center::write_sealed_reading(
        path,
        keys,
        kind,
        lines.inspect(|_| held += 1),
        &|staged| std::fs::read(staged),
    )?;
    Ok((sealer, held))
}

/// Files that fail, for the tests of a failed append. They write to the
/// real file up to the point of the failure, so the file on disk is what a
/// full disk or a failing device leaves. A real full disk is not used: it
/// would need a file system of its own and root.
#[cfg(test)]
pub(super) mod faults {
    use super::OpenFile;
    use crate::app::fleet_seal::LogFile;
    use std::io::{Seek, SeekFrom, Write};

    /// No limit on the bytes written or the syncs done.
    pub const NO_LIMIT: usize = usize::MAX;

    /// A file that takes `bytes` bytes and `syncs` syncs and then fails.
    struct Failing {
        /// The real file.
        file: std::fs::File,
        /// The bytes it still takes.
        bytes: usize,
        /// The syncs it still does.
        syncs: usize,
        /// The error it fails with, or none for a write of no bytes.
        errno: Option<i32>,
        /// Whether the next write is first interrupted.
        interrupt: bool,
        /// The most bytes one write takes.
        step: usize,
    }

    impl Failing {
        /// The error this file fails with.
        fn error(&self) -> std::io::Error {
            self.errno.map_or_else(
                || std::io::ErrorKind::WriteZero.into(),
                std::io::Error::from_raw_os_error,
            )
        }
    }

    impl Write for Failing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            if self.bytes == 0 {
                return match self.errno {
                    Some(_) => Err(self.error()),
                    None => Ok(0),
                };
            }
            let take = buf.len().min(self.bytes).min(self.step);
            let n = self.file.write(&buf[..take])?;
            self.bytes = self.bytes.saturating_sub(n);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    impl Seek for Failing {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.file.seek(pos)
        }
    }

    impl LogFile for Failing {
        fn sync(&mut self) -> std::io::Result<()> {
            if self.syncs == 0 {
                return Err(self.error());
            }
            self.syncs = self.syncs.saturating_sub(1);
            self.file.sync_data()
        }
    }

    /// An opener of files that behave as `make` says.
    fn opener(
        bytes: usize,
        syncs: usize,
        errno: Option<i32>,
        interrupt: bool,
        step: usize,
    ) -> OpenFile {
        Box::new(move |path| {
            let file = std::fs::OpenOptions::new().write(true).open(path)?;
            Ok(Box::new(Failing {
                file,
                bytes,
                syncs,
                errno,
                interrupt,
                step,
            }))
        })
    }

    /// Files whose writes fail with `errno` once `bytes` bytes are written.
    pub fn stop_at(bytes: usize, errno: i32) -> OpenFile {
        opener(bytes, NO_LIMIT, Some(errno), false, NO_LIMIT)
    }

    /// Files whose sync fails with an input/output error after `syncs`
    /// syncs that work.
    pub fn sync_fails(syncs: usize) -> OpenFile {
        opener(NO_LIMIT, syncs, Some(libc::EIO), false, NO_LIMIT)
    }

    /// Files that take `bytes` bytes and then accept none, without an
    /// error of their own.
    pub fn zero_write(bytes: usize) -> OpenFile {
        opener(bytes, NO_LIMIT, None, false, NO_LIMIT)
    }

    /// Files that work, slowly: the first write is interrupted, and each
    /// write takes one byte.
    pub fn slow() -> OpenFile {
        opener(NO_LIMIT, NO_LIMIT, Some(libc::EIO), true, 1)
    }

    /// No file: the open fails with `errno`.
    pub fn refuse(errno: i32) -> OpenFile {
        Box::new(move |_| Err(std::io::Error::from_raw_os_error(errno)))
    }

    /// The real file.
    pub fn real() -> OpenFile {
        Box::new(crate::app::fleet_seal::open_for_append)
    }
}

#[cfg(test)]
mod tests {
    use super::faults::{real, refuse, slow, stop_at, sync_fails, zero_write};
    use super::*;
    use crate::app::fleet_seal::{MAX_RECORD_BYTES, MasterKey, open_log};

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The bytes one record of [`line`] takes in the file: a length, the
    /// mark, the line and the tag.
    const FRAME: usize = 4 + 1 + 10 + 16;

    /// The bytes the end of an append takes in the file.
    const END: usize = 4 + 1 + 16;

    /// The bytes one count takes in the file's header.
    const COUNT: usize = crate::app::fleet_seal::COUNT_SLOT_BYTES;

    /// The test key.
    fn keys() -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([1; 32]), Vec::new()))
    }

    /// Record `n`, ten bytes.
    fn line(n: u8) -> Vec<u8> {
        format!("record-{n:03}").into_bytes()
    }

    /// The records `ns`.
    fn lines(ns: &[u8]) -> Vec<Vec<u8>> {
        ns.iter().map(|n| line(*n)).collect()
    }

    /// A log in a directory of its own.
    struct Fixture {
        /// The directory, removed when this is dropped.
        _dir: tempfile::TempDir,
        /// The file.
        path: PathBuf,
        /// The log.
        log: AppendLog,
    }

    /// A log of `kind` written with the records `ns`.
    fn log_of(kind: Kind, ns: &[u8]) -> Result<Fixture, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let log = AppendLog::create(&path, keys(), kind, lines(ns).into_iter().map(Ok))?;
        Ok(Fixture {
            _dir: dir,
            path,
            log,
        })
    }

    /// A store log written with records 1 and 2.
    fn log() -> Result<Fixture, Box<dyn std::error::Error>> {
        log_of(Kind::Registry, &[1, 2])
    }

    /// What the file at `path` holds when it is opened as a center opens it
    /// at start.
    fn on_disk(path: &Path, kind: Kind) -> Result<Vec<Vec<u8>>, String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        open_log(&bytes, &keys(), kind)
            .map(|log| log.records)
            .map_err(|e| e.to_string())
    }

    /// The id of the file at `path`, which changes with its data key.
    fn file_id(path: &Path) -> std::io::Result<Vec<u8>> {
        Ok(std::fs::read(path)?[14..30].to_vec())
    }

    /// Append record 3 to `f` through files `open` makes, which must fail,
    /// and put the real file back. Returns the error.
    fn fail(f: &mut Fixture, open: OpenFile) -> Result<std::io::Error, String> {
        f.log.open_with(open);
        let failed = f.log.append(&lines(&[3]));
        f.log.open_with(real());
        failed.err().ok_or_else(|| "the append did not fail".into())
    }

    /// A log of `kind` holding records 1 and 2 takes an append of record 3
    /// that fails through `open`, and then record 4 through the real file.
    /// Returns what the file holds at the next start.
    fn after_failure(
        kind: Kind,
        open: OpenFile,
    ) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut f = log_of(kind, &[1, 2])?;
        fail(&mut f, open)?;
        f.log.append(&lines(&[4]))?;
        Ok(on_disk(&f.path, kind)?)
    }

    #[test]
    fn success_an_append_after_an_open_that_failed_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, refuse(libc::ENOENT))?,
            lines(&[1, 2, 4]),
            "success an append after an open that failed reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_a_write_that_stopped_part_way_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, stop_at(10, libc::ENOSPC))?,
            lines(&[1, 2, 4]),
            "success an append after a write that stopped part way reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_a_full_disk_at_the_first_byte_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, stop_at(0, libc::ENOSPC))?,
            lines(&[1, 2, 4]),
            "success an append after a full disk at the first byte reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_an_input_output_error_part_way_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, stop_at(FRAME + 3, libc::EIO))?,
            lines(&[1, 2, 4]),
            "success an append after an input/output error part way reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_a_failed_first_sync_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, sync_fails(0))?,
            lines(&[1, 2, 4]),
            "success an append after a failed first sync reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_a_count_that_was_not_written_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, stop_at(FRAME + END, libc::ENOSPC))?,
            lines(&[1, 2, 4]),
            "success an append after a count that was not written reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_a_count_written_part_way_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, stop_at(FRAME + END + 5, libc::EIO))?,
            lines(&[1, 2, 4]),
            "success an append after a count written part way reopens"
        );
        Ok(())
    }

    #[test]
    fn success_an_append_after_a_failed_second_sync_reopens() -> TestResult {
        assert_eq!(
            after_failure(Kind::Registry, sync_fails(1))?,
            lines(&[1, 2, 4]),
            "success an append after a failed second sync reopens"
        );
        Ok(())
    }

    #[test]
    fn success_the_intake_is_repaired_the_same_way() -> TestResult {
        assert_eq!(
            after_failure(Kind::Intake, stop_at(FRAME - 1, libc::ENOSPC))?,
            lines(&[1, 2, 4]),
            "success the intake is repaired the same way"
        );
        Ok(())
    }

    #[test]
    fn success_the_append_after_a_failure_writes_under_a_new_data_key() -> TestResult {
        let mut f = log()?;
        let before = file_id(&f.path)?;
        fail(&mut f, stop_at(10, libc::ENOSPC))?;
        f.log.append(&lines(&[4]))?;
        assert_ne!(
            file_id(&f.path)?,
            before,
            "success the append after a failure writes under a new data key"
        );
        Ok(())
    }

    #[test]
    fn success_a_failed_append_of_several_records_leaves_none_of_them() -> TestResult {
        let mut f = log()?;
        f.log.open_with(stop_at(2 * FRAME + 4, libc::ENOSPC));
        let failed = f.log.append(&lines(&[3, 4, 5]));
        assert!(failed.is_err(), "the append of three records fails");
        f.log.open_with(real());
        f.log.append(&lines(&[6]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 6]),
            "success a failed append of several records leaves none of them"
        );
        Ok(())
    }

    #[test]
    fn success_appends_of_several_records_survive_a_later_failure() -> TestResult {
        let mut f = log()?;
        f.log.append(&lines(&[10, 11, 12]))?;
        fail(&mut f, sync_fails(0))?;
        f.log.append(&lines(&[4]))?;
        f.log.append(&lines(&[5, 6]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 10, 11, 12, 4, 5, 6]),
            "success appends of several records survive a later failure"
        );
        Ok(())
    }

    #[test]
    fn success_held_counts_the_appends_that_succeeded() -> TestResult {
        let mut f = log()?;
        f.log.append(&lines(&[10, 11]))?;
        fail(&mut f, sync_fails(1))?;
        assert_eq!(f.log.held(), 4, "a failed append is not held");
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            f.log.held(),
            5,
            "success held counts the appends that succeeded"
        );
        Ok(())
    }

    #[test]
    fn success_a_rewrite_after_a_failed_append_needs_no_second_one() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(10, libc::ENOSPC))?;
        f.log.rewrite(lines(&[7, 8]).into_iter().map(Ok))?;
        let rewritten = file_id(&f.path)?;
        f.log.append(&lines(&[9]))?;
        assert_eq!(
            file_id(&f.path)?,
            rewritten,
            "the append after the rewrite goes to the file the rewrite wrote"
        );
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[7, 8, 9]),
            "success a rewrite after a failed append needs no second one"
        );
        Ok(())
    }

    #[test]
    fn success_held_lines_leave_out_what_a_failed_append_wrote() -> TestResult {
        let mut f = log()?;
        // The second sync failed: record 3 is whole in the file and
        // counted, and was never acknowledged.
        fail(&mut f, sync_fails(1))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 3]),
            "the failed append left its record in the file"
        );
        assert_eq!(
            f.log.held_lines()?,
            lines(&[1, 2]),
            "success held lines leave out what a failed append wrote"
        );
        Ok(())
    }

    #[test]
    fn success_a_trim_shaped_rewrite_after_a_failure_keeps_the_held_records() -> TestResult {
        let mut f = log()?;
        fail(&mut f, sync_fails(1))?;
        let held = f.log.held_lines()?;
        f.log.rewrite(held[1..].iter().cloned().map(Ok))?;
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[2, 4]),
            "success a trim shaped rewrite after a failure keeps the held records"
        );
        Ok(())
    }

    #[test]
    fn failure_a_failed_append_returns_the_error_of_the_disk() -> TestResult {
        let mut f = log()?;
        let e = fail(&mut f, stop_at(10, libc::ENOSPC))?;
        assert_eq!(
            e.raw_os_error(),
            Some(libc::ENOSPC),
            "failure a failed append returns the error of the disk"
        );
        Ok(())
    }

    #[test]
    fn failure_an_append_fails_while_the_file_is_away_and_works_when_it_is_back() -> TestResult {
        let mut f = log()?;
        let away = f.path.with_extension("away");
        std::fs::rename(&f.path, &away)?;
        for n in [3, 4] {
            assert_eq!(
                f.log.append(&lines(&[n])).map_err(|e| e.kind()),
                Err(std::io::ErrorKind::NotFound),
                "the append of record {n} fails while the file is away"
            );
        }
        std::fs::rename(&away, &f.path)?;
        f.log.append(&lines(&[5]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 5]),
            "failure an append fails while the file is away and works when it is back"
        );
        Ok(())
    }

    #[test]
    fn failure_a_repair_that_cannot_write_fails_the_append_and_the_next_repairs() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(10, libc::ENOSPC))?;
        // The rewrite stages its file at this name; a directory there
        // makes it fail.
        let staged = f.path.with_file_name(".center.store.partial");
        std::fs::create_dir(&staged)?;
        let torn = std::fs::read(&f.path)?;
        assert!(
            f.log.append(&lines(&[4])).is_err(),
            "the append fails while the file cannot be written again"
        );
        assert_eq!(
            std::fs::read(&f.path)?,
            torn,
            "nothing was appended to the file that was not repaired"
        );
        std::fs::remove_dir(&staged)?;
        f.log.append(&lines(&[5]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 5]),
            "failure a repair that cannot write fails the append and the next repairs"
        );
        Ok(())
    }

    #[test]
    fn failure_an_earlier_copy_put_back_after_a_failure_is_refused() -> TestResult {
        let mut f = log()?;
        let earlier = std::fs::read(&f.path)?;
        f.log.append(&lines(&[10]))?;
        fail(&mut f, refuse(libc::EIO))?;
        std::fs::write(&f.path, &earlier)?;
        let e = f.log.append(&lines(&[4])).err().ok_or("an error")?;
        assert_eq!(
            e.to_string(),
            "sealed layer: the file holds 2 record(s) where 3 were written; it was changed \
             while the center ran",
            "failure an earlier copy put back after a failure is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_cut_after_a_failure_is_refused() -> TestResult {
        let mut f = log()?;
        f.log.append(&lines(&[10]))?;
        fail(&mut f, refuse(libc::EIO))?;
        let bytes = std::fs::read(&f.path)?;
        std::fs::write(&f.path, &bytes[..bytes.len() - FRAME - END])?;
        let e = f.log.append(&lines(&[4])).err().ok_or("an error")?;
        assert!(
            e.to_string().contains("was cut at its end"),
            "failure a file cut after a failure is refused: {e}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_modified_after_a_failure_is_refused_and_left() -> TestResult {
        let mut f = log()?;
        fail(&mut f, refuse(libc::EIO))?;
        let mut bytes = std::fs::read(&f.path)?;
        let at = bytes.len() - END - 3;
        bytes[at] ^= 1;
        std::fs::write(&f.path, &bytes)?;
        let e = f.log.append(&lines(&[4])).err().ok_or("an error")?;
        assert!(
            e.to_string().contains("did not authenticate"),
            "a modified file is refused: {e}"
        );
        assert_eq!(
            std::fs::read(&f.path)?,
            bytes,
            "failure a file modified after a failure is refused and left"
        );
        Ok(())
    }

    #[test]
    fn failure_every_append_fails_while_the_disk_stays_full() -> TestResult {
        let mut f = log()?;
        f.log.open_with(stop_at(FRAME / 2, libc::ENOSPC));
        for n in [3, 4, 5] {
            assert_eq!(
                f.log.append(&lines(&[n])).map_err(|e| e.raw_os_error()),
                Err(Some(libc::ENOSPC)),
                "the append of record {n} fails on the full disk"
            );
        }
        f.log.open_with(real());
        f.log.append(&lines(&[6]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 6]),
            "failure every append fails while the disk stays full"
        );
        Ok(())
    }

    #[test]
    fn failure_a_record_over_the_limit_fails_and_leaves_the_file() -> TestResult {
        let mut f = log()?;
        let before = std::fs::read(&f.path)?;
        let e = f
            .log
            .append(&[vec![0u8; MAX_RECORD_BYTES + 1]])
            .err()
            .ok_or("an error")?;
        assert!(
            e.to_string().contains("is over"),
            "the record is refused: {e}"
        );
        assert_eq!(
            std::fs::read(&f.path)?,
            before,
            "failure a record over the limit fails and leaves the file"
        );
        Ok(())
    }

    #[test]
    fn failure_a_batch_refused_at_its_second_record_leaves_a_log_that_reopens() -> TestResult {
        let mut f = log()?;
        let batch = [line(3), vec![0u8; MAX_RECORD_BYTES + 1]];
        assert!(f.log.append(&batch).is_err(), "the batch is refused");
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 4]),
            "failure a batch refused at its second record leaves a log that reopens"
        );
        Ok(())
    }

    #[test]
    fn failure_a_write_that_takes_no_bytes_fails_the_append() -> TestResult {
        let mut f = log()?;
        let e = fail(&mut f, zero_write(FRAME))?;
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::WriteZero,
            "a write of no bytes is an error"
        );
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 4]),
            "failure a write that takes no bytes fails the append"
        );
        Ok(())
    }

    #[test]
    fn failure_a_failed_sync_returns_an_input_output_error() -> TestResult {
        let mut f = log()?;
        for (syncs, which) in [(0, "first"), (1, "second")] {
            let e = fail(&mut f, sync_fails(syncs))?;
            assert_eq!(
                e.raw_os_error(),
                Some(libc::EIO),
                "failure a failed {which} sync returns an input/output error"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_held_lines_of_a_file_that_is_away_is_an_error() -> TestResult {
        let f = log()?;
        std::fs::remove_file(&f.path)?;
        assert_eq!(
            f.log.held_lines().map_err(|e| e.kind()),
            Err(std::io::ErrorKind::NotFound),
            "failure held lines of a file that is away is an error"
        );
        Ok(())
    }

    #[test]
    fn failure_an_append_to_a_file_that_was_removed_does_not_create_it() -> TestResult {
        let mut f = log()?;
        std::fs::remove_file(&f.path)?;
        for n in [3, 4] {
            assert!(
                f.log.append(&lines(&[n])).is_err(),
                "the append of record {n} fails"
            );
        }
        assert!(
            !f.path.exists(),
            "failure an append to a file that was removed does not create it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_failed_append_leaves_held_as_it_was() -> TestResult {
        let mut f = log()?;
        for open in [
            refuse(libc::EACCES),
            stop_at(1, libc::ENOSPC),
            sync_fails(0),
            sync_fails(1),
        ] {
            fail(&mut f, open)?;
            assert_eq!(
                f.log.held(),
                2,
                "failure a failed append leaves held as it was"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_a_failed_rewrite_leaves_the_log_appending_to_its_file() -> TestResult {
        let mut f = log()?;
        let failed = f
            .log
            .rewrite(std::iter::once(Err(std::io::Error::other("no record"))));
        assert!(failed.is_err(), "the rewrite fails");
        f.log.append(&lines(&[3]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 3]),
            "failure a failed rewrite leaves the log appending to its file"
        );
        Ok(())
    }

    #[test]
    fn edge_an_empty_append_after_a_failure_writes_nothing() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(10, libc::ENOSPC))?;
        let torn = std::fs::read(&f.path)?;
        f.log.append(&[])?;
        assert_eq!(
            std::fs::read(&f.path)?,
            torn,
            "edge an empty append after a failure writes nothing"
        );
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 4]),
            "the next append with a record repairs the file"
        );
        Ok(())
    }

    #[test]
    fn edge_two_failures_in_a_row_then_an_append_that_works() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(FRAME + END + 1, libc::EIO))?;
        fail(&mut f, stop_at(3, libc::ENOSPC))?;
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 4]),
            "edge two failures in a row then an append that works"
        );
        Ok(())
    }

    #[test]
    fn edge_a_failure_on_a_log_with_no_records_reopens() -> TestResult {
        let mut f = log_of(Kind::Intake, &[])?;
        fail(&mut f, stop_at(FRAME, libc::ENOSPC))?;
        assert_eq!(f.log.held(), 0, "the log holds no record");
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Intake)?,
            lines(&[4]),
            "edge a failure on a log with no records reopens"
        );
        Ok(())
    }

    #[test]
    fn edge_a_failure_at_every_byte_of_an_append_is_repaired() -> TestResult {
        // Every point a write can stop at: in the record, in the end of
        // the append, between them and the count, and in the count.
        for bytes in 0..FRAME + END + COUNT {
            assert_eq!(
                after_failure(Kind::Registry, stop_at(bytes, libc::ENOSPC))?,
                lines(&[1, 2, 4]),
                "edge a failure after {bytes} byte(s) of an append is repaired"
            );
        }
        Ok(())
    }

    #[test]
    fn edge_a_center_stopped_after_a_failure_at_any_byte_starts_again() -> TestResult {
        // No append follows the failure: the file is what the next start
        // finds. It opens, and holds the records written before, first.
        for bytes in 0..FRAME + END + COUNT {
            let mut f = log()?;
            fail(&mut f, stop_at(bytes, libc::EIO))?;
            let found = on_disk(&f.path, Kind::Registry)?;
            assert_eq!(
                found.get(..2),
                Some(lines(&[1, 2]).as_slice()),
                "edge a center stopped after a failure at byte {bytes} starts again"
            );
        }
        Ok(())
    }

    #[test]
    fn edge_a_failure_that_wrote_nothing_still_moves_to_a_new_data_key() -> TestResult {
        let mut f = log()?;
        let before = std::fs::read(&f.path)?;
        fail(&mut f, refuse(libc::EACCES))?;
        assert_eq!(std::fs::read(&f.path)?, before, "the failure wrote nothing");
        f.log.append(&lines(&[4]))?;
        assert_ne!(
            file_id(&f.path)?,
            before[14..30],
            "edge a failure that wrote nothing still moves to a new data key"
        );
        Ok(())
    }

    #[test]
    fn edge_a_rewrite_to_no_records_after_a_failure_takes_appends() -> TestResult {
        let mut f = log()?;
        fail(&mut f, sync_fails(0))?;
        f.log.rewrite(std::iter::empty())?;
        assert_eq!(f.log.held(), 0, "the rewrite holds no record");
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[4]),
            "edge a rewrite to no records after a failure takes appends"
        );
        Ok(())
    }

    #[test]
    fn edge_an_interrupted_write_one_byte_at_a_time_is_not_a_failure() -> TestResult {
        let mut f = log()?;
        let before = file_id(&f.path)?;
        f.log.open_with(slow());
        f.log.append(&lines(&[3]))?;
        f.log.open_with(real());
        f.log.append(&lines(&[4]))?;
        assert_eq!(file_id(&f.path)?, before, "the file was not written again");
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 3, 4]),
            "edge an interrupted write one byte at a time is not a failure"
        );
        Ok(())
    }

    #[test]
    fn edge_appends_that_work_never_write_the_file_again() -> TestResult {
        let mut f = log()?;
        let before = file_id(&f.path)?;
        for n in 3..9 {
            f.log.append(&lines(&[n]))?;
        }
        assert_eq!(
            file_id(&f.path)?,
            before,
            "edge appends that work never write the file again"
        );
        Ok(())
    }

    #[test]
    fn edge_the_largest_record_cut_part_way_is_repaired() -> TestResult {
        let mut f = log()?;
        f.log.open_with(stop_at(MAX_RECORD_BYTES / 2, libc::ENOSPC));
        assert!(
            f.log.append(&[vec![7u8; MAX_RECORD_BYTES]]).is_err(),
            "the append of the largest record fails"
        );
        f.log.open_with(real());
        f.log.append(&lines(&[4]))?;
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 4]),
            "edge the largest record cut part way is repaired"
        );
        Ok(())
    }

    #[test]
    fn edge_held_lines_of_a_log_that_never_failed_are_all_its_records() -> TestResult {
        let mut f = log()?;
        f.log.append(&lines(&[3, 4]))?;
        assert_eq!(
            f.log.held_lines()?,
            lines(&[1, 2, 3, 4]),
            "edge held lines of a log that never failed are all its records"
        );
        Ok(())
    }

    #[test]
    fn edge_a_failure_right_after_a_repair_is_repaired_too() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(5, libc::ENOSPC))?;
        f.log.append(&lines(&[4]))?;
        let repaired = file_id(&f.path)?;
        fail(&mut f, sync_fails(0))?;
        f.log.append(&lines(&[5]))?;
        assert_ne!(
            file_id(&f.path)?,
            repaired,
            "the second repair has its own key"
        );
        assert_eq!(
            on_disk(&f.path, Kind::Registry)?,
            lines(&[1, 2, 4, 5]),
            "edge a failure right after a repair is repaired too"
        );
        Ok(())
    }

    #[test]
    fn edge_the_repaired_file_has_no_partial_file_beside_it() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(10, libc::ENOSPC))?;
        f.log.append(&lines(&[4]))?;
        let names: Vec<String> = std::fs::read_dir(f.path.parent().ok_or("a directory")?)?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            ["center.store"],
            "edge the repaired file has no partial file beside it"
        );
        Ok(())
    }

    #[test]
    fn edge_a_failed_first_sync_leaves_the_counts_as_they_were() -> TestResult {
        // The count is written only once the records are on disk: when the
        // sync of the records fails, no count says the file holds them.
        let header = crate::app::fleet_seal::HEADER_BYTES;
        let mut f = log()?;
        let before = std::fs::read(&f.path)?;
        fail(&mut f, sync_fails(0))?;
        let after = std::fs::read(&f.path)?;
        assert_eq!(
            after.len(),
            before.len() + FRAME + END,
            "the records were written"
        );
        assert_eq!(
            after[..header],
            before[..header],
            "edge a failed first sync leaves the counts as they were"
        );
        Ok(())
    }

    #[test]
    fn edge_a_repaired_file_is_private() -> TestResult {
        let mut f = log()?;
        fail(&mut f, stop_at(10, libc::ENOSPC))?;
        f.log.append(&lines(&[4]))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(
                std::fs::metadata(&f.path)?.mode() & 0o777,
                0o600,
                "edge a repaired file is private"
            );
        }
        Ok(())
    }
}
