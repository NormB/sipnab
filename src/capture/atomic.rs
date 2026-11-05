// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Atomic file writes — the Wireshark "safe save" pattern.
//!
//! Write to a temporary file in the *destination directory*, fsync it, then
//! rename it over the target. A failed or partial write (e.g. `ENOSPC`) never
//! corrupts an existing file: the original is replaced only after the new
//! contents are fully and durably written. The temp file must be on the same
//! filesystem as the target (a cross-filesystem rename is `EXDEV`), which is
//! why it is created in the target's own directory.

use std::io::{self, Write};
use std::path::Path;

/// Write `path` atomically. `write` is handed a writer for a fresh temp file in
/// the same directory; on success the temp is fsync'd and renamed over `path`,
/// and the directory is fsync'd for crash durability. On any error from `write`
/// (or the fsync/rename) the temp file is removed and `path` is left untouched.
///
/// # Arguments
///
/// * `path` — final destination file; replaced atomically on success. A bare
///   filename (no parent directory) is treated as relative to `.`.
/// * `write` — closure that produces the new contents by writing to the
///   supplied writer. The writer is internally buffered ([`io::BufWriter`])
///   and flushed before the fsync, so the closure may make many small writes
///   without paying one syscall each.
///
/// # Errors
///
/// Returns any `io::Error` from creating the temp file, from the `write`
/// closure itself, from fsyncing the temp file, or from the rename. In every
/// error case the partial temp file is removed and `path` keeps its previous
/// contents (or remains absent).
///
/// # Side effects
///
/// Filesystem I/O: creates a `.sipnab-tmp-*` temp file in `path`'s directory,
/// fsyncs it, renames it over `path` (replacing any existing file), and
/// best-effort fsyncs the containing directory (that fsync's own error is
/// deliberately ignored).
pub fn write_atomic<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    write_via_temp(path, write, Publish::Replace)
}

/// Write `path` atomically, only if nothing is there yet: [`write_atomic`]
/// for a file that must never replace another, such as the `--redact-map`
/// that may be the only way back from tokens already sent. The temp file is
/// created owner-only (0600 on Unix, `tempfile`'s default) and published by
/// a rename that fails if the name is taken (`renameat2` with
/// `RENAME_NOREPLACE` on Linux and macOS, a hard link then an unlink where
/// that is not supported), so there is no window between checking the name
/// and taking it, and a reader sees the whole file or none.
///
/// # Errors
///
/// As [`write_atomic`], and `AlreadyExists` when anything is at `path`. In
/// every error case the temp file is removed and nothing is left at `path`
/// that was not there before.
pub fn write_atomic_new<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    write_via_temp(path, write, Publish::NewOnly)
}

/// How a finished temp file takes its name.
#[derive(Clone, Copy)]
enum Publish {
    /// rename(2): replaces whatever is at the name.
    Replace,
    /// A rename that fails if the name is taken.
    NewOnly,
}

/// The one body both writers share: temp file in the destination directory,
/// buffered write, flush, fsync, publish, directory fsync.
fn write_via_temp<F>(path: &Path, write: F, publish: Publish) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => Path::new(".").to_path_buf(),
    };

    let mut tmp = tempfile::Builder::new()
        .prefix(".sipnab-tmp-")
        .tempfile_in(&dir)?;

    // Write the new contents through a buffer (small closure writes coalesce
    // instead of costing a syscall each); on any error — from the closure or
    // from the final flush (e.g. ENOSPC surfacing on buffered bytes) — the
    // NamedTempFile is dropped here, removing the partial file and leaving
    // `path` untouched.
    {
        let mut buffered = io::BufWriter::new(tmp.as_file_mut());
        write(&mut buffered)?;
        buffered.flush()?;
    }

    // Durable temp contents before the rename.
    tmp.as_file_mut().sync_all()?;

    match publish {
        // Atomic replace. `persist` maps to rename(2): if `path` exists it is
        // atomically replaced; readers see either the old or the new file,
        // never a partial one.
        Publish::Replace => tmp.persist(path).map_err(|e| e.error)?,
        // `persist_noclobber` renames without replacing (RENAME_NOREPLACE,
        // or link then unlink), so it fails if the name is taken. On failure
        // the temp is dropped, and so removed.
        Publish::NewOnly => tmp.persist_noclobber(path).map_err(|e| e.error)?,
    };

    // fsync the directory so the rename survives a crash.
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Tests for `write_atomic`: fresh-file creation, atomic replacement, and
/// the guarantee that a failed write leaves the target and directory clean.
#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A successful write to a previously nonexistent path creates the file
    /// with exactly the written contents.
    #[test]
    fn writes_new_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.bin");
        write_atomic(&path, |w| w.write_all(b"hello"))?;
        assert_eq!(std::fs::read(&path)?, b"hello");
        Ok(())
    }

    /// A successful write over an existing file fully replaces the old
    /// contents with the new ones.
    #[test]
    fn replaces_existing_file_on_success() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"old contents")?;
        write_atomic(&path, |w| w.write_all(b"new"))?;
        assert_eq!(std::fs::read(&path)?, b"new");
        Ok(())
    }

    /// A mid-write failure must leave the original file byte-identical and
    /// leave no `.sipnab-tmp-*` litter in the directory.
    #[test]
    fn failure_leaves_original_intact_and_no_temp() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"original")?;

        // The writer fails partway; the original must be untouched.
        let err = write_atomic(&path, |w| {
            w.write_all(b"partial")?;
            Err(io::Error::other("boom"))
        });
        assert!(err.is_err());
        assert_eq!(std::fs::read(&path)?, b"original");

        // No leftover temp files in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".sipnab-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {leftovers:?}");
        Ok(())
    }

    /// The writer handed to the closure must be buffered: a small write must
    /// not land in the temp file immediately (an unbuffered `File` writes
    /// through to disk on every call, one syscall per write).
    #[test]
    fn closure_writer_is_buffered() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.bin");
        let dir_path = dir.path().to_path_buf();
        write_atomic(&path, |w| {
            w.write_all(b"tiny")?;
            // With an unbuffered File these 4 bytes are already in the temp
            // file; a buffered writer holds them until flush.
            let tmp_bytes_on_disk: u64 = std::fs::read_dir(&dir_path)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with(".sipnab-tmp-"))
                .map(|e| e.metadata().map(|m| m.len()))
                .sum::<std::io::Result<u64>>()?;
            assert_eq!(
                tmp_bytes_on_disk, 0,
                "small writes must be buffered, not written through per call"
            );
            Ok(())
        })?;
        assert_eq!(std::fs::read(&path)?, b"tiny");
        Ok(())
    }

    /// Byte-at-a-time writes spanning several buffer fills (and ending with a
    /// partial buffer) must all land in the final file — i.e. the buffer is
    /// flushed before the fsync + rename.
    #[test]
    fn buffered_contents_are_flushed_before_rename() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.bin");
        // > 8 KiB (the default BufWriter capacity) and not a multiple of it.
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        write_atomic(&path, |w| {
            for b in &data {
                w.write_all(std::slice::from_ref(b))?;
            }
            Ok(())
        })?;
        assert_eq!(std::fs::read(&path)?, data);
        Ok(())
    }

    /// Names left in `dir` by a write that went through a temp file.
    fn temp_files(dir: &Path) -> Result<Vec<std::ffi::OsString>, TestError> {
        Ok(std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().starts_with(".sipnab-tmp-"))
            .collect())
    }

    /// `write_atomic_new` makes a file that did not exist, with exactly the
    /// written contents, readable and writable by its owner only.
    #[test]
    fn new_only_writes_a_new_file_whole_and_owner_only() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("map.tsv");
        write_atomic_new(&path, |w| w.write_all(b"a\tb\n"))?;
        assert_eq!(
            std::fs::read(&path)?,
            b"a\tb\n",
            "the file holds exactly what was written"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600,
                "the file is owner-only"
            );
        }
        assert!(temp_files(dir.path())?.is_empty(), "no temp file is left");
        Ok(())
    }

    /// Whatever is already at the path stays as it was: `write_atomic_new`
    /// never replaces a file, and says so with `AlreadyExists`.
    #[test]
    fn new_only_never_replaces_a_file_already_there() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("map.tsv");
        std::fs::write(&path, b"the only way back")?;
        let err = write_atomic_new(&path, |w| w.write_all(b"new"))
            .err()
            .ok_or("an existing file was replaced")?;
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "the refusal says the name is taken"
        );
        assert_eq!(
            std::fs::read(&path)?,
            b"the only way back",
            "the existing file is kept"
        );
        assert!(temp_files(dir.path())?.is_empty(), "temp file left behind");
        Ok(())
    }

    /// A write that fails part way leaves no file at the path and no temp
    /// file beside it: a reader never sees part of the contents.
    #[test]
    fn new_only_failure_leaves_neither_file_nor_temp() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("map.tsv");
        let err = write_atomic_new(&path, |w| {
            w.write_all(b"first row\n")?;
            Err(io::Error::other("disk full"))
        });
        assert!(err.is_err(), "a failed write is reported as an error");
        assert!(!path.exists(), "a partial file was published");
        assert!(temp_files(dir.path())?.is_empty(), "temp file left behind");
        Ok(())
    }

    /// A failed write to a path that never existed must not create the
    /// target file at all.
    #[test]
    fn failure_when_target_is_new_creates_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("never.bin");
        let err = write_atomic(&path, |_w| Err(io::Error::other("nope")));
        assert!(err.is_err());
        assert!(
            !path.exists(),
            "target should not exist after a failed write"
        );
        Ok(())
    }
}
