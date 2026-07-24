// SPDX-License-Identifier: MIT OR Apache-2.0

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

    // Atomic replace. `persist` maps to rename(2): if `path` exists it is
    // atomically replaced; readers see either the old or the new file, never
    // a partial one.
    tmp.persist(path).map_err(|e| e.error)?;

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

    /// A successful write to a previously nonexistent path creates the file
    /// with exactly the written contents.
    #[test]
    fn writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_atomic(&path, |w| w.write_all(b"hello")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    /// A successful write over an existing file fully replaces the old
    /// contents with the new ones.
    #[test]
    fn replaces_existing_file_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"old contents").unwrap();
        write_atomic(&path, |w| w.write_all(b"new")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    /// A mid-write failure must leave the original file byte-identical and
    /// leave no `.sipnab-tmp-*` litter in the directory.
    #[test]
    fn failure_leaves_original_intact_and_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"original").unwrap();

        // The writer fails partway; the original must be untouched.
        let err = write_atomic(&path, |w| {
            w.write_all(b"partial")?;
            Err(io::Error::other("boom"))
        });
        assert!(err.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");

        // No leftover temp files in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".sipnab-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {leftovers:?}");
    }

    /// The writer handed to the closure must be buffered: a small write must
    /// not land in the temp file immediately (an unbuffered `File` writes
    /// through to disk on every call, one syscall per write).
    #[test]
    fn closure_writer_is_buffered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        let dir_path = dir.path().to_path_buf();
        write_atomic(&path, |w| {
            w.write_all(b"tiny")?;
            // With an unbuffered File these 4 bytes are already in the temp
            // file; a buffered writer holds them until flush.
            let tmp_bytes_on_disk: u64 = std::fs::read_dir(&dir_path)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with(".sipnab-tmp-"))
                .map(|e| e.metadata().unwrap().len())
                .sum();
            assert_eq!(
                tmp_bytes_on_disk, 0,
                "small writes must be buffered, not written through per call"
            );
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"tiny");
    }

    /// Byte-at-a-time writes spanning several buffer fills (and ending with a
    /// partial buffer) must all land in the final file — i.e. the buffer is
    /// flushed before the fsync + rename.
    #[test]
    fn buffered_contents_are_flushed_before_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        // > 8 KiB (the default BufWriter capacity) and not a multiple of it.
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        write_atomic(&path, |w| {
            for b in &data {
                w.write_all(std::slice::from_ref(b))?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    /// A failed write to a path that never existed must not create the
    /// target file at all.
    #[test]
    fn failure_when_target_is_new_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never.bin");
        let err = write_atomic(&path, |_w| Err(io::Error::other("nope")));
        assert!(err.is_err());
        assert!(
            !path.exists(),
            "target should not exist after a failed write"
        );
    }
}
