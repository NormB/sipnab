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

    // Write the new contents; on any error the NamedTempFile is dropped here,
    // removing the partial file and leaving `path` untouched.
    write(tmp.as_file_mut())?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_atomic(&path, |w| w.write_all(b"hello")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn replaces_existing_file_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"old contents").unwrap();
        write_atomic(&path, |w| w.write_all(b"new")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

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
