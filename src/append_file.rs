// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The rotation rule of sipnab's append-only outputs.
//!
//! The audit files (`--mcp-audit-file`, `--tui-audit-file`, through
//! `app::audit::AuditSink`) and `--evidence-out PATH`
//! (`security::evidence::EvidenceSink`) are opened once and appended to for
//! the whole run. Log rotation renames the file away (logrotate's default
//! `create` mode) or removes it while sipnab holds it open. Without this rule
//! every later record went into the renamed or unlinked file, so the file at
//! the configured path stayed empty and a removed file kept growing on disk
//! where no one could see it.
//!
//! Before each record, the writer asks [`reopen_if_moved`] whether the path
//! still names the open file, and reopens it when it does not. One rule in
//! one place, so the three outputs cannot drift apart.

use std::path::Path;

/// Whether `path` no longer names the file `open` refers to: the path was
/// renamed away or removed (log rotation), or now names another file.
///
/// Compares the device and inode of the open file with those of the path.
/// A path that cannot be read for any reason other than "not found" counts
/// as not moved: the open file is still the best place for the record, and
/// a write to it reports its own error.
///
/// Off Unix there is no inode to compare, and this is always `false`.
#[must_use]
pub fn path_moved(open: &std::fs::File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(held) = open.metadata() else {
            return false;
        };
        match std::fs::metadata(path) {
            Ok(now) => (now.dev(), now.ino()) != (held.dev(), held.ino()),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (open, path);
        false
    }
}

/// Reopen `path` into `file` with `open` when [`path_moved`] says the path
/// no longer names it. Returns whether it reopened.
///
/// # Errors
///
/// When the reopen fails (the directory is gone, the path is a directory,
/// permission denied), with the path named. `file` is left as it was.
///
/// # Side effects
///
/// One `stat(2)` of the path and one `fstat(2)` of the file; on a reopen,
/// opens (and may create) the file and logs one line naming the path.
pub fn reopen_if_moved(
    file: &mut std::fs::File,
    path: &Path,
    open: impl FnOnce(&Path) -> std::io::Result<std::fs::File>,
) -> std::io::Result<bool> {
    if !path_moved(file, path) {
        return Ok(false);
    }
    let fresh = open(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "{}: the file was rotated away and cannot be opened again: {e}",
                path.display()
            ),
        )
    })?;
    *file = fresh;
    tracing::info!("reopened {} after rotation", path.display());
    Ok(true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    type TestError = Box<dyn std::error::Error>;

    /// (device, inode) of an open file.
    fn id(f: &std::fs::File) -> Result<(u64, u64), TestError> {
        let m = f.metadata()?;
        Ok((m.dev(), m.ino()))
    }

    /// An append handle on `path`, creating it.
    fn append(path: &Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }

    /// EDGE: an unmoved file is left alone and the opener is never called,
    /// so a run without rotation pays no open per record.
    #[test]
    fn an_unmoved_file_is_left_alone() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("f");
        let mut file = append(&path)?;
        let before = id(&file)?;
        let mut called = false;
        let reopened = reopen_if_moved(&mut file, &path, |p| {
            called = true;
            append(p)
        })?;
        assert!(!reopened, "nothing moved, so nothing reopened");
        assert!(!called, "the opener must not run for an unmoved file");
        assert_eq!(id(&file)?, before, "the same file is still held");
        Ok(())
    }

    /// SUCCESS: a moved file is replaced by the file now at the path.
    #[test]
    fn a_moved_file_is_replaced_by_the_one_at_the_path() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("f");
        let mut file = append(&path)?;
        std::fs::rename(&path, dir.path().join("f.1"))?;
        assert!(reopen_if_moved(&mut file, &path, append)?, "it reopened");
        let at_path = std::fs::metadata(&path)?;
        assert_eq!(
            id(&file)?,
            (at_path.dev(), at_path.ino()),
            "the held file is now the one at the path"
        );
        Ok(())
    }

    /// FAILURE: a reopen that fails names the path and keeps the old file.
    #[test]
    fn a_failed_reopen_names_the_path_and_keeps_the_old_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("f");
        let mut file = append(&path)?;
        let before = id(&file)?;
        std::fs::remove_file(&path)?;
        let err = reopen_if_moved(&mut file, &path, |_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .err()
        .ok_or("a failed open must be an error")?;
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the open's own error kind is kept"
        );
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "the error names the path: {err}"
        );
        assert_eq!(id(&file)?, before, "the old file is still held");
        Ok(())
    }
}
