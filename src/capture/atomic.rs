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
///
/// On Unix, a regular file at `path` (or a symlink's final target) gives the
/// new file its permission bits, as a write in place would keep them, and,
/// where the process may set them, its owner and group; the umask does not
/// change them. A new file is owner-only: 0600, less what the umask removes.
pub fn write_atomic<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    write_via_temp(path, write, Publish::Replace)
}

/// Write `path` atomically, as [`write_atomic`], but always owner-only
/// (0600 on Unix): the mode of a file it replaces is not kept. For a file
/// whose contents decide its mode, such as the operator's notes about a
/// call, which may name a subscriber.
///
/// # Errors
///
/// As [`write_atomic`].
pub fn write_atomic_owner_only<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    write_via_temp(path, write, Publish::ReplaceOwnerOnly)
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
    /// rename(2): replaces whatever is at the name, keeping a regular
    /// file's mode (and, where it may, its owner and group).
    Replace,
    /// rename(2), the new file owner-only whatever was at the name.
    ReplaceOwnerOnly,
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

    // A replace keeps the replaced file's mode (and, where it may, its owner
    // and group): the temp file is owner-only, and without this every save
    // over a group-readable file made it 0600.
    #[cfg(unix)]
    if let Publish::Replace = publish
        && let Some(kept) = kept_attributes(path)
    {
        apply_kept(tmp.as_file(), kept);
    }

    match publish {
        // Atomic replace. `persist` maps to rename(2): if `path` exists it is
        // atomically replaced; readers see either the old or the new file,
        // never a partial one.
        Publish::Replace | Publish::ReplaceOwnerOnly => tmp.persist(path).map_err(|e| e.error)?,
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

/// What a replace keeps of the file it replaces.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Kept {
    /// The permission bits (`0o777`). The set-user-ID, set-group-ID and
    /// sticky bits are not carried: a save writes data, not a program.
    mode: u32,
    /// The owner and group, only when the name is the file itself, with
    /// one link: not through a symlink or from a hard-linked inode, whose
    /// owner the name's directory does not decide.
    owner: Option<(u32, u32)>,
}

/// The attributes a replace of `path` keeps: `None` when nothing regular is
/// there (a new name, a dangling symlink, a directory, a FIFO), so the new
/// file stays owner-only. A symlink gives its final target's mode.
#[cfg(unix)]
fn kept_attributes(path: &Path) -> Option<Kept> {
    use std::os::unix::fs::MetadataExt as _;
    let link = std::fs::symlink_metadata(path).ok()?;
    let is_link = link.file_type().is_symlink();
    let file = if is_link {
        std::fs::metadata(path).ok()?
    } else {
        link
    };
    if !file.is_file() {
        return None;
    }
    let owner = (!is_link && file.nlink() == 1).then(|| (file.uid(), file.gid()));
    Some(Kept {
        mode: file.mode() & 0o777,
        owner,
    })
}

/// Give the finished temp file `kept`'s owner, group and mode, before it is
/// renamed into place. Owner and group are set only where the process may:
/// an unprivileged process keeps its own owner and sets a group it belongs
/// to; a group it is not in leaves the temp file's group. Each step is best
/// effort: a filesystem that refuses one leaves the temp file owner-only,
/// stricter than the file it replaces, never looser.
#[cfg(unix)]
fn apply_kept(file: &std::fs::File, kept: Kept) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if let Some((uid, gid)) = kept.owner
        && let Ok(now) = file.metadata()
        && (now.uid(), now.gid()) != (uid, gid)
        && std::os::unix::fs::fchown(file, Some(uid), Some(gid)).is_err()
    {
        let _ = std::os::unix::fs::fchown(file, None, Some(gid));
    }
    // After the owner: a chown may clear mode bits.
    let _ = file.set_permissions(std::fs::Permissions::from_mode(kept.mode));
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

/// What a replace keeps of the file it replaces: its permission bits and,
/// where the process may set them, its owner and group. A new file is
/// owner-only (0600) whatever the umask.
#[cfg(all(test, unix))]
mod mode_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    type TestError = Box<dyn std::error::Error>;

    /// The environment variable that makes [`umask_child`] run, holding the
    /// umask in octal.
    const UMASK_CHILD: &str = "SIPNAB_TEST_ATOMIC_UMASK_CHILD";

    /// The permission bits of `path` itself (not of a symlink's target),
    /// and whether it is a regular file.
    fn own_mode(path: &Path) -> Result<(u32, bool), TestError> {
        let meta = std::fs::symlink_metadata(path)?;
        Ok((meta.mode() & 0o7777, meta.file_type().is_file()))
    }

    /// A file at `path` holding `old`, set to `mode`.
    fn file_with_mode(path: &Path, old: &[u8], mode: u32) -> Result<(), TestError> {
        std::fs::write(path, old)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    /// Replace a file of mode `mode` through [`write_atomic`]; the mode the
    /// regular file at the path has afterwards.
    fn mode_after_replace(mode: u32) -> Result<u32, TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", mode)?;
        write_atomic(&path, |w| w.write_all(b"new\n"))?;
        let (after, regular) = own_mode(&path)?;
        assert!(regular, "a regular file is at the path");
        assert_eq!(std::fs::read(&path)?, b"new\n", "the new contents");
        assert!(
            temp_files(dir.path())?.is_empty(),
            "no temp file is left beside it"
        );
        Ok(after)
    }

    /// Names left in `dir` by a write that went through a temp file.
    fn temp_files(dir: &Path) -> Result<Vec<std::ffi::OsString>, TestError> {
        Ok(std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().starts_with(".sipnab-tmp-"))
            .collect())
    }

    // ── success ────────────────────────────────────────────────────────

    /// An owner-only file stays owner-only.
    #[test]
    fn a_replaced_0600_file_keeps_0600() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o600)?, 0o600, "mode kept");
        Ok(())
    }

    /// A group-readable file stays group-readable.
    #[test]
    fn a_replaced_0640_file_keeps_0640() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o640)?, 0o640, "mode kept");
        Ok(())
    }

    /// A world-readable file stays world-readable.
    #[test]
    fn a_replaced_0644_file_keeps_0644() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o644)?, 0o644, "mode kept");
        Ok(())
    }

    /// The live case: a group-writable config stays group-writable.
    #[test]
    fn a_replaced_0664_file_keeps_0664() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o664)?, 0o664, "mode kept");
        Ok(())
    }

    /// A world-writable file keeps its mode: the bits the usual umask
    /// clears are set on the file, not through the umask.
    #[test]
    fn a_replaced_0666_file_keeps_0666() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o666)?, 0o666, "mode kept");
        Ok(())
    }

    /// A read-only file in a writable directory is replaced (this helper
    /// does not check writability; the config writer does) and stays
    /// read-only.
    #[test]
    fn a_replaced_0444_file_keeps_0444() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o444)?, 0o444, "mode kept");
        Ok(())
    }

    /// A file that did not exist is created owner-only.
    #[test]
    fn a_new_file_is_0600() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("new.toml");
        write_atomic(&path, |w| w.write_all(b"x"))?;
        assert_eq!(own_mode(&path)?, (0o600, true), "a regular owner-only file");
        Ok(())
    }

    /// A symlink is replaced by a regular file with the mode of the file
    /// the link pointed to; that file is unchanged.
    #[test]
    fn a_replaced_symlink_takes_its_targets_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("shared.toml");
        file_with_mode(&target, b"shared\n", 0o640)?;
        let link = dir.path().join("sipnab.toml");
        std::os::unix::fs::symlink(&target, &link)?;
        write_atomic(&link, |w| w.write_all(b"new\n"))?;
        assert_eq!(
            own_mode(&link)?,
            (0o640, true),
            "a regular file with the target's mode"
        );
        assert_eq!(std::fs::read(&target)?, b"shared\n", "target unchanged");
        assert_eq!(own_mode(&target)?.0, 0o640, "target mode unchanged");
        Ok(())
    }

    /// A second and third replace keep the mode the first kept.
    #[test]
    fn repeated_replaces_keep_the_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"0\n", 0o664)?;
        for round in 1..=3 {
            write_atomic(&path, |w| writeln!(w, "{round}"))?;
            assert_eq!(own_mode(&path)?.0, 0o664, "round {round}: mode kept");
        }
        Ok(())
    }

    /// The group of the replaced file is kept when the process belongs to
    /// it: set to a supplementary group of this process when it has one,
    /// else the file's group is the process's own, which is kept too.
    /// `apply_kept`'s group-only retry runs only when the file's owner is
    /// another user, which a test that is not root cannot create; it is
    /// not driven here.
    #[test]
    fn a_replaced_file_keeps_its_group() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", 0o640)?;
        if let Some(other) = other_group() {
            std::os::unix::fs::chown(&path, None, Some(other))?;
        }
        let before = std::fs::metadata(&path)?.gid();
        write_atomic(&path, |w| w.write_all(b"new\n"))?;
        assert_eq!(std::fs::metadata(&path)?.gid(), before, "group kept");
        let fresh = dir.path().join("fresh.toml");
        std::fs::write(&fresh, b"x")?;
        assert_eq!(
            std::fs::metadata(&path)?.uid(),
            std::fs::metadata(&fresh)?.uid(),
            "owner kept (the process's own)"
        );
        Ok(())
    }

    /// A file of a mode the usual umask (0002 or 0022) would not give a
    /// new file is kept, and a new file is 0600, under every umask that
    /// leaves the owner read and write; each in a child process of its own,
    /// since the umask is per process.
    #[test]
    fn the_mode_does_not_depend_on_the_umask() -> Result<(), TestError> {
        for umask in ["000", "002", "022", "027", "077"] {
            run_umask_child(umask)?;
        }
        Ok(())
    }

    /// Run [`umask_child`] in a new process, in a process group of its own,
    /// with `umask` in [`UMASK_CHILD`]; killed at a deadline. It must run
    /// exactly one test and pass.
    fn run_umask_child(umask: &str) -> Result<(), TestError> {
        use std::io::Read as _;
        use std::os::unix::process::CommandExt as _;
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, module)| module);
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &format!("{module}::umask_child")])
            .args(["--ignored", "--nocapture", "--test-threads=1"])
            .env(UMASK_CHILD, umask)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err(format!("umask {umask}: the child passed its 60 s deadline").into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let mut said = String::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_string(&mut said)?;
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut said)?;
        }
        assert!(status.success(), "umask {umask}: the child failed:\n{said}");
        assert!(
            said.contains("1 passed"),
            "umask {umask}: the child ran no test:\n{said}"
        );
        Ok(())
    }

    /// The child of [`the_mode_does_not_depend_on_the_umask`]: sets the
    /// umask it is given, then replaces a 0664 and a 0640 file and creates
    /// a new one.
    #[test]
    #[ignore = "a child process of the_mode_does_not_depend_on_the_umask; it runs it"]
    fn umask_child() -> Result<(), TestError> {
        let Some(umask) = std::env::var_os(UMASK_CHILD) else {
            return Ok(());
        };
        let umask = u32::from_str_radix(&umask.to_string_lossy(), 8)?;
        // SAFETY: umask has no preconditions; this process runs this one
        // test only (--exact, --test-threads=1).
        unsafe { libc::umask(umask as libc::mode_t) };
        assert_eq!(
            mode_after_replace(0o664)?,
            0o664,
            "umask {umask:o}: 0664 kept"
        );
        assert_eq!(
            mode_after_replace(0o640)?,
            0o640,
            "umask {umask:o}: 0640 kept"
        );
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("new.toml");
        write_atomic(&path, |w| w.write_all(b"x"))?;
        assert_eq!(
            own_mode(&path)?.0,
            0o600,
            "umask {umask:o}: a new file is 0600"
        );
        Ok(())
    }

    // ── failure ────────────────────────────────────────────────────────

    /// A write that fails leaves the file it would replace as it was:
    /// contents, mode and no temp file.
    #[test]
    fn a_failed_replace_leaves_contents_and_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", 0o664)?;
        let err = write_atomic(&path, |w| {
            w.write_all(b"part")?;
            Err(io::Error::other("disk full"))
        });
        assert!(err.is_err(), "the failure is reported");
        assert_eq!(std::fs::read(&path)?, b"old\n", "contents unchanged");
        assert_eq!(own_mode(&path)?, (0o664, true), "mode unchanged");
        assert!(temp_files(dir.path())?.is_empty(), "no temp file");
        Ok(())
    }

    /// A directory at the path is not replaced, and keeps its mode.
    #[test]
    fn a_directory_at_the_path_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750))?;
        let err = write_atomic(&path, |w| w.write_all(b"new\n"));
        assert!(err.is_err(), "a directory is not replaced");
        let meta = std::fs::symlink_metadata(&path)?;
        assert!(meta.is_dir(), "still a directory");
        assert_eq!(meta.mode() & 0o777, 0o750, "its mode unchanged");
        assert!(temp_files(dir.path())?.is_empty(), "no temp file");
        Ok(())
    }

    /// A failed write over a symlink leaves the link and its target as
    /// they were.
    #[test]
    fn a_failed_replace_of_a_symlink_leaves_both() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("shared.toml");
        file_with_mode(&target, b"shared\n", 0o644)?;
        let link = dir.path().join("sipnab.toml");
        std::os::unix::fs::symlink(&target, &link)?;
        let err = write_atomic(&link, |_| Err(io::Error::other("no")));
        assert!(err.is_err(), "the failure is reported");
        assert!(
            std::fs::symlink_metadata(&link)?.file_type().is_symlink(),
            "still a link"
        );
        assert_eq!(own_mode(&target)?, (0o644, true), "target mode unchanged");
        assert_eq!(std::fs::read(&target)?, b"shared\n", "target unchanged");
        Ok(())
    }

    /// `write_atomic_owner_only` replaces a group-readable file with an
    /// owner-only one, whatever mode the old file had.
    #[test]
    fn owner_only_replaces_with_0600() -> Result<(), TestError> {
        for mode in [0o600, 0o640, 0o644, 0o664, 0o666] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("notes.jsonl");
            file_with_mode(&path, b"old\n", mode)?;
            write_atomic_owner_only(&path, |w| w.write_all(b"new\n"))?;
            assert_eq!(own_mode(&path)?, (0o600, true), "{mode:o} became 0600");
            assert_eq!(std::fs::read(&path)?, b"new\n", "{mode:o}: new contents");
        }
        Ok(())
    }

    /// A failed owner-only write leaves the old file, mode and all.
    #[test]
    fn a_failed_owner_only_replace_leaves_the_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("notes.jsonl");
        file_with_mode(&path, b"old\n", 0o644)?;
        let err = write_atomic_owner_only(&path, |_| Err(io::Error::other("no")));
        assert!(err.is_err(), "the failure is reported");
        assert_eq!(own_mode(&path)?, (0o644, true), "mode unchanged");
        assert_eq!(std::fs::read(&path)?, b"old\n", "contents unchanged");
        assert!(temp_files(dir.path())?.is_empty(), "no temp file");
        Ok(())
    }

    /// `write_atomic_new` never takes a mode from anything: it refuses a
    /// name that is taken, and a new file is 0600.
    #[test]
    fn new_only_keeps_no_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("map.tsv");
        file_with_mode(&path, b"keep\n", 0o664)?;
        let err = write_atomic_new(&path, |w| w.write_all(b"new"));
        assert!(err.is_err(), "the name is taken");
        assert_eq!(own_mode(&path)?, (0o664, true), "the file is unchanged");
        let fresh = dir.path().join("fresh.tsv");
        write_atomic_new(&fresh, |w| w.write_all(b"new"))?;
        assert_eq!(own_mode(&fresh)?.0, 0o600, "a new file is owner-only");
        Ok(())
    }

    // ── edge ───────────────────────────────────────────────────────────

    /// The set-user-ID, set-group-ID and sticky bits are not carried to
    /// the new file: only the permission bits are.
    #[test]
    fn special_bits_are_not_carried() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o4755)?, 0o755, "set-user-ID dropped");
        assert_eq!(mode_after_replace(0o2664)?, 0o664, "set-group-ID dropped");
        assert_eq!(mode_after_replace(0o1644)?, 0o644, "sticky dropped");
        Ok(())
    }

    /// An executable file stays executable.
    #[test]
    fn an_executable_file_keeps_its_execute_bits() -> Result<(), TestError> {
        assert_eq!(mode_after_replace(0o750)?, 0o750, "mode kept");
        Ok(())
    }

    /// A write-only file (no read bit) keeps its mode.
    #[test]
    fn a_write_only_file_keeps_its_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", 0o200)?;
        write_atomic(&path, |w| w.write_all(b"new\n"))?;
        assert_eq!(own_mode(&path)?, (0o200, true), "mode kept");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(std::fs::read(&path)?, b"new\n", "the new contents");
        Ok(())
    }

    /// A symlink to a symlink to a file takes the final file's mode.
    #[test]
    fn a_symlink_chain_takes_the_final_files_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("real.toml");
        file_with_mode(&target, b"real\n", 0o660)?;
        let middle = dir.path().join("middle.toml");
        std::os::unix::fs::symlink(&target, &middle)?;
        let link = dir.path().join("sipnab.toml");
        std::os::unix::fs::symlink(&middle, &link)?;
        write_atomic(&link, |w| w.write_all(b"new\n"))?;
        assert_eq!(own_mode(&link)?, (0o660, true), "the final file's mode");
        assert!(
            std::fs::symlink_metadata(&middle)?.file_type().is_symlink(),
            "the middle link is untouched"
        );
        Ok(())
    }

    /// A symlink to nothing is replaced by a new, owner-only file.
    #[test]
    fn a_dangling_symlink_gives_a_new_0600_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let link = dir.path().join("sipnab.toml");
        std::os::unix::fs::symlink(dir.path().join("gone.toml"), &link)?;
        write_atomic(&link, |w| w.write_all(b"new\n"))?;
        assert_eq!(own_mode(&link)?, (0o600, true), "a new owner-only file");
        Ok(())
    }

    /// A symlink to a directory is replaced by a new, owner-only file:
    /// a directory's mode is not a file's.
    #[test]
    fn a_symlink_to_a_directory_gives_a_new_0600_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub)?;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755))?;
        let link = dir.path().join("sipnab.toml");
        std::os::unix::fs::symlink(&sub, &link)?;
        write_atomic(&link, |w| w.write_all(b"new\n"))?;
        assert_eq!(own_mode(&link)?, (0o600, true), "a new owner-only file");
        assert!(sub.is_dir(), "the directory is untouched");
        Ok(())
    }

    /// A FIFO at the path is replaced by a new, owner-only file: only a
    /// regular file's mode is kept.
    #[test]
    fn a_fifo_at_the_path_gives_a_new_0600_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        // SAFETY: `c_path` is a NUL-terminated path that outlives the call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o666) };
        assert_eq!(rc, 0, "mkfifo: {}", io::Error::last_os_error());
        write_atomic(&path, |w| w.write_all(b"new\n"))?;
        assert_eq!(own_mode(&path)?, (0o600, true), "a new owner-only file");
        Ok(())
    }

    /// One of two hard links is replaced: the new file keeps the mode, and
    /// the other link keeps the old contents.
    #[test]
    fn a_hard_linked_file_keeps_its_mode_and_the_other_link() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", 0o664)?;
        let other = dir.path().join("other.toml");
        std::fs::hard_link(&path, &other)?;
        write_atomic(&path, |w| w.write_all(b"new\n"))?;
        assert_eq!(own_mode(&path)?, (0o664, true), "mode kept");
        assert_eq!(std::fs::read(&other)?, b"old\n", "the other link is old");
        Ok(())
    }

    /// A supplementary group of this process other than the group a new
    /// file gets, if any.
    fn other_group() -> Option<u32> {
        let dir = tempfile::tempdir().ok()?;
        let probe = dir.path().join("probe");
        std::fs::write(&probe, b"").ok()?;
        let primary = std::fs::metadata(&probe).ok()?.gid();
        let mut groups = vec![0 as libc::gid_t; 256];
        // SAFETY: the buffer holds `groups.len()` entries.
        let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
        groups.truncate(usize::try_from(count).unwrap_or(0));
        groups.into_iter().find(|g| *g != primary)
    }

    /// The group of the file a symlink points to is not given to the new
    /// file: only the mode comes through a link. Without a supplementary
    /// group the target's group is the process's own, and the case holds
    /// trivially.
    #[test]
    fn a_symlink_targets_group_is_not_carried() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("shared.toml");
        file_with_mode(&target, b"shared\n", 0o660)?;
        if let Some(other) = other_group() {
            std::os::unix::fs::chown(&target, None, Some(other))?;
        }
        let link = dir.path().join("sipnab.toml");
        std::os::unix::fs::symlink(&target, &link)?;
        write_atomic(&link, |w| w.write_all(b"new\n"))?;
        let fresh = dir.path().join("fresh.toml");
        write_atomic(&fresh, |w| w.write_all(b"x"))?;
        assert_eq!(
            std::fs::symlink_metadata(&link)?.gid(),
            std::fs::metadata(&fresh)?.gid(),
            "the group a new file gets, not the target's"
        );
        assert_eq!(own_mode(&link)?.0, 0o660, "the target's mode");
        Ok(())
    }

    /// A file with a second hard link keeps its mode but not its group:
    /// its owner is not the name's to give.
    #[test]
    fn a_hard_linked_files_group_is_not_carried() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", 0o640)?;
        if let Some(other) = other_group() {
            std::os::unix::fs::chown(&path, None, Some(other))?;
        }
        std::fs::hard_link(&path, dir.path().join("other.toml"))?;
        write_atomic(&path, |w| w.write_all(b"new\n"))?;
        let fresh = dir.path().join("fresh.toml");
        write_atomic(&fresh, |w| w.write_all(b"x"))?;
        assert_eq!(
            std::fs::metadata(&path)?.gid(),
            std::fs::metadata(&fresh)?.gid(),
            "the group a new file gets"
        );
        assert_eq!(own_mode(&path)?.0, 0o640, "mode kept");
        Ok(())
    }

    /// An empty write over a file keeps its mode too.
    #[test]
    fn an_empty_replace_keeps_the_mode() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        file_with_mode(&path, b"old\n", 0o640)?;
        write_atomic(&path, |_| Ok(()))?;
        assert_eq!(own_mode(&path)?, (0o640, true), "mode kept");
        assert!(std::fs::read(&path)?.is_empty(), "empty");
        Ok(())
    }
}
