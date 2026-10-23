// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Opening a file a writer is about to fill.

use std::path::Path;

/// How a writer opens its output.
///
/// Each caller states which, so the choice is visible where the path comes
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMode {
    /// Create the file, or truncate one already there. For a path the
    /// operator typed on the command line or chose in the TUI.
    Replace,
    /// Create the file only if nothing is at the path yet.
    NewOnly,
}

/// Open `path` for writing as `mode` says. `NewOnly` creates with `mode_bits`
/// (Unix permission bits before the umask).
///
/// `NewOnly` is one atomic open, `create_new` (`O_CREAT | O_EXCL`), so there
/// is no window between deciding the name is free and taking it: an existing
/// file is never truncated, and a link at the name is refused rather than
/// followed, a dangling one included (POSIX: with `O_EXCL` the final
/// component is not followed). `O_NOFOLLOW` is added where `libc` is linked,
/// stating the same intent to the kernel. A writer that checks the name
/// first, for a clearer refusal, still needs this open: the check alone
/// leaves the window open.
///
/// # Errors
///
/// What the open returned: `AlreadyExists` when anything, a link included,
/// is at `path` under `NewOnly`.
pub fn open_for_write(
    path: &Path,
    mode: CreateMode,
    mode_bits: u32,
) -> std::io::Result<std::fs::File> {
    match mode {
        CreateMode::Replace => std::fs::File::create(path),
        CreateMode::NewOnly => {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(mode_bits);
                #[cfg(feature = "native")]
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            #[cfg(not(unix))]
            let _ = mode_bits;
            opts.open(path)
        }
    }
}

/// Create `path` as a new file holding `bytes`.
///
/// # Errors
///
/// What the open or the write returned.
pub fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = open_for_write(path, CreateMode::NewOnly, 0o666)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    // MCP-WRITE-TOCTOU: an MCP writer checked that its target name was free
    // and then opened it with a create-or-truncate that follows a link. A
    // file or link placed at the name between the check and the open was
    // truncated, or written through.

    #[test]
    fn new_only_creates_a_file_that_was_not_there() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.pcap");
        write_new(&path, b"bytes")?;
        assert_eq!(std::fs::read(&path)?, b"bytes");
        Ok(())
    }

    #[test]
    fn new_only_refuses_an_existing_file_and_leaves_it_whole() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.pcap");
        std::fs::write(&path, b"the only copy")?;
        let err = write_new(&path, b"x")
            .err()
            .ok_or("an existing file is refused")?;
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path)?, b"the only copy");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_only_refuses_a_link_and_leaves_its_target_whole() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("victim");
        std::fs::write(&target, b"someone else's file")?;
        let link = dir.path().join("out.pcap");
        std::os::unix::fs::symlink(&target, &link)?;
        let err = write_new(&link, b"x").err().ok_or("a link is refused")?;
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target)?, b"someone else's file");
        Ok(())
    }

    /// A dangling link would otherwise create the file it points at.
    #[cfg(unix)]
    #[test]
    fn new_only_refuses_a_dangling_link_and_creates_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("planted");
        let link = dir.path().join("out.pcap");
        std::os::unix::fs::symlink(&target, &link)?;
        let err = write_new(&link, b"x")
            .err()
            .ok_or("a dangling link is refused")?;
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!target.exists(), "nothing is created through the link");
        Ok(())
    }

    /// The operator's own path keeps its behavior: an existing file is
    /// replaced.
    #[test]
    fn replace_truncates_an_existing_file() -> Result<(), TestError> {
        use std::io::Write;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.pcap");
        std::fs::write(&path, b"old contents")?;
        open_for_write(&path, CreateMode::Replace, 0o666)?.write_all(b"new")?;
        assert_eq!(std::fs::read(&path)?, b"new");
        Ok(())
    }

    /// Every MCP writer opens through this module. The race the new-only open
    /// closes sits between a name check and the open, and no test can drive
    /// it, so this keeps an MCP write from drifting back to a call that
    /// creates or truncates and follows a link. It reads each file under
    /// `src/mcp` up to its first `#[cfg(test)]`.
    #[test]
    fn mcp_production_code_never_creates_or_truncates_a_file() -> Result<(), TestError> {
        fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    walk(&path, out)?;
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
            Ok(())
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("mcp");
        let mut files = Vec::new();
        walk(&root, &mut files)?;
        assert!(files.len() > 5, "the walk found the MCP sources: {files:?}");
        let mut found = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(&file)?;
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("#[cfg(test)]") {
                    break;
                }
                if [
                    "std::fs::write(",
                    "fs::write(",
                    "File::create(",
                    "CreateMode::Replace",
                ]
                .iter()
                .any(|call| line.contains(call))
                {
                    found.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "open MCP output with crate::new_file (write_new or open_for_write \
             with NewOnly), not a create-or-truncate:\n{}",
            found.join("\n")
        );
        Ok(())
    }
}
