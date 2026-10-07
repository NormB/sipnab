// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writing a file that a test then executes.
//!
//! Linux refuses to execute a file that any process has open for writing
//! (`ETXTBSY`). A child forked by another test thread inherits every
//! descriptor this process holds at that instant, and keeps it until its own
//! `exec`; under host load that gap stretches. A stub written here with
//! `std::fs::write` and run straight after can therefore fail with "Text file
//! busy". Writing it from a child process means this process never holds a
//! writable descriptor to it. `tests/executable_stub_test.rs` refuses the
//! in-process pattern.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Write `contents` to `path` and mark it executable (0755), from a child
/// process, so this process never holds the file open for writing.
///
/// # Errors
///
/// The writer cannot start, its input cannot be written, or it exits
/// unsuccessfully.
pub fn write_executable(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut writer = Command::new("sh")
        .arg("-c")
        .arg("cat >\"$1\" && chmod 755 \"$1\"")
        .arg("sh")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()?;
    writer
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("the writer has no stdin"))?
        .write_all(contents.as_bytes())?;
    let status = writer.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "writing {} failed: {status}",
            path.display()
        )))
    }
}
