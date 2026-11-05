// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `-I` refuses a path that is not a regular file or a directory: a FIFO,
//! a pipe named through `/dev/stdin` or `/dev/fd/N`, a device or a socket
//! (STDIN-READ-IGNORES-STOP).
//!
//! sipnab reads a capture from its start more than once: it reads the first
//! bytes to tell a compressed file or an archive from a capture, and libpcap
//! then opens the file again. A pipe can be read only once, so no such input
//! ever worked: a pipe that delivered a capture failed with libpcap's
//! `unknown file format`, because the first read had taken its header. Until
//! this fix, a pipe that delivered nothing kept the run waiting in that first
//! read, and a FIFO kept it waiting in its second open, and in both the run
//! ignored SIGTERM, SIGINT and SIGHUP. Now the run refuses such a path
//! before it opens it, and exits at once.
//!
//! Linux only: the held standard input reads `/proc`.
#![cfg(all(target_os = "linux", feature = "native"))]

include!("support/timeout.rs");

#[path = "support/held_stdin.rs"]
mod held_stdin;

type TestError = Box<dyn std::error::Error>;

/// `-I /dev/stdin`, with standard input a pipe that never ends, is refused
/// at once with exit 1, the status of an `-I` that names nothing.
#[test]
fn i_dev_stdin_on_a_pipe_is_refused_at_once() -> Result<(), TestError> {
    let args = ["--no-config", "-N", "-I", "/dev/stdin"].map(String::from);
    let mut run = held_stdin::HeldStdin::spawn(&args)?;
    let (status, err) = run.wait_for_exit(test_timeout(10), "the start")?;
    assert_eq!(status.code(), Some(1), "{status}: {err}");
    assert!(
        err.contains("-I/--input: '/dev/stdin' is a pipe or FIFO, not a file"),
        "{err}"
    );
    Ok(())
}

/// A FIFO named with `-I`, with no writer, is refused at once: sipnab no
/// longer opens it, so it never waits for a writer.
#[test]
fn i_naming_a_fifo_is_refused_at_once() -> Result<(), TestError> {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = tempfile::tempdir()?;
    let fifo = dir.path().join("live.pcap");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes())?;
    // SAFETY: mkfifo(3) with a valid NUL-terminated path.
    if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let shown = fifo.display().to_string();
    let args = ["--no-config", "-N", "-I", shown.as_str()].map(String::from);
    let mut run = held_stdin::HeldStdin::spawn(&args)?;
    let (status, err) = run.wait_for_exit(test_timeout(10), "the start")?;
    assert_eq!(status.code(), Some(1), "{status}: {err}");
    assert!(
        err.contains(&format!("'{shown}' is a pipe or FIFO, not a file")),
        "{err}"
    );
    Ok(())
}

/// A character device is refused the same way, naming what it is.
#[test]
fn i_naming_a_device_is_refused() -> Result<(), TestError> {
    let args = ["--no-config", "-N", "-I", "/dev/null"].map(String::from);
    let mut run = held_stdin::HeldStdin::spawn(&args)?;
    let (status, err) = run.wait_for_exit(test_timeout(10), "the start")?;
    assert_eq!(status.code(), Some(1), "{status}: {err}");
    assert!(
        err.contains("'/dev/null' is a character device, not a file"),
        "{err}"
    );
    Ok(())
}
