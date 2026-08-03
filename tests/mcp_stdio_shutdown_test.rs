// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(feature = "native", feature = "mcp"))]

//! A stdio MCP server must not outlive the client that started it (#229).
//!
//! Reported from a laptop: connecting Claude to the server started
//! `sipnab --mcp -N --quiet` processes that were never terminated, disabling the
//! server did not reap them, and re-enabling added another. Unbounded growth,
//! and because those flags start a LIVE capture, every orphan was still
//! sniffing the network.
//!
//! The mechanism, once found, was narrow. `app::servers` sets `mcp_stdio_done`
//! when the transport ends, and the post-capture keep-alive loop in
//! `app::batch::run` polls it. A file capture drains, the packet loop exits on
//! a disconnected channel, and that loop is reached. A live capture never
//! disconnects, so the packet loop spun forever and the flag was written but
//! never read. The check now lives in the packet loop too, and routes through
//! `signals::request_shutdown` so the capture thread stops as well -- breaking
//! out of the loop alone still blocked forever joining a thread sat in libpcap.
//!
//! ## Why `--replay` rather than a live capture
//!
//! The real defect needs a source that never ends, which normally means a live
//! capture, which needs `CAP_NET_RAW`. CI has no such privilege, so a test
//! gated on it would skip there -- and a shutdown test that silently skips is
//! worse than none, which this repo has learned twice (`abebdc0`, and the
//! vacuous compaction test in stage 4 of #128).
//!
//! `--replay` paces a capture at its original timestamps. `sip_call.pcap` spans
//! about a minute, so for that minute the packet loop is in exactly the state a
//! live capture is in permanently: connected channel, no EOF coming. That
//! reproduces the defect with no privileges at all.
//!
//! Verified to fail before the fix: with the guard removed, this hangs past 15s
//! rather than exiting in under one.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Spawn a stdio MCP server over a slow source, hand back the child.
fn spawn_replaying_server() -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["--mcp", "-N", "--quiet", "--replay", "-I"])
        .arg(fixture("sip_call.pcap"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --mcp")
}

/// Wait for exit, or report how long we waited.
fn wait_for_exit(child: &mut std::process::Child, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => return Some(start.elapsed()),
            None if start.elapsed() >= limit => return None,
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Closing stdin is how an MCP client shuts a stdio server down. It must exit.
#[test]
fn closing_stdin_terminates_the_server_even_mid_capture() {
    let mut child = spawn_replaying_server();

    // Let it get past startup and into the packet loop with the source still
    // open -- the state a live capture is in permanently.
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the server exited before the test could act; --replay is not pacing \
         the fixture and this test is not exercising the defect"
    );

    drop(child.stdin.take().expect("stdin piped"));

    let waited = wait_for_exit(&mut child, Duration::from_secs(20));
    if waited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let waited = waited.unwrap_or_else(|| {
        panic!(
            "the server was still running 20s after its client closed stdin. \
             This is #229: every client disconnect leaks a process that keeps \
             capturing."
        )
    });

    // Promptly, not eventually. Without the fix the process survives until the
    // replay finishes (~60s for this fixture), which a generous timeout would
    // have called a pass.
    assert!(
        waited < Duration::from_secs(10),
        "exited, but took {waited:?} -- that is the source draining, not the \
         client-gone check firing"
    );
}

/// SIGTERM must still work, and must not have been broken by the fix.
#[cfg(unix)]
#[test]
fn sigterm_still_terminates_the_server() {
    let mut child = spawn_replaying_server();
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "exited before the signal could be sent"
    );

    // SAFETY: `kill(2)` with a pid this process owns and a valid signal.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }

    let waited = wait_for_exit(&mut child, Duration::from_secs(15));
    if waited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("SIGTERM no longer terminates the MCP server");
    }
}

/// A server whose client never disconnects keeps running.
///
/// The counterpart to the first test: proves the exit is caused by the client
/// leaving, not by the server quitting on its own after a couple of seconds,
/// which would make the first test pass for the wrong reason.
#[test]
fn a_server_with_a_live_client_keeps_running() {
    let mut child = spawn_replaying_server();
    let mut stdin = child.stdin.take().expect("stdin piped");

    std::thread::sleep(Duration::from_millis(2500));
    // Hold the pipe open and keep it alive.
    let _ = stdin.write_all(b"");
    let _ = stdin.flush();
    std::thread::sleep(Duration::from_millis(3000));

    let running = child.try_wait().expect("try_wait").is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        running,
        "the server exited while its client was still attached, so the first \
         test's exit cannot be attributed to the client leaving"
    );
}
