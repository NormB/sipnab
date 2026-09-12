// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whether the sipnab binary under test can open a live capture device HERE.
//!
//! # The bug this replaces
//!
//! Two test files each carried a copy that read `/proc/self/status` and asked
//! whether the TEST RUNNER holds `CAP_NET_RAW`. That is the wrong process. A
//! sipnab built and then given file capabilities -- `setcap cap_net_raw+ep`,
//! which this project does to exercise live capture and uprobes -- gains the
//! capability at `exec`, whatever the runner holds.
//!
//! On 2026-09-12 the runner's `CapEff` was `0000000000000000` and
//! `target/debug/sipnab` carried `cap_net_admin,cap_net_raw=ep`. The probe
//! answered "unprivileged", the test took its unprivileged branch, and the
//! child opened `lo` and captured happily. The assertion that failed was
//! correct about the branch it was in; the branch was chosen by a measurement
//! of the wrong thing.
//!
//! # What it does instead
//!
//! It asks the binary. One spawn against the loopback interface with a bounded
//! duration, and the answer is whatever actually happened. A capability model
//! reimplemented in a test is a second copy of the kernel's rules; an
//! observation is not.
//!
//! The result is memoized, because a probe that is cheap once and repeated a
//! hundred times becomes the slowest thing in the suite.

use std::process::Command;
use std::sync::OnceLock;

/// The interface probed. Loopback exists on every host this suite runs on and
/// carries nothing an unrelated process would mind being read.
const PROBE_DEVICE: &str = "lo";

static ANSWER: OnceLock<Option<bool>> = OnceLock::new();

/// `Some(true)` when the binary can open a device, `Some(false)` when it
/// cannot, `None` when the question could not be settled.
///
/// `None` is not "no". A caller that cannot tell must skip loudly rather than
/// assert the unprivileged branch, which is how the original defect stayed
/// invisible: an unprivileged answer is indistinguishable from an unknown one
/// once it has been coerced to a bool.
pub fn can_live_capture(binary: &str) -> Option<bool> {
    *ANSWER.get_or_init(|| probe(binary))
}

/// The measurement itself, unmemoized. Public so a test can prove the memo
/// returns what a fresh probe would.
pub fn probe(binary: &str) -> Option<bool> {
    // No loopback, no question worth answering.
    if !std::path::Path::new("/sys/class/net")
        .join(PROBE_DEVICE)
        .exists()
    {
        return None;
    }
    let out = Command::new(binary)
        .args([
            "-N",
            "-q",
            "-d",
            PROBE_DEVICE,
            "--duration",
            "1s",
            "--no-cli-print",
        ])
        .env("SIPNAB_LOG", "info")
        .output()
        .ok()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The line the capture path prints once the handle is live. Matching the
    // OPEN rather than the exit code: a bounded run can exit 0 having captured
    // nothing, and a run refused for permission exits non-zero for a reason
    // that is not always distinguishable from any other startup failure.
    if stderr.contains(&format!("Capturing on '{PROBE_DEVICE}'")) {
        return Some(true);
    }
    let refused = stderr.contains("Operation not permitted")
        || stderr.contains("permission denied")
        || stderr.contains("Permission denied")
        || stderr.contains("You don't have permission");
    if refused {
        return Some(false);
    }
    // Neither opened nor plainly refused: say so rather than guessing.
    None
}

/// The device this probe uses, so a caller's own capture names the same one.
#[must_use]
pub const fn probe_device() -> &'static str {
    PROBE_DEVICE
}
