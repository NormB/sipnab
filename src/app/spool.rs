// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A spool: a directory of files waiting to be delivered over HTTP, each
//! delivered or refused on its own, in name order.
//!
//! Two senders use it: the vCon forwarder (`--vcon-forward`), which
//! delivers the containers a capture wrote, and a fleet member
//! (`[fleet] report_url`), which delivers its heartbeats to a fleet center.
//! The rules a file is read, written, retried and judged by live here once,
//! so the two cannot read one spool two ways.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;
#[cfg(feature = "vcon")]
use std::time::Instant;

/// How often the wait between passes asks whether a stop was requested.
///
/// Not a setting: it changes nothing that is sent or when, only how soon
/// after SIGTERM or SIGINT a sender returns, which is at most this long.
#[cfg(feature = "vcon")]
const STOP_POLL_STEP: Duration = Duration::from_millis(100);

/// The files waiting in `spool`, by name, sorted.
///
/// A waiting file is a regular file whose name ends in `.json` and does not
/// start with a dot. sipnab stages every write as `.<name>.partial` and
/// renames it into place, so neither rule ever selects a half-written file.
/// Directories (the delivered and failed ones among them), symbolic links and
/// names that are not UTF-8 are passed over.
///
/// # Errors
///
/// The directory cannot be read.
pub fn pending(spool: &Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(spool)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        if entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// How long a file waits after its `attempts`-th failed try:
/// `first_secs`, then doubling, never more than `cap_secs`.
#[must_use]
pub fn backoff_delay(attempts: u32, first_secs: u64, cap_secs: u64) -> Duration {
    let doublings = attempts.saturating_sub(1).min(u64::BITS - 1);
    let secs = first_secs.saturating_mul(1u64 << doublings);
    Duration::from_secs(secs.min(cap_secs))
}

/// What an HTTP status means for the file that drew it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `2xx`: the store accepted it.
    Delivered,
    /// A `4xx` that a retry will not change.
    Refused,
    /// `5xx`, or a status this client does not act on: try later.
    Retry,
    /// `409` with a replace URL: PUT it there.
    Replace,
    /// `401` or `403`: the store refuses the credentials or the client, for
    /// every container alike. Stop.
    Halt,
}

/// Classify a status. `can_replace` is whether a replace URL is set;
/// `delivered` is the inclusive range of statuses that count as delivered
/// (the vCon forwarder's `KindFacts::delivered`, or `(200, 299)`). Any other
/// `2xx` is retried.
#[must_use]
pub fn classify(status: u16, can_replace: bool, delivered: (u16, u16)) -> Verdict {
    match status {
        s if (delivered.0..=delivered.1).contains(&s) => Verdict::Delivered,
        401 | 403 => Verdict::Halt,
        409 if can_replace => Verdict::Replace,
        400..=499 => Verdict::Refused,
        _ => Verdict::Retry,
    }
}

/// Write `bytes` to `path` by staging a dot-prefixed sibling and renaming it,
/// so a reader never sees half a record.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map_or_else(|| "record".into(), |n| n.to_string_lossy().into_owned());
    let staged = path.with_file_name(format!(".{name}.partial"));
    let result = std::fs::File::create(&staged)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&staged, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Sleep for `interval` in short steps. Returns `false` as soon as `stop`
/// says so.
#[cfg(feature = "vcon")]
pub(crate) fn sleep_unless_stopped(interval: Duration, stop: &dyn Fn() -> bool) -> bool {
    let until = Instant::now() + interval;
    while Instant::now() < until {
        if stop() {
            return false;
        }
        std::thread::sleep(STOP_POLL_STEP.min(until.saturating_duration_since(Instant::now())));
    }
    !stop()
}
