// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TFPS-observe view's off-thread ask and its pure conversions.
//!
//! The view SHELLS OUT: `tfps_ctl` is a child process this run spawns to read
//! the enforcing peer's current state (the sources it bans, the packets it has
//! dropped). Spawning that on the input/render thread would freeze the TUI if
//! the child hangs, so the ask runs on a short-lived worker thread and its
//! answer arrives over a channel; the view shows the last answer (or an
//! "asking…" line) until it lands.
//!
//! The peer is unreachable without it installed, so the view cannot be driven
//! end to end here (the same reason the relay-stats view is tested at its pure
//! core). The CONVERSION it performs — a `tfps_ctl` reply, or the fact that
//! there is none, rendered to the text the view shows — is pure, and is
//! exercised directly.

use std::sync::mpsc::Receiver;

use crate::security::tfps::{Reply, TfpsBanned, TfpsDropped, TfpsError, TfpsLocator};

/// Which TFPS facet the view is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TfpsMode {
    /// The sources TFPS currently bans (`b` default).
    #[default]
    Banned,
    /// The per-source packet-drop counters (`d`).
    Dropped,
}

/// A finished ask, tagged with the facet it answers so a stale reply — the user
/// switched facets while it was in flight — is discarded rather than shown under
/// the wrong header.
pub struct TfpsReply {
    /// The facet this text answers.
    pub mode: TfpsMode,
    /// The rendered answer.
    pub text: String,
}

/// The TFPS-observe view's cache and the ask in flight.
#[derive(Default)]
pub struct TfpsCache {
    /// The rendered answer currently shown.
    pub text: String,
    /// Which facet `text` answers, or `None` before the first ask.
    pub showing: Option<TfpsMode>,
    /// The ask in flight, so the same one is not spawned twice.
    pub pending: Option<TfpsMode>,
    /// The channel the worker sends its one answer on.
    pub rx: Option<Receiver<TfpsReply>>,
}

/// Epoch seconds to a compact UTC instant for display. TFPS reports a ban's
/// times as epoch seconds; a person reads a time, not a count of seconds. An
/// out-of-range value falls back to the number itself rather than vanishing.
fn fmt_epoch(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| secs.to_string())
}

/// Compose the banned-sources text from a `tfps_ctl banned` result. Pure, so it
/// is tested without the peer or a thread. A source's reason evidence and its
/// last request are the peer's own words, shown raw for a human reader.
#[must_use]
pub fn compose_tfps_banned(result: Result<Reply<Vec<TfpsBanned>>, TfpsError>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "TFPS — banned sources");
    let _ = writeln!(out);
    let rows = match result {
        Ok(Reply::NotInstalled { reason }) => {
            let _ = writeln!(out, "  {reason}");
            return out;
        }
        Err(e) => {
            let _ = writeln!(out, "  tfps could not be reached: {e}");
            return out;
        }
        Ok(Reply::Answered { value, .. }) => value,
    };
    if rows.is_empty() {
        let _ = writeln!(out, "  Nothing is banned right now.");
        return out;
    }
    let plural = if rows.len() == 1 { "" } else { "s" };
    let _ = writeln!(out, "  {} source{plural} banned:", rows.len());
    for b in &rows {
        let _ = writeln!(out);
        let held = if b.enforced { "enforced" } else { "observing" };
        let reason = b.reason.as_deref().unwrap_or("—");
        let _ = writeln!(out, "  {}  [{held}]  reason: {reason}", b.ip);
        // Raw: the reason's evidence is the peer's own words. The peer speaks
        // epoch seconds; a person reads a time, so the instants are shown UTC.
        if let Some(detail) = &b.detail {
            let _ = writeln!(out, "    saw: {detail}");
        }
        if let Some(since) = b.first_seen {
            let _ = writeln!(out, "    since: {}", fmt_epoch(since));
        }
        if let Some(expires) = b.expires {
            let _ = writeln!(out, "    expires: {}", fmt_epoch(expires));
        }
    }
    out
}

/// Compose the drop-counter text from a `tfps_ctl dropped` result. Pure.
#[must_use]
pub fn compose_tfps_dropped(result: Result<Reply<Vec<TfpsDropped>>, TfpsError>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "TFPS — dropped packets");
    let _ = writeln!(out);
    let rows = match result {
        Ok(Reply::NotInstalled { reason }) => {
            let _ = writeln!(out, "  {reason}");
            return out;
        }
        Err(e) => {
            let _ = writeln!(out, "  tfps could not be reached: {e}");
            return out;
        }
        Ok(Reply::Answered { value, .. }) => value,
    };
    if rows.is_empty() {
        let _ = writeln!(out, "  Nothing has been dropped.");
        return out;
    }
    let plural = if rows.len() == 1 { "" } else { "s" };
    let _ = writeln!(out, "  {} source{plural}:", rows.len());
    for d in &rows {
        let _ = writeln!(out);
        let rule = d.rule.as_deref().unwrap_or("—");
        let _ = writeln!(
            out,
            "  {}  dropped {}  events {}  rule: {rule}",
            d.ip, d.dropped, d.events
        );
        let _ = writeln!(out, "    last seen: {}", d.last_seen);
        // Raw: the last request line is the sender's own text.
        if let Some(req) = &d.last_request {
            let _ = writeln!(out, "    last request: {req}");
        }
    }
    out
}

/// Spawn a worker that asks TFPS for `mode` and sends the composed text back.
///
/// Mirrors the relay-stats worker: the ask runs off the render thread because it
/// spawns a child process, and a failed send is the ordinary race where the user
/// left the view before the answer landed, not an error.
#[must_use]
pub fn spawn_tfps_ask(locator: TfpsLocator, mode: TfpsMode) -> Receiver<TfpsReply> {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("tfps-observe-ask".to_owned())
        .spawn(move || {
            let text = match mode {
                TfpsMode::Banned => compose_tfps_banned(locator.banned()),
                TfpsMode::Dropped => compose_tfps_dropped(locator.dropped()),
            };
            let _ = tx.send(TfpsReply { mode, text });
        });
    let _ = spawned;
    rx
}
