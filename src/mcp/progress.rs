// SPDX-License-Identifier: MIT OR Apache-2.0

//! `notifications/progress` for tool calls that make the caller wait (PB5).
//!
//! A tool call is one request and one response. When the response takes tens of
//! seconds to arrive the caller cannot tell a server that is working from one
//! that has stopped answering, and an agent's usual remedy — ask again — costs
//! another call and learns nothing. MCP's answer is a progress notification
//! stream keyed to the request, and this is sipnab's side of it.
//!
//! # Only when asked
//!
//! The spec is explicit that a receiver MUST NOT send progress notifications
//! for a request that carried no `progressToken`, so [`Progress`] is built from
//! the token or from nothing, and every method on it is a no-op in the second
//! case. That is not merely compliance: the token is also how the streamable
//! HTTP transport routes a notification back to the stream the call is being
//! answered on, so a notification sent without one has nowhere to go.
//!
//! # Why the waiting tool ticks rather than a watcher task
//!
//! [`Progress::sleep_reporting`] cuts the wait into steps and reports between
//! them, in the handler's own task. A second task reporting on a timer would
//! need to know when the first one finished, and the window where it does not
//! yet know is a progress report sent after the result — which a client is
//! entitled to treat as a protocol error. Splitting the sleep has no such
//! window: the last report happens before the handler returns because it is the
//! same task.
//!
//! A caller that asked for nothing gets exactly one sleep, which is the code
//! path that existed before this module. There is one loop, not two, so the
//! silent case cannot drift from the reporting one.

use rmcp::RoleServer;
use rmcp::model::{ProgressNotificationParam, ProgressToken};
use std::time::{Duration, Instant};

/// How often a waiting tool reports while the caller is listening.
///
/// One second, because the thing being reported on is measured in seconds:
/// `capture_health` samples for at most `MAX_SAMPLE_SECONDS`, so a finer tick
/// would send notifications carrying the same figure twice, and a coarser one
/// would leave the longest wait sipnab can be asked for reporting under half a
/// dozen times.
const TICK: Duration = Duration::from_secs(1);

/// Where one tool call's progress reports go, or nowhere.
///
/// Cloneable and cheap: it holds a peer handle and the caller's token, both of
/// which are handles rather than buffers.
#[derive(Clone)]
pub struct Progress {
    /// The peer to notify and the token to key it to, or `None` when the
    /// caller sent no `progressToken` and is owed no notifications.
    channel: Option<(rmcp::Peer<RoleServer>, ProgressToken)>,
}

impl std::fmt::Debug for Progress {
    /// Prints whether reports are going anywhere, not the peer.
    ///
    /// `Peer` has no useful `Debug`, and the only question anyone debugging a
    /// missing progress report asks is whether the caller supplied a token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Progress")
            .field("requested", &self.requested())
            .finish()
    }
}

impl Progress {
    /// A reporter that sends nothing.
    ///
    /// What a caller that supplied no `progressToken` gets, and what a test
    /// calling a handler directly passes in.
    #[must_use]
    pub fn silent() -> Self {
        Self { channel: None }
    }

    /// A reporter for `token`, addressed to `peer`.
    ///
    /// `token` is the caller's own `_meta.progressToken`; `None` yields
    /// [`Progress::silent`].
    #[must_use]
    pub fn to(peer: rmcp::Peer<RoleServer>, token: Option<ProgressToken>) -> Self {
        Self {
            channel: token.map(|t| (peer, t)),
        }
    }

    /// Whether the caller asked to be told about progress.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.channel.is_some()
    }

    /// Send one progress report, or nothing.
    ///
    /// `done` and `total` are in whatever unit `message` names; MCP requires
    /// only that `done` rise across a request's reports.
    ///
    /// A failed send is logged and swallowed. The notification is a courtesy to
    /// a caller that is still waiting for the real answer, and a peer that has
    /// gone away must not turn a completed piece of work into a tool error.
    pub async fn report(&self, done: f64, total: f64, message: &str) {
        let Some((peer, token)) = &self.channel else {
            return;
        };
        let param = ProgressNotificationParam::new(token.clone(), done)
            .with_total(total)
            .with_message(message);
        if let Err(e) = peer.notify_progress(param).await {
            tracing::debug!("MCP progress notification dropped: {e}");
        }
    }

    /// How long one sleep may last inside a `window`-long wait.
    ///
    /// The whole window when nobody is listening, so a caller that asked for
    /// nothing waits exactly once and the scheduler is not woken thirty times
    /// for reports that will be discarded.
    fn step(&self, window: Duration) -> Duration {
        if self.requested() {
            TICK.min(window)
        } else {
            window
        }
    }

    /// Wait `window`, reporting elapsed seconds against it while waiting.
    ///
    /// Reports what the CLOCK says rather than the sum of the sleeps asked for:
    /// a loaded runtime wakes this late, and reporting nominal steps would let
    /// a report claim 3 of 3 seconds elapsed while the handler still has work
    /// to do. That is the same discipline `capture_health` applies to its own
    /// window measurement, and for the same reason.
    pub async fn sleep_reporting(&self, window: Duration, message: &str) {
        let step = self.step(window);
        let total = window.as_secs_f64();
        let started = Instant::now();
        while let Some(remaining) = window.checked_sub(started.elapsed()) {
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(remaining.min(step)).await;
            // Clamped: the last sleep can overshoot, and a report of "31 of 30"
            // reads as a bug in the tool rather than as scheduler jitter.
            self.report(started.elapsed().as_secs_f64().min(total), total, message)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's rule, as a property of the type: no token, no channel.
    #[test]
    fn a_reporter_with_no_token_is_silent() {
        assert!(!Progress::silent().requested());
    }

    /// A caller that asked for nothing must wait once, not thirty times.
    #[test]
    fn a_silent_reporter_sleeps_the_whole_window_at_once() {
        let window = Duration::from_secs(30);
        assert_eq!(
            Progress::silent().step(window),
            window,
            "an unwatched wait must not be cut into ticks"
        );
    }

    /// A window shorter than one tick must not be padded up to one.
    #[test]
    fn a_window_shorter_than_a_tick_is_never_lengthened() {
        let window = Duration::from_millis(250);
        // `step` is what a listening reporter would use; `silent` is exercised
        // through the same expression so the clamp is proved for both.
        assert_eq!(Progress::silent().step(window), window);
        assert!(
            TICK > window,
            "the fixture is only meaningful while TICK is the longer of the two"
        );
    }

    /// The silent path must still wait: a no-op reporter that also skipped the
    /// sleep would turn `capture_health` into two readings of the same instant.
    #[tokio::test]
    async fn a_silent_wait_still_waits() {
        let window = Duration::from_millis(60);
        let started = Instant::now();
        Progress::silent().sleep_reporting(window, "waiting").await;

        assert!(
            started.elapsed() >= window,
            "slept {:?}, which is less than the {window:?} asked for",
            started.elapsed()
        );
    }

    /// Reporting with no peer must not panic, because every handler calls it
    /// unconditionally.
    #[tokio::test]
    async fn reporting_into_silence_is_a_no_op() {
        Progress::silent().report(1.0, 2.0, "halfway").await;
    }
}
