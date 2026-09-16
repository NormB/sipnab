// SPDX-License-Identifier: MIT OR Apache-2.0

//! The relay-statistics view's state and its off-thread ask (ST8).
//!
//! The view TRANSMITS: C1/C2/C4 put a UDP question to the relay, whose control
//! timeout is measured in seconds ([`crate::rtpengine::control::DEFAULT_CONTROL_TIMEOUT`]).
//! Doing that on the input/render thread would freeze the TUI for up to that
//! long on a keypress, so the ask runs on a short-lived worker thread and its
//! answer arrives over a channel; the view shows the last answer (or an
//! "asking…" line) until it lands.
//!
//! The figures are resolved and rendered by the SAME functions the CLI and REST
//! use ([`crate::output::relay_statistics`], [`crate::stats_vocab`]), so a
//! number cannot differ between surfaces. Nothing here names a relay vendor: the
//! answer is labeled from [`ReadOnlyRelay::describe`], and which relay the
//! `Arc` points at was chosen by the composition root, per RP2's seam.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use super::state::RelayStatsMode;
use crate::output::relay_statistics as fmt;
use crate::relay::reconcile::ReadOnlyRelay;
use crate::relay::types::ControlReply;
use crate::security::transmit_guard::TransmitPermit;
use crate::stats_vocab::{
    self, NameSource, RelayCompareValue, StatisticsOutcome, known_names, ready_comparison,
    relay_compare_value, relay_reply_refusal, relay_reported, resolve_for_wire,
};

/// What the TUI needs to ask the relay: the relay itself, a permit to transmit,
/// and its address so an answer can name its own source.
///
/// Absent (`None` on the view's access) when the run has no relay configured or
/// no transmit permit -- the view then renders the ST-S4 classification instead
/// of asking, the same distinction every other surface draws.
#[derive(Clone)]
pub struct TuiRelayAccess {
    /// The relay to ask, chosen by the composition root. A trait object so this
    /// layer names no implementation and a second relay needs no second field.
    pub relay: Arc<dyn ReadOnlyRelay + Send + Sync>,
    /// Proof this run reads a live source and may put a packet on the wire.
    pub permit: TransmitPermit,
    /// The relay's control address, for the answer to name its source. Never
    /// used to CHOOSE a destination -- the client already points at it.
    pub addr: SocketAddr,
}

/// Whether the relay-statistics view can ask, or which ST-S4 invocation refusal
/// applies when it cannot. The composition root decides this once, and the two
/// no-ask reasons are kept apart -- they send an operator to different places.
#[derive(Clone, Default)]
pub enum RelayQueryState {
    /// The run can ask: a relay, a permit, and an address.
    Ready(TuiRelayAccess),
    /// No relay was configured to ask. ST-S4 `not_configured`.
    #[default]
    NotConfigured,
    /// A relay is configured, but this run may not transmit -- a file-backed
    /// run, whose addresses are historical. ST-S4 `not_permitted`.
    NotPermitted,
}

impl RelayQueryState {
    /// The ST-S4 invocation refusal to render for a state that cannot ask, or
    /// `None` when it can. `not_configured` and `not_permitted` are never
    /// collapsed.
    #[must_use]
    pub fn invocation_refusal(&self) -> Option<String> {
        match self {
            RelayQueryState::Ready(_) => None,
            RelayQueryState::NotConfigured => Some(compose_outcome_text(
                StatisticsOutcome::NotConfigured,
                "no relay to ask; start sipnab with a relay control address",
            )),
            RelayQueryState::NotPermitted => Some(compose_outcome_text(
                StatisticsOutcome::NotPermitted,
                "this run may not transmit to the relay: it reads a file, and a file's \
                 addresses are historical and belong to third parties. Ask from a live \
                 capture instead.",
            )),
        }
    }
}

/// Which answer an ask produces: the call scope, and the mode.
type AskKey = (Option<String>, RelayStatsMode);

/// A finished ask, tagged with what it answers so a stale reply -- the user
/// moved to another mode or call while it was in flight -- is discarded rather
/// than shown under the wrong header.
pub struct RelayStatsReply {
    /// The (call_id, mode) this text answers.
    pub key: AskKey,
    /// The rendered answer.
    pub text: String,
}

/// The relay-stats view's cache and the ask in flight (ST8).
#[derive(Default)]
pub struct RelayStatsCache {
    /// The rendered answer currently shown.
    pub text: String,
    /// What `text` answers, or `None` before the first ask.
    pub showing: Option<AskKey>,
    /// The ask in flight, so the same one is not spawned twice.
    pub pending: Option<AskKey>,
    /// The channel the worker sends its one answer on.
    pub rx: Option<Receiver<RelayStatsReply>>,
}

/// The label an answer carries, vendor-neutral: the relay's own description and
/// its address, plus the call when the ask is scoped to one.
///
/// `describe()` is what keeps a relay name out of this layer -- the CLI writes
/// `rtpengine at {addr}` from the composition root, which may; a consuming layer
/// may not, so it asks the relay to describe itself.
#[must_use]
pub fn answer_label(relay: &dyn ReadOnlyRelay, addr: SocketAddr, call_id: Option<&str>) -> String {
    match call_id {
        Some(cid) => format!("relay {} ({addr}), call {cid}", relay.describe()),
        None => format!("relay {} ({addr})", relay.describe()),
    }
}

/// Render one of the five ST-S4 classifications as a text block (the TUI's form
/// of the refusal every surface reports identically).
///
/// Names the classification, whose problem it is, and a detail -- the same
/// tokens REST puts in its JSON envelope, spelled for a terminal reader.
#[must_use]
pub fn compose_outcome_text(outcome: StatisticsOutcome, detail: &str) -> String {
    format!(
        "Relay statistics unavailable — {} ({})\n\n{detail}\n",
        outcome.as_wire_str(),
        outcome.responsibility().as_wire_str(),
    )
}

/// Compose the text for a relay `statistics`/`call_statistics` reply in the
/// counters or names mode (C1/C2/C3), pure so it is tested without a relay or a
/// thread -- the same reason `query_relay`'s conversion is tested directly.
///
/// `per_call` selects the per-call refusal rule: only a per-call reply can be
/// the relay's "I do not hold that call", matching `relay_rest_answer`.
#[must_use]
pub fn compose_counters_or_names(
    reply: &ControlReply,
    label: &str,
    obtained_at: chrono::DateTime<chrono::Utc>,
    per_call: bool,
    names_only: bool,
    origin: fmt::FetchOrigin,
) -> String {
    let ControlReply::Statistics(pairs) = reply else {
        return compose_outcome_text(
            StatisticsOutcome::Suspect,
            "the relay answered with something other than statistics",
        );
    };
    if per_call && let Some(reason) = relay_reply_refusal(pairs) {
        return compose_outcome_text(StatisticsOutcome::Refused, &reason);
    }
    let tiered = relay_reported(pairs);
    if names_only {
        // The current relay enumerates its statistics -- the reply IS the list.
        let source = NameSource::Listed;
        fmt::format_relay_stat_names(&known_names(&tiered), source, label, obtained_at)
    } else {
        let wire = resolve_for_wire(&tiered);
        fmt::format_relay_statistics(&wire, label, obtained_at, origin)
    }
}

/// Compose the text for a relay `list` reply (ST8 holdings): the Call-IDs the
/// relay is holding right now. Pure, so it is tested without a relay or a
/// thread, the same reason the counters and compare conversions are. A refusal
/// carries the relay's own words; any other reply shape is `suspect`, matching
/// `relay_rest_answer`'s holdings arm.
///
/// STUB — filled in after the failing test.
#[must_use]
pub fn compose_holdings(
    reply: &ControlReply,
    label: &str,
    obtained_at: chrono::DateTime<chrono::Utc>,
) -> String {
    use std::fmt::Write as _;

    let ControlReply::Calls(e) = reply else {
        return match reply {
            ControlReply::Refused { reason } => {
                compose_outcome_text(StatisticsOutcome::Refused, &format!("{label}: {reason}"))
            }
            _ => compose_outcome_text(
                StatisticsOutcome::Suspect,
                "the relay answered with something other than a call list",
            ),
        };
    };

    let mut out = String::new();
    let _ = writeln!(out, "{label}");
    let _ = writeln!(out, "asked {}", obtained_at.to_rfc3339());
    let _ = writeln!(out);
    if e.call_ids.is_empty() {
        let _ = writeln!(out, "The relay holds no calls.");
    } else {
        let plural = if e.call_ids.len() == 1 { "" } else { "s" };
        let _ = writeln!(out, "Holding {} call{plural}:", e.call_ids.len());
        for cid in &e.call_ids {
            // Raw: a Call-ID is the relay's own word, shown as it wrote it.
            let _ = writeln!(out, "  {cid}");
        }
        if e.truncated {
            let _ = writeln!(
                out,
                "  … more, not shown (the relay returned a bounded set)"
            );
        }
    }
    out
}

/// Whether a C5 re-poll is due: an interval is set and at least that long has
/// passed since the last ask (or none has been made). Pure, so the cadence is
/// tested without a clock -- the same lesson the relay-poll loop test learned.
#[must_use]
pub fn poll_due(
    asked_at: Option<std::time::Instant>,
    now: std::time::Instant,
    interval_secs: Option<u64>,
) -> bool {
    let Some(secs) = interval_secs else {
        return false;
    };
    match asked_at {
        None => true,
        Some(then) => now.duration_since(then) >= std::time::Duration::from_secs(secs),
    }
}

/// The fetch origin the counters view labels itself with: `polled` with the
/// interval when the run set one (C5), else `asked`.
#[must_use]
pub fn fetch_origin(interval_secs: Option<u64>) -> fmt::FetchOrigin {
    match interval_secs {
        Some(every_secs) => fmt::FetchOrigin::Polled { every_secs },
        None => fmt::FetchOrigin::Asked,
    }
}

/// Compose the text for a C4 comparison, pure: the relay's per-call reply and
/// this capture's measured count in, a rendered comparison (or an ST-S4
/// classification) out. Keeps zero and absent distinct (ST9) via
/// [`ready_comparison`].
#[must_use]
pub fn compose_compare(
    reply: &ControlReply,
    call_id: &str,
    sipnab_side: Option<u64>,
    label: &str,
    obtained_at: chrono::DateTime<chrono::Utc>,
) -> String {
    use stats_vocab::CompareOutcome;
    let ControlReply::Statistics(pairs) = reply else {
        return compose_outcome_text(
            StatisticsOutcome::Suspect,
            "the relay answered with something other than statistics",
        );
    };
    if let Some(reason) = relay_reply_refusal(pairs) {
        return compose_outcome_text(StatisticsOutcome::Refused, &reason);
    }
    let tiered = relay_reported(pairs);
    // ST-S4 condition 11: a per-call total too large for u64 is a SUSPECT answer
    // carrying its digits, never coerced to an absent side that would read as
    // "the relay does not hold the call".
    let relay_side = match relay_compare_value(&tiered, "totals.RTP.packets") {
        RelayCompareValue::Overflow(digits) => {
            return compose_outcome_text(
                StatisticsOutcome::Suspect,
                &format!(
                    "the relay reported {digits} RTP packet(s) for call {call_id}, a value too \
                     large to compare; carried as received, not truncated"
                ),
            );
        }
        RelayCompareValue::Counted(n) => Some(n),
        RelayCompareValue::Absent => None,
    };
    match ready_comparison(relay_side, sipnab_side) {
        CompareOutcome::Compared(c) => {
            fmt::format_relay_comparison(&c, call_id, label, obtained_at)
        }
        // The call is on the relay, but this capture measured no RTP for it.
        CompareOutcome::SipnabHasNoRtp { relay_value } => compose_outcome_text(
            StatisticsOutcome::NotConfigured,
            &format!(
                "the relay reports {relay_value} RTP packet(s) for call {call_id}, but this \
                 capture measured none for it; widen the capture filter to include the media"
            ),
        ),
        CompareOutcome::RelayDoesNotHoldCall { .. } => compose_outcome_text(
            StatisticsOutcome::Refused,
            &format!("the relay does not hold call {call_id}"),
        ),
        CompareOutcome::NeitherSide => compose_outcome_text(
            StatisticsOutcome::Refused,
            &format!("neither the relay nor this capture has RTP for call {call_id}"),
        ),
    }
}

/// Ask the relay for `key` on a worker thread and hand back the receiver its one
/// answer will arrive on.
///
/// The transmit is done off the caller's thread precisely so a slow or
/// unreachable relay -- up to the multi-second control timeout -- never freezes
/// the UI. `sipnab_side` is computed by the caller (a stream-store read) and
/// carried in, so the worker touches only the relay.
#[must_use]
pub fn spawn_ask(
    access: TuiRelayAccess,
    key: AskKey,
    sipnab_side: Option<u64>,
    origin: fmt::FetchOrigin,
) -> Receiver<RelayStatsReply> {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("relay-stats-ask".to_owned())
        .spawn(move || {
            let text = do_ask(&access, &key, sipnab_side, origin);
            // The receiver is dropped when the user leaves the view before the
            // answer lands; a failed send is that ordinary race, not an error.
            let _ = tx.send(RelayStatsReply { key, text });
        });
    // A thread that will not spawn is rare (resource exhaustion); the receiver
    // then never fires and the view keeps its "asking…" line, which is honest.
    let _ = spawned;
    rx
}

/// Perform one ask and compose its text. Transmits, so it is not unit-tested;
/// the composition it delegates to IS (`compose_*`), and the wire is exercised
/// live against the harness relay.
fn do_ask(
    access: &TuiRelayAccess,
    key: &AskKey,
    sipnab_side: Option<u64>,
    origin: fmt::FetchOrigin,
) -> String {
    let (call_id, mode) = key;
    let obtained_at = chrono::Utc::now();
    let label = answer_label(access.relay.as_ref(), access.addr, call_id.as_deref());
    // ST-S4: a reply that arrived but could not be trusted (a mismatched cookie)
    // is `suspect`; everything else is `unreachable`. Classified through the one
    // seam rule so the TUI, REST and the CLI agree on which is which.
    let fetch_failure = |e: &anyhow::Error| match crate::relay::types::fetch_error_outcome(e) {
        StatisticsOutcome::Suspect => compose_outcome_text(
            StatisticsOutcome::Suspect,
            &format!("{label}: {e}; the reply was discarded and not read"),
        ),
        _ => compose_outcome_text(
            StatisticsOutcome::Unreachable,
            &format!("{label} did not answer ({e}); asked, nothing came back"),
        ),
    };
    match mode {
        RelayStatsMode::Counters => match call_id {
            Some(cid) => match access.relay.call_statistics(&access.permit, cid) {
                Ok(reply) => {
                    compose_counters_or_names(&reply, &label, obtained_at, true, false, origin)
                }
                Err(e) => fetch_failure(&e),
            },
            None => match access.relay.statistics(&access.permit) {
                Ok(reply) => {
                    compose_counters_or_names(&reply, &label, obtained_at, false, false, origin)
                }
                Err(e) => fetch_failure(&e),
            },
        },
        // Names never label themselves polled: `?` is a one-shot question, and
        // its own header states the source.
        RelayStatsMode::Names => match access.relay.statistics(&access.permit) {
            Ok(reply) => compose_counters_or_names(
                &reply,
                &label,
                obtained_at,
                false,
                true,
                fmt::FetchOrigin::Asked,
            ),
            Err(e) => fetch_failure(&e),
        },
        RelayStatsMode::Compare => {
            let Some(cid) = call_id else {
                // The view refuses to open Compare without a call; a Compare ask
                // with no call is a caller bug, reported rather than transmitted.
                return compose_outcome_text(
                    StatisticsOutcome::NotConfigured,
                    "a comparison needs a call to compare; open the relay-stats view from a call",
                );
            };
            match access.relay.call_statistics(&access.permit, cid) {
                Ok(reply) => compose_compare(&reply, cid, sipnab_side, &label, obtained_at),
                Err(e) => fetch_failure(&e),
            }
        }
        // Holdings is the relay's full held set, independent of any call scope
        // (like Names), so it ignores `call_id`.
        RelayStatsMode::Holdings => {
            match access
                .relay
                .list(&access.permit, crate::relay::reconcile::DEFAULT_LIST_LIMIT)
            {
                Ok(reply) => compose_holdings(&reply, &label, obtained_at),
                Err(e) => fetch_failure(&e),
            }
        }
    }
}
