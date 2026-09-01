// SPDX-License-Identifier: MIT OR Apache-2.0

//! `await_condition`: ONE call that returns when a filter matches or a
//! deadline passes, whichever comes first (PB4, bounded form).
//!
//! The complaint this answers is a real cost with a name: an agent watching a
//! live capture calls `tail_dialogs`, is told nothing happened, and pays a
//! model turn to learn it. Ten turns later it has learned it ten times.
//!
//! # Why this is a tool call and not a subscription
//!
//! The obvious fix is to invert the flow — `subscribe(filter)`, or
//! `notifications/resources/updated` — and `docs/design/backlog.md` DECLINES
//! it. Both put the server into a long-lived relationship with a client: a
//! registry, per-client filters, delivery state, and a lifecycle for a
//! subscriber that goes away without saying so.
//! [`positioning.md`](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md)
//! §4 states the test as a verb — *if a feature requires sipnab to be operated
//! rather than run, it is out of position* — and a subscription service is the
//! thing that has to be operated.
//!
//! The deadline is not a detail, it is the whole reason this version fits.
//! Everything this call allocates dies when it returns: no registry, no task,
//! no state keyed by a client, nothing to reap when a caller disconnects. The
//! server's obligation ENDS, and it ends at a time the request named.
//!
//! # `matched: false` is an answer, not a failure
//!
//! A deadline that passes with nothing matching is the most useful thing this
//! tool says: it is the difference between "the fault has not reproduced" and
//! "the tool broke". Returning an error for it would collapse the two into one
//! shape at exactly the moment an agent has to tell them apart, and would put
//! the finding where a model is least likely to act on it. So the deadline
//! path is a SUCCESSFUL call carrying [`StoppedBecause::Deadline`]. The only
//! errors here are a filter that does not compile and a serializer that fails.
//!
//! # The wait is bounded three ways
//!
//! 1. **`SipnabMcp::max_wait_seconds`** — `--mcp-max-wait-seconds`, else
//!    `[limits] mcp_max_wait_seconds`, else
//!    [`Cli::DEFAULT_MCP_MAX_WAIT_SECONDS`](crate::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS).
//!    The operator owns the ceiling for the same reason they own
//!    `--mcp-max-rows`: the right value is a property of the consumer, not of
//!    sipnab. An over-large request is CLAMPED and told so
//!    ([`AwaitConditionResponse::timeout_clamped`]) rather than refused —
//!    the row cap sets that precedent, and a clamp the response reports is
//!    not a silent one.
//! 2. **[`MIN_POLL_INTERVAL_MS`]** — a caller cannot ask this to spin. Each
//!    look takes both store locks, and a caller that names `poll_interval_ms:
//!    1` would buy a thousand lock acquisitions a second with one request.
//! 3. **The capture source draining.** Once the source is exhausted the answer
//!    can no longer change, so waiting out the rest of the deadline holds a
//!    `--mcp-max-concurrent` permit to learn nothing. That case returns early
//!    with [`StoppedBecause::SourceExhausted`], which an agent must be able to
//!    tell from a deadline: one means "not yet", the other means "not ever,
//!    from this capture".
//!
//! # An idle capture costs a `u64` compare
//!
//! Both stores number their revisions, so an unchanged pair PROVES an
//! unchanged store and the scan can be skipped entirely — the same cheap gate
//! [`crate::mcp::subscribe::Watcher::tick`] uses.
//!
//! BOTH generations, though, where a dialog-list subscriber deliberately reads
//! only the dialog store's. A subscriber is watching a rendered list, which
//! media does not appear in; a filter here can select on media directly
//! (`rtp.mos < 3.5`), and RTP moves the STREAM store without touching the
//! dialog store. Gating on the dialog generation alone would make
//! `await_condition { filter: "rtp.mos < 3.5" }` wait out its whole deadline
//! on a capture whose MOS had already collapsed.
//!
//! [`AwaitConditionResponse::scans`] is reported beside
//! [`AwaitConditionResponse::polls`] so the gate has an observable effect: on
//! an idle capture the two diverge, and a build in which the gate stopped
//! working says so in its own answer.

use std::time::{Duration, Instant};

use crate::mcp::server::SipnabMcp;
use crate::mcp::shape::{fenced_dialog_summary, resolve_limit_with_cap, untrusted_note};
use crate::output::model::DialogSummary;
use crate::sip::dsl::FilterExpr;
use rmcp::handler::server::tool::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Floor on `poll_interval_ms`, in milliseconds.
///
/// **One hundred**, which is [`crate::mcp::subscribe::POLL`] restated on
/// purpose: that constant is already the answer to "how often may this server
/// look at a store on a caller's behalf", and a second number here would be a
/// second answer to one question.
///
/// The floor is what keeps this from being a spin loop bought with one cheap
/// request. Each look takes the dialog and stream read locks, and the gate
/// above ends most of them in a `u64` compare — but ten a second is the rate
/// at which that is free and a thousand a second is not.
///
/// A value BELOW the floor is raised to it rather than refused, because there
/// is nothing to refuse: the caller asked to be told promptly, and the floor
/// is the promptest this server offers. The effective value is reported back
/// in [`AwaitConditionResponse::poll_interval_ms`].
pub const MIN_POLL_INTERVAL_MS: u64 = 100;

/// `poll_interval_ms` when the caller names none, in milliseconds.
///
/// Five times the floor. A caller that did not choose is not in a hurry — it
/// asked to be woken when something happened, not to be woken as soon as
/// physically possible — and half a second is well inside the granularity at
/// which a model can act on being told something.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 500;

/// Shipped ceiling on `timeout_seconds`, in seconds.
///
/// **Sixty**, and the number lives on
/// [`Cli::DEFAULT_MCP_MAX_WAIT_SECONDS`](crate::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS)
/// rather than here — this reads it, the way
/// [`crate::mcp::shape::DEFAULT_MAX_BODY_BYTES`] reads its own. A figure
/// written down twice is a figure that can disagree with itself.
///
/// Grounded in the other bound it multiplies against, which is checkable
/// rather than assumed: `--mcp-max-concurrent` ships at 100, so a stock
/// server's worst case is a hundred permits held for a minute, bought with a
/// hundred cheap requests. Raising this to an hour would make that same
/// hundred requests worth a hundred permit-hours. The operator who knows what
/// their agent can wait for raises it; sipnab does not guess on their behalf.
pub const DEFAULT_MAX_WAIT_SECONDS: u64 = crate::cli::Cli::DEFAULT_MCP_MAX_WAIT_SECONDS;

/// `timeout_seconds` when the caller names none, in seconds.
///
/// Thirty. Short enough that a caller which passed no deadline still gets one
/// it can afford, and long enough to replace the ten-or-so `tail_dialogs`
/// turns this tool exists to delete. Clamped by the operator's ceiling like
/// any other value, so a server configured below it still wins.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

/// Why the wait ended.
///
/// Three outcomes, and an agent has to tell them apart: only the first is a
/// match, and the other two differ in whether waiting longer could ever help.
/// Collapsing them into `matched: false` alone would leave a caller polling a
/// drained pcap forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "snake_case")]
pub enum StoppedBecause {
    /// The filter selected at least one dialog. `matched` is true.
    ConditionMet,
    /// The deadline passed with nothing selected. An ordinary answer: the
    /// condition has not happened YET, and asking again may still find it.
    Deadline,
    /// The capture source drained with nothing selected. Asking again cannot
    /// change this answer, because nothing further will arrive.
    SourceExhausted,
}

/// Parameters for `await_condition`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct AwaitConditionParams {
    /// The condition: a named alias (e.g. `problems`) or a raw Filter DSL
    /// expression, exactly as `list_dialogs` and `find_problems` accept it.
    ///
    /// Required, and deliberately so. The vocabulary is shared rather than
    /// re-invented — a condition language only this tool understood would be
    /// one an agent has to learn twice, and `validate_filter` could not check
    /// it. An absent filter would mean "wait for any dialog at all", which on
    /// a non-empty capture is a call that returns instantly and on an empty
    /// one is a sleep; neither is worth a tool.
    pub filter: String,
    /// How long to wait before answering `matched: false`, in seconds.
    ///
    /// Defaults to [`DEFAULT_TIMEOUT_SECONDS`]. Clamped to the operator's
    /// `--mcp-max-wait-seconds`; the clamp is reported rather than applied
    /// silently.
    #[serde(default)]
    pub timeout_seconds: Option<u32>,
    /// How often to look, in milliseconds. Defaults to
    /// [`DEFAULT_POLL_INTERVAL_MS`], raised to [`MIN_POLL_INTERVAL_MS`] if
    /// smaller.
    #[serde(default)]
    pub poll_interval_ms: Option<u32>,
}

/// Response of `await_condition`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct AwaitConditionResponse {
    /// Schema version of this response shape.
    pub schema_version: u32,
    /// The condition as submitted, echoed verbatim.
    pub filter: String,
    /// Whether the condition was met. `false` on the deadline and on source
    /// exhaustion — both ordinary answers, neither an error.
    pub matched: bool,
    /// Which of the three endings this was.
    pub stopped_because: StoppedBecause,
    /// The matching dialogs: the default page size, cut to the server's
    /// row cap when that is lower. Empty whenever `matched` is false.
    pub dialogs: Vec<DialogSummary>,
    /// Dialogs returned in `dialogs`.
    pub returned: usize,
    /// Dialogs the filter selected, before the row cap cut the page.
    pub total_matched: usize,
    /// True when `total_matched` exceeds what `dialogs` carries.
    pub truncated: bool,
    /// Wall-clock time the call spent waiting, in milliseconds.
    pub elapsed_ms: u64,
    /// The deadline actually used, in seconds, AFTER the operator's ceiling.
    pub timeout_seconds: u64,
    /// True when the request asked for longer than the operator allows.
    ///
    /// Stated explicitly because the ceiling is policy the caller cannot see:
    /// without this, a client that asked for 600 seconds and got an answer in
    /// 60 has no way to tell a clamp from a match it missed. The poll interval
    /// needs no such flag — its floor is a published constant, and the
    /// effective value is returned beside it.
    pub timeout_clamped: bool,
    /// The poll interval actually used, in milliseconds, after the floor.
    pub poll_interval_ms: u64,
    /// How many times the stores were LOOKED at.
    pub polls: u64,
    /// How many of those looks ran the filter.
    ///
    /// Fewer than `polls` on a capture that was idle for part of the wait:
    /// a look whose store generations are unchanged is answered by a `u64`
    /// compare. Reported so that gate has an effect something can observe.
    pub scans: u64,
    /// Whether the capture source had drained by the time this answered.
    pub source_exhausted: bool,
    /// Which capture this answer came from, and which revision of its stores.
    ///
    /// A waiter is exactly the caller a capture swap misleads: it asked about
    /// one capture and can be answered about another.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// What one look at the stores found.
struct Scan {
    /// Dialogs the filter selected, before the page was cut.
    total_matched: usize,
    /// The page itself, already fenced.
    dialogs: Vec<DialogSummary>,
    /// Whether the page is shorter than `total_matched`.
    truncated: bool,
    /// Identity of the capture this look read.
    identity: crate::provenance::CaptureEtag,
    /// `(dialog store, stream store)` revisions at the moment of the look.
    generations: (u64, u64),
}

/// The outcome of one look, which may not have scanned anything.
enum Look {
    /// Neither store moved since the previous look, so the filter was not run.
    Unchanged,
    /// The stores moved, or this was the first look.
    Scanned(Box<Scan>),
}

#[tool_router(router = await_condition_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Wait for a filter to select something, or for a deadline to pass.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `filter` is neither a known alias nor a
    /// parseable Filter DSL expression. Raised BEFORE any waiting: a caller
    /// that mistyped a field name must learn it in milliseconds, not at the
    /// end of a deadline it named.
    ///
    /// `internal_error` (-32603) if the response fails to serialize. A deadline
    /// that passes is NOT an error -- see the module doc.
    #[tool(
        name = "await_condition",
        description = "Waits until a filter selects at least one dialog, or \
                       until timeout_seconds passes, whichever comes first, \
                       and returns the matching dialogs. Replaces a \
                       tail_dialogs polling loop, where every turn that finds \
                       nothing still costs a model call. A deadline that \
                       passes is an ordinary answer — matched=false with \
                       stopped_because=deadline — not a tool error. Returns \
                       early with stopped_because=source_exhausted when the \
                       capture drains, because no further waiting could change \
                       that answer. filter uses the same aliases and DSL as \
                       list_dialogs. timeout_seconds is clamped by the \
                       operator's --mcp-max-wait-seconds and the clamp is \
                       reported. Nothing outlives the call.",
        output_schema = schema_for_output::<AwaitConditionResponse>(),
        annotations(read_only_hint = true, open_world_hint = false, idempotent_hint = false)
    )]
    pub async fn await_condition(
        &self,
        Parameters(params): Parameters<AwaitConditionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Compiled first, outside every lock and before any waiting: a filter
        // that does not parse is a mistake to report now, not in a minute.
        let expr = self.compile_filter(Some(&params.filter))?;
        // No caller-facing page size, deliberately. This tool answers "did it
        // happen", and the rows are evidence that it did rather than a page to
        // work through; `list_dialogs` with the SAME filter is the paging
        // surface, with the cursors and field projection this one has no
        // business restating. So the page is exactly what every list tool
        // gives a caller that named no `limit` -- the default page size, cut
        // to `--mcp-max-rows` when the operator set it lower -- and
        // `total_matched` is reported beside it, so a bounded page never reads
        // as a smaller event than it was.
        let limit = resolve_limit_with_cap(None, self.row_cap);

        let requested = params
            .timeout_seconds
            .map_or(DEFAULT_TIMEOUT_SECONDS, u64::from);
        let ceiling = self.max_wait_seconds;
        let timeout_seconds = requested.min(ceiling);
        let timeout_clamped = requested > ceiling;

        let poll_interval_ms = params
            .poll_interval_ms
            .map_or(DEFAULT_POLL_INTERVAL_MS, u64::from)
            .max(MIN_POLL_INTERVAL_MS);
        let interval = Duration::from_millis(poll_interval_ms);

        let started = Instant::now();
        let deadline = started + Duration::from_secs(timeout_seconds);
        let mut generations: Option<(u64, u64)> = None;
        let mut polls = 0u64;
        let mut scans = 0u64;
        // Carried out of the loop so a wait that never scanned twice still
        // reports the identity and exhaustion state of the look it did make.
        let mut last = None;

        let (stopped_because, scan) = loop {
            // Read BEFORE the look, never after. The capture owner sets this
            // flag with a Release store once the source drains, so an Acquire
            // read of `true` makes every write that preceded it visible — and
            // a look taken after that read is therefore looking at the store
            // in its final state. Sampling it afterwards inverts that: the
            // look could miss a dialog the flag then claims was the last word.
            let exhausted = self.source_is_exhausted();

            polls += 1;
            let look = self.look(expr.as_ref(), generations, limit);
            if let Look::Scanned(scan) = look {
                scans += 1;
                generations = Some(scan.generations);
                let matched = scan.total_matched > 0;
                last = Some(scan);
                if matched {
                    break (StoppedBecause::ConditionMet, last);
                }
            }

            if exhausted {
                break (StoppedBecause::SourceExhausted, last);
            }

            // Checked after the look, so a zero-second deadline still gets one
            // look. "Is it true right now" is a legitimate question, and a
            // caller that asks it with timeout_seconds=0 must not be answered
            // `false` without anything having been read.
            let now = Instant::now();
            if now >= deadline {
                break (StoppedBecause::Deadline, last);
            }

            // Never past the deadline: the last sleep of a wait is short, so a
            // deadline of 250 ms with a 100 ms interval answers at 250 ms
            // rather than at 300.
            tokio::time::sleep(interval.min(deadline - now)).await;
        };

        let matched = stopped_because == StoppedBecause::ConditionMet;
        // The state the ANSWER describes, re-read after the loop: the source
        // can drain during the final sleep, and reporting the value from the
        // first look would tell a caller a drained capture was still filling.
        let source_exhausted = self.source_is_exhausted();
        let scan = scan.ok_or_else(|| {
            rmcp::ErrorData::internal_error(
                "await_condition ended without looking at the stores".to_string(),
                None,
            )
        })?;

        let payload = AwaitConditionResponse {
            schema_version: 1,
            filter: params.filter,
            matched,
            stopped_because,
            // Taken straight from the last look rather than gated on
            // `matched`, because a guard here would be unreachable and an
            // unreachable guard is a claim nothing can check: the loop leaves
            // by `ConditionMet` the instant a scan selects anything, so every
            // other exit carries a scan that selected nothing, and a scan that
            // selected nothing rendered no rows.
            returned: scan.dialogs.len(),
            dialogs: scan.dialogs,
            total_matched: scan.total_matched,
            truncated: scan.truncated,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            timeout_seconds,
            timeout_clamped,
            poll_interval_ms,
            polls,
            scans,
            source_exhausted,
            capture_identity: scan.identity,
        };

        Ok(CallToolResult::success(vec![
            ContentBlock::json(payload)?,
            ContentBlock::text(untrusted_note()),
        ]))
    }
}

impl SipnabMcp {
    /// One look at the stores: the cheap revision compare, and the scan only
    /// if it says something moved.
    ///
    /// `since` is the `(dialog, stream)` generation pair the previous look
    /// recorded, or `None` for the first look — which always scans, because
    /// "unchanged since nothing" is not a thing that can be true.
    ///
    /// Takes no `await` and holds all three guards together, the order
    /// [`crate::mcp::server::CaptureState`] documents: a page and the identity
    /// stamped on it must describe ONE capture.
    fn look(&self, expr: Option<&FilterExpr>, since: Option<(u64, u64)>, limit: usize) -> Look {
        let state = self.capture.read();
        let ds = self.dialog_store.read();
        let ss = self.stream_store.read();
        let generations = (ds.generation(), ss.generation());
        if since == Some(generations) {
            return Look::Unchanged;
        }
        let identity = state.identity.etag(generations.0, generations.1);

        // Grouped once. `streams_for` walks the whole stream store per call,
        // so calling it inside a scan of every dialog is quadratic.
        let mut by_call: std::collections::HashMap<&str, Vec<&crate::rtp::stream::RtpStream>> =
            std::collections::HashMap::new();
        for s in ss.iter() {
            if let Some(id) = s.associated_dialog.as_deref() {
                by_call.entry(id).or_default().push(s);
            }
        }
        const NO_STREAMS: &[&crate::rtp::stream::RtpStream] = &[];
        // Two run-level facts, read once for the whole scan rather than per
        // dialog: `rtp.mos` in a caller's filter is scored on the delay the
        // capture's RTCP supports, the same one `rtp_stats` reports.
        let capture_media = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);
        let delay = crate::rtp::quality::MosDelay::from_capture(&ss);

        let mut matched: Vec<&crate::sip::dialog::SipDialog> = ds
            .iter()
            .filter(|d| {
                let streams = by_call
                    .get(d.call_id.as_str())
                    .map_or(NO_STREAMS, Vec::as_slice);
                expr.is_none_or(|e| e.matches_dialog(d, streams, capture_media, delay))
            })
            .collect();
        let total_matched = matched.len();

        // Sorted before the cut, and by creation time like `list_dialogs`
        // rather than by update time: two calls with the same filter must
        // return the same page, and store order is insertion order.
        crate::sort::sort_by_dyn(&mut matched, &mut |a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.call_id.cmp(&b.call_id))
        });
        let truncated = total_matched > limit;
        let dialogs: Vec<DialogSummary> = matched
            .iter()
            .take(limit)
            .map(|d| fenced_dialog_summary(d))
            .collect();
        drop(ss);
        drop(ds);
        drop(state);

        Look::Scanned(Box::new(Scan {
            total_matched,
            dialogs,
            truncated,
            identity,
            generations,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use parking_lot::RwLock;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    /// An INVITE for `call_id`, parsed between localhost endpoints.
    fn invite(call_id: &str) -> crate::sip::SipMessage {
        let headers = [
            format!("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{call_id}"),
            "From: Alice <sip:alice@example.com>;tag=t1".to_string(),
            "To: <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Content-Length: 0".to_string(),
        ];
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        parse_sip(
            &build_sip("INVITE sip:bob@example.com SIP/2.0", &refs, b""),
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap(),
            local,
            local,
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("the fixture parses")
    }

    /// A server over a store holding `call_ids`, and the store itself so a
    /// test can add to it mid-wait.
    fn server_with(call_ids: &[&str]) -> (SipnabMcp, Arc<RwLock<DialogStore>>) {
        let mut store = DialogStore::new(100, false);
        for id in call_ids {
            store.process_message(invite(id));
        }
        let ds = Arc::new(RwLock::new(store));
        let server = SipnabMcp::new(
            Arc::clone(&ds),
            Arc::new(RwLock::new(StreamStore::new(100))),
        );
        (server, ds)
    }

    /// The JSON payload of a tool result.
    fn json_of(result: &CallToolResult) -> serde_json::Value {
        let note = untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("a payload block that is not the provenance note");
        serde_json::from_str(&text).expect("the payload is JSON")
    }

    /// Params naming `filter`, with everything else defaulted.
    fn params(filter: &str) -> AwaitConditionParams {
        AwaitConditionParams {
            filter: filter.to_string(),
            ..Default::default()
        }
    }

    /// A condition that is already true costs no waiting at all.
    #[tokio::test]
    async fn a_condition_already_true_returns_at_once() {
        let (server, _ds) = server_with(&["a@test", "b@test"]);
        let started = Instant::now();
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(30),
                poll_interval_ms: Some(100),
                ..params("call_id == \"b@test\"")
            }))
            .await
            .expect("an already-true condition is not an error");

        let v = json_of(&result);
        assert_eq!(v["matched"], true);
        assert_eq!(v["stopped_because"], "condition_met");
        assert_eq!(v["total_matched"], 1);
        assert_eq!(v["dialogs"][0]["call_id"], "b@test");
        assert_eq!(v["polls"], 1, "one look was enough; it must not have slept");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a condition already true must not wait out its deadline; took {:?}",
            started.elapsed()
        );
    }

    /// THE load-bearing case: the deadline is an ordinary answer.
    ///
    /// An agent has to tell "the fault has not reproduced" from "the tool
    /// broke", and it can only do that if the two arrive in different shapes.
    #[tokio::test]
    async fn the_deadline_answers_matched_false_rather_than_erroring() {
        let (server, _ds) = server_with(&["a@test"]);
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(1),
                poll_interval_ms: Some(100),
                ..params("call_id == \"never@test\"")
            }))
            .await
            .expect("a deadline that passes is an ANSWER, not an error");

        assert_ne!(
            result.is_error,
            Some(true),
            "the deadline path must not be flagged as an error result either"
        );
        let v = json_of(&result);
        assert_eq!(v["matched"], false);
        assert_eq!(v["stopped_because"], "deadline");
        assert_eq!(v["total_matched"], 0);
        assert_eq!(
            v["dialogs"].as_array().expect("an array").len(),
            0,
            "no match means no rows"
        );
        assert!(
            v["elapsed_ms"].as_u64().expect("a number") >= 900,
            "the deadline must actually have been waited out, not short-circuited: {v:#}"
        );
    }

    /// The operator's ceiling BINDS: an over-large request is answered in the
    /// operator's time, not the caller's.
    #[tokio::test]
    async fn the_operator_ceiling_bounds_an_over_large_request() {
        let (server, _ds) = server_with(&["a@test"]);
        let server = server.with_max_wait_seconds(1);
        let started = Instant::now();
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(3_600),
                poll_interval_ms: Some(100),
                ..params("call_id == \"never@test\"")
            }))
            .await
            .expect("clamping is not an error");

        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(30),
            "an hour was asked for against a one-second ceiling and the call \
             took {elapsed:?}; the ceiling did not bind"
        );
        let v = json_of(&result);
        assert_eq!(
            v["timeout_seconds"], 1,
            "the EFFECTIVE deadline is reported"
        );
        assert_eq!(
            v["timeout_clamped"], true,
            "a clamp the caller cannot see is a silent one"
        );
        assert_eq!(v["stopped_because"], "deadline");
    }

    /// Under the ceiling, the caller's own number is honored unchanged.
    #[tokio::test]
    async fn a_request_under_the_ceiling_is_not_clamped() {
        let (server, _ds) = server_with(&["a@test"]);
        let server = server.with_max_wait_seconds(600);
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(1),
                poll_interval_ms: Some(100),
                ..params("call_id == \"never@test\"")
            }))
            .await
            .expect("ok");

        let v = json_of(&result);
        assert_eq!(v["timeout_seconds"], 1);
        assert_eq!(v["timeout_clamped"], false);
    }

    /// The whole point: a dialog that arrives DURING the wait ends it.
    #[tokio::test]
    async fn a_dialog_arriving_during_the_wait_ends_it() {
        let (server, ds) = server_with(&["a@test"]);
        let writer = Arc::clone(&ds);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            writer.write().process_message(invite("late@test"));
        });

        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(10),
                poll_interval_ms: Some(100),
                ..params("call_id == \"late@test\"")
            }))
            .await
            .expect("ok");

        let v = json_of(&result);
        assert_eq!(v["matched"], true, "the late dialog must be seen: {v:#}");
        assert_eq!(v["stopped_because"], "condition_met");
        assert_eq!(v["dialogs"][0]["call_id"], "late@test");
        assert!(
            v["polls"].as_u64().expect("a number") >= 2,
            "it cannot have been true on the first look: {v:#}"
        );
        assert!(
            v["elapsed_ms"].as_u64().expect("a number") < 9_000,
            "it must have returned on the change, not on the deadline: {v:#}"
        );
    }

    /// A caller cannot ask this to spin.
    #[tokio::test]
    async fn the_poll_interval_has_a_floor() {
        let (server, _ds) = server_with(&["a@test"]);
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(1),
                poll_interval_ms: Some(0),
                ..params("call_id == \"never@test\"")
            }))
            .await
            .expect("ok");

        let v = json_of(&result);
        assert_eq!(
            v["poll_interval_ms"], MIN_POLL_INTERVAL_MS,
            "a sub-floor request is RAISED to the floor and reported"
        );
        // One second at the floor is ten looks; anything far above that is a
        // spin the floor was supposed to have prevented.
        let polls = v["polls"].as_u64().expect("a number");
        assert!(
            polls <= 20,
            "poll_interval_ms=0 produced {polls} looks in one second, so the \
             floor is not being applied"
        );
    }

    /// A filter that does not compile is refused in milliseconds, not at the
    /// end of a deadline the caller named.
    #[tokio::test]
    async fn a_filter_that_does_not_compile_is_refused_before_any_waiting() {
        let (server, _ds) = server_with(&["a@test"]);
        let started = Instant::now();
        let err = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(3_600),
                ..params("state = ")
            }))
            .await
            .expect_err("an uncompilable filter is a caller error");

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the refusal waited: {:?}",
            started.elapsed()
        );
    }

    /// A drained source ends the wait early, and says which of the two
    /// no-match endings this was.
    #[tokio::test]
    async fn an_exhausted_source_ends_the_wait_early_and_says_so() {
        let (server, _ds) = server_with(&["a@test"]);
        let server = server.with_source_exhausted(Arc::new(AtomicBool::new(true)));
        let started = Instant::now();
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(30),
                poll_interval_ms: Some(100),
                ..params("call_id == \"never@test\"")
            }))
            .await
            .expect("exhaustion is an answer, not an error");

        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "a drained capture cannot change its answer, so the wait must not \
             have run to its deadline; took {elapsed:?}"
        );
        let v = json_of(&result);
        assert_eq!(v["matched"], false);
        assert_eq!(
            v["stopped_because"], "source_exhausted",
            "an agent must tell 'not yet' from 'not ever': {v:#}"
        );
        assert_eq!(v["source_exhausted"], true);
    }

    /// A match already in a drained capture is still a match: exhaustion is
    /// checked around the look, not instead of it.
    #[tokio::test]
    async fn an_exhausted_source_still_reports_a_condition_already_true() {
        let (server, _ds) = server_with(&["a@test"]);
        let server = server.with_source_exhausted(Arc::new(AtomicBool::new(true)));
        let result = server
            .await_condition(Parameters(params("call_id == \"a@test\"")))
            .await
            .expect("ok");

        let v = json_of(&result);
        assert_eq!(v["matched"], true, "{v:#}");
        assert_eq!(v["stopped_because"], "condition_met");
    }

    /// The cheap revision gate has an observable effect.
    #[tokio::test]
    async fn an_idle_capture_is_looked_at_more_often_than_it_is_scanned() {
        let (server, _ds) = server_with(&["a@test"]);
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(1),
                poll_interval_ms: Some(100),
                ..params("call_id == \"never@test\"")
            }))
            .await
            .expect("ok");

        let v = json_of(&result);
        let polls = v["polls"].as_u64().expect("a number");
        let scans = v["scans"].as_u64().expect("a number");
        assert_eq!(
            scans, 1,
            "nothing moved, so only the first look may have run the filter: {v:#}"
        );
        assert!(
            polls > scans,
            "the wait must have looked more than once for the gate to have \
             skipped anything: {v:#}"
        );
    }

    /// A zero deadline is still one look, not zero.
    #[tokio::test]
    async fn a_zero_second_deadline_still_looks_once() {
        let (server, _ds) = server_with(&["a@test"]);
        let result = server
            .await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(0),
                ..params("call_id == \"a@test\"")
            }))
            .await
            .expect("ok");

        let v = json_of(&result);
        assert_eq!(
            v["matched"], true,
            "'is it true right now' must be answered by reading, not by \
             assuming: {v:#}"
        );
        assert_eq!(v["polls"], 1);
    }

    /// The page is bounded by the server's row cap, and says so.
    #[tokio::test]
    async fn the_row_cap_bounds_the_dialogs_returned() {
        let (server, _ds) = server_with(&["a@test", "b@test", "c@test", "d@test"]);
        let server = server.with_row_cap(2);
        let result = server
            .await_condition(Parameters(params("method == 'INVITE'")))
            .await
            .expect("ok");

        let v = json_of(&result);
        assert_eq!(v["matched"], true, "{v:#}");
        assert_eq!(v["total_matched"], 4, "the count is not truncated");
        assert_eq!(
            v["dialogs"].as_array().expect("an array").len(),
            2,
            "the page is: {v:#}"
        );
        assert_eq!(v["returned"], 2);
        assert_eq!(v["truncated"], true);
    }

    /// Nothing outlives the call: two identical waits are indistinguishable.
    ///
    /// A registry, a cached cursor or any per-client state would make the
    /// second call differ from the first. This is what "no state keyed by a
    /// client" looks like from outside.
    #[tokio::test]
    async fn a_second_identical_wait_is_indistinguishable_from_the_first() {
        let (server, _ds) = server_with(&["a@test"]);
        let call = || {
            server.await_condition(Parameters(AwaitConditionParams {
                timeout_seconds: Some(1),
                poll_interval_ms: Some(200),
                ..params("call_id == \"never@test\"")
            }))
        };

        let first = json_of(&call().await.expect("ok"));
        let second = json_of(&call().await.expect("ok"));
        for key in [
            "matched",
            "stopped_because",
            "total_matched",
            "polls",
            "scans",
        ] {
            assert_eq!(
                first[key], second[key],
                "{key} differed between two identical calls, so something \
                 survived the first: {first:#} vs {second:#}"
            );
        }
    }
}
