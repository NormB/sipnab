// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-tool call counters behind the `sipnab_mcp_tool_*` metric families.
//!
//! The audit line in `call_tool` already knows the tool, the outcome and how
//! long the call took, and it writes all three to a log nobody aggregates. So
//! the only thing standing between an operator and "which of these tools do
//! agents actually call" was a place to add the three numbers up. Without it
//! the tool surface can only be pruned by argument, because nothing measures
//! which tools are dead.
//!
//! Process-global for the same reason [`crate::security::record_alert`] is:
//! `SipnabMcp` is cloned per HTTP session and the scrape runs on a different
//! thread from every one of them, so a per-server tally would report whichever
//! clone the scraper happened to hold.
//!
//! # Cardinality
//!
//! The tool name arrives from the CLIENT, so it is unbounded input in exactly
//! the way a metric label must not be. Refusals are counted too — an unknown
//! tool name is the probing this counter exists to show — which means a peer
//! looping over random names would otherwise mint a series per attempt. The
//! cap and its overflow bucket below are what make that safe: past
//! `MAX_TOOLS` distinct names the calls still count, under
//! `OVERFLOW_TOOL`, so the total stays right even when the breakdown cannot.

use std::collections::BTreeMap;

use crate::output::prometheus::McpToolTally;

/// Per-tool tallies since the process started, keyed by tool name.
///
/// A `BTreeMap` so a scrape reads the label values already in a stable order,
/// which is the same reason `ALERTS_BY_TYPE` is one.
static TOOL_METRICS: parking_lot::Mutex<BTreeMap<String, McpToolTally>> =
    parking_lot::Mutex::new(BTreeMap::new());

/// Cap on distinct tool names tracked, plus one slot for the overflow bucket.
///
/// The registered surface is around fifty names, so the real set is small and
/// the cap is only ever reached by a caller inventing names. It is set well
/// above the surface so that growing the tool set never silently starts
/// folding real tools into the overflow bucket.
const MAX_TOOLS: usize = 256;

/// Label used once [`MAX_TOOLS`] distinct names have been seen. A visible
/// bucket beats a silent drop, exactly as it does for the alert counter.
const OVERFLOW_TOOL: &str = "other";

/// Count one finished tool call.
///
/// Called from the single `call_tool` choke point, so every outcome the audit
/// line records — `ok`, `tool_error` and every flavor of `refused` — is
/// counted here too. Two surfaces derived from one site cannot disagree about
/// how many calls there were.
///
/// # Arguments
///
/// * `tool` — the tool name the client asked for, registered or not.
/// * `outcome` — the audit line's outcome word (`ok`, `tool_error`,
///   `refused`).
/// * `elapsed` — how long the call took, measured from the same instant the
///   audit line's `elapsed_ms` is.
///
/// # Side effects
///
/// Bumps the process-wide per-tool counters read by [`tallies`], and so by the
/// next `/metrics` scrape.
pub fn record_tool_call(tool: &str, outcome: &str, elapsed: std::time::Duration) {
    record_call_into(&mut TOOL_METRICS.lock(), tool, outcome, elapsed);
}

/// Count the bytes one tool call returned to the caller.
///
/// Separate from [`record_tool_call`] because it answers a different question
/// and is not always answerable: a refusal returns no payload at all, and
/// counting a zero there would drag the per-tool average toward zero every
/// time a rate limit fired. Only calls that produced content reach here.
///
/// # Arguments
///
/// * `tool` — the tool that produced the response.
/// * `bytes` — the response's content bytes.
///
/// # Side effects
///
/// Bumps the process-wide per-tool byte counter read by [`tallies`].
pub fn record_response_bytes(tool: &str, bytes: usize) {
    record_bytes_into(&mut TOOL_METRICS.lock(), tool, bytes);
}

/// The counting rule behind [`record_tool_call`], over a caller-supplied map
/// so the cap, the overflow bucket and the bucketing are testable without
/// touching the global one.
///
/// # Arguments
///
/// * `tallies` — the per-tool map to update.
/// * `tool` — the tool name asked for.
/// * `outcome` — the audit outcome word.
/// * `elapsed` — the call's duration.
fn record_call_into(
    tallies: &mut BTreeMap<String, McpToolTally>,
    tool: &str,
    outcome: &str,
    elapsed: std::time::Duration,
) {
    let Some(tally) = slot(tallies, tool) else {
        return;
    };
    let count = tally
        .calls_by_outcome
        .entry(outcome.to_string())
        .or_insert(0);
    *count = count.saturating_add(1);
    tally.observe_latency(elapsed.as_secs_f64());
}

/// The counting rule behind [`record_response_bytes`], over a caller-supplied
/// map for the reason [`record_call_into`] gives.
///
/// # Arguments
///
/// * `tallies` — the per-tool map to update.
/// * `tool` — the tool that answered.
/// * `bytes` — the response's content bytes.
fn record_bytes_into(tallies: &mut BTreeMap<String, McpToolTally>, tool: &str, bytes: usize) {
    let Some(tally) = slot(tallies, tool) else {
        return;
    };
    tally.response_bytes = tally.response_bytes.saturating_add(bytes as u64);
}

/// The tally `tool` counts against, creating it if there is room.
///
/// `None` only when the map is full AND the overflow bucket itself could not
/// be created, which cannot happen while [`MAX_TOOLS`] is above zero — the
/// overflow name takes a slot of its own the first time it is needed. Written
/// as an `Option` rather than an `expect` so the impossible branch drops the
/// observation instead of ending the process holding an operator's capture.
///
/// # Arguments
///
/// * `tallies` — the per-tool map.
/// * `tool` — the name asked for.
fn slot<'a>(
    tallies: &'a mut BTreeMap<String, McpToolTally>,
    tool: &str,
) -> Option<&'a mut McpToolTally> {
    if tallies.contains_key(tool) {
        return tallies.get_mut(tool);
    }
    if tallies.len() < MAX_TOOLS {
        return Some(tallies.entry(tool.to_string()).or_default());
    }
    // Full: the call still counts, under a name that cannot grow the series
    // set any further. `entry` on the overflow name is what makes the first
    // overflowing call work at all -- it is the one insertion allowed past
    // the cap, and every later one lands on the same key.
    Some(tallies.entry(OVERFLOW_TOOL.to_string()).or_default())
}

/// Every tool's tally since the process started, in label order.
///
/// # Returns
///
/// A snapshot; empty when no tool call has been made. Taken under one lock so
/// the counter, the histogram and the byte total for a given tool describe the
/// same instant rather than three consecutive ones.
#[must_use]
pub fn tallies() -> BTreeMap<String, McpToolTally> {
    TOOL_METRICS.lock().clone()
}

/// Content bytes in one tool response.
///
/// Counts the TEXT of every content block, which is the whole payload for this
/// server: every tool here answers with `ContentBlock::json` or
/// `ContentBlock::text`, and `ContentBlock::json` is itself text
/// (`serde_json::to_string` then `ContentBlock::text`). A block of some other
/// kind would contribute zero rather than a guess, and the doc on the metric
/// says the figure is the text payload rather than the framed wire bytes — the
/// JSON-RPC envelope and its escaping are not measured here.
///
/// The alternative was serializing the response a second time purely to
/// measure it, which doubles the cost of exactly the large answers this metric
/// exists to find.
///
/// # Arguments
///
/// * `result` — the response about to be returned to the caller.
///
/// # Returns
///
/// Bytes of text content, `0` for a response carrying none.
#[must_use]
pub fn response_bytes(result: &rmcp::model::CallToolResponse) -> usize {
    let rmcp::model::CallToolResponse::Complete(complete) = result else {
        // An input-required or task result carries no tool payload yet: the
        // bytes are counted when the call that produces them completes.
        return 0;
    };
    complete
        .content
        .iter()
        .filter_map(rmcp::model::ContentBlock::as_text)
        .map(|t| t.text.len())
        .sum()
}

/// Tests for the per-tool cap, the overflow bucket, latency bucketing and the
/// response-byte measurement.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::prometheus::MCP_TOOL_LATENCY_BUCKETS_SECONDS;

    /// Two calls to one tool with two outcomes count under both, and the
    /// latency histogram counts each once.
    #[test]
    fn calls_count_per_tool_and_outcome() {
        let mut tallies = BTreeMap::new();
        record_call_into(
            &mut tallies,
            "list_dialogs",
            "ok",
            std::time::Duration::from_millis(2),
        );
        record_call_into(
            &mut tallies,
            "list_dialogs",
            "ok",
            std::time::Duration::from_millis(2),
        );
        record_call_into(
            &mut tallies,
            "list_dialogs",
            "refused",
            std::time::Duration::from_millis(2),
        );

        let t = &tallies["list_dialogs"];
        assert_eq!(t.calls_by_outcome["ok"], 2);
        assert_eq!(t.calls_by_outcome["refused"], 1);
        assert_eq!(t.latency_count, 3, "every outcome is timed, not just ok");
    }

    /// An observation lands in the first bucket whose boundary it is at or
    /// below, and one past the last boundary lands in none of them while still
    /// counting toward the total.
    #[test]
    fn latency_lands_in_the_first_bucket_at_or_above_it() {
        let last = MCP_TOOL_LATENCY_BUCKETS_SECONDS
            .last()
            .copied()
            .unwrap_or_default();

        let mut tallies = BTreeMap::new();
        record_call_into(
            &mut tallies,
            "t",
            "ok",
            std::time::Duration::from_secs_f64(last * 2.0),
        );
        let t = &tallies["t"];
        assert_eq!(
            t.latency_buckets.iter().sum::<u64>(),
            0,
            "an observation past the last boundary belongs to +Inf alone"
        );
        assert_eq!(t.latency_count, 1, "and still counts toward the total");

        let first = MCP_TOOL_LATENCY_BUCKETS_SECONDS
            .first()
            .copied()
            .unwrap_or_default();
        let mut tallies = BTreeMap::new();
        record_call_into(
            &mut tallies,
            "t",
            "ok",
            std::time::Duration::from_secs_f64(first / 2.0),
        );
        assert_eq!(
            tallies["t"].latency_buckets[0], 1,
            "a fast call lands in the first bucket"
        );
    }

    /// The `_sum` line accumulates seconds, not milliseconds: the metric is
    /// published in base units and a unit slip here is invisible in the
    /// exposition.
    #[test]
    fn latency_sum_accumulates_seconds() {
        let mut tallies = BTreeMap::new();
        record_call_into(
            &mut tallies,
            "t",
            "ok",
            std::time::Duration::from_millis(250),
        );
        record_call_into(
            &mut tallies,
            "t",
            "ok",
            std::time::Duration::from_millis(750),
        );
        assert!(
            (tallies["t"].latency_sum_seconds - 1.0).abs() < 1e-9,
            "expected 1.0 s, got {}",
            tallies["t"].latency_sum_seconds
        );
    }

    /// Past the cap a new name folds into the overflow bucket rather than
    /// minting a series, and the calls are still counted.
    #[test]
    fn distinct_tool_names_are_capped_with_an_overflow_bucket() {
        let mut tallies = BTreeMap::new();
        for i in 0..MAX_TOOLS {
            record_call_into(
                &mut tallies,
                &format!("tool{i}"),
                "ok",
                std::time::Duration::from_millis(1),
            );
        }
        assert_eq!(tallies.len(), MAX_TOOLS);

        record_call_into(
            &mut tallies,
            "one_too_many",
            "refused",
            std::time::Duration::from_millis(1),
        );
        record_call_into(
            &mut tallies,
            "another_too_many",
            "refused",
            std::time::Duration::from_millis(1),
        );

        assert_eq!(
            tallies.len(),
            MAX_TOOLS + 1,
            "the overflow bucket is the only slot past the cap"
        );
        assert_eq!(
            tallies[OVERFLOW_TOOL].calls_by_outcome["refused"], 2,
            "calls past the cap are folded in, not dropped"
        );
        assert!(
            !tallies.contains_key("one_too_many"),
            "a name past the cap must not mint its own series"
        );
    }

    /// Response bytes accumulate per tool and are kept apart from the call
    /// counters.
    #[test]
    fn response_bytes_accumulate_per_tool() {
        let mut tallies = BTreeMap::new();
        record_bytes_into(&mut tallies, "rtp_stats", 100);
        record_bytes_into(&mut tallies, "rtp_stats", 23);
        record_bytes_into(&mut tallies, "list_dialogs", 7);

        assert_eq!(tallies["rtp_stats"].response_bytes, 123);
        assert_eq!(tallies["list_dialogs"].response_bytes, 7);
        assert_eq!(
            tallies["rtp_stats"].latency_count, 0,
            "a byte observation is not a call observation"
        );
    }

    /// The byte measurement reads the text of every content block, which is
    /// what every tool on this surface returns.
    #[test]
    fn response_bytes_measures_every_text_block() {
        let result = rmcp::model::CallToolResult::success(vec![
            rmcp::model::ContentBlock::text("12345"),
            rmcp::model::ContentBlock::text("678"),
        ]);
        assert_eq!(
            response_bytes(&rmcp::model::CallToolResponse::Complete(result)),
            8,
            "both blocks count -- the provenance note is bytes an agent reads too"
        );
    }

    /// The global recorder reaches the global snapshot. Written as a delta
    /// rather than an absolute, because every test in this binary shares one
    /// process-wide tally.
    #[test]
    fn the_global_recorder_reaches_the_snapshot() {
        let tool = "mcp_metrics_module_test_tool";
        let before = tallies()
            .get(tool)
            .and_then(|t| t.calls_by_outcome.get("ok").copied())
            .unwrap_or(0);

        record_tool_call(tool, "ok", std::time::Duration::from_millis(3));
        record_response_bytes(tool, 42);

        let after = tallies();
        assert_eq!(
            after[tool].calls_by_outcome["ok"],
            before + 1,
            "the global counter moved by exactly one"
        );
        assert!(
            after[tool].response_bytes >= 42,
            "the global byte counter took the observation"
        );
    }
}
