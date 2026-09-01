//! Aggregation tools: questions about a SET of dialogs rather than one.

use crate::mcp::server::SipnabMcp;
use crate::mcp::shape::resolve_limit_with_cap;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Parameters for `timeline`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TimelineParams {
    /// Bucket width in seconds. Defaults to 60.
    #[serde(default)]
    pub bucket_seconds: Option<u64>,
}

/// One `timeline` answer, as an object rather than a bare array.
///
/// VAL16. `timeline` was the last tool on the agent surface answering with a
/// top-level array, which is the shape `DialogPage`'s own doc comment warns
/// about: a payload with no key has nowhere to put `source_exhausted`,
/// `truncated`, or a cursor. The completeness stamp could only reach it as a
/// SECOND content block, which is additive but is not the same as a response
/// that describes itself -- a client reading `result.content[0]` alone got the
/// rows and no idea how much of the capture they covered.
///
/// There is no `truncated` or cursor here because `timeline` takes no `limit`:
/// it returns every bucket in the capture. `returned` is still carried so
/// counting the array is never necessary, and the object gives the stamp
/// somewhere to land.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TimelinePage {
    /// Version of this response schema.
    pub schema_version: u32,
    /// One row per interval, oldest first.
    pub buckets: Vec<crate::mcp::server::TimelineBucket>,
    /// Rows in `buckets`.
    pub returned: usize,
    /// The width actually used, echoed because the caller may have omitted it.
    pub bucket_seconds: u64,
}

/// Dimensions `group_dialogs` accepts beyond the shared
/// [`GROUPABLE`](crate::mcp::server::GROUPABLE) list.
///
/// A strict SUPERSET, which is why it does not repeat the vocabulary mistake
/// `GROUPABLE` warns about. Two tools with overlapping-but-incomparable key
/// sets cannot be learned — an agent has to discover, per tool, which of two
/// sets it is talking to. A superset can: everything `aggregate_dialogs`
/// groups by, `group_dialogs` groups by too, plus these three.
///
/// They live here rather than in the shared list because they earn their place
/// from the METRICS. "Which trunk", "which customer domain" and "which hour"
/// are the questions a per-group ASR exists to answer, and none of them is
/// worth a bucket of bare counts: `timeline` already draws call volume against
/// time, and `dst.ip` already answers "where did the traffic go" when the
/// answer is a count.
const EXTRA_DIMENSIONS: &[&str] = &["to_domain", "hour", "next_hop"];

/// Seconds in the calendar hour the `hour` dimension buckets on.
const HOUR_SECONDS: i64 = 3600;

/// Every metric `group_dialogs` computes, with the unit it is expressed in.
///
/// One table rather than a list and a lookup beside it. The dispatch, the
/// default set, the refusal message and the `units` block all read this, so a
/// metric cannot be offered without a unit, accepted without being computed,
/// or computed in a unit the answer does not name.
const METRICS: &[(&str, &str)] = &[
    ("count", "dialogs"),
    ("asr", "percent"),
    ("ner", "percent"),
    ("acd", "seconds"),
    ("pdd_p50", "milliseconds"),
    ("pdd_p95", "milliseconds"),
    ("mos_p10", "mos"),
    ("retransmit_rate", "retransmissions per dialog"),
];

/// Final INVITE responses that mean the network DELIVERED the call and the
/// far end decided its fate. The numerator of NER, per ITU-T E.411.
///
/// NER exists to separate "the network could not carry this call" from "the
/// network carried it and the callee said no", because those have different
/// owners and only the first is anybody's outage. So each of these is an
/// answer from the destination side: 480 and 486 are the callee unavailable or
/// busy, 600 is busy everywhere, 603 is an explicit decline, and 487 is the
/// CALLER hanging up on a call that had already reached the far end.
///
/// 408 Request Timeout is deliberately absent. A proxy emits it when a
/// transaction went unanswered, which happens for a silent phone and for an
/// unreachable next hop alike — crediting it to the network would credit the
/// network for calls that may never have arrived, which is the exact
/// misattribution NER was defined to prevent. Everything not listed here, and
/// every other 4xx/5xx/6xx, counts as network-ineffective.
const DESTINATION_DECIDED: &[u16] = &[480, 486, 487, 600, 603];

/// Decimal places every metric is rounded to.
///
/// A ratio over three dialogs is not accurate to fourteen decimal places, and
/// printing it that way states a precision the population cannot support. Two
/// is enough to read, and it costs nothing: the population each figure was
/// computed over is published beside it, so a reader who wants the exact ratio
/// divides the two integers.
const METRIC_DECIMALS: f64 = 100.0;

/// Parameters for `group_dialogs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GroupDialogsParams {
    /// The ONE dimension to group by: everything `aggregate_dialogs` accepts
    /// (`state`, `response_code`, `method`, `from.user`, `to.user`, `ua`,
    /// `src.ip`, `dst.ip`, `rtp.codec`) plus `to_domain`, `hour` and
    /// `next_hop`.
    ///
    /// One dimension, for the reason `aggregate_dialogs` gives: two is a pivot
    /// table, and a pivot table wants a UI. Narrow with `filter` instead.
    pub by: String,
    /// Metrics to compute per group. Defaults to all of them.
    ///
    /// `count` is always returned as a field of its own as well, because it is
    /// the one figure no group can fail to have and the denominator a reader
    /// checks every other number against.
    #[serde(default)]
    pub metrics: Option<Vec<String>>,
    /// Optional filter (alias or DSL) applied before grouping, so a grouped
    /// answer can be scoped the same way a listing is.
    #[serde(default)]
    pub filter: Option<String>,
    /// Groups to return, largest first. Bounded by `--mcp-max-rows` and
    /// defaulted the same way `aggregate_dialogs` defaults `top_n`.
    ///
    /// Spelled `top_n` rather than `top` to match the sibling tool: an agent
    /// that learned one parameter name should not have to learn a second for
    /// the same idea.
    #[serde(default)]
    pub top_n: Option<u32>,
}

/// The denominators every figure in [`DialogGroup::metrics`] was computed over.
///
/// Published rather than implied, and that is the whole grounding discipline
/// in one struct. An ASR of 100% over two seizures and an ASR of 100% over two
/// thousand are the same number and not the same evidence, and a reader given
/// only the number cannot tell them apart. Nothing here is a metric; each
/// field is the population one of them rests on.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GroupPopulation {
    /// Dialogs of every kind that fell in this group.
    pub dialogs: usize,
    /// INVITE dialogs that reached a final response — the ASR and NER
    /// denominator. A call still ringing has not been decided, so counting it
    /// as a failed seizure would report an in-progress capture as an outage.
    pub seizures: usize,
    /// Seizures answered with a 2xx — the ASR numerator.
    pub answered: usize,
    /// Seizures the network delivered, per `DESTINATION_DECIDED` — the NER
    /// numerator.
    pub delivered: usize,
    /// Calls that were both answered and torn down inside the capture — the
    /// ACD population. A call still up has no duration yet.
    pub completed_calls: usize,
    /// Dialogs whose post-dial delay was measured — the PDD percentile
    /// population.
    pub pdd_measured: usize,
    /// Dialogs carrying at least one stream whose codec has a published or
    /// operator-declared impairment factor — the MOS percentile population.
    /// Streams without one score a placeholder, not an estimate, and a
    /// percentile over placeholders is a number about nothing.
    pub mos_grounded_dialogs: usize,
    /// Retransmitted messages summed across the group — the
    /// `retransmit_rate` numerator, whose denominator is `dialogs`.
    pub retransmits: u64,
}

/// One group of a `group_dialogs` answer.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DialogGroup {
    /// The grouped value, rendered as a string. A missing value becomes the
    /// literal `"(none)"` rather than being dropped, because "which calls
    /// carry no User-Agent" is a real question and a group set that omits them
    /// would not sum to `total_matched`.
    pub value: String,
    /// Dialogs in this group.
    pub count: usize,
    /// The requested metrics. `null` where the group's population cannot
    /// support the figure; [`Self::not_grounded`] says which population was
    /// missing.
    pub metrics: BTreeMap<String, Option<f64>>,
    /// Why each `null` in [`Self::metrics`] is null, keyed the same way.
    ///
    /// The half that makes a `null` an answer rather than an omission. A
    /// missing ASR reads as a tool that failed; "no INVITE in this group
    /// reached a final response" reads as a group of registrations, which is
    /// what it is.
    pub not_grounded: BTreeMap<String, String>,
    /// What each figure above was computed over.
    pub population: GroupPopulation,
}

/// Answer shape for `group_dialogs`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GroupDialogsResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// Echo of the dimension grouped on, so an answer is self-describing.
    pub group_by: String,
    /// The metrics computed, sorted and de-duplicated.
    pub metrics: Vec<String>,
    /// The unit each computed metric is expressed in.
    ///
    /// Carried in the answer rather than left to the key name, because the
    /// ambiguity is real and expensive: an ASR of `0.65` and an ASR of `65`
    /// describe the same trunk and differ by a factor of a hundred, and a
    /// reader that guesses wrong escalates a healthy carrier.
    pub units: BTreeMap<String, String>,
    /// Groups, largest first, ties broken by value for a stable answer.
    ///
    /// Largest by DIALOG COUNT, not by any metric. A group that ranked itself
    /// by the metric asked for would answer a different question per call and
    /// could not be paged against `other_count`.
    pub groups: Vec<DialogGroup>,
    /// Dialogs in groups beyond `top_n`. Zero when nothing was truncated.
    ///
    /// A count and nothing else, deliberately: an ASR over the remainder would
    /// be an average of averages across groups that were dropped for being
    /// small, which is the arithmetic that turns one busy trunk into a
    /// capture-wide verdict.
    pub other_count: usize,
    /// Distinct values seen, whether or not each got a group.
    pub distinct_values: usize,
    /// Dialogs the filter matched across the WHOLE store. The `count` of every
    /// group plus `other_count` equals this, always.
    pub total_matched: usize,
    /// Which capture this answer came from, and which revision of its stores.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// The host half of a `host[:port]` taken from a SIP URI.
///
/// IPv6 literals are bracketed in a SIP URI (RFC 3261 §19.1.1), so the address
/// ends at the `]` and only a `:` after it can be a port. An unbracketed value
/// carries at most one `:`, and that one is the port — so a value with more
/// than one is returned whole rather than truncated at a colon that is part of
/// an address a peer wrote malformed.
fn host_only(host_port: &str) -> &str {
    if host_port.starts_with('[') {
        return match host_port.find(']') {
            Some(close) => &host_port[..=close],
            None => host_port,
        };
    }
    match host_port.rsplit_once(':') {
        Some((host, _)) if !host.contains(':') => host,
        _ => host_port,
    }
}

/// The group `dialog` falls into for `key`, ready to put in front of a model.
///
/// The shared keys go straight to
/// [`dialog_group_value`](crate::mcp::server::dialog_group_value) rather than
/// being re-extracted here, so the two tools cannot come to disagree about
/// what `ua` or `rtp.codec` means for one dialog.
///
/// `None` for a key this tool does not offer, which the caller reports as an
/// internal error: a dimension added to a list without an arm here is a bug
/// the compiler cannot see, so it fails loudly rather than silently grouping
/// every dialog as one.
fn group_value(
    key: &str,
    dialog: &crate::sip::dialog::SipDialog,
    streams: &[&crate::rtp::stream::RtpStream],
) -> Option<String> {
    match key {
        // The To URI's host, written by whoever sent the request, so it is
        // fenced exactly as `to.user` is.
        "to_domain" => Some(crate::mcp::shape::fence(
            dialog.to_host.as_deref().map_or("(none)", host_only),
        )),
        // The calendar hour the dialog opened in, aligned to the epoch for the
        // reason `timeline_buckets` aligns its buckets there: two captures of
        // the same window then land on the same boundaries and can be laid
        // side by side.
        "hour" => Some(
            chrono::DateTime::from_timestamp(
                dialog
                    .created_at
                    .timestamp()
                    .div_euclid(HOUR_SECONDS)
                    .saturating_mul(HOUR_SECONDS),
                0,
            )
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        // Where the dialog's opening message was addressed on the wire. Read
        // off the IP and transport headers, so it is sipnab's own observation
        // rather than anything a peer claimed in a header -- and it is the
        // next hop only from the vantage point of a capture taken beside the
        // sender, which is where a proxy's own trunk traffic is captured.
        "next_hop" => Some(format!("{}:{}", dialog.dst_addr, dialog.dst_port)),
        _ => crate::mcp::server::dialog_group_value(key, dialog, streams),
    }
}

/// Everything one group needs, accumulated in one pass over the store.
///
/// Populations are counted rather than derived afterwards because most of them
/// cannot be recovered from the others: "answered" and "seizures" are not
/// "count" minus anything, since a group of REGISTER dialogs has a count and
/// no seizures at all.
#[derive(Debug, Clone, Default)]
struct GroupAccumulator {
    /// Every dialog that fell in this group.
    dialogs: usize,
    /// INVITE dialogs that reached a final response.
    seizures: usize,
    /// Seizures answered with a 2xx.
    answered: usize,
    /// Seizures whose final response says the far end decided.
    delivered: usize,
    /// Conversation milliseconds summed over answered-and-ended calls.
    conversation_ms_total: i64,
    /// How many calls contributed to `conversation_ms_total`.
    completed_calls: usize,
    /// Every measured post-dial delay, in milliseconds.
    pdd_ms: Vec<f64>,
    /// One grounded MOS per dialog: the worst across its scorable streams.
    mos: Vec<f64>,
    /// Retransmitted messages summed across the group.
    retransmits: u64,
}

impl GroupAccumulator {
    /// Fold one dialog and its streams into this group.
    fn add(
        &mut self,
        dialog: &crate::sip::dialog::SipDialog,
        streams: &[&crate::rtp::stream::RtpStream],
        delay: crate::rtp::quality::MosDelay<'_>,
    ) {
        self.dialogs += 1;
        self.retransmits += u64::from(dialog.timing.total_retransmits());

        // A seizure is an INVITE that got an answer of some kind. Both halves
        // matter: a REGISTER is not a call attempt, and an INVITE still
        // ringing when the capture ended has not failed -- counting it as a
        // failed seizure reports a live capture as an outage that grows worse
        // the earlier you look.
        if dialog.method == crate::sip::method::SipMethod::Invite
            && let Some(code) = dialog.final_status_code()
        {
            self.seizures += 1;
            if (200..300).contains(&code) {
                self.answered += 1;
                self.delivered += 1;
            } else if DESTINATION_DECIDED.contains(&code) {
                self.delivered += 1;
            }
        }

        if let Some(ms) = dialog.timing.conversation_ms() {
            self.conversation_ms_total = self.conversation_ms_total.saturating_add(ms);
            self.completed_calls += 1;
        }
        if let Some(ms) = dialog.timing.pdd_ms() {
            self.pdd_ms.push(ms as f64);
        }

        // Only streams whose codec has a real impairment factor, and the WORST
        // of them, matching what `rtp.mos` means in the filter DSL. Scoring an
        // unpublished codec would put a placeholder into a percentile, where it
        // is indistinguishable from a measurement.
        if let Some(worst) = streams
            .iter()
            .filter(|s| crate::rtp::quality::mos_is_grounded(s.codec.as_deref()))
            .map(|s| delay.score(s))
            .reduce(f64::min)
        {
            self.mos.push(worst);
        }
    }

    /// This group's value for `metric`.
    ///
    /// `None` for a metric with no extractor — the caller raises that as an
    /// internal error rather than reporting a silent zero. `Some(Err(why))` is
    /// the grounding refusal: the metric exists and this group's population
    /// cannot support it, and `why` names the population that was missing.
    fn value_of(&self, metric: &str) -> Option<Result<f64, String>> {
        /// The refusal an empty population produces, so every branch phrases
        /// it as "what was missing" rather than "no data".
        fn empty(reason: &str) -> Option<Result<f64, String>> {
            Some(Err(reason.to_string()))
        }

        let ratio =
            |numerator: usize, denominator: usize| numerator as f64 * 100.0 / denominator as f64;
        let seizure_refusal = "no INVITE in this group reached a final response, so nothing in \
                               it was a decided call attempt";

        Some(Ok(match metric {
            "count" => self.dialogs as f64,
            "asr" => {
                if self.seizures == 0 {
                    return empty(seizure_refusal);
                }
                ratio(self.answered, self.seizures)
            }
            "ner" => {
                if self.seizures == 0 {
                    return empty(seizure_refusal);
                }
                ratio(self.delivered, self.seizures)
            }
            "acd" => {
                if self.completed_calls == 0 {
                    return empty(
                        "no call in this group was both answered and torn down inside the \
                         capture, so no conversation was timed",
                    );
                }
                self.conversation_ms_total as f64 / self.completed_calls as f64 / 1000.0
            }
            "pdd_p50" | "pdd_p95" => {
                let p = if metric == "pdd_p50" { 50.0 } else { 95.0 };
                let mut sorted = self.pdd_ms.clone();
                crate::sort::sort_by_dyn(&mut sorted, &mut f64::total_cmp);
                match percentile_nearest_rank(&sorted, p) {
                    Some(v) => v,
                    None => {
                        return empty(
                            "no INVITE in this group was followed by a 180 or 183, so post-dial \
                             delay was never measured",
                        );
                    }
                }
            }
            "mos_p10" => {
                let mut sorted = self.mos.clone();
                crate::sort::sort_by_dyn(&mut sorted, &mut f64::total_cmp);
                match percentile_nearest_rank(&sorted, 10.0) {
                    Some(v) => v,
                    None => {
                        return empty(
                            "no stream in this group uses a codec with a published or \
                             operator-declared impairment factor, so every MOS here would be a \
                             placeholder rather than an estimate",
                        );
                    }
                }
            }
            // Never refused: a group exists because a dialog fell into it, so
            // the denominator is at least one. It is a FLOOR rather than an
            // exact figure -- a dialog past `MAX_SEEN_CSEQ_PER_DIALOG` stops
            // recognizing new retransmissions -- and it counts retransmitted
            // messages per dialog, not the share of messages that were
            // retransmissions. The message denominator is the one retention
            // sheds; this one is not.
            "retransmit_rate" => self.retransmits as f64 / self.dialogs.max(1) as f64,
            _ => return None,
        }))
    }
}

/// The value at percentile `p` (0-100) of `sorted`, by nearest rank.
///
/// No interpolation, deliberately. An interpolated p95 returns a number no
/// call experienced, and these percentiles are quoted back to a carrier as
/// evidence about real calls; nearest rank always names an observed sample.
///
/// `None` for an empty slice — a percentile of nothing is not zero.
fn percentile_nearest_rank(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    // ceil(p/100 * n), held inside 1..=n so p=0 still names the smallest
    // sample instead of indexing before the slice.
    let rank = (p / 100.0 * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted.get(rank.min(sorted.len()) - 1).copied()
}

/// `value` at [`METRIC_DECIMALS`], with a non-finite result reported as absent.
///
/// A NaN or an infinity is not a measurement, and `serde_json` cannot carry
/// one anyway — it would serialize as `null` with nothing saying why. Rounding
/// is where both are caught.
fn rounded(value: f64) -> Option<f64> {
    value
        .is_finite()
        .then(|| (value * METRIC_DECIMALS).round() / METRIC_DECIMALS)
}

#[tool_router(router = aggregation_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Call volume over time, in fixed-width buckets.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `bucket_seconds` is zero: a zero-width
    /// bucket has no meaning and dividing by it would panic rather than answer.
    #[tool(
        name = "timeline",
        description = "Call volume over time in fixed-width buckets. Returns one \
                       row per bucket with the count of dialogs that started in \
                       it, so a spike or a gap is visible without reading every \
                       dialog.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn timeline(
        &self,
        Parameters(params): Parameters<TimelineParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let width = params.bucket_seconds.unwrap_or(60);
        if width == 0 {
            return Err(rmcp::ErrorData::invalid_params(
                "bucket_seconds must be greater than zero: a zero-width bucket \
                 describes no interval, and every dialog would fall into all of \
                 them at once",
                None,
            ));
        }
        let buckets = self.timeline_buckets(width);
        let page = TimelinePage {
            schema_version: 1,
            returned: buckets.len(),
            bucket_seconds: width,
            buckets,
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(page)?]))
    }

    /// Carrier metrics per group, computed inside the store.
    ///
    /// `aggregate_dialogs` answers "how many" and stops there. Every question
    /// beginning with WHICH — which trunk is failing, which User-Agent has the
    /// worst audio, which hour it started — needs a rate rather than a count,
    /// and a rate is the thing a language model cannot recover from a page of
    /// rows: it would have to hold every dialog, classify each outcome, and
    /// divide. Agents stop early and answer from the rows they happen to hold,
    /// which is how a truncated page becomes a confident verdict about a
    /// carrier.
    ///
    /// ASR, NER and ACD are the vocabulary carrier engineers already think in,
    /// so they are reported under those names and defined exactly:
    ///
    /// - **ASR**, answer-seizure ratio: 2xx answers over seizures, where a
    ///   seizure is an INVITE dialog that reached a final response.
    /// - **NER**, network effectiveness ratio (ITU-T E.411): seizures the
    ///   network delivered over seizures, crediting the outcomes the far end
    ///   decided — see `DESTINATION_DECIDED`.
    /// - **ACD**, average call duration: mean conversation time of calls that
    ///   were answered and torn down inside the capture, from
    ///   [`DialogTiming::conversation_ms`](crate::sip::timing::DialogTiming::conversation_ms).
    ///
    /// Every figure carries the population it was computed over, and a metric
    /// whose population is empty comes back `null` with the reason beside it
    /// rather than as a number. That is the same discipline `mos_grounded`
    /// applies to a MOS on an unpublished codec, applied to the other seven:
    /// an ASR of zero over a group of registrations is not a failing trunk,
    /// and reporting it as one would be a wrong answer rather than a missing
    /// one.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown or multi-valued `by`, an
    /// unknown metric name, or an unparseable `filter`.
    /// `internal_error` (-32603) for a dimension or metric that is offered and
    /// has no extractor, which is a bug rather than a bad request.
    #[tool(
        name = "group_dialogs",
        description = "Groups dialogs by ONE dimension (state, response_code, \
                       method, from.user, to.user, ua, src.ip, dst.ip, \
                       rtp.codec, to_domain, hour, next_hop) and returns \
                       carrier metrics per group: count, asr, ner, acd, \
                       pdd_p50, pdd_p95, mos_p10, retransmit_rate. Each group \
                       carries the population every figure was computed over, \
                       and a metric its population cannot support comes back \
                       null with the reason in not_grounded rather than as a \
                       number. Groups come back largest-first by dialog count, \
                       plus other_count, so the groups and the remainder \
                       account for total_matched. aggregate_dialogs answers \
                       the same question when a bare count is enough.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn group_dialogs(
        &self,
        Parameters(params): Parameters<GroupDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let key = params.by.trim();
        let dimensions: Vec<&str> = crate::mcp::server::GROUPABLE
            .iter()
            .chain(EXTRA_DIMENSIONS)
            .copied()
            .collect();
        if !dimensions.contains(&key) {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "cannot group by '{key}'; one of: {}. One dimension only -- \
                     narrow with `filter` rather than adding a second.",
                    dimensions.join(", ")
                ),
                None,
            ));
        }

        // Sorted and de-duplicated, so the answer's key order does not depend
        // on the order the caller happened to list them in and a repeated name
        // is not computed twice.
        let wanted: Vec<String> = match params.metrics {
            Some(ref asked) => {
                let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                for m in asked {
                    let m = m.trim();
                    if !METRICS.iter().any(|(name, _)| *name == m) {
                        return Err(rmcp::ErrorData::invalid_params(
                            format!(
                                "unknown metric '{m}'; one of: {}",
                                METRICS
                                    .iter()
                                    .map(|(name, _)| *name)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            None,
                        ));
                    }
                    set.insert(m.to_string());
                }
                set.into_iter().collect()
            }
            None => METRICS
                .iter()
                .map(|(name, _)| (*name).to_string())
                .collect(),
        };

        let top_n = resolve_limit_with_cap(params.top_n, self.row_cap);
        let filter = self.compile_filter(params.filter.as_deref())?;

        let (mut tally, total_matched, capture_identity) = {
            // Capture, dialogs, streams -- the order `CaptureState` documents.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            let delay = crate::rtp::quality::MosDelay::from_capture(&ss);
            let capture = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);

            // Streams grouped by Call-ID once, the way `dialog_page` does it.
            // `streams_for` scans the whole stream store per dialog, and this
            // tool must visit every dialog to compute a rate, so the per-dialog
            // scan would be quadratic in the size of the capture.
            let mut by_call: std::collections::HashMap<&str, Vec<&crate::rtp::stream::RtpStream>> =
                std::collections::HashMap::new();
            for s in ss.iter() {
                if let Some(id) = s.associated_dialog.as_deref() {
                    by_call.entry(id).or_default().push(s);
                }
            }

            const NO_STREAMS: &[&crate::rtp::stream::RtpStream] = &[];
            let mut tally: std::collections::HashMap<String, GroupAccumulator> =
                std::collections::HashMap::new();
            let mut total = 0usize;
            for d in ds.iter() {
                let streams = by_call
                    .get(d.call_id.as_str())
                    .map_or(NO_STREAMS, Vec::as_slice);
                if let Some(expr) = filter.as_ref()
                    && !expr.matches_dialog(d, streams, capture, delay)
                {
                    continue;
                }
                total += 1;
                let Some(value) = group_value(key, d, streams) else {
                    return Err(rmcp::ErrorData::internal_error(
                        format!("dimension '{key}' has no extractor"),
                        None,
                    ));
                };
                tally.entry(value).or_default().add(d, streams, delay);
            }
            (tally, total, capture_identity)
        };

        let distinct_values = tally.len();
        let mut ordered: Vec<(String, GroupAccumulator)> = tally.drain().collect();
        // Largest first, ties broken by value so the same store always gives
        // the same answer -- a cursor-free grouping that reordered between
        // calls would look like the capture changed.
        crate::sort::sort_by_dyn(&mut ordered, &mut |a, b| {
            b.1.dialogs.cmp(&a.1.dialogs).then_with(|| a.0.cmp(&b.0))
        });
        let other_count: usize = ordered.iter().skip(top_n).map(|(_, a)| a.dialogs).sum();

        let mut groups = Vec::with_capacity(ordered.len().min(top_n));
        for (value, acc) in ordered.into_iter().take(top_n) {
            let mut metrics = BTreeMap::new();
            let mut not_grounded = BTreeMap::new();
            for m in &wanted {
                match acc.value_of(m) {
                    Some(Ok(v)) => {
                        // A non-finite result is not a measurement either, so
                        // it takes the same road as an empty population rather
                        // than serializing as a bare null.
                        match rounded(v) {
                            Some(v) => {
                                metrics.insert(m.clone(), Some(v));
                            }
                            None => {
                                metrics.insert(m.clone(), None);
                                not_grounded.insert(
                                    m.clone(),
                                    "the computed value is not a finite number".to_string(),
                                );
                            }
                        }
                    }
                    Some(Err(why)) => {
                        metrics.insert(m.clone(), None);
                        not_grounded.insert(m.clone(), why);
                    }
                    None => {
                        return Err(rmcp::ErrorData::internal_error(
                            format!("metric '{m}' has no extractor"),
                            None,
                        ));
                    }
                }
            }
            groups.push(DialogGroup {
                value,
                count: acc.dialogs,
                metrics,
                not_grounded,
                population: GroupPopulation {
                    dialogs: acc.dialogs,
                    seizures: acc.seizures,
                    answered: acc.answered,
                    delivered: acc.delivered,
                    completed_calls: acc.completed_calls,
                    pdd_measured: acc.pdd_ms.len(),
                    mos_grounded_dialogs: acc.mos.len(),
                    retransmits: acc.retransmits,
                },
            });
        }

        let units = wanted
            .iter()
            .filter_map(|m| {
                METRICS
                    .iter()
                    .find(|(name, _)| name == m)
                    .map(|(_, unit)| (m.clone(), (*unit).to_string()))
            })
            .collect();

        let response = GroupDialogsResponse {
            schema_version: 1,
            group_by: key.to_string(),
            metrics: wanted,
            units,
            groups,
            other_count,
            distinct_values,
            total_matched,
            capture_identity,
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(response)?]))
    }
}

/// Tests for `group_dialogs`: the metric definitions, the grounding refusals,
/// and the dimensions this tool adds over `aggregate_dialogs`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::SipMessage;
    use crate::sip::dialog_store::DialogStore;
    use chrono::{DateTime, TimeDelta, Utc};
    use parking_lot::RwLock;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// The address every fixture message is sent FROM, so `src.ip` puts a
    /// whole fixture in one group unless a test says otherwise.
    fn from_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    /// The address every fixture message is sent TO, which is also what
    /// `next_hop` reports.
    fn to_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    /// Fixed base timestamp, so every derived duration is exact.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
            .single()
            .expect("2024-06-15T12:00:00Z is unambiguous")
    }

    /// `base_ts()` plus `secs`.
    fn at(secs: i64) -> DateTime<Utc> {
        base_ts() + TimeDelta::seconds(secs)
    }

    /// Parse fixture SIP sent to `dst:dst_port` at `ts`.
    fn sip(
        first_line: &str,
        headers: &[&str],
        ts: DateTime<Utc>,
        dst: IpAddr,
        dst_port: u16,
    ) -> SipMessage {
        let raw = crate::test_utils::build_sip_message(first_line, headers, b"");
        crate::sip::parser::parse_sip(
            &raw,
            ts,
            from_addr(),
            dst,
            5060,
            dst_port,
            TransportProto::Udp,
        )
        .expect("fixture SIP must parse")
    }

    /// An INVITE for `call_id` whose To URI is `to_uri`.
    fn invite_to(call_id: &str, to_uri: &str, ts: DateTime<Utc>, port: u16) -> SipMessage {
        sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                "From: Alice <sip:alice@example.com>;tag=t1",
                &format!("To: <{to_uri}>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "User-Agent: TestUA/1.0",
                "Content-Length: 0",
            ],
            ts,
            to_addr(),
            port,
        )
    }

    /// An INVITE for `call_id` to the default callee.
    fn invite(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        invite_to(call_id, "sip:bob@example.com", ts, 5060)
    }

    /// A response to `call_id`'s initial INVITE.
    fn invite_response(call_id: &str, status_line: &str, ts: DateTime<Utc>) -> SipMessage {
        sip(
            status_line,
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Contact: <sip:bob@10.0.0.2>",
                "Content-Length: 0",
            ],
            ts,
            to_addr(),
            5060,
        )
    }

    /// The BYE that ends `call_id`.
    fn bye(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        sip(
            "BYE sip:alice@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKbye{call_id}"),
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
            ts,
            to_addr(),
            5060,
        )
    }

    /// A REGISTER and its 200 OK — a dialog that is not a call attempt.
    fn registration(call_id: &str, ts: DateTime<Utc>) -> Vec<SipMessage> {
        let headers = |line: &str, tagged: bool, ts: DateTime<Utc>| {
            sip(
                line,
                &[
                    &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                    "From: Alice <sip:alice@example.com>;tag=t1",
                    if tagged {
                        "To: <sip:alice@example.com>;tag=t2"
                    } else {
                        "To: <sip:alice@example.com>"
                    },
                    &format!("Call-ID: {call_id}"),
                    "CSeq: 1 REGISTER",
                    "Content-Length: 0",
                ],
                ts,
                to_addr(),
                5060,
            )
        };
        vec![
            headers("REGISTER sip:example.com SIP/2.0", false, ts),
            headers("SIP/2.0 200 OK", true, ts + TimeDelta::milliseconds(20)),
        ]
    }

    /// A server whose dialog store holds exactly `messages`, in order.
    fn server_of(messages: Vec<SipMessage>) -> SipnabMcp {
        server_of_with_media(messages, &[])
    }

    /// A server holding `messages` plus one linked RTP stream per
    /// `(call_id, payload_type)`, so MOS grounding can be exercised.
    fn server_of_with_media(messages: Vec<SipMessage>, media: &[(&str, u8)]) -> SipnabMcp {
        let mut ds = DialogStore::new(100, false);
        for m in messages {
            ds.process_message(m);
        }
        let mut ss = StreamStore::new(100);
        for (i, (call_id, pt)) in media.iter().enumerate() {
            let port = 30000 + (i as u16) * 2;
            let header = crate::rtp::parser::RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: *pt,
                sequence: 1,
                timestamp: 160,
                ssrc: 0xA000 + i as u32,
                payload_offset: 12,
            };
            let packet = crate::capture::parse::ParsedPacket {
                frame_bytes: None,
                frame: None,
                timestamp: base_ts(),
                src_addr: from_addr(),
                dst_addr: to_addr(),
                src_port: 40000 + i as u16,
                dst_port: port,
                transport: TransportProto::Udp,
                payload: vec![0u8; 12 + 160].into(),
                ip_id: None,
                tcp_seq: None,
                tcp_flags: None,
                fragment_offset: None,
                more_fragments: false,
                ip_protocol: 17,
                dscp: None,
                input_origin: crate::capture::parse::InputOrigin::Wire,
                hep: None,
            };
            ss.process_rtp(&packet, &header, base_ts());
            ss.link_to_dialog(to_addr(), port, call_id);
        }
        SipnabMcp::new(Arc::new(RwLock::new(ds)), Arc::new(RwLock::new(ss)))
    }

    /// The payload block of a tool result, skipping the provenance note.
    fn payload(result: &rmcp::model::CallToolResult) -> serde_json::Value {
        let note = crate::mcp::shape::untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("a payload block that is not the note");
        serde_json::from_str(&text).expect("the payload is JSON")
    }

    /// Call `group_dialogs` and return its parsed answer.
    async fn grouped(server: &SipnabMcp, by: &str) -> serde_json::Value {
        let result = server
            .group_dialogs(Parameters(GroupDialogsParams {
                by: by.to_string(),
                ..Default::default()
            }))
            .await
            .expect("group_dialogs should succeed");
        payload(&result)
    }

    /// The single group of a one-group answer.
    fn only_group(v: &serde_json::Value) -> &serde_json::Value {
        let groups = v["groups"].as_array().expect("groups array");
        assert_eq!(groups.len(), 1, "expected exactly one group: {v}");
        &groups[0]
    }

    /// Nearest rank names a sample that was actually observed, at both ends.
    ///
    /// An interpolating percentile would answer 25 for the median of
    /// `[10, 20, 30, 40]`, which is a post-dial delay no call in the set ever
    /// had — and these figures are quoted back to a carrier as evidence about
    /// real calls.
    #[test]
    fn percentile_nearest_rank_names_an_observed_sample() {
        let samples = [10.0, 20.0, 30.0, 40.0];
        assert_eq!(percentile_nearest_rank(&samples, 50.0), Some(20.0));
        assert_eq!(percentile_nearest_rank(&samples, 95.0), Some(40.0));
        // p10 of four samples rounds up to rank 1: the worst one, not a
        // fraction of it, and not an index before the slice.
        assert_eq!(percentile_nearest_rank(&samples, 10.0), Some(10.0));
        assert_eq!(percentile_nearest_rank(&samples, 0.0), Some(10.0));
        assert_eq!(
            percentile_nearest_rank(&[], 50.0),
            None,
            "a percentile of nothing is not zero"
        );
    }

    /// A port is stripped and an address is not.
    ///
    /// The IPv6 arm is the one that matters: `[2001:db8::1]` split at its last
    /// colon yields `[2001:db8:`, which is neither a host nor a group anybody
    /// could act on.
    #[test]
    fn host_only_strips_a_port_and_keeps_an_address() {
        assert_eq!(host_only("example.com:5060"), "example.com");
        assert_eq!(host_only("example.com"), "example.com");
        assert_eq!(host_only("[2001:db8::1]:5060"), "[2001:db8::1]");
        assert_eq!(host_only("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(host_only("2001:db8::1"), "2001:db8::1");
    }

    /// A value that is not a finite number never reaches the answer as one.
    #[test]
    fn rounded_refuses_a_value_that_is_not_a_number() {
        assert_eq!(rounded(66.66666), Some(66.67));
        assert_eq!(rounded(f64::NAN), None);
        assert_eq!(rounded(f64::INFINITY), None);
    }

    /// The whole point of the tool: a RATE per group, not a count.
    ///
    /// `aggregate_dialogs` answers "42 calls from this IP" and the agent still
    /// has to page every one of them to learn that a third failed. Three
    /// seizures, two answered, is an ASR of 66.67% and the population that
    /// produced it.
    #[tokio::test]
    async fn group_dialogs_returns_a_rate_and_the_population_under_it() {
        let mut msgs = Vec::new();
        for (id, status) in [
            ("a@h", "SIP/2.0 200 OK"),
            ("b@h", "SIP/2.0 200 OK"),
            ("c@h", "SIP/2.0 503 Service Unavailable"),
        ] {
            msgs.push(invite(id, base_ts()));
            msgs.push(invite_response(id, status, at(1)));
        }
        let v = grouped(&server_of(msgs), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(g["count"], 3);
        assert_eq!(g["metrics"]["asr"], 66.67, "two answers over three: {v}");
        assert_eq!(
            g["metrics"]["ner"], 66.67,
            "a 503 is the network failing, so NER matches ASR here: {v}"
        );
        assert_eq!(g["population"]["seizures"], 3);
        assert_eq!(g["population"]["answered"], 2);
        assert_eq!(
            v["units"]["asr"], "percent",
            "the answer names its own unit, because 0.67 and 67 differ by a \
             factor of a hundred: {v}"
        );
        assert!(
            v["capture_identity"]["instance"].is_string(),
            "an answer that cannot say which capture it came from cannot be \
             checked against a later one: {v}"
        );
    }

    /// NER credits the far end where ASR does not.
    ///
    /// A trunk full of 486s has an ASR of zero and is working perfectly: the
    /// network delivered every call and the callee was busy. Reading the ASR
    /// alone is how a healthy carrier gets escalated.
    #[tokio::test]
    async fn ner_credits_the_far_end_where_asr_does_not() {
        let msgs = vec![
            invite("busy@h", base_ts()),
            invite_response("busy@h", "SIP/2.0 486 Busy Here", at(1)),
        ];
        let v = grouped(&server_of(msgs), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(g["metrics"]["asr"], 0.0, "nobody answered: {v}");
        assert_eq!(
            g["metrics"]["ner"], 100.0,
            "the network delivered the call and the callee was busy: {v}"
        );
        assert_eq!(g["population"]["delivered"], 1);
    }

    /// A metric whose population is empty says which population was missing.
    ///
    /// Registrations are not call attempts. An ASR of 0 here would name a
    /// working registrar as a dead trunk, which is a wrong answer rather than
    /// a missing one.
    #[tokio::test]
    async fn a_population_that_cannot_support_a_metric_says_so() {
        let v = grouped(&server_of(registration("reg@h", base_ts())), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(g["count"], 1, "the dialog is still counted: {v}");
        assert!(
            g["metrics"]["asr"].is_null(),
            "a registration is not a seizure: {v}"
        );
        let why = g["not_grounded"]["asr"]
            .as_str()
            .expect("a null metric carries its reason");
        assert!(
            why.contains("INVITE") && why.contains("final response"),
            "the reason must name the population that was missing: {why}"
        );
        assert_eq!(g["population"]["seizures"], 0);
    }

    /// ACD times the conversation, not the dialog.
    ///
    /// The dialog spans 66 seconds and the conversation is 60 of them: the
    /// caller spent five listening to ring-back and one more on the BYE
    /// handshake. Averaging the dialog span bills the caller for the ringing,
    /// which is not what any carrier means by average call duration.
    #[tokio::test]
    async fn acd_times_the_conversation_and_not_the_dialog_span() {
        let msgs = vec![
            invite("talk@h", base_ts()),
            invite_response("talk@h", "SIP/2.0 200 OK", at(5)),
            bye("talk@h", at(65)),
            sip(
                "SIP/2.0 200 OK",
                &[
                    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKbyetalk@h",
                    "From: Alice <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: talk@h",
                    "CSeq: 2 BYE",
                    "Content-Length: 0",
                ],
                at(66),
                to_addr(),
                5060,
            ),
        ];
        let v = grouped(&server_of(msgs), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(
            g["metrics"]["acd"], 60.0,
            "200 OK to BYE is 60s; the dialog spans 66: {v}"
        );
        assert_eq!(g["population"]["completed_calls"], 1);
    }

    /// PDD percentiles are computed over the calls that HAVE a PDD.
    ///
    /// A call that never rang has no post-dial delay. Reading it as zero drags
    /// the median toward the floor and turns a slow trunk into a fast one —
    /// the same substitution that made `rtp.mos < 3.0` select every call with
    /// no RTP at all.
    #[tokio::test]
    async fn pdd_percentiles_ignore_calls_that_never_rang() {
        let mut msgs = Vec::new();
        for (id, ring_ms) in [("p1@h", 100), ("p2@h", 200), ("p3@h", 5000)] {
            msgs.push(invite(id, base_ts()));
            msgs.push(invite_response(
                id,
                "SIP/2.0 180 Ringing",
                base_ts() + TimeDelta::milliseconds(ring_ms),
            ));
            msgs.push(invite_response(id, "SIP/2.0 200 OK", at(10)));
        }
        // A fourth call that failed before any provisional response.
        msgs.push(invite("p4@h", base_ts()));
        msgs.push(invite_response("p4@h", "SIP/2.0 404 Not Found", at(1)));

        let v = grouped(&server_of(msgs), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(g["count"], 4);
        assert_eq!(
            g["population"]["pdd_measured"], 3,
            "the call that never rang contributes no sample: {v}"
        );
        assert_eq!(g["metrics"]["pdd_p50"], 200.0, "{v}");
        assert_eq!(g["metrics"]["pdd_p95"], 5000.0, "{v}");
    }

    /// A MOS percentile over a codec with no published impairment factor is
    /// refused, and one over G.711 is not.
    ///
    /// The score sipnab returns for G.722 is byte-identical to a grounded
    /// G.711 one and means "unknown". A p10 built out of those is a number
    /// about nothing, presented in the shape of a measurement.
    #[tokio::test]
    async fn mos_p10_refuses_a_codec_with_no_published_impairment_factor() {
        let call = |id: &str| {
            vec![
                invite(id, base_ts()),
                invite_response(id, "SIP/2.0 200 OK", at(1)),
            ]
        };

        let ungrounded = server_of_with_media(call("g722@h"), &[("g722@h", 9)]);
        let v = grouped(&ungrounded, "src.ip").await;
        let g = only_group(&v);
        assert!(
            g["metrics"]["mos_p10"].is_null(),
            "G.722 is unpublished: {v}"
        );
        assert_eq!(g["population"]["mos_grounded_dialogs"], 0);
        let why = g["not_grounded"]["mos_p10"]
            .as_str()
            .expect("a null metric carries its reason");
        assert!(
            why.contains("impairment factor"),
            "the reason must name what is missing: {why}"
        );

        let grounded = server_of_with_media(call("pcmu@h"), &[("pcmu@h", 0)]);
        let v = grouped(&grounded, "src.ip").await;
        let g = only_group(&v);
        assert!(
            g["metrics"]["mos_p10"].as_f64().is_some_and(|m| m > 1.0),
            "PCMU is published, so the percentile is a real estimate: {v}"
        );
        assert_eq!(g["population"]["mos_grounded_dialogs"], 1);
    }

    /// `retransmit_rate` counts retransmitted messages per dialog.
    ///
    /// Per DIALOG rather than per message, because the message denominator is
    /// the one retention sheds: compaction and the per-dialog message cap both
    /// drop stored messages, while the CSeq set that detects a retransmission
    /// survives them.
    #[tokio::test]
    async fn retransmit_rate_counts_retransmissions_per_dialog() {
        let msgs = vec![
            invite("rtx@h", base_ts()),
            // The same INVITE again: one retransmission.
            invite("rtx@h", at(1)),
            invite_response("rtx@h", "SIP/2.0 200 OK", at(2)),
            invite("quiet@h", base_ts()),
            invite_response("quiet@h", "SIP/2.0 200 OK", at(1)),
        ];
        let v = grouped(&server_of(msgs), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(g["count"], 2);
        assert_eq!(g["population"]["retransmits"], 1);
        assert_eq!(
            g["metrics"]["retransmit_rate"], 0.5,
            "one retransmission across two dialogs: {v}"
        );
    }

    /// `hour` groups on the calendar hour a call started in.
    ///
    /// The dimension `aggregate_dialogs` deliberately does not have, and the
    /// one that turns "the ASR is bad" into "the ASR is bad after 14:00".
    /// Buckets are aligned to the epoch, so two captures of the same window
    /// land on the same boundaries.
    #[tokio::test]
    async fn hour_groups_on_the_calendar_hour() {
        // Two minutes past the hour, deliberately: a timestamp already on a
        // boundary would pass whether or not anything truncated it.
        let msgs = vec![
            invite("early@h", at(120)),
            invite_response("early@h", "SIP/2.0 200 OK", at(121)),
            invite("late@h", at(3720)),
            invite_response("late@h", "SIP/2.0 200 OK", at(3721)),
        ];
        let v = grouped(&server_of(msgs), "hour").await;

        let groups = v["groups"].as_array().expect("groups array");
        assert_eq!(groups.len(), 2, "two hours, two groups: {v}");
        let mut hours: Vec<&str> = groups
            .iter()
            .filter_map(|g| g["value"].as_str())
            .collect::<Vec<_>>();
        hours.sort_unstable();
        assert_eq!(
            hours,
            vec!["2024-06-15T12:00:00Z", "2024-06-15T13:00:00Z"],
            "each group names the hour it starts, truncated to the hour: {v}"
        );
    }

    /// `next_hop` names the peer the opening message was addressed to, and
    /// `to_domain` names the callee's domain.
    ///
    /// The two questions a carrier engineer asks first — which trunk, which
    /// customer — and neither was reachable before.
    #[tokio::test]
    async fn next_hop_names_the_peer_and_to_domain_names_the_callee_domain() {
        let msgs = vec![
            invite_to("t1@h", "sip:bob@carrier-a.example:5060", base_ts(), 5080),
            invite_response("t1@h", "SIP/2.0 200 OK", at(1)),
        ];
        let server = server_of(msgs);

        let v = grouped(&server, "next_hop").await;
        assert_eq!(
            only_group(&v)["value"],
            "10.0.0.2:5080",
            "the transport peer the INVITE was addressed to: {v}"
        );

        let v = grouped(&server, "to_domain").await;
        let value = only_group(&v)["value"]
            .as_str()
            .expect("a group value")
            .to_string();
        assert!(
            value.contains("carrier-a.example"),
            "the To URI's host, with the port stripped: {value}"
        );
        assert!(
            !value.contains(":5060"),
            "the port is not part of the domain: {value}"
        );
        assert!(
            value.contains(crate::mcp::shape::UNTRUSTED_OPEN),
            "a To URI is written by the sender and must be fenced: {value}"
        );
    }

    /// A derived dimension is not fenced.
    ///
    /// `next_hop` is read off the IP and transport headers — sipnab's own
    /// observation — and fencing it would tell the agent to distrust the
    /// analysis rather than the traffic.
    #[tokio::test]
    async fn a_derived_dimension_is_not_fenced() {
        let msgs = vec![
            invite("d@h", base_ts()),
            invite_response("d@h", "SIP/2.0 200 OK", at(1)),
        ];
        let v = grouped(&server_of(msgs), "next_hop").await;
        let value = only_group(&v)["value"].as_str().expect("a group value");
        assert!(
            !value.contains(crate::mcp::shape::UNTRUSTED_OPEN),
            "an address sipnab read off the wire is not sender-written: {value}"
        );
    }

    /// Groups plus the remainder account for every matched dialog.
    ///
    /// A truncated grouping that does not say what it left out is a wrong
    /// total rather than a partial one — and the remainder carries a count and
    /// no metrics, because an ASR averaged across the groups that were dropped
    /// for being small is how one busy trunk becomes a capture-wide verdict.
    #[tokio::test]
    async fn groups_and_other_count_account_for_every_matched_dialog() {
        let msgs = vec![
            invite("h1@h", base_ts()),
            invite_response("h1@h", "SIP/2.0 200 OK", at(1)),
            invite("h2@h", at(3600)),
            invite_response("h2@h", "SIP/2.0 200 OK", at(3601)),
            invite("h3@h", at(7200)),
            invite_response("h3@h", "SIP/2.0 200 OK", at(7201)),
        ];
        let result = server_of(msgs)
            .group_dialogs(Parameters(GroupDialogsParams {
                by: "hour".to_string(),
                top_n: Some(1),
                ..Default::default()
            }))
            .await
            .expect("group_dialogs should succeed");
        let v = payload(&result);

        let groups = v["groups"].as_array().expect("groups array");
        assert_eq!(groups.len(), 1, "top_n bounded the answer: {v}");
        assert_eq!(v["distinct_values"], 3, "three hours were seen: {v}");
        let returned: u64 = groups
            .iter()
            .filter_map(|g| g["count"].as_u64())
            .sum::<u64>();
        assert_eq!(
            returned + v["other_count"].as_u64().expect("other_count"),
            v["total_matched"].as_u64().expect("total_matched"),
            "the groups and the remainder must account for every matched \
             dialog: {v}"
        );
    }

    /// Only the metrics asked for are computed, and each names its unit.
    #[tokio::test]
    async fn a_metric_subset_is_honored_and_carries_its_units() {
        let msgs = vec![
            invite("m@h", base_ts()),
            invite_response("m@h", "SIP/2.0 200 OK", at(1)),
        ];
        let result = server_of(msgs)
            .group_dialogs(Parameters(GroupDialogsParams {
                by: "src.ip".to_string(),
                metrics: Some(vec!["ner".to_string(), "asr".to_string()]),
                ..Default::default()
            }))
            .await
            .expect("group_dialogs should succeed");
        let v = payload(&result);

        assert_eq!(
            v["metrics"],
            serde_json::json!(["asr", "ner"]),
            "sorted, so the key order does not depend on the request: {v}"
        );
        let metrics = only_group(&v)["metrics"]
            .as_object()
            .expect("metrics object");
        assert_eq!(
            metrics.len(),
            2,
            "nothing beyond the requested pair was computed: {v}"
        );
        assert_eq!(v["units"]["ner"], "percent");
        assert!(
            v["units"].as_object().expect("units object").len() == 2,
            "units describe exactly what was computed: {v}"
        );
    }

    /// An unknown dimension and an unknown metric are both refused, and each
    /// refusal names the legal set so the agent does not guess again.
    #[tokio::test]
    async fn an_unknown_dimension_and_an_unknown_metric_are_refused() {
        let server = server_of(vec![invite("x@h", base_ts())]);

        for bad in ["src.ip,hour", "created_at", "payload"] {
            let err = server
                .group_dialogs(Parameters(GroupDialogsParams {
                    by: bad.to_string(),
                    ..Default::default()
                }))
                .await
                .expect_err("an unknown or multi-valued dimension must be refused");
            let json = serde_json::to_value(err).expect("the error serializes");
            assert_eq!(json["code"], -32602, "refused as invalid_params: {bad}");
            let msg = json["message"].as_str().unwrap_or_default();
            assert!(
                msg.contains("src.ip") && msg.contains("next_hop"),
                "the refusal must name what IS groupable, the added dimensions \
                 included: {msg}"
            );
        }

        let err = server
            .group_dialogs(Parameters(GroupDialogsParams {
                by: "src.ip".to_string(),
                metrics: Some(vec!["acd".to_string(), "abr".to_string()]),
                ..Default::default()
            }))
            .await
            .expect_err("an unknown metric must be refused");
        let json = serde_json::to_value(err).expect("the error serializes");
        assert_eq!(json["code"], -32602);
        let msg = json["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("abr") && msg.contains("asr"),
            "the refusal must name the typo AND the legal set: {msg}"
        );
    }

    /// A seizure is an INVITE dialog, not any dialog that saw an INVITE
    /// response.
    ///
    /// A UA that reuses one Call-ID for its OPTIONS keepalives and for a call
    /// puts an INVITE-CSeq response inside a dialog that is not a call
    /// attempt. Counting it as a seizure reports a keepalive channel as a
    /// trunk with a perfect ASR, which is a confident wrong answer about a
    /// dimension an operator is about to act on.
    #[tokio::test]
    async fn a_seizure_is_an_invite_dialog_and_not_a_keepalive_that_saw_one() {
        let keepalive = sip(
            "OPTIONS sip:example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKopt",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:example.com>",
                "Call-ID: mixed@h",
                "CSeq: 1 OPTIONS",
                "Content-Length: 0",
            ],
            base_ts(),
            to_addr(),
            5060,
        );
        let stray_invite_response = sip(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKopt2",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:example.com>;tag=t2",
                "Call-ID: mixed@h",
                "CSeq: 2 INVITE",
                "Content-Length: 0",
            ],
            at(1),
            to_addr(),
            5060,
        );
        let v = grouped(&server_of(vec![keepalive, stray_invite_response]), "src.ip").await;

        let g = only_group(&v);
        assert_eq!(g["count"], 1, "the dialog is still counted: {v}");
        assert_eq!(
            g["population"]["seizures"], 0,
            "an OPTIONS dialog is not a call attempt: {v}"
        );
        assert!(
            g["metrics"]["asr"].is_null(),
            "and so it has no answer-seizure ratio at all: {v}"
        );
    }

    /// A filter scopes a grouped answer the way it scopes a listing.
    #[tokio::test]
    async fn a_filter_scopes_the_grouping() {
        let msgs = vec![
            invite("ok@h", base_ts()),
            invite_response("ok@h", "SIP/2.0 200 OK", at(1)),
            invite("bad@h", base_ts()),
            invite_response("bad@h", "SIP/2.0 503 Service Unavailable", at(1)),
        ];
        let result = server_of(msgs)
            .group_dialogs(Parameters(GroupDialogsParams {
                by: "src.ip".to_string(),
                filter: Some("response_code == 503".to_string()),
                ..Default::default()
            }))
            .await
            .expect("group_dialogs should succeed");
        let v = payload(&result);

        assert_eq!(v["total_matched"], 1, "the filter ran before grouping: {v}");
        let g = only_group(&v);
        assert_eq!(g["metrics"]["asr"], 0.0, "only the failure survived: {v}");
    }
    // --- `timeline` -------------------------------------------------------
    //
    // These pay a debt. `timeline` shipped with its two load-bearing
    // properties stated only in a doc comment: buckets align to the epoch, and
    // empty buckets survive. A property asserted in prose is a property nobody
    // checks, and both are the kind that break silently -- a shifted boundary
    // still returns plausible counts, and a dropped gap still renders a chart.

    /// A gap between calls must appear as a bucket with zero in it.
    ///
    /// This is the whole reason an operator reads a timeline. A trunk that died
    /// for two minutes and a trunk that never had traffic there produce the
    /// same rows if empty buckets are dropped -- the series just gets shorter,
    /// which reads as continuous traffic rather than as an outage.
    #[test]
    fn timeline_keeps_the_empty_bucket_that_is_the_outage() {
        // One call, a two-minute silence, then one more.
        let server = server_of(vec![
            invite_to("a", "sip:bob@example.com", at(0), 20000),
            invite_to("b", "sip:bob@example.com", at(180), 20002),
        ]);
        let rows = server.timeline_buckets(60);
        assert_eq!(
            rows.len(),
            4,
            "three minutes of span at 60s must be four buckets, gap included: {rows:?}"
        );
        let counts: Vec<u64> = rows.iter().map(|r| r.dialogs).collect();
        assert_eq!(
            counts,
            vec![1, 0, 0, 1],
            "the two silent minutes must be reported as zeros, not skipped: {rows:?}"
        );
    }

    /// Buckets align to the epoch, not to the first dialog.
    ///
    /// Two captures of the same window must produce boundaries that line up, or
    /// they cannot be laid against each other -- which is the entire point of
    /// comparing a baseline to today. Aligning to the earliest call instead
    /// moves every boundary whenever that one call moves.
    #[test]
    fn timeline_buckets_align_to_the_epoch_not_to_the_first_call() {
        // 12:00:37 is deliberately NOT on a bucket boundary.
        let offset = 37;
        let server = server_of(vec![invite_to(
            "a",
            "sip:bob@example.com",
            at(offset),
            20000,
        )]);
        let rows = server.timeline_buckets(60);
        assert_eq!(rows.len(), 1, "one call is one bucket: {rows:?}");
        assert_eq!(
            rows[0].start.timestamp() % 60,
            0,
            "the bucket must start on a multiple of its width, not at the \
             call's own second: {rows:?}"
        );
        assert!(
            rows[0].start <= at(offset),
            "the bucket must CONTAIN the call it counts: {rows:?}"
        );
    }

    /// An empty store yields no rows rather than one bucket of zero.
    ///
    /// A single empty bucket would name an interval that no capture covers,
    /// which is a claim about a window nobody observed.
    #[test]
    fn timeline_of_an_empty_store_is_empty() {
        let server = server_of(vec![]);
        assert!(
            server.timeline_buckets(60).is_empty(),
            "no dialogs means no intervals to report"
        );
    }

    /// The width the caller asked for is the width they get, and it is echoed.
    #[test]
    fn timeline_honors_the_requested_width_and_echoes_it() {
        let server = server_of(vec![
            invite_to("a", "sip:bob@example.com", at(0), 20000),
            invite_to("b", "sip:bob@example.com", at(700), 20002),
        ]);
        let rows = server.timeline_buckets(300);
        assert!(
            rows.iter().all(|r| r.bucket_seconds == 300),
            "each row must carry the width it was built at, so a row is \
             readable on its own: {rows:?}"
        );
        assert_eq!(
            rows.len(),
            3,
            "0s and 700s are two 300s buckets apart, so three rows with the \
             middle one empty: {rows:?}"
        );
        assert_eq!(rows[1].dialogs, 0, "the middle bucket is the gap: {rows:?}");
    }

    /// A zero width is refused rather than dividing by zero.
    #[tokio::test]
    async fn timeline_refuses_a_zero_width_bucket() {
        let server = server_of(vec![invite_to("a", "sip:bob@example.com", at(0), 20000)]);
        let err = server
            .timeline(Parameters(TimelineParams {
                bucket_seconds: Some(0),
            }))
            .await
            .expect_err("a zero-width bucket must be refused");
        assert!(
            err.message.contains("greater than zero"),
            "the refusal must name the constraint it enforced: {err:?}"
        );
    }
}
