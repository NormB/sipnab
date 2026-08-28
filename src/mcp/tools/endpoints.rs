// SPDX-License-Identifier: MIT OR Apache-2.0

//! Endpoint tools: questions about one PARTICIPANT rather than one call.
//!
//! Every other tool on this surface is keyed by Call-ID, which is the right
//! shape for "why did this call fail" and the wrong shape for the question that
//! comes before it. An operator handed a complaint has a phone, a trunk or a
//! subscriber — an address and a name — and wants to know what that thing has
//! been doing. Answering that from a dialog-centric surface means listing every
//! dialog, filtering client-side, and re-deriving per-entity facts the stores
//! already hold.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::mcp::server::SipnabMcp;
use crate::mcp::shape::{
    fence, fence_field, fenced_dialog_summary, resolve_limit_with_cap, truncate_string,
};
use crate::output::model::DialogSummary;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Parameters for `describe_endpoint`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DescribeEndpointParams {
    /// The endpoint's IP address. Mutually exclusive with `user`.
    #[serde(default)]
    pub ip: Option<String>,
    /// The user part of a SIP URI, e.g. `alice` from `sip:alice@example.com`.
    /// Mutually exclusive with `ip`.
    #[serde(default)]
    pub user: Option<String>,
    /// Maximum dialog summaries to return. Clamped to the server's row cap.
    /// The counts above them always describe every match, not this page.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A `User-Agent` or `Server` banner this endpoint sent, and how often.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointBanner {
    /// Which header carried it — `User-Agent` on a request, `Server` on a
    /// response. Kept apart because they identify different roles: RFC 3261
    /// §20.41 has the UAC naming itself, §20.35 has the UAS.
    pub header: String,
    /// The banner text, fenced: it is a string the sender chose.
    pub value: String,
    /// Messages carrying it.
    pub count: usize,
}

/// REGISTER activity for this endpoint.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointRegistration {
    /// False when the endpoint sent no REGISTER at all, in which case every
    /// count below is zero for want of input rather than for want of failures.
    pub applicable: bool,
    /// Dialogs carrying a REGISTER request.
    pub dialogs: usize,
    /// Of those, how many drew a 2xx.
    pub succeeded: usize,
    /// Of those, how many the signaling diagnosis calls a registration failure
    /// — rejected outright, or granted a shorter expiry than asked for.
    pub failed: usize,
    /// Of those, how many are looping on authentication: challenged repeatedly
    /// with no 2xx.
    pub auth_loops: usize,
    /// Call-IDs of the REGISTER dialogs that failed or looped, bounded by the
    /// request's `limit`, so the detail is one `diagnose_registration` away.
    pub problem_call_ids: Vec<String>,
}

/// Call outcomes for this endpoint.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointCallOutcomes {
    /// INVITE dialogs involving this endpoint.
    pub invites: usize,
    /// Of those, how many reached a final INVITE response.
    pub with_final_status: usize,
    /// Of those, how many ended 4xx, 5xx or 6xx.
    pub failed: usize,
    /// `failed` over `with_final_status`, as a percentage.
    ///
    /// `None` when nothing has reached a final status yet. A zero there would
    /// report a perfect endpoint on a capture holding no completed call.
    pub failure_rate_pct: Option<f64>,
    /// Count per final INVITE status code, so a dominant cause is visible
    /// without fetching a dialog.
    pub by_final_status: BTreeMap<String, usize>,
}

/// RTP this endpoint sent or received.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointStreams {
    /// Streams attributed to this endpoint.
    pub count: usize,
    /// Of those, how many are not linked to any dialog. An orphan is what a
    /// NAT fault or a one-way-audio path looks like from the media side.
    pub orphaned: usize,
    /// Total RTP packets across them.
    pub packets: u64,
    /// Total packets the sequence gaps say were lost.
    pub lost_packets: u64,
    /// Worst interarrival jitter seen on any of them, milliseconds.
    pub max_jitter_ms: Option<f64>,
    /// Codecs observed, sorted. A codec sipnab could not name is omitted
    /// rather than reported as a guess.
    pub codecs: Vec<String>,
}

/// One security finding filed against this endpoint.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointFinding {
    /// The rule that fired.
    pub rule_name: String,
    /// The rule's detail line, bounded by the server's body cap.
    pub detail: String,
    /// When it fired, RFC 3339.
    pub timestamp: String,
}

/// What the alert engine had to say about this endpoint.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointFindings {
    /// Whether findings could be selected for this endpoint at all.
    ///
    /// False for a `user` lookup: the alert engine files every finding against
    /// a source IP, so there is no key to select a user by. An empty list with
    /// this flag set false means "not askable", which is a different answer
    /// from "asked, nothing found".
    pub selectable: bool,
    /// The findings themselves, newest first, bounded by the request's `limit`.
    pub findings: Vec<EndpointFinding>,
    /// Findings matching before `limit` truncated the list.
    pub total_matched: usize,
    /// Detectors armed on this server. Empty means nothing was watching.
    pub armed_kinds: Vec<String>,
    /// Why an empty list may mean nothing rather than something. Present only
    /// when it does.
    pub note: Option<String>,
}

/// Response of `describe_endpoint`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DescribeEndpointResponse {
    /// Schema version of this response shape.
    pub schema_version: u32,
    /// Which selector was used — `ip` or `user`.
    pub endpoint_kind: String,
    /// The selector's value, echoed verbatim as the caller sent it.
    pub endpoint: String,
    /// Dialogs this endpoint took part in.
    pub dialogs: usize,
    /// Dialog count per method, e.g. `INVITE`, `REGISTER`, `OPTIONS`.
    pub by_method: BTreeMap<String, usize>,
    /// Dialog count per dialog state.
    pub by_state: BTreeMap<String, usize>,
    /// SIP messages this endpoint SENT. Zero for a `user` lookup, where the
    /// selector names a URI rather than a socket.
    pub messages_sent: usize,
    /// SIP messages addressed TO this endpoint. Zero for a `user` lookup, for
    /// the same reason.
    pub messages_received: usize,
    /// Call outcomes.
    pub calls: EndpointCallOutcomes,
    /// Registration state.
    pub registration: EndpointRegistration,
    /// Banners the endpoint sent, most frequent first.
    pub user_agents: Vec<EndpointBanner>,
    /// Media attributed to the endpoint.
    pub streams: EndpointStreams,
    /// Security findings filed against it.
    pub findings: EndpointFindings,
    /// The most recent dialogs, newest first, bounded by `limit`.
    pub recent_dialogs: Vec<DialogSummary>,
    /// True when `dialogs` exceeds what `recent_dialogs` carries.
    pub truncated: bool,
}

/// Parameters for `top_talkers`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TopTalkersParams {
    /// Which kind of talker to rank: `ip`, `ua` or `prefix`.
    ///
    /// One dimension, never several. Two at once is a cross-product whose
    /// rows describe pairs rather than talkers, and the ranking of a pair
    /// answers a different question from the ranking of either half.
    pub by: String,
    /// Maximum rows to return. Clamped to the server's row cap.
    ///
    /// `distinct_talkers` beside them always counts every talker, so a page
    /// cannot be mistaken for the whole ranking.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Filter DSL expression narrowing which dialogs count, e.g.
    /// `state == failed`. Omitted, every dialog counts.
    ///
    /// The same vocabulary every other filtering tool takes, so an agent that
    /// learned it once can ask "who is failing most" without learning a
    /// second one.
    #[serde(default)]
    pub filter: Option<String>,
    /// Leading digits of the dialed number that make one `prefix` bucket.
    /// Default 4. Ignored for every other `by`.
    ///
    /// No single right value: a national plan's routing decision is often
    /// three or four digits, an international one starts at the country code.
    /// The default is the one that groups a typical NPA-NXX range without
    /// collapsing every destination into one row.
    #[serde(default)]
    pub prefix_digits: Option<u32>,
}

/// One ranked talker.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TopTalker {
    /// The address, banner or prefix this row is about. Fenced for `ua` and
    /// `prefix`, which carry text the packet's sender wrote; an address is a
    /// value sipnab derived and is returned as it is.
    pub key: String,
    /// Dialogs this talker took part in.
    pub dialogs: usize,
    /// Messages attributed to it: messages SENT for an `ip`, messages
    /// carrying the banner for a `ua`, every message of the dialog for a
    /// `prefix`.
    pub messages: usize,
    /// Of `dialogs`, how many were INVITE dialogs.
    pub invites: usize,
    /// Of `invites`, how many reached a 2xx.
    pub answered: usize,
    /// Of `invites`, how many ended 4xx, 5xx or 6xx.
    pub failed: usize,
    /// `dialogs` as a percentage of `total_matched`.
    ///
    /// The share of matched dialogs this talker APPEARED IN, not a partition
    /// of them: a call has two ends, so both ends' shares count it. `null`
    /// when nothing matched, rather than a zero that would read as a talker
    /// measured to be idle.
    pub share_pct: Option<f64>,
}

/// Answer shape for `top_talkers`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TopTalkersResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// Echo of the dimension ranked on, so an answer is self-describing.
    pub by: String,
    /// Talkers, busiest first, bounded by `limit`.
    pub talkers: Vec<TopTalker>,
    /// Distinct talkers seen, whether or not each got a row.
    pub distinct_talkers: usize,
    /// Dialogs the filter matched across the whole store.
    ///
    /// The rows do NOT sum to this for `ip` and `ua`, and that is the tool
    /// working: one dialog has two ends and counts for both.
    pub total_matched: usize,
    /// True when `distinct_talkers` exceeds the rows returned.
    pub truncated: bool,
    /// Which capture this answer came from, and which revision of its stores.
    pub capture_identity: crate::provenance::CaptureEtag,
}

#[tool_router(router = endpoints_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Everything the capture holds about one participant.
    ///
    /// # Which messages count as "this endpoint"
    ///
    /// An `ip` selector matches on MESSAGES, not on the dialog's opening
    /// addresses: a dialog records the socket pair its first message arrived
    /// on, so a proxy that re-originates mid-dialog, a re-INVITE from a second
    /// interface, or a BYE from the far side all belong to the call while
    /// carrying different addresses. Matching the dialog record alone would
    /// silently drop them, and the dropped ones are exactly the transfers and
    /// hand-offs an operator is looking for.
    ///
    /// A `user` selector matches the dialog's From or To user part, compared
    /// EXACTLY. RFC 3261 §19.1.4 makes the user part of a SIP URI
    /// case-sensitive, so `Alice` and `alice` are two URIs, and case-folding
    /// them here would report one endpoint's traffic under another's name.
    ///
    /// # What a banner is attributed to
    ///
    /// For an `ip`, `User-Agent` is read off requests the address SENT and
    /// `Server` off responses it sent — both name the sender (RFC 3261 §20.41,
    /// §20.35), so reading them off received messages would attribute the far
    /// end's software to this endpoint. For a `user`, only `User-Agent` on
    /// requests whose From user matches, which is the one case where the URI
    /// identifies the party that wrote the header.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when neither `ip` nor `user` is given, when
    /// both are, or when `ip` is not a valid address. Both at once is refused
    /// rather than guessed: a caller means either intersection or union, the
    /// two give different answers, and picking one silently would answer a
    /// question nobody asked.
    #[tool(
        name = "describe_endpoint",
        description = "Everything one endpoint did, selected by ip OR user \
                       (exactly one). Returns dialog counts by method and \
                       state, INVITE outcomes with a failure rate, REGISTER \
                       state, the User-Agent and Server banners it sent, its \
                       RTP streams, security findings filed against it, and a \
                       bounded page of its most recent dialogs. The counts \
                       cover every match; only the dialog page is limited. \
                       Findings are selectable by ip only, because the alert \
                       engine files them against a source address.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn describe_endpoint(
        &self,
        Parameters(params): Parameters<DescribeEndpointParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let selector = Selector::from_params(&params)?;

        let payload = {
            let ds = self.dialog_store.read();

            let mut dialogs: Vec<&crate::sip::dialog::SipDialog> = Vec::new();
            let mut by_method: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_state: BTreeMap<String, usize> = BTreeMap::new();
            let mut messages_sent = 0usize;
            let mut messages_received = 0usize;
            let mut banners: BTreeMap<(String, String), usize> = BTreeMap::new();

            let mut invites = 0usize;
            let mut with_final_status = 0usize;
            let mut failed = 0usize;
            let mut by_final_status: BTreeMap<String, usize> = BTreeMap::new();

            let mut reg_dialogs = 0usize;
            let mut reg_succeeded = 0usize;
            let mut reg_failed = 0usize;
            let mut reg_auth_loops = 0usize;
            let mut reg_problem_ids: Vec<String> = Vec::new();

            for d in ds.iter() {
                if !selector.matches_dialog(d) {
                    continue;
                }
                dialogs.push(d);
                *by_method.entry(d.method.as_str().to_string()).or_insert(0) += 1;
                *by_state.entry(d.state().to_string()).or_insert(0) += 1;

                for m in &d.messages {
                    if selector.sent(m) {
                        messages_sent += 1;
                        if let Some((header, value)) = banner_of(m) {
                            *banners.entry((header, value)).or_insert(0) += 1;
                        }
                    }
                    if selector.received(m) {
                        messages_received += 1;
                    }
                }

                if d.method == crate::sip::method::SipMethod::Invite {
                    invites += 1;
                    if let Some(code) = d.final_status_code() {
                        with_final_status += 1;
                        *by_final_status.entry(code.to_string()).or_insert(0) += 1;
                        if code >= 400 {
                            failed += 1;
                        }
                    }
                }

                // Keyed off the REQUEST rather than off `d.method`: a REGISTER
                // can arrive inside a dialog opened by something else once
                // Call-ID reuse is in play, and a registration that is not
                // examined reports as a healthy one.
                let registers = d.messages.iter().any(|m| {
                    m.is_request && m.method == Some(crate::sip::method::SipMethod::Register)
                });
                if registers {
                    reg_dialogs += 1;
                    let diag = crate::sip::diagnosis::diagnose_signaling(&d.messages);
                    let ok = d.messages.iter().any(|m| {
                        !m.is_request
                            && m.cseq().map(|(_, method)| method) == Some("REGISTER")
                            && m.status_code.is_some_and(|c| (200..300).contains(&c))
                    });
                    if ok {
                        reg_succeeded += 1;
                    }
                    let problem = diag.registration_failure.is_some() || diag.auth_loop.is_some();
                    if diag.registration_failure.is_some() {
                        reg_failed += 1;
                    }
                    if diag.auth_loop.is_some() {
                        reg_auth_loops += 1;
                    }
                    if problem && reg_problem_ids.len() < limit {
                        reg_problem_ids.push(d.call_id.clone());
                    }
                }
            }

            // Newest first: an operator chasing a complaint wants what just
            // happened, and `list_dialogs` already pages the whole history
            // oldest-first for anyone sweeping it.
            dialogs.sort_by(|a, b| {
                b.updated_at
                    .cmp(&a.updated_at)
                    .then_with(|| a.call_id.cmp(&b.call_id))
            });
            let matched_call_ids: std::collections::HashSet<&str> =
                dialogs.iter().map(|d| d.call_id.as_str()).collect();
            let streams = self.endpoint_streams(&selector, &matched_call_ids);

            let mut user_agents: Vec<EndpointBanner> = banners
                .into_iter()
                .map(|((header, value), count)| EndpointBanner {
                    header,
                    value: fence(&value),
                    count,
                })
                .collect();
            user_agents.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));

            let total_dialogs = dialogs.len();
            let recent_dialogs: Vec<DialogSummary> = dialogs
                .iter()
                .take(limit)
                .map(|d| fenced_dialog_summary(d))
                .collect();
            drop(ds);

            DescribeEndpointResponse {
                schema_version: 1,
                endpoint_kind: selector.kind().to_string(),
                endpoint: selector.value().to_string(),
                dialogs: total_dialogs,
                by_method,
                by_state,
                messages_sent,
                messages_received,
                calls: EndpointCallOutcomes {
                    invites,
                    with_final_status,
                    failed,
                    // Guarded, not defaulted. `0.0` on a zero denominator is a
                    // clean bill of health for an endpoint nothing has been
                    // measured about.
                    failure_rate_pct: (with_final_status > 0)
                        .then(|| (failed as f64 / with_final_status as f64) * 100.0),
                    by_final_status,
                },
                registration: EndpointRegistration {
                    applicable: reg_dialogs > 0,
                    dialogs: reg_dialogs,
                    succeeded: reg_succeeded,
                    failed: reg_failed,
                    auth_loops: reg_auth_loops,
                    problem_call_ids: reg_problem_ids,
                },
                user_agents,
                streams,
                findings: self.endpoint_findings(&selector, limit),
                truncated: total_dialogs > recent_dialogs.len(),
                recent_dialogs,
            }
        };

        Ok(CallToolResult::success(vec![
            ContentBlock::json(payload)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// The busiest participants in the capture, ranked.
    ///
    /// # Why this is not `aggregate_dialogs`
    ///
    /// `aggregate_dialogs` counts DIALOGS and puts each one in exactly one
    /// bucket, keyed off the dialog record — its opening source address, the
    /// first `User-Agent` it happened to carry. This counts PARTICIPANTS, and
    /// a dialog has more than one. An address that answers a call it did not
    /// open, a proxy that re-originates a leg mid-dialog, the far end's phone:
    /// none of them appear in the dialog's opening addresses, and all of them
    /// are talkers.
    ///
    /// So a dialog counts once for every talker that took part in it, and the
    /// per-talker shares therefore sum above 100 % — two endpoints on one call
    /// are both fully responsible for it. `share_pct` says what fraction of
    /// the matched dialogs each talker appeared in, which is the question an
    /// operator asks; it is not a partition of them. `prefix` is the one
    /// dimension where each dialog does land in a single bucket, because a
    /// dialog has one dialed number.
    ///
    /// # The three dimensions
    ///
    /// * `ip` — every address that SENT a message, read off the messages
    ///   rather than off the dialog, for the reason `describe_endpoint`
    ///   records.
    /// * `ua` — every `User-Agent` a request carried and every `Server` a
    ///   response carried, both of which name their own sender (RFC 3261
    ///   §20.41, §20.35). Software present on the wire, not software that
    ///   opened calls.
    /// * `prefix` — the leading digits of the dialed number, from the To user
    ///   part. The toll-fraud and routing question: a destination range
    ///   climbing the ranking is what a compromised account looks like before
    ///   anyone reads a single call.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `by`, a `prefix_digits` of
    /// zero, or an unparseable `filter`.
    #[tool(
        name = "top_talkers",
        description = "Ranks the busiest PARTICIPANTS by ip, ua or prefix \
                       (the dialed number's leading digits), largest first. \
                       Each row carries dialogs, messages, INVITEs, answered, \
                       failed and the share of matched dialogs the talker \
                       appeared in. A dialog counts for every talker that took \
                       part in it, so ip and ua shares sum above 100%; \
                       aggregate_dialogs answers the one-bucket-per-dialog \
                       question instead.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn top_talkers(
        &self,
        Parameters(params): Parameters<TopTalkersParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let dimension = TalkerDimension::from_params(&params)?;
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let filter = self.compile_filter(params.filter.as_deref())?;

        let (tally, total_matched, capture_identity) = {
            // Capture, dialogs, streams -- the order `CaptureState` documents.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            let delay = crate::rtp::quality::MosDelay::from_capture(&ss);
            let capture_media = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);

            // Streams grouped by Call-ID once. `streams_for` scans the whole
            // stream store per dialog, and this tool visits every dialog, so
            // the per-dialog scan would be quadratic in the capture's size.
            let mut by_call: std::collections::HashMap<&str, Vec<&crate::rtp::stream::RtpStream>> =
                std::collections::HashMap::new();
            for s in ss.iter() {
                if let Some(id) = s.associated_dialog.as_deref() {
                    by_call.entry(id).or_default().push(s);
                }
            }

            const NO_STREAMS: &[&crate::rtp::stream::RtpStream] = &[];
            let mut tally: BTreeMap<String, TalkerAccumulator> = BTreeMap::new();
            let mut total = 0usize;
            for d in ds.iter() {
                let streams = by_call
                    .get(d.call_id.as_str())
                    .map_or(NO_STREAMS, Vec::as_slice);
                if let Some(expr) = filter.as_ref()
                    && !expr.matches_dialog(d, streams, capture_media, delay)
                {
                    continue;
                }
                total += 1;
                dimension.credit(d, &mut tally);
            }
            (tally, total, capture_identity)
        };

        let distinct_talkers = tally.len();
        let mut ordered: Vec<(String, TalkerAccumulator)> = tally.into_iter().collect();
        // Dialogs first, messages as the tie-break, then the key itself so the
        // same store always answers in the same order.
        ordered.sort_by(|(ka, a), (kb, b)| {
            b.dialogs
                .cmp(&a.dialogs)
                .then_with(|| b.messages.cmp(&a.messages))
                .then_with(|| ka.cmp(kb))
        });

        let talkers: Vec<TopTalker> = ordered
            .into_iter()
            .take(limit)
            .map(|(key, acc)| TopTalker {
                key: dimension.render_key(&key),
                dialogs: acc.dialogs,
                messages: acc.messages,
                invites: acc.invites,
                answered: acc.answered,
                failed: acc.failed,
                // Guarded rather than defaulted: a zero share on an empty
                // capture reads as a talker measured to be idle.
                share_pct: (total_matched > 0)
                    .then(|| (acc.dialogs as f64 / total_matched as f64) * 100.0),
            })
            .collect();

        let payload = TopTalkersResponse {
            schema_version: 1,
            by: dimension.name().to_string(),
            truncated: distinct_talkers > talkers.len(),
            talkers,
            distinct_talkers,
            total_matched,
            capture_identity,
        };

        Ok(CallToolResult::success(vec![
            ContentBlock::json(payload)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }
}

/// Digits of the dialed number one `prefix` bucket covers when the caller
/// names none.
///
/// Four, because that is where a North American plan's NPA plus the first
/// digit of the NXX separates one route from another, and it is short enough
/// that an international number still groups by country and carrier rather
/// than resolving to one row per destination.
const DEFAULT_PREFIX_DIGITS: usize = 4;

/// Bucket key used when a dialog has no To user at all.
const NO_DESTINATION: &str = "(none)";

/// Bucket key used when the To user carries no leading digits, so it names a
/// person rather than a number and has no dialing prefix.
const NON_NUMERIC_DESTINATION: &str = "(non-numeric)";

/// What `top_talkers` was asked to rank.
///
/// An enum rather than the raw string threaded through the scan: the string
/// is validated once, at the edge, and every decision below is then a match
/// the compiler checks. A `&str` carried into the loop leaves "prefix without
/// a width" representable long after it was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TalkerDimension {
    /// Addresses that sent messages.
    Ip,
    /// `User-Agent` and `Server` banners.
    Ua,
    /// Leading digits of the dialed number, this many of them.
    Prefix(usize),
}

/// What one talker did, accumulated across the dialogs it took part in.
#[derive(Debug, Clone, Default)]
struct TalkerAccumulator {
    /// Dialogs the talker appeared in.
    dialogs: usize,
    /// Messages attributed to the talker.
    messages: usize,
    /// Of `dialogs`, the INVITE ones.
    invites: usize,
    /// Of `invites`, the ones that reached a 2xx.
    answered: usize,
    /// Of `invites`, the ones that ended 4xx, 5xx or 6xx.
    failed: usize,
}

impl TalkerDimension {
    /// Read the dimension out of the request.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `by`, or for a `prefix` asked
    /// for with zero digits — a zero-width prefix puts every destination in
    /// one bucket, which is a ranking of one row that says nothing.
    fn from_params(params: &TopTalkersParams) -> Result<Self, rmcp::ErrorData> {
        match params.by.trim() {
            "ip" => Ok(Self::Ip),
            "ua" => Ok(Self::Ua),
            "prefix" => match params.prefix_digits {
                Some(0) => Err(rmcp::ErrorData::invalid_params(
                    "prefix_digits must be greater than zero: a zero-digit \
                     prefix is the same bucket for every destination, so the \
                     ranking would have exactly one row"
                        .to_string(),
                    None,
                )),
                Some(n) => Ok(Self::Prefix(n as usize)),
                None => Ok(Self::Prefix(DEFAULT_PREFIX_DIGITS)),
            },
            other => Err(rmcp::ErrorData::invalid_params(
                format!(
                    "cannot rank by '{other}'; one of: ip, ua, prefix. One \
                     dimension only -- a ranking of pairs answers a different \
                     question from a ranking of either half."
                ),
                None,
            )),
        }
    }

    /// The dimension's name, for the response.
    fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Ua => "ua",
            Self::Prefix(_) => "prefix",
        }
    }

    /// Credit one dialog to every talker that took part in it.
    ///
    /// # Arguments
    ///
    /// * `d` — the dialog, already past the filter.
    /// * `tally` — the per-talker accumulator map.
    ///
    /// # Side effects
    ///
    /// Adds one dialog to each distinct key the dialog carries, plus the
    /// messages attributed to that key. A key appears at most once per
    /// dialog, so an endpoint that sent forty messages in one call counts as
    /// one dialog and forty messages rather than as forty dialogs.
    fn credit(
        self,
        d: &crate::sip::dialog::SipDialog,
        tally: &mut BTreeMap<String, TalkerAccumulator>,
    ) {
        // Key to the messages it accounts for, built per dialog so the
        // de-duplication is structural rather than a second pass that could
        // disagree with the first.
        let mut per_key: BTreeMap<String, usize> = BTreeMap::new();
        match self {
            // The SENDER. A talker is a thing that put packets on the wire,
            // and counting receivers too would rank a proxy top of every
            // capture it appears in for work it did not originate.
            Self::Ip => {
                for m in &d.messages {
                    *per_key.entry(m.src_addr.to_string()).or_insert(0) += 1;
                }
            }
            // `banner_of` reads `User-Agent` off requests and `Server` off
            // responses, so each banner names the party that wrote it.
            Self::Ua => {
                for m in &d.messages {
                    if let Some((_, value)) = banner_of(m) {
                        *per_key.entry(value).or_insert(0) += 1;
                    }
                }
            }
            // One bucket per dialog: a dialog has one dialed number, so
            // every message in it belongs to that destination.
            Self::Prefix(digits) => {
                per_key.insert(prefix_key(d.to_user.as_deref(), digits), d.messages.len());
            }
        }

        let invite = d.method == crate::sip::method::SipMethod::Invite;
        let final_code = d.final_status_code();
        let answered = invite && final_code.is_some_and(|c| (200..300).contains(&c));
        let failed = invite && final_code.is_some_and(|c| c >= 400);

        for (key, messages) in per_key {
            let acc = tally.entry(key).or_default();
            acc.dialogs += 1;
            acc.messages += messages;
            if invite {
                acc.invites += 1;
                if answered {
                    acc.answered += 1;
                }
                if failed {
                    acc.failed += 1;
                }
            }
        }
    }

    /// The key as it goes into the response.
    ///
    /// Only `ua` is fenced. An address is a value sipnab derived from the
    /// packet headers, and a `prefix` key is either digits this code
    /// extracted or one of two literals it chose — neither can carry text the
    /// sender wrote. A banner is a string a stranger typed.
    fn render_key(self, key: &str) -> String {
        match self {
            Self::Ua => fence(key),
            Self::Ip | Self::Prefix(_) => key.to_string(),
        }
    }
}

/// The prefix bucket a dialed number falls into.
///
/// Leading digits only, after an optional `+`: an E.164 number is written
/// both ways on one wire, and bucketing `+15551234` apart from `15551234`
/// would split one destination in two and rank each half below where the
/// destination belongs.
///
/// # Arguments
///
/// * `to_user` — the dialog's To user part, if it has one.
/// * `digits` — how many leading digits make a bucket.
///
/// # Returns
///
/// The leading digits (fewer, for a number shorter than `digits`), or a named
/// literal for a destination with no digits at all. Named rather than
/// dropped: "how much traffic goes to a name rather than a number" is a real
/// question, and a bucket set that silently omits it would not describe the
/// capture.
fn prefix_key(to_user: Option<&str>, digits: usize) -> String {
    let Some(user) = to_user else {
        return NO_DESTINATION.to_string();
    };
    let leading: String = user
        .strip_prefix('+')
        .unwrap_or(user)
        .chars()
        .take_while(char::is_ascii_digit)
        .take(digits)
        .collect();
    if leading.is_empty() {
        return NON_NUMERIC_DESTINATION.to_string();
    }
    leading
}

/// Which entity `describe_endpoint` was asked about.
///
/// A small enum rather than two `Option`s threaded through the scan: every
/// predicate below differs between the two selectors, and an `Option` pair
/// leaves "both" and "neither" representable long after they were rejected.
enum Selector {
    /// An address, matched against message and stream endpoints.
    Ip(IpAddr),
    /// A SIP URI user part, matched against dialog From/To users.
    User(String),
}

impl Selector {
    /// Read the selector out of the request.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when neither or both selectors are present,
    /// or when the address does not parse.
    fn from_params(params: &DescribeEndpointParams) -> Result<Self, rmcp::ErrorData> {
        match (params.ip.as_deref(), params.user.as_deref()) {
            (Some(ip), None) => ip.parse::<IpAddr>().map(Selector::Ip).map_err(|e| {
                rmcp::ErrorData::invalid_params(format!("ip '{ip}' is not an address: {e}"), None)
            }),
            (None, Some(user)) => Ok(Selector::User(user.to_string())),
            (None, None) => Err(rmcp::ErrorData::invalid_params(
                "give exactly one of ip or user: an endpoint is either an \
                 address or a URI user part, and neither can be inferred from \
                 the other"
                    .to_string(),
                None,
            )),
            (Some(_), Some(_)) => Err(rmcp::ErrorData::invalid_params(
                "give exactly one of ip or user, not both: the two select \
                 different sets, and whether you meant their intersection or \
                 their union changes the answer"
                    .to_string(),
                None,
            )),
        }
    }

    /// The selector's name, for the response.
    fn kind(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::User(_) => "user",
        }
    }

    /// The selector's value, for the response.
    fn value(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::User(u) => u.clone(),
        }
    }

    /// Whether this dialog involves the endpoint.
    fn matches_dialog(&self, d: &crate::sip::dialog::SipDialog) -> bool {
        match self {
            // Every message, not `d.src_addr`/`d.dst_addr`: those record where
            // the dialog OPENED, and a leg re-originated by a proxy mid-call
            // carries addresses the opening message never had.
            Self::Ip(ip) => d
                .messages
                .iter()
                .any(|m| m.src_addr == *ip || m.dst_addr == *ip),
            // Exact, per RFC 3261 §19.1.4 — the user part is case-sensitive.
            Self::User(u) => {
                d.from_user.as_deref() == Some(u.as_str())
                    || d.to_user.as_deref() == Some(u.as_str())
            }
        }
    }

    /// Whether the endpoint SENT this message.
    ///
    /// Always false for a user selector: a URI user part names a party, not a
    /// socket, and the party that sent a given message is not recoverable from
    /// it. Reporting a count derived from something else under the name
    /// `messages_sent` would be worse than reporting zero.
    fn sent(&self, m: &crate::sip::SipMessage) -> bool {
        match self {
            Self::Ip(ip) => m.src_addr == *ip,
            Self::User(_) => false,
        }
    }

    /// Whether the message was addressed TO the endpoint. False for a user
    /// selector, for the reason [`Self::sent`] gives.
    fn received(&self, m: &crate::sip::SipMessage) -> bool {
        match self {
            Self::Ip(ip) => m.dst_addr == *ip,
            Self::User(_) => false,
        }
    }

    /// Whether this RTP stream belongs to the endpoint.
    ///
    /// An address is matched against the media 5-tuple directly. A user has no
    /// media identity of its own, so its streams are the ones linked to its
    /// dialogs — which is why the matched Call-IDs are passed in.
    fn matches_stream(
        &self,
        s: &crate::rtp::stream::RtpStream,
        call_ids: &std::collections::HashSet<&str>,
    ) -> bool {
        match self {
            Self::Ip(ip) => s.key.src.ip() == *ip || s.key.dst.ip() == *ip,
            Self::User(_) => s
                .associated_dialog
                .as_deref()
                .is_some_and(|id| call_ids.contains(id)),
        }
    }
}

/// The banner one message carries about ITS OWN sender, if any.
///
/// `User-Agent` on a request and `Server` on a response, per RFC 3261 §20.41
/// and §20.35. A request's `Server` header and a response's `User-Agent` are
/// not errors on the wire, but they describe the other direction, so reading
/// them here would file the far end's software under this endpoint.
fn banner_of(m: &crate::sip::SipMessage) -> Option<(String, String)> {
    if m.is_request {
        m.header("User-Agent")
            .map(|v| ("User-Agent".to_string(), v.to_string()))
    } else {
        m.header("Server")
            .map(|v| ("Server".to_string(), v.to_string()))
    }
}

impl SipnabMcp {
    /// Media attributed to the endpoint.
    ///
    /// # Arguments
    ///
    /// * `selector` — the entity asked about.
    /// * `call_ids` — Call-IDs of the endpoint's dialogs, used only by the
    ///   `user` selector, which has no media identity of its own.
    fn endpoint_streams(
        &self,
        selector: &Selector,
        call_ids: &std::collections::HashSet<&str>,
    ) -> EndpointStreams {
        let ss = self.stream_store.read();
        let mut out = EndpointStreams {
            count: 0,
            orphaned: 0,
            packets: 0,
            lost_packets: 0,
            max_jitter_ms: None,
            codecs: Vec::new(),
        };
        let mut codecs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for s in ss.iter() {
            if !selector.matches_stream(s, call_ids) {
                continue;
            }
            out.count += 1;
            if s.associated_dialog.is_none() {
                out.orphaned += 1;
            }
            out.packets = out.packets.saturating_add(s.packet_count);
            out.lost_packets = out.lost_packets.saturating_add(s.lost_packets);
            out.max_jitter_ms = Some(out.max_jitter_ms.map_or(s.jitter, |m: f64| m.max(s.jitter)));
            if let Some(c) = &s.codec {
                codecs.insert(c.clone());
            }
        }
        // For a dynamic payload type `RtpStream::codec` holds the SDP's own
        // `a=rtpmap` encoding name, so the offerer chose this string. Fenced
        // at the boundary rather than in `stream_store`, which also feeds the
        // CLI and REST readers who want the token unmarked.
        out.codecs = codecs.iter().map(|c| fence_field(c)).collect();
        out
    }

    /// Security findings filed against the endpoint.
    ///
    /// # Arguments
    ///
    /// * `selector` — the entity asked about; only an address is selectable.
    /// * `limit` — maximum findings to return; `total_matched` is unbounded.
    fn endpoint_findings(&self, selector: &Selector, limit: usize) -> EndpointFindings {
        let armed_kinds = self.armed_detections.clone();
        // Stated in the same words `security_findings` uses, because it is the
        // same trap: an empty list on a server with nothing armed means nobody
        // was watching, and an agent that reads it as "clean" has inverted the
        // answer.
        let note = armed_kinds.is_empty().then(|| {
            "No detection rule is armed on this server, so no finding could \
             have been recorded. An empty findings list here means nothing was \
             watching, NOT that this endpoint was clean. Arm a detector with \
             --kill-scanner, --fraud-detect, --digest-leak or --reg-flood and \
             re-run the capture."
                .to_string()
        });

        let Selector::Ip(ip) = selector else {
            return EndpointFindings {
                selectable: false,
                findings: Vec::new(),
                total_matched: 0,
                armed_kinds,
                note: Some(
                    "Findings are filed against a source IP, so a user selector \
                     cannot select any. Re-ask with the endpoint's address."
                        .to_string(),
                ),
            };
        };

        let (findings, total_matched) = match &self.alert_engine {
            Some(engine) => {
                let guard = engine.read();
                // The whole ring, not the first `limit`: a truncated scan
                // cannot report what it truncated, and the buffer is bounded by
                // --findings-history.
                let all = guard.iter_findings(&[], None, usize::MAX);
                let mine: Vec<&crate::security::alerting::Finding> =
                    all.into_iter().filter(|f| f.src_ip == *ip).collect();
                let total = mine.len();
                let page = mine
                    .iter()
                    .take(limit)
                    .map(|f| EndpointFinding {
                        rule_name: f.rule_name.clone(),
                        // The detail line quotes the scanner's own
                        // `User-Agent` back; fenced like the same field is in
                        // `security_findings` and `generate_fail2ban_rule`.
                        detail: fence(&truncate_string(&f.detail, self.body_cap)),
                        timestamp: f.timestamp.to_rfc3339(),
                    })
                    .collect();
                (page, total)
            }
            None => (Vec::new(), 0),
        };

        EndpointFindings {
            selectable: true,
            findings,
            total_matched,
            armed_kinds,
            note,
        }
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

    /// `10.0.0.<last>` as an `IpAddr`.
    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// A fixed base timestamp, so every fixture is deterministic.
    fn base_ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Parse `raw` as SIP from `src` to `dst` at `ts`.
    fn parse_between(
        raw: &[u8],
        src: IpAddr,
        dst: IpAddr,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        parse_sip(
            raw,
            ts,
            src,
            dst,
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("the fixture parses")
    }

    /// An INVITE from `user` to `bob`, sent `src` -> `dst`.
    fn invite(
        call_id: &str,
        user: &str,
        src: IpAddr,
        dst: IpAddr,
        ua: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                &format!("From: <sip:{user}@example.com>;tag=t1"),
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_between(&raw, src, dst, ts)
    }

    /// An INVITE dialing `number` rather than a name, for the `prefix`
    /// dimension.
    fn numeric_invite(
        call_id: &str,
        number: &str,
        src: IpAddr,
        dst: IpAddr,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{number}@example.com SIP/2.0"),
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                "From: <sip:alice@example.com>;tag=t1",
                &format!("To: <sip:{number}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "User-Agent: Phone/1.0",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_between(&raw, src, dst, ts)
    }

    /// A final response to `call_id`, sent `src` -> `dst`.
    fn response(
        call_id: &str,
        code: u16,
        reason: &str,
        method: &str,
        src: IpAddr,
        dst: IpAddr,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {method}"),
                "Contact: <sip:bob@10.0.0.2>",
                "Server: TestProxy/9.9",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_between(&raw, src, dst, ts)
    }

    /// A REGISTER from `user`, sent `src` -> `dst`.
    fn register(
        call_id: &str,
        user: &str,
        src: IpAddr,
        dst: IpAddr,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        let raw = build_sip(
            "REGISTER sip:example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}"),
                &format!("From: <sip:{user}@example.com>;tag=t1"),
                &format!("To: <sip:{user}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 REGISTER",
                "Expires: 3600",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_between(&raw, src, dst, ts)
    }

    /// A server over a store holding the given messages.
    fn server_with(messages: Vec<crate::sip::SipMessage>) -> SipnabMcp {
        let mut store = DialogStore::new(100, false);
        for m in messages {
            store.process_message(m);
        }
        SipnabMcp::new(
            Arc::new(RwLock::new(store)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// The JSON block of a tool result.
    fn json_of(result: &CallToolResult) -> serde_json::Value {
        let note = crate::mcp::shape::untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("a payload block that is not the provenance note");
        serde_json::from_str(&text).expect("the payload is JSON")
    }

    /// One phone at 10.0.0.1 placing two calls through a proxy at 10.0.0.2:
    /// one answered, one rejected 403. Plus an unrelated call between two other
    /// addresses, which must never appear in the phone's answer.
    fn two_call_capture() -> SipnabMcp {
        server_with(vec![
            invite("ok@test", "alice", ip(1), ip(2), "Phone/1.0", base_ts()),
            response(
                "ok@test",
                200,
                "OK",
                "INVITE",
                ip(2),
                ip(1),
                base_ts() + chrono::Duration::seconds(1),
            ),
            invite(
                "bad@test",
                "alice",
                ip(1),
                ip(2),
                "Phone/1.0",
                base_ts() + chrono::Duration::seconds(10),
            ),
            response(
                "bad@test",
                403,
                "Forbidden",
                "INVITE",
                ip(2),
                ip(1),
                base_ts() + chrono::Duration::seconds(11),
            ),
            invite(
                "other@test",
                "carol",
                ip(7),
                ip(8),
                "Other/2.0",
                base_ts() + chrono::Duration::seconds(20),
            ),
        ])
    }

    /// Call the tool with an `ip` selector.
    async fn by_ip(srv: &SipnabMcp, addr: &str) -> serde_json::Value {
        json_of(
            &srv.describe_endpoint(Parameters(DescribeEndpointParams {
                ip: Some(addr.to_string()),
                user: None,
                limit: None,
            }))
            .await
            .expect("the call succeeds"),
        )
    }

    /// The endpoint's own traffic is counted and nobody else's is.
    #[tokio::test]
    async fn describe_endpoint_by_ip_counts_only_that_endpoints_dialogs() {
        let v = by_ip(&two_call_capture(), "10.0.0.1").await;
        assert_eq!(
            v["dialogs"], 2,
            "the third call is between two other addresses and must not be \
             counted here: {v}"
        );
        assert_eq!(v["by_method"]["INVITE"], 2, "{v}");
        assert_eq!(
            v["messages_sent"], 2,
            "the phone sent two INVITEs and received two responses: {v}"
        );
        assert_eq!(v["messages_received"], 2, "{v}");
    }

    /// The failure rate is a real ratio over completed calls.
    #[tokio::test]
    async fn describe_endpoint_reports_a_failure_rate_over_completed_calls() {
        let v = by_ip(&two_call_capture(), "10.0.0.1").await;
        assert_eq!(v["calls"]["invites"], 2, "{v}");
        assert_eq!(v["calls"]["with_final_status"], 2, "{v}");
        assert_eq!(v["calls"]["failed"], 1, "{v}");
        assert_eq!(
            v["calls"]["failure_rate_pct"], 50.0,
            "one of two completed calls was rejected: {v}"
        );
        assert_eq!(
            v["calls"]["by_final_status"]["403"], 1,
            "the dominant cause has to be visible without fetching a dialog: {v}"
        );
    }

    /// A rate over nothing is `null`, never `0`.
    #[tokio::test]
    async fn describe_endpoint_withholds_a_failure_rate_when_nothing_completed() {
        // One INVITE, no final response: nothing has an outcome yet.
        let srv = server_with(vec![invite(
            "pending@test",
            "alice",
            ip(1),
            ip(2),
            "Phone/1.0",
            base_ts(),
        )]);
        let v = by_ip(&srv, "10.0.0.1").await;
        assert_eq!(v["calls"]["invites"], 1, "{v}");
        assert_eq!(v["calls"]["with_final_status"], 0, "{v}");
        assert!(
            v["calls"]["failure_rate_pct"].is_null(),
            "0% over an empty denominator reads as a healthy endpoint; there is \
             no measurement here to report: {v}"
        );
    }

    /// Banners are attributed to the SENDER, so the proxy's `Server` banner
    /// does not become the phone's.
    #[tokio::test]
    async fn describe_endpoint_attributes_a_banner_to_the_endpoint_that_sent_it() {
        let srv = two_call_capture();
        let phone = by_ip(&srv, "10.0.0.1").await;
        let uas = phone["user_agents"].as_array().expect("an array");
        assert_eq!(uas.len(), 1, "the phone sent exactly one banner: {phone}");
        assert_eq!(uas[0]["header"], "User-Agent", "{phone}");
        assert_eq!(
            uas[0]["value"],
            crate::mcp::shape::fence("Phone/1.0"),
            "a banner is text the sender chose and must arrive fenced: {phone}"
        );
        assert_eq!(uas[0]["count"], 2, "{phone}");

        let proxy = by_ip(&srv, "10.0.0.2").await;
        let proxy_uas = proxy["user_agents"].as_array().expect("an array");
        assert!(
            proxy_uas
                .iter()
                .all(|b| b["header"] == "Server"
                    && b["value"] != crate::mcp::shape::fence("Phone/1.0")),
            "the proxy only ever sent responses, so the phone's User-Agent must \
             not be filed under it: {proxy}"
        );
    }

    /// REGISTER state is reported, and a capture with no REGISTER says so
    /// rather than reporting a healthy registration.
    #[tokio::test]
    async fn describe_endpoint_separates_no_register_from_a_good_one() {
        let none = by_ip(&two_call_capture(), "10.0.0.1").await;
        assert_eq!(
            none["registration"]["applicable"], false,
            "an endpoint that never registered must not read as registered: \
             {none}"
        );

        let srv = server_with(vec![
            register("reg@test", "alice", ip(1), ip(2), base_ts()),
            response(
                "reg@test",
                200,
                "OK",
                "REGISTER",
                ip(2),
                ip(1),
                base_ts() + chrono::Duration::seconds(1),
            ),
        ]);
        let v = by_ip(&srv, "10.0.0.1").await;
        assert_eq!(v["registration"]["applicable"], true, "{v}");
        assert_eq!(v["registration"]["dialogs"], 1, "{v}");
        assert_eq!(
            v["registration"]["succeeded"], 1,
            "a REGISTER answered 200 is a successful registration: {v}"
        );
    }

    /// A rejected REGISTER is counted as a failure and named, so the detail is
    /// one `diagnose_registration` away.
    #[tokio::test]
    async fn describe_endpoint_names_the_register_dialogs_that_failed() {
        let srv = server_with(vec![
            register("bad-reg@test", "alice", ip(1), ip(2), base_ts()),
            response(
                "bad-reg@test",
                403,
                "Forbidden",
                "REGISTER",
                ip(2),
                ip(1),
                base_ts() + chrono::Duration::seconds(1),
            ),
        ]);
        let v = by_ip(&srv, "10.0.0.1").await;
        assert_eq!(v["registration"]["failed"], 1, "{v}");
        assert_eq!(v["registration"]["succeeded"], 0, "{v}");
        assert_eq!(
            v["registration"]["problem_call_ids"][0], "bad-reg@test",
            "the failing dialog has to be nameable, or the count is a dead \
             end: {v}"
        );
    }

    /// The user part is case-sensitive per RFC 3261 §19.1.4, so a differently
    /// cased name is a different endpoint.
    #[tokio::test]
    async fn describe_endpoint_by_user_matches_the_uri_case_exactly() {
        let srv = two_call_capture();
        let exact = json_of(
            &srv.describe_endpoint(Parameters(DescribeEndpointParams {
                ip: None,
                user: Some("alice".to_string()),
                limit: None,
            }))
            .await
            .expect("the call succeeds"),
        );
        assert_eq!(exact["dialogs"], 2, "alice placed two calls: {exact}");
        assert_eq!(exact["endpoint_kind"], "user", "{exact}");

        let wrong_case = json_of(
            &srv.describe_endpoint(Parameters(DescribeEndpointParams {
                ip: None,
                user: Some("Alice".to_string()),
                limit: None,
            }))
            .await
            .expect("the call succeeds"),
        );
        assert_eq!(
            wrong_case["dialogs"], 0,
            "RFC 3261 §19.1.4 makes the user part case-sensitive; folding it \
             would report one subscriber's traffic under another's name: \
             {wrong_case}"
        );
    }

    /// A user lookup says findings are not selectable rather than returning an
    /// empty list that reads as "nothing found".
    #[tokio::test]
    async fn describe_endpoint_by_user_says_findings_are_not_selectable() {
        let v = json_of(
            &two_call_capture()
                .describe_endpoint(Parameters(DescribeEndpointParams {
                    ip: None,
                    user: Some("alice".to_string()),
                    limit: None,
                }))
                .await
                .expect("the call succeeds"),
        );
        assert_eq!(
            v["findings"]["selectable"], false,
            "the alert engine files findings against a source IP; an empty list \
             here must not read as 'asked, nothing found': {v}"
        );
        assert!(v["findings"]["note"].as_str().is_some(), "{v}");
    }

    /// An IP lookup on a server with nothing armed carries the note that says
    /// an empty list means nobody was watching.
    #[tokio::test]
    async fn describe_endpoint_says_when_no_detector_was_armed() {
        let v = by_ip(&two_call_capture(), "10.0.0.1").await;
        assert_eq!(v["findings"]["selectable"], true, "{v}");
        assert_eq!(v["findings"]["total_matched"], 0, "{v}");
        assert!(
            v["findings"]["note"]
                .as_str()
                .is_some_and(|n| n.contains("nothing was watching")),
            "an empty findings list on an unarmed server must say so, or it \
             reads as a clean endpoint: {v}"
        );
    }

    /// Exactly one selector. Neither and both are refused, not guessed.
    #[tokio::test]
    async fn describe_endpoint_refuses_zero_or_two_selectors() {
        let srv = two_call_capture();
        for params in [
            DescribeEndpointParams::default(),
            DescribeEndpointParams {
                ip: Some("10.0.0.1".to_string()),
                user: Some("alice".to_string()),
                limit: None,
            },
            DescribeEndpointParams {
                ip: Some("not-an-address".to_string()),
                user: None,
                limit: None,
            },
        ] {
            let err = srv
                .describe_endpoint(Parameters(params.clone()))
                .await
                .expect_err("an ambiguous or unparseable selector must be refused");
            assert_eq!(
                err.code,
                rmcp::model::ErrorCode::INVALID_PARAMS,
                "refused with the wrong code for {params:?}"
            );
        }
    }

    /// The dialog page is bounded; the counts above it are not.
    #[tokio::test]
    async fn describe_endpoint_bounds_the_page_but_not_the_counts() {
        let v = json_of(
            &two_call_capture()
                .describe_endpoint(Parameters(DescribeEndpointParams {
                    ip: Some("10.0.0.1".to_string()),
                    user: None,
                    limit: Some(1),
                }))
                .await
                .expect("the call succeeds"),
        );
        assert_eq!(
            v["dialogs"], 2,
            "the count must describe every match, not the page: {v}"
        );
        assert_eq!(
            v["recent_dialogs"].as_array().map(Vec::len),
            Some(1),
            "the page is what `limit` bounds: {v}"
        );
        assert_eq!(v["truncated"], true, "{v}");
        assert_eq!(
            v["recent_dialogs"][0]["call_id"], "bad@test",
            "newest first: an operator chasing a complaint wants what just \
             happened: {v}"
        );
    }

    // ── top_talkers ──────────────────────────────────────────────────

    /// Call `top_talkers` and hand back its JSON payload.
    async fn talkers(srv: &SipnabMcp, by: &str) -> serde_json::Value {
        json_of(
            &srv.top_talkers(Parameters(TopTalkersParams {
                by: by.to_string(),
                limit: None,
                filter: None,
                prefix_digits: None,
            }))
            .await
            .expect("the call succeeds"),
        )
    }

    /// The rows, as `(key, dialogs)` pairs in the order they came back.
    fn ranking(v: &serde_json::Value) -> Vec<(String, u64)> {
        v["talkers"]
            .as_array()
            .expect("talkers is an array")
            .iter()
            .map(|row| {
                (
                    row["key"].as_str().unwrap_or_default().to_string(),
                    row["dialogs"].as_u64().unwrap_or_default(),
                )
            })
            .collect()
    }

    /// The busiest address is first, and an address that only RECEIVED is not
    /// ranked above one that sent.
    #[tokio::test]
    async fn top_talkers_by_ip_ranks_the_busiest_sender_first() {
        let v = talkers(&two_call_capture(), "ip").await;
        let rows = ranking(&v);
        assert_eq!(
            rows.first().map(|(k, _)| k.as_str()),
            Some("10.0.0.1"),
            "the phone opened two of the three calls: {v}"
        );
        assert_eq!(
            rows.iter().find(|(k, _)| k == "10.0.0.1").map(|(_, n)| *n),
            Some(2),
            "two dialogs, not four messages: a talker counts a dialog once: {v}"
        );
    }

    /// A dialog counts for BOTH ends, which is what separates this tool from
    /// `aggregate_dialogs`. The phone and the proxy each carry the same two
    /// dialogs, so the rows sum above `total_matched`.
    #[tokio::test]
    async fn top_talkers_credits_a_dialog_to_every_participant() {
        let v = talkers(&two_call_capture(), "ip").await;
        let rows = ranking(&v);
        let phone = rows.iter().find(|(k, _)| k == "10.0.0.1").map(|(_, n)| *n);
        let proxy = rows.iter().find(|(k, _)| k == "10.0.0.2").map(|(_, n)| *n);
        assert_eq!(phone, Some(2), "the phone sent in both of its calls: {v}");
        assert_eq!(
            proxy,
            Some(2),
            "the proxy answered both, so both are its dialogs too: {v}"
        );
        assert_eq!(v["total_matched"], 3, "three dialogs in the store: {v}");
        let summed: u64 = rows.iter().map(|(_, n)| *n).sum();
        assert!(
            summed > 3,
            "the rows must NOT partition the dialogs -- a call has two ends: {v}"
        );
    }

    /// INVITE outcomes are attributed per talker: one answered, one 403.
    #[tokio::test]
    async fn top_talkers_reports_invite_outcomes_per_talker() {
        let v = talkers(&two_call_capture(), "ip").await;
        let row = v["talkers"]
            .as_array()
            .expect("talkers is an array")
            .iter()
            .find(|r| r["key"] == "10.0.0.1")
            .cloned()
            .expect("the phone is ranked");
        assert_eq!(row["invites"], 2, "{row}");
        assert_eq!(row["answered"], 1, "one call reached 200: {row}");
        assert_eq!(row["failed"], 1, "the other reached 403: {row}");
    }

    /// Banners rank by the software that sent them, and the value is fenced
    /// because a `User-Agent` is a string a stranger chose.
    #[tokio::test]
    async fn top_talkers_by_ua_ranks_banners_and_fences_them() {
        let v = talkers(&two_call_capture(), "ua").await;
        let rows = ranking(&v);
        let phone = rows
            .iter()
            .find(|(k, _)| k.contains("Phone/1.0"))
            .map(|(_, n)| *n);
        assert_eq!(phone, Some(2), "the phone's banner is on both calls: {v}");
        let fenced = rows
            .iter()
            .find(|(k, _)| k.contains("Phone/1.0"))
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        assert_ne!(
            fenced, "Phone/1.0",
            "a banner reaches a model fenced, exactly as a row fences it: {v}"
        );
    }

    /// The dialed number's leading digits make one bucket per dialog, and a
    /// destination that is a name rather than a number is named rather than
    /// dropped.
    #[tokio::test]
    async fn top_talkers_by_prefix_buckets_the_dialed_number() {
        let srv = server_with(vec![
            numeric_invite("n1@test", "15551234", ip(1), ip(2), base_ts()),
            numeric_invite(
                "n2@test",
                "+15559999",
                ip(1),
                ip(2),
                base_ts() + chrono::Duration::seconds(1),
            ),
            numeric_invite(
                "n3@test",
                "16135551212",
                ip(1),
                ip(2),
                base_ts() + chrono::Duration::seconds(2),
            ),
            invite(
                "named@test",
                "alice",
                ip(1),
                ip(2),
                "Phone/1.0",
                base_ts() + chrono::Duration::seconds(3),
            ),
        ]);
        let v = talkers(&srv, "prefix").await;
        let rows = ranking(&v);

        assert_eq!(
            rows.first().map(|(k, n)| (k.as_str(), *n)),
            Some(("1555", 2)),
            "the two 1555 numbers share a bucket, and the `+` does not split \
             one destination in two: {v}"
        );
        assert!(
            rows.iter().any(|(k, n)| k == "1613" && *n == 1),
            "the third number is its own prefix: {v}"
        );
        assert!(
            rows.iter().any(|(k, _)| k == "(non-numeric)"),
            "a destination with no digits is named, not dropped: {v}"
        );
        let summed: u64 = rows.iter().map(|(_, n)| *n).sum();
        assert_eq!(
            summed,
            v["total_matched"].as_u64().unwrap_or_default(),
            "a dialog has ONE dialed number, so prefix rows do partition: {v}"
        );
    }

    /// `limit` bounds the rows and says so, while `distinct_talkers` keeps
    /// describing every talker.
    #[tokio::test]
    async fn top_talkers_limit_bounds_rows_without_hiding_the_total() {
        let srv = two_call_capture();
        let v = json_of(
            &srv.top_talkers(Parameters(TopTalkersParams {
                by: "ip".to_string(),
                limit: Some(1),
                filter: None,
                prefix_digits: None,
            }))
            .await
            .expect("the call succeeds"),
        );
        assert_eq!(v["talkers"].as_array().map(Vec::len), Some(1), "{v}");
        assert_eq!(v["truncated"], true, "{v}");
        assert!(
            v["distinct_talkers"].as_u64().unwrap_or_default() > 1,
            "the count above the page describes every talker: {v}"
        );
    }

    /// A filter narrows which dialogs count, so "who is failing" is one call.
    #[tokio::test]
    async fn top_talkers_honors_the_filter() {
        let srv = two_call_capture();
        let v = json_of(
            &srv.top_talkers(Parameters(TopTalkersParams {
                by: "ip".to_string(),
                limit: None,
                filter: Some("response_code == 403".to_string()),
                prefix_digits: None,
            }))
            .await
            .expect("the call succeeds"),
        );
        assert_eq!(
            v["total_matched"], 1,
            "only the rejected call matches the filter: {v}"
        );
        assert_eq!(
            ranking(&v)
                .iter()
                .find(|(k, _)| k == "10.0.0.1")
                .map(|(_, n)| *n),
            Some(1),
            "and the phone is credited with exactly that one: {v}"
        );
    }

    /// An unknown dimension is refused by name rather than silently ranked by
    /// something else.
    #[tokio::test]
    async fn top_talkers_refuses_an_unknown_dimension() {
        let err = two_call_capture()
            .top_talkers(Parameters(TopTalkersParams {
                by: "codec".to_string(),
                limit: None,
                filter: None,
                prefix_digits: None,
            }))
            .await
            .expect_err("an unknown dimension is refused");
        assert!(
            err.message.contains("ip, ua, prefix"),
            "the refusal must name the vocabulary: {}",
            err.message
        );
    }

    /// A zero-digit prefix is refused: it is one bucket for every
    /// destination, so the ranking would have a single meaningless row.
    #[tokio::test]
    async fn top_talkers_refuses_a_zero_width_prefix() {
        let err = two_call_capture()
            .top_talkers(Parameters(TopTalkersParams {
                by: "prefix".to_string(),
                limit: None,
                filter: None,
                prefix_digits: Some(0),
            }))
            .await
            .expect_err("a zero-width prefix is refused");
        assert!(
            err.message.contains("prefix_digits"),
            "the refusal must name the parameter: {}",
            err.message
        );
    }

    /// `share_pct` is null rather than zero on an empty capture: a zero there
    /// reads as a talker that was measured and found idle.
    #[tokio::test]
    async fn top_talkers_on_an_empty_capture_ranks_nobody() {
        let v = talkers(&server_with(vec![]), "ip").await;
        assert_eq!(v["total_matched"], 0, "{v}");
        assert_eq!(v["distinct_talkers"], 0, "{v}");
        assert_eq!(v["truncated"], false, "{v}");
        assert_eq!(
            v["talkers"].as_array().map(Vec::len),
            Some(0),
            "nothing to rank: {v}"
        );
    }
}
